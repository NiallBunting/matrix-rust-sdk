// Copyright 2023 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Secret Storage Support
//!
//! This submodule provides essential functionality for secret storage in
//! compliance with the [Matrix protocol specification][spec].
//!
//! Secret storage is a critical component that provides an encrypted
//! key/value storage system. It leverages [account data] events stored on the
//! Matrix homeserver to ensure secure and private storage of sensitive
//! information.
//!
//! For detailed information and usage guidelines, refer to the documentation of
//! the [`SecretStore`] struct.
//!
//! # Examples
//!
//! ```no_run
//! # use matrix_sdk::Client;
//! # use url::Url;
//! # async {
//! # let homeserver = Url::parse("http://example.com")?;
//! # let client = Client::new(homeserver).await?;
//! use ruma::events::secret::request::SecretName;
//!
//! // Open the store.
//! let secret_store = client
//!     .encryption()
//!     .open_secret_store("It's a secret to everybody")
//!     .await?;
//!
//! // Import the secrets.
//! secret_store.import_secrets().await?;
//!
//! // Our own device should now be verified.
//! let device = client
//!     .encryption()
//!     .get_own_device()
//!     .await?
//!     .expect("We should be able to retrieve our own device");
//!
//! assert!(device.is_cross_signed_by_owner());
//!
//! # anyhow::Ok(()) };
//! ```
//!
//! [spec]: https://spec.matrix.org/v1.8/client-server-api/#secret-storage
//! [account data]: https://spec.matrix.org/v1.8/client-server-api/#client-config

use std::{fmt, string::FromUtf8Error};

use matrix_sdk_base::crypto::{
    secret_storage::{DecodeError, MacError, SecretStorageKey},
    CrossSigningKeyExport, CryptoStoreError, SecretImportError,
};
use ruma::{
    events::{
        secret::request::SecretName,
        secret_storage::{
            default_key::SecretStorageDefaultKeyEventContent, key::SecretStorageKeyEventContent,
            secret::SecretEventContent,
        },
        EventContentFromType, GlobalAccountDataEventType,
    },
    serde::Raw,
};
use serde_json::value::to_raw_value;
use thiserror::Error;
use tracing::{
    error,
    field::{debug, display},
    info, instrument, Span,
};

use super::identities::ManualVerifyError;
use crate::Client;

/// Convenicence type alias for the secret-storage specific results.
pub type Result<T, E = SecretStorageError> = std::result::Result<T, E>;

/// Error type for the secret-storage subsystem.
#[derive(Debug, Error)]
pub enum SecretStorageError {
    /// A typical SDK error.
    #[error(transparent)]
    Sdk(#[from] crate::Error),
    /// Error when deserializing account data events.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    /// The secret storage key could not have been decoded or verified
    /// successfully.
    SecretStorageKey(#[from] DecodeError),
    #[error(
        "The info about the secret key could not have been found in the account data of the user"
    )]
    /// The secret store could not be opened because info about the
    /// secret-storage key could not have been found in the account data of
    /// the user.
    MissingKeyInfo {
        /// The key ID of the default key. Will be set to the key ID in the
        /// `m.secret_storage.default_key` event.
        key_id: String,
    },
    /// A secret could not have been imported from the secret store into the
    /// local store.
    #[error(transparent)]
    SecretImportError(#[from] SecretImportError),
    /// A general storage error.
    #[error(transparent)]
    Storage(#[from] CryptoStoreError),
    /// An error happened while trying to mark our own device as verified after
    /// the private cross-signing keys have been imported.
    #[error(transparent)]
    Verification(#[from] ManualVerifyError),
    /// Error describing a decryption failure of a secret.
    #[error(transparent)]
    Decryption(#[from] DecryptionError),
}

/// Error type describing decryption failures of the secret-storage system.
#[derive(Debug, Error)]
pub enum DecryptionError {
    /// The secret could not have been decrypted.
    #[error("Could not decrypt the secret using the secret storage key, invalid MAC.")]
    Mac(#[from] MacError),
    /// Could not decode the secret, the secret is not valid UTF-8.
    #[error("Could not decode the secret, the secret is not valid UTF-8")]
    Utf8(#[from] FromUtf8Error),
}

#[cfg_attr(doc, aquamarine::aquamarine)]
/// Secure key/value storage for Matrix users.
///
/// The `SecretStore` struct encapsulates the secret storage mechanism for
/// Matrix users, as it is specified in the [Matrix specification].
///
/// This specialized storage is tied to the user's Matrix account and serves as
/// an encrypted key/value store, backed by [account data] residing on the
/// homeserver. Any secrets uploaded to the homeserver using the
/// [`SecretStore::store_secret()`] method are automatically encrypted by the
/// [`SecretStore`].
///
/// [`SecretStore`] enables you to safely manage and access sensitive
/// information while ensuring that it remains protected from unauthorized
/// access. It plays a crucial role in maintaining the privacy and security of a
/// Matrix user's data.
///
/// **Data Flow Overview:**
/// ```mermaid
/// flowchart LR
///    subgraph Client
///        SecretStore
///    end
///    subgraph Homeserver
///        data[Account Data]
///    end
///    SecretStore <== Encrypted ==> data
/// ```
///
/// **Note**: It's important to emphasize that the `SecretStore` should not be
/// used for storing large volumes of data due to its nature as a key/value
/// store for sensitive information.
///
/// # Examples
///
/// ```no_run
/// # use matrix_sdk::Client;
/// # use url::Url;
/// # async {
/// # let homeserver = Url::parse("http://example.com")?;
/// # let client = Client::new(homeserver).await?;
/// use ruma::events::secret::request::SecretName;
///
/// let secret_store = client
///     .encryption()
///     .open_secret_store("It's a secret to everybody")
///     .await?;
///
/// let my_secret = "Top secret secret";
/// let my_secret_name = SecretName::from("m.treasure");
///
/// secret_store.store_secret(&my_secret_name, my_secret);
///
/// # anyhow::Ok(()) };
/// ```
///
/// [Matrix specification]: https://spec.matrix.org/v1.8/client-server-api/#secret-storage
/// [account data]: https://spec.matrix.org/v1.8/client-server-api/#client-config
pub struct SecretStore {
    client: Client,
    key: SecretStorageKey,
}

impl SecretStore {
    pub(super) async fn open(client: Client, key: &str) -> Result<Self> {
        // Prevent multiple simultaneous calls to this method.
        //
        // See the documentation for the lock in the `store_secret` method for more
        // info.
        let guard = client.locks().open_secret_store_lock.lock().await;

        let maybe_default_key_id = client
            .account()
            .fetch_account_data(GlobalAccountDataEventType::SecretStorageDefaultKey)
            .await?;

        if let Some(default_key_id) = maybe_default_key_id {
            let default_key_id =
                default_key_id.deserialize_as::<SecretStorageDefaultKeyEventContent>()?;

            let event_type =
                GlobalAccountDataEventType::SecretStorageKey(default_key_id.key_id.to_owned());
            let secret_key = client.account().fetch_account_data(event_type.to_owned()).await?;

            if let Some(secret_key_content) = secret_key {
                let event_type = event_type.to_string();
                let secret_key_content = to_raw_value(&secret_key_content)?;

                let secret_key_content =
                    SecretStorageKeyEventContent::from_parts(&event_type, &secret_key_content)?;

                let key = SecretStorageKey::from_account_data(key, secret_key_content)?;

                drop(guard);

                Ok(Self { client, key })
            } else {
                Err(SecretStorageError::MissingKeyInfo { key_id: default_key_id.key_id })
            }
        } else {
            let key = SecretStorageKey::new();
            let content = key.event_content().to_owned();

            client.account().set_account_data(content).await?;

            let default_key_content =
                SecretStorageDefaultKeyEventContent::new(key.key_id().to_owned());

            client.account().set_account_data(default_key_content).await?;

            drop(guard);

            Ok(Self { client, key })
        }
    }

    /// Retrieve a secret from the homeserver's account data
    ///
    /// This method allows you to retrieve a secret from the account data stored
    /// on the Matrix homeserver.
    ///
    /// # Arguments
    ///
    /// - `secret_name`: The name of the secret. The provided `secret_name`
    ///   serves as the event type for the associated account data event.
    ///
    /// The `retrieve_secret` method enables you to access and decrypt secrets
    /// previously stored in the user's account data on the homeserver. You can
    /// use the `secret_name` parameter to specify the desired secret to
    /// retrieve.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use matrix_sdk::Client;
    /// # use url::Url;
    /// # async {
    /// # let homeserver = Url::parse("http://example.com")?;
    /// # let client = Client::new(homeserver).await?;
    /// use ruma::events::secret::request::SecretName;
    ///
    /// let secret_store = client
    ///     .encryption()
    ///     .open_secret_store("It's a secret to everybody")
    ///     .await?;
    ///
    /// let my_secret_name = SecretName::from("m.treasure");
    ///
    /// let secret = secret_store.get_secret(&my_secret_name).await?;
    ///
    /// # anyhow::Ok(()) };
    /// ```
    pub async fn get_secret(&self, secret_name: &SecretName) -> Result<Option<String>> {
        let event_type = GlobalAccountDataEventType::from(secret_name.to_owned());

        if let Some(secret_content) = self.client.account().fetch_account_data(event_type).await? {
            let mut secret_content = secret_content.deserialize_as::<SecretEventContent>()?;

            // The `SecretEventContent` contains a map from the secret storage key ID to the
            // ciphertext. Let's try to find a secret which was encrypted using our
            // [`SecretStorageKey`].
            if let Some(secret_content) = secret_content.encrypted.remove(self.key.key_id()) {
                // We found a secret we should be able to decrypt, let's try to do so.
                let decrypted = self
                    .key
                    .decrypt(&secret_content.try_into()?, secret_name)
                    .map_err(DecryptionError::from)?;

                let secret = String::from_utf8(decrypted).map_err(DecryptionError::from)?;

                Ok(Some(secret))
            } else {
                // We did not find a secret which was encrypted using our [`SecretStorageKey`],
                // no need to try to decrypt.
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    /// Store a secret in the homeserver's account data
    ///
    /// This method allows you to securely store a secret on the Matrix
    /// homeserver as an encrypted account data event.
    ///
    /// # Arguments
    ///
    /// - `secret_name`: The name of the secret. The provided `secret_name`
    ///   serves as the event type for the account data event on the homeserver.
    ///
    /// - `secret`: The secret to be stored on the homeserver. The secret is
    ///   encrypted before being stored, ensuring its confidentiality and
    ///   integrity.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use matrix_sdk::Client;
    /// # use url::Url;
    /// # async {
    /// # let homeserver = Url::parse("http://example.com")?;
    /// # let client = Client::new(homeserver).await?;
    /// use ruma::events::secret::request::SecretName;
    ///
    /// let secret_store = client
    ///     .encryption()
    ///     .open_secret_store("It's a secret to everybody")
    ///     .await?;
    ///
    /// let my_secret = "Top secret secret";
    /// let my_secret_name = SecretName::from("m.treasure");
    ///
    /// secret_store.store_secret(&my_secret_name, my_secret);
    ///
    /// # anyhow::Ok(()) };
    /// ```
    pub async fn store_secret(&self, secret_name: &SecretName, secret: &str) -> Result<()> {
        // This function does a read/update/store of an account data event stored on the
        // homeserver. We first fetch the existing account data event, the event
        // contains a map which gets updated by this method, finally we upload the
        // modified event.
        //
        // To prevent multiple calls to this method trying to update a secret at the
        // same time, and thus trampling on each other we introduce a lock which
        // acts as a semaphore.
        //
        // Technically there's a low chance of this happening since we're not storing
        // many secrets and the bigger problem is that another client might be
        // doing this as well and the server doesn't have a mechanism to protect against
        // this.
        //
        // We could make this lock be per `secret_name` but this is not a performance
        // critical method.
        let _guard = self.client.locks().store_secret_lock.lock().await;

        let event_type = GlobalAccountDataEventType::from(secret_name.to_owned());

        // Get the existing account data event or create a new empty one.
        let mut secret_content = if let Some(secret_content) =
            self.client.account().fetch_account_data(event_type.to_owned()).await?
        {
            secret_content.deserialize_as::<SecretEventContent>()?
        } else {
            SecretEventContent::new(Default::default())
        };

        // Encrypt the secret.
        let secret = secret.as_bytes().to_vec();
        let encrypted_secret = self.key.encrypt(secret, secret_name);

        // Insert the encrypted secret into the account data event.
        secret_content.encrypted.insert(self.key.key_id().to_owned(), encrypted_secret.into());
        let secret_content = Raw::from_json(to_raw_value(&secret_content)?);

        // Upload the modified account data event, now that the new secret has been
        // inserted.
        self.client.account().set_account_data_raw(event_type, secret_content).await?;

        Ok(())
    }

    /// Get all the well-known private parts/keys of the [`OwnUserIdentity`] as
    /// a [`CrossSigningKeyExport`].
    ///
    /// The export can be imported into the [`OlmMachine`] using
    /// [`OlmMachine::import_cross_signing_keys()`].
    async fn get_cross_signing_keys(&self) -> Result<CrossSigningKeyExport> {
        let export = CrossSigningKeyExport {
            master_key: self.get_secret(&SecretName::CrossSigningMasterKey).await?,
            self_signing_key: self.get_secret(&SecretName::CrossSigningSelfSigningKey).await?,
            user_signing_key: self.get_secret(&SecretName::CrossSigningUserSigningKey).await?,
        };

        Ok(export)
    }

    /// Retrieve and store well-known secrets locally
    ///
    /// This method retrieves and stores all well-known secrets from the account
    /// data on the Matrix homeserver to enhance local security and identity
    /// verification.
    ///
    /// The following secrets are retrieved by this method:
    ///
    /// - `m.cross_signing.master`: The master cross-signing key.
    /// - `m.cross_signing.self_signing`: The self-signing cross-signing key.
    /// - `m.cross_signing.user_signing`: The user-signing cross-signing key.
    ///
    /// If the `m.cross_signing.self_signing` key is successfully imported, it
    /// is used to sign our own [`Device`], marking it as verified. This step is
    /// establishes trust in your own device's identity.
    ///
    /// By invoking this method, you ensure that your device has access to
    /// the necessary secrets for device and identity verification.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use matrix_sdk::Client;
    /// # use url::Url;
    /// # async {
    /// # let homeserver = Url::parse("http://example.com")?;
    /// # let client = Client::new(homeserver).await?;
    /// use ruma::events::secret::request::SecretName;
    ///
    /// let secret_store = client
    ///     .encryption()
    ///     .open_secret_store("It's a secret to everybody")
    ///     .await?;
    ///
    /// secret_store.import_secrets().await?;
    ///
    /// let status = client
    ///     .encryption()
    ///     .cross_signing_status()
    ///     .await
    ///     .expect("We should be able to check out cross-signing status");
    ///
    /// println!("Cross-signing status {status:?}");
    ///
    /// # anyhow::Ok(()) };
    /// ```
    ///
    /// [`Device`]: crate::encryption::identities::Device
    #[instrument(fields(user_id, device_id, cross_signing_status))]
    pub async fn import_secrets(&self) -> Result<()> {
        let olm_machine = self.client.olm_machine().await;
        let olm_machine = olm_machine.as_ref().ok_or(crate::Error::NoOlmMachine)?;

        Span::current()
            .record("user_id", display(olm_machine.user_id()))
            .record("device_id", display(olm_machine.device_id()));

        info!("Fetching the private cross-signing keys from the secret store");

        // Get all our private cross-signing keys from the secret store.
        let export = self.get_cross_signing_keys().await?;

        info!(cross_signing_keys = ?export, "Received the cross signing keys from the server");

        // We need to ensure that we have the public parts of the cross-signing keys,
        // those are represented as the `OwnUserIdentity` struct. The public
        // parts from the server are compared to the public parts re-derived from the
        // private parts. We will only import the private parts of the cross-signing
        // keys if they match to the public parts, otherwise we would risk
        // importing some stale cross-signing keys leftover in the secret store.
        let (request_id, request) = olm_machine.query_keys_for_users([olm_machine.user_id()]);
        self.client.keys_query(&request_id, request.device_keys).await?;

        // TODO: Import the backup key here as well if it exists and enable backups if
        // the current backup version is trusted, or expose a different method for this?

        // Let's now try to import our private cross-signing keys.
        let status = olm_machine.import_cross_signing_keys(export).await?;

        Span::current().record("cross_signing_status", debug(&status));

        info!("Done importing the cross signing keys");

        if status.has_self_signing {
            info!("Successfully imported the self-signing key, attempting to sign our own device");

            // Now that we successfully imported them, the self-signing key can be used to
            // verify our own device so other devices and user identities trust
            // it if the trust our user identity.
            if let Some(own_device) = self.client.encryption().get_own_device().await? {
                own_device.verify().await?;

                // Another /keys/query request to ensure that the signatures we uploaded using
                // `own_device.verify()` are attached to the `Device` we have in storage.
                let (request_id, request) =
                    olm_machine.query_keys_for_users([olm_machine.user_id()]);
                self.client.keys_query(&request_id, request.device_keys).await?;

                info!("Successfully signed our own device, the device is now verified");
            } else {
                error!("Couldn't find our own device in the store");
            }
        }

        Ok(())
    }
}

impl fmt::Debug for SecretStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretStore").field("key", &self.key).finish_non_exhaustive()
    }
}
