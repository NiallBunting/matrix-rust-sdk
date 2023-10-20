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

//! The recovery module
//!
//! The recovery module attempts to provide a unified and simplified view over
//! the secret storage and backup subsystems.
//!
//! Dear spec connosieuers, recovery here is not the same as the [`Recovery
//! key`] mentioned in the spec. The recovery key from the spec is solely about
//! backups, while the term recovery in this file includes both the backups
//! and the secret storage mechanism. The recovery key mentioned in this file is
//! the secret storage key.
//!
//! [`Recovery key`]: https://spec.matrix.org/v1.8/client-server-api/#recovery-key

use ruma::{
    api::client::uiaa::AuthData,
    events::{EventContent, GlobalAccountDataEventType},
    exports::ruma_macros::EventContent,
};
use serde::{Deserialize, Serialize};

use crate::{Client, Result};

mod futures;

pub use futures::{Enable, EnableProgress};

#[derive(Clone, Debug, Default, Deserialize, Serialize, EventContent)]
#[ruma_event(type = "m.org.matrix.custom.secret_storage_disabled", kind = GlobalAccountData)]
struct SecretStorageDisabledContent {
    disabled: bool,
}

impl SecretStorageDisabledContent {
    fn event_type() -> GlobalAccountDataEventType {
        Self { disabled: false }.event_type()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, EventContent)]
#[ruma_event(type = "m.org.matrix.custom.backup_disabled", kind = GlobalAccountData)]
struct BackupDisabledContent {
    disabled: bool,
}

impl BackupDisabledContent {
    fn event_type() -> GlobalAccountDataEventType {
        // This is dumb, there's got to be a better way to get to the event type?
        Self { disabled: false }.event_type()
    }
}

#[derive(Debug)]
pub struct Recovery {
    pub(super) client: Client,
}

// TODO: We need to support the following flows:
// 1. Set up recovery - this creates a secret storage key and presumably uploads
//    all the known secrets to secret storage
// 2. Change recovery key - this does the same as the above but overwrites any
//    existing secret storage key, it does not create a new backup or rotate the
//    cross-signing keys.
// 3. Turn off backup - This is one of the most confusing options, this option
//    should turn off the backup, delete the backup version, and somehow delete
//    4S (I don't think that this is possible the default_key event can't be
//    deleted nor can we unset the key ID in the event as it's a required
//    field).
// 3. Turn on backup - This should create a backup if it doesn't exist, but
//    should it upload the backup recovery key to secret storage? Pretty sure it
//    should.
// 4. Fix recovery issues - This is basically restoring your cross-signing keys
//    and backup key from secret storage after the user has entered a secret
//    storage key/passphrase. Something we explicitly said we're not going to
//    do.
// 5. Let users set up recovery in a quick manner before logging out if they are
//    on their last device.
// 6. Automatically bootstrap cross-signing and backups if they are logging in
//    for the first time.
//
// All of this is a bit much for something called the "Key backup / recovery"
// and it might even have been wise to flesh out the concepts a bit more. If
// you're trying to make sense of all of this and are a bit lost, the song
// "Black fairy" fairly accurately portrays the mood this file might have put
// you in.

impl Recovery {
    /// Enable secret storage *and* backups.
    pub fn enable(&self) -> Enable<'_> {
        // TODO: How to only allow this to be called if you are the only/last device
        // this user has?
        Enable::new(self)
    }

    /// Enable backups only.
    pub async fn enable_backup(&self) -> Result<()> {
        self.client.encryption().backups().create().await?;
        self.mark_backup_as_enabled().await?;
        self.client.encryption().backups().maybe_trigger_backup();

        Ok(())
    }

    /// Is this device the last device the user has.
    pub async fn are_we_the_last_man_standing(&self) -> Result<bool> {
        let olm_machine = self.client.olm_machine().await;
        let olm_machine = olm_machine.as_ref().ok_or(crate::Error::NoOlmMachine)?;
        let user_id = olm_machine.user_id();

        self.ensure_initial_key_query().await?;

        let devices = self.client.encryption().get_user_devices(user_id).await?;

        Ok(devices.devices().count() == 1)
    }

    pub async fn is_recovery_enabled(&self) -> Result<bool> {
        let disabled_content = self
            .client
            .account()
            .account_data_raw(SecretStorageDisabledContent::event_type())
            .await?;

        let disabled_content = if let Some(disabled_content) = disabled_content {
            Some(disabled_content)
        } else {
            self.client
                .account()
                .fetch_account_data(SecretStorageDisabledContent::event_type())
                .await?
        };

        if let Some(disabled_content) = disabled_content {
            let content: SecretStorageDisabledContent = disabled_content.deserialize_as()?;

            Ok(content.disabled)
        } else {
            self.client.encryption().secret_storage().is_enabled().await
        }
    }

    /// Disable recovery completely.
    ///
    /// This method will disable the uploading of room keys to a backup, delete
    /// the currently active backup version, and remove the default secret
    /// storage key. It will not delete the `m.secret_storage.default_key`
    /// global account data even since that's not possible. Can someone explain
    /// me why a key/value store doesn't have a `DELETE` method?
    ///
    /// Finally, the method will upload a
    /// `m.org.matrix.custom.recovery_disabled` global account data event
    /// signaling other clients that we should not re-enable backups and
    /// secret storage automatically.
    pub async fn disable(&self) -> Result<()> {
        self.client.encryption().backups().disable().await?;
        self.mark_as_globally_disabled().await?;

        Ok(())
    }

    /// Reset the recovery key but first import all the secrets from foobar.
    pub async fn recover_and_reset(
        &self,
        old_key: &str,
        new_passphrase: Option<&str>,
    ) -> Result<String> {
        self.fix_recovery_issues(old_key).await?;
        self.reset_key(new_passphrase).await
    }

    /// Reset the recovery key.
    ///
    /// This will rotate the secret storage key and re-upload all the secrets to
    /// the [`SecretStore`].
    pub async fn reset_key(&self, passphrase: Option<&str>) -> Result<String> {
        let store = self
            .client
            .encryption()
            .secret_storage()
            .create_secret_store(passphrase)
            .await
            .unwrap();

        self.mark_secret_storage_as_enabled().await?;

        Ok(store.secret_storage_key())
    }

    /// What the fuck is this supposed to do if not fetch the secrets from
    /// secret storage? How is that different from the initial restore stuff
    /// from secret storage flow?
    pub async fn fix_recovery_issues(&self, recovery_key: &str) -> Result<()> {
        let store = self
            .client
            .encryption()
            .secret_storage()
            .open_secret_store(recovery_key)
            .await
            .unwrap();
        store.import_secrets().await.unwrap();

        Ok(())
    }

    async fn ensure_initial_key_query(&self) -> Result<()> {
        let olm_machine = self.client.olm_machine().await;
        let olm_machine = olm_machine.as_ref().ok_or(crate::Error::NoOlmMachine)?;
        let user_id = olm_machine.user_id();

        if self.client.encryption().get_user_identity(user_id).await?.is_none() {
            let (request_id, request) = olm_machine.query_keys_for_users([olm_machine.user_id()]);
            self.client.keys_query(&request_id, request.device_keys).await?;
        }

        Ok(())
    }

    async fn does_a_user_identity_exist(&self) -> Result<bool> {
        let olm_machine = self.client.olm_machine().await;
        let olm_machine = olm_machine.as_ref().ok_or(crate::Error::NoOlmMachine)?;
        let user_id = olm_machine.user_id();

        self.ensure_initial_key_query().await?;

        Ok(self.client.encryption().get_user_identity(user_id).await?.is_some())
    }

    async fn should_auto_enable_backups(&self) -> Result<bool> {
        // If we didn't already enable backups, we don't see a backup version on the
        // server and finally if backups have not been marked to be explicitly
        // disabled, then we can automatically enable them.
        Ok(!self.client.encryption().backups().is_enabled().await
            && !self.client.encryption().backups().exists_on_server().await?
            && !self.are_backups_disabled().await?)
    }

    /// Automatically do the following:
    ///
    /// 1. Bootstrap cross-signing keys, if it wasn't already done so.
    /// 2. Create and enable a backup version if there isn't a currently active
    ///    one.
    pub(crate) async fn auto_enable(&self, auth_data: Option<AuthData>) -> Result<()> {
        // We first try to bootstrap a user identity, this will give us the proper keys
        // to sign a backup if we create one in the next step.
        if let Some(auth_data) = auth_data {
            self.maybe_bootstrap_cross_signing(auth_data).await?;
        }

        if self.should_auto_enable_backups().await? {
            self.enable_backup().await?;
        }

        Ok(())
    }

    pub(crate) async fn maybe_bootstrap_cross_signing(&self, auth_data: AuthData) -> Result<()> {
        if !self.does_a_user_identity_exist().await? {
            if let Err(e) = self.client.encryption().bootstrap_cross_signing(Some(auth_data)).await
            {
                // Convert this into a log.
                todo!("{e:?}");
            }
        }

        Ok(())
    }

    async fn are_backups_disabled(&self) -> Result<bool> {
        Ok(self
            .client
            .account()
            .fetch_account_data(BackupDisabledContent::event_type())
            .await?
            .map(|event| {
                event
                    .deserialize_as::<BackupDisabledContent>()
                    .map(|event| event.disabled)
                    .unwrap_or(false)
            })
            .unwrap_or(false))
    }

    async fn mark_secret_storage_as_enabled(&self) -> Result<()> {
        self.client
            .account()
            .set_account_data(SecretStorageDisabledContent { disabled: false })
            .await?;

        // TODO: We need to listen for this event over `/sync` and if we notice that it
        // got toggled to `true`, we should re-request the missing secrets over
        // `m.secret.send`. Of course, this should only happen if we are verified.

        Ok(())
    }

    async fn mark_backup_as_enabled(&self) -> Result<()> {
        self.client.account().set_account_data(BackupDisabledContent { disabled: false }).await?;

        Ok(())
    }

    async fn mark_as_globally_disabled(&self) -> Result<()> {
        // Why oh why, can't we delete account data events?
        self.client
            .account()
            .set_account_data(SecretStorageDisabledContent { disabled: true })
            .await?;

        self.client.account().set_account_data(BackupDisabledContent { disabled: true }).await?;

        Ok(())
    }
}
