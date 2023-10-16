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

#![allow(missing_docs)]

use std::{collections::BTreeMap, future::IntoFuture, pin::Pin, time::Duration};

use eyeball::{ObservableWriteGuard, SharedObservable};
use futures_core::{Future, Stream};
use matrix_sdk_base::crypto::{
    backups::MegolmV1BackupKey,
    olm::BackedUpRoomKey,
    store::{BackupDecryptionKey, RoomKeyCounts},
    types::RoomKeyBackupInfo,
    GossippedSecret, OlmMachine,
};
use ruma::{
    api::client::backup::{
        create_backup_version, get_backup_keys, get_backup_keys_for_room,
        get_backup_keys_for_session, get_latest_backup_info, RoomKeyBackup,
    },
    events::secret::{request::SecretName, send::ToDeviceSecretSendEvent},
    serde::Raw,
    OwnedRoomId,
};
use tracing::{info, instrument, trace, warn, Span};

use crate::Client;

// TODO: Do we want to attach some data to these states? I.e. the backup
// version?
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackupState {
    Unknown,
    Creating,
    Enabling,
    Resuming,
    Enabled,
    Downloading,
    Disabling,
    Disabled,
}

impl Default for BackupState {
    fn default() -> Self {
        Self::Unknown
    }
}

pub struct UploadBackups<'a> {
    backups: &'a Backups,
    olm_machine: OlmMachine,
    timeout: Option<Duration>,
    progress: SharedObservable<RoomKeyCounts>,
}

impl<'a> UploadBackups<'a> {
    pub fn subscribe_to_progress(&self) -> impl Stream<Item = RoomKeyCounts> {
        self.progress.subscribe_reset()
    }

    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.timeout = Some(delay);

        self
    }
}

impl<'a> IntoFuture for UploadBackups<'a> {
    type Output = crate::Result<()>;
    #[cfg(target_arch = "wasm32")]
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + 'a>>;
    #[cfg(not(target_arch = "wasm32"))]
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            let Self { backups, olm_machine, timeout, progress } = self;

            while let Some((request_id, request)) = olm_machine.backup_machine().backup().await? {
                trace!(%request_id, "Uploading some room keys");

                let request = ruma::api::client::backup::add_backup_keys::v3::Request::new(
                    request.version,
                    request.rooms,
                );

                let response = backups.client.send(request, Default::default()).await?;

                olm_machine.mark_request_as_sent(&request_id, &response).await?;

                if progress.subscriber_count() != 0 {
                    let new_counts = olm_machine.backup_machine().room_key_counts().await?;

                    progress.set(new_counts);
                }

                #[cfg(not(target_arch = "wasm32"))]
                if let Some(timeout) = timeout {
                    tokio::time::sleep(timeout).await;
                }
            }

            Ok(())
        })
    }
}

#[derive(Debug)]
pub struct Backups {
    pub(super) client: Client,
}

// TODO:
// 1. Automatically create a backup if it doesn't exist
// 2. Some type of observable telling the application in which state we're in
// 3. Disable and mark that backups should stay disabled via a custom account
//    data event.

impl Backups {
    fn set_state(&self, state: BackupState) {
        let mut guard = self.client.inner.backups_state.write();
        ObservableWriteGuard::set(&mut guard, state);
    }

    async fn enable(
        &self,
        olm_machine: &OlmMachine,
        backup_key: MegolmV1BackupKey,
    ) -> Result<(), crate::Error> {
        olm_machine.backup_machine().enable_backup_v1(backup_key).await?;

        self.set_state(BackupState::Enabled);

        Ok(())
    }

    pub async fn create(&self) -> Result<(), crate::Error> {
        let _guard = self.client.locks().backup_modify_lock.lock().await;

        self.set_state(BackupState::Creating);

        let future = async {
            let decryption_key = BackupDecryptionKey::new().unwrap();

            let backup_key = decryption_key.megolm_v1_public_key();

            // TODO: Should we sign this? I guess we need to because other clients might
            // expect the signature.
            let backup_info = decryption_key.as_room_key_backup_info();

            let algorithm = Raw::new(&backup_info)?.cast();
            let request = create_backup_version::v3::Request::new(algorithm);
            let response = self.client.send(request, Default::default()).await?;
            let version = response.version;

            let olm_machine = self.client.olm_machine().await;
            let olm_machine = olm_machine.as_ref().ok_or(crate::Error::NoOlmMachine).unwrap();

            olm_machine
                .backup_machine()
                .save_decryption_key(Some(decryption_key), Some(version.to_owned()))
                .await?;

            backup_key.set_version(version);
            olm_machine.backup_machine().disable_backup().await?;

            self.enable(olm_machine, backup_key).await?;

            Ok(())
        };

        let result = future.await;

        if result.is_err() {
            self.set_state(BackupState::Unknown)
        }

        result
    }

    #[instrument(skip_all, fields(version))]
    pub async fn disable(&self) -> Result<(), crate::Error> {
        let _guard = self.client.locks().backup_modify_lock.lock().await;

        // TODO: We don't seem to fire out that we went into the disabling state.
        self.set_state(BackupState::Disabling);

        let future = async {
            let olm_machine = self.client.olm_machine().await;
            let olm_machine = olm_machine.as_ref().ok_or(crate::Error::NoOlmMachine).unwrap();

            let backup_keys = olm_machine.backup_machine().get_backup_keys().await?;

            if let Some(version) = backup_keys.backup_version {
                Span::current().record("version", &version);

                info!("Disabling and deleting backup");

                // TODO: If we fail at any point we should go back to a different state.

                olm_machine.backup_machine().disable_backup().await?;

                info!("Backup successfully disabled");

                let request =
                    ruma::api::client::backup::delete_backup_version::v3::Request::new(version);

                self.client.send(request, Default::default()).await?;
                self.set_state(BackupState::Disabled);

                info!("Backup successfully disabled and deleted");
            } else {
                info!("Backup is not enabled, can't disable it");
            }
            Ok(())
        };

        let result = future.await;

        // TODO: Is this the right state for this, we could had a storage error or a
        // network error for the delete call.
        if result.is_err() {
            self.set_state(BackupState::Unknown);
        }

        result
    }

    pub(crate) async fn setup(&self) -> Result<(), crate::Error> {
        info!("Setting up secret listeners and trying to resume backups");

        // TODO: We have a nice [`OlmMachine::store()::secrets_strea()`] which we could
        // use instead of a event handler.
        self.client.add_event_handler(Self::secret_send_event_handler);
        self.maybe_resume_backups().await?;

        Ok(())
    }

    #[instrument]
    pub(crate) async fn maybe_enable_backups(
        &self,
        maybe_recovery_key: &str,
    ) -> Result<bool, crate::Error> {
        let _guard = self.client.locks().backup_modify_lock.lock().await;

        self.set_state(BackupState::Enabling);

        let olm_machine = self.client.olm_machine().await;
        let olm_machine = olm_machine.as_ref().ok_or(crate::Error::NoOlmMachine).unwrap();

        let decryption_key = BackupDecryptionKey::from_base64(maybe_recovery_key).unwrap();

        let current_version = self.get_current_version().await;
        let backup_info: RoomKeyBackupInfo = current_version.algorithm.deserialize_as().unwrap();
        let stored_keys = olm_machine.backup_machine().get_backup_keys().await?;

        let ret = if stored_keys.backup_version.as_ref() == Some(&current_version.version)
            && stored_keys.decryption_key.as_ref() == Some(&decryption_key)
        {
            todo!("Backups are already enabled")
        } else if decryption_key.backup_key_matches(&backup_info) {
            let backup_key = decryption_key.megolm_v1_public_key();

            let result = olm_machine.backup_machine().verify_backup(backup_info, false).await;

            if let Ok(result) = result {
                info!("Signature verification on the latest backup version {result:?}");

                // TODO: What's the point of checking if the backup is signed by our master key,
                // if we received the secret from secret storage or from secret send, is this
                // some remnant where we used to enable backups without having
                // access to the backup recovery key?
                if result.trusted() {
                    info!(
                        "The backup is trusted and we have the correct recovery key, \
                         storing the recovery key and enabling backups"
                    );
                    backup_key.set_version(current_version.version.to_owned());

                    olm_machine
                        .backup_machine()
                        .save_decryption_key(
                            Some(decryption_key.to_owned()),
                            Some(current_version.version.to_owned()),
                        )
                        .await
                        .unwrap();
                    olm_machine.backup_machine().enable_backup_v1(backup_key).await.unwrap();

                    // TODO: Start backing up keys now.
                    // TODO: Download all keys now, or just leave this task for
                    // when we have a decryption failure?
                    self.set_state(BackupState::Downloading);
                    self.download_all_room_keys(decryption_key, current_version.version).await;
                    self.maybe_trigger_backup();

                    self.set_state(BackupState::Enabled);

                    true
                } else {
                    warn!("Found an active backup but the backup is not trusted.");

                    self.set_state(BackupState::Disabled);

                    false
                }
            } else {
                self.set_state(BackupState::Disabled);
                false
            }
        } else {
            warn!(
                "Found an active backup but the recovery key we received isn't the one used in \
                 this backup version"
            );
            self.set_state(BackupState::Disabled);

            false
        };

        Ok(ret)
    }

    async fn maybe_resume_backup_from_decryption_key(
        &self,
        decryption_key: BackupDecryptionKey,
        version: Option<String>,
    ) -> Result<bool, crate::Error> {
        let olm_machine = self.client.olm_machine().await;
        let olm_machine = olm_machine.as_ref().ok_or(crate::Error::NoOlmMachine).unwrap();

        let current_version = self.get_current_version().await;
        let backup_info: RoomKeyBackupInfo = current_version.algorithm.deserialize_as().unwrap();

        if decryption_key.backup_key_matches(&backup_info) {
            let backup_key = decryption_key.megolm_v1_public_key();
            olm_machine.backup_machine().enable_backup_v1(backup_key).await.unwrap();

            if let Some(version) = version {
                if current_version.version != version {
                    olm_machine
                        .backup_machine()
                        .save_decryption_key(None, Some(current_version.version.to_owned()))
                        .await
                        .unwrap();
                }
            }

            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn get_current_version(&self) -> get_latest_backup_info::v3::Response {
        let request = get_latest_backup_info::v3::Request::new();
        self.client.send(request, Default::default()).await.unwrap()
    }

    async fn resume_backup_from_stored_backup_key(
        &self,
        olm_machine: &OlmMachine,
    ) -> Result<bool, crate::Error> {
        let backup_keys = olm_machine.store().load_backup_keys().await.unwrap();

        if let Some(decryption_key) = backup_keys.decryption_key {
            self.maybe_resume_backup_from_decryption_key(decryption_key, backup_keys.backup_version)
                .await
        } else {
            Ok(false)
        }
    }

    async fn maybe_resume_from_secret_inbox(&self, olm_machine: &OlmMachine) {
        let secrets =
            olm_machine.store().get_secrets_from_inbox(&SecretName::RecoveryKey).await.unwrap();

        for secret in secrets {
            if self.handle_received_secret(secret).await {
                break;
            }
        }

        olm_machine.store().delete_secrets_from_inbox(&SecretName::RecoveryKey).await.unwrap();
    }

    /// Check and re-enable a backup if we have a backup recovery key locally.
    async fn maybe_resume_backups(&self) -> Result<(), crate::Error> {
        let olm_machine = self.client.olm_machine().await;
        let olm_machine = olm_machine.as_ref().ok_or(crate::Error::NoOlmMachine).unwrap();

        // Let us first check if we have a stored backup recovery key and a backup
        // version.
        if !self.resume_backup_from_stored_backup_key(olm_machine).await? {
            // We didn't manage to enable backups from a stored backup recovery key, let us
            // check our secret inbox. Perhaps we can find a valid key there.
            self.maybe_resume_from_secret_inbox(olm_machine).await;
        }

        Ok(())
    }

    pub(crate) async fn secret_send_event_handler(_: ToDeviceSecretSendEvent, client: Client) {
        let olm_machine = client.olm_machine().await;

        // TODO: Because of our crude multi-process support, which reloads the whole
        // [`OlmMachine`] the `secrets_stream` might stop giving you updates. Once
        // that's fixed, stop listening to individual secret send events and
        // listen to the secrets stream.
        if let Some(olm_machine) = olm_machine.as_ref() {
            client.encryption().backups().maybe_resume_from_secret_inbox(olm_machine).await;
        }
    }

    pub(crate) async fn handle_received_secret(&self, secret: GossippedSecret) -> bool {
        if secret.secret_name == SecretName::RecoveryKey {
            if self.maybe_enable_backups(&secret.event.content.secret).await.unwrap() {
                let olm_machine = self.client.olm_machine().await;
                let olm_machine = olm_machine.as_ref().ok_or(crate::Error::NoOlmMachine).unwrap();
                olm_machine.store().delete_secrets_from_inbox(&secret.secret_name).await.unwrap();

                true
            } else {
                false
            }
        } else {
            false
        }
    }

    pub(crate) fn maybe_trigger_backup(&self) {
        let tasks = self.client.inner.tasks.lock().unwrap();

        if let Some(tasks) = tasks.as_ref() {
            tasks.upload_room_keys.trigger_upload();
        }
    }

    pub(crate) async fn backup_room_keys(&self) -> UploadBackups<'_> {
        // TODO: Lock this, so we're uploading only one per client.

        let olm_machine = self.client.olm_machine().await;
        let olm_machine =
            olm_machine.as_ref().ok_or(crate::Error::NoOlmMachine).unwrap().to_owned();

        UploadBackups { backups: self, olm_machine, timeout: None, progress: Default::default() }
    }

    async fn handle_downloaded_room_keys(
        &self,
        backed_up_keys: get_backup_keys::v3::Response,
        backup_decryption_key: BackupDecryptionKey,
        olm_machine: &OlmMachine,
    ) {
        let mut decrypted_room_keys: BTreeMap<_, BTreeMap<_, _>> = BTreeMap::new();

        for (room_id, room_keys) in backed_up_keys.rooms {
            for (session_id, room_key) in room_keys.sessions {
                let room_key = room_key.deserialize().unwrap();

                let room_key =
                    backup_decryption_key.decrypt_session_data(room_key.session_data).unwrap();
                let room_key: BackedUpRoomKey = serde_json::from_slice(&room_key).unwrap();

                decrypted_room_keys
                    .entry(room_id.to_owned())
                    .or_default()
                    .insert(session_id, room_key);
            }
        }

        olm_machine
            .backup_machine()
            .import_backed_up_room_keys(decrypted_room_keys, |_, _| {})
            .await
            .unwrap();
    }

    pub async fn download_room_keys_for_room(&self, room_id: OwnedRoomId) {
        let olm_machine = self.client.olm_machine().await;
        let olm_machine = olm_machine.as_ref().ok_or(crate::Error::NoOlmMachine).unwrap();

        let backup_keys = olm_machine.store().load_backup_keys().await.unwrap();

        if let Some(decryption_key) = backup_keys.decryption_key {
            if let Some(version) = backup_keys.backup_version {
                let request =
                    get_backup_keys_for_room::v3::Request::new(version, room_id.to_owned());
                let response = self.client.send(request, Default::default()).await.unwrap();
                let response = get_backup_keys::v3::Response::new(BTreeMap::from([(
                    room_id,
                    RoomKeyBackup::new(response.sessions),
                )]));

                self.handle_downloaded_room_keys(response, decryption_key, olm_machine).await
            }
        }
    }

    pub async fn download_room_key(&self, room_id: OwnedRoomId, session_id: String) {
        let olm_machine = self.client.olm_machine().await;
        let olm_machine = olm_machine.as_ref().ok_or(crate::Error::NoOlmMachine).unwrap();

        let backup_keys = olm_machine.store().load_backup_keys().await.unwrap();

        if let Some(decryption_key) = backup_keys.decryption_key {
            if let Some(version) = backup_keys.backup_version {
                let request = get_backup_keys_for_session::v3::Request::new(
                    version,
                    room_id.to_owned(),
                    session_id.to_owned(),
                );
                let response = self.client.send(request, Default::default()).await.unwrap();
                let response = get_backup_keys::v3::Response::new(BTreeMap::from([(
                    room_id,
                    RoomKeyBackup::new(BTreeMap::from([(session_id, response.key_data)])),
                )]));

                self.handle_downloaded_room_keys(response, decryption_key, olm_machine).await;
            }
        }
    }

    pub async fn download_all_room_keys(
        &self,
        decryption_key: BackupDecryptionKey,
        version: String,
    ) {
        let request = get_backup_keys::v3::Request::new(version);
        let response = self.client.send(request, Default::default()).await.unwrap();

        let olm_machine = self.client.olm_machine().await;
        let olm_machine = olm_machine.as_ref().ok_or(crate::Error::NoOlmMachine).unwrap();

        self.handle_downloaded_room_keys(response, decryption_key, olm_machine).await;
    }

    pub fn state_stream(&self) -> impl Stream<Item = BackupState> {
        self.client.inner.backups_state.subscribe_reset()
    }

    pub fn state(&self) -> BackupState {
        self.client.inner.backups_state.get()
    }
}
