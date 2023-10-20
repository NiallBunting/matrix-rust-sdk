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

use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
    time::Duration,
};

use futures_core::Stream;
use futures_util::StreamExt;
use matrix_sdk_base::crypto::{
    backups::MegolmV1BackupKey,
    store::{BackupDecryptionKey, RoomKeyCounts},
    types::RoomKeyBackupInfo,
    GossippedSecret, OlmMachine,
};
use ruma::{
    api::client::{
        backup::{
            create_backup_version, get_backup_keys, get_backup_keys_for_room,
            get_backup_keys_for_session, get_latest_backup_info, RoomKeyBackup,
        },
        error::ErrorKind,
    },
    events::secret::{request::SecretName, send::ToDeviceSecretSendEvent},
    serde::Raw,
    OwnedRoomId,
};
use serde::de::Error;
use tokio::sync::broadcast;
use tokio_stream::wrappers::{errors::BroadcastStreamRecvError, BroadcastStream};
use tracing::{info, instrument, trace, warn, Span};

mod futures;

pub use self::futures::WaitForSteadyState;
use crate::Client;

#[derive(Clone, Debug)]
pub struct ChannelObservable<T: Clone + Send> {
    value: Arc<RwLock<T>>,
    channel: broadcast::Sender<T>,
}

impl<T: Default + Clone + Send + 'static> Default for ChannelObservable<T> {
    fn default() -> Self {
        let value = Default::default();
        Self::new(value)
    }
}

impl<T: 'static + Send + Clone> ChannelObservable<T> {
    pub fn new(value: T) -> Self {
        let channel = broadcast::Sender::new(100);
        Self { value: RwLock::new(value).into(), channel }
    }

    pub fn subscribe(&self) -> impl Stream<Item = Result<T, BroadcastStreamRecvError>> {
        let current_value = self.value.read().unwrap().to_owned();
        let initial_stream = tokio_stream::once(Ok(current_value));
        let broadcast_stream = BroadcastStream::new(self.channel.subscribe());

        let combined = initial_stream.chain(broadcast_stream);

        combined
    }

    pub fn set(&self, new_value: T) {
        *self.value.write().unwrap() = new_value.to_owned();
        // We're ignoring the error case where no receivers exist.
        let _ = self.channel.send(new_value);
    }

    pub fn get(&self) -> T {
        self.value.read().unwrap().to_owned()
    }
}

#[derive(Debug, Clone)]
pub struct Backups {
    pub(super) client: Client,
}

#[derive(Clone, Debug)]
pub enum UploadState {
    Idle,
    CheckingIfUploadNeeded(RoomKeyCounts),
    Uploading(RoomKeyCounts),
    Done,
}

pub(crate) struct BackupClientState {
    upload_delay: Duration,
    pub(crate) upload_progress: ChannelObservable<UploadState>,
    global_state: ChannelObservable<BackupState>,
}

impl Default for BackupClientState {
    fn default() -> Self {
        Self {
            upload_delay: Duration::from_millis(100),
            upload_progress: ChannelObservable::new(UploadState::Idle),
            global_state: Default::default(),
        }
    }
}

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

impl Backups {
    fn set_state(&self, state: BackupState) {
        self.client.inner.backups_state.global_state.set(state);
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

    pub fn wait_for_steady_state(&self) -> WaitForSteadyState<'_> {
        WaitForSteadyState {
            backups: self,
            progress: self.client.inner.backups_state.upload_progress.clone(),
            timeout: None,
        }
    }

    pub async fn create(&self) -> Result<(), crate::Error> {
        let _guard = self.client.locks().backup_modify_lock.lock().await;

        self.set_state(BackupState::Creating);

        let future = async {
            let decryption_key = BackupDecryptionKey::new().expect(
                "We should be able to generate enough randomness to \
                 create a new backup recovery key",
            );

            let backup_key = decryption_key.megolm_v1_public_key();

            // TODO: We should sign this with our own device key and, if available, with our
            // Master key. This is only for compat reasons important.
            let backup_info = decryption_key.as_room_key_backup_info();

            let algorithm = Raw::new(&backup_info)?.cast();
            let request = create_backup_version::v3::Request::new(algorithm);
            let response = self.client.send(request, Default::default()).await?;
            let version = response.version;

            backup_key.set_version(version.to_owned());

            let olm_machine = self.client.olm_machine().await;
            let olm_machine = olm_machine.as_ref().ok_or(crate::Error::NoOlmMachine)?;

            // TODO: This should remove the old stored key and version.
            olm_machine.backup_machine().disable_backup().await?;

            olm_machine
                .backup_machine()
                .save_decryption_key(Some(decryption_key), Some(version))
                .await?;

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

        self.set_state(BackupState::Disabling);

        let future = async {
            let olm_machine = self.client.olm_machine().await;
            let olm_machine = olm_machine.as_ref().ok_or(crate::Error::NoOlmMachine)?;

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

    pub(crate) async fn setup_and_resume(&self) -> Result<(), crate::Error> {
        info!("Setting up secret listeners and trying to resume backups");

        // TODO: We have a nice [`OlmMachine::store()::secrets_strea()`] which we could
        // use instead of a event handler.
        self.client.add_event_handler(Self::secret_send_event_handler);
        self.maybe_resume_backups().await?;

        Ok(())
    }

    #[instrument(skip_all)]
    pub(crate) async fn maybe_enable_backups(
        &self,
        maybe_recovery_key: &str,
    ) -> Result<bool, crate::Error> {
        let _guard = self.client.locks().backup_modify_lock.lock().await;

        self.set_state(BackupState::Enabling);

        let olm_machine = self.client.olm_machine().await;
        let olm_machine = olm_machine.as_ref().ok_or(crate::Error::NoOlmMachine)?;

        let decryption_key = BackupDecryptionKey::from_base64(maybe_recovery_key).map_err(|e| {
            serde_json::Error::custom(format!("Couldn't deserialize the backup key: {e:?}"))
        })?;

        let current_version = self.get_current_version().await?;

        let Some(current_version) = current_version else { todo!() };

        Span::current().record("backup_version", &current_version.version);

        let backup_info: RoomKeyBackupInfo = current_version.algorithm.deserialize_as()?;
        let stored_keys = olm_machine.backup_machine().get_backup_keys().await?;

        let ret = if stored_keys.backup_version.as_ref() == Some(&current_version.version)
            && self.is_enabled().await
        {
            self.set_state(BackupState::Enabled);
            return Ok(true);
        } else if decryption_key.backup_key_matches(&backup_info) {
            info!(
                "We have found the correct backup recovery key, storing the backup recovery key \
                 and enabling backups"
            );

            let backup_key = decryption_key.megolm_v1_public_key();
            backup_key.set_version(current_version.version.to_owned());

            olm_machine
                .backup_machine()
                .save_decryption_key(
                    Some(decryption_key.to_owned()),
                    Some(current_version.version.to_owned()),
                )
                .await?;
            olm_machine.backup_machine().enable_backup_v1(backup_key).await?;

            // TODO: Download all keys now, or just leave this task for
            // when we have a decryption failure?
            self.set_state(BackupState::Downloading);

            if let Err(_e) =
                self.download_all_room_keys(decryption_key, current_version.version).await
            {
                // TODO: Log a warning here?
            }

            self.maybe_trigger_backup();

            self.set_state(BackupState::Enabled);

            true
        } else {
            let derived_key = decryption_key.megolm_v1_public_key();
            let downloaded_key = current_version.algorithm;

            warn!(
                ?derived_key,
                ?downloaded_key,
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
        let olm_machine = olm_machine.as_ref().ok_or(crate::Error::NoOlmMachine)?;

        let current_version = self.get_current_version().await?;

        let Some(current_version) = current_version else { todo!() };

        let backup_info: RoomKeyBackupInfo = current_version.algorithm.deserialize_as()?;

        if decryption_key.backup_key_matches(&backup_info) {
            let backup_key = decryption_key.megolm_v1_public_key();
            self.enable(olm_machine, backup_key).await?;

            if let Some(version) = version {
                if current_version.version != version {
                    olm_machine
                        .backup_machine()
                        .save_decryption_key(None, Some(current_version.version.to_owned()))
                        .await?;
                }
            }

            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn get_current_version(
        &self,
    ) -> Result<Option<get_latest_backup_info::v3::Response>, crate::Error> {
        let request = get_latest_backup_info::v3::Request::new();

        match self.client.send(request, None).await {
            Ok(r) => Ok(Some(r)),
            Err(e) => {
                if let Some(kind) = e.client_api_error_kind() {
                    if kind == &ErrorKind::NotFound {
                        Ok(None)
                    } else {
                        Err(e.into())
                    }
                } else {
                    Err(e.into())
                }
            }
        }
    }

    async fn resume_backup_from_stored_backup_key(
        &self,
        olm_machine: &OlmMachine,
    ) -> Result<bool, crate::Error> {
        let backup_keys = olm_machine.store().load_backup_keys().await?;

        if let Some(decryption_key) = backup_keys.decryption_key {
            self.maybe_resume_backup_from_decryption_key(decryption_key, backup_keys.backup_version)
                .await
        } else {
            Ok(false)
        }
    }

    async fn maybe_resume_from_secret_inbox(
        &self,
        olm_machine: &OlmMachine,
    ) -> Result<(), crate::Error> {
        let secrets = olm_machine.store().get_secrets_from_inbox(&SecretName::RecoveryKey).await?;

        for secret in secrets {
            if self.handle_received_secret(secret).await? {
                break;
            }
        }

        olm_machine.store().delete_secrets_from_inbox(&SecretName::RecoveryKey).await?;

        Ok(())
    }

    /// Check and re-enable a backup if we have a backup recovery key locally.
    async fn maybe_resume_backups(&self) -> Result<(), crate::Error> {
        let olm_machine = self.client.olm_machine().await;
        let olm_machine = olm_machine.as_ref().ok_or(crate::Error::NoOlmMachine)?;

        // Let us first check if we have a stored backup recovery key and a backup
        // version.
        if !self.resume_backup_from_stored_backup_key(olm_machine).await? {
            // We didn't manage to enable backups from a stored backup recovery key, let us
            // check our secret inbox. Perhaps we can find a valid key there.
            self.maybe_resume_from_secret_inbox(olm_machine).await?;
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
            if let Err(_e) =
                client.encryption().backups().maybe_resume_from_secret_inbox(olm_machine).await
            {
                // TODO: Log a warning here.
            }
        }
    }

    pub(crate) async fn handle_received_secret(
        &self,
        secret: GossippedSecret,
    ) -> Result<bool, crate::Error> {
        if secret.secret_name == SecretName::RecoveryKey {
            if self.maybe_enable_backups(&secret.event.content.secret).await? {
                let olm_machine = self.client.olm_machine().await;
                let olm_machine = olm_machine.as_ref().ok_or(crate::Error::NoOlmMachine)?;
                olm_machine.store().delete_secrets_from_inbox(&secret.secret_name).await?;

                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    pub(crate) fn maybe_trigger_backup(&self) {
        let tasks = self.client.inner.tasks.lock().unwrap();

        if let Some(tasks) = tasks.as_ref() {
            tasks.upload_room_keys.trigger_upload();
        }
    }

    pub(crate) async fn backup_room_keys(&self) -> Result<(), crate::Error> {
        // TODO: Lock this, so we're uploading only one per client.

        let olm_machine = self.client.olm_machine().await;
        let olm_machine = olm_machine.as_ref().ok_or(crate::Error::NoOlmMachine)?;

        let old_counts = olm_machine.backup_machine().room_key_counts().await?;

        self.client
            .inner
            .backups_state
            .upload_progress
            .set(UploadState::CheckingIfUploadNeeded(old_counts));

        while let Some((request_id, request)) = olm_machine.backup_machine().backup().await? {
            trace!(%request_id, "Uploading some room keys");

            let request = ruma::api::client::backup::add_backup_keys::v3::Request::new(
                request.version,
                request.rooms,
            );

            let response = self.client.send(request, Default::default()).await?;

            olm_machine.mark_request_as_sent(&request_id, &response).await?;

            let new_counts = olm_machine.backup_machine().room_key_counts().await?;

            self.client.inner.backups_state.upload_progress.set(UploadState::Uploading(new_counts));

            #[cfg(not(target_arch = "wasm32"))]
            tokio::time::sleep(self.client.inner.backups_state.upload_delay).await;
        }

        self.client.inner.backups_state.upload_progress.set(UploadState::Done);

        Ok(())
    }

    async fn handle_downloaded_room_keys(
        &self,
        backed_up_keys: get_backup_keys::v3::Response,
        backup_decryption_key: BackupDecryptionKey,
        olm_machine: &OlmMachine,
    ) -> Result<(), crate::Error> {
        let mut decrypted_room_keys: BTreeMap<_, BTreeMap<_, _>> = BTreeMap::new();

        for (room_id, room_keys) in backed_up_keys.rooms {
            for (session_id, room_key) in room_keys.sessions {
                // TODO: Log that we're skipping some keys here.
                let Ok(room_key) = room_key.deserialize() else { continue };

                let Ok(room_key) =
                    backup_decryption_key.decrypt_session_data(room_key.session_data)
                else {
                    continue;
                };
                let Ok(room_key) = serde_json::from_slice(&room_key) else { continue };

                decrypted_room_keys
                    .entry(room_id.to_owned())
                    .or_default()
                    .insert(session_id, room_key);
            }
        }

        olm_machine
            .backup_machine()
            .import_backed_up_room_keys(decrypted_room_keys, |_, _| {})
            .await?;

        Ok(())
    }

    pub async fn download_room_keys_for_room(
        &self,
        room_id: OwnedRoomId,
    ) -> Result<(), crate::Error> {
        let olm_machine = self.client.olm_machine().await;
        let olm_machine = olm_machine.as_ref().ok_or(crate::Error::NoOlmMachine)?;

        let backup_keys = olm_machine.store().load_backup_keys().await?;

        if let Some(decryption_key) = backup_keys.decryption_key {
            if let Some(version) = backup_keys.backup_version {
                let request =
                    get_backup_keys_for_room::v3::Request::new(version, room_id.to_owned());
                let response = self.client.send(request, Default::default()).await?;
                let response = get_backup_keys::v3::Response::new(BTreeMap::from([(
                    room_id,
                    RoomKeyBackup::new(response.sessions),
                )]));

                self.handle_downloaded_room_keys(response, decryption_key, olm_machine).await?;
            }
        }

        Ok(())
    }

    pub async fn download_room_key(
        &self,
        room_id: OwnedRoomId,
        session_id: String,
    ) -> Result<(), crate::Error> {
        let olm_machine = self.client.olm_machine().await;
        let olm_machine = olm_machine.as_ref().ok_or(crate::Error::NoOlmMachine)?;

        let backup_keys = olm_machine.store().load_backup_keys().await?;

        if let Some(decryption_key) = backup_keys.decryption_key {
            if let Some(version) = backup_keys.backup_version {
                let request = get_backup_keys_for_session::v3::Request::new(
                    version,
                    room_id.to_owned(),
                    session_id.to_owned(),
                );
                let response = self.client.send(request, Default::default()).await?;
                let response = get_backup_keys::v3::Response::new(BTreeMap::from([(
                    room_id,
                    RoomKeyBackup::new(BTreeMap::from([(session_id, response.key_data)])),
                )]));

                self.handle_downloaded_room_keys(response, decryption_key, olm_machine).await?;
            }
        }

        Ok(())
    }

    pub async fn download_all_room_keys(
        &self,
        decryption_key: BackupDecryptionKey,
        version: String,
    ) -> Result<(), crate::Error> {
        let request = get_backup_keys::v3::Request::new(version);
        let response = self.client.send(request, Default::default()).await?;

        let olm_machine = self.client.olm_machine().await;
        let olm_machine = olm_machine.as_ref().ok_or(crate::Error::NoOlmMachine)?;

        self.handle_downloaded_room_keys(response, decryption_key, olm_machine).await?;

        Ok(())
    }

    pub fn state_stream(
        &self,
    ) -> impl Stream<Item = Result<BackupState, BroadcastStreamRecvError>> {
        self.client.inner.backups_state.global_state.subscribe()
    }

    pub fn state(&self) -> BackupState {
        self.client.inner.backups_state.global_state.get()
    }

    pub(crate) async fn is_enabled(&self) -> bool {
        let olm_machine = self.client.olm_machine().await;

        if let Some(machine) = olm_machine.as_ref() {
            machine.backup_machine().enabled().await
        } else {
            false
        }
    }

    pub(crate) async fn exists_on_server(&self) -> Result<bool, crate::Error> {
        Ok(self.get_current_version().await?.is_some())
    }
}
