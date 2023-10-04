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

use std::collections::BTreeMap;

use matrix_sdk_base::crypto::{
    olm::BackedUpRoomKey, store::BackupDecryptionKey, types::RoomKeyBackupInfo, GossippedSecret,
    OlmMachine,
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
use tracing::{info, instrument, trace, warn};

use crate::Client;

#[derive(Debug)]
pub struct Backups {
    pub(super) client: Client,
}

impl Backups {
    pub async fn create_or_reset(&self) -> Result<(), crate::Error> {
        let decryption_key = BackupDecryptionKey::new().unwrap();

        let backup_key = decryption_key.megolm_v1_public_key();
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
        olm_machine.backup_machine().enable_backup_v1(backup_key).await?;

        Ok(())
    }

    pub(crate) async fn setup(&self) -> Result<(), crate::Error> {
        info!("Setting up secret listeners and trying to resume backups");

        self.client.add_event_handler(Self::secret_send_event_handler);
        self.maybe_resume_backups().await?;

        Ok(())
    }

    #[instrument]
    pub(crate) async fn maybe_enable_backups(
        &self,
        maybe_recovery_key: &str,
    ) -> Result<bool, crate::Error> {
        let olm_machine = self.client.olm_machine().await;
        let olm_machine = olm_machine.as_ref().ok_or(crate::Error::NoOlmMachine).unwrap();

        let decryption_key = BackupDecryptionKey::from_base64(maybe_recovery_key).unwrap();

        let current_version = self.get_current_version().await;
        let backup_info: RoomKeyBackupInfo = current_version.algorithm.deserialize_as().unwrap();

        let ret = if decryption_key.backup_key_matches(&backup_info) {
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
                    self.download_all_room_keys(decryption_key, current_version.version).await;
                    self.maybe_trigger_backup();

                    true
                } else {
                    warn!("Found an active backup but the backup is not trusted.");

                    false
                }
            } else {
                false
            }
        } else {
            warn!(
                "Found an active backup but the recovery key we received isn't the one used in \
                 this backup version"
            );

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

    pub(crate) async fn backup_room_keys(&self) -> Result<(), crate::Error> {
        // TODO: Lock this, so we're uploading only one per client.

        let olm_machine = self.client.olm_machine().await;
        let olm_machine = olm_machine.as_ref().ok_or(crate::Error::NoOlmMachine).unwrap();

        while let Some((request_id, request)) = olm_machine.backup_machine().backup().await? {
            trace!(%request_id, "Uploading some room keys");

            let request = ruma::api::client::backup::add_backup_keys::v3::Request::new(
                request.version,
                request.rooms,
            );

            let response = self.client.send(request, Default::default()).await?;

            olm_machine.mark_request_as_sent(&request_id, &response).await?;
            // TODO: Should we sleep for a bit after every loop iteration?
        }

        Ok(())
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

    pub async fn is_enabled(&self) -> bool {
        let olm_machine = self.client.olm_machine().await;
        let Some(olm_machine) = olm_machine.as_ref() else { return false };

        olm_machine.backup_machine().enabled().await
    }
}
