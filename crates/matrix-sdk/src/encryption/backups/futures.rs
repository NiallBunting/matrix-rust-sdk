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

use std::{future::IntoFuture, pin::Pin, time::Duration};

use eyeball::SharedObservable;
use futures_core::{Future, Stream};
use matrix_sdk_base::crypto::{store::RoomKeyCounts, OlmMachine};
use tracing::trace;

use super::Backups;

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

#[derive(Debug)]
pub struct UploadBackups<'a> {
    pub(super) backups: &'a Backups,
    pub(super) olm_machine: OlmMachine,
    pub(super) timeout: Option<Duration>,
    pub(super) progress: SharedObservable<RoomKeyCounts>,
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
