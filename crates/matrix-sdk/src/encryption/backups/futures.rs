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

use futures_core::{Future, Stream};
use futures_util::StreamExt;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tracing::trace;

use super::{Backups, ChannelObservable, UploadState};

#[derive(Debug)]
pub struct WaitForSteadyState<'a> {
    pub(super) backups: &'a Backups,
    pub(super) progress: ChannelObservable<UploadState>,
    pub(super) timeout: Option<Duration>,
}

impl<'a> WaitForSteadyState<'a> {
    pub fn subscribe_to_progress(
        &self,
    ) -> impl Stream<Item = Result<UploadState, BroadcastStreamRecvError>> {
        self.progress.subscribe()
    }

    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.timeout = Some(delay);

        self
    }
}

impl<'a> IntoFuture for WaitForSteadyState<'a> {
    type Output = ();
    #[cfg(target_arch = "wasm32")]
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output + 'a>>>;
    #[cfg(not(target_arch = "wasm32"))]
    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            let Self { backups, timeout, progress } = self;

            let mut stream = progress.subscribe();

            // TODO: Set the delay here
            if let Some(_delay) = timeout {
                let _old_delay = backups.client.inner.backups_state.upload_delay;
            }

            trace!("Waiting for the upload steady state");

            backups.maybe_trigger_backup();

            // TODO: Do we want to be smart here and remember the count when we started
            // waiting and prevent the total from increasing, in case new room
            // keys arrive after we started waiting.
            while let Some(state) = stream.next().await {
                trace!(?state, "Update state while waiting for the backup steady state");

                match state {
                    Ok(UploadState::Done) => break,
                    Err(_) => break,
                    _ => (),
                }
            }

            // TODO: Reset the delay here.
        })
    }
}
