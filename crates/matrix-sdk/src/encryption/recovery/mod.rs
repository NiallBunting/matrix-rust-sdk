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
//! backups, while the term recovery in this file includes both the backup
//! recovery key and the secret storage key.
//!
//! [`Recovery key`]: https://spec.matrix.org/v1.8/client-server-api/#recovery-key

use ruma::{
    events::{EventContent, GlobalAccountDataEventType},
    exports::ruma_macros::EventContent,
};
use serde::{Deserialize, Serialize};

use crate::{Client, Result};

mod futures;

pub use futures::{Enable, EnableProgress};

#[derive(Clone, Debug, Default, Deserialize, Serialize, EventContent)]
#[ruma_event(type = "m.org.matrix.custom.recovery_disabled", kind = GlobalAccountData)]
struct RecoveryDisabledEventContent {
    disabled: bool,
}

impl RecoveryDisabledEventContent {
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
    /// Enable recovery if it isn't already enabled.
    pub fn enable(&self) -> Enable<'_> {
        // TODO: How to only allow this to be called if you are the only/last device
        // this user has?
        Enable {
            recovery: self,
            progress: Default::default(),
            wait_for_backups_upload: false,
            create_new_backup: false,
            passphrase: Default::default(),
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

    /// Reset the recovery key.
    ///
    /// This will rotate the secret storage key and re-upload all the secrets to
    /// the [`SecretStore`].
    pub async fn reset_key(&self, passphrase: Option<&str>) -> Result<Option<String>> {
        // Only do this if we have all the secrets at hand:
        //
        // 1. Cross-signing keys
        // 2. Backup recovery key

        // TODO: The `true` here should be replaced with a call to a
        // `do_we_have_all_the_secrets_locally()` method.
        if true {
            let mut enable = self.enable();
            enable.passphrase = passphrase;

            let recovery_key = enable.await?;

            Ok(Some(recovery_key))
        } else {
            // TODO: The else case should open the currently active secret store, the user
            // needs to enter the recovery key, wait a minute!?!? Another case
            // where we do ENTER the existing recovery key??! The product requirement doc
            // tells us this:
            // > Requires the device to be trusted. Otherwise an existing recovery key is required.
            //
            // What happens if you don't know the recovery key and are not a trusted device
            // and are the last device?!?
            Ok(None)
        }
    }

    /// Automatically do the following:
    ///
    /// 1. Bootstrap cross-signing keys, if it wasn't already done so.
    /// 2. Create and enable a backup version if there isn't a currently active
    ///    one.
    pub(crate) async fn auto_enable(&self) -> Result<()> {
        if self.is_globally_disabled().await? {
            return Ok(());
        }

        // TODO: Do the enabling.

        Ok(())
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

    async fn is_globally_disabled(&self) -> Result<bool> {
        Ok(self
            .client
            .account()
            .fetch_account_data(RecoveryDisabledEventContent::event_type())
            .await?
            .map(|event| {
                event
                    .deserialize_as::<RecoveryDisabledEventContent>()
                    .map(|event| event.disabled)
                    .unwrap_or(false)
            })
            .unwrap_or(false))
    }

    async fn mark_as_globally_enabled(&self) -> Result<()> {
        self.client
            .account()
            .set_account_data(RecoveryDisabledEventContent { disabled: false })
            .await?;

        // TODO: We need to listen for this event over `/sync` and if we notice that it
        // got toggled to `true`, we should re-request the missing secrets over
        // `m.secret.send`. Of course, this should only happen if we are verified.

        Ok(())
    }

    async fn mark_as_globally_disabled(&self) -> Result<()> {
        // Why oh why, can't we delete account data events?
        self.client
            .account()
            .set_account_data(RecoveryDisabledEventContent { disabled: true })
            .await?;

        Ok(())
    }
}
