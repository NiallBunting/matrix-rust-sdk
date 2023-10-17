use std::sync::Arc;

use futures_util::{pin_mut, StreamExt};
use matrix_sdk::encryption::{backups, recovery};

use super::RUNTIME;
use crate::{error::ClientError, task_handle::TaskHandle};

#[derive(uniffi::Object)]
pub struct Encryption {
    inner: matrix_sdk::encryption::Encryption,
}

impl From<matrix_sdk::encryption::Encryption> for Encryption {
    fn from(value: matrix_sdk::encryption::Encryption) -> Self {
        Self { inner: value }
    }
}

#[uniffi::export(callback_interface)]
pub trait BackupStateListener: Sync + Send {
    fn on_update(&self, status: BackupState);
}

#[derive(uniffi::Enum)]
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

impl From<backups::BackupState> for BackupState {
    fn from(value: backups::BackupState) -> Self {
        match value {
            backups::BackupState::Unknown => BackupState::Unknown,
            backups::BackupState::Creating => BackupState::Creating,
            backups::BackupState::Enabling => BackupState::Enabling,
            backups::BackupState::Resuming => BackupState::Resuming,
            backups::BackupState::Enabled => BackupState::Enabled,
            backups::BackupState::Downloading => BackupState::Downloading,
            backups::BackupState::Disabling => BackupState::Disabling,
            backups::BackupState::Disabled => BackupState::Disabled,
        }
    }
}

#[uniffi::export(callback_interface)]
pub trait EnableProgressListener: Sync + Send {
    fn on_update(&self, status: EnableProgress);
}

#[derive(uniffi::Enum)]
pub enum EnableProgress {
    CreatingBackup,
    CreatingRecoveryKey,
    BackingUp { backed_up_count: u32, total_count: u32 },
    Done { recovery_key: String },
}

impl From<recovery::EnableProgress> for EnableProgress {
    fn from(value: recovery::EnableProgress) -> Self {
        match &value {
            recovery::EnableProgress::CreatingBackup => Self::CreatingBackup,
            recovery::EnableProgress::CreatingRecoveryKey => Self::CreatingRecoveryKey,
            recovery::EnableProgress::BackingUp(counts) => Self::BackingUp {
                backed_up_count: counts.backed_up.try_into().unwrap_or(u32::MAX),
                total_count: counts.backed_up.try_into().unwrap_or(u32::MAX),
            },
            recovery::EnableProgress::Done { recovery_key } => {
                Self::Done { recovery_key: recovery_key.to_owned() }
            }
        }
    }
}

#[uniffi::export]
impl Encryption {
    pub fn backup_state_listener(&self, listener: Box<dyn BackupStateListener>) -> Arc<TaskHandle> {
        let stream = self.inner.backups().state_stream();

        let stream_task = TaskHandle::new(RUNTIME.spawn(async move {
            pin_mut!(stream);

            while let Some(state) = stream.next().await {
                listener.on_update(state.into());
            }
        }));

        stream_task.into()
    }

    pub fn backup_state(&self) -> BackupState {
        self.inner.backups().state().into()
    }

    pub async fn enable_backups(&self) -> Result<(), ClientError> {
        Ok(self.inner.recovery().enable_backup().await?)
    }

    pub async fn is_last_device(&self) -> Result<bool, ClientError> {
        Ok(self.inner.recovery().are_we_the_last_man_standing().await?)
    }

    pub async fn enable_recovery(
        &self,
        wait_for_backups_to_upload: bool,
        progress_listener: Box<dyn EnableProgressListener>,
    ) -> Result<String, ClientError> {
        let recovery = self.inner.recovery();

        let enable = if wait_for_backups_to_upload {
            recovery.enable().wait_for_backups_to_upload()
        } else {
            recovery.enable()
        };

        let mut progress_stream = enable.subscribe_to_progress();

        let task = RUNTIME.spawn(async move {
            while let Some(progress) = progress_stream.next().await {
                progress_listener.on_update(progress.into());
            }
        });

        let ret = enable.await?;

        // TODO: Do we need to abort the task manually?
        task.abort();

        Ok(ret)
    }

    pub async fn disable_recovery(&self) -> Result<(), ClientError> {
        Ok(self.inner.recovery().disable().await?)
    }

    pub async fn reset_recovery_key(&self) -> Result<String, ClientError> {
        // TODO: This works even if we don't have all secrets on this device. Add
        // another method which resets the key but requires the old key?
        //
        // What does the user even do if they don't remember the old key 🫠
        Ok(self.inner.recovery().reset_key(None).await?)
    }
}
