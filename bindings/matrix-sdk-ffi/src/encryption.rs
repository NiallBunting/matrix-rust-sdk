use std::sync::Arc;

use futures_util::{pin_mut, StreamExt};
use matrix_sdk::encryption::backups;

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

    pub async fn disable_backups(&self) -> Result<(), ClientError> {
        // TODO: This should delete the 4S stuff as well.
        Ok(self.inner.backups().disable().await?)
    }

    pub async fn enable_backups(&self) -> Result<(), ClientError> {
        // TODO: This should create a new secret storage key.
        Ok(self.inner.backups().create().await?)
    }
}
