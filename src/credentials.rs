use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use keyring::{Entry, Error as KeyringError};

use crate::models::SecretPayload;

/// Keychain 访问超时时间（秒）
const KEYRING_TIMEOUT_SECS: u64 = 5;

#[derive(Clone)]
pub struct SecretStore {
    service_name: String,
    backend: Arc<dyn CredentialBackend>,
}

pub(crate) trait CredentialBackend: Send + Sync {
    fn set_password(&self, service_name: &str, account: &str, payload: &str) -> Result<()>;
    fn get_password(&self, service_name: &str, account: &str) -> Result<Option<String>>;
    fn delete_password(&self, service_name: &str, account: &str) -> Result<()>;
}

struct KeyringBackend;

impl CredentialBackend for KeyringBackend {
    fn set_password(&self, service_name: &str, account: &str, payload: &str) -> Result<()> {
        let entry =
            Entry::new(service_name, account).context("failed to initialize keyring entry")?;
        let payload = payload.to_string();

        let (tx, rx) = std::sync::mpsc::channel();
        let timeout = Duration::from_secs(KEYRING_TIMEOUT_SECS);

        std::thread::spawn(move || {
            let result = entry.set_password(&payload);
            let _ = tx.send(result);
        });

        match rx.recv_timeout(timeout) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => Err(err).context("failed to store keychain secret"),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(anyhow::anyhow!(
                "keyring save timed out after {}s",
                KEYRING_TIMEOUT_SECS
            )),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(anyhow::anyhow!(
                "keyring save thread terminated unexpectedly"
            )),
        }
    }

    fn get_password(&self, service_name: &str, account: &str) -> Result<Option<String>> {
        let entry =
            Entry::new(service_name, account).context("failed to initialize keyring entry")?;

        let (tx, rx) = std::sync::mpsc::channel();
        let timeout = Duration::from_secs(KEYRING_TIMEOUT_SECS);

        std::thread::spawn(move || {
            let result = entry.get_password();
            let _ = tx.send(result);
        });

        match rx.recv_timeout(timeout) {
            Ok(Ok(payload)) => Ok(Some(payload)),
            Ok(Err(KeyringError::NoEntry)) => Ok(None),
            Ok(Err(err)) => Err(err).context("failed to load keychain secret"),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(anyhow::anyhow!(
                "keyring access timed out after {}s",
                KEYRING_TIMEOUT_SECS
            )),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(anyhow::anyhow!(
                "keyring access thread terminated unexpectedly"
            )),
        }
    }

    fn delete_password(&self, service_name: &str, account: &str) -> Result<()> {
        let entry =
            Entry::new(service_name, account).context("failed to initialize keyring entry")?;

        let (tx, rx) = std::sync::mpsc::channel();
        let timeout = Duration::from_secs(KEYRING_TIMEOUT_SECS);

        std::thread::spawn(move || {
            let result = entry.delete_credential();
            let _ = tx.send(result);
        });

        match rx.recv_timeout(timeout) {
            Ok(Ok(_) | Err(KeyringError::NoEntry)) => Ok(()),
            Ok(Err(err)) => Err(err).context("failed to delete keychain secret"),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(anyhow::anyhow!(
                "keyring delete timed out after {}s",
                KEYRING_TIMEOUT_SECS
            )),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(anyhow::anyhow!(
                "keyring delete thread terminated unexpectedly"
            )),
        }
    }
}

impl SecretStore {
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
            backend: Arc::new(KeyringBackend),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_backend(
        service_name: impl Into<String>,
        backend: Arc<dyn CredentialBackend>,
    ) -> Self {
        Self {
            service_name: service_name.into(),
            backend,
        }
    }

    pub fn save_secret(&self, instance_id: &str, secret: &SecretPayload) -> Result<()> {
        let payload = serde_json::to_string(secret).context("failed to serialize secret")?;
        self.backend
            .set_password(&self.service_name, instance_id, &payload)
            .with_context(|| format!("failed to store secret for '{}'", instance_id))
    }

    pub fn load_secret(&self, instance_id: &str) -> Result<Option<SecretPayload>> {
        match self
            .backend
            .get_password(&self.service_name, instance_id)
            .with_context(|| format!("failed to load secret for '{}'", instance_id))?
        {
            Some(payload) => {
                let secret = serde_json::from_str(&payload)
                    .with_context(|| format!("failed to decode secret for '{}'", instance_id))?;
                Ok(Some(secret))
            }
            None => Ok(None),
        }
    }

    pub fn delete_secret(&self, instance_id: &str) -> Result<()> {
        self.backend
            .delete_password(&self.service_name, instance_id)
            .with_context(|| format!("failed to delete secret for '{}'", instance_id))
    }

    pub fn has_secret(&self, instance_id: &str) -> Result<bool> {
        Ok(self.load_secret(instance_id)?.is_some())
    }
}
