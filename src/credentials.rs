use std::time::Duration;

use anyhow::{Context, Result};
use keyring::{Entry, Error as KeyringError};

use crate::models::SecretPayload;

/// Keychain 访问超时时间（秒）
const KEYRING_TIMEOUT_SECS: u64 = 5;

#[derive(Clone)]
pub struct SecretStore {
    service_name: String,
}

impl SecretStore {
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
        }
    }

    pub fn save_secret(&self, instance_id: &str, secret: &SecretPayload) -> Result<()> {
        let entry = self.entry(instance_id)?;
        let payload = serde_json::to_string(secret).context("failed to serialize secret")?;

        // 使用独立线程 + 超时来访问 Keychain
        let (tx, rx) = std::sync::mpsc::channel();
        let timeout = Duration::from_secs(KEYRING_TIMEOUT_SECS);

        std::thread::spawn(move || {
            let result = entry.set_password(&payload);
            let _ = tx.send(result);
        });

        match rx.recv_timeout(timeout) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => {
                Err(err).with_context(|| format!("failed to store secret for '{}'", instance_id))
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(anyhow::anyhow!(
                "keyring save timed out after {}s",
                KEYRING_TIMEOUT_SECS
            )),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(anyhow::anyhow!(
                "keyring save thread terminated unexpectedly"
            )),
        }
    }

    pub fn load_secret(&self, instance_id: &str) -> Result<Option<SecretPayload>> {
        let entry = self.entry(instance_id)?;

        // 使用独立线程 + 超时来访问 Keychain，避免 macOS 弹框阻塞 MCP 主循环
        let instance_id_owned = instance_id.to_string();
        let (tx, rx) = std::sync::mpsc::channel();
        let timeout = Duration::from_secs(KEYRING_TIMEOUT_SECS);

        std::thread::spawn(move || {
            let result = entry.get_password();
            let _ = tx.send(result);
        });

        match rx.recv_timeout(timeout) {
            Ok(Ok(payload)) => {
                let secret = serde_json::from_str(&payload).with_context(|| {
                    format!("failed to decode secret for '{}'", instance_id_owned)
                })?;
                Ok(Some(secret))
            }
            Ok(Err(KeyringError::NoEntry)) => Ok(None),
            Ok(Err(err)) => Err(err)
                .with_context(|| format!("failed to load secret for '{}'", instance_id_owned)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(anyhow::anyhow!(
                "keyring access timed out after {}s",
                KEYRING_TIMEOUT_SECS
            )),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(anyhow::anyhow!(
                "keyring access thread terminated unexpectedly"
            )),
        }
    }

    pub fn delete_secret(&self, instance_id: &str) -> Result<()> {
        let entry = self.entry(instance_id)?;

        // 使用独立线程 + 超时来访问 Keychain
        let instance_id_owned = instance_id.to_string();
        let (tx, rx) = std::sync::mpsc::channel();
        let timeout = Duration::from_secs(KEYRING_TIMEOUT_SECS);

        std::thread::spawn(move || {
            let result = entry.delete_credential();
            let _ = tx.send(result);
        });

        match rx.recv_timeout(timeout) {
            Ok(Ok(_) | Err(KeyringError::NoEntry)) => Ok(()),
            Ok(Err(err)) => Err(err)
                .with_context(|| format!("failed to delete secret for '{}'", instance_id_owned)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(anyhow::anyhow!(
                "keyring delete timed out after {}s",
                KEYRING_TIMEOUT_SECS
            )),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(anyhow::anyhow!(
                "keyring delete thread terminated unexpectedly"
            )),
        }
    }

    pub fn has_secret(&self, instance_id: &str) -> Result<bool> {
        Ok(self.load_secret(instance_id)?.is_some())
    }

    fn entry(&self, instance_id: &str) -> Result<Entry> {
        Entry::new(&self.service_name, instance_id).context("failed to initialize keyring entry")
    }
}
