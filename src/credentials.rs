use anyhow::{Context, Result};
use keyring::{Entry, Error as KeyringError};

use crate::models::SecretPayload;

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
        entry
            .set_password(&payload)
            .with_context(|| format!("failed to store secret for '{}'", instance_id))?;
        Ok(())
    }

    pub fn load_secret(&self, instance_id: &str) -> Result<Option<SecretPayload>> {
        let entry = self.entry(instance_id)?;
        match entry.get_password() {
            Ok(payload) => {
                let secret = serde_json::from_str(&payload)
                    .with_context(|| format!("failed to decode secret for '{}'", instance_id))?;
                Ok(Some(secret))
            }
            Err(KeyringError::NoEntry) => Ok(None),
            Err(err) => Err(err).with_context(|| format!("failed to load secret for '{}'", instance_id)),
        }
    }

    pub fn delete_secret(&self, instance_id: &str) -> Result<()> {
        let entry = self.entry(instance_id)?;
        match entry.delete_credential() {
            Ok(_) | Err(KeyringError::NoEntry) => Ok(()),
            Err(err) => Err(err)
                .with_context(|| format!("failed to delete secret for '{}'", instance_id)),
        }
    }

    pub fn has_secret(&self, instance_id: &str) -> Result<bool> {
        Ok(self.load_secret(instance_id)?.is_some())
    }

    fn entry(&self, instance_id: &str) -> Result<Entry> {
        Entry::new(&self.service_name, instance_id).context("failed to initialize keyring entry")
    }
}
