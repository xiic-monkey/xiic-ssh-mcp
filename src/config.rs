use std::collections::HashMap;
use std::env;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

const INSTANCES_ENV: &str = "SSH_MCP_INSTANCES_JSON";

#[derive(Debug, Clone, Deserialize)]
pub struct InstanceConfig {
    pub instance_id: String,
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub passphrase: Option<String>,
    #[serde(default)]
    pub host_key_check: bool,
}

impl InstanceConfig {
    pub fn validate(&self) -> Result<()> {
        if self.instance_id.trim().is_empty() {
            bail!("instance_id cannot be empty");
        }
        if self.host.trim().is_empty() {
            bail!("host cannot be empty");
        }
        if self.username.trim().is_empty() {
            bail!("username cannot be empty");
        }
        if self.password.is_none() && self.private_key.is_none() {
            bail!(
                "instance '{}' must define either password or private_key",
                self.instance_id
            );
        }
        Ok(())
    }
}

fn default_port() -> u16 {
    22
}

#[derive(Debug, Clone)]
pub struct InstanceRegistry {
    instances: HashMap<String, InstanceConfig>,
}

impl InstanceRegistry {
    pub fn from_env() -> Result<Self> {
        let raw = env::var(INSTANCES_ENV).with_context(|| {
            format!(
                "missing required environment variable {} with inline instance JSON",
                INSTANCES_ENV
            )
        })?;
        Self::from_json_str(&raw)
    }

    pub fn from_json_str(raw: &str) -> Result<Self> {
        let configs: Vec<InstanceConfig> =
            serde_json::from_str(raw).context("failed to parse instance config JSON")?;

        if configs.is_empty() {
            bail!("instance config JSON must contain at least one instance");
        }

        let mut instances = HashMap::with_capacity(configs.len());
        for config in configs {
            config.validate()?;
            if instances
                .insert(config.instance_id.clone(), config)
                .is_some()
            {
                bail!("duplicate instance_id found in instance config");
            }
        }

        Ok(Self { instances })
    }

    pub fn get(&self, instance_id: &str) -> Option<&InstanceConfig> {
        self.instances.get(instance_id)
    }
}

#[cfg(test)]
mod tests {
    use super::InstanceRegistry;

    #[test]
    fn parses_instance_registry() {
        let registry = InstanceRegistry::from_json_str(
            r#"[
                {
                    "instance_id": "prod",
                    "host": "example.com",
                    "username": "root",
                    "password": "secret"
                }
            ]"#,
        )
        .expect("config should parse");

        let instance = registry.get("prod").expect("instance should exist");
        assert_eq!(instance.port, 22);
        assert!(!instance.host_key_check);
    }

    #[test]
    fn rejects_missing_auth() {
        let err = InstanceRegistry::from_json_str(
            r#"[
                {
                    "instance_id": "prod",
                    "host": "example.com",
                    "username": "root"
                }
            ]"#,
        )
        .expect_err("config should fail");

        assert!(err.to_string().contains("either password or private_key"));
    }
}
