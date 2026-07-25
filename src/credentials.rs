use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD_NO_PAD};
use chrono::Utc;
use rusqlite::{Connection, params};

use crate::models::SecretPayload;
use crate::paths::{ensure_private_dir, ensure_private_file};

const CREDENTIAL_KEY_FILE: &str = "credentials.key";
const ENCRYPTED_SECRET_PREFIX: &str = "enc-v1:";
const MASTER_KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;

#[derive(Clone)]
pub struct SecretStore {
    db_path: PathBuf,
    cipher: Aes256Gcm,
}

impl SecretStore {
    pub fn new(db_path: PathBuf) -> Result<Self> {
        let key_path = credential_key_path(&db_path)?;
        let key = load_or_create_master_key(&key_path)?;
        let cipher = Aes256Gcm::new_from_slice(&key).expect("AES-256 key has a fixed size");
        let store = Self { db_path, cipher };
        store.migrate_plaintext_rows()?;
        Ok(store)
    }

    pub fn save_secret(&self, instance_id: &str, secret: &SecretPayload) -> Result<()> {
        let payload = serde_json::to_vec(secret).context("failed to serialize secret")?;
        let encrypted = self.encrypt(instance_id, &payload)?;
        self.open()?.execute(
            "INSERT INTO instance_secrets (instance_id, secret_json, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(instance_id) DO UPDATE SET
                secret_json = excluded.secret_json,
                updated_at = excluded.updated_at",
            params![instance_id, encrypted, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn load_secret(&self, instance_id: &str) -> Result<Option<SecretPayload>> {
        let connection = self.open()?;
        let result = connection.query_row(
            "SELECT secret_json FROM instance_secrets WHERE instance_id = ?1",
            [instance_id],
            |row| row.get::<_, String>(0),
        );
        let payload = match result {
            Ok(payload) => payload,
            Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
            Err(err) => return Err(err).context("failed to load stored secret"),
        };
        let secret = self.decode(instance_id, &payload)?;
        if !payload.starts_with(ENCRYPTED_SECRET_PREFIX) {
            self.save_secret(instance_id, &secret)?;
        }
        Ok(Some(secret))
    }

    pub fn delete_secret(&self, instance_id: &str) -> Result<()> {
        self.open()?
            .execute(
                "DELETE FROM instance_secrets WHERE instance_id = ?1",
                [instance_id],
            )
            .with_context(|| format!("failed to delete secret for '{}'", instance_id))?;
        Ok(())
    }

    pub fn has_secret(&self, instance_id: &str) -> Result<bool> {
        Ok(self.load_secret(instance_id)?.is_some())
    }

    fn migrate_plaintext_rows(&self) -> Result<()> {
        let connection = self.open()?;
        let mut statement = connection.prepare(
            "SELECT instance_id, secret_json FROM instance_secrets
             WHERE secret_json NOT LIKE 'enc-v1:%'",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let rows = rows.collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        drop(connection);

        for (instance_id, payload) in rows {
            let secret = self.decode(&instance_id, &payload)?;
            self.save_secret(&instance_id, &secret)?;
        }
        Ok(())
    }

    fn encrypt(&self, instance_id: &str, payload: &[u8]) -> Result<String> {
        let mut nonce = [0_u8; NONCE_SIZE];
        getrandom::fill(&mut nonce)
            .map_err(|err| anyhow::anyhow!("failed to generate credential nonce: {err}"))?;
        let encrypted = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: payload,
                    aad: instance_id.as_bytes(),
                },
            )
            .map_err(|_| anyhow::anyhow!("failed to encrypt credential"))?;
        let mut encoded = nonce.to_vec();
        encoded.extend_from_slice(&encrypted);
        Ok(format!(
            "{ENCRYPTED_SECRET_PREFIX}{}",
            STANDARD_NO_PAD.encode(encoded)
        ))
    }

    fn decode(&self, instance_id: &str, payload: &str) -> Result<SecretPayload> {
        let bytes = if let Some(encoded) = payload.strip_prefix(ENCRYPTED_SECRET_PREFIX) {
            let bytes = STANDARD_NO_PAD
                .decode(encoded)
                .context("credential ciphertext is not valid base64")?;
            if bytes.len() <= NONCE_SIZE {
                bail!("credential ciphertext is truncated");
            }
            self.cipher
                .decrypt(
                    Nonce::from_slice(&bytes[..NONCE_SIZE]),
                    Payload {
                        msg: &bytes[NONCE_SIZE..],
                        aad: instance_id.as_bytes(),
                    },
                )
                .map_err(|_| anyhow::anyhow!("credential ciphertext failed authentication"))?
        } else {
            payload.as_bytes().to_vec()
        };
        serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to decode secret for '{}'", instance_id))
    }

    fn open(&self) -> Result<Connection> {
        Connection::open(&self.db_path).with_context(|| {
            format!(
                "failed to open SQLite database '{}'",
                self.db_path.display()
            )
        })
    }
}

fn credential_key_path(db_path: &Path) -> Result<PathBuf> {
    let directory = db_path
        .parent()
        .context("database path does not have a parent directory")?;
    let existed = directory.exists();
    std::fs::create_dir_all(directory)?;
    if !existed {
        ensure_private_dir(directory)?;
    }
    Ok(directory.join(CREDENTIAL_KEY_FILE))
}

fn load_or_create_master_key(path: &Path) -> Result<[u8; MASTER_KEY_SIZE]> {
    if path.exists() {
        return read_master_key(path);
    }

    let mut key = [0_u8; MASTER_KEY_SIZE];
    getrandom::fill(&mut key)
        .map_err(|err| anyhow::anyhow!("failed to generate credential master key: {err}"))?;
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            use std::io::Write;

            file.write_all(&key)
                .context("failed to write credential master key")?;
            file.sync_all()
                .context("failed to sync credential master key")?;
            ensure_private_file(path)?;
            Ok(key)
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => read_master_key(path),
        Err(err) => Err(err).context("failed to create credential master key"),
    }
}

fn read_master_key(path: &Path) -> Result<[u8; MASTER_KEY_SIZE]> {
    ensure_private_file(path)?;
    let bytes = std::fs::read(path).context("failed to read credential master key")?;
    if bytes.len() != MASTER_KEY_SIZE {
        bail!("credential master key has an invalid length");
    }
    let mut key = [0_u8; MASTER_KEY_SIZE];
    key.copy_from_slice(&bytes);
    Ok(key)
}

#[cfg(test)]
mod tests {
    use std::env;

    use rusqlite::Connection;
    use uuid::Uuid;

    use super::SecretStore;
    use crate::models::SecretPayload;

    fn secret() -> SecretPayload {
        SecretPayload {
            password: Some("correct horse battery staple".to_string()),
            private_key: None,
            private_key_path: None,
            passphrase: None,
        }
    }

    fn test_paths() -> (std::path::PathBuf, std::path::PathBuf) {
        let directory = env::temp_dir().join(format!("xiic-ssh-credentials-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&directory).expect("test directory should be created");
        let db_path = directory.join("instances.sqlite3");
        (directory, db_path)
    }

    fn initialize_secret_table(db_path: &std::path::Path) {
        Connection::open(db_path)
            .expect("database should open")
            .execute_batch(
                "CREATE TABLE instance_secrets (
                    instance_id TEXT PRIMARY KEY,
                    secret_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );",
            )
            .expect("secret table should initialize");
    }

    #[test]
    fn saves_aead_ciphertext_and_round_trips() {
        let (directory, db_path) = test_paths();
        initialize_secret_table(&db_path);
        let store = SecretStore::new(db_path.clone()).expect("store should initialize");

        store
            .save_secret("prod", &secret())
            .expect("secret should save");

        let stored = Connection::open(&db_path)
            .expect("database should open")
            .query_row(
                "SELECT secret_json FROM instance_secrets WHERE instance_id = 'prod'",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("ciphertext should load");
        assert!(stored.starts_with("enc-v1:"));
        assert!(!stored.contains("correct horse battery staple"));
        assert_eq!(
            store.load_secret("prod").expect("secret should load"),
            Some(secret())
        );

        std::fs::remove_dir_all(directory).expect("test directory should be removed");
    }

    #[test]
    fn migrates_legacy_plaintext_rows_on_startup() {
        let (directory, db_path) = test_paths();
        initialize_secret_table(&db_path);
        let plaintext = serde_json::to_string(&secret()).expect("secret should serialize");
        Connection::open(&db_path)
            .expect("database should open")
            .execute(
                "INSERT INTO instance_secrets (instance_id, secret_json, updated_at)
                 VALUES ('prod', ?1, 'now')",
                [plaintext],
            )
            .expect("legacy row should insert");

        let store = SecretStore::new(db_path.clone()).expect("store should initialize");
        assert_eq!(
            store.load_secret("prod").expect("secret should load"),
            Some(secret())
        );
        let stored = Connection::open(&db_path)
            .expect("database should open")
            .query_row(
                "SELECT secret_json FROM instance_secrets WHERE instance_id = 'prod'",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("ciphertext should load");
        assert!(stored.starts_with("enc-v1:"));

        std::fs::remove_dir_all(directory).expect("test directory should be removed");
    }

    #[test]
    fn ciphertext_is_bound_to_its_instance_id() {
        let (directory, db_path) = test_paths();
        initialize_secret_table(&db_path);
        let store = SecretStore::new(db_path.clone()).expect("store should initialize");
        store
            .save_secret("prod", &secret())
            .expect("secret should save");
        let ciphertext = Connection::open(&db_path)
            .expect("database should open")
            .query_row(
                "SELECT secret_json FROM instance_secrets WHERE instance_id = 'prod'",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("ciphertext should load");
        Connection::open(&db_path)
            .expect("database should open")
            .execute(
                "INSERT INTO instance_secrets (instance_id, secret_json, updated_at)
                 VALUES ('other', ?1, 'now')",
                [ciphertext],
            )
            .expect("copied row should insert");

        assert!(store.load_secret("other").is_err());
        std::fs::remove_dir_all(directory).expect("test directory should be removed");
    }
}
