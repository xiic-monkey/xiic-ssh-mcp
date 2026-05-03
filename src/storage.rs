use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};

use crate::models::{AuthKind, InstanceDraft, SecretPayload, StoredInstance};

#[derive(Clone)]
pub struct InstanceStore {
    db_path: PathBuf,
}

impl InstanceStore {
    pub fn new(db_path: PathBuf) -> Result<Self> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create '{}'", parent.display()))?;
        }

        let store = Self { db_path };
        store.init_schema()?;
        Ok(store)
    }

    pub fn list_instances(&self) -> Result<Vec<StoredInstance>> {
        let connection = self.open()?;
        let mut statement = connection.prepare(
            "SELECT instance_id, name, host, port, username, auth_kind, host_key_check, notes, created_at, updated_at
             FROM instances
             ORDER BY name COLLATE NOCASE ASC, instance_id COLLATE NOCASE ASC",
        )?;

        let rows = statement.query_map([], map_instance_row)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to list instances")
    }

    pub fn get_instance(&self, instance_id: &str) -> Result<Option<StoredInstance>> {
        let connection = self.open()?;
        let mut statement = connection.prepare(
            "SELECT instance_id, name, host, port, username, auth_kind, host_key_check, notes, created_at, updated_at
             FROM instances
             WHERE instance_id = ?1",
        )?;

        let result = statement.query_row([instance_id], map_instance_row);
        match result {
            Ok(instance) => Ok(Some(instance)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(err).context("failed to load instance"),
        }
    }

    pub fn save_instance(&self, draft: &InstanceDraft) -> Result<StoredInstance> {
        let connection = self.open()?;
        let now = Utc::now().to_rfc3339();
        let existing = self.get_instance(&draft.instance_id)?;
        let created_at = existing
            .as_ref()
            .map(|instance| instance.created_at.to_rfc3339())
            .unwrap_or_else(|| now.clone());

        connection.execute(
            "INSERT INTO instances (
                instance_id, name, host, port, username, auth_kind, host_key_check, notes, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(instance_id) DO UPDATE SET
                name = excluded.name,
                host = excluded.host,
                port = excluded.port,
                username = excluded.username,
                auth_kind = excluded.auth_kind,
                host_key_check = excluded.host_key_check,
                notes = excluded.notes,
                updated_at = excluded.updated_at",
            params![
                draft.instance_id,
                draft.name,
                draft.host,
                i64::from(draft.port),
                draft.username,
                auth_kind_to_str(&draft.auth_kind),
                if draft.host_key_check { 1 } else { 0 },
                draft.notes,
                created_at,
                now,
            ],
        )?;

        self.get_instance(&draft.instance_id)?
            .with_context(|| format!("instance '{}' disappeared after save", draft.instance_id))
    }

    pub fn delete_instance(&self, instance_id: &str) -> Result<()> {
        let connection = self.open()?;
        connection
            .execute("DELETE FROM instances WHERE instance_id = ?1", [instance_id])
            .with_context(|| format!("failed to delete instance '{}'", instance_id))?;
        Ok(())
    }

    fn init_schema(&self) -> Result<()> {
        let connection = self.open()?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS instances (
                instance_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                username TEXT NOT NULL,
                auth_kind TEXT NOT NULL,
                host_key_check INTEGER NOT NULL DEFAULT 0,
                notes TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS instance_secrets (
                instance_id TEXT PRIMARY KEY,
                secret_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(instance_id) REFERENCES instances(instance_id) ON DELETE CASCADE
            );",
        )?;
        Ok(())
    }

    pub fn save_secret(&self, instance_id: &str, secret: &SecretPayload) -> Result<()> {
        let connection = self.open()?;
        let secret_json =
            serde_json::to_string(secret).context("failed to serialize secret payload")?;
        let now = Utc::now().to_rfc3339();

        connection.execute(
            "INSERT INTO instance_secrets (instance_id, secret_json, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(instance_id) DO UPDATE SET
                secret_json = excluded.secret_json,
                updated_at = excluded.updated_at",
            params![instance_id, secret_json, now],
        )?;

        Ok(())
    }

    pub fn load_secret(&self, instance_id: &str) -> Result<Option<SecretPayload>> {
        let connection = self.open()?;
        let mut statement = connection.prepare(
            "SELECT secret_json
             FROM instance_secrets
             WHERE instance_id = ?1",
        )?;

        let result = statement.query_row([instance_id], |row| row.get::<_, String>(0));
        match result {
            Ok(secret_json) => {
                let secret = serde_json::from_str(&secret_json)
                    .with_context(|| format!("failed to decode secret for '{}'", instance_id))?;
                Ok(Some(secret))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(err) => Err(err).context("failed to load stored secret"),
        }
    }

    pub fn delete_secret(&self, instance_id: &str) -> Result<()> {
        let connection = self.open()?;
        connection
            .execute("DELETE FROM instance_secrets WHERE instance_id = ?1", [instance_id])
            .with_context(|| format!("failed to delete secret '{}'", instance_id))?;
        Ok(())
    }

    pub fn has_secret(&self, instance_id: &str) -> Result<bool> {
        Ok(self.load_secret(instance_id)?.is_some())
    }

    fn open(&self) -> Result<Connection> {
        Connection::open(&self.db_path)
            .with_context(|| format!("failed to open SQLite database '{}'", self.db_path.display()))
    }
}

fn map_instance_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredInstance> {
    let auth_kind = auth_kind_from_str(row.get::<_, String>(5)?.as_str());
    let created_at = parse_timestamp(row.get::<_, String>(8)?.as_str())?;
    let updated_at = parse_timestamp(row.get::<_, String>(9)?.as_str())?;

    Ok(StoredInstance {
        instance_id: row.get(0)?,
        name: row.get(1)?,
        host: row.get(2)?,
        port: row.get::<_, u16>(3)?,
        username: row.get(4)?,
        auth_kind,
        host_key_check: row.get::<_, i64>(6)? != 0,
        notes: row.get(7)?,
        created_at,
        updated_at,
    })
}

fn parse_timestamp(value: &str) -> rusqlite::Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(
                value.len(),
                rusqlite::types::Type::Text,
                Box::new(err),
            )
        })
}

fn auth_kind_to_str(auth_kind: &AuthKind) -> &'static str {
    match auth_kind {
        AuthKind::Password => "password",
        AuthKind::PrivateKey => "private_key",
    }
}

fn auth_kind_from_str(value: &str) -> AuthKind {
    match value {
        "private_key" => AuthKind::PrivateKey,
        _ => AuthKind::Password,
    }
}

#[allow(dead_code)]
fn _ensure_send_sync(_: &Path) {}
