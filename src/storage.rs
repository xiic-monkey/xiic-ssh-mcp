use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};

use crate::models::{
    AuthKind, InstanceDraft, OperationLogEntry, RuleAction, RuleType, SecretPayload,
    StoredInstance, WhitelistRule,
};

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
            .execute(
                "DELETE FROM instances WHERE instance_id = ?1",
                [instance_id],
            )
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
            );

            CREATE TABLE IF NOT EXISTS operation_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT NOT NULL DEFAULT '',
                client_session_id TEXT NOT NULL DEFAULT '',
                session_id TEXT NOT NULL,
                instance_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                details TEXT,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_operation_logs_created_at ON operation_logs(created_at);
            CREATE INDEX IF NOT EXISTS idx_operation_logs_client_session_id ON operation_logs(client_session_id);
            CREATE INDEX IF NOT EXISTS idx_operation_logs_session_id ON operation_logs(session_id);

            CREATE TABLE IF NOT EXISTS whitelist_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_type TEXT NOT NULL CHECK(rule_type IN ('tool','command','path','instance')),
                pattern TEXT NOT NULL,
                action TEXT NOT NULL CHECK(action IN ('allow','deny')),
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );

            INSERT OR IGNORE INTO whitelist_rules (rule_type, pattern, action, created_at)
            VALUES ('tool', 'list_servers', 'allow', datetime('now'));",
        )?;
        let _ = connection.execute(
            "ALTER TABLE operation_logs ADD COLUMN client_id TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = connection.execute(
            "ALTER TABLE operation_logs ADD COLUMN client_session_id TEXT NOT NULL DEFAULT ''",
            [],
        );
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
            .execute(
                "DELETE FROM instance_secrets WHERE instance_id = ?1",
                [instance_id],
            )
            .with_context(|| format!("failed to delete secret '{}'", instance_id))?;
        Ok(())
    }

    pub fn has_secret(&self, instance_id: &str) -> Result<bool> {
        Ok(self.load_secret(instance_id)?.is_some())
    }

    pub fn insert_log(
        &self,
        client_id: &str,
        client_session_id: &str,
        session_id: &str,
        instance_id: &str,
        operation: &str,
        details: &str,
    ) -> Result<()> {
        let connection = self.open()?;
        connection.execute(
            "DELETE FROM operation_logs WHERE created_at < datetime('now', '-3 days')",
            [],
        )?;
        let now = Utc::now().to_rfc3339();
        connection.execute(
            "INSERT INTO operation_logs (client_id, client_session_id, session_id, instance_id, operation, details, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![client_id, client_session_id, session_id, instance_id, operation, details, now],
        )?;
        Ok(())
    }

    pub fn get_operation_logs(&self, limit: Option<u64>) -> Result<Vec<OperationLogEntry>> {
        let connection = self.open()?;
        let limit = limit.unwrap_or(200) as i64;
        let mut statement = connection.prepare(
            "SELECT id, client_id, client_session_id, session_id, instance_id, operation, details, created_at
             FROM operation_logs
             ORDER BY id DESC
             LIMIT ?1",
        )?;
        let rows = statement.query_map([limit], |row| {
            Ok(OperationLogEntry {
                id: row.get(0)?,
                client_id: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                client_session_id: row.get::<_, Option<String>>(2)?.unwrap_or_default(),
                session_id: row.get(3)?,
                instance_id: row.get(4)?,
                operation: row.get(5)?,
                details: row.get::<_, Option<String>>(6)?.unwrap_or_default(),
                created_at: row.get(7)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to list operation logs")
    }

    pub fn get_operation_logs_since(
        &self,
        since_id: i64,
        limit: u64,
    ) -> Result<Vec<OperationLogEntry>> {
        let connection = self.open()?;
        let limit = limit as i64;
        let mut statement = connection.prepare(
            "SELECT id, client_id, client_session_id, session_id, instance_id, operation, details, created_at
             FROM operation_logs
             WHERE id > ?1
             ORDER BY id ASC
             LIMIT ?2",
        )?;
        let rows = statement.query_map(params![since_id, limit], |row| {
            Ok(OperationLogEntry {
                id: row.get(0)?,
                client_id: row.get::<_, Option<String>>(1)?.unwrap_or_default(),
                client_session_id: row.get::<_, Option<String>>(2)?.unwrap_or_default(),
                session_id: row.get(3)?,
                instance_id: row.get(4)?,
                operation: row.get(5)?,
                details: row.get::<_, Option<String>>(6)?.unwrap_or_default(),
                created_at: row.get(7)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to list operation logs since")
    }

    pub fn list_whitelist_rules(&self) -> Result<Vec<WhitelistRule>> {
        let connection = self.open()?;
        let mut statement = connection.prepare(
            "SELECT id, rule_type, pattern, action, enabled, created_at
             FROM whitelist_rules
             ORDER BY id ASC",
        )?;

        let rows = statement.query_map([], |row| {
            Ok(WhitelistRule {
                id: row.get(0)?,
                rule_type: RuleType::from_db_value(row.get::<_, String>(1)?.as_str())
                    .unwrap_or(RuleType::Tool),
                pattern: row.get(2)?,
                action: RuleAction::from_db_value(row.get::<_, String>(3)?.as_str())
                    .unwrap_or(RuleAction::Deny),
                enabled: row.get::<_, i64>(4)? != 0,
                created_at: row.get(5)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to list whitelist rules")
    }

    pub fn get_whitelist_rules_by_type(&self, rule_type: &RuleType) -> Result<Vec<WhitelistRule>> {
        let connection = self.open()?;
        let type_str = rule_type.as_str();
        let mut statement = connection.prepare(
            "SELECT id, rule_type, pattern, action, enabled, created_at
             FROM whitelist_rules
             WHERE rule_type = ?1 AND enabled = 1
             ORDER BY id ASC",
        )?;

        let rows = statement.query_map([type_str], |row| {
            Ok(WhitelistRule {
                id: row.get(0)?,
                rule_type: RuleType::from_db_value(row.get::<_, String>(1)?.as_str())
                    .unwrap_or(RuleType::Tool),
                pattern: row.get(2)?,
                action: RuleAction::from_db_value(row.get::<_, String>(3)?.as_str())
                    .unwrap_or(RuleAction::Deny),
                enabled: true,
                created_at: row.get(5)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("failed to list whitelist rules by type")
    }

    pub fn add_whitelist_rule(
        &self,
        rule_type: &RuleType,
        pattern: &str,
        action: &RuleAction,
    ) -> Result<i64> {
        let connection = self.open()?;
        let now = Utc::now().to_rfc3339();
        connection.execute(
            "INSERT INTO whitelist_rules (rule_type, pattern, action, enabled, created_at)
             VALUES (?1, ?2, ?3, 1, ?4)",
            params![rule_type.as_str(), pattern, action.as_str(), now],
        )?;

        Ok(connection.last_insert_rowid())
    }

    pub fn remove_whitelist_rule(&self, id: i64) -> Result<()> {
        let connection = self.open()?;
        let affected = connection
            .execute("DELETE FROM whitelist_rules WHERE id = ?1", [id])
            .context("failed to remove whitelist rule")?;
        if affected == 0 {
            bail!("whitelist rule with id {} not found", id);
        }
        Ok(())
    }

    fn open(&self) -> Result<Connection> {
        let conn = Connection::open(&self.db_path).with_context(|| {
            format!(
                "failed to open SQLite database '{}'",
                self.db_path.display()
            )
        })?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")?;
        Ok(conn)
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

#[cfg(test)]
mod tests {
    use std::env;

    use super::InstanceStore;
    use crate::models::{AuthKind, InstanceDraft, SecretPayload};
    use uuid::Uuid;

    #[test]
    fn secret_round_trip_preserves_private_key_path() {
        let test_dir = env::temp_dir().join(format!("xiic-ssh-mcp-storage-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&test_dir).expect("test dir should be created");
        let db_path = test_dir.join("instances.sqlite3");

        let store = InstanceStore::new(db_path).expect("store should initialize");
        store
            .save_instance(&InstanceDraft {
                instance_id: "prod".to_string(),
                name: "Production".to_string(),
                host: "example.com".to_string(),
                port: 22,
                username: "root".to_string(),
                auth_kind: AuthKind::PrivateKey,
                host_key_check: false,
                notes: None,
                password: None,
                private_key: None,
                private_key_path: None,
                passphrase: None,
                keep_existing_secret: false,
            })
            .expect("instance should be saved");
        let secret = SecretPayload {
            password: None,
            private_key: None,
            private_key_path: Some("/Users/test/.ssh/id_ed25519".to_string()),
            passphrase: Some("hunter2".to_string()),
        };

        store
            .save_secret("prod", &secret)
            .expect("secret should be saved");
        let loaded = store
            .load_secret("prod")
            .expect("secret should load")
            .expect("secret should exist");

        assert_eq!(loaded, secret);

        std::fs::remove_dir_all(test_dir).expect("test dir should be removed");
    }
}
