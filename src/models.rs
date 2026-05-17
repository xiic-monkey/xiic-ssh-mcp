use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthKind {
    Password,
    PrivateKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredInstance {
    pub instance_id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_kind: AuthKind,
    pub host_key_check: bool,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceSummary {
    pub instance_id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_kind: AuthKind,
    pub host_key_check: bool,
    pub notes: Option<String>,
    pub has_secret: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl InstanceSummary {
    pub fn from_stored(instance: StoredInstance, has_secret: bool) -> Self {
        Self {
            instance_id: instance.instance_id,
            name: instance.name,
            host: instance.host,
            port: instance.port,
            username: instance.username,
            auth_kind: instance.auth_kind,
            host_key_check: instance.host_key_check,
            notes: instance.notes,
            has_secret,
            created_at: instance.created_at,
            updated_at: instance.updated_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceDraft {
    pub instance_id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_kind: AuthKind,
    pub host_key_check: bool,
    pub notes: Option<String>,
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub private_key_path: Option<String>,
    pub passphrase: Option<String>,
    #[serde(default)]
    pub keep_existing_secret: bool,
}

impl InstanceDraft {
    pub fn normalize(mut self) -> Self {
        self.instance_id = self.instance_id.trim().to_string();
        self.name = self.name.trim().to_string();
        self.host = self.host.trim().to_string();
        self.username = self.username.trim().to_string();
        self.notes = trim_to_none(self.notes);
        self.password = trim_to_none(self.password);
        self.private_key = trim_to_none(self.private_key);
        self.private_key_path = trim_to_none(self.private_key_path);
        self.passphrase = trim_to_none(self.passphrase);
        if self.port == 0 {
            self.port = 22;
        }
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretPayload {
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub private_key_path: Option<String>,
    pub passphrase: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestConnectionResult {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfigBundle {
    pub command: String,
    pub args: Vec<String>,
    pub stdio_json: String,
    pub helper_found: bool,
    pub helper_warning: Option<String>,
}

#[derive(Debug, Clone)]
pub struct McpConfigRequest<'a> {
    pub command_path: &'a str,
    pub db_path: &'a str,
    pub keyring_service: &'a str,
    pub notify_endpoint: Option<&'a str>,
    pub approval_endpoint: Option<&'a str>,
    pub helper_found: bool,
    pub helper_warning: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListServersResult {
    pub servers: Vec<InstanceSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationLogEntry {
    pub id: i64,
    pub session_id: String,
    pub instance_id: String,
    pub operation: String,
    pub details: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSessionResult {
    pub session_id: String,
    pub instance_id: String,
    pub connected_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteCommandResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadFileResult {
    pub local_path: String,
    pub remote_path: String,
    pub bytes_written: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadFileResult {
    pub local_path: String,
    pub remote_path: String,
    pub size: usize,
    pub encoding: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadLocalFileArgs {
    pub session_id: String,
    pub local_path: String,
    pub remote_path: String,
    #[serde(default = "default_overwrite")]
    pub overwrite: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadLocalFileResult {
    pub bytes_written: usize,
    pub local_path: String,
    pub remote_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadToLocalArgs {
    pub session_id: String,
    pub remote_path: String,
    pub local_path: String,
    #[serde(default = "default_overwrite")]
    pub overwrite: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadToLocalResult {
    pub local_path: String,
    pub remote_path: String,
    pub bytes_written: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UploadEncoding {
    #[default]
    Utf8,
    Base64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DownloadEncoding {
    Utf8,
    #[default]
    Base64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecuteCommandArgs {
    pub session_id: String,
    pub command: String,
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadFileArgs {
    pub session_id: String,
    pub local_path: String,
    pub remote_path: String,
    #[serde(default = "default_overwrite")]
    pub overwrite: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadFileArgs {
    pub session_id: String,
    pub remote_path: String,
    #[serde(default)]
    pub local_path: Option<String>,
}

fn default_overwrite() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleType {
    Tool,
    Command,
    Path,
    Instance,
}

impl RuleType {
    pub fn from_db_value(s: &str) -> Option<Self> {
        match s {
            "tool" => Some(Self::Tool),
            "command" => Some(Self::Command),
            "path" => Some(Self::Path),
            "instance" => Some(Self::Instance),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Tool => "tool",
            Self::Command => "command",
            Self::Path => "path",
            Self::Instance => "instance",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    Allow,
    Deny,
}

impl RuleAction {
    pub fn from_db_value(s: &str) -> Option<Self> {
        match s {
            "allow" => Some(Self::Allow),
            "deny" => Some(Self::Deny),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistRule {
    pub id: i64,
    pub rule_type: RuleType,
    pub pattern: String,
    pub action: RuleAction,
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationContext {
    pub tool_name: String,
    pub command: Option<String>,
    pub remote_path: Option<String>,
    pub local_path: Option<String>,
    pub instance_id: Option<String>,
}

#[derive(Debug, Clone)]
pub enum RuleDecision {
    Allow,
    Deny(String),
    NeedsElicitation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub name: String,
    #[serde(default)]
    pub arguments: Value,
}

#[derive(Debug, Clone)]
pub struct PendingToolCall {
    pub id: Value,
    pub tool_call: ToolCall,
    pub operation: OperationContext,
    pub approval: ApprovalOperationMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WhitelistMode {
    Strict,
    Off,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalMode {
    Auto,
    Elicitation,
    Local,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalOperationMetadata {
    pub tool_name: String,
    pub command: Option<String>,
    pub remote_path: Option<String>,
    pub local_path: Option<String>,
    pub instance_id: Option<String>,
}

impl From<&OperationContext> for ApprovalOperationMetadata {
    fn from(value: &OperationContext) -> Self {
        Self {
            tool_name: value.tool_name.clone(),
            command: value.command.clone(),
            remote_path: value.remote_path.clone(),
            local_path: value.local_path.clone(),
            instance_id: value.instance_id.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub kind: String,
    pub request_id: String,
    pub message: String,
    pub metadata: ApprovalOperationMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalResponse {
    pub kind: String,
    pub request_id: String,
    pub accepted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequestedEvent {
    pub request: ApprovalRequest,
    pub pending_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalResolvedEvent {
    pub request_id: String,
    pub accepted: bool,
    pub pending_count: usize,
}

fn trim_to_none(value: Option<String>) -> Option<String> {
    value.and_then(|text| {
        let trimmed = text.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{AuthKind, InstanceDraft};

    #[test]
    fn normalize_trims_private_key_path() {
        let draft = InstanceDraft {
            instance_id: " prod ".to_string(),
            name: " Production ".to_string(),
            host: " example.com ".to_string(),
            port: 22,
            username: " root ".to_string(),
            auth_kind: AuthKind::PrivateKey,
            host_key_check: false,
            notes: None,
            password: None,
            private_key: None,
            private_key_path: Some("  /Users/test/.ssh/id_ed25519  ".to_string()),
            passphrase: None,
            keep_existing_secret: false,
        }
        .normalize();

        assert_eq!(
            draft.private_key_path.as_deref(),
            Some("/Users/test/.ssh/id_ed25519")
        );
    }
}
