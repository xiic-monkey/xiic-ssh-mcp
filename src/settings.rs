use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::paths::{ensure_private_dir, ensure_private_file, shared_app_data_dir};

/// 应用持久化配置。
#[derive(Debug, Clone, Serialize)]
pub struct AppSettings {
    /// 敏感操作审核等级。
    pub approval_level: ApprovalLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalLevel {
    /// 使用系统原生弹窗审核。
    SystemDialog,
    /// 使用独立审批 App 审核。
    AppDialog,
    /// 跳过审核，直接允许未命中白名单但未被拒绝的操作。
    AllowAll,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            approval_level: ApprovalLevel::SystemDialog,
        }
    }
}

#[derive(Deserialize)]
struct RawAppSettings {
    approval_level: Option<ApprovalLevel>,
    use_system_approval: Option<bool>,
}

impl<'de> Deserialize<'de> for AppSettings {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawAppSettings::deserialize(deserializer)?;
        let approval_level = raw.approval_level.unwrap_or_else(|| {
            if raw.use_system_approval.unwrap_or(true) {
                ApprovalLevel::SystemDialog
            } else {
                ApprovalLevel::AppDialog
            }
        });

        Ok(Self { approval_level })
    }
}

fn settings_file_path() -> anyhow::Result<PathBuf> {
    let dir = shared_app_data_dir()?;
    ensure_private_dir(&dir)?;
    Ok(dir.join("settings.json"))
}

/// 从磁盘加载设置，文件不存在或格式错误时返回默认值。
pub fn load_settings() -> AppSettings {
    let path = match settings_file_path() {
        Ok(p) => p,
        Err(_) => return AppSettings::default(),
    };

    match std::fs::read_to_string(&path) {
        Ok(content) => serde_json::from_str(&content).unwrap_or_default(),
        Err(_) => AppSettings::default(),
    }
}

/// 将设置持久化到磁盘。
pub fn save_settings(settings: &AppSettings) -> anyhow::Result<()> {
    let path = settings_file_path()?;
    let content = serde_json::to_string_pretty(settings)?;
    std::fs::write(&path, content)?;
    ensure_private_file(&path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{AppSettings, ApprovalLevel};

    #[test]
    fn legacy_system_approval_true_maps_to_system_dialog() {
        let settings: AppSettings = serde_json::from_str(
            r#"{
              "use_system_approval": true
            }"#,
        )
        .expect("legacy settings should deserialize");

        assert_eq!(settings.approval_level, ApprovalLevel::SystemDialog);
    }

    #[test]
    fn legacy_system_approval_false_maps_to_app_dialog() {
        let settings: AppSettings = serde_json::from_str(
            r#"{
              "use_system_approval": false,
              "prefer_client_approval_for_codex": true
            }"#,
        )
        .expect("legacy settings should deserialize");

        assert_eq!(settings.approval_level, ApprovalLevel::AppDialog);
    }

    #[test]
    fn round_trip_preserves_new_field() {
        let settings = AppSettings {
            approval_level: ApprovalLevel::AllowAll,
        };

        let serialized = serde_json::to_string(&settings).expect("settings should serialize");
        let restored: AppSettings =
            serde_json::from_str(&serialized).expect("settings should deserialize");

        assert_eq!(restored.approval_level, ApprovalLevel::AllowAll);
    }
}
