use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::paths::{ensure_private_dir, ensure_private_file, shared_app_data_dir};

/// 应用持久化配置。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    /// 启用系统原生弹窗进行审批（跳过 Tauri 桌面审批 App）。
    pub use_system_approval: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            use_system_approval: true,
        }
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
    use super::AppSettings;

    #[test]
    fn legacy_extra_fields_are_ignored() {
        let settings: AppSettings = serde_json::from_str(
            r#"{
              "use_system_approval": false,
              "prefer_client_approval_for_codex": true
            }"#,
        )
        .expect("legacy settings should deserialize");

        assert!(!settings.use_system_approval);
    }

    #[test]
    fn round_trip_preserves_new_field() {
        let settings = AppSettings {
            use_system_approval: false,
        };

        let serialized = serde_json::to_string(&settings).expect("settings should serialize");
        let restored: AppSettings =
            serde_json::from_str(&serialized).expect("settings should deserialize");

        assert!(!restored.use_system_approval);
    }
}
