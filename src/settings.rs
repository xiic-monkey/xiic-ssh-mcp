use std::path::PathBuf;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

use crate::paths::{ensure_private_dir, ensure_private_file, shared_app_data_dir};

pub const AUTO_REVIEW_API_KEY: &str = "auto_review_api_key";

/// 应用持久化配置。
#[derive(Debug, Clone, Serialize)]
pub struct AppSettings {
    /// 敏感操作审核等级。
    pub approval_level: ApprovalLevel,
    pub auto_review: AutoReviewSettings,
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
    /// 使用配置的大模型自动审核。
    AutoAgent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AutoReviewSettings {
    pub base_url: String,
    pub model: String,
}

impl Default for AutoReviewSettings {
    fn default() -> Self {
        Self {
            base_url: String::new(),
            model: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AppSettingsView {
    pub approval_level: ApprovalLevel,
    pub auto_review: AutoReviewSettings,
    pub api_key_configured: bool,
}

impl AppSettingsView {
    pub fn from_settings(settings: AppSettings, api_key_configured: bool) -> Self {
        Self {
            approval_level: settings.approval_level,
            auto_review: settings.auto_review,
            api_key_configured,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SaveSettingsRequest {
    pub settings: AppSettings,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub clear_api_key: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            approval_level: ApprovalLevel::SystemDialog,
            auto_review: AutoReviewSettings::default(),
        }
    }
}

#[derive(Deserialize)]
struct RawAppSettings {
    approval_level: Option<ApprovalLevel>,
    use_system_approval: Option<bool>,
    auto_review: Option<AutoReviewSettings>,
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

        Ok(Self {
            approval_level,
            auto_review: raw.auto_review.unwrap_or_default(),
        })
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

pub fn validate_auto_review_settings(settings: &AutoReviewSettings) -> Result<AutoReviewSettings> {
    let base_url = settings.base_url.trim().trim_end_matches('/').to_string();
    let model = settings.model.trim().to_string();

    if base_url.is_empty() {
        bail!("自动审核需要填写模型 Base URL");
    }
    if model.is_empty() {
        bail!("自动审核需要填写模型名称");
    }
    if !base_url.starts_with("http://") && !base_url.starts_with("https://") {
        bail!("模型 Base URL 必须以 http:// 或 https:// 开头");
    }
    if base_url.chars().any(char::is_whitespace) {
        bail!("模型 Base URL 不能包含空白字符");
    }

    Ok(AutoReviewSettings { base_url, model })
}

#[cfg(test)]
mod tests {
    use super::{AppSettings, ApprovalLevel, AutoReviewSettings, validate_auto_review_settings};

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
            auto_review: AutoReviewSettings::default(),
        };

        let serialized = serde_json::to_string(&settings).expect("settings should serialize");
        let restored: AppSettings =
            serde_json::from_str(&serialized).expect("settings should deserialize");

        assert_eq!(restored.approval_level, ApprovalLevel::AllowAll);
    }

    #[test]
    fn old_settings_default_auto_review_config() {
        let settings: AppSettings = serde_json::from_str(r#"{"approval_level":"allow_all"}"#)
            .expect("old settings should deserialize");
        assert_eq!(settings.auto_review, AutoReviewSettings::default());
    }

    #[test]
    fn normalizes_and_validates_auto_review_settings() {
        let normalized = validate_auto_review_settings(&AutoReviewSettings {
            base_url: " https://example.com/v1/ ".into(),
            model: " review-model ".into(),
        })
        .expect("valid settings should normalize");

        assert_eq!(normalized.base_url, "https://example.com/v1");
        assert_eq!(normalized.model, "review-model");
    }

    #[test]
    fn auto_agent_serializes_to_expected_setting_value() {
        assert_eq!(
            serde_json::to_value(ApprovalLevel::AutoAgent).expect("level should serialize"),
            "auto_agent"
        );
        assert!(
            validate_auto_review_settings(&AutoReviewSettings {
                base_url: "ftp://example.com".into(),
                model: "review-model".into(),
            })
            .is_err()
        );
    }
}
