#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::sync::Arc;

use tauri::{Manager, State};
use xiic_ssh_mcp::app_core::{DEFAULT_KEYRING_SERVICE, DesktopCore};
use xiic_ssh_mcp::models::{InstanceDraft, InstanceSummary, McpConfigBundle, TestConnectionResult};

struct DesktopState {
    core: Arc<DesktopCore>,
    mcp_config: McpConfigBundle,
}

#[tauri::command]
fn list_instances(state: State<'_, DesktopState>) -> Result<Vec<InstanceSummary>, String> {
    state.core.list_instances().map_err(|err| err.to_string())
}

#[tauri::command]
fn save_instance(
    state: State<'_, DesktopState>,
    draft: InstanceDraft,
) -> Result<InstanceSummary, String> {
    state.core.save_instance(draft).map_err(|err| err.to_string())
}

#[tauri::command]
fn delete_instance(state: State<'_, DesktopState>, instance_id: String) -> Result<(), String> {
    state
        .core
        .delete_instance(&instance_id)
        .map_err(|err| err.to_string())
}

#[tauri::command]
fn test_connection(
    state: State<'_, DesktopState>,
    draft: InstanceDraft,
) -> Result<TestConnectionResult, String> {
    state
        .core
        .test_connection(draft)
        .map_err(|err| err.to_string())
}

#[tauri::command]
fn get_mcp_configs(state: State<'_, DesktopState>) -> Result<McpConfigBundle, String> {
    Ok(state.mcp_config.clone())
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(|app| {
            let (core, db_path) = build_core(app.handle().clone())?;
            let helper_path = resolve_stdio_helper_path(std::env::current_exe()?);
            let mcp_config = core.mcp_config_bundle(
                &helper_path.to_string_lossy(),
                &db_path.to_string_lossy(),
                DEFAULT_KEYRING_SERVICE,
            )?;

            app.manage(DesktopState {
                core,
                mcp_config,
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            list_instances,
            save_instance,
            delete_instance,
            test_connection,
            get_mcp_configs
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn build_core(app: tauri::AppHandle) -> anyhow::Result<(Arc<DesktopCore>, PathBuf)> {
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    std::fs::create_dir_all(&data_dir)?;

    let database_path: PathBuf = data_dir.join("instances.sqlite3");
    let core = DesktopCore::new(database_path.clone(), DEFAULT_KEYRING_SERVICE)?;
    Ok((Arc::new(core), database_path))
}

fn resolve_stdio_helper_path(current_exe: PathBuf) -> PathBuf {
    let helper_name = helper_binary_name();
    let sibling = current_exe.with_file_name(helper_name);
    if sibling.exists() {
        return sibling;
    }

    let Some(profile_dir) = current_exe.parent() else {
        return sibling;
    };
    let Some(profile_name) = profile_dir.file_name() else {
        return sibling;
    };
    let Some(repo_root) = current_exe.ancestors().nth(4) else {
        return sibling;
    };

    let dev_helper = repo_root.join("target").join(profile_name).join(helper_name);
    if dev_helper.exists() {
        return dev_helper;
    }

    sibling
}

fn helper_binary_name() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "xiic-ssh-mcp.exe"
    }

    #[cfg(not(target_os = "windows"))]
    {
        "xiic-ssh-mcp"
    }
}
