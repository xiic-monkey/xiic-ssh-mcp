use std::path::PathBuf;

use anyhow::{Result, anyhow};

pub const SHARED_APP_IDENTIFIER: &str = "com.xiic.sshmanager";

pub fn shared_app_data_dir() -> Result<PathBuf> {
    let base = dirs::data_local_dir()
        .ok_or_else(|| anyhow!("failed to resolve local application data directory"))?;
    Ok(base.join(SHARED_APP_IDENTIFIER))
}
