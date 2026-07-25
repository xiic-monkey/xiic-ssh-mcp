use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};

pub const SHARED_APP_IDENTIFIER: &str = "com.xiic.sshmanager";

pub fn shared_app_data_dir() -> Result<PathBuf> {
    let base = dirs::data_local_dir()
        .ok_or_else(|| anyhow!("failed to resolve local application data directory"))?;
    Ok(base.join(SHARED_APP_IDENTIFIER))
}

pub fn ensure_private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)?;
    set_private_mode(path, 0o700)
}

pub fn ensure_private_file(path: &Path) -> Result<()> {
    if path.exists() {
        set_private_mode(path, 0o600)?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_mode(mode);
    std::fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_mode(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use uuid::Uuid;

    use super::{ensure_private_dir, ensure_private_file};

    #[test]
    fn private_paths_replace_permissive_unix_modes() {
        let test_dir = std::env::temp_dir().join(format!("xiic-ssh-paths-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&test_dir).expect("test directory should be created");
        std::fs::set_permissions(&test_dir, std::fs::Permissions::from_mode(0o755))
            .expect("directory mode should be set");
        let file = test_dir.join("settings.json");
        std::fs::write(&file, "{}").expect("test file should be created");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644))
            .expect("file mode should be set");

        ensure_private_dir(&test_dir).expect("directory should be secured");
        ensure_private_file(&file).expect("file should be secured");

        assert_eq!(
            std::fs::metadata(&test_dir)
                .expect("directory metadata should load")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&file)
                .expect("file metadata should load")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        std::fs::remove_dir_all(test_dir).expect("test directory should be removed");
    }
}
