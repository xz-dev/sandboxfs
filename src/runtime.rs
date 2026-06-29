//! Runtime directory/socket/log path selection.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::Result;

pub const ENV_RUNTIME_DIR: &str = "SANDBOXFS_RUNTIME_DIR";
pub const ENV_SOCKET: &str = "SANDBOXFS_SOCKET";
pub const ENV_LOG_DIR: &str = "SANDBOXFS_LOG_DIR";

#[derive(Debug, Clone)]
pub struct RuntimePaths {
    pub runtime_dir: PathBuf,
    pub log_dir: PathBuf,
    socket_override: Option<PathBuf>,
}

impl RuntimePaths {
    pub fn discover() -> Result<Self> {
        let runtime_dir = runtime_dir()?;
        ensure_runtime_dir(&runtime_dir)?;
        let log_dir = std::env::var_os(ENV_LOG_DIR)
            .map(PathBuf::from)
            .unwrap_or_else(|| runtime_dir.clone());
        ensure_private_dir(&log_dir)?;
        let socket_override = std::env::var_os(ENV_SOCKET).map(PathBuf::from);
        Ok(Self {
            runtime_dir,
            log_dir,
            socket_override,
        })
    }

    pub fn for_tests(runtime_dir: PathBuf, socket_override: Option<PathBuf>) -> Self {
        Self {
            log_dir: runtime_dir.clone(),
            runtime_dir,
            socket_override,
        }
    }

    pub fn for_tests_with_log_dir(
        runtime_dir: PathBuf,
        log_dir: PathBuf,
        socket_override: Option<PathBuf>,
    ) -> Self {
        Self {
            runtime_dir,
            log_dir,
            socket_override,
        }
    }

    pub fn socket_path(&self, name: &str) -> PathBuf {
        self.socket_override
            .clone()
            .unwrap_or_else(|| self.runtime_dir.join(format!("{name}.sock")))
    }

    pub fn sandbox_log_path(&self, name: &str) -> PathBuf {
        self.log_dir.join(format!("{name}.log"))
    }

    pub fn tmp_mount_dir(&self, name: &str, operation_id: u64) -> PathBuf {
        self.runtime_dir
            .join("tmp")
            .join(format!("{name}-{operation_id}"))
    }
}

pub fn runtime_dir() -> Result<PathBuf> {
    if let Some(value) = std::env::var_os(ENV_RUNTIME_DIR) {
        return Ok(PathBuf::from(value));
    }
    if let Some(value) = std::env::var_os("XDG_RUNTIME_DIR") {
        return Ok(PathBuf::from(value).join("sandboxfs"));
    }
    if unsafe { libc::geteuid() } == 0 {
        return Ok(PathBuf::from("/run/sandboxfs"));
    }
    Ok(std::env::temp_dir().join(format!("sandboxfs-{}", unsafe { libc::geteuid() })))
}

pub fn ensure_runtime_dir(path: &Path) -> Result<()> {
    ensure_private_dir(path)?;
    ensure_private_dir(&path.join("tmp"))?;
    Ok(())
}

pub fn ensure_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn env_runtime_dir_wins() {
        let temp = TempDir::new().unwrap();
        unsafe {
            std::env::set_var(ENV_RUNTIME_DIR, temp.path());
            std::env::remove_var("XDG_RUNTIME_DIR");
        }
        assert_eq!(runtime_dir().unwrap(), temp.path());
        unsafe {
            std::env::remove_var(ENV_RUNTIME_DIR);
        }
    }

    #[test]
    fn default_socket_is_per_sandbox() {
        let temp = TempDir::new().unwrap();
        let runtime = RuntimePaths::for_tests(temp.path().to_path_buf(), None);
        assert_eq!(runtime.socket_path("demo"), temp.path().join("demo.sock"));
    }

    #[test]
    fn log_dir_can_be_separate_from_runtime_dir() {
        let runtime_temp = TempDir::new().unwrap();
        let log_temp = TempDir::new().unwrap();
        let runtime = RuntimePaths::for_tests_with_log_dir(
            runtime_temp.path().to_path_buf(),
            log_temp.path().to_path_buf(),
            None,
        );
        assert_eq!(
            runtime.socket_path("demo"),
            runtime_temp.path().join("demo.sock")
        );
        assert_eq!(
            runtime.sandbox_log_path("demo"),
            log_temp.path().join("demo.log")
        );
    }
}
