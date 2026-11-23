//! 界面用到的平台功能。Windows、macOS 上为真实实现；其他平台为空实现，仅用于开发时预览界面。

use std::path::PathBuf;

#[cfg(windows)]
pub use crate::win::{autostart, procs};

#[cfg(target_os = "macos")]
pub use crate::mac::procs;

#[cfg(windows)]
pub fn pick_exe_files() -> Vec<PathBuf> {
    rfd::FileDialog::new()
        .set_title("选择要控制的程序")
        .add_filter("程序", &["exe"])
        .pick_files()
        .unwrap_or_default()
}

/// macOS：选择 .app 应用（应用包本身就是要控制的对象，里面的辅助程序一并算作该应用）。
#[cfg(target_os = "macos")]
pub fn pick_exe_files() -> Vec<PathBuf> {
    rfd::FileDialog::new()
        .set_title("选择要控制的应用")
        .set_directory("/Applications")
        .add_filter("应用", &["app"])
        .pick_files()
        .unwrap_or_default()
}

#[cfg(not(any(windows, target_os = "macos")))]
pub fn pick_exe_files() -> Vec<PathBuf> {
    Vec::new()
}

#[cfg(not(any(windows, target_os = "macos")))]
pub mod procs {
    #[derive(Debug, Clone)]
    pub struct ProcInfo {
        pub pid: u32,
        pub name: String,
        pub path: String,
    }
    pub use crate::discovery::normalize as normalize_path;
    pub fn list_processes() -> Vec<ProcInfo> {
        vec![ProcInfo { pid: 1234, name: "chrome.exe".into(), path: r"C:\Program Files\Google\Chrome\Application\chrome.exe".into() }]
    }
}

/// 开机自启。macOS 由后台服务与登录项实现（见 gui::backend），这里不用。
#[cfg(not(windows))]
pub mod autostart {
    use std::path::Path;
    pub fn is_enabled() -> bool {
        false
    }
    pub fn enable(_exe: &Path, _config: &Path) -> anyhow::Result<()> {
        anyhow::bail!("此平台不支持")
    }
    pub fn disable() -> anyhow::Result<()> {
        Ok(())
    }
}
