//! 界面用到的平台功能。Windows 上为真实实现；其他平台为空实现，仅用于开发时预览界面。

use std::path::PathBuf;

#[cfg(windows)]
pub use crate::win::{autostart, procs};

#[cfg(windows)]
pub fn pick_exe_files() -> Vec<PathBuf> {
    rfd::FileDialog::new()
        .set_title("选择要控制的程序")
        .add_filter("程序", &["exe"])
        .pick_files()
        .unwrap_or_default()
}

#[cfg(not(windows))]
pub fn pick_exe_files() -> Vec<PathBuf> {
    Vec::new()
}

#[cfg(not(windows))]
pub mod procs {
    #[derive(Debug, Clone)]
    pub struct ProcInfo {
        pub pid: u32,
        pub name: String,
        pub path: String,
    }
    pub fn normalize_path(p: &str) -> String {
        p.replace('/', "\\").to_lowercase()
    }
    pub fn list_processes() -> Vec<ProcInfo> {
        vec![ProcInfo { pid: 1234, name: "chrome.exe".into(), path: r"C:\Program Files\Google\Chrome\Application\chrome.exe".into() }]
    }
}

#[cfg(not(windows))]
pub mod autostart {
    use std::path::Path;
    pub fn is_enabled() -> bool {
        false
    }
    pub fn enable(_exe: &Path) -> anyhow::Result<()> {
        anyhow::bail!("仅支持 Windows")
    }
    pub fn disable() -> anyhow::Result<()> {
        Ok(())
    }
}
