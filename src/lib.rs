//! egress-guard：根据本机公网出口 IP 判断是否阻断网络连接。
//!
//! 出口 IP 在白名单内 → 放行；否则 → 阻断配置中列出的应用（Windows：WFP，macOS：网络扩展），
//! 或者切断全部网络（全局断网；Windows：WFP，macOS：pf）。

pub mod blockall;
pub mod config;
pub mod controller;
#[cfg(unix)]
pub mod daemon;
pub mod discovery;
pub mod egress;
pub mod engine;
#[cfg(unix)]
pub mod filterfeed;
pub mod leaktest;
pub mod gui;
#[cfg(unix)]
pub mod ipc;
pub mod logbuf;
#[cfg(target_os = "macos")]
pub mod mac;
pub mod netext;
pub mod pfrules;
#[cfg(windows)]
pub mod win;

use std::path::{Path, PathBuf};

/// exe 所在目录。
pub fn exe_dir() -> Option<PathBuf> {
    std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf))
}

/// 子进程识别记录文件：与配置文件放在同一目录。
pub fn learned_file(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
        .join("learned-apps.txt")
}
