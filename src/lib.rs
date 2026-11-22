//! egress-guard：根据本机公网出口 IP 判断是否阻断选中应用的网络连接。
//!
//! 出口 IP 在白名单内 → 放行；否则 → 通过 WFP 阻断配置中列出的应用。

pub mod config;
pub mod controller;
pub mod egress;
pub mod engine;
pub mod logbuf;
pub mod gui;
#[cfg(windows)]
pub mod win;

use std::path::{Path, PathBuf};

/// exe 所在目录。
pub fn exe_dir() -> Option<PathBuf> {
    std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf))
}
