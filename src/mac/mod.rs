//! macOS 平台实现：pf 防火墙、网络变化监听、进程枚举、launchd 后台服务。

pub mod netwatch;
pub mod paths;
pub mod pf;
pub mod procs;
pub mod service;
