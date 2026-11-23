//! macOS 上的固定路径与名称。

use std::path::PathBuf;

/// 后台服务（LaunchDaemon）的标签。
pub const DAEMON_LABEL: &str = "com.egressguard.daemon";
/// 登录时启动界面（LaunchAgent）的标签。
pub const GUI_LABEL: &str = "com.egressguard.gui";
/// 后台服务的 plist。
pub const DAEMON_PLIST: &str = "/Library/LaunchDaemons/com.egressguard.daemon.plist";
/// 后台服务的数据目录（root 所有）：配置、子进程识别记录、服务程序副本。
pub const SUPPORT_DIR: &str = "/Library/Application Support/EgressGuard";
/// 界面与后台服务通信的本地套接字（由 launchd 创建并按需启动服务）。
pub const SOCKET: &str = "/var/run/egress-guard.sock";
/// pf 锚点的所有权锁：持有它的进程才能改动本工具的 pf 锚点（进程退出时由系统释放）。
pub const PF_LOCK: &str = "/var/run/egress-guard.pf.lock";
/// 后台服务日志。
pub const LOG_FILE: &str = "/Library/Logs/egress-guard.log";

pub fn config_path() -> PathBuf {
    PathBuf::from(SUPPORT_DIR).join("config.toml")
}

/// 安装后的服务程序（从 .app 包里复制过来，避免移动或删除 .app 后服务失效）。
pub fn daemon_bin() -> PathBuf {
    PathBuf::from(SUPPORT_DIR).join("bin").join("egress-guard")
}

/// 当前用户的 LaunchAgent plist。
pub fn gui_agent_plist() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join("Library/LaunchAgents").join(format!("{GUI_LABEL}.plist")))
}

/// 界面程序自己的数据目录（单实例锁、界面日志）。
pub fn gui_data_dir() -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    home.join("Library/Application Support/EgressGuard")
}
