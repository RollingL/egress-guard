//! 图形界面版本：egress-guard-gui（Windows 上需要管理员权限，清单中已声明；
//! macOS 上以普通用户运行，拦截由 root 后台服务负责）。
//!
//! 参数：
//!   --minimized        启动后直接隐藏到托盘 / 菜单栏（开机自启时使用）
//!   -c, --config PATH  配置文件路径（Windows，默认：exe 所在目录下的 config.toml）
//!   --page NAME        打开时显示的页面（截图用）
//!   --netext-selftest [秒]  macOS：查询网络扩展状态并尝试安装，打印结果后退出（CI 用）
#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
fn main() {
    use std::path::PathBuf;

    use egress_guard::{exe_dir, gui, logbuf};
    use windows::core::{w, PCWSTR};
    use windows::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
    use windows::Win32::System::Threading::CreateMutexW;
    use windows::Win32::UI::WindowsAndMessaging::{
        FindWindowW, MessageBoxW, SetForegroundWindow, ShowWindow, MB_ICONERROR, MB_OK, SW_RESTORE,
    };

    let mut args = std::env::args().skip(1);
    let mut start_minimized = false;
    let mut config: Option<PathBuf> = None;
    let mut start_page = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--minimized" => start_minimized = true,
            "-c" | "--config" => config = args.next().map(PathBuf::from),
            "--page" => start_page = args.next(),
            _ => {}
        }
    }
    let dir = exe_dir().unwrap_or_else(|| PathBuf::from("."));
    let config_path = config.unwrap_or_else(|| dir.join("config.toml"));

    // 单实例：已在运行则把已有窗口调出来
    unsafe {
        let _mutex = CreateMutexW(None, false, w!("Local\\egress-guard-gui"));
        if GetLastError() == ERROR_ALREADY_EXISTS {
            let title: Vec<u16> = gui::WINDOW_TITLE.encode_utf16().chain(std::iter::once(0)).collect();
            if let Ok(hwnd) = FindWindowW(PCWSTR::null(), PCWSTR(title.as_ptr())) {
                let _ = ShowWindow(hwnd, SW_RESTORE);
                let _ = SetForegroundWindow(hwnd);
            }
            return;
        }
        std::mem::forget(_mutex);
    }

    logbuf::init("info", false, Some(&dir.join("egress-guard.log")));
    log::info!("egress-guard-gui {} 启动", env!("CARGO_PKG_VERSION"));

    if let Err(e) = gui::run(gui::Options { config_path, start_minimized, start_page }) {
        log::error!("{e:#}");
        let text: Vec<u16> = format!("{e:#}").encode_utf16().chain(std::iter::once(0)).collect();
        unsafe {
            MessageBoxW(None, PCWSTR(text.as_ptr()), w!("egress-guard"), MB_OK | MB_ICONERROR);
        }
        std::process::exit(1);
    }
}

/// macOS：普通用户运行的界面 + 菜单栏图标；拦截由 root 后台服务负责（见 egress-guard daemon）。
#[cfg(target_os = "macos")]
fn main() {
    use std::os::fd::AsRawFd;

    use egress_guard::mac::paths;
    use egress_guard::{gui, logbuf};

    let mut args = std::env::args().skip(1);
    let mut start_minimized = false;
    let mut start_page = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--minimized" => start_minimized = true,
            "--page" => start_page = args.next(),
            // CI 自检：查询网络扩展状态并尝试安装，打印结果（JSON）后退出
            "--netext-selftest" => {
                egress_guard::netext::selftest(args.next().and_then(|s| s.parse().ok()).unwrap_or(10.0));
                return;
            }
            _ => {}
        }
    }

    // 单实例：从 Finder 再次打开时系统会激活已有实例；这里再用文件锁兜底
    let dir = paths::gui_data_dir();
    let _ = std::fs::create_dir_all(&dir);
    let lock = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(dir.join("gui.lock"));
    if let Ok(f) = &lock {
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            eprintln!("egress-guard-gui 已在运行");
            return;
        }
    }

    let log_dir = std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join("Library/Logs"));
    logbuf::init("info", true, log_dir.map(|d| d.join("egress-guard-gui.log")).as_deref());
    log::info!("egress-guard-gui {} 启动", env!("CARGO_PKG_VERSION"));

    // 配置由后台服务保存；这里的路径只在连不上服务时作为占位
    let config_path = paths::config_path();
    if let Err(e) = gui::run(gui::Options { config_path, start_minimized, start_page }) {
        log::error!("{e:#}");
        let msg = format!("{e:#}").replace('\\', "\\\\").replace('"', "\\\"");
        let _ = std::process::Command::new("/usr/bin/osascript")
            .arg("-e")
            .arg(format!("display alert \"Egress Guard 无法启动\" message \"{msg}\" as critical"))
            .status();
        std::process::exit(1);
    }
    drop(lock);
}

/// 其他平台：仅用于开发时预览界面（无托盘、无拦截后端，进入模拟模式）。
#[cfg(not(any(windows, target_os = "macos")))]
fn main() {
    use egress_guard::{gui, logbuf};
    logbuf::init("info", true, None);
    let mut args = std::env::args().skip(1);
    let mut config_path = std::path::PathBuf::from("config.toml");
    let mut start_page = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--page" => start_page = args.next(),
            other => config_path = other.into(),
        }
    }
    if let Err(e) = gui::run(gui::Options { config_path, start_minimized: false, start_page }) {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}
