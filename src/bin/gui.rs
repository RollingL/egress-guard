//! 图形界面版本：egress-guard-gui.exe（需要管理员权限，清单中已声明）。
//!
//! 参数：
//!   --minimized        启动后直接隐藏到托盘（开机自启时使用）
//!   -c, --config PATH  配置文件路径（默认：exe 所在目录下的 config.toml）
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
    while let Some(a) = args.next() {
        match a.as_str() {
            "--minimized" => start_minimized = true,
            "-c" | "--config" => config = args.next().map(PathBuf::from),
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

    if let Err(e) = gui::run(gui::Options { config_path, start_minimized }) {
        log::error!("{e:#}");
        let text: Vec<u16> = format!("{e:#}").encode_utf16().chain(std::iter::once(0)).collect();
        unsafe {
            MessageBoxW(None, PCWSTR(text.as_ptr()), w!("egress-guard"), MB_OK | MB_ICONERROR);
        }
        std::process::exit(1);
    }
}

/// 非 Windows：仅用于开发时预览界面（无托盘、无 WFP，进入模拟模式）。
#[cfg(not(windows))]
fn main() {
    use egress_guard::{gui, logbuf};
    logbuf::init("info", true, None);
    let config_path = std::env::args().nth(1).map(Into::into).unwrap_or_else(|| "config.toml".into());
    if let Err(e) = gui::run(gui::Options { config_path, start_minimized: false }) {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}
