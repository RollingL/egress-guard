//! 系统托盘：在独立线程中运行自己的 Win32 消息循环，
//! 这样主窗口隐藏时托盘图标、提示文字和菜单仍能实时更新。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use windows::core::PCWSTR;
use windows::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, FindWindowW, IsWindowVisible, MsgWaitForMultipleObjects, PeekMessageW,
    SetForegroundWindow, ShowWindow, TranslateMessage, MSG, PM_REMOVE, QS_ALLINPUT, SW_RESTORE,
};

use super::backend::Backend;
use super::icons::{shield_rgba, Shade};

/// 托盘需要显示的状态。
pub struct TrayState {
    pub shade: Shade,
    pub tooltip: String,
}

pub struct TrayCtx {
    pub egui_ctx: eframe::egui::Context,
    pub show_requested: Arc<AtomicBool>,
    pub backend: Arc<dyn Backend>,
    pub window_title: String,
}

fn icon(shade: Shade) -> Option<Icon> {
    Icon::from_rgba(shield_rgba(32, shade), 32, 32).ok()
}

/// 请求显示主窗口：先走 eframe 的正常流程，若稍后窗口仍未出现，再直接调用 Win32 兜底。
fn request_show(t: &TrayCtx, fallback_at: &mut Option<Instant>) {
    t.show_requested.store(true, Ordering::SeqCst);
    t.egui_ctx.request_repaint();
    *fallback_at = Some(Instant::now() + Duration::from_millis(600));
}

fn force_show(title: &str) {
    let w: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        if let Ok(hwnd) = FindWindowW(PCWSTR::null(), PCWSTR(w.as_ptr())) {
            if !IsWindowVisible(hwnd).as_bool() {
                let _ = ShowWindow(hwnd, SW_RESTORE);
            }
            let _ = SetForegroundWindow(hwnd);
        }
    }
}

pub fn spawn(t: TrayCtx, state_rx: Receiver<TrayState>) {
    std::thread::Builder::new()
        .name("tray".into())
        .spawn(move || {
            if let Err(e) = run(t, state_rx) {
                log::error!("托盘图标创建失败: {e:#}");
            }
        })
        .expect("无法创建托盘线程");
}

fn run(t: TrayCtx, state_rx: Receiver<TrayState>) -> anyhow::Result<()> {
    let show = MenuItem::new("显示主窗口", true, None);
    let check = MenuItem::new("立即检测出口 IP", true, None);
    let quit = MenuItem::new("退出程序（解除所有阻断）", true, None);
    let menu = Menu::new();
    menu.append_items(&[&show, &check, &PredefinedMenuItem::separator(), &quit])?;

    let mut builder = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_menu_on_left_click(false)
        .with_tooltip("出口 IP 网络控制：启动中");
    if let Some(i) = icon(Shade::Gray) {
        builder = builder.with_icon(i);
    }
    let tray = builder.build()?;

    let mut fallback_at: Option<Instant> = None;
    let mut msg = MSG::default();
    loop {
        unsafe {
            MsgWaitForMultipleObjects(None, false, 100, QS_ALLINPUT);
            while PeekMessageW(&mut msg, None, 0, 0, PM_REMOVE).as_bool() {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }

        while let Ok(ev) = MenuEvent::receiver().try_recv() {
            if ev.id == show.id() {
                request_show(&t, &mut fallback_at);
            } else if ev.id == check.id() {
                t.backend.check_now();
            } else if ev.id == quit.id() {
                t.backend.quit();
            }
        }

        while let Ok(ev) = TrayIconEvent::receiver().try_recv() {
            match ev {
                TrayIconEvent::DoubleClick { button: MouseButton::Left, .. }
                | TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                } => request_show(&t, &mut fallback_at),
                _ => {}
            }
        }

        // 只取最新的状态
        if let Some(s) = state_rx.try_iter().last() {
            let _ = tray.set_icon(icon(s.shade));
            let _ = tray.set_tooltip(Some(&s.tooltip));
        }

        if fallback_at.is_some_and(|d| Instant::now() >= d) {
            fallback_at = None;
            force_show(&t.window_title);
        }
    }
}
