//! macOS 菜单栏图标。
//!
//! 状态栏图标必须在主线程创建和修改：在 eframe 的创建回调（主线程、事件循环已启动）里创建，
//! 之后的状态更新通过主队列（GCD）派发回主线程。菜单事件由 AppKit 在主线程回调，
//! 窗口隐藏、egui 不再刷新时也能响应。

use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::Arc;

use dispatch2::DispatchQueue;
use objc2::MainThreadMarker;
use objc2_app_kit::NSApplication;
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

use super::backend::Backend;
use super::icons::{shield_rgba, Shade};

/// 菜单栏需要显示的状态。
pub struct TrayState {
    pub shade: Shade,
    pub tooltip: String,
}

pub struct TrayCtx {
    pub egui_ctx: eframe::egui::Context,
    pub show_requested: Arc<AtomicBool>,
    pub backend: Arc<dyn Backend>,
    #[allow(dead_code)]
    pub window_title: String,
}

thread_local! {
    /// 只在主线程访问。
    static TRAY: RefCell<Option<TrayIcon>> = const { RefCell::new(None) };
}

/// 菜单栏图标按 2 倍像素绘制，系统按 18pt 高度显示。
fn icon(shade: Shade) -> Option<Icon> {
    Icon::from_rgba(shield_rgba(36, shade), 36, 36).ok()
}

/// 直接用 AppKit 把窗口调到前面（窗口隐藏时 egui 不刷新，ViewportCommand 要等下一帧才生效）。
pub fn bring_to_front() {
    let Some(mtm) = MainThreadMarker::new() else { return };
    let app = NSApplication::sharedApplication(mtm);
    #[allow(deprecated)]
    app.activateIgnoringOtherApps(true);
    for w in app.windows().iter() {
        w.makeKeyAndOrderFront(None);
    }
}

/// 创建菜单栏图标。必须在主线程调用。
pub fn spawn(t: TrayCtx, state_rx: Receiver<TrayState>) {
    if MainThreadMarker::new().is_none() {
        log::error!("菜单栏图标必须在主线程创建");
        return;
    }
    let show = MenuItem::new("显示主窗口", true, None);
    let check = MenuItem::new("立即检测出口 IP", true, None);
    let quit = MenuItem::new("退出（解除所有阻断）", true, None);
    let menu = Menu::new();
    if let Err(e) = menu.append_items(&[&show, &check, &PredefinedMenuItem::separator(), &quit]) {
        log::error!("菜单创建失败: {e}");
        return;
    }

    let mut builder = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_menu_on_left_click(true)
        .with_tooltip("出口 IP 网络控制：启动中");
    if let Some(i) = icon(Shade::Gray) {
        builder = builder.with_icon(i);
    }
    match builder.build() {
        Ok(tray) => TRAY.with(|c| *c.borrow_mut() = Some(tray)),
        Err(e) => {
            log::error!("菜单栏图标创建失败: {e}");
            return;
        }
    }

    let (show_id, check_id, quit_id) = (show.id().clone(), check.id().clone(), quit.id().clone());
    let TrayCtx { egui_ctx, show_requested, backend, .. } = t;
    MenuEvent::set_event_handler(Some(move |ev: MenuEvent| {
        if ev.id == show_id {
            show_requested.store(true, Ordering::SeqCst);
            egui_ctx.request_repaint();
            DispatchQueue::main().exec_async(bring_to_front);
        } else if ev.id == check_id {
            backend.check_now();
        } else if ev.id == quit_id {
            backend.quit();
        }
    }));

    // 状态更新：在普通线程等待，再派发到主线程修改图标
    std::thread::Builder::new()
        .name("tray-state".into())
        .spawn(move || {
            while let Ok(mut s) = state_rx.recv() {
                // 只取最新的状态
                while let Ok(newer) = state_rx.try_recv() {
                    s = newer;
                }
                DispatchQueue::main().exec_async(move || {
                    TRAY.with(|c| {
                        if let Some(tray) = c.borrow().as_ref() {
                            let _ = tray.set_icon(icon(s.shade));
                            let _ = tray.set_tooltip(Some(&s.tooltip));
                        }
                    });
                });
            }
        })
        .expect("无法创建菜单栏状态线程");
}
