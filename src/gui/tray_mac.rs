//! macOS 菜单栏图标。
//!
//! 状态栏图标必须在主线程创建和修改：在 eframe 的创建回调（主线程、事件循环已启动）里创建，
//! 之后的状态更新通过主队列（GCD）派发回主线程。菜单事件由 AppKit 在主线程回调，
//! 窗口隐藏、egui 不再刷新时也能响应。

use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, OnceLock};

use dispatch2::DispatchQueue;
use objc2::runtime::{AnyClass, AnyObject, Bool, Imp, Sel};
use objc2::{msg_send, sel, Encode, Encoding, MainThreadMarker};
use objc2_app_kit::NSApplication;
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

use super::backend::Backend;
use super::icons::{shield_rgba, Shade};

/// 菜单栏需要显示的状态。
#[derive(PartialEq)]
pub struct TrayState {
    pub shade: Shade,
    pub tooltip: String,
    /// 菜单第一行显示的当前状态。
    pub status_line: String,
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
    static TRAY: RefCell<Option<(TrayIcon, MenuItem)>> = const { RefCell::new(None) };
}

/// 再次打开应用（在 Finder / 启动台里双击）时显示主窗口。
static REOPEN: OnceLock<Box<dyn Fn() + Send + Sync>> = OnceLock::new();

unsafe extern "C-unwind" fn should_handle_reopen(_this: *mut AnyObject, _cmd: Sel, _app: *mut AnyObject, _visible: Bool) -> Bool {
    if let Some(f) = REOPEN.get() {
        f();
    }
    Bool::NO
}

/// 菜单栏应用的窗口隐藏后，再次打开应用时系统只会发送「重新打开」事件，不会启动新进程。
/// winit 的应用代理没有处理这个事件，这里在运行时给它补上
/// `applicationShouldHandleReopen:hasVisibleWindows:`。必须在主线程、事件循环启动后调用。
fn install_reopen_handler(show: impl Fn() + Send + Sync + 'static) {
    if REOPEN.set(Box::new(show)).is_err() {
        return;
    }
    let Some(cls) = AnyClass::get(c"WinitApplicationDelegate") else {
        log::warn!("找不到 winit 的应用代理，再次打开应用时不会显示窗口");
        return;
    };
    let types = format!("{}{}{}{}{}", Bool::ENCODING, Encoding::Object, Encoding::Sel, Encoding::Object, Bool::ENCODING);
    let Ok(types) = std::ffi::CString::new(types) else { return };
    type ReopenFn = unsafe extern "C-unwind" fn(*mut AnyObject, Sel, *mut AnyObject, Bool) -> Bool;
    let imp: ReopenFn = should_handle_reopen;
    let added = unsafe {
        objc2::ffi::class_addMethod(
            cls as *const AnyClass as *mut AnyClass,
            sel!(applicationShouldHandleReopen:hasVisibleWindows:),
            std::mem::transmute::<ReopenFn, Imp>(imp),
            types.as_ptr(),
        )
    };
    if !added.as_bool() {
        log::warn!("无法处理「重新打开」事件（方法已存在）");
        return;
    }
    // NSApplication 可能在设置代理时缓存了它能响应哪些方法，重新设置一次
    let Some(mtm) = MainThreadMarker::new() else { return };
    let app = NSApplication::sharedApplication(mtm);
    unsafe {
        let delegate: *mut AnyObject = msg_send![&*app, delegate];
        if !delegate.is_null() {
            let _: () = msg_send![&*app, setDelegate: std::ptr::null::<AnyObject>()];
            let _: () = msg_send![&*app, setDelegate: delegate];
        }
    }
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
    let status = MenuItem::new("正在连接后台服务…", false, None);
    let show = MenuItem::new("打开 Egress Guard", true, None);
    let check = MenuItem::new("立即检测出口 IP", true, None);
    let quit = MenuItem::new("退出并解除阻断", true, None);
    let menu = Menu::new();
    let sep = || PredefinedMenuItem::separator();
    if let Err(e) = menu.append_items(&[&status, &sep(), &show, &check, &sep(), &quit]) {
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
        Ok(tray) => TRAY.with(|c| *c.borrow_mut() = Some((tray, status))),
        Err(e) => {
            log::error!("菜单栏图标创建失败: {e}");
            return;
        }
    }

    let (show_id, check_id, quit_id) = (show.id().clone(), check.id().clone(), quit.id().clone());
    let TrayCtx { egui_ctx, show_requested, backend, .. } = t;
    let show_window = move || {
        show_requested.store(true, Ordering::SeqCst);
        egui_ctx.request_repaint();
        DispatchQueue::main().exec_async(bring_to_front);
    };
    install_reopen_handler(show_window.clone());
    MenuEvent::set_event_handler(Some(move |ev: MenuEvent| {
        if ev.id == show_id {
            show_window();
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
                        if let Some((tray, status)) = c.borrow().as_ref() {
                            let _ = tray.set_icon(icon(s.shade));
                            let _ = tray.set_tooltip(Some(&s.tooltip));
                            status.set_text(&s.status_line);
                        }
                    });
                });
            }
        })
        .expect("无法创建菜单栏状态线程");
}

/// 有新状态时唤醒托盘线程：macOS 的状态线程阻塞在通道上，不需要额外唤醒。
pub fn wake() {}
