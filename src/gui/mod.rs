//! 图形界面（eframe/egui），苹果风格：侧边栏导航、大标题、分组圆角卡片、开关控件，
//! 浅色/深色跟随系统。另有系统托盘（Windows）/ 菜单栏图标（macOS）。

mod auto;
pub mod backend;
pub mod icons;
mod leak;
mod notify;
mod platform;
mod theme;
#[cfg(windows)]
mod tray;
#[cfg(target_os = "macos")]
#[path = "tray_mac.rs"]
mod tray;
#[cfg(not(any(windows, target_os = "macos")))]
#[path = "tray_stub.rs"]
mod tray;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use eframe::egui::{self, Align, Color32, CornerRadius, Layout, Margin, RichText};

use crate::config::{self, parse_net, Appearance, ChildMode, Config, FailMode, Ipv6Mode, RawConfig};
use crate::discovery::Source;
use crate::engine::{self, Status};
use crate::eventlog::Kind;
use backend::{Backend, ServiceState};
use icons::Shade;
use platform::procs;
use theme::{Glyph, Palette};

pub const WINDOW_TITLE: &str = "出口 IP 网络控制 - egress-guard";

/// 全局断网能否按程序放行例外（macOS 的全局断网用 pf，分不清程序）。
const ALLOW_APPS: bool = !cfg!(target_os = "macos");

/// 网络扩展的说明文档。
const NETEXT_DOC: &str = "https://github.com/RollingL/egress-guard/blob/main/docs/macos-network-extension.md";

/// macOS 窗口不显示标题栏：侧边栏一直延伸到顶部，红绿灯按钮浮在侧边栏上（与「系统设置」一致）。
/// 内容需要给标题栏区域（约 28pt）留出空间。
const UNIFIED_TITLEBAR: bool = cfg!(target_os = "macos");
const TITLEBAR_H: f32 = 28.0;

/// 与平台相关的界面文字。
#[cfg(not(target_os = "macos"))]
mod text {
    pub const ENGINE_RUNNING: &str = "WFP 运行中";
    pub const OVERVIEW_SUB: &str = "根据本机公网出口 IP，自动放行或阻断受控应用的网络连接。";
    pub const DNS_SUB: &str = "域名解析（端口 53）。关闭后本工具也可能无法检测出口 IP";
    pub const NETWORK_SUB: &str = "出口 IP 不在白名单内时，切断本机的全部网络连接，而不只是受控应用。";
    pub const BLOCK_ALL_OFF: &str = "关闭时只阻断「受控应用」中的程序";
    pub const NETWORK_FOOTNOTE: &str = "受控应用不受下面的例外影响，阻断时仍然完全断网。退出程序会立即恢复全部网络。";
    pub const CHILDREN_SUB: &str = "受控应用启动的其他程序（即使是不同的 exe）自动加入阻断";
    pub const BACKEND_UNAVAILABLE: &str = "WFP 不可用，当前为模拟模式。请以管理员身份运行。";
    pub const CLOSE_HINT: &str = "点窗口右上角的 × 会隐藏到托盘，程序继续运行。要退出，请右键托盘图标选择「退出程序」，退出后所有阻断随之解除。";
    pub const PROGRAM: &str = "exe";
    pub const APPS_SUB: &str = "出口 IP 不在白名单内时，以下程序的全部网络连接会被阻断。";
    pub const KILL_EXISTING_SUB: &str = "切换为阻断时，主动断开受控应用的 TCP 连接";
    pub const SYSTEM_DIRS_HINT: &str = "Windows 系统目录下的程序（cmd、PowerShell、conhost 等）不会被自动加入。识别到的子进程会被记住，下次启动立即生效。";
    pub const AUTOSTART_TITLE: &str = "登录时自动启动";
    pub const AUTOSTART_SUB: &str = "以管理员权限在托盘中运行，不弹出 UAC";
    pub const SELF_SUB: &str = "用于在断网期间继续检测出口 IP，以便自动恢复";
    pub const VPN_HINT: &str = "部分 VPN（如 WireGuard）由系统内核发送流量，按程序放行无效，请在这里填写 VPN 服务器的 IP。";
}

#[cfg(target_os = "macos")]
mod text {
    pub const ENGINE_RUNNING: &str = "pf 运行中";
    pub const OVERVIEW_SUB: &str = "根据本机公网出口 IP，自动放行或阻断受控应用、或者整台 Mac 的网络连接。";
    // macOS 的域名解析由系统服务 mDNSResponder 代为发出，无法只放行本工具的 DNS 查询
    pub const DNS_SUB: &str = "域名解析（端口 53）。关闭后断网期间无法解析检测服务的域名，出口回到白名单也不会自动恢复";
    pub const NETWORK_SUB: &str = "出口 IP 不在白名单内时，用 pf 防火墙切断本机的全部网络连接，而不只是受控应用。";
    pub const BLOCK_ALL_OFF: &str = "关闭时只阻断「受控应用」中的应用（需要启用网络扩展）";
    pub const NETWORK_FOOTNOTE: &str = "断网时只放行下面列出的连接；启用了网络扩展时，受控应用连这些例外也不能访问。退出程序会立即恢复全部网络。";
    pub const CHILDREN_SUB: &str = "受控应用启动的其他程序自动加入阻断";
    pub const BACKEND_UNAVAILABLE: &str = "pf 不可用，当前为模拟模式。";
    pub const CLOSE_HINT: &str = "关闭窗口后程序在菜单栏继续运行。要退出，请点菜单栏图标选择「退出并解除阻断」。";
    pub const PROGRAM: &str = "应用";
    pub const APPS_SUB: &str = "出口 IP 不在白名单内时，以下应用的全部网络连接会被阻断（由网络扩展执行）。";
    pub const KILL_EXISTING_SUB: &str = "切换为阻断时，立即切断受控应用正在进行的连接（网络扩展会持续检查这些连接）";
    pub const SYSTEM_DIRS_HINT: &str = "系统目录（/System、/usr、/bin 等）下的程序不会被自动加入。识别到的子进程会被记住。";
    pub const AUTOSTART_TITLE: &str = "开机自动启动";
    pub const AUTOSTART_SUB: &str = "开机即由后台服务保护，登录后在菜单栏显示图标";
    pub const SELF_SUB: &str = "检测出口 IP 的请求（以 nobody 身份发出），以便断网期间自动恢复";
    pub const VPN_HINT: &str = "VPN 断开、正在重连时也会被断网。请在这里填写 VPN 服务器的 IP，让它能重新连上。";
}

/// 后台的安装/卸载任务（会弹出系统密码对话框，放在线程里运行）。
type Job = Arc<Mutex<Option<Result<(), String>>>>;

pub struct Options {
    pub config_path: PathBuf,
    pub start_minimized: bool,
    /// 打开时显示的页面（overview / whitelist / apps / network / leaktest / events / settings / log），用于截图。
    pub start_page: Option<String>,
    /// 打开后立即开始泄露测试（截图、CI 用）。
    pub run_leak_test: bool,
    /// 打开时页面向下滚动的距离（截图用）。
    pub scroll: Option<f32>,
}

#[derive(PartialEq, Clone, Copy)]
enum Page {
    Overview,
    Whitelist,
    Apps,
    Network,
    Leak,
    Events,
    Settings,
    Log,
}

impl Page {
    fn from_name(name: &str) -> Option<Page> {
        Some(match name {
            "overview" => Page::Overview,
            "whitelist" => Page::Whitelist,
            "apps" => Page::Apps,
            "network" => Page::Network,
            "leaktest" => Page::Leak,
            "events" => Page::Events,
            "settings" => Page::Settings,
            "log" => Page::Log,
            _ => return None,
        })
    }

    fn editable(self) -> bool {
        matches!(self, Page::Whitelist | Page::Apps | Page::Network | Page::Leak | Page::Settings)
    }
}

/// 程序选择器选中的程序加到哪个列表。
#[derive(PartialEq, Clone, Copy)]
enum PickFor {
    /// 受控应用。
    Apps,
    /// 全局断网的例外程序。
    AllowApps,
}

struct ProcPicker {
    filter: String,
    list: Vec<procs::ProcInfo>,
    target: PickFor,
}

struct App {
    backend: Arc<dyn Backend>,
    status: Arc<Mutex<Status>>,
    show_requested: Arc<AtomicBool>,
    /// 已保存/已应用的配置。
    applied: RawConfig,
    /// 正在编辑的配置。
    draft: RawConfig,
    services_text: String,
    page: Page,
    new_entry: String,
    entry_error: Option<String>,
    /// 全局断网例外地址的输入框。
    new_remote: String,
    remote_error: Option<String>,
    /// (是否成功, 文本, 时间)
    message: Option<(bool, String, Instant)>,
    load_error: Option<String>,
    picker: Option<ProcPicker>,
    autostart: bool,
    hide_on_first_frame: bool,
    /// 已经处理过第一帧。
    started: bool,
    /// 当前已应用到界面的外观。
    shown_appearance: Option<Appearance>,
    /// 页面切换动效：上一帧显示的页面及切换时刻。
    shown_page: Page,
    page_since: f64,
    /// 正在进行的后台服务安装/卸载及其说明。
    service_job: Option<(Job, &'static str)>,
    service_error: Option<String>,
    /// macOS 网络扩展的安装状态（系统一侧），以及上次请求刷新的时间。
    netext: crate::netext::State,
    netext_refreshed: Option<Instant>,
    /// 泄露测试页的状态与结果。
    leak: leak::LeakUi,
    /// 第一帧开始泄露测试。
    run_leak_test: bool,
    /// 开头几帧把页面滚动到这里（截图用），以及还剩几帧。
    start_scroll: Option<(f32, u32)>,
    /// 已保存的配置，供后台任务（自动泄露测试、检查更新）读取。
    shared_cfg: Arc<Mutex<RawConfig>>,
    auto_leak: Arc<Mutex<auto::AutoLeak>>,
    update: Arc<Mutex<auto::UpdateState>>,
    /// 「立即检查更新」。
    update_tx: mpsc::Sender<()>,
    gui_state: auto::GuiState,
    /// 「VPN 守护」网卡名称、IPv6 查询服务的文本框。
    vpn_text: String,
    v6_services_text: String,
    /// 本机网卡（设置页显示可选的 VPN 网卡），以及上次读取的时间。
    adapters: (Option<Instant>, Vec<(String, String, bool)>),
    /// 连接记录页的筛选。
    event_filter: Option<Kind>,
}

pub fn run(opts: Options) -> Result<()> {
    let (cfg, load_error) = if opts.config_path.exists() {
        let saved_as = |broken: &Option<std::path::PathBuf>| match broken {
            Some(b) => format!("原文件已另存为 {}。", b.display()),
            None => String::new(),
        };
        match Config::load_recovering(&opts.config_path) {
            config::Loaded::Ok(c) => (c, None),
            config::Loaded::LastGood { cfg: c, error, broken } => {
                let msg = format!(
                    "已改用最近一次有效的配置（受控应用、白名单等与上次成功保存时相同）。{}检查各项设置后点「保存并应用」，会覆盖有误的文件。{error}",
                    saved_as(&broken)
                );
                (c, Some(msg))
            }
            config::Loaded::Failed { error: e, broken } => {
                log::error!("{e}");
                let msg = format!(
                    "没有可用的最近有效配置，当前按默认设置运行：没有受控应用，也没有开启全局断网，出口不在白名单时不会拦截任何连接。{}请检查各项设置后点「保存并应用」。{e}",
                    saved_as(&broken)
                );
                (Config::from_raw(RawConfig::default())?, Some(msg))
            }
        }
    } else {
        log::info!("配置文件不存在，将使用默认设置：{}", opts.config_path.display());
        (Config::from_raw(RawConfig::default())?, None)
    };

    let viewport = egui::ViewportBuilder::default()
        .with_title(if UNIFIED_TITLEBAR { "Egress Guard" } else { WINDOW_TITLE })
        .with_fullsize_content_view(UNIFIED_TITLEBAR)
        .with_titlebar_shown(!UNIFIED_TITLEBAR)
        .with_title_shown(!UNIFIED_TITLEBAR)
        .with_inner_size([900.0, 620.0])
        .with_min_inner_size([720.0, 480.0])
        .with_icon(egui::IconData { rgba: icons::shield_rgba(64, Shade::Green), width: 64, height: 64 });
    let native = native_options(viewport);
    let start_page = opts.start_page.as_deref().and_then(Page::from_name).unwrap_or(Page::Overview);

    eframe::run_native(
        "egress-guard",
        native,
        Box::new(move |cc| {
            theme::setup_fonts(&cc.egui_ctx);
            theme::apply_style(&cc.egui_ctx);
            let ctx = cc.egui_ctx.clone();
            let status = Arc::new(Mutex::new(Status::default()));
            let (tray_tx, tray_rx) = mpsc::channel();

            let reporter: engine::Reporter = {
                let status = status.clone();
                let ctx = ctx.clone();
                Arc::new(move |s: &Status| {
                    *status.lock().unwrap() = s.clone();
                    let _ = tray_tx.send(tray_state(s));
                    ctx.request_repaint();
                })
            };
            let (backend, cfg) = start_backend(cfg, &opts.config_path, reporter);
            let show_requested = Arc::new(AtomicBool::new(false));
            tray::spawn(
                tray::TrayCtx {
                    egui_ctx: ctx.clone(),
                    show_requested: show_requested.clone(),
                    backend: backend.clone(),
                    window_title: WINDOW_TITLE.into(),
                },
                tray_rx,
            );

            let raw = cfg.to_raw();
            let leak = leak::LeakUi::new(&raw.leak_test.stun_servers);
            let shared_cfg = Arc::new(Mutex::new(raw.clone()));
            let auto_leak = Arc::new(Mutex::new(auto::AutoLeak::default()));
            auto::LeakScheduler {
                status: status.clone(),
                config: shared_cfg.clone(),
                job: leak.job.clone(),
                backend: backend.clone(),
                ctx: ctx.clone(),
                state: auto_leak.clone(),
            }
            .spawn();
            let update = Arc::new(Mutex::new(auto::UpdateState::default()));
            let (update_tx, update_rx) = mpsc::channel();
            auto::UpdateChecker { config: shared_cfg.clone(), state: update.clone(), manual: update_rx, ctx: ctx.clone() }
                .spawn();
            Ok(Box::new(App {
                leak,
                shared_cfg,
                auto_leak,
                update,
                update_tx,
                gui_state: auto::GuiState::load(),
                vpn_text: raw.vpn.interfaces.join("\n"),
                v6_services_text: raw.ipv6.services.join("\n"),
                adapters: (None, Vec::new()),
                event_filter: None,
                run_leak_test: opts.run_leak_test,
                start_scroll: opts.scroll.map(|y| (y, 30)),
                autostart: backend.autostart_enabled(),
                backend,
                status,
                show_requested,
                services_text: raw.detect.services.join("\n"),
                applied: raw.clone(),
                draft: raw,
                page: start_page,
                new_entry: String::new(),
                entry_error: None,
                new_remote: String::new(),
                remote_error: None,
                message: None,
                load_error,
                picker: None,
                hide_on_first_frame: opts.start_minimized,
                started: false,
                shown_appearance: None,
                shown_page: start_page,
                page_since: f64::NEG_INFINITY,
                service_job: None,
                service_error: None,
                netext: Default::default(),
                netext_refreshed: None,
            }))
        }),
    )
    .map_err(|e| anyhow::anyhow!("界面启动失败: {e}"))
}

/// 界面窗口的 eframe 设置（正式界面与剪贴板自检共用，保证自检测到的就是用户用的那一套）。
fn native_options(viewport: egui::ViewportBuilder) -> eframe::NativeOptions {
    #[allow(unused_mut)]
    let mut native = eframe::NativeOptions { viewport, ..Default::default() };
    // macOS：菜单栏应用，不在程序坞显示图标（与 Info.plist 的 LSUIElement 一致）
    #[cfg(target_os = "macos")]
    {
        native.event_loop_builder = Some(Box::new(|b| {
            use winit::platform::macos::{ActivationPolicy, EventLoopBuilderExtMacOS};
            b.with_activation_policy(ActivationPolicy::Accessory);
        }));
    }
    native
}

/// 剪贴板自检（CI 用）：程序启动时复制的文字。
pub const CLIPBOARD_PROBE_COPY: &str = "egress-guard-copy-ok";

/// 剪贴板自检（CI 用）：打开一个只有输入框的窗口并让它获得焦点。
///
/// 发一条测试通知，打印使用的方式（CI 用：之后截图看通知有没有出现）。
pub fn notify_selftest() -> Result<()> {
    let how = notify::try_show("Egress Guard 通知测试", "自动泄露测试发现泄露、发现新版本时会这样提醒你。")?;
    eprintln!("已发送通知：{how}");
    Ok(())
}

/// 第一帧把 [`CLIPBOARD_PROBE_COPY`] 复制到系统剪贴板（检查「复制」能到达其他程序）；
/// 之后 CI 往系统剪贴板放一段文字、模拟按下 ⌘V / Ctrl+V，`seconds` 秒后把输入框里的内容
/// 写入 `out`（JSON：`{"pasted": "..."}`）并退出（检查「粘贴」能从其他程序拿到内容）。
pub fn clipboard_selftest(out: PathBuf, seconds: f64) -> Result<()> {
    struct Probe {
        text: String,
        out: PathBuf,
        deadline: f64,
        started: bool,
        done: bool,
    }
    impl eframe::App for Probe {
        fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
            if !self.started {
                self.started = true;
                ctx.copy_text(CLIPBOARD_PROBE_COPY.to_owned());
                ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                #[cfg(target_os = "macos")]
                tray::bring_to_front();
            }
            let now = ctx.input(|i| i.time);
            if now >= self.deadline && !self.done {
                self.done = true;
                let json = serde_json::json!({ "pasted": self.text });
                if let Err(e) = std::fs::write(&self.out, json.to_string()) {
                    eprintln!("无法写入 {}: {e}", self.out.display());
                }
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            ctx.request_repaint_after(Duration::from_millis(100));
        }

        fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
            egui::CentralPanel::default().show(ui, |ui| {
                ui.label("剪贴板自检");
                let r = ui.add(egui::TextEdit::singleline(&mut self.text).desired_width(f32::INFINITY));
                r.request_focus();
            });
        }
    }

    let viewport = egui::ViewportBuilder::default().with_title("Egress Guard 剪贴板自检").with_inner_size([420.0, 120.0]);
    eframe::run_native(
        "egress-guard-clipboard-selftest",
        native_options(viewport),
        Box::new(move |cc| {
            theme::setup_fonts(&cc.egui_ctx);
            Ok(Box::new(Probe { text: String::new(), out, deadline: seconds, started: false, done: false }))
        }),
    )
    .map_err(|e| anyhow::anyhow!("界面启动失败: {e}"))
}

/// 启动引擎。Windows/Linux：在本进程中运行；macOS：连接 root 后台服务，并以服务的配置为准。
#[cfg(not(target_os = "macos"))]
fn start_backend(cfg: Config, config_path: &std::path::Path, reporter: engine::Reporter) -> (Arc<dyn Backend>, Config) {
    let learned = crate::learned_file(config_path);
    crate::eventlog::init(&crate::events_file(config_path));
    let engine = Arc::new(engine::spawn(cfg.clone(), false, false, Some(learned), reporter));
    (Arc::new(backend::Local { engine, config_path: config_path.to_path_buf() }), cfg)
}

#[cfg(target_os = "macos")]
fn start_backend(cfg: Config, _config_path: &std::path::Path, reporter: engine::Reporter) -> (Arc<dyn Backend>, Config) {
    let remote = backend::Remote::start(reporter);
    let cfg = remote.take_new_config().and_then(|raw| Config::from_raw(raw).ok()).unwrap_or(cfg);
    (remote, cfg)
}

fn tray_state(s: &Status) -> tray::TrayState {
    let (shade, what) = if !s.running {
        (Shade::Gray, if s.backend_error.is_some() { "未连接后台服务" } else { "已停止" }.to_string())
    } else if inert(s) {
        (Shade::Amber, "未拦截（网络扩展、全局断网都未启用）".to_string())
    } else if let Some(e) = &s.apply_error {
        (Shade::Amber, shorten(e, 60))
    } else if s.blocked {
        (Shade::Red, "已阻断".to_string())
    } else if s.egress_ip.is_some() {
        (Shade::Green, "已放行".to_string())
    } else {
        (Shade::Gray, "检测中".to_string())
    };
    let shade = if s.simulated && s.running { Shade::Amber } else { shade };
    let mut tooltip = format!("出口 IP 网络控制：{what}");
    if let Some(ip) = s.egress_ip {
        tooltip.push_str(&format!("\n出口 IP：{ip}"));
    }
    if let Some(r) = s.block_reason.as_deref().filter(|_| s.blocked) {
        tooltip.push_str(&format!("\n{}", shorten(r, 60)));
    }
    if s.simulated {
        tooltip.push_str("\n模拟模式（规则未生效）");
    }
    tray::TrayState {
        shade,
        tooltip,
        #[cfg(target_os = "macos")]
        status_line: status_line(s),
    }
}

/// macOS 菜单栏菜单第一行：一句话说明现在的状态。
#[cfg(target_os = "macos")]
fn status_line(s: &Status) -> String {
    let line = if !s.running {
        if s.backend_error.is_some() { "未连接后台服务".to_owned() } else { "已停止".to_owned() }
    } else if inert(s) {
        "未拦截：网络扩展、全局断网都没有启用".to_owned()
    } else if let Some(e) = &s.apply_error {
        shorten(e, 40)
    } else if s.blocked {
        match s.egress_ip {
            Some(ip) => format!("已切断网络：出口 IP {ip} 不在白名单"),
            None => "已切断网络：正在确认出口 IP".to_owned(),
        }
    } else if let Some(ip) = s.egress_ip {
        format!("网络已放行：出口 IP {ip}")
    } else {
        "正在检测出口 IP…".to_owned()
    };
    if s.simulated { format!("{line}（模拟模式）") } else { line }
}

/// 阻断范围的名称。只能整机断网时（macOS 网络扩展未连接）直接说「网络」。
fn scope_name(s: &Status) -> &'static str {
    if !s.per_app {
        "网络"
    } else if s.block_all {
        "全部网络"
    } else {
        "受控应用"
    }
}

/// 引擎判定要阻断，但按应用断网不可用（macOS 网络扩展未连接）而全局断网又没开，实际什么也不拦截。
fn inert(s: &Status) -> bool {
    s.running && s.blocked && !s.per_app && !s.block_all && !s.simulated
}

/// 概览大标题：带上阻断范围（「受控应用已阻断」），未运行或未拦截时不带。
fn headline(s: &Status, title: &str) -> String {
    if !s.running || inert(s) { title.to_owned() } else { format!("{}{title}", scope_name(s)) }
}

/// 状态的展示信息：标题、说明（说的是接下来会发生什么）、颜色。
fn describe(s: &Status, p: &Palette) -> (&'static str, String, Color32) {
    if !s.running {
        match &s.backend_error {
            Some(e) => ("未连接", format!("{e}。"), p.gray),
            None => ("已停止", "后台引擎没有运行。".into(), p.gray),
        }
    } else if inert(s) {
        ("未拦截", "出口 IP 没有通过白名单，但网络扩展没有启用、全局断网也没有开启，什么也没有切断。".into(), p.orange)
    } else if let Some(e) = &s.apply_error {
        ("未生效", format!("{e}。每 5 秒自动重试一次。"), p.orange)
    } else if s.blocked {
        let why = match (&s.block_reason, s.egress_ip, &s.detect_error) {
            (Some(r), _, _) if s.egress_ip.is_some() || !s.checking => format!("{r}。出口回到白名单后会自动恢复。"),
            (_, Some(_), _) => "出口 IP 不在白名单内。出口回到白名单后会自动恢复。".into(),
            (_, None, Some(_)) => "无法确定出口 IP，为安全起见保持断网。".into(),
            (_, None, None) => "正在确认出口 IP，确认前保持断网。".into(),
        };
        ("已阻断", why, p.red)
    } else if s.egress_ip.is_some() {
        let why = if s.vpn_guarded.is_empty() {
            "出口 IP 在白名单内。网络一有变化就会重新检查。".to_owned()
        } else {
            format!("出口 IP 在白名单内。VPN（{}）一断开就立即断网。", s.vpn_guarded.join("、"))
        };
        ("已放行", why, p.green)
    } else if s.detect_error.is_some() {
        ("状态未知", "出口 IP 检测失败，按「检测失败时」的设置保持当前状态。".into(), p.orange)
    } else {
        ("检测中", "正在确认出口 IP…".into(), p.gray)
    }
}

impl App {
    fn dirty(&self) -> bool {
        self.draft != self.applied
    }

    fn notify(&mut self, ok: bool, text: impl Into<String>) {
        self.message = Some((ok, text.into(), Instant::now()));
    }

    fn save_and_apply(&mut self) {
        self.sync_services();
        match Config::from_raw(self.draft.clone()).and_then(|cfg| {
            self.backend.apply(&cfg)?;
            Ok(cfg)
        }) {
            Ok(cfg) => {
                self.set_applied(cfg.to_raw());
                self.load_error = None;
                self.notify(true, "已保存并生效");
            }
            Err(e) => self.notify(false, format!("保存失败：{e:#}")),
        }
    }

    /// 采用新的已保存配置（保存成功、后台服务推来新配置时）。
    fn set_applied(&mut self, raw: RawConfig) {
        *self.shared_cfg.lock().unwrap() = raw.clone();
        self.applied = raw;
        self.draft = self.applied.clone();
        self.reset_texts();
    }

    /// 让文本框与 draft 一致。
    fn reset_texts(&mut self) {
        self.services_text = self.draft.detect.services.join("\n");
        self.vpn_text = self.draft.vpn.interfaces.join("\n");
        self.v6_services_text = self.draft.ipv6.services.join("\n");
        self.leak.reset_text(&self.draft.leak_test.stun_servers);
    }

    fn revert(&mut self) {
        self.draft = self.applied.clone();
        self.reset_texts();
        self.message = None;
        self.entry_error = None;
        self.remote_error = None;
    }

    fn sync_services(&mut self) {
        let lines = |t: &str| -> Vec<String> { t.lines().map(|l| l.trim().to_owned()).filter(|l| !l.is_empty()).collect() };
        self.draft.detect.services = lines(&self.services_text);
        self.draft.vpn.interfaces = lines(&self.vpn_text);
        self.draft.ipv6.services = lines(&self.v6_services_text);
    }

    fn add_whitelist_entry(&mut self, entry: String) {
        let entry = entry.trim().to_owned();
        if entry.is_empty() {
            return;
        }
        match parse_net(&entry) {
            Ok(_) if self.draft.whitelist.iter().any(|e| e == &entry) => {
                self.entry_error = Some("该条目已存在".into());
            }
            Ok(_) => {
                self.draft.whitelist.push(entry);
                self.new_entry.clear();
                self.entry_error = None;
            }
            Err(e) => self.entry_error = Some(format!("{e}")),
        }
    }

    fn add_app(&mut self, path: PathBuf) {
        let key = procs::normalize_path(&path.to_string_lossy());
        if !self.draft.apps.iter().any(|a| procs::normalize_path(&a.to_string_lossy()) == key) {
            self.draft.apps.push(path);
        }
    }

    fn add_allow_app(&mut self, path: PathBuf) {
        let key = procs::normalize_path(&path.to_string_lossy());
        let list = &mut self.draft.block_all.allow_apps;
        if !list.iter().any(|a| procs::normalize_path(&a.to_string_lossy()) == key) {
            list.push(path);
        }
    }

    fn add_remote_entry(&mut self) {
        let entry = self.new_remote.trim().to_owned();
        if entry.is_empty() {
            return;
        }
        match parse_net(&entry) {
            Ok(net) => {
                let text = crate::config::format_net(&net);
                if self.draft.block_all.allow_remote.contains(&text) {
                    self.remote_error = Some("该地址已存在".into());
                } else {
                    self.draft.block_all.allow_remote.push(text);
                    self.new_remote.clear();
                    self.remote_error = None;
                }
            }
            Err(_) => self.remote_error = Some(format!("无法解析为 IP 或 CIDR：{entry}")),
        }
    }

    // ---------------- 后台服务（macOS） ----------------

    /// 在线程中安装/卸载后台服务（期间系统会弹出管理员密码对话框）。
    fn start_service_job(&mut self, ctx: &egui::Context, install: bool) {
        let job: Job = Arc::new(Mutex::new(None));
        let (b, j, ctx) = (self.backend.clone(), job.clone(), ctx.clone());
        std::thread::spawn(move || {
            let r = if install { b.install_service() } else { b.uninstall_service() };
            *j.lock().unwrap() = Some(r.map_err(|e| format!("{e:#}")));
            ctx.request_repaint();
        });
        self.service_error = None;
        self.service_job = Some((job, if install { "后台服务已安装" } else { "后台服务已卸载" }));
    }

    fn poll_service_job(&mut self) {
        let done = self.service_job.as_ref().and_then(|(j, msg)| j.lock().unwrap().take().map(|r| (r, *msg)));
        if let Some((r, msg)) = done {
            self.service_job = None;
            // 安装/卸载会改变自动启动的状态（卸载时一并关闭）
            self.autostart = self.backend.autostart_enabled();
            match r {
                Ok(()) => self.notify(true, msg),
                Err(e) if e == "已取消" => {}
                Err(e) => {
                    self.notify(false, e.clone());
                    self.service_error = Some(e);
                }
            }
        }
    }

    /// 概览顶部：后台服务未安装、连不上或版本不一致时的提示。
    fn service_card(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let ours = env!("CARGO_PKG_VERSION");
        let (title, body, button) = match self.backend.service() {
            ServiceState::NotApplicable => return,
            ServiceState::Running { version } if version == ours => return,
            ServiceState::Running { version } => (
                "后台服务需要更新",
                format!("后台服务是 {version} 版，界面是 {ours} 版。更新时需要输入管理员密码。"),
                "更新后台服务…",
            ),
            ServiceState::NotInstalled => (
                "需要安装后台服务",
                "macOS 上由一个以 root 运行的后台服务负责检测出口 IP、设置 pf 防火墙。安装时需要输入一次管理员密码，之后日常使用不再需要。".to_owned(),
                "安装后台服务…",
            ),
            // 刚启动、还没尝试连接过
            ServiceState::Unreachable(e) if e.is_empty() => return,
            ServiceState::Unreachable(e) => ("正在连接后台服务", format!("{e}。如果一直连不上，可以重新安装。"), "重新安装…"),
        };
        let body = match &self.service_error {
            Some(e) => format!("{body}\n上次操作失败：{e}"),
            None => body,
        };
        let busy = self.service_job.is_some();
        let mut clicked = false;
        warning_card_with(ui, p, title, &body, |ui| {
            if busy {
                ui.label(RichText::new("等待管理员授权…").size(12.5).color(p.secondary));
                ui.add(egui::Spinner::new().size(14.0));
            } else {
                clicked = theme::accent_button(ui, p, button, true).clicked();
            }
        });
        if clicked {
            self.start_service_job(ui.ctx(), true);
        }
        ui.add_space(4.0);
    }

    /// 设置页「启动」分组里的后台服务一行（仅 macOS）。
    fn service_rows(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let state = self.backend.service();
        let (color, label) = match &state {
            ServiceState::NotApplicable => return,
            ServiceState::Running { version } => (p.green, format!("运行中 · {version}")),
            ServiceState::NotInstalled => (p.gray, "未安装".to_owned()),
            ServiceState::Unreachable(_) => (p.orange, "未连接".to_owned()),
        };
        theme::hairline(ui, p);
        let mut action = None;
        let busy = self.service_job.is_some();
        theme::row(ui, p, "后台服务", Some("以 root 运行，负责检测出口 IP、设置 pf 防火墙"), |ui| {
            if busy {
                ui.add(egui::Spinner::new().size(14.0));
            } else if state == ServiceState::NotInstalled {
                if theme::text_button(ui, p.accent, "安装…").clicked() {
                    action = Some(true);
                }
            } else if theme::text_button(ui, p.red, "卸载…").on_hover_text("停止后台服务并移除全部 pf 规则").clicked() {
                action = Some(false);
            }
            theme::chip(ui, color, &label);
        });
        if let Some(install) = action {
            self.start_service_job(ui.ctx(), install);
        }
    }

    // ---------------- 检查更新 ----------------

    /// 概览顶部：发现新版本时的提示。
    fn update_card(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let rel = match self.update.lock().unwrap().newer() {
            Some(r) if r.version != self.gui_state.dismissed_version => r.clone(),
            _ => return,
        };
        let notes = rel.notes.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with('#')).unwrap_or("");
        let body = format!(
            "当前是 {}。{}",
            crate::update::CURRENT,
            if notes.is_empty() { String::new() } else { shorten(notes.trim_start_matches(['-', '*', ' ']), 120) }
        );
        let (mut download, mut dismiss) = (false, false);
        info_card_with(ui, p, &format!("Egress Guard {} 已发布", rel.version), &body, |ui| {
            dismiss = theme::text_button(ui, p.secondary, "忽略这个版本").clicked();
            download = theme::accent_button(ui, p, if rel.download.is_some() { "下载" } else { "查看" }, true).clicked();
        });
        if download {
            open_url(rel.download.as_deref().unwrap_or(&rel.url));
        }
        if dismiss {
            // 后台线程也会写这个文件（已通知的版本），先读最新的再改
            self.gui_state = auto::GuiState::load();
            self.gui_state.dismissed_version = rel.version.clone();
            self.gui_state.save();
        }
        ui.add_space(4.0);
    }

    fn update_section(&mut self, ui: &mut egui::Ui, p: &Palette) {
        theme::section(ui, p, "检查更新");
        let st = self.update.lock().unwrap().clone();
        let mut check_now = false;
        theme::card(ui, p, |ui| {
            let u = &mut self.draft.update;
            theme::row(ui, p, "自动检查新版本", Some("启动时和之后每天一次，读取 GitHub 上的发布版本；发现新版本时通知你"), |ui| {
                theme::toggle(ui, p, &mut u.check);
            });
            theme::hairline(ui, p);
            theme::row(ui, p, "仓库", None, |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut u.repo)
                        .desired_width(220.0)
                        .font(egui::TextStyle::Monospace)
                        .margin(Margin::symmetric(8, 4)),
                );
            });
            theme::hairline(ui, p);
            theme::row(ui, p, "访问令牌", Some("私有仓库才需要：GitHub 细粒度令牌，只给这个仓库 Contents 只读权限"), |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut u.token)
                        .password(true)
                        .hint_text("公开仓库留空")
                        .desired_width(220.0)
                        .margin(Margin::symmetric(8, 4)),
                );
            });
            theme::hairline(ui, p);
            let (color, text) = match (&st.newer(), &st.latest, &st.error) {
                _ if st.checking => (p.secondary, "正在检查…".to_owned()),
                (Some(r), _, _) => (p.accent, format!("有新版本 {}", r.version)),
                (None, Some(r), _) => (p.green, format!("已是最新（最新发布 {}）", r.version)),
                (None, None, Some(e)) => (p.orange, shorten(e, 60)),
                _ => (p.secondary, "尚未检查".to_owned()),
            };
            let sub = st.checked_at.as_ref().map(|t| format!("上次检查：{t}"));
            theme::row(ui, p, &format!("当前版本 {}", crate::update::CURRENT), sub.as_deref(), |ui| {
                if st.checking {
                    ui.add(egui::Spinner::new().size(14.0));
                } else {
                    check_now = theme::gray_button(ui, p, "立即检查").clicked();
                }
                ui.label(RichText::new(text).size(12.5).color(color))
                    .on_hover_text(st.error.clone().unwrap_or_default());
            });
            if let Some(r) = st.newer() {
                theme::hairline(ui, p);
                let r = r.clone();
                theme::row(ui, p, &format!("新版本 {}", r.version), None, |ui| {
                    if theme::text_button(ui, p.accent, "打开发布页  ›").on_hover_text(&r.url).clicked() {
                        open_url(&r.url);
                    }
                });
            }
        });
        if check_now {
            // 用正在编辑的仓库和令牌（尚未保存时也能先试试）
            let mut cfg = self.shared_cfg.lock().unwrap().clone();
            cfg.update = self.draft.update.clone();
            cfg.update.repo = cfg.update.repo.trim().trim_matches('/').to_owned();
            cfg.update.token = cfg.update.token.trim().to_owned();
            *self.shared_cfg.lock().unwrap() = cfg;
            let _ = self.update_tx.send(());
        }
        theme::footnote(ui, p, "只读取发布信息，不会自动下载或安装。令牌保存在配置文件里。");
    }

    // ---------------- VPN 守护、IPv6 ----------------

    fn vpn_section(&mut self, ui: &mut egui::Ui, p: &Palette, s: &Status) {
        theme::section(ui, p, "VPN 守护");
        if self.adapters.0.is_none_or(|t| t.elapsed() >= Duration::from_secs(2)) {
            self.adapters = (Some(Instant::now()), crate::vpn::candidates(&crate::vpn::scan().unwrap_or_default()));
        }
        let mut add = None;
        theme::card(ui, p, |ui| {
            let v = &mut self.draft.vpn;
            theme::row(
                ui,
                p,
                "VPN 断开时立即断网",
                Some("放行时记下正在使用的 VPN 网卡，它断开、关闭或失去地址就立即阻断，不等下一次检测"),
                |ui| {
                    theme::toggle(ui, p, &mut v.guard);
                },
            );
            theme::hairline(ui, p);
            theme::row(ui, p, "连着 VPN 时的检测间隔", Some("更勤地确认出口 IP，VPN 服务器一侧换了出口也能尽快发现；0 表示与平时相同"), |ui| {
                ui.add(egui::DragValue::new(&mut v.check_interval_secs).range(0..=3600).suffix(" 秒"));
            });
            theme::hairline(ui, p);
            ui.add_space(4.0);
            ui.label(RichText::new("守护的网卡").color(p.label));
            ui.add_space(-2.0);
            ui.label(
                RichText::new("每行一个网卡名称（Windows 也可以填网卡描述）。留空时自动识别 utun、wg、ppp、TAP、WireGuard、OpenVPN 等 VPN 网卡")
                    .size(12.0)
                    .color(p.secondary),
            );
            ui.add(
                egui::TextEdit::multiline(&mut self.vpn_text)
                    .desired_rows(2)
                    .desired_width(f32::INFINITY)
                    .hint_text("自动识别")
                    .font(egui::TextStyle::Monospace)
                    .margin(Margin::symmetric(8, 6)),
            );
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = egui::vec2(6.0, 6.0);
                ui.label(RichText::new("本机网卡（点击加入）：").size(12.0).color(p.secondary));
                for (name, desc, vpnish) in &self.adapters.1 {
                    let on = s.vpn_connected.contains(name);
                    let color = if s.vpn_guarded.contains(name) { p.green } else if on || *vpnish { p.accent } else { p.gray };
                    let hover = if desc.is_empty() { name.clone() } else { format!("{name}\n{desc}") };
                    let hover = if s.vpn_guarded.contains(name) {
                        format!("{hover}\n守护中")
                    } else if on {
                        format!("{hover}\n识别为 VPN")
                    } else {
                        hover
                    };
                    if theme::chip(ui, color, name).on_hover_text(hover).interact(egui::Sense::click()).clicked() {
                        add = Some(name.clone());
                    }
                }
            });
            ui.add_space(4.0);
        });
        if let Some(name) = add {
            if !self.vpn_text.lines().any(|l| l.trim().eq_ignore_ascii_case(&name)) {
                if !self.vpn_text.trim().is_empty() && !self.vpn_text.ends_with('\n') {
                    self.vpn_text.push('\n');
                }
                self.vpn_text.push_str(&name);
            }
        }
        let status = if !s.vpn_guarded.is_empty() {
            format!("正在守护：{}。", s.vpn_guarded.join("、"))
        } else if !s.vpn_connected.is_empty() {
            format!("识别到的 VPN：{}（出口通过白名单后开始守护）。", s.vpn_connected.join("、"))
        } else {
            "现在没有识别到 VPN 网卡。".to_owned()
        };
        theme::footnote(ui, p, &format!("{status}VPN 重新连上、出口回到白名单后自动恢复。"));
    }

    fn ipv6_section(&mut self, ui: &mut egui::Ui, p: &Palette) {
        theme::section(ui, p, "IPv6");
        theme::card(ui, p, |ui| {
            theme::row(ui, p, "IPv6 防护", None, |ui| {
                theme::segmented(
                    ui,
                    p,
                    &mut self.draft.ipv6.mode,
                    &[(Ipv6Mode::Off, "不处理"), (Ipv6Mode::Block, "始终阻断"), (Ipv6Mode::Check, "检测出口")],
                );
            });
            let explain = match self.draft.ipv6.mode {
                Ipv6Mode::Check => "另外只走 IPv6 检测一次出口：本机能直连 IPv6、而 IPv6 出口不在白名单时也阻断（IPv6 流量常常绕过只支持 IPv4 的 VPN）",
                Ipv6Mode::Block => {
                    if cfg!(target_os = "macos") {
                        "放行期间也一直切断 IPv6：受控应用的 IPv6 连接由网络扩展切断，开启全局断网时用 pf 切断整机 IPv6（例外同全局断网）"
                    } else {
                        "放行期间也一直切断 IPv6：受控应用的 IPv6 连接，开启全局断网时为整机 IPv6（例外同全局断网）。适合不支持 IPv6 的 VPN"
                    }
                }
                Ipv6Mode::Off => "只按默认路由检测到的出口 IP 决定（0.8 及以前的行为）",
            };
            ui.label(RichText::new(explain).size(12.0).color(p.secondary));
            if self.draft.ipv6.mode == Ipv6Mode::Check {
                theme::hairline(ui, p);
                ui.add_space(4.0);
                ui.label(RichText::new("IPv6 查询服务").color(p.label));
                ui.add_space(-2.0);
                ui.label(RichText::new("每行一个，只走 IPv6、同时请求，第一个成功的结果生效；本机有 IPv6 路由却都失败时按检测失败处理").size(12.0).color(p.secondary));
                ui.add(
                    egui::TextEdit::multiline(&mut self.v6_services_text)
                        .desired_rows(3)
                        .desired_width(f32::INFINITY)
                        .font(egui::TextStyle::Monospace)
                        .margin(Margin::symmetric(8, 6)),
                );
            }
            ui.add_space(4.0);
        });
        if self.draft.ipv6.mode == Ipv6Mode::Check {
            theme::footnote(ui, p, "IPv6 出口不在白名单而又用不到 IPv6 时，可以改为「始终阻断」，或者把 IPv6 出口加入白名单。");
        }
    }

    // ---------------- 连接记录 ----------------

    fn events_page(&mut self, ui: &mut egui::Ui, p: &Palette) {
        theme::page_title(ui, p, "连接记录", "每次阻断、恢复的时间、原因和当时的出口 IP，以及自动泄露测试发现的泄露。");
        let events = self.backend.events();
        let mut clear = false;
        ui.horizontal(|ui| {
            theme::segmented(
                ui,
                p,
                &mut self.event_filter,
                &[(None, "全部"), (Some(Kind::Block), "阻断"), (Some(Kind::Restore), "恢复"), (Some(Kind::Leak), "泄露")],
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if !events.is_empty() {
                    clear = theme::gray_button(ui, p, "清空").clicked();
                }
                let n = events.iter().filter(|e| e.kind == Kind::Block).count();
                ui.label(RichText::new(format!("共 {} 条，阻断 {n} 次", events.len())).size(12.5).color(p.secondary));
            });
        });
        ui.add_space(6.0);
        const SHOWN: usize = 300;
        let list: Vec<_> = events.iter().rev().filter(|e| self.event_filter.is_none_or(|k| e.kind == k)).take(SHOWN).collect();
        theme::card(ui, p, |ui| {
            if list.is_empty() {
                empty_state(ui, p, "暂无记录", "阻断、恢复和自动泄露测试发现的泄露会记在这里。");
                return;
            }
            let n = list.len();
            for (i, e) in list.iter().enumerate() {
                let color = match e.kind {
                    Kind::Block => p.red,
                    Kind::Restore => p.green,
                    Kind::Leak => p.orange,
                };
                ui.horizontal(|ui| {
                    ui.set_min_height(44.0);
                    ui.allocate_ui_with_layout(egui::vec2(52.0, 40.0), Layout::top_down(Align::Min), |ui| {
                        ui.add_space(6.0);
                        theme::chip(ui, color, e.kind.label());
                    });
                    ui.vertical(|ui| {
                        ui.add_space(4.0);
                        ui.add(egui::Label::new(RichText::new(&e.reason).color(p.label)).wrap());
                        ui.add_space(-5.0);
                        let mut sub = vec![e.time.clone()];
                        if let Some(ip) = e.egress {
                            sub.push(format!("出口 {ip}"));
                        }
                        if let Some(ip) = e.egress_v6 {
                            sub.push(format!("IPv6 {ip}"));
                        }
                        if !e.scope.is_empty() {
                            sub.push(e.scope.clone());
                        }
                        ui.label(RichText::new(sub.join(" · ")).size(12.0).color(p.secondary));
                        ui.add_space(2.0);
                    });
                });
                if i + 1 < n {
                    theme::hairline(ui, p);
                }
            }
        });
        let file = crate::events_file(std::path::Path::new(&self.backend.config_location()));
        theme::footnote(
            ui,
            p,
            &format!("最多保留最近 {} 条，这里显示最近 {SHOWN} 条。记录文件：{}", crate::eventlog::MAX_EVENTS, file.display()),
        );
        if clear {
            match self.backend.clear_events() {
                Ok(()) => self.notify(true, "已清空连接记录"),
                Err(e) => self.notify(false, format!("{e:#}")),
            }
        }
        ui.ctx().request_repaint_after(Duration::from_secs(2));
    }

    // ---------------- 网络扩展（macOS） ----------------

    /// 定时读取网络扩展的安装状态；在「受控应用」页时每 10 秒向系统查询一次。
    fn poll_netext(&mut self, ctx: &egui::Context) {
        if !crate::netext::supported() {
            return;
        }
        if self.page == Page::Apps && self.netext_refreshed.is_none_or(|t| t.elapsed() >= Duration::from_secs(10)) {
            self.netext_refreshed = Some(Instant::now());
            crate::netext::refresh();
        }
        self.netext = crate::netext::state();
        if self.page == Page::Apps {
            ctx.request_repaint_after(Duration::from_millis(if self.netext.busy() { 300 } else { 1000 }));
        }
    }

    /// 「受控应用」页顶部：网络扩展的状态与操作。
    fn netext_card(&mut self, ui: &mut egui::Ui, p: &Palette) {
        enum Act {
            Activate,
            EnableFilter,
            OpenSettings,
        }
        let s = self.status.lock().unwrap().clone();
        let st = self.netext.clone();

        if let Some(v) = &s.filter_ext {
            let mut deactivate = false;
            theme::card(ui, p, |ui| {
                theme::row(ui, p, "按应用断网", Some(&format!("网络扩展 {v} 已连接后台服务，逐个放行或切断受控应用的连接")), |ui| {
                    theme::chip(ui, p.green, "已启用");
                });
                theme::hairline(ui, p);
                theme::row(ui, p, "网络扩展", Some("也可以在「系统设置 → 通用 → 登录项与扩展」中查看"), |ui| {
                    if st.busy() {
                        ui.add(egui::Spinner::new().size(14.0));
                    } else if theme::text_button(ui, p.red, "停用…").on_hover_text("关闭内容过滤并卸载网络扩展").clicked() {
                        deactivate = true;
                    }
                });
            });
            if deactivate {
                crate::netext::deactivate();
                self.netext_refreshed = None;
            }
            ui.add_space(4.0);
            return;
        }

        let ext_on = st.ext_enabled == Some(true);
        let (title, mut body, action): (&str, String, Option<(&str, Act)>) = if !st.loaded {
            ("正在检查网络扩展", "正在向系统查询网络扩展的安装状态…".into(), None)
        } else if !st.bundled {
            ("这个版本没有附带网络扩展", "应用包里找不到 Egress Guard 网络扩展，无法按应用断网。请使用完整的发布版本，或者使用「全局断网」。".into(), None)
        } else if !st.signed() {
            (
                "需要签名版本才能按应用断网",
                "按应用断网依赖 Apple 的网络扩展（内容过滤）。macOS 只加载用 Developer ID 签名、并经过 Apple 公证的网络扩展，\
                 当前这个版本没有签名，系统会拒绝启用。受控应用可以照常添加、保存，换成签名版本并启用扩展后立即生效；在那之前请使用「全局断网」。"
                    .into(),
                Some(("仍要尝试启用…", Act::Activate)),
            )
        } else if st.awaiting_approval() {
            (
                "等待你在系统设置中允许",
                "打开「系统设置 → 隐私与安全性」，在页面下方找到 Egress Guard 被阻止的系统扩展，点「允许」并输入密码。\
                 之后系统会询问是否允许过滤网络内容，请选择「允许」。"
                    .into(),
                Some(("打开系统设置", Act::OpenSettings)),
            )
        } else if st.phase == "reboot_required" {
            ("需要重新启动", "网络扩展将在重新启动 Mac 后生效。".into(), None)
        } else if ext_on && !st.filter_enabled {
            (
                "内容过滤未开启",
                "网络扩展已安装，但内容过滤没有开启（可能在系统设置里被关闭了）。开启时系统会询问是否允许过滤网络内容。".into(),
                Some(("开启内容过滤", Act::EnableFilter)),
            )
        } else if ext_on && self.backend.service() != ServiceState::NotApplicable && !s.running {
            ("等待后台服务", "网络扩展已启用。后台服务运行后，它会自动连接并开始按应用断网。".into(), None)
        } else if ext_on {
            ("正在连接后台服务", "网络扩展已启用，正在等待它连接后台服务…如果一直连不上，可以重新启用。".into(), Some(("重新启用", Act::Activate)))
        } else {
            (
                "启用按应用断网",
                "受控应用的连接由 Egress Guard 网络扩展逐个放行或切断。启用时系统会先要求你在「系统设置 → 隐私与安全性」中允许这个系统扩展，\
                 然后询问是否允许过滤网络内容。"
                    .into(),
                Some(("启用网络扩展…", Act::Activate)),
            )
        };
        if let Some(e) = st.last_error() {
            body.push_str(&format!("\n上次操作失败：{e}"));
        }
        let mut clicked = None;
        let mut doc = false;
        warning_card_with(ui, p, title, &body, |ui| {
            if st.busy() {
                ui.label(RichText::new("等待系统…").size(12.5).color(p.secondary));
                ui.add(egui::Spinner::new().size(14.0));
            } else if let Some((label, act)) = action {
                let primary = !matches!(act, Act::Activate) || st.signed();
                let r = if primary { theme::accent_button(ui, p, label, true) } else { theme::gray_button(ui, p, label) };
                if r.clicked() {
                    clicked = Some(act);
                }
            }
            if !st.signed() || st.last_error().is_some() {
                doc = theme::text_button(ui, p.accent, "说明  ›").on_hover_text(NETEXT_DOC).clicked();
            }
        });
        match clicked {
            Some(Act::Activate) => crate::netext::activate(),
            Some(Act::EnableFilter) => crate::netext::set_filter(true),
            Some(Act::OpenSettings) => open_url("x-apple.systempreferences:com.apple.preference.security"),
            None => {}
        }
        if clicked.is_some() {
            self.netext_refreshed = None;
        }
        if doc {
            open_url(NETEXT_DOC);
        }
        ui.add_space(4.0);
    }

    // ---------------- 侧边栏 ----------------

    fn sidebar(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let s = self.status.lock().unwrap().clone();
        ui.add_space(if UNIFIED_TITLEBAR { TITLEBAR_H + 4.0 } else { 6.0 });
        ui.horizontal(|ui| {
            theme::app_icon(ui, 34.0, p.green, Glyph::Shield);
            ui.vertical(|ui| {
                ui.add_space(1.0);
                ui.label(RichText::new("Egress Guard").font(theme::bold(15.0)).color(p.label));
                ui.add_space(-7.0);
                ui.label(RichText::new("出口 IP 网络控制").size(11.5).color(p.secondary));
            });
        });
        ui.add_space(16.0);

        let wl = self.draft.whitelist.len().to_string();
        let apps = self.draft.apps.len().to_string();
        let scope = if self.draft.block_all.enabled { "开" } else { "关" };
        let all = [
            (Page::Overview, theme::NavItem { glyph: Glyph::Shield, icon_bg: p.green, text: "概览", badge: None }),
            (Page::Whitelist, theme::NavItem { glyph: Glyph::Check, icon_bg: p.accent, text: "出口 IP 白名单", badge: Some(&wl) }),
            (Page::Apps, theme::NavItem { glyph: Glyph::Grid, icon_bg: p.orange, text: "受控应用", badge: Some(&apps) }),
            (Page::Network, theme::NavItem { glyph: Glyph::Globe, icon_bg: p.red, text: "全局断网", badge: Some(scope) }),
            (Page::Leak, theme::NavItem { glyph: Glyph::Drop, icon_bg: p.teal, text: "泄露测试", badge: None }),
            (Page::Events, theme::NavItem { glyph: Glyph::Clock, icon_bg: p.purple, text: "连接记录", badge: None }),
            (Page::Settings, theme::NavItem { glyph: Glyph::Gear, icon_bg: p.gray, text: "设置", badge: None }),
            (Page::Log, theme::NavItem { glyph: Glyph::Lines, icon_bg: p.indigo, text: "日志", badge: None }),
        ];
        let (pages, items): (Vec<Page>, Vec<theme::NavItem>) = all.into_iter().unzip();
        let selected = pages.iter().position(|x| *x == self.page).unwrap_or(0);
        if let Some(i) = theme::nav_list(ui, p, &items, selected) {
            self.page = pages[i];
        }

        // 底部：状态摘要 + 隐藏/退出（顶部留白把它们推到底部）
        let bottom_h = if s.simulated { 84.0 } else { 66.0 };
        ui.add_space((ui.available_height() - bottom_h).max(8.0));
        let (title, _, color) = describe(&s, p);
        egui::Frame::new()
            .fill(p.card.gamma_multiply(if p.dark { 0.6 } else { 0.8 }))
            .corner_radius(CornerRadius::same(9))
            .inner_margin(Margin::symmetric(10, 8))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.spacing_mut().item_spacing.y = 2.0;
                ui.horizontal(|ui| {
                    let (r, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
                    ui.painter().circle_filled(r.center(), 4.5, color);
                    ui.label(RichText::new(title).font(theme::bold(13.0)).color(p.label));
                    if s.checking {
                        ui.add(egui::Spinner::new().size(12.0));
                    }
                });
                let ip = s.egress_ip.map(|i| i.to_string()).unwrap_or_else(|| "出口 IP 未知".into());
                ui.label(RichText::new(ip).size(12.0).color(p.secondary));
                if s.simulated {
                    ui.label(RichText::new("模拟模式 · 规则未生效").size(12.0).color(p.orange));
                }
            });
    }

    // ---------------- 页面 ----------------

    fn overview(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let s = self.status.lock().unwrap().clone();
        theme::page_title(ui, p, "概览", text::OVERVIEW_SUB);

        if let Some(e) = self.backend.config_error() {
            // 0.9.3 起后台服务给出完整说明；更早的服务只给错误本身
            let body = if e.starts_with("后台服务") || e.starts_with("为安全起见") {
                e
            } else {
                format!("为安全起见，后台服务正按默认设置运行并开启了全局断网。检查各项设置后点「保存并应用」，会覆盖损坏的文件。{e}")
            };
            warning_card(ui, p, "后台服务的配置文件有误", &body);
            ui.add_space(4.0);
        } else if let Some(e) = &self.load_error {
            warning_card(ui, p, "配置文件有误", e);
            ui.add_space(4.0);
        }
        self.service_card(ui, p);
        self.update_card(ui, p);
        if let (true, Some(e)) = (s.running, &s.backend_error) {
            warning_card(ui, p, "拦截规则未生效", &format!("{}{e}", text::BACKEND_UNAVAILABLE));
            ui.add_space(4.0);
        }
        if let (true, Some(e)) = (s.running, &s.apply_error) {
            warning_card(ui, p, "切换没有生效，正在重试", &format!("{e}。每 5 秒自动重试一次，生效后这条提示会消失。"));
            ui.add_space(4.0);
        }
        if let (true, Some(e)) = (s.running, &s.degraded) {
            let title = if cfg!(windows) { "部分拦截规则没能加上" } else { "网络扩展需要更新" };
            warning_card(ui, p, title, e);
            ui.add_space(4.0);
        }
        // macOS：网络扩展没连上时只有 pf 全局断网有效
        if !s.per_app && s.running && !s.simulated && !self.applied.block_all.enabled {
            let mut go = None;
            let body = if self.applied.apps.is_empty() {
                "还没有添加受控应用，全局断网也没有开启：出口 IP 不在白名单时不会拦截任何连接。"
            } else {
                "网络扩展没有启用，出口 IP 不在白名单时受控应用不会被断网。可以启用网络扩展，或者开启全局断网。"
            };
            warning_card_with(ui, p, "按应用断网未生效", body, |ui| {
                if theme::text_button(ui, p.accent, "全局断网  ›").clicked() {
                    go = Some(Page::Network);
                }
                if theme::text_button(ui, p.accent, "网络扩展  ›").clicked() {
                    go = Some(Page::Apps);
                }
            });
            if let Some(pg) = go {
                self.page = pg;
            }
            ui.add_space(4.0);
        }

        // 主视觉：本机 ── 闸门 ── 互联网
        let (title, desc, color) = describe(&s, p);
        let route = if inert(&s) {
            theme::Route::Open
        } else if !s.running || s.blocked {
            theme::Route::Closed
        } else if s.egress_ip.is_some() {
            theme::Route::Open
        } else {
            theme::Route::Checking
        };
        let scope = if s.block_all || !s.per_app { "全部网络".to_owned() } else { format!("{} 个受控应用", self.applied.apps.len()) };
        let gate = match (s.whitelisted, s.blocked) {
            _ if !s.running => if s.backend_error.is_some() { "未连接" } else { "已停止" },
            _ if inert(&s) => "未通过，未拦截",
            // 出口命中但仍阻断：IPv6 出口未命中，或者 VPN 断开、网络变化后在等重新检测
            (Some(true), true) if s.v6_whitelisted == Some(false) => "IPv6 未命中，阻断",
            (Some(true), true) => "命中，暂时阻断",
            (Some(true), false) => "命中，放行",
            (Some(false), _) => "未命中，阻断",
            (None, true) => "未确认，阻断",
            (None, false) if s.detect_error.is_some() => "检测失败",
            (None, false) => "检测中",
        };
        let ip = s.egress_ip.map(|i| i.to_string()).unwrap_or_else(|| "未知".into());
        theme::card(ui, p, |ui| {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(RichText::new(headline(&s, title)).font(theme::bold(22.0)).color(p.label));
                    ui.add_space(-4.0);
                    ui.label(RichText::new(desc).color(p.secondary));
                });
                ui.with_layout(Layout::right_to_left(Align::Min), |ui| {
                    if s.checking {
                        ui.add_space(8.0);
                        ui.add(egui::Spinner::new().size(18.0));
                    } else if theme::gray_button(ui, p, "立即检测").clicked() {
                        self.backend.check_now();
                    }
                });
            });
            ui.add_space(14.0);
            theme::route_diagram(ui, p, route, color, [("本机", &scope), ("白名单", gate), (&ip, "出口 IP")]);
        });

        theme::section(ui, p, "检测");
        theme::card(ui, p, |ui| {
            theme::row(ui, p, "检测方式", None, |ui| {
                let mut secs = self.applied.detect.interval_secs;
                let fast = self.applied.vpn.check_interval_secs;
                if !s.vpn_guarded.is_empty() && fast > 0 {
                    secs = secs.min(fast);
                }
                ui.label(RichText::new(format!("每 {secs} 秒，网络变化时立即")).color(p.secondary));
            });
            theme::hairline(ui, p);
            theme::row(ui, p, "IPv6 出口", None, |ui| {
                match (self.applied.ipv6.mode, s.egress_v6, s.v6_whitelisted) {
                    (Ipv6Mode::Block, _, _) => theme::chip(ui, p.indigo, "始终阻断"),
                    (Ipv6Mode::Off, _, _) => theme::chip(ui, p.gray, "不单独检测"),
                    (Ipv6Mode::Check, Some(ip), Some(ok)) => {
                        let r = theme::chip(ui, if ok { p.green } else { p.red }, if ok { "白名单内" } else { "不在白名单" });
                        ui.label(RichText::new(ip.to_string()).monospace().color(p.secondary));
                        r
                    }
                    (Ipv6Mode::Check, _, _) if s.egress_ip.is_some_and(|i| i.is_ipv6()) => {
                        theme::chip(ui, p.gray, "与出口 IP 相同")
                    }
                    (Ipv6Mode::Check, _, _) if s.egress_ip.is_some() => theme::chip(ui, p.gray, "没有（不能直连 IPv6）"),
                    (Ipv6Mode::Check, _, _) => theme::chip(ui, p.gray, "未检测"),
                };
            });
            theme::hairline(ui, p);
            theme::row(ui, p, "上次检测", None, |ui| {
                ui.label(RichText::new(s.last_check.clone().unwrap_or_else(|| "尚未完成".into())).color(p.secondary));
            });
            if let Some(err) = &s.detect_error {
                theme::hairline(ui, p);
                theme::row(ui, p, "检测失败", Some(&shorten(err, 90)), |ui| {
                    theme::chip(ui, p.orange, &format!("连续 {} 次", s.failures));
                });
            }
        });

        theme::section(ui, p, "保护");
        let mut goto = None;
        theme::card(ui, p, |ui| {
            theme::row(ui, p, "拦截引擎", None, |ui| {
                if s.backend_error.is_some() {
                    theme::chip(ui, p.orange, "模拟模式");
                } else if s.running {
                    if let Some(v) = &s.filter_ext {
                        theme::chip(ui, p.green, &format!("网络扩展 {v}"));
                    }
                    theme::chip(ui, p.green, text::ENGINE_RUNNING);
                } else {
                    theme::chip(ui, p.gray, "未运行");
                }
            });
            theme::hairline(ui, p);
            let scope = match (self.applied.block_all.enabled, s.per_app || !s.running) {
                (true, _) => "全部网络",
                (false, true) => "仅受控应用",
                (false, false) => "未开启",
            };
            theme::row(ui, p, "断网范围", None, |ui| {
                if theme::text_button(ui, p.accent, &format!("{scope}  ›")).clicked() {
                    goto = Some(Page::Network);
                }
            });
            theme::hairline(ui, p);
            let extra_n = s.extra_apps.len();
            let sub = (extra_n > 0).then(|| format!("另有 {extra_n} 个自动识别的关联程序"));
            theme::row(ui, p, "受控应用", sub.as_deref(), |ui| {
                if theme::text_button(ui, p.accent, &format!("{} 个  ›", self.applied.apps.len())).clicked() {
                    goto = Some(Page::Apps);
                }
            });
            theme::hairline(ui, p);
            theme::row(ui, p, "白名单条目", None, |ui| {
                if theme::text_button(ui, p.accent, &format!("{} 条  ›", self.applied.whitelist.len())).clicked() {
                    goto = Some(Page::Whitelist);
                }
            });
            theme::hairline(ui, p);
            theme::row(ui, p, "VPN 守护", Some("VPN 一断开就立即断网，不等下一次检测"), |ui| {
                let (color, text) = if !self.applied.vpn.guard {
                    (p.gray, "已关闭".to_owned())
                } else if !s.vpn_guarded.is_empty() {
                    (p.green, format!("守护中 · {}", s.vpn_guarded.join("、")))
                } else if !s.vpn_connected.is_empty() {
                    (p.gray, format!("等待放行 · {}", s.vpn_connected.join("、")))
                } else {
                    (p.gray, "没有连接 VPN".to_owned())
                };
                if theme::text_button(ui, color, &format!("{}  ›", shorten(&text, 40))).clicked() {
                    goto = Some(Page::Settings);
                }
            });
            theme::hairline(ui, p);
            if self.leak_overview_row(ui, p) {
                goto = Some(Page::Leak);
            }
            theme::hairline(ui, p);
            let last = self.backend.events().into_iter().rev().find(|e| e.kind != Kind::Leak);
            let sub = last.as_ref().map(|e| format!("{} {} · {}", e.time, e.kind.label(), shorten(&e.reason, 40)));
            theme::row(ui, p, "连接记录", sub.as_deref(), |ui| {
                if theme::text_button(ui, p.accent, "查看  ›").clicked() {
                    goto = Some(Page::Events);
                }
            });
        });
        if let Some(pg) = goto {
            self.page = pg;
        }
        theme::footnote(ui, p, text::CLOSE_HINT);
    }

    fn whitelist(&mut self, ui: &mut egui::Ui, p: &Palette) {
        theme::page_title(
            ui,
            p,
            "出口 IP 白名单",
            "出口 IP 命中任一条目时放行受控应用，否则阻断。支持单个 IPv4/IPv6 地址和 CIDR 网段。",
        );

        theme::card(ui, p, |ui| {
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                let w = ui.available_width() - 80.0;
                let edit = ui.add(
                    egui::TextEdit::singleline(&mut self.new_entry)
                        .hint_text("例如 203.0.113.10 或 198.51.100.0/24")
                        .desired_width(w)
                        .margin(Margin::symmetric(8, 5)),
                );
                let enter = edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if theme::accent_button(ui, p, "添加", true).clicked() || enter {
                    let e = self.new_entry.clone();
                    self.add_whitelist_entry(e);
                }
            });
            if let Some(e) = &self.entry_error {
                ui.label(RichText::new(e).size(12.0).color(p.red));
            }
            let current = self.status.lock().unwrap().egress_ip;
            if let Some(ip) = current {
                let s = ip.to_string();
                if !self.draft.whitelist.contains(&s)
                    && theme::text_button(ui, p.accent, &format!("＋ 添加当前出口 IP（{s}）")).clicked()
                {
                    self.add_whitelist_entry(s);
                }
            }
        });

        theme::section(ui, p, &format!("已添加 {} 条", self.draft.whitelist.len()));
        let current = self.status.lock().unwrap().egress_ip;
        let mut remove = None;
        theme::card(ui, p, |ui| {
            if self.draft.whitelist.is_empty() {
                empty_state(ui, p, "白名单为空", "任何出口 IP 都会阻断受控应用。");
                return;
            }
            let n = self.draft.whitelist.len();
            for (i, entry) in self.draft.whitelist.iter().enumerate() {
                let kind = match parse_net(entry) {
                    Ok(net) if net.prefix_len() == net.max_prefix_len() => "单个地址",
                    Ok(_) => "网段",
                    Err(_) => "无效",
                };
                ui.horizontal(|ui| {
                    ui.set_min_height(32.0);
                    ui.label(RichText::new(entry).monospace().color(p.label));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if theme::minus_button(ui, p).on_hover_text("移除").clicked() {
                            remove = Some(i);
                        }
                        ui.label(RichText::new(kind).size(12.0).color(p.secondary));
                        let hit = match (parse_net(entry), current) {
                            (Ok(net), Some(ip)) => net.contains(&ip),
                            _ => false,
                        };
                        if hit {
                            theme::chip(ui, p.green, "当前出口");
                        }
                    });
                });
                if i + 1 < n {
                    theme::hairline(ui, p);
                }
            }
        });
        if let Some(i) = remove {
            self.draft.whitelist.remove(i);
        }
    }

    fn apps(&mut self, ui: &mut egui::Ui, p: &Palette) {
        theme::page_title(ui, p, "受控应用", text::APPS_SUB);
        if crate::netext::supported() {
            self.netext_card(ui, p);
        }

        ui.horizontal(|ui| {
            if theme::gray_button(ui, p, "浏览选择程序…").clicked() {
                for f in platform::pick_exe_files() {
                    self.add_app(f);
                }
            }
            if theme::gray_button(ui, p, "从正在运行的程序中选择…").clicked() {
                self.picker =
                    Some(ProcPicker { filter: String::new(), list: procs::list_processes(), target: PickFor::Apps });
            }
        });
        ui.add_space(4.0);

        theme::section(ui, p, &format!("{} 个应用", self.draft.apps.len()));
        let mut remove = None;
        theme::card(ui, p, |ui| {
            if self.draft.apps.is_empty() {
                empty_state(ui, p, "尚未添加受控应用", "添加后，出口 IP 不在白名单内时这些程序会被断网。");
                return;
            }
            let n = self.draft.apps.len();
            for (i, app) in self.draft.apps.iter().enumerate() {
                let name = exe_name(&app.to_string_lossy());
                ui.horizontal(|ui| {
                    ui.set_min_height(44.0);
                    letter_icon(ui, p, &name);
                    ui.vertical(|ui| {
                        ui.add_space(3.0);
                        ui.label(RichText::new(&name).font(theme::bold(14.0)).color(p.label));
                        ui.add_space(-6.0);
                        ui.label(RichText::new(shorten(&app.display().to_string(), 70)).size(12.0).color(p.secondary))
                            .on_hover_text(app.display().to_string());
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if theme::minus_button(ui, p).on_hover_text("移除").clicked() {
                            remove = Some(i);
                        }
                        if !app.exists() {
                            theme::chip(ui, p.red, "文件不存在");
                        }
                    });
                });
                if i + 1 < n {
                    theme::hairline_inset(ui, p, theme::ICON_INSET);
                }
            }
        });
        if let Some(i) = remove {
            self.draft.apps.remove(i);
        }
        theme::footnote(ui, p, &format!("同一个{}的所有进程都会被阻断；它启动的其他程序见下方「自动识别」。", text::PROGRAM));

        // ---- 自动识别关联程序 ----
        theme::section(ui, p, "自动识别");
        theme::card(ui, p, |ui| {
            let c = &mut self.draft.children;
            let mut tree = c.mode == ChildMode::Tree;
            theme::row(
                ui,
                p,
                "一并阻断子进程",
                Some(text::CHILDREN_SUB),
                |ui| {
                    if theme::toggle(ui, p, &mut tree).changed() {
                        c.mode = if tree { ChildMode::Tree } else { ChildMode::Off };
                    }
                },
            );
            theme::hairline(ui, p);
            theme::row(
                ui,
                p,
                "阻断所在目录的全部程序",
                Some(if cfg!(target_os = "macos") {
                    "受控应用所在 .app 包里的所有程序，未运行的也提前阻断"
                } else {
                    "受控应用 exe 所在目录（含子目录）下的所有 exe，未运行的也提前阻断"
                }),
                |ui| {
                    theme::toggle(ui, p, &mut c.include_app_dir);
                },
            );
        });
        theme::footnote(ui, p, text::SYSTEM_DIRS_HINT);

        // 刚点了"忽略"、尚未保存的项先隐藏
        let pending: Vec<String> =
            self.draft.children.exclude.iter().map(|p| crate::discovery::normalize_path(p)).collect();
        let extra: Vec<_> = self
            .status
            .lock()
            .unwrap()
            .extra_apps
            .iter()
            .filter(|x| !pending.contains(&crate::discovery::normalize_path(&x.path)))
            .cloned()
            .collect();
        theme::section(ui, p, &format!("已自动识别 {} 个", extra.len()));
        let mut ignore = None;
        theme::card(ui, p, |ui| {
            if extra.is_empty() {
                empty_state(ui, p, "暂无", "受控应用运行并启动其他程序后，会出现在这里。");
                return;
            }
            let n = extra.len();
            for (i, x) in extra.iter().enumerate() {
                let path = x.path.display().to_string();
                let name = exe_name(&path);
                ui.horizontal(|ui| {
                    ui.set_min_height(40.0);
                    letter_icon(ui, p, &name);
                    ui.vertical(|ui| {
                        ui.add_space(2.0);
                        ui.label(RichText::new(&name).color(p.label));
                        ui.add_space(-6.0);
                        ui.label(RichText::new(shorten(&path, 70)).size(12.0).color(p.secondary))
                            .on_hover_text(&path);
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if theme::gray_button(ui, p, "忽略").on_hover_text("不再自动阻断这个程序").clicked() {
                            ignore = Some(x.path.clone());
                        }
                        match x.source {
                            Source::Child => theme::chip(ui, p.indigo, "子进程"),
                            Source::AppDir => theme::chip(ui, p.teal, "同目录"),
                        };
                    });
                });
                if i + 1 < n {
                    theme::hairline_inset(ui, p, theme::ICON_INSET);
                }
            }
        });
        if let Some(path) = ignore {
            self.draft.children.exclude.push(path);
        }
        ui.horizontal(|ui| {
            ui.add_space(8.0);
            if theme::text_button(ui, p.accent, "清空子进程识别记录").clicked() {
                self.backend.clear_learned();
                self.notify(true, "已清空子进程识别记录");
            }
        });

        if !self.draft.children.exclude.is_empty() {
            theme::section(ui, p, &format!("已忽略 {} 个", self.draft.children.exclude.len()));
            let mut restore = None;
            theme::card(ui, p, |ui| {
                let n = self.draft.children.exclude.len();
                for (i, path) in self.draft.children.exclude.iter().enumerate() {
                    let s = path.display().to_string();
                    ui.horizontal(|ui| {
                        ui.set_min_height(32.0);
                        ui.label(RichText::new(shorten(&s, 80)).size(13.0).color(p.secondary)).on_hover_text(&s);
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if theme::text_button(ui, p.accent, "恢复").clicked() {
                                restore = Some(i);
                            }
                        });
                    });
                    if i + 1 < n {
                        theme::hairline(ui, p);
                    }
                }
            });
            if let Some(i) = restore {
                self.draft.children.exclude.remove(i);
            }
        }
    }

    fn picker_window(&mut self, ctx: &egui::Context, p: &Palette) {
        let Some(picker) = &mut self.picker else { return };
        let target = picker.target;
        let mut open = true;
        let mut chosen = None;
        egui::Window::new("从正在运行的程序中选择")
            .open(&mut open)
            .default_size([620.0, 440.0])
            .collapsible(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut picker.filter)
                            .hint_text("搜索名称或路径")
                            .desired_width(ui.available_width() - 70.0)
                            .margin(Margin::symmetric(8, 5)),
                    );
                    if theme::gray_button(ui, p, "刷新").clicked() {
                        picker.list = procs::list_processes();
                    }
                });
                ui.add_space(4.0);
                let f = picker.filter.to_lowercase();
                egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                    for proc_ in picker.list.iter().filter(|x| {
                        f.is_empty() || x.name.to_lowercase().contains(&f) || x.path.to_lowercase().contains(&f)
                    }) {
                        ui.horizontal(|ui| {
                            ui.set_min_height(40.0);
                            letter_icon(ui, p, &proc_.name);
                            ui.vertical(|ui| {
                                ui.add_space(2.0);
                                ui.label(RichText::new(&proc_.name).color(p.label));
                                ui.add_space(-6.0);
                                ui.label(RichText::new(shorten(&proc_.path, 60)).size(12.0).color(p.secondary))
                                    .on_hover_text(format!("{}\nPID {}", proc_.path, proc_.pid));
                            });
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if theme::accent_button(ui, p, "添加", true).clicked() {
                                    chosen = Some(PathBuf::from(&proc_.path));
                                }
                            });
                        });
                        theme::hairline_inset(ui, p, theme::ICON_INSET);
                    }
                });
            });
        if let Some(path) = chosen {
            match target {
                PickFor::Apps => self.add_app(path),
                PickFor::AllowApps => self.add_allow_app(path),
            }
            self.notify(true, "已添加，记得保存");
        }
        if !open {
            self.picker = None;
        }
    }

    fn network(&mut self, ui: &mut egui::Ui, p: &Palette) {
        theme::page_title(
            ui,
            p,
            "全局断网",
            text::NETWORK_SUB,
        );

        theme::card(ui, p, |ui| {
            theme::row(
                ui,
                p,
                "不在白名单时切断全部网络",
                Some(text::BLOCK_ALL_OFF),
                |ui| {
                    theme::toggle(ui, p, &mut self.draft.block_all.enabled);
                },
            );
        });
        let enabled = self.draft.block_all.enabled;
        if enabled && self.draft.whitelist.is_empty() {
            ui.add_space(4.0);
            warning_card(ui, p, "白名单为空", "开启后本机会一直断网，直到添加白名单条目或退出程序。");
        }
        theme::footnote(
            ui,
            p,
            text::NETWORK_FOOTNOTE,
        );

        let b = &mut self.draft.block_all;
        theme::section(ui, p, "始终放行");
        theme::card(ui, p, |ui| {
            let mut fixed = vec![
                ("Egress Guard 本身", text::SELF_SUB),
                ("本机回环", "127.0.0.1、::1 等本机内部通信"),
                ("DHCP", "自动获取 IP 地址，否则网卡可能拿不到地址"),
            ];
            if cfg!(target_os = "macos") {
                fixed.push(("IPv6 邻居发现", "同一网段内的地址解析与路由通告，否则 IPv6 无法工作"));
            }
            for (i, (title, sub)) in fixed.iter().enumerate() {
                if i > 0 {
                    theme::hairline(ui, p);
                }
                theme::row(ui, p, title, Some(sub), |ui| {
                    theme::chip(ui, p.green, "放行");
                });
            }
        });

        theme::section(ui, p, "可选放行");
        theme::card(ui, p, |ui| {
            theme::row(
                ui,
                p,
                "局域网",
                Some("10.x、172.16–31.x、192.168.x、链路本地与组播地址，例如路由器、打印机、共享文件夹"),
                |ui| {
                    theme::toggle(ui, p, &mut b.allow_lan);
                },
            );
            theme::hairline(ui, p);
            theme::row(ui, p, "DNS 查询", Some(text::DNS_SUB), |ui| {
                theme::toggle(ui, p, &mut b.allow_dns);
            });
        });

        theme::section(ui, p, &format!("例外程序 {} 个", self.draft.block_all.allow_apps.len()));
        if !ALLOW_APPS {
            info_card(ui, p, "macOS 版不支持按程序放行", "pf 防火墙不能区分程序。VPN 客户端请改为把 VPN 服务器地址填到下面的「例外地址」。");
            ui.add_space(4.0);
        }
        if ALLOW_APPS {
        ui.horizontal(|ui| {
            if theme::gray_button(ui, p, "浏览选择程序…").clicked() {
                for f in platform::pick_exe_files() {
                    self.add_allow_app(f);
                }
            }
            if theme::gray_button(ui, p, "从正在运行的程序中选择…").clicked() {
                self.picker = Some(ProcPicker {
                    filter: String::new(),
                    list: procs::list_processes(),
                    target: PickFor::AllowApps,
                });
            }
        });
        ui.add_space(4.0);
        }
        let mut remove = None;
        if ALLOW_APPS || !self.draft.block_all.allow_apps.is_empty() {
        theme::card(ui, p, |ui| {
            let list = &self.draft.block_all.allow_apps;
            if list.is_empty() {
                empty_state(ui, p, "暂无例外程序", "例如 VPN 客户端：断网期间仍需要它连上 VPN，出口才能回到白名单。");
                return;
            }
            let n = list.len();
            for (i, app) in list.iter().enumerate() {
                let name = exe_name(&app.to_string_lossy());
                ui.horizontal(|ui| {
                    ui.set_min_height(40.0);
                    letter_icon(ui, p, &name);
                    ui.vertical(|ui| {
                        ui.add_space(2.0);
                        ui.label(RichText::new(&name).color(p.label));
                        ui.add_space(-6.0);
                        ui.label(RichText::new(shorten(&app.display().to_string(), 70)).size(12.0).color(p.secondary))
                            .on_hover_text(app.display().to_string());
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if theme::minus_button(ui, p).on_hover_text("移除").clicked() {
                            remove = Some(i);
                        }
                        if !app.exists() {
                            theme::chip(ui, p.red, "文件不存在");
                        }
                    });
                });
                if i + 1 < n {
                    theme::hairline_inset(ui, p, theme::ICON_INSET);
                }
            }
        });
        }
        if let Some(i) = remove {
            self.draft.block_all.allow_apps.remove(i);
        }

        theme::section(ui, p, &format!("例外地址 {} 条", self.draft.block_all.allow_remote.len()));
        let mut remove = None;
        theme::card(ui, p, |ui| {
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                let w = ui.available_width() - 80.0;
                let edit = ui.add(
                    egui::TextEdit::singleline(&mut self.new_remote)
                        .hint_text("VPN 服务器地址，例如 198.51.100.7 或 198.51.100.0/24")
                        .desired_width(w)
                        .margin(Margin::symmetric(8, 5)),
                );
                let enter = edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if theme::accent_button(ui, p, "添加", true).clicked() || enter {
                    self.add_remote_entry();
                }
            });
            if let Some(e) = &self.remote_error {
                ui.label(RichText::new(e).size(12.0).color(p.red));
            }
            for (i, entry) in self.draft.block_all.allow_remote.iter().enumerate() {
                theme::hairline(ui, p);
                ui.horizontal(|ui| {
                    ui.set_min_height(32.0);
                    ui.label(RichText::new(entry).monospace().color(p.label));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if theme::minus_button(ui, p).on_hover_text("移除").clicked() {
                            remove = Some(i);
                        }
                    });
                });
            }
        });
        if let Some(i) = remove {
            self.draft.block_all.allow_remote.remove(i);
        }
        theme::footnote(ui, p, text::VPN_HINT);
    }

    fn settings(&mut self, ui: &mut egui::Ui, p: &Palette) {
        theme::page_title(ui, p, "设置", "");

        theme::section(ui, p, "外观");
        theme::card(ui, p, |ui| {
            theme::row(ui, p, "界面外观", None, |ui| {
                theme::segmented(
                    ui,
                    p,
                    &mut self.draft.ui.appearance,
                    &[(Appearance::Dark, "深色"), (Appearance::Light, "浅色"), (Appearance::System, "跟随系统")],
                );
            });
        });

        theme::section(ui, p, "出口 IP 检测");
        theme::card(ui, p, |ui| {
            let d = &mut self.draft.detect;
            theme::row(ui, p, "定时检测间隔", Some("网卡、地址或路由变化时还会立即检测"), |ui| {
                ui.add(egui::DragValue::new(&mut d.interval_secs).range(5..=86400).suffix(" 秒"));
            });
            theme::hairline(ui, p);
            theme::row(ui, p, "单个服务超时", None, |ui| {
                ui.add(egui::DragValue::new(&mut d.timeout_secs).range(1..=60).suffix(" 秒"));
            });
            theme::hairline(ui, p);
            theme::row(ui, p, "检测失败时", None, |ui| {
                egui::ComboBox::from_id_salt("fail_mode")
                    .selected_text(fail_mode_text(d.fail_mode))
                    .show_ui(ui, |ui| {
                        for m in [FailMode::Block, FailMode::Allow, FailMode::Keep] {
                            ui.selectable_value(&mut d.fail_mode, m, fail_mode_text(m));
                        }
                    });
            });
            theme::hairline(ui, p);
            theme::row(ui, p, "连续失败几次后执行", None, |ui| {
                ui.add(egui::DragValue::new(&mut d.failure_threshold).range(1..=20).suffix(" 次"));
            });
            theme::hairline(ui, p);
            theme::row(ui, p, "通过代理检测", Some("如 http://127.0.0.1:7890 或 socks5://127.0.0.1:7891"), |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut d.proxy)
                        .hint_text("留空 = 直连（推荐）")
                        .desired_width(220.0)
                        .font(egui::TextStyle::Monospace)
                        .margin(Margin::symmetric(8, 4)),
                );
            });
        });
        if !self.draft.detect.proxy.trim().is_empty() {
            let mut note = String::from(
                "填了代理后，检测到的是代理的出口，不是本机直连的出口。只有受控应用的流量全部经过这个代理时才适合这样设置；\
                 有任何受控应用直连时，它会在代理出口在白名单内时被一起放行。",
            );
            if self.draft.block_all.enabled {
                note.push_str(if ALLOW_APPS {
                    "已开启全局断网：请把代理程序加入全局断网的例外，否则断网后代理也连不出去，检测会一直失败，无法自动恢复。"
                } else {
                    "已开启全局断网：请把代理连接的远端服务器地址加入全局断网的例外地址，否则断网后代理也连不出去，检测会一直失败，无法自动恢复。"
                });
            }
            if self.draft.ipv6.mode == Ipv6Mode::Check {
                note.push_str("「检测 IPv6 出口」也会通过代理检测，代理没有 IPv6 出口时会按检测失败处理。");
            }
            theme::footnote(ui, p, &note);
        }

        theme::section(ui, p, "出口 IP 查询服务");
        theme::card(ui, p, |ui| {
            ui.add(
                egui::TextEdit::multiline(&mut self.services_text)
                    .desired_rows(4)
                    .desired_width(f32::INFINITY)
                    .font(egui::TextStyle::Monospace)
                    .margin(Margin::symmetric(8, 6)),
            );
        });
        self.sync_services();
        theme::footnote(
            ui,
            p,
            "每行一个，按顺序尝试。若使用按应用或域名分流的 VPN/代理，请选择与受控应用走同一出口的服务。",
        );

        theme::section(ui, p, "行为");
        theme::card(ui, p, |ui| {
            let b = &mut self.draft.behavior;
            theme::row(ui, p, "启动时先阻断", Some("确认出口 IP 在白名单后再放行"), |ui| {
                theme::toggle(ui, p, &mut b.start_blocked);
            });
            theme::hairline(ui, p);
            theme::row(ui, p, "网络变化时先阻断", Some("防止切换网络的瞬间泄漏"), |ui| {
                theme::toggle(ui, p, &mut b.block_on_network_change);
            });
            // macOS 的全局断网（pf 不建立状态）总会切断已有连接；这个选项只影响受控应用
            theme::hairline(ui, p);
            theme::row(ui, p, "断开已有连接", Some(text::KILL_EXISTING_SUB), |ui| {
                theme::toggle(ui, p, &mut b.kill_existing_tcp);
            });
            theme::hairline(ui, p);
            theme::row(ui, p, "网络变化防抖", None, |ui| {
                ui.add(egui::DragValue::new(&mut b.debounce_ms).range(0..=30000).suffix(" 毫秒"));
            });
        });

        let s = self.status.lock().unwrap().clone();
        self.vpn_section(ui, p, &s);
        self.ipv6_section(ui, p);
        self.sync_services();
        self.update_section(ui, p);

        theme::section(ui, p, "启动");
        let mut auto = self.autostart;
        let mut changed = false;
        theme::card(ui, p, |ui| {
            theme::row(ui, p, text::AUTOSTART_TITLE, Some(text::AUTOSTART_SUB), |ui| {
                changed = theme::toggle(ui, p, &mut auto).changed();
            });
            self.service_rows(ui, p);
        });
        if changed {
            match self.backend.set_autostart(auto) {
                Ok(()) => self.notify(true, if auto { "已开启开机自启" } else { "已关闭开机自启" }),
                Err(e) => self.notify(false, format!("{e:#}")),
            }
            self.autostart = self.backend.autostart_enabled();
        }
        theme::footnote(ui, p, &format!("配置文件：{}", self.backend.config_location()));
    }

    fn log(&mut self, ui: &mut egui::Ui, p: &Palette) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("日志").font(theme::bold(26.0)).color(p.label));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if theme::gray_button(ui, p, "清空").clicked() {
                    self.backend.clear_logs();
                }
            });
        });
        if let Some(path) = self.backend.log_location() {
            ui.label(RichText::new(format!("完整日志：{path}")).color(p.secondary));
        }
        ui.add_space(8.0);
        theme::card(ui, p, |ui| {
            egui::ScrollArea::vertical().auto_shrink([false, false]).stick_to_bottom(true).show(ui, |ui| {
                for line in self.backend.logs() {
                    let c = if line.contains(" ERROR ") {
                        p.red
                    } else if line.contains(" WARN ") {
                        p.orange
                    } else {
                        p.label
                    };
                    ui.label(RichText::new(line).monospace().size(12.5).color(c));
                }
            });
        });
    }

    /// 底部浮动保存栏：有未保存修改或刚保存时显示。
    fn save_bar(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let dirty = self.dirty();
        let recent = self.message.as_ref().filter(|m| m.2.elapsed() < Duration::from_secs(4) || !m.0).cloned();
        let visible = dirty || recent.is_some();
        let t = theme::ease(ui.ctx(), egui::Id::unique("save-bar"), visible, 0.2);
        if !visible {
            return;
        }
        ui.multiply_opacity(t);
        egui::Frame::new()
            .fill(p.card)
            .corner_radius(CornerRadius::same(12))
            .inner_margin(Margin::symmetric(16, 10))
            .stroke(egui::Stroke::new(0.5, p.separator))
            .shadow(ui.visuals().popup_shadow)
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    match (&recent, dirty) {
                        (Some((false, msg, _)), _) => {
                            ui.label(RichText::new(shorten(msg, 80)).color(p.red)).on_hover_text(msg);
                        }
                        (_, true) => {
                            ui.label(RichText::new("有未保存的修改").color(p.label));
                        }
                        (Some((true, msg, _)), false) => {
                            ui.label(RichText::new(msg).color(p.green));
                        }
                        _ => {}
                    }
                    if dirty {
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if theme::accent_button(ui, p, "保存并应用", true).clicked() {
                                self.save_and_apply();
                            }
                            if theme::gray_button(ui, p, "撤销").clicked() {
                                self.revert();
                            }
                        });
                    }
                });
            });
        if recent.is_some() {
            ui.ctx().request_repaint_after(Duration::from_millis(500));
        }
    }
}

fn fail_mode_text(m: FailMode) -> &'static str {
    match m {
        FailMode::Block => "阻断（推荐）",
        FailMode::Allow => "放行",
        FailMode::Keep => "保持当前状态",
    }
}

fn warning_card(ui: &mut egui::Ui, p: &Palette, title: &str, text: &str) {
    egui::Frame::new()
        .fill(p.orange.gamma_multiply(0.12))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(14, 10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                let (r, _) = ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::hover());
                ui.painter().circle_filled(r.center(), 8.0, p.orange);
                ui.painter().text(r.center(), egui::Align2::CENTER_CENTER, "!", theme::bold(12.0), Color32::WHITE);
                ui.label(RichText::new(title).font(theme::bold(14.0)).color(p.orange));
            });
            ui.label(RichText::new(text).size(12.5).color(p.label));
        });
}

/// 带右侧操作的警告卡片。
fn warning_card_with(ui: &mut egui::Ui, p: &Palette, title: &str, text: &str, action: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(p.orange.gamma_multiply(0.12))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(14, 10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                let (r, _) = ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::hover());
                ui.painter().circle_filled(r.center(), 8.0, p.orange);
                ui.painter().text(r.center(), egui::Align2::CENTER_CENTER, "!", theme::bold(12.0), Color32::WHITE);
                ui.label(RichText::new(title).font(theme::bold(14.0)).color(p.orange));
                ui.with_layout(Layout::right_to_left(Align::Center), action);
            });
            ui.label(RichText::new(text).size(12.5).color(p.label));
        });
}

/// 说明性的提示卡片（蓝色，不表示出错）。
fn info_card(ui: &mut egui::Ui, p: &Palette, title: &str, text: &str) {
    egui::Frame::new()
        .fill(p.accent.gamma_multiply(if p.dark { 0.16 } else { 0.08 }))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(14, 10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                let (r, _) = ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::hover());
                ui.painter().circle_filled(r.center(), 8.0, p.accent);
                ui.painter().text(r.center(), egui::Align2::CENTER_CENTER, "i", theme::bold(12.0), Color32::WHITE);
                ui.label(RichText::new(title).font(theme::bold(14.0)).color(p.accent));
            });
            ui.label(RichText::new(text).size(12.5).color(p.label));
        });
}

/// 带右侧操作的提示卡片（蓝色）。
fn info_card_with(ui: &mut egui::Ui, p: &Palette, title: &str, text: &str, action: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(p.accent.gamma_multiply(if p.dark { 0.16 } else { 0.08 }))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(14, 10))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                let (r, _) = ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::hover());
                ui.painter().circle_filled(r.center(), 8.0, p.accent);
                ui.painter().text(r.center(), egui::Align2::CENTER_CENTER, "↑", theme::bold(12.0), Color32::WHITE);
                ui.label(RichText::new(title).font(theme::bold(14.0)).color(p.accent));
                ui.with_layout(Layout::right_to_left(Align::Center), action);
            });
            ui.label(RichText::new(text).size(12.5).color(p.label));
        });
}

fn empty_state(ui: &mut egui::Ui, p: &Palette, title: &str, text: &str) {
    ui.vertical_centered(|ui| {
        ui.add_space(14.0);
        ui.label(RichText::new(title).font(theme::bold(15.0)).color(p.secondary));
        ui.label(RichText::new(text).size(12.5).color(p.tertiary));
        ui.add_space(14.0);
    });
}

/// 用首字母做的应用图标。
fn letter_icon(ui: &mut egui::Ui, p: &Palette, name: &str) {
    let colors = [p.accent, p.orange, p.green, p.indigo, p.teal, p.red];
    let idx = name.bytes().fold(0usize, |a, b| a.wrapping_mul(31).wrapping_add(b as usize)) % colors.len();
    let (rect, _) = ui.allocate_exact_size(egui::vec2(30.0, 30.0), egui::Sense::hover());
    // 浅色底 + 同色字母：比实心色块安静，列表里不会显得花哨
    ui.painter().rect_filled(rect, CornerRadius::same(8), colors[idx].gamma_multiply(if p.dark { 0.24 } else { 0.14 }));
    let letter: String = name.chars().next().map(|c| c.to_uppercase().collect()).unwrap_or_default();
    ui.painter().text(rect.center(), egui::Align2::CENTER_CENTER, letter, theme::bold(15.0), colors[idx]);
}

impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_service_job();
        self.poll_netext(ctx);
        // macOS：连上后台服务后以服务里的配置为准（没有未保存的修改时）
        if let Some(raw) = self.backend.take_new_config() {
            if !self.dirty() && raw != self.applied {
                self.set_applied(raw);
            }
        }
        // --leak-test：等出口 IP 检测出来（最多 15 秒）再开始，结果才能和出口对照
        if self.run_leak_test {
            let known = self.status.lock().unwrap().egress_ip.is_some();
            if known || ctx.input(|i| i.time) > 15.0 {
                self.run_leak_test = false;
                self.start_leak_test(ctx);
            } else {
                ctx.request_repaint_after(Duration::from_millis(200));
            }
        }
        if !self.started {
            self.started = true;
            if self.hide_on_first_frame {
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            } else {
                // macOS 菜单栏应用启动时不会自动成为前台应用
                #[cfg(target_os = "macos")]
                tray::bring_to_front();
            }
        }
        if self.show_requested.swap(false, Ordering::SeqCst) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        }
        // 点窗口的关闭按钮：隐藏到托盘，程序继续在后台保护
        if ctx.input(|i| i.viewport().close_requested()) {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        if theme::center_glyphs(&ctx) {
            ctx.request_repaint();
        }
        // 外观修改立即预览，保存后写入配置
        if self.shown_appearance != Some(self.draft.ui.appearance) {
            self.shown_appearance = Some(self.draft.ui.appearance);
            ctx.set_theme(match self.draft.ui.appearance {
                Appearance::System => egui::ThemePreference::System,
                Appearance::Light => egui::ThemePreference::Light,
                Appearance::Dark => egui::ThemePreference::Dark,
            });
        }
        let p = Palette::of(ui);

        egui::Panel::left("sidebar")
            .exact_size(220.0)
            .resizable(false)
            .show_separator_line(false)
            .frame(egui::Frame::new().fill(p.sidebar).inner_margin(Margin::symmetric(12, 14)))
            .show(ui, |ui| self.sidebar(ui, &p));

        if self.page.editable() {
            egui::Panel::bottom("save")
                .show_separator_line(false)
                .frame(egui::Frame::new().fill(p.bg).inner_margin(Margin { left: 28, right: 28, top: 0, bottom: 14 }))
                .show(ui, |ui| self.save_bar(ui, &p));
        }

        // 切换页面时内容淡入并轻微上移（约 0.2 秒），首次打开不播放
        let now = ctx.input(|i| i.time);
        if self.page != self.shown_page {
            self.shown_page = self.page;
            self.page_since = now;
        }
        let raw = if theme::reduced_motion() { 1.0 } else { ((now - self.page_since) / 0.2).clamp(0.0, 1.0) as f32 };
        if raw < 1.0 {
            ctx.request_repaint();
        }
        let enter = egui::emath::easing::cubic_out(raw);

        let top = if UNIFIED_TITLEBAR { 22 + TITLEBAR_H as i8 / 2 } else { 22 };
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(p.bg).inner_margin(Margin { left: 28, right: 28, top, bottom: 8 }))
            .show(ui, |ui| {
                ui.multiply_opacity(0.25 + 0.75 * enter);
                ui.add_space((1.0 - enter) * 6.0);
                if self.page == Page::Log {
                    self.log(ui, &p);
                    return;
                }
                let mut area = egui::ScrollArea::vertical().auto_shrink([false, false]);
                // 内容高度要等排版过几帧才知道，所以连续几帧都设一次
                if let Some((y, n)) = self.start_scroll.as_mut() {
                    area = area.vertical_scroll_offset(*y);
                    *n -= 1;
                    if *n == 0 {
                        self.start_scroll = None;
                    }
                    ui.ctx().request_repaint();
                }
                area.show(ui, |ui| {
                    ui.set_max_width(ui.available_width().min(760.0));
                    match self.page {
                        Page::Overview => self.overview(ui, &p),
                        Page::Whitelist => self.whitelist(ui, &p),
                        Page::Apps => self.apps(ui, &p),
                        Page::Network => self.network(ui, &p),
                        Page::Leak => self.leak_page(ui, &p),
                        Page::Events => self.events_page(ui, &p),
                        Page::Settings => self.settings(ui, &p),
                        Page::Log => {}
                    }
                    ui.add_space(12.0);
                });
            });

        self.picker_window(&ctx, &p);
        if self.page == Page::Log {
            ctx.request_repaint_after(Duration::from_secs(1));
        }
        if UNIFIED_TITLEBAR {
            titlebar_drag_area(ui);
        }
    }
}

/// 隐藏标题栏后，顶部一条仍然可以拖动窗口、双击缩放（系统通常自己处理，这里兜底）。
fn titlebar_drag_area(ui: &mut egui::Ui) {
    let rect = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(ui.ctx().content_rect().width(), TITLEBAR_H));
    let r = ui.interact(rect, egui::Id::unique("titlebar-drag"), egui::Sense::click_and_drag());
    if r.drag_started() {
        ui.ctx().send_viewport_cmd(egui::ViewportCommand::StartDrag);
    } else if r.double_clicked() {
        let max = ui.ctx().input(|i| i.viewport().maximized.unwrap_or(false));
        ui.ctx().send_viewport_cmd(egui::ViewportCommand::Maximized(!max));
    }
}

/// 从路径中取出不带扩展名（.exe / .app）的程序名（与运行平台无关）。
/// 用系统默认方式打开链接（macOS 的 open，Windows 的 ShellExecute）。
fn open_url(url: &str) {
    #[cfg(target_os = "macos")]
    if let Err(e) = std::process::Command::new("/usr/bin/open").arg(url).spawn() {
        log::warn!("无法打开 {url}: {e}");
    }
    #[cfg(windows)]
    {
        use windows::core::{w, PCWSTR};
        use windows::Win32::UI::Shell::ShellExecuteW;
        use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
        let u: Vec<u16> = url.encode_utf16().chain(std::iter::once(0)).collect();
        // 只打开 http(s) 链接，不把任意文字交给 ShellExecute
        if url.starts_with("https://") || url.starts_with("http://") {
            unsafe { ShellExecuteW(None, w!("open"), PCWSTR(u.as_ptr()), PCWSTR::null(), PCWSTR::null(), SW_SHOWNORMAL) };
        }
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    log::info!("打开 {url}");
}

fn exe_name(path: &str) -> String {
    let file = path.trim_end_matches(['\\', '/']).rsplit(['\\', '/']).next().unwrap_or(path);
    match file.rsplit_once('.') {
        Some((stem, ext)) if ext.eq_ignore_ascii_case("exe") || ext.eq_ignore_ascii_case("app") => stem.to_owned(),
        _ => file.to_owned(),
    }
}


fn shorten(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_owned()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn exe_names() {
        assert_eq!(super::exe_name(r"C:\Program Files\App\app.EXE"), "app");
        assert_eq!(super::exe_name("/Applications/Google Chrome.app"), "Google Chrome");
        assert_eq!(super::exe_name("/Applications/Foo.app/"), "Foo");
        assert_eq!(super::exe_name("/usr/local/bin/curl"), "curl");
    }
}
