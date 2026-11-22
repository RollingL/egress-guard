//! 图形界面（eframe/egui），苹果风格：侧边栏导航、大标题、分组圆角卡片、开关控件，
//! 浅色/深色跟随系统。另有系统托盘。

mod icons;
mod platform;
mod theme;
#[cfg(windows)]
mod tray;
#[cfg(not(windows))]
#[path = "tray_stub.rs"]
mod tray;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use eframe::egui::{self, Align, Color32, CornerRadius, Layout, Margin, RichText};

use crate::config::{parse_net, Appearance, ChildMode, Config, FailMode, RawConfig};
use crate::discovery::Source;
use crate::engine::{self, EngineHandle, Event, Status};
use crate::{learned_file, logbuf};
use icons::Shade;
use platform::{autostart, procs};
use theme::{Glyph, Palette};

pub const WINDOW_TITLE: &str = "出口 IP 网络控制 - egress-guard";

/// 退出程序：关闭引擎（WFP 会话随之关闭、规则移除）后结束进程。
pub fn quit(engine: &EngineHandle) -> ! {
    log::info!("用户选择退出");
    let _ = engine.shutdown();
    std::process::exit(0);
}

pub struct Options {
    pub config_path: PathBuf,
    pub start_minimized: bool,
}

#[derive(PartialEq, Clone, Copy)]
enum Page {
    Overview,
    Whitelist,
    Apps,
    Network,
    Settings,
    Log,
}

impl Page {
    fn editable(self) -> bool {
        matches!(self, Page::Whitelist | Page::Apps | Page::Network | Page::Settings)
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
    engine: Arc<EngineHandle>,
    status: Arc<Mutex<Status>>,
    show_requested: Arc<AtomicBool>,
    config_path: PathBuf,
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
    /// 当前已应用到界面的外观。
    shown_appearance: Option<Appearance>,
    /// 页面切换动效：上一帧显示的页面及切换时刻。
    shown_page: Page,
    page_since: f64,
}

pub fn run(opts: Options) -> Result<()> {
    let (cfg, load_error) = if opts.config_path.exists() {
        match Config::load(&opts.config_path) {
            Ok(c) => (c, None),
            Err(e) => {
                log::error!("{e:#}");
                (Config::from_raw(RawConfig::default())?, Some(format!("{e:#}")))
            }
        }
    } else {
        log::info!("配置文件不存在，将使用默认设置：{}", opts.config_path.display());
        (Config::from_raw(RawConfig::default())?, None)
    };

    let viewport = egui::ViewportBuilder::default()
        .with_title(WINDOW_TITLE)
        .with_inner_size([900.0, 620.0])
        .with_min_inner_size([720.0, 480.0])
        .with_icon(egui::IconData { rgba: icons::shield_rgba(64, Shade::Green), width: 64, height: 64 });
    let native = eframe::NativeOptions { viewport, ..Default::default() };

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
            let engine = Arc::new(engine::spawn(cfg.clone(), false, false, Some(learned_file(&opts.config_path)), reporter));
            let show_requested = Arc::new(AtomicBool::new(false));
            tray::spawn(
                tray::TrayCtx {
                    egui_ctx: ctx.clone(),
                    show_requested: show_requested.clone(),
                    engine: engine.clone(),
                    window_title: WINDOW_TITLE.into(),
                },
                tray_rx,
            );

            let raw = cfg.to_raw();
            Ok(Box::new(App {
                engine,
                status,
                show_requested,
                config_path: opts.config_path,
                services_text: raw.detect.services.join("\n"),
                applied: raw.clone(),
                draft: raw,
                page: Page::Overview,
                new_entry: String::new(),
                entry_error: None,
                new_remote: String::new(),
                remote_error: None,
                message: None,
                load_error,
                picker: None,
                autostart: autostart::is_enabled(),
                hide_on_first_frame: opts.start_minimized,
                shown_appearance: None,
                shown_page: Page::Overview,
                page_since: f64::NEG_INFINITY,
            }))
        }),
    )
    .map_err(|e| anyhow::anyhow!("界面启动失败: {e}"))
}

fn tray_state(s: &Status) -> tray::TrayState {
    let (shade, what) = if !s.running {
        (Shade::Gray, "已停止".to_string())
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
    if s.simulated {
        tooltip.push_str("\n模拟模式（规则未生效）");
    }
    tray::TrayState { shade, tooltip }
}

/// 阻断范围的名称。
fn scope_name(s: &Status) -> &'static str {
    if s.block_all { "全部网络" } else { "受控应用" }
}

/// 状态的展示信息：标题、说明（说的是接下来会发生什么）、颜色。
fn describe(s: &Status, p: &Palette) -> (&'static str, String, Color32) {
    if !s.running {
        ("已停止", "后台引擎没有运行。".into(), p.gray)
    } else if s.blocked {
        let why = match (s.egress_ip, &s.detect_error) {
            (Some(_), _) => "出口 IP 不在白名单内。出口回到白名单后会自动恢复。",
            (None, Some(_)) => "无法确定出口 IP，为安全起见保持断网。",
            (None, None) => "正在确认出口 IP，确认前保持断网。",
        };
        ("已阻断", why.into(), p.red)
    } else if s.egress_ip.is_some() {
        ("已放行", "出口 IP 在白名单内。网络一有变化就会重新检查。".into(), p.green)
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
            cfg.save(&self.config_path)?;
            Ok(cfg)
        }) {
            Ok(cfg) => {
                self.applied = cfg.to_raw();
                self.draft = self.applied.clone();
                self.engine.send(Event::Reconfigure(cfg));
                self.load_error = None;
                self.notify(true, "已保存并生效");
            }
            Err(e) => self.notify(false, format!("保存失败：{e:#}")),
        }
    }

    fn revert(&mut self) {
        self.draft = self.applied.clone();
        self.services_text = self.draft.detect.services.join("\n");
        self.message = None;
        self.entry_error = None;
        self.remote_error = None;
    }

    fn sync_services(&mut self) {
        self.draft.detect.services =
            self.services_text.lines().map(|l| l.trim().to_owned()).filter(|l| !l.is_empty()).collect();
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

    // ---------------- 侧边栏 ----------------

    fn sidebar(&mut self, ui: &mut egui::Ui, p: &Palette) {
        let s = self.status.lock().unwrap().clone();
        ui.add_space(6.0);
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
        let pages = [Page::Overview, Page::Whitelist, Page::Apps, Page::Network, Page::Settings, Page::Log];
        let items = [
            theme::NavItem { glyph: Glyph::Shield, icon_bg: p.green, text: "概览", badge: None },
            theme::NavItem { glyph: Glyph::Check, icon_bg: p.accent, text: "出口 IP 白名单", badge: Some(&wl) },
            theme::NavItem { glyph: Glyph::Grid, icon_bg: p.orange, text: "受控应用", badge: Some(&apps) },
            theme::NavItem { glyph: Glyph::Globe, icon_bg: p.red, text: "全局断网", badge: Some(scope) },
            theme::NavItem { glyph: Glyph::Gear, icon_bg: p.gray, text: "设置", badge: None },
            theme::NavItem { glyph: Glyph::Lines, icon_bg: p.indigo, text: "日志", badge: None },
        ];
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
        theme::page_title(ui, p, "概览", "根据本机公网出口 IP，自动放行或阻断受控应用的网络连接。");

        if let Some(e) = &self.load_error {
            warning_card(ui, p, "配置文件读取失败", &format!("当前使用默认设置，保存会覆盖原文件。{e}"));
            ui.add_space(4.0);
        }
        if let Some(e) = &s.backend_error {
            warning_card(ui, p, "拦截规则未生效", &format!("WFP 不可用，当前为模拟模式。请以管理员身份运行。{e}"));
            ui.add_space(4.0);
        }

        // 主视觉：本机 ── 闸门 ── 互联网
        let (title, desc, color) = describe(&s, p);
        let route = if !s.running || s.blocked {
            theme::Route::Closed
        } else if s.egress_ip.is_some() {
            theme::Route::Open
        } else {
            theme::Route::Checking
        };
        let scope = if s.block_all { "全部网络".to_owned() } else { format!("{} 个受控应用", self.applied.apps.len()) };
        let gate = match (s.whitelisted, s.blocked) {
            (Some(true), _) => "命中，放行",
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
                    ui.label(RichText::new(format!("{}{title}", scope_name(&s))).font(theme::bold(22.0)).color(p.label));
                    ui.add_space(-4.0);
                    ui.label(RichText::new(desc).color(p.secondary));
                });
                ui.with_layout(Layout::right_to_left(Align::Min), |ui| {
                    if s.checking {
                        ui.add_space(8.0);
                        ui.add(egui::Spinner::new().size(18.0));
                    } else if theme::gray_button(ui, p, "立即检测").clicked() {
                        self.engine.send(Event::CheckNow);
                    }
                });
            });
            ui.add_space(14.0);
            theme::route_diagram(ui, p, route, color, [("本机", &scope), ("白名单", gate), (&ip, "出口 IP")]);
        });

        theme::section(ui, p, "检测");
        theme::card(ui, p, |ui| {
            theme::row(ui, p, "检测方式", None, |ui| {
                let secs = self.applied.detect.interval_secs;
                ui.label(RichText::new(format!("每 {secs} 秒，网络变化时立即")).color(p.secondary));
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
                    theme::chip(ui, p.green, "WFP 运行中");
                } else {
                    theme::chip(ui, p.gray, "未运行");
                }
            });
            theme::hairline(ui, p);
            let scope = if self.applied.block_all.enabled { "全部网络" } else { "仅受控应用" };
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
        });
        if let Some(pg) = goto {
            self.page = pg;
        }
        theme::footnote(ui, p, "点窗口右上角的 × 会隐藏到托盘，程序继续运行。要退出，请右键托盘图标选择「退出程序」，退出后所有阻断随之解除。");
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
        theme::page_title(ui, p, "受控应用", "出口 IP 不在白名单内时，以下程序的全部网络连接会被阻断。");

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
        theme::footnote(ui, p, "同一个 exe 的所有进程都会被阻断；它启动的其他程序见下方「自动识别」。");

        // ---- 自动识别关联程序 ----
        theme::section(ui, p, "自动识别");
        theme::card(ui, p, |ui| {
            let c = &mut self.draft.children;
            let mut tree = c.mode == ChildMode::Tree;
            theme::row(
                ui,
                p,
                "一并阻断子进程",
                Some("受控应用启动的其他程序（即使是不同的 exe）自动加入阻断"),
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
                Some("受控应用 exe 所在目录（含子目录）下的所有 exe，未运行的也提前阻断"),
                |ui| {
                    theme::toggle(ui, p, &mut c.include_app_dir);
                },
            );
        });
        theme::footnote(
            ui,
            p,
            "Windows 系统目录下的程序（cmd、PowerShell、conhost 等）不会被自动加入。识别到的子进程会被记住，下次启动立即生效。",
        );

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
                self.engine.send(Event::ClearLearned);
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
            "出口 IP 不在白名单内时，切断本机的全部网络连接，而不只是受控应用。",
        );

        theme::card(ui, p, |ui| {
            theme::row(
                ui,
                p,
                "不在白名单时切断全部网络",
                Some("关闭时只阻断「受控应用」中的程序"),
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
            "受控应用不受下面的例外影响，阻断时仍然完全断网。退出程序会立即恢复全部网络。",
        );

        let b = &mut self.draft.block_all;
        theme::section(ui, p, "始终放行");
        theme::card(ui, p, |ui| {
            let fixed = [
                ("Egress Guard 本身", "用于在断网期间继续检测出口 IP，以便自动恢复"),
                ("本机回环", "127.0.0.1、::1 等本机内部通信"),
                ("DHCP", "自动获取 IP 地址，否则网卡可能拿不到地址"),
            ];
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
            theme::row(ui, p, "DNS 查询", Some("域名解析（端口 53）。关闭后本工具也可能无法检测出口 IP"), |ui| {
                theme::toggle(ui, p, &mut b.allow_dns);
            });
        });

        theme::section(ui, p, &format!("例外程序 {} 个", self.draft.block_all.allow_apps.len()));
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
        let mut remove = None;
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
        theme::footnote(
            ui,
            p,
            "部分 VPN（如 WireGuard）由系统内核发送流量，按程序放行无效，请在这里填写 VPN 服务器的 IP。",
        );
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
        });

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
            theme::hairline(ui, p);
            theme::row(ui, p, "断开已有连接", Some("切换为阻断时，主动断开受控应用的 TCP 连接"), |ui| {
                theme::toggle(ui, p, &mut b.kill_existing_tcp);
            });
            theme::hairline(ui, p);
            theme::row(ui, p, "网络变化防抖", None, |ui| {
                ui.add(egui::DragValue::new(&mut b.debounce_ms).range(0..=30000).suffix(" 毫秒"));
            });
        });

        theme::section(ui, p, "启动");
        let mut auto = self.autostart;
        let mut changed = false;
        theme::card(ui, p, |ui| {
            theme::row(ui, p, "登录时自动启动", Some("以管理员权限在托盘中运行，不弹出 UAC"), |ui| {
                changed = theme::toggle(ui, p, &mut auto).changed();
            });
        });
        if changed {
            let res = match std::env::current_exe() {
                Ok(exe) if auto => autostart::enable(&exe),
                Ok(_) => autostart::disable(),
                Err(e) => Err(e.into()),
            };
            match res {
                Ok(()) => self.notify(true, if auto { "已开启开机自启" } else { "已关闭开机自启" }),
                Err(e) => self.notify(false, format!("{e:#}")),
            }
            self.autostart = autostart::is_enabled();
        }
        theme::footnote(ui, p, &format!("配置文件：{}", self.config_path.display()));
    }

    fn log(&mut self, ui: &mut egui::Ui, p: &Palette) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("日志").font(theme::bold(26.0)).color(p.label));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if theme::gray_button(ui, p, "清空").clicked() {
                    logbuf::clear();
                }
            });
        });
        if let Some(dir) = crate::exe_dir() {
            ui.label(RichText::new(format!("完整日志：{}", dir.join("egress-guard.log").display())).color(p.secondary));
        }
        ui.add_space(8.0);
        theme::card(ui, p, |ui| {
            egui::ScrollArea::vertical().auto_shrink([false, false]).stick_to_bottom(true).show(ui, |ui| {
                for line in logbuf::recent_lines() {
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
        if self.hide_on_first_frame {
            self.hide_on_first_frame = false;
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
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

        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(p.bg).inner_margin(Margin { left: 28, right: 28, top: 22, bottom: 8 }))
            .show(ui, |ui| {
                ui.multiply_opacity(0.25 + 0.75 * enter);
                ui.add_space((1.0 - enter) * 6.0);
                if self.page == Page::Log {
                    self.log(ui, &p);
                    return;
                }
                egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                    ui.set_max_width(ui.available_width().min(760.0));
                    match self.page {
                        Page::Overview => self.overview(ui, &p),
                        Page::Whitelist => self.whitelist(ui, &p),
                        Page::Apps => self.apps(ui, &p),
                        Page::Network => self.network(ui, &p),
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
    }
}

/// 从 Windows 路径中取出不带扩展名的程序名（与运行平台无关）。
fn exe_name(path: &str) -> String {
    let file = path.rsplit(['\\', '/']).next().unwrap_or(path);
    match file.rsplit_once('.') {
        Some((stem, ext)) if ext.eq_ignore_ascii_case("exe") => stem.to_owned(),
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
