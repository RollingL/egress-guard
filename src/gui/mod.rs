//! 图形界面（eframe/egui）：状态、白名单、受控应用、设置、日志，以及系统托盘。

mod icons;
mod platform;
#[cfg(windows)]
mod tray;
#[cfg(not(windows))]
#[path = "tray_stub.rs"]
mod tray;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use eframe::egui::{self, Color32, RichText};

use crate::config::{parse_net, Config, FailMode, RawConfig};
use crate::engine::{self, EngineHandle, Event, Status};
use crate::logbuf;
use platform::{autostart, procs};
use icons::Shade;

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
enum Tab {
    Whitelist,
    Apps,
    Settings,
    Log,
}

struct ProcPicker {
    filter: String,
    list: Vec<procs::ProcInfo>,
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
    tab: Tab,
    new_entry: String,
    entry_error: Option<String>,
    message: Option<(bool, String)>,
    load_error: Option<String>,
    picker: Option<ProcPicker>,
    autostart: bool,
    hide_on_first_frame: bool,
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
        .with_inner_size([820.0, 600.0])
        .with_min_inner_size([640.0, 460.0])
        .with_icon(egui::IconData { rgba: icons::shield_rgba(64, Shade::Green), width: 64, height: 64 });
    let native = eframe::NativeOptions { viewport, ..Default::default() };

    eframe::run_native(
        "egress-guard",
        native,
        Box::new(move |cc| {
            setup_fonts(&cc.egui_ctx);
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
            let engine = Arc::new(engine::spawn(cfg.clone(), false, false, reporter));
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
                tab: Tab::Whitelist,
                new_entry: String::new(),
                entry_error: None,
                message: None,
                load_error,
                picker: None,
                autostart: autostart::is_enabled(),
                hide_on_first_frame: opts.start_minimized,
            }))
        }),
    )
    .map_err(|e| anyhow::anyhow!("界面启动失败: {e}"))
}

/// egui 自带字体不含中文：加载 Windows 自带的中文字体。
fn setup_fonts(ctx: &egui::Context) {
    let windir = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into());
    let candidates = ["msyh.ttc", "msyh.ttf", "simhei.ttf", "simsun.ttc", "Deng.ttf"];
    let mut fonts = egui::FontDefinitions::default();
    for name in candidates {
        let path = Path::new(&windir).join("Fonts").join(name);
        if let Ok(bytes) = std::fs::read(&path) {
            fonts
                .font_data
                .insert("cjk".into(), Arc::new(egui::FontData::from_owned(bytes)));
            fonts.families.entry(egui::FontFamily::Proportional).or_default().insert(0, "cjk".into());
            fonts.families.entry(egui::FontFamily::Monospace).or_default().push("cjk".into());
            log::debug!("使用字体 {}", path.display());
            break;
        }
    }
    ctx.set_fonts(fonts);
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

fn color(shade: Shade) -> Color32 {
    let [r, g, b] = shade.rgb();
    Color32::from_rgb(r, g, b)
}

impl App {
    fn dirty(&self) -> bool {
        self.draft != self.applied
    }

    fn save_and_apply(&mut self) {
        self.draft.detect.services =
            self.services_text.lines().map(|l| l.trim().to_owned()).filter(|l| !l.is_empty()).collect();
        match Config::from_raw(self.draft.clone()).and_then(|cfg| {
            cfg.save(&self.config_path)?;
            Ok(cfg)
        }) {
            Ok(cfg) => {
                self.applied = cfg.to_raw();
                self.draft = self.applied.clone();
                self.engine.send(Event::Reconfigure(cfg));
                self.load_error = None;
                self.message = Some((true, format!("已保存到 {} 并生效", self.config_path.display())));
            }
            Err(e) => self.message = Some((false, format!("保存失败：{e:#}"))),
        }
    }

    fn revert(&mut self) {
        self.draft = self.applied.clone();
        self.services_text = self.draft.detect.services.join("\n");
        self.message = None;
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

    // ---------------- 各区域 ----------------

    fn status_panel(&mut self, ui: &mut egui::Ui) {
        let s = self.status.lock().unwrap().clone();
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            let (text, shade) = if !s.running {
                ("● 已停止", Shade::Gray)
            } else if s.blocked {
                ("● 已阻断受控应用", Shade::Red)
            } else if s.egress_ip.is_some() {
                ("● 已放行受控应用", Shade::Green)
            } else {
                ("● 正在检测…", Shade::Gray)
            };
            ui.label(RichText::new(text).size(22.0).strong().color(color(shade)));
            if s.simulated {
                ui.label(RichText::new("模拟模式").color(color(Shade::Amber)).strong());
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("退出程序").on_hover_text("关闭程序，所有阻断规则随之移除").clicked() {
                    quit(&self.engine);
                }
                if ui.button("隐藏到托盘").clicked() {
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Visible(false));
                }
                let check = ui.add_enabled(!s.checking, egui::Button::new("立即检测"));
                if check.clicked() {
                    self.engine.send(Event::CheckNow);
                }
            });
        });

        egui::Grid::new("status_grid").num_columns(2).spacing([16.0, 4.0]).show(ui, |ui| {
            ui.label("出口 IP");
            ui.horizontal(|ui| {
                match s.egress_ip {
                    Some(ip) => {
                        ui.label(RichText::new(ip.to_string()).monospace().strong());
                        if s.whitelisted == Some(true) {
                            ui.label(RichText::new("命中白名单").color(color(Shade::Green)));
                        } else {
                            ui.label(RichText::new("不在白名单内").color(color(Shade::Red)));
                        }
                    }
                    None => {
                        ui.label("未知");
                    }
                }
                if s.checking {
                    ui.spinner();
                }
            });
            ui.end_row();

            ui.label("上次检测");
            ui.label(s.last_check.clone().unwrap_or_else(|| "尚未完成".into()));
            ui.end_row();

            if let Some(err) = &s.detect_error {
                ui.label("检测错误");
                ui.label(
                    RichText::new(format!("（连续 {} 次）{}", s.failures, shorten(err, 160)))
                        .color(color(Shade::Amber)),
                )
                .on_hover_text(err);
                ui.end_row();
            }

            ui.label("拦截引擎");
            match &s.backend_error {
                Some(e) => {
                    ui.label(
                        RichText::new(format!("不可用，规则未生效：{e}")).color(color(Shade::Red)),
                    );
                }
                None if s.running => {
                    ui.label("WFP 动态会话（程序退出时规则自动移除）");
                }
                None => {
                    ui.label("未运行");
                }
            }
            ui.end_row();
        });

        if let Some(e) = &self.load_error {
            ui.colored_label(
                color(Shade::Red),
                format!("配置文件读取失败，当前使用默认设置（保存会覆盖原文件）：{e}"),
            );
        }
        ui.add_space(6.0);
    }

    fn whitelist_tab(&mut self, ui: &mut egui::Ui) {
        ui.label("出口 IP 命中以下任一条目时放行受控应用，否则阻断。支持单个 IP（IPv4/IPv6）和 CIDR 网段。");
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let edit = ui.add(
                egui::TextEdit::singleline(&mut self.new_entry)
                    .hint_text("例如 203.0.113.10 或 198.51.100.0/24")
                    .desired_width(280.0),
            );
            let enter = edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if ui.button("添加").clicked() || enter {
                let e = self.new_entry.clone();
                self.add_whitelist_entry(e);
            }
            let current = self.status.lock().unwrap().egress_ip;
            if let Some(ip) = current {
                if ui.button(format!("添加当前出口 IP（{ip}）")).clicked() {
                    self.add_whitelist_entry(ip.to_string());
                }
            }
        });
        if let Some(e) = &self.entry_error {
            ui.colored_label(color(Shade::Red), e);
        }
        ui.separator();

        if self.draft.whitelist.is_empty() {
            ui.label(RichText::new("白名单为空：任何出口 IP 都会阻断受控应用。").color(color(Shade::Amber)));
        }
        let mut remove = None;
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            for (i, entry) in self.draft.whitelist.iter().enumerate() {
                ui.horizontal(|ui| {
                    if ui.small_button("删除").clicked() {
                        remove = Some(i);
                    }
                    ui.label(RichText::new(entry).monospace());
                });
            }
        });
        if let Some(i) = remove {
            self.draft.whitelist.remove(i);
        }
    }

    fn apps_tab(&mut self, ui: &mut egui::Ui) {
        ui.label("出口 IP 不在白名单内时，以下程序的全部网络连接会被阻断。");
        ui.label(
            RichText::new("提示：浏览器等多进程程序通常只需添加主程序；若有独立的更新器或辅助程序（不同 exe），也需要一并添加。")
                .weak(),
        );
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if ui.button("浏览选择 exe…").clicked() {
                for f in platform::pick_exe_files() {
                    self.add_app(f);
                }
            }
            if ui.button("从正在运行的程序中选择…").clicked() {
                self.picker = Some(ProcPicker { filter: String::new(), list: procs::list_processes() });
            }
        });
        ui.separator();

        if self.draft.apps.is_empty() {
            ui.label(RichText::new("尚未添加受控应用。").color(color(Shade::Amber)));
        }
        let mut remove = None;
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            for (i, app) in self.draft.apps.iter().enumerate() {
                ui.horizontal(|ui| {
                    if ui.small_button("删除").clicked() {
                        remove = Some(i);
                    }
                    if app.exists() {
                        ui.label(RichText::new("存在").color(color(Shade::Green)));
                    } else {
                        ui.label(RichText::new("文件不存在").color(color(Shade::Red)));
                    }
                    ui.label(RichText::new(app.display().to_string()).monospace());
                });
            }
        });
        if let Some(i) = remove {
            self.draft.apps.remove(i);
        }
    }

    fn picker_window(&mut self, ctx: &egui::Context) {
        let Some(picker) = &mut self.picker else { return };
        let mut open = true;
        let mut chosen = None;
        egui::Window::new("从正在运行的程序中选择")
            .open(&mut open)
            .default_size([620.0, 420.0])
            .collapsible(false)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("筛选");
                    ui.add(egui::TextEdit::singleline(&mut picker.filter).desired_width(240.0));
                    if ui.button("刷新").clicked() {
                        picker.list = procs::list_processes();
                    }
                });
                ui.separator();
                let f = picker.filter.to_lowercase();
                egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                    for p in picker.list.iter().filter(|p| {
                        f.is_empty() || p.name.to_lowercase().contains(&f) || p.path.to_lowercase().contains(&f)
                    }) {
                        ui.horizontal(|ui| {
                            if ui.small_button("添加").clicked() {
                                chosen = Some(PathBuf::from(&p.path));
                            }
                            ui.label(RichText::new(&p.name).strong());
                            ui.label(RichText::new(&p.path).weak()).on_hover_text(format!("PID {}", p.pid));
                        });
                    }
                });
            });
        if let Some(p) = chosen {
            self.add_app(p);
        }
        if !open {
            self.picker = None;
        }
    }

    fn settings_tab(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.heading("出口 IP 检测");
            egui::Grid::new("detect_grid").num_columns(2).spacing([16.0, 6.0]).show(ui, |ui| {
                let d = &mut self.draft.detect;
                ui.label("定时检测间隔");
                ui.add(egui::DragValue::new(&mut d.interval_secs).range(5..=86400).suffix(" 秒"));
                ui.end_row();
                ui.label("单个服务超时");
                ui.add(egui::DragValue::new(&mut d.timeout_secs).range(1..=60).suffix(" 秒"));
                ui.end_row();
                ui.label("检测失败时");
                egui::ComboBox::from_id_salt("fail_mode")
                    .selected_text(match d.fail_mode {
                        FailMode::Block => "阻断（推荐）",
                        FailMode::Allow => "放行",
                        FailMode::Keep => "保持当前状态",
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut d.fail_mode, FailMode::Block, "阻断（推荐）");
                        ui.selectable_value(&mut d.fail_mode, FailMode::Allow, "放行");
                        ui.selectable_value(&mut d.fail_mode, FailMode::Keep, "保持当前状态");
                    });
                ui.end_row();
                ui.label("连续失败几次后执行");
                ui.add(egui::DragValue::new(&mut d.failure_threshold).range(1..=20).suffix(" 次"));
                ui.end_row();
            });
            ui.add_space(4.0);
            ui.label("出口 IP 查询服务（每行一个，按顺序尝试）：");
            ui.label(
                RichText::new("如果使用按应用/域名分流的 VPN 或代理，请选择与受控应用走同一出口的服务。").weak(),
            );
            ui.add(egui::TextEdit::multiline(&mut self.services_text).desired_rows(4).desired_width(f32::INFINITY));
            // 同步到草稿，以便“未保存”状态能正确显示
            self.draft.detect.services = self
                .services_text
                .lines()
                .map(|l| l.trim().to_owned())
                .filter(|l| !l.is_empty())
                .collect();

            ui.add_space(8.0);
            ui.heading("行为");
            let b = &mut self.draft.behavior;
            ui.checkbox(&mut b.start_blocked, "启动时先阻断，确认出口 IP 在白名单后再放行");
            ui.checkbox(&mut b.block_on_network_change, "网络变化时立即先阻断，重新检测确认后再放行");
            ui.checkbox(&mut b.kill_existing_tcp, "切换为阻断时，主动断开受控应用已有的 TCP 连接");
            ui.horizontal(|ui| {
                ui.label("网络变化防抖");
                ui.add(egui::DragValue::new(&mut b.debounce_ms).range(0..=30000).suffix(" 毫秒"));
            });

            ui.add_space(8.0);
            ui.heading("启动");
            let mut auto = self.autostart;
            if ui
                .checkbox(&mut auto, "登录 Windows 时自动启动（以管理员权限运行在托盘，不弹出 UAC）")
                .changed()
            {
                let res = match std::env::current_exe() {
                    Ok(exe) if auto => autostart::enable(&exe),
                    Ok(_) => autostart::disable(),
                    Err(e) => Err(e.into()),
                };
                match res {
                    Ok(()) => {
                        self.message =
                            Some((true, if auto { "已开启开机自启".into() } else { "已关闭开机自启".into() }));
                    }
                    Err(e) => self.message = Some((false, format!("{e:#}"))),
                }
                self.autostart = autostart::is_enabled();
            }
        });
    }

    fn log_tab(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("清空").clicked() {
                logbuf::clear();
            }
            if let Some(dir) = crate::exe_dir() {
                ui.label(RichText::new(format!("完整日志：{}", dir.join("egress-guard.log").display())).weak());
            }
        });
        ui.separator();
        egui::ScrollArea::vertical().auto_shrink([false, false]).stick_to_bottom(true).show(ui, |ui| {
            for line in logbuf::recent_lines() {
                let c = if line.contains(" ERROR ") {
                    Some(color(Shade::Red))
                } else if line.contains(" WARN ") {
                    Some(color(Shade::Amber))
                } else {
                    None
                };
                let t = RichText::new(line).monospace();
                ui.label(match c {
                    Some(c) => t.color(c),
                    None => t,
                });
            }
        });
    }

    fn save_bar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let dirty = self.dirty();
            if ui.add_enabled(dirty, egui::Button::new(RichText::new("保存并应用").strong())).clicked() {
                self.save_and_apply();
            }
            if ui.add_enabled(dirty, egui::Button::new("撤销修改")).clicked() {
                self.revert();
            }
            if dirty {
                ui.colored_label(color(Shade::Amber), "有未保存的修改");
            } else if let Some((ok, msg)) = &self.message {
                ui.colored_label(if *ok { color(Shade::Green) } else { color(Shade::Red) }, msg);
            } else {
                ui.label(RichText::new(format!("配置文件：{}", self.config_path.display())).weak());
            }
        });
        if self.dirty() {
            if let Some((false, msg)) = &self.message {
                ui.colored_label(color(Shade::Red), msg);
            }
        }
        ui.add_space(4.0);
    }
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
        egui::Panel::top("status").show(ui, |ui| self.status_panel(ui));
        if self.tab != Tab::Log {
            egui::Panel::bottom("save").show(ui, |ui| self.save_bar(ui));
        }
        egui::CentralPanel::default().show(ui, |ui| {
            ui.horizontal(|ui| {
                let wl = format!("出口 IP 白名单（{}）", self.draft.whitelist.len());
                let apps = format!("受控应用（{}）", self.draft.apps.len());
                ui.selectable_value(&mut self.tab, Tab::Whitelist, wl);
                ui.selectable_value(&mut self.tab, Tab::Apps, apps);
                ui.selectable_value(&mut self.tab, Tab::Settings, "设置");
                ui.selectable_value(&mut self.tab, Tab::Log, "日志");
            });
            ui.separator();
            match self.tab {
                Tab::Whitelist => self.whitelist_tab(ui),
                Tab::Apps => self.apps_tab(ui),
                Tab::Settings => self.settings_tab(ui),
                Tab::Log => self.log_tab(ui),
            }
        });
        self.picker_window(&ctx);
        // 日志页需要持续刷新
        if self.tab == Tab::Log {
            ctx.request_repaint_after(std::time::Duration::from_secs(1));
        }
    }
}

fn shorten(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_owned()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}
