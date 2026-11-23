//! 「泄露测试」页：DNS 泄露测试与 WebRTC 泄露测试。
//!
//! 测试在界面进程的后台线程里运行（macOS 上界面以普通用户身份运行，测到的就是普通应用的情况）。
//! 结果按正在编辑的白名单、可信解析器实时重新判定，点「信任」后立即变色。

use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use eframe::egui::{self, Align, Color32, CornerRadius, Layout, Margin, RichText};

use super::theme::{self, Palette};
use super::{empty_state, info_card, warning_card, App};
use crate::leaktest::dns::{self, DnsReport, HttpSource};
use crate::config::LeakTestConfig;
use crate::leaktest::webrtc::{self, WebRtcReport};
use crate::leaktest::{self, Judge, Level, Trusted, Verdict};

/// 后台测试的进度与结果。
pub(super) enum Task<T> {
    Idle,
    Running { since: Instant, progress: u32 },
    Done { at: String, result: T },
}

type Shared<T> = Arc<Mutex<Task<T>>>;

/// 一次测试（手动或自动）之外的信息。
#[derive(Default)]
pub(super) struct JobMeta {
    /// 开始测试时的出口 IP。
    pub egress: Option<IpAddr>,
    /// 这次测试是自动运行的。
    pub auto: bool,
    /// 上次（有效的）测试完成的时刻。作废的自动测试不算。
    pub finished: Option<Instant>,
    /// 测试编号：每开始一次加一。工作线程只在编号没变时更新界面上的结果。
    pub id: u64,
}

/// 测试完成后的结论（按开始测试时的白名单判定）。
pub(super) struct Outcome {
    /// DNS 测试的级别与一句话结论；测试失败时为 Err。
    pub dns: Result<(Level, String), String>,
    pub webrtc: (Level, String),
    pub egress: Option<IpAddr>,
}

impl Outcome {
    /// 发现泄露时的说明（DNS、WebRTC 合在一起）。
    pub fn leak_text(&self) -> Option<String> {
        let mut parts = Vec::new();
        if let Ok((Level::Leak, t)) = &self.dns {
            parts.push(format!("DNS：{t}"));
        }
        if self.webrtc.0 == Level::Leak {
            parts.push(format!("WebRTC：{}", self.webrtc.1));
        }
        (!parts.is_empty()).then(|| parts.join("；"))
    }

    /// 需要留意的地方（没有直接泄露、但结论不完整或有未知解析器等）。
    pub fn warn_text(&self) -> Option<String> {
        let mut parts = Vec::new();
        match &self.dns {
            Ok((Level::Warn, t)) => parts.push(format!("DNS：{t}")),
            Err(e) => parts.push(format!("DNS 测试失败：{e}")),
            _ => {}
        }
        if self.webrtc.0 == Level::Warn {
            parts.push(format!("WebRTC：{}", self.webrtc.1));
        }
        (!parts.is_empty()).then(|| parts.join("；"))
    }
}

type Done = Box<dyn FnOnce(Outcome) + Send>;

/// 一次测试自己的结果（不与界面共享）。
#[derive(Default)]
struct Private {
    dns: Option<Result<DnsReport, String>>,
    webrtc: Option<WebRtcReport>,
}

/// 自动测试是否仍然有效。
pub(super) type Validity = Arc<dyn Fn() -> bool + Send + Sync>;

/// 测试的进度与结果。界面（手动）和自动测试线程共用同一份，结果都显示在「泄露测试」页。
#[derive(Clone)]
pub(super) struct LeakJob {
    dns: Shared<Result<DnsReport, String>>,
    webrtc: Shared<WebRtcReport>,
    pub meta: Arc<Mutex<JobMeta>>,
}

impl LeakJob {
    fn new() -> Self {
        Self {
            dns: Arc::new(Mutex::new(Task::Idle)),
            webrtc: Arc::new(Mutex::new(Task::Idle)),
            meta: Arc::new(Mutex::new(JobMeta::default())),
        }
    }

    pub(super) fn running(&self) -> bool {
        matches!(*self.dns.lock().unwrap(), Task::Running { .. }) || matches!(*self.webrtc.lock().unwrap(), Task::Running { .. })
    }

    /// 开始测试（DNS、WebRTC 同时进行），两项都完成后调用 `done`。已经在测试时返回 false。
    ///
    /// `auto`：自动测试时传入，返回 false（网络或配置已经变了、阻断了、进入模拟模式）时不再发出新的探测。
    pub(super) fn start(
        &self,
        lt: LeakTestConfig,
        judge: Judge,
        egress: Option<IpAddr>,
        auto: Option<Validity>,
        ctx: egui::Context,
        done: impl FnOnce(Outcome) + Send + 'static,
    ) -> bool {
        let valid: Validity = auto.clone().unwrap_or_else(|| Arc::new(|| true));
        let auto = auto.is_some();
        {
            // 先占住两项，避免界面和自动测试同时开始
            let mut d = self.dns.lock().unwrap();
            let mut w = self.webrtc.lock().unwrap();
            if matches!(*d, Task::Running { .. }) || matches!(*w, Task::Running { .. }) {
                return false;
            }
            *d = Task::Running { since: Instant::now(), progress: 0 };
            *w = Task::Running { since: Instant::now(), progress: 0 };
        }
        let id = {
            let mut m = self.meta.lock().unwrap();
            m.egress = egress;
            m.auto = auto;
            m.id += 1;
            m.id
        };
        log::info!(
            "开始{}泄露测试（出口 IP {}）",
            if auto { "自动" } else { "" },
            egress.map(|i| i.to_string()).unwrap_or_else(|| "未知".into())
        );

        // 本次测试私有的结果：汇总只看它，不读共享的显示状态（那里可能已经是下一次测试）
        let results: Arc<Mutex<Private>> = Arc::default();
        // 后完成的那个线程汇总结论
        let remaining = Arc::new(AtomicUsize::new(2));
        let done: Arc<Mutex<Option<Done>>> = Arc::new(Mutex::new(Some(Box::new(done))));
        let finish = {
            let job = self.clone();
            let ctx = ctx.clone();
            let valid = valid.clone();
            let results = results.clone();
            move |remaining: &AtomicUsize, done: &Mutex<Option<Done>>| {
                if remaining.fetch_sub(1, Ordering::SeqCst) != 1 {
                    return;
                }
                // 作废的自动测试不算「最近一次测试」，不推迟下一次定时测试
                if valid() {
                    let mut m = job.meta.lock().unwrap();
                    if m.id == id {
                        m.finished = Some(Instant::now());
                    }
                }
                let r = results.lock().unwrap();
                let dns = match &r.dns {
                    Some(Ok(r)) => Ok(leaktest::dns_summary(r)),
                    Some(Err(e)) => Err(e.clone()),
                    None => Err("未完成".into()),
                };
                let webrtc = r.webrtc.as_ref().map(leaktest::webrtc_summary).unwrap_or((Level::Ok, String::new()));
                drop(r);
                if let Some(f) = done.lock().unwrap().take() {
                    f(Outcome { dns, webrtc, egress });
                }
                ctx.request_repaint();
            }
        };

        {
            let (task, ctx, judge, lt) = (self.dns.clone(), ctx.clone(), judge.clone(), lt.clone());
            let (remaining, done, finish, valid) = (remaining.clone(), done.clone(), finish.clone(), valid.clone());
            let (results, meta) = (results.clone(), self.meta.clone());
            std::thread::Builder::new()
                .name("dns-leak-test".into())
                .spawn(move || {
                    let progress = |n: u32| {
                        if let Task::Running { progress, .. } = &mut *task.lock().unwrap() {
                            *progress = n;
                        }
                        ctx.request_repaint();
                    };
                    let zone = lt.dnscheck_zone.trim().trim_matches('.').to_ascii_lowercase();
                    let r = if !valid() {
                        Err(anyhow::anyhow!("测试已取消（网络或设置变了）"))
                    } else if leaktest::valid_zone(&zone) {
                        dns::run(&zone, &lt.dns_sources, egress, &judge, &progress, &|| !valid())
                    } else {
                        Err(anyhow::anyhow!("DNS 测试服务的域名有误：{:?}", lt.dnscheck_zone))
                    };
                    match &r {
                        Ok(r) => log::info!("DNS 泄露测试：{}", leaktest::dns_summary(r).1),
                        Err(e) => log::warn!("DNS 泄露测试失败：{e:#}"),
                    }
                    let r = r.map_err(|e| format!("{e:#}"));
                    results.lock().unwrap().dns = Some(r.clone());
                    if meta.lock().unwrap().id == id {
                        *task.lock().unwrap() = Task::Done { at: crate::logbuf::now_hms(), result: r };
                    }
                    ctx.request_repaint();
                    finish(&remaining, &done);
                })
                .expect("无法创建测试线程");
        }
        {
            let (task, ctx) = (self.webrtc.clone(), ctx.clone());
            let meta = self.meta.clone();
            std::thread::Builder::new()
                .name("webrtc-leak-test".into())
                .spawn(move || {
                    let r = webrtc::run(&lt.stun_servers, egress, &judge, &|| !valid());
                    log::info!("WebRTC 泄露测试：{}", leaktest::webrtc_summary(&r).1);
                    results.lock().unwrap().webrtc = Some(r.clone());
                    if meta.lock().unwrap().id == id {
                        *task.lock().unwrap() = Task::Done { at: crate::logbuf::now_hms(), result: r };
                    }
                    ctx.request_repaint();
                    finish(&remaining, &done);
                })
                .expect("无法创建测试线程");
        }
        true
    }
}

pub(super) struct LeakUi {
    pub(super) job: LeakJob,
    new_trusted: String,
    trusted_error: Option<String>,
    stun_text: String,
}

impl LeakUi {
    pub(super) fn new(stun: &[String]) -> Self {
        Self { job: LeakJob::new(), new_trusted: String::new(), trusted_error: None, stun_text: stun.join("\n") }
    }

    /// 撤销修改时恢复 STUN 服务器的文本框。
    pub(super) fn reset_text(&mut self, stun: &[String]) {
        self.stun_text = stun.join("\n");
        self.trusted_error = None;
    }
}

fn level_color(p: &Palette, l: Level) -> Color32 {
    match l {
        Level::Ok => p.green,
        Level::Warn => p.orange,
        Level::Leak => p.red,
    }
}

fn verdict_color(p: &Palette, v: Verdict) -> Color32 {
    match v {
        Verdict::Whitelisted | Verdict::Trusted | Verdict::SameNetwork => p.green,
        Verdict::Local | Verdict::NoResponse => p.gray,
        Verdict::Exposed => p.orange,
        Verdict::Leak => p.red,
    }
}

fn verdict_hint(v: Verdict) -> &'static str {
    match v {
        Verdict::Whitelisted => "在出口 IP 白名单内",
        Verdict::Trusted => "在下方「可信 DNS 解析器」列表内",
        Verdict::SameNetwork => "与当前出口 IP 属于同一个网络（同一自治系统），多半是 VPN 服务商自己的解析器",
        Verdict::Local => "局域网地址，只在本地网络可见",
        Verdict::Exposed => "网卡上的公网地址：网页获得摄像头/麦克风权限后可以通过 WebRTC 读到",
        Verdict::Leak => "不在白名单内，也不是可信解析器（解析器本身不一定说明泄露：VPN 也可能使用公共解析器）",
        Verdict::NoResponse => "STUN 服务器没有响应：这条路径没有验证到（只说明到这些服务器的 UDP 不通，不能证明不会暴露）",
    }
}

/// 摘要卡片里的一行：圆点 + 名称 + 结论。
fn summary_line(ui: &mut egui::Ui, p: &Palette, name: &str, color: Color32, text: &str, busy: bool) {
    ui.horizontal(|ui| {
        ui.set_min_height(26.0);
        let (r, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
        ui.painter().circle_filled(r.center(), 4.5, color);
        ui.allocate_ui_with_layout(egui::vec2(62.0, 18.0), Layout::left_to_right(Align::Center), |ui| {
            ui.set_min_width(62.0);
            ui.label(RichText::new(name).font(theme::bold(14.0)).color(p.label));
        });
        if busy {
            ui.add(egui::Spinner::new().size(13.0));
        }
        ui.add(egui::Label::new(RichText::new(text).color(p.secondary)).wrap());
    });
}

/// 可点击的胶囊开关（选中时为强调色）。
fn toggle_chip(ui: &mut egui::Ui, p: &Palette, on: &mut bool, text: &str) -> egui::Response {
    let fg = if *on { Color32::WHITE } else { p.label };
    let galley = ui.painter().layout_no_wrap(text.to_owned(), egui::FontId::proportional(12.5), fg);
    let size = egui::vec2(galley.size().x + 22.0, 24.0);
    let (rect, mut resp) = ui.allocate_exact_size(size, egui::Sense::click());
    if resp.clicked() {
        *on = !*on;
        resp.mark_changed();
    }
    let h = theme::ease(ui.ctx(), resp.id.with("hover"), resp.hovered(), 0.12);
    let bg = if *on { p.accent.gamma_multiply(1.0 - 0.12 * h) } else if h > 0.0 { p.fill_hover } else { p.fill };
    ui.painter().rect_filled(rect, CornerRadius::same(12), bg);
    let fg = if *on { Color32::WHITE } else { p.label };
    ui.painter().galley_with_override_text_color(rect.center() - galley.size() / 2.0, galley, fg);
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// 列表行：左侧主文字（等宽）+ 说明，右侧控件。
fn item_row(ui: &mut egui::Ui, p: &Palette, main: &str, sub: &str, right: impl FnOnce(&mut egui::Ui)) {
    /// 右侧（判定标签、「信任」按钮）预留的宽度；左侧文字超出时截断，悬停看全文。
    const RIGHT_W: f32 = 200.0;
    let h = if sub.is_empty() { 34.0 } else { 44.0 };
    ui.horizontal(|ui| {
        ui.set_min_height(h);
        let left_w = (ui.available_width() - RIGHT_W).max(120.0);
        ui.allocate_ui_with_layout(egui::vec2(left_w, h), Layout::top_down(Align::Min), |ui| {
            ui.set_width(left_w);
            ui.add_space(if sub.is_empty() { 8.0 } else { 4.0 });
            ui.add(egui::Label::new(RichText::new(main).monospace().color(p.label)).truncate());
            if !sub.is_empty() {
                ui.add_space(-5.0);
                ui.add(egui::Label::new(RichText::new(sub).size(12.0).color(p.secondary)).truncate());
            }
        });
        ui.with_layout(Layout::right_to_left(Align::Center), right);
    });
}

impl App {
    /// 手动开始测试（按正在编辑的设置）。
    pub(super) fn start_leak_test(&mut self, ctx: &egui::Context) {
        self.sync_stun();
        let egress = self.status.lock().unwrap().egress_ip;
        let lt = self.draft.leak_test.clone();
        let judge = Judge::from_strings(&self.draft.whitelist, &lt.trusted_dns);
        self.leak.job.start(lt, judge, egress, None, ctx.clone(), |_| {});
    }

    fn sync_stun(&mut self) {
        self.draft.leak_test.stun_servers =
            self.leak.stun_text.lines().map(|l| l.trim().to_owned()).filter(|l| !l.is_empty()).collect();
    }

    fn judge(&self) -> Judge {
        Judge::from_strings(&self.draft.whitelist, &self.draft.leak_test.trusted_dns)
    }

    /// 当前结果（按正在编辑的白名单重新判定）。
    fn leak_results(&self) -> (LeakView, LeakView) {
        let j = self.judge();
        let d = match &*self.leak.job.dns.lock().unwrap() {
            Task::Idle => LeakView::Idle,
            Task::Running { since, progress } => LeakView::Running(since.elapsed().as_secs(), *progress),
            Task::Done { at, result: Ok(r) } => {
                let r = r.judged(&j);
                let (l, t) = leaktest::dns_summary(&r);
                LeakView::Done { at: at.clone(), level: Some(l), text: t, dns: Some(Box::new(r)), rtc: None }
            }
            Task::Done { at, result: Err(e) } => {
                LeakView::Done { at: at.clone(), level: None, text: format!("测试失败：{e}"), dns: None, rtc: None }
            }
        };
        let w = match &*self.leak.job.webrtc.lock().unwrap() {
            Task::Idle => LeakView::Idle,
            Task::Running { since, .. } => LeakView::Running(since.elapsed().as_secs(), 0),
            Task::Done { at, result } => {
                let r = result.judged(&j);
                let (l, t) = leaktest::webrtc_summary(&r);
                LeakView::Done { at: at.clone(), level: Some(l), text: t, dns: None, rtc: Some(Box::new(r)) }
            }
        };
        (d, w)
    }

    /// 概览页「保护」卡片里的一行。
    pub(super) fn leak_overview_row(&mut self, ui: &mut egui::Ui, p: &Palette) -> bool {
        let (d, w) = self.leak_results();
        let (text, color) = match (&d, &w) {
            (LeakView::Running(..), _) | (_, LeakView::Running(..)) => ("测试中…".to_owned(), p.secondary),
            (LeakView::Idle, LeakView::Idle) => ("未测试".to_owned(), p.accent),
            _ => {
                let worst = [d.level(), w.level()].into_iter().flatten().max_by_key(|l| *l as u8);
                match worst {
                    Some(Level::Leak) => ("发现泄露".to_owned(), p.red),
                    Some(Level::Warn) => ("需要留意".to_owned(), p.orange),
                    Some(Level::Ok) if d.level().is_none() => ("DNS 测试失败".to_owned(), p.orange),
                    Some(Level::Ok) => ("未发现泄露".to_owned(), p.green),
                    None => ("测试失败".to_owned(), p.orange),
                }
            }
        };
        let mut go = false;
        theme::row(ui, p, "DNS / WebRTC 泄露", None, |ui| {
            go = theme::text_button(ui, color, &format!("{text}  ›")).clicked();
        });
        go
    }

    pub(super) fn leak_page(&mut self, ui: &mut egui::Ui, p: &Palette) {
        theme::page_title(ui, p, "泄露测试", "检查域名解析（DNS）和 WebRTC 会不会绕过白名单出口，暴露你的真实网络。");
        let s = self.status.lock().unwrap().clone();
        let judge = self.judge();
        let (d, w) = self.leak_results();
        let busy = matches!(d, LeakView::Running(..)) || matches!(w, LeakView::Running(..));
        if busy {
            ui.ctx().request_repaint_after(std::time::Duration::from_millis(250));
        }

        match s.egress_ip {
            Some(ip) if !judge.whitelisted(ip) => {
                info_card(
                    ui,
                    p,
                    "当前出口 IP 不在白名单内",
                    &format!("测试结果会与白名单对比。先连上白名单内的出口（例如 VPN），再测试才有参考意义。当前出口：{ip}"),
                );
                ui.add_space(4.0);
            }
            _ => {}
        }
        if cfg!(target_os = "macos") && s.blocked && s.block_all {
            warning_card(ui, p, "全局断网生效中", "测试流量也会被 pf 拦截，大部分结果会显示为失败或无响应。");
            ui.add_space(4.0);
        }

        // ---- 摘要 ----
        let mut start = false;
        theme::card(ui, p, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    let title = match (d.level(), w.level()) {
                        _ if busy => "正在测试…",
                        (Some(Level::Leak), _) | (_, Some(Level::Leak)) => "发现泄露",
                        (Some(Level::Ok), Some(Level::Ok)) => "未发现泄露",
                        _ if matches!((&d, &w), (LeakView::Idle, LeakView::Idle)) => "尚未测试",
                        _ => "测试完成",
                    };
                    ui.label(RichText::new(title).font(theme::bold(20.0)).color(p.label));
                    ui.add_space(-4.0);
                    let sub = match (&d, &w) {
                        (LeakView::Done { at, .. }, _) | (_, LeakView::Done { at, .. }) if !busy => {
                            let m = self.leak.job.meta.lock().unwrap();
                            let e = m.egress.map(|i| format!("，当时出口 IP {i}")).unwrap_or_default();
                            format!("{}测试于 {at}{e}", if m.auto { "自动" } else { "" })
                        }
                        _ if busy => "大约需要 10 秒".to_owned(),
                        _ => "大约需要 10 秒；也可以在下方设置网络变化后、定时自动测试".to_owned(),
                    };
                    ui.label(RichText::new(sub).size(12.5).color(p.secondary));
                });
                ui.with_layout(Layout::right_to_left(Align::Min), |ui| {
                    let label = if matches!((&d, &w), (LeakView::Idle, LeakView::Idle)) { "开始测试" } else { "重新测试" };
                    start = theme::accent_button(ui, p, label, !busy).clicked();
                });
            });
            ui.add_space(8.0);
            theme::hairline(ui, p);
            for (name, v) in [("DNS", &d), ("WebRTC", &w)] {
                let (color, text, running) = match v {
                    LeakView::Idle => (p.gray, "未测试".to_owned(), false),
                    LeakView::Running(secs, n) if *n > 0 => (p.gray, format!("正在测试… 已收到 {n} 次查询（{secs} 秒）"), true),
                    LeakView::Running(secs, _) => (p.gray, format!("正在测试…（{secs} 秒）"), true),
                    LeakView::Done { level, text, .. } => {
                        (level.map(|l| level_color(p, l)).unwrap_or(p.orange), text.clone(), false)
                    }
                };
                summary_line(ui, p, name, color, &text, running);
            }
            ui.add_space(2.0);
        });
        if start {
            self.start_leak_test(ui.ctx());
        }

        // ---- DNS 结果 ----
        if let LeakView::Done { dns: Some(r), .. } = &d {
            self.dns_results(ui, p, r);
        }

        // ---- WebRTC 结果 ----
        if let LeakView::Done { rtc: Some(r), .. } = &w {
            webrtc_results(ui, p, r);
        }

        // ---- 自动测试 ----
        self.auto_section(ui, p, &s);

        // ---- 可信解析器 ----
        self.trusted_section(ui, p);

        // ---- 测试服务 ----
        self.services_section(ui, p);
    }

    fn dns_results(&mut self, ui: &mut egui::Ui, p: &Palette, r: &DnsReport) {
        theme::section(ui, p, &format!("DNS 解析器 {} 个", r.resolvers.len()));
        let mut trust = None;
        theme::card(ui, p, |ui| {
            let n = r.resolvers.len() + r.client_subnets.len();
            let mut i = 0;
            for x in &r.resolvers {
                let mut sub = x.info.as_ref().map(|i| i.describe()).unwrap_or_default();
                if x.queries > 0 {
                    let protos = if x.protos.is_empty() { String::new() } else { format!("{} ", x.protos.join("/")) };
                    sub.push_str(&format!("{}{protos}{} 次查询", if sub.is_empty() { "" } else { " · " }, x.queries));
                }
                if !x.sources.is_empty() {
                    sub.push_str(&format!("{}{}", if sub.is_empty() { "" } else { " · " }, x.sources.join("、")));
                }
                let asn = x.info.as_ref().and_then(|i| i.asn);
                item_row(ui, p, &x.ip.to_string(), &sub, |ui| {
                    theme::chip(ui, verdict_color(p, x.verdict), x.verdict.label()).on_hover_text(verdict_hint(x.verdict));
                    if x.verdict.is_leak() {
                        let (label, entry) = match asn {
                            Some(a) => (format!("信任 AS{a}"), format!("AS{a}")),
                            None => ("信任".to_owned(), x.ip.to_string()),
                        };
                        let hover = format!("把 {entry} 加入可信 DNS 解析器（保存后生效）");
                        if theme::text_button(ui, p.accent, &label).on_hover_text(hover).clicked() {
                            trust = Some(entry);
                        }
                    }
                });
                i += 1;
                if i < n {
                    theme::hairline(ui, p);
                }
            }
            for x in &r.client_subnets {
                let sub = format!("解析器转发给网站的客户端网段（ECS）{}", x.info.as_ref().map(|i| format!(" · {}", i.describe())).unwrap_or_default());
                item_row(ui, p, &x.subnet.to_string(), &sub, |ui| {
                    let hint = if x.verdict.is_leak() {
                        "这是解析器看到的「你」所在的网段，它不在白名单内：说明域名查询是从白名单以外的出口发给解析器的"
                    } else {
                        "与白名单或当前出口一致"
                    };
                    theme::chip(ui, verdict_color(p, x.verdict), x.verdict.label()).on_hover_text(hint);
                });
                i += 1;
                if i < n {
                    theme::hairline(ui, p);
                }
            }
        });
        // 检测源状态：一行小字，失败的悬停看原因
        egui::Frame::new().inner_margin(Margin { left: 12, right: 12, top: 0, bottom: 0 }).show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                ui.label(RichText::new("检测源：").size(12.0).color(p.secondary));
                for s in &r.sources {
                    let c = if s.ok { p.green } else { p.orange };
                    let hover = if s.ok { s.detail.clone() } else { format!("失败：{}", s.detail) };
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing.x = 3.0;
                        let (rect, _) = ui.allocate_exact_size(egui::vec2(7.0, 12.0), egui::Sense::hover());
                        ui.painter().circle_filled(rect.center(), 3.0, c);
                        ui.label(RichText::new(&s.name).size(12.0).color(p.secondary));
                    })
                    .response
                    .on_hover_text(hover);
                }
            });
        });
        if let Some(e) = trust {
            self.add_trusted(e);
        }
    }

    fn add_trusted(&mut self, entry: String) {
        match Trusted::parse(&entry) {
            Ok(t) => {
                let text = t.to_string();
                if self.draft.leak_test.trusted_dns.contains(&text) {
                    self.leak.trusted_error = Some("该条目已存在".into());
                } else {
                    self.draft.leak_test.trusted_dns.push(text);
                    self.leak.new_trusted.clear();
                    self.leak.trusted_error = None;
                }
            }
            Err(e) => self.leak.trusted_error = Some(format!("{e}")),
        }
    }

    fn trusted_section(&mut self, ui: &mut egui::Ui, p: &Palette) {
        theme::section(ui, p, &format!("可信 DNS 解析器 {} 条", self.draft.leak_test.trusted_dns.len()));
        let mut remove = None;
        let mut add = None;
        theme::card(ui, p, |ui| {
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                let w = ui.available_width() - 80.0;
                let edit = ui.add(
                    egui::TextEdit::singleline(&mut self.leak.new_trusted)
                        .hint_text("例如 AS13335、1.1.1.1 或 172.64.0.0/13")
                        .desired_width(w)
                        .margin(Margin::symmetric(8, 5)),
                );
                let enter = edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if theme::accent_button(ui, p, "添加", true).clicked() || enter {
                    add = Some(self.leak.new_trusted.trim().to_owned()).filter(|s| !s.is_empty());
                }
            });
            if let Some(e) = &self.leak.trusted_error {
                ui.label(RichText::new(e).size(12.0).color(p.red));
            }
            for (i, entry) in self.draft.leak_test.trusted_dns.iter().enumerate() {
                theme::hairline(ui, p);
                let kind = match Trusted::parse(entry) {
                    Ok(Trusted::Asn(_)) => "自治系统",
                    Ok(Trusted::Net(n)) if n.prefix_len() == n.max_prefix_len() => "单个地址",
                    Ok(Trusted::Net(_)) => "网段",
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
                    });
                });
            }
        });
        if let Some(e) = add {
            self.add_trusted(e);
        }
        if let Some(i) = remove {
            self.draft.leak_test.trusted_dns.remove(i);
        }
        theme::footnote(
            ui,
            p,
            "出口 IP 白名单内的解析器本来就算安全。用 Cloudflare、Google 等公共解析器时，它们向外查询的 IP 不固定，按自治系统（AS 号）信任更方便。",
        );
    }

    fn auto_section(&mut self, ui: &mut egui::Ui, p: &Palette, s: &crate::engine::Status) {
        theme::section(ui, p, "自动测试");
        let st = self.auto_leak.lock().unwrap().clone();
        theme::card(ui, p, |ui| {
            let lt = &mut self.draft.leak_test;
            theme::row(
                ui,
                p,
                "允许后台自动测试",
                Some("测试会绕过代理直连下方的 DNS 检测源和 STUN 服务器：用系统 DNS 解析检测域名，并从默认路由和每个网卡地址发 UDP。只靠代理上网时，这些第三方会看到你直连的公网地址"),
                |ui| {
                    theme::toggle(ui, p, &mut lt.auto);
                },
            );
            theme::hairline(ui, p);
            let enabled = lt.auto;
            ui.add_enabled_ui(enabled, |ui| {
                theme::row(ui, p, "网络变化后自动测试", Some("刚放行、或者出口 IP 变了时，等 10 秒网络稳定后测一次"), |ui| {
                    theme::toggle(ui, p, &mut lt.auto_after_change);
                });
                theme::hairline(ui, p);
                theme::row(ui, p, "定时测试", Some("距上次测试满这么久就再测一次；0 表示不定时测试"), |ui| {
                    ui.add(egui::DragValue::new(&mut lt.interval_mins).range(0..=1440).suffix(" 分钟"));
                });
                theme::hairline(ui, p);
                theme::row(ui, p, "发现泄露时发系统通知", Some("同一出口、同样的结论只提醒一次；结果也会写进「连接记录」"), |ui| {
                    theme::toggle(ui, p, &mut lt.notify);
                });
            });
            theme::hairline(ui, p);
            let next = match st.next {
                _ if !lt.auto || (!lt.auto_after_change && lt.interval_mins == 0) => "已关闭（可以随时手动测试）".to_owned(),
                _ if s.simulated => "模拟模式下不自动测试".to_owned(),
                Some(t) => {
                    let secs = t.saturating_duration_since(Instant::now()).as_secs();
                    match secs {
                        0 => "即将开始".to_owned(),
                        1..=59 => format!("{secs} 秒后"),
                        _ => format!("约 {} 分钟后", secs.div_ceil(60)),
                    }
                }
                None if s.running && !s.blocked => "等待出口 IP 通过检查".to_owned(),
                None => "出口放行后进行（阻断时测试流量也被切断）".to_owned(),
            };
            let last = st.last.as_ref().map(|(t, r)| format!("；上次 {t}：{r}")).unwrap_or_default();
            ui.add_space(6.0);
            ui.label(RichText::new(format!("下一次自动测试：{next}{last}")).size(12.5).color(p.secondary));
            ui.add_space(4.0);
        });
        if st.next.is_some() {
            ui.ctx().request_repaint_after(std::time::Duration::from_secs(1));
        }
        theme::footnote(ui, p, "自动测试在后台进行，窗口收在托盘 / 菜单栏里也照常运行；改动在保存设置后生效。");
    }

    fn services_section(&mut self, ui: &mut egui::Ui, p: &Palette) {
        theme::section(ui, p, "测试服务");
        theme::card(ui, p, |ui| {
            theme::row(ui, p, "DNS 测试服务", Some("addr.tools 的 dnscheck，开源（AGPL-3.0），可以自建"), |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.draft.leak_test.dnscheck_zone)
                        .desired_width(170.0)
                        .font(egui::TextStyle::Monospace)
                        .margin(Margin::symmetric(8, 4)),
                );
            });
            theme::hairline(ui, p);
            ui.add_space(4.0);
            ui.label(RichText::new("DNS 检测源").color(p.label));
            ui.add_space(-2.0);
            ui.label(
                RichText::new("dnscheck 能看到全部解析器和 ECS；其余每个只发一次 HTTP 请求、只看到一个解析器，在 dnscheck 连不上时也能给出结果")
                    .size(12.0)
                    .color(p.secondary),
            );
            ui.add_space(2.0);
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = egui::vec2(6.0, 6.0);
                let names: Vec<&str> = std::iter::once(dns::DNSCHECK).chain(HttpSource::ALL.iter().map(|s| s.name())).collect();
                for name in names {
                    let list = &mut self.draft.leak_test.dns_sources;
                    let mut on = list.iter().any(|s| s == name);
                    if toggle_chip(ui, p, &mut on, name).changed() {
                        if on {
                            list.push(name.to_owned());
                        } else {
                            list.retain(|s| s != name);
                        }
                    }
                }
            });
            ui.add_space(6.0);
            theme::hairline(ui, p);
            ui.add_space(4.0);
            ui.label(RichText::new("STUN 服务器").color(p.label));
            ui.add_space(-2.0);
            ui.label(RichText::new("每行一个「主机:端口」，按顺序尝试").size(12.0).color(p.secondary));
            ui.add(
                egui::TextEdit::multiline(&mut self.leak.stun_text)
                    .desired_rows(3)
                    .desired_width(f32::INFINITY)
                    .font(egui::TextStyle::Monospace)
                    .margin(Margin::symmetric(8, 6)),
            );
            ui.add_space(4.0);
        });
        self.sync_stun();
        theme::footnote(
            ui,
            p,
            "DNS 测试解析几个随机子域名，由检测服务的权威服务器告诉本程序是哪些解析器来查询的（方法参考 addr.tools 与 MyIP）。\
             WebRTC 测试从默认路由和每个网卡分别向 STUN 服务器发送绑定请求，与浏览器收集 ICE 候选地址的方式相同。\
             解析器与出口 IP 的归属信息来自 ip.addr.tools。",
        );
    }
}

fn webrtc_results(ui: &mut egui::Ui, p: &Palette, r: &WebRtcReport) {
    theme::section(ui, p, "WebRTC 能看到的公网 IP（STUN）");
    theme::card(ui, p, |ui| {
        if r.paths.is_empty() {
            empty_state(ui, p, "没有可测试的网络", "本机没有可用的网卡地址。");
            return;
        }
        let n = r.paths.len();
        for (i, x) in r.paths.iter().enumerate() {
            let family = if x.local.is_ipv4() { "IPv4" } else { "IPv6" };
            let title = match &x.iface {
                None => format!("默认路由 · {family}"),
                Some(name) => format!("{name} · {}", x.local),
            };
            let (main, sub) = match (&x.mapped, &x.server) {
                (Some(m), server) => (m.ip().to_string(), format!("{title}{}", server.as_ref().map(|s| format!(" · 经 {s}")).unwrap_or_default())),
                (None, _) => ("—".to_owned(), format!("{title} · {}", x.error.as_deref().unwrap_or("无响应"))),
            };
            item_row(ui, p, &main, &sub, |ui| {
                theme::chip(ui, verdict_color(p, x.verdict), x.verdict.label()).on_hover_text(verdict_hint(x.verdict));
            });
            if i + 1 < n {
                theme::hairline(ui, p);
            }
        }
    });
    if !r.unresolved.is_empty() {
        theme::footnote(ui, p, &format!("无法解析的 STUN 服务器：{}", r.unresolved.join("；")));
    }

    theme::section(ui, p, &format!("网卡地址 {} 个（host 候选）", r.hosts.len()));
    theme::card(ui, p, |ui| {
        if r.hosts.is_empty() {
            empty_state(ui, p, "没有网卡地址", "");
            return;
        }
        let n = r.hosts.len();
        for (i, h) in r.hosts.iter().enumerate() {
            item_row(ui, p, &h.ip.to_string(), &h.iface, |ui| {
                theme::chip(ui, verdict_color(p, h.verdict), h.verdict.label()).on_hover_text(verdict_hint(h.verdict));
            });
            if i + 1 < n {
                theme::hairline(ui, p);
            }
        }
    });
    theme::footnote(
        ui,
        p,
        "浏览器默认用随机的 .local 名称隐藏网卡地址；网页获得摄像头或麦克风权限后，就能读到这里列出的真实地址，并从每个网卡分别连 STUN 服务器。",
    );
}

/// 一项测试在界面上的状态。
enum LeakView {
    Idle,
    /// 已运行秒数、收到的查询数。
    Running(u64, u32),
    Done { at: String, level: Option<Level>, text: String, dns: Option<Box<DnsReport>>, rtc: Option<Box<WebRtcReport>> },
}

impl LeakView {
    fn level(&self) -> Option<Level> {
        match self {
            LeakView::Done { level, .. } => *level,
            _ => None,
        }
    }
}
