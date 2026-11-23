//! 界面的后台任务：自动泄露测试、检查新版本。
//!
//! 窗口大多数时候隐藏在托盘 / 菜单栏里，egui 不会刷新界面，所以这两件事各自在后台线程里按时间进行，
//! 结果写进共享状态，界面打开时显示；需要提醒时发系统通知。

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui;
use serde::{Deserialize, Serialize};

use super::backend::Backend;
use super::leak::LeakJob;
use super::notify;
use crate::config::RawConfig;
use crate::engine::Status;
use crate::eventlog::{ConnEvent, Kind};
use crate::leaktest::Judge;
use crate::update::{self, Release};

/// 网络变化后等多久再测（VPN 刚连上时 DNS 等设置可能还没到位）。
const SETTLE: Duration = Duration::from_secs(10);

// ---------------- 界面自己的小状态文件 ----------------

/// 界面记住的东西（不属于配置）：已经提醒过、已经忽略的版本。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct GuiState {
    /// 已经为这个版本发过通知。
    pub notified_version: String,
    /// 用户点了「忽略这个版本」。
    pub dismissed_version: String,
}

fn state_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    let dir = crate::mac::paths::gui_data_dir();
    #[cfg(windows)]
    let dir = std::env::var_os("LOCALAPPDATA")
        .map(|d| PathBuf::from(d).join("EgressGuard"))
        .or_else(crate::exe_dir)
        .unwrap_or_else(std::env::temp_dir);
    #[cfg(not(any(windows, target_os = "macos")))]
    let dir = std::env::temp_dir().join("egress-guard");
    dir.join("gui-state.json")
}

impl GuiState {
    pub fn load() -> Self {
        std::fs::read_to_string(state_path()).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
    }

    pub fn save(&self) {
        let path = state_path();
        if let Some(d) = path.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        if let Err(e) = std::fs::write(&path, serde_json::to_string_pretty(self).unwrap_or_default()) {
            log::warn!("无法保存 {}: {e}", path.display());
        }
    }
}

// ---------------- 自动泄露测试 ----------------

/// 自动测试的进度（界面显示用）。
#[derive(Debug, Clone, Default)]
pub struct AutoLeak {
    /// 计划下一次自动测试的时刻。
    pub next: Option<Instant>,
    /// 上一次自动测试完成的本地时间与结论。
    pub last: Option<(String, String)>,
}

/// 出口处于「放行」：只有这时测试才有意义（阻断时测试流量也被切断，macOS 全局断网时尤其如此）。
fn allowed_key(s: &Status) -> Option<(IpAddr, Option<IpAddr>)> {
    let ok = s.running && !s.blocked && s.whitelisted == Some(true) && s.v6_whitelisted != Some(false);
    ok.then_some(())?;
    Some((s.egress_ip?, s.egress_v6))
}

pub struct LeakScheduler {
    pub status: Arc<Mutex<Status>>,
    /// 已保存的配置。
    pub config: Arc<Mutex<RawConfig>>,
    pub job: LeakJob,
    pub backend: Arc<dyn Backend>,
    pub ctx: egui::Context,
    pub state: Arc<Mutex<AutoLeak>>,
}

impl LeakScheduler {
    pub fn spawn(self) {
        std::thread::Builder::new()
            .name("auto-leak-test".into())
            .spawn(move || self.run())
            .expect("无法创建自动泄露测试线程");
    }

    fn run(self) {
        let mut last_key: Option<(IpAddr, Option<IpAddr>)> = None;
        // 网络变化后计划的那次测试；进入放行状态的时刻
        let mut change_at: Option<Instant> = None;
        let mut allowed_since = Instant::now();
        // 已经通知过的泄露（同一出口、同样的结论只提醒一次）
        let notified: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        loop {
            std::thread::sleep(Duration::from_secs(1));
            let s = self.status.lock().unwrap().clone();
            let cfg = self.config.lock().unwrap().clone();
            let lt = &cfg.leak_test;
            let Some(key) = allowed_key(&s) else {
                last_key = None;
                change_at = None;
                self.state.lock().unwrap().next = None;
                continue;
            };
            let now = Instant::now();
            // 刚放行、或者出口变了：等网络稳定后测一次
            if last_key != Some(key) {
                last_key = Some(key);
                allowed_since = now;
                change_at = Some(now + SETTLE);
            }
            if !lt.auto_after_change {
                change_at = None;
            }
            // 定时测试：距上次测试（手动或自动）满间隔；从没测过时放行后稍等就测
            let interval_at = (lt.interval_mins > 0).then(|| {
                let every = Duration::from_secs(lt.interval_mins * 60);
                match self.job.meta.lock().unwrap().finished {
                    Some(t) => (t + every).max(allowed_since + SETTLE),
                    None => allowed_since + SETTLE,
                }
            });
            let next = [change_at, interval_at].into_iter().flatten().min();
            self.state.lock().unwrap().next = next;
            if !next.is_some_and(|t| t <= now) || self.job.running() {
                continue;
            }
            change_at = None;
            let judge = Judge::from_strings(&cfg.whitelist, &lt.trusted_dns);
            let (backend, state, notified, notify_on) = (self.backend.clone(), self.state.clone(), notified.clone(), lt.notify);
            self.job.start(lt.clone(), judge, Some(key.0), true, self.ctx.clone(), move |o| {
                let summary = match o.leak_text() {
                    Some(t) => {
                        let mut e = ConnEvent::now(Kind::Leak, format!("自动泄露测试：{t}"));
                        e.egress = o.egress;
                        e.egress_v6 = key.1;
                        backend.record_event(e);
                        let tag = format!("{key:?}{t}");
                        let mut n = notified.lock().unwrap();
                        if notify_on && n.as_deref() != Some(&tag) {
                            *n = Some(tag);
                            notify::show("Egress Guard 发现泄露", &t);
                        }
                        "发现泄露".to_owned()
                    }
                    None => {
                        *notified.lock().unwrap() = None;
                        if o.dns.is_err() { "DNS 测试失败，WebRTC 未发现泄露".to_owned() } else { "未发现泄露".to_owned() }
                    }
                };
                state.lock().unwrap().last = Some((crate::logbuf::now_hms(), summary));
            });
        }
    }
}

// ---------------- 检查新版本 ----------------

/// 检查新版本的结果（界面显示用）。
#[derive(Debug, Clone, Default)]
pub struct UpdateState {
    pub checking: bool,
    /// 上次检查的本地时间。
    pub checked_at: Option<String>,
    /// 最新的发布版本（检查成功时）。
    pub latest: Option<Release>,
    pub error: Option<String>,
}

impl UpdateState {
    /// 有比当前更新的版本。
    pub fn newer(&self) -> Option<&Release> {
        self.latest.as_ref().filter(|r| update::is_newer(&r.version, update::CURRENT))
    }
}

/// 启动后多久第一次检查，之后的间隔。
const FIRST_CHECK: Duration = Duration::from_secs(20);
const CHECK_EVERY: Duration = Duration::from_secs(24 * 3600);
/// 失败后多久重试。
const RETRY_AFTER: Duration = Duration::from_secs(3600);

pub struct UpdateChecker {
    pub config: Arc<Mutex<RawConfig>>,
    pub state: Arc<Mutex<UpdateState>>,
    /// 「立即检查」按钮。
    pub manual: Receiver<()>,
    pub ctx: egui::Context,
}

impl UpdateChecker {
    pub fn spawn(self) {
        std::thread::Builder::new()
            .name("update-check".into())
            .spawn(move || self.run())
            .expect("无法创建检查更新线程");
    }

    fn run(self) {
        let mut wait = FIRST_CHECK;
        loop {
            let manual = match self.manual.recv_timeout(wait) {
                Ok(()) => true,
                Err(RecvTimeoutError::Timeout) => false,
                Err(RecvTimeoutError::Disconnected) => return,
            };
            let cfg = self.config.lock().unwrap().update.clone();
            if !cfg.check && !manual {
                wait = CHECK_EVERY;
                continue;
            }
            self.state.lock().unwrap().checking = true;
            self.ctx.request_repaint();
            let r = update::fetch_latest(&cfg.repo, &cfg.token, Duration::from_secs(15));
            let mut st = self.state.lock().unwrap();
            st.checking = false;
            st.checked_at = Some(crate::logbuf::now_string());
            match r {
                Ok(rel) => {
                    log::info!("检查更新：最新版本 {}，当前 {}", rel.version, update::CURRENT);
                    st.error = None;
                    st.latest = Some(rel);
                    wait = CHECK_EVERY;
                }
                Err(e) => {
                    log::warn!("检查更新失败: {e:#}");
                    st.error = Some(format!("{e:#}"));
                    wait = RETRY_AFTER;
                }
            }
            // 同一个新版本只通知一次（用户忽略的版本不通知）
            if let Some(rel) = st.newer().cloned() {
                let mut gs = GuiState::load();
                if gs.notified_version != rel.version && gs.dismissed_version != rel.version {
                    gs.notified_version = rel.version.clone();
                    gs.save();
                    drop(st);
                    notify::show(
                        &format!("Egress Guard {} 已发布", rel.version),
                        &format!("当前是 {}。打开 Egress Guard 查看并下载新版本。", update::CURRENT),
                    );
                }
            }
            self.ctx.request_repaint();
        }
    }
}
