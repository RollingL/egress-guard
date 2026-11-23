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
/// 模拟模式下规则没有生效，测试结果说明不了保护的情况，也不测。
/// 第三项是网络 / 配置代次：网络一变，之前的测试就作废。
type Key = (IpAddr, Option<IpAddr>, u64);

fn allowed_key(s: &Status) -> Option<Key> {
    let ok = s.running
        && !s.blocked
        && !s.simulated
        && s.apply_error.is_none()
        // 保护范围没有完全就绪（例如网络扩展缺能力、规则没按新配置更新）时测出来的结果说明不了问题
        && s.degraded.is_none()
        && s.config_apply_error.is_none()
        && s.whitelisted == Some(true)
        && s.v6_whitelisted != Some(false)
        // 出口是在当前这一代网络上测的（网卡、VPN 变了之后显示的还是旧出口，不能据此开始测试）。
        // 旧版本的服务不报告这一项，按原来的方式判断
        && s.verified_generation.is_none_or(|g| g == s.generation);
    ok.then_some(())?;
    Some((s.egress_ip?, s.egress_v6, s.generation))
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
        // 上一次的出口（不含代次：网络抖一下而出口没变时不必重测）
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
            // 总开关关闭时不发出任何后台探测
            let Some(key) = allowed_key(&s).filter(|_| lt.auto) else {
                last_key = None;
                change_at = None;
                self.state.lock().unwrap().next = None;
                continue;
            };
            let now = Instant::now();
            // 刚放行、或者出口变了：等网络稳定后测一次
            if last_key != Some((key.0, key.1)) {
                last_key = Some((key.0, key.1));
                allowed_since = now;
                change_at = Some(now + SETTLE);
            }
            if !lt.auto_after_change {
                change_at = None;
            }
            // 定时测试：距上次测试（手动或自动）满间隔；从没测过时放行后稍等就测
            let interval_at = (lt.interval_mins > 0).then(|| {
                let every = Duration::from_secs(lt.interval_mins.saturating_mul(60));
                let settled = allowed_since + SETTLE;
                match self.job.meta.lock().unwrap().finished {
                    // 间隔大到超出时钟范围时等同于不定时测试
                    Some(t) => t.checked_add(every).map_or(settled.max(now + Duration::from_secs(86400)), |at| at.max(settled)),
                    None => settled,
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
            // 测试期间网络、配置或阻断状态变了：停止发出后续探测，结果作废（不记录、不通知）
            let valid: super::leak::Validity = {
                let (status, config) = (self.status.clone(), self.config.clone());
                let lt0 = lt.clone();
                Arc::new(move || {
                    let still = allowed_key(&status.lock().unwrap()) == Some(key);
                    let cfg = config.lock().unwrap();
                    still && cfg.leak_test.auto && cfg.leak_test == lt0
                })
            };
            let check = valid.clone();
            self.job.start(lt.clone(), judge, Some(key.0), Some(valid), self.ctx.clone(), move |o| {
                if !check() {
                    log::info!("自动泄露测试期间网络或设置变了，结果作废");
                    state.lock().unwrap().last = Some((crate::logbuf::now_hms(), "网络或设置变了，结果作废".to_owned()));
                    return;
                }
                let summary = match o.leak_text() {
                    Some(t) => {
                        let mut e = ConnEvent::now(Kind::Leak, format!("自动泄露测试：{t}"));
                        e.egress = o.egress;
                        e.egress_v6 = key.1;
                        backend.record_event(e);
                        let tag = format!("{:?}{t}", (key.0, key.1));
                        let mut n = notified.lock().unwrap();
                        if notify_on && n.as_deref() != Some(&tag) {
                            *n = Some(tag);
                            notify::show("Egress Guard 发现泄露", &t);
                        }
                        "发现泄露".to_owned()
                    }
                    None => {
                        *notified.lock().unwrap() = None;
                        match o.warn_text() {
                            Some(w) => format!("没有直接泄露，需要留意：{w}"),
                            None => "未发现泄露".to_owned(),
                        }
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
/// 关闭检查更新时多久再看一次设置。
const DISABLED_POLL: Duration = Duration::from_secs(60);
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
                // 关闭期间每分钟看一次设置，重新打开后很快就会检查
                wait = DISABLED_POLL;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed() -> Status {
        Status {
            running: true,
            egress_ip: Some("203.0.113.9".parse().unwrap()),
            whitelisted: Some(true),
            generation: 3,
            verified_generation: Some(3),
            ..Default::default()
        }
    }

    #[test]
    fn only_tests_while_really_allowed() {
        assert_eq!(allowed_key(&allowed()), Some(("203.0.113.9".parse().unwrap(), None, 3)));
        assert!(allowed_key(&Status { blocked: true, ..allowed() }).is_none());
        assert!(allowed_key(&Status { simulated: true, ..allowed() }).is_none(), "模拟模式不测");
        assert!(allowed_key(&Status { apply_error: Some("放行未生效".into()), ..allowed() }).is_none());
        assert!(allowed_key(&Status { v6_whitelisted: Some(false), ..allowed() }).is_none());
        // 网络变了（代次不同）：之前开始的测试作废；新一代还没有检测结果时不测（旧出口只用来显示）
        assert!(allowed_key(&Status { generation: 4, ..allowed() }).is_none());
        let next = Status { generation: 4, verified_generation: Some(4), ..allowed() };
        assert_ne!(allowed_key(&next), allowed_key(&allowed()));
        assert!(allowed_key(&next).is_some());
        // 检测失败后没有当前代次的结果
        assert!(allowed_key(&Status { verified_generation: None, ..allowed() }).is_some(), "旧版本服务");
        // 默认不允许后台自动测试
        assert!(!RawConfig::default().leak_test.auto);
    }
}
