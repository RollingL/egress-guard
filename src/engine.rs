//! 后台引擎：在独立线程中运行事件循环（定时检测、网络变化、配置变更、退出）。
//! 命令行和图形界面共用。

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};

use crate::config::Config;
use crate::controller::{Controller, DryRunFirewall, Firewall};
use crate::discovery::{self, ExtraApp, WatchSettings};
use crate::egress::EgressDetector;
use crate::logbuf;

/// 发给引擎的事件。
pub enum Event {
    /// 网卡/地址/路由发生变化。
    NetworkChanged,
    /// 立即检测一次出口 IP。
    CheckNow,
    /// 应用新配置。
    Reconfigure(Config),
    /// 退出（关闭 WFP 会话，规则随之移除）。
    Shutdown,
    /// 内部：检测线程返回结果。
    Detected { generation: u64, result: Result<IpAddr> },
    /// 内部：自动识别到的关联程序发生变化。
    ExtraApps(Vec<ExtraApp>),
    /// 清空子进程识别记录。
    ClearLearned,
}

/// 引擎对外报告的状态快照。
#[derive(Debug, Clone, Default)]
pub struct Status {
    /// 最近一次检测到的出口 IP。
    pub egress_ip: Option<IpAddr>,
    /// 该 IP 是否命中白名单。
    pub whitelisted: Option<bool>,
    /// 受控应用当前是否被阻断。
    pub blocked: bool,
    /// 是否正在检测。
    pub checking: bool,
    /// 上次检测完成时间（本地 HH:MM:SS）。
    pub last_check: Option<String>,
    /// 最近一次检测失败的原因。
    pub detect_error: Option<String>,
    /// 连续失败次数。
    pub failures: u32,
    /// 拦截后端不可用的原因（此时为模拟模式，规则未真正生效）。
    pub backend_error: Option<String>,
    /// 模拟模式（--dry-run 或 WFP 打开失败）。
    pub simulated: bool,
    /// 引擎是否在运行。
    pub running: bool,
    /// 自动识别到、一并阻断的关联程序。
    pub extra_apps: Vec<ExtraApp>,
}

pub type Reporter = Arc<dyn Fn(&Status) + Send + Sync>;

pub struct EngineHandle {
    tx: Sender<Event>,
    join: Mutex<Option<JoinHandle<Result<()>>>>,
}

impl EngineHandle {
    pub fn send(&self, e: Event) {
        let _ = self.tx.send(e);
    }

    pub fn sender(&self) -> Sender<Event> {
        self.tx.clone()
    }

    /// 通知引擎退出并等待其结束，返回引擎的运行结果。
    pub fn shutdown(&self) -> Result<()> {
        let _ = self.tx.send(Event::Shutdown);
        self.join()
    }

    /// 等待引擎线程结束。
    pub fn join(&self) -> Result<()> {
        match self.join.lock().unwrap().take() {
            Some(h) => h.join().map_err(|_| anyhow!("引擎线程异常退出"))?,
            None => Ok(()),
        }
    }
}

/// 启动引擎线程。
///
/// - `dry_run`：只模拟，不修改网络。
/// - `strict`：WFP 打开失败时直接报错退出（命令行用）；否则降级为模拟模式并在状态中报告（界面用）。
/// - `learned_file`：子进程识别记录的保存位置（通常在配置文件旁）。
pub fn spawn(
    cfg: Config,
    dry_run: bool,
    strict: bool,
    learned_file: Option<PathBuf>,
    reporter: Reporter,
) -> EngineHandle {
    let (tx, rx) = mpsc::channel();
    let loop_tx = tx.clone();
    let join = std::thread::Builder::new()
        .name("engine".into())
        .spawn(move || run(cfg, dry_run, strict, learned_file, loop_tx, rx, reporter))
        .expect("无法创建引擎线程");
    EngineHandle { tx, join: Mutex::new(Some(join)) }
}

fn run(
    cfg: Config,
    dry_run: bool,
    strict: bool,
    learned_file: Option<PathBuf>,
    tx: Sender<Event>,
    rx: Receiver<Event>,
    reporter: Reporter,
) -> Result<()> {
    let mut status = Status { running: true, ..Default::default() };

    // 网卡变化监听（仅 Windows），需在整个循环期间保持存活
    #[cfg(windows)]
    let _watcher = match crate::win::netwatch::NetWatcher::start(tx.clone()) {
        Ok(w) => Some(w),
        Err(e) => {
            log::warn!("网卡变化监听启动失败，仅使用定时检测: {e:#}");
            None
        }
    };
    #[cfg(not(windows))]
    log::warn!("非 Windows 平台：不监听网卡变化，仅定时检测");

    let fw: Box<dyn Firewall> = if dry_run {
        status.simulated = true;
        Box::new(DryRunFirewall::default())
    } else {
        match open_backend(&cfg) {
            Ok(fw) => fw,
            Err(e) if strict => {
                status.running = false;
                reporter(&status);
                return Err(e);
            }
            Err(e) => {
                log::error!("拦截引擎不可用，进入模拟模式: {e:#}");
                status.simulated = true;
                status.backend_error = Some(format!("{e:#}"));
                Box::new(DryRunFirewall::default())
            }
        }
    };

    log::info!(
        "引擎启动：受控应用 {} 个，白名单 {} 条，检测间隔 {}s{}",
        cfg.apps.len(),
        cfg.whitelist.len(),
        cfg.detect.interval_secs,
        if status.simulated { "（模拟模式）" } else { "" }
    );

    let mut ctrl = Controller::new(cfg.clone(), fw);

    // 关联程序识别：先同步载入已知的，再启动后台线程持续识别
    let windir = std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".into());
    let mut watch_version = 0u64;
    let watch = Arc::new(Mutex::new(WatchSettings::from_config(&cfg, watch_version)));
    let initial = discovery::initial_extra(&watch.lock().unwrap(), learned_file.clone(), &windir);
    if !initial.is_empty() {
        log::info!("载入 {} 个已识别的关联程序", initial.len());
    }
    if let Err(e) = ctrl.set_extra(initial.iter().map(|x| x.path.clone()).collect()) {
        log::error!("{e:#}");
    }
    status.extra_apps = initial;
    discovery::spawn(watch.clone(), learned_file, snapshot_fn(), windir, tx.clone());

    if cfg.behavior.start_blocked {
        log::info!("启动时先阻断，等待首次出口 IP 检测");
        if let Err(e) = ctrl.firewall().block() {
            log::error!("{e:#}");
        }
    }

    let mut detector = Arc::new(make_detector(&cfg));
    let mut generation: u64 = 0;
    let mut checking = false;
    let mut next_check: Option<Instant> = Some(Instant::now());
    let mut debounce_until: Option<Instant> = None;
    let mut after_change = false;

    let start_check = |checking: &mut bool, detector: &Arc<EgressDetector>, generation: u64| {
        if *checking {
            return;
        }
        *checking = true;
        let det = detector.clone();
        let tx = tx.clone();
        std::thread::spawn(move || {
            let result = det.detect();
            let _ = tx.send(Event::Detected { generation, result });
        });
    };

    update_status(&mut status, &ctrl, checking);
    reporter(&status);

    loop {
        let deadline = [next_check, debounce_until].into_iter().flatten().min();
        let event = match deadline {
            Some(d) => rx.recv_timeout(d.saturating_duration_since(Instant::now())),
            None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };

        match event {
            Ok(Event::Shutdown) | Err(RecvTimeoutError::Disconnected) => break,
            Ok(Event::NetworkChanged) => {
                if debounce_until.is_none() {
                    if let Err(e) = ctrl.on_network_change() {
                        log::error!("{e:#}");
                    }
                }
                // 正在进行的检测结果作废；等网络安静下来再检测
                generation += 1;
                debounce_until =
                    Some(Instant::now() + Duration::from_millis(ctrl.config().behavior.debounce_ms));
                next_check = None;
            }
            Ok(Event::CheckNow) => {
                log::info!("手动触发检测");
                next_check = None;
                start_check(&mut checking, &detector, generation);
            }
            Ok(Event::Reconfigure(new_cfg)) => {
                log::info!(
                    "应用新配置：受控应用 {} 个，白名单 {} 条",
                    new_cfg.apps.len(),
                    new_cfg.whitelist.len()
                );
                detector = Arc::new(make_detector(&new_cfg));
                watch_version += 1;
                {
                    let mut w = watch.lock().unwrap();
                    let clear = w.clear_learned;
                    *w = WatchSettings::from_config(&new_cfg, watch_version);
                    w.clear_learned = clear;
                }
                if let Err(e) = ctrl.reconfigure(new_cfg) {
                    log::error!("应用新配置失败: {e:#}");
                }
                generation += 1;
                next_check = None;
                start_check(&mut checking, &detector, generation);
            }
            Ok(Event::ExtraApps(extra)) => {
                log::info!("关联程序更新：共 {} 个", extra.len());
                if let Err(e) = ctrl.set_extra(extra.iter().map(|x| x.path.clone()).collect()) {
                    log::error!("更新关联程序的阻断规则失败: {e:#}");
                }
                status.extra_apps = extra;
            }
            Ok(Event::ClearLearned) => {
                watch.lock().unwrap().clear_learned = true;
            }
            Ok(Event::Detected { generation: g, result }) => {
                checking = false;
                if g == generation {
                    if let Err(e) = ctrl.on_detection(result) {
                        log::error!("{e:#}");
                    }
                    status.last_check = Some(logbuf::now_hms());
                    let interval = Duration::from_secs(ctrl.config().detect.interval_secs);
                    // 网络变化后的下一次检测提前，以便 VPN 等慢速连接建立后尽快放行
                    let wait = if after_change { interval.min(Duration::from_secs(15)) } else { interval };
                    after_change = false;
                    if debounce_until.is_none() {
                        next_check = Some(Instant::now() + wait);
                    }
                } else if debounce_until.is_none() {
                    // 检测期间网络或配置变了，结果作废，立刻重测
                    log::debug!("丢弃过期的检测结果");
                    start_check(&mut checking, &detector, generation);
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                let now = Instant::now();
                if debounce_until.is_some_and(|d| d <= now) {
                    debounce_until = None;
                    after_change = true;
                    log::info!("网络发生变化，重新检测出口 IP");
                    start_check(&mut checking, &detector, generation);
                }
                if next_check.is_some_and(|d| d <= now) {
                    next_check = None;
                    start_check(&mut checking, &detector, generation);
                }
            }
        }

        update_status(&mut status, &ctrl, checking);
        reporter(&status);
    }

    log::info!("引擎退出，阻断规则随 WFP 动态会话自动移除");
    drop(ctrl); // 关闭 WFP 会话
    status.running = false;
    status.checking = false;
    status.blocked = false;
    reporter(&status);
    Ok(())
}

fn update_status(s: &mut Status, ctrl: &Controller, checking: bool) {
    s.egress_ip = ctrl.last_ip();
    s.whitelisted = ctrl.last_ip().map(|ip| ctrl.config().is_whitelisted(ip));
    s.blocked = ctrl.is_blocked();
    s.checking = checking;
    s.detect_error = ctrl.last_error().map(str::to_owned);
    s.failures = ctrl.failures();
}

fn make_detector(cfg: &Config) -> EgressDetector {
    EgressDetector::new(cfg.detect.services.clone(), Duration::from_secs(cfg.detect.timeout_secs))
}

#[cfg(windows)]
fn snapshot_fn() -> discovery::SnapshotFn {
    crate::win::procs::snapshot
}

#[cfg(not(windows))]
fn snapshot_fn() -> discovery::SnapshotFn {
    Vec::new
}

#[cfg(windows)]
fn open_backend(cfg: &Config) -> Result<Box<dyn Firewall>> {
    Ok(Box::new(crate::win::wfp::WfpFirewall::open(
        cfg.apps.clone(),
        cfg.behavior.kill_existing_tcp,
    )?))
}

#[cfg(not(windows))]
fn open_backend(_cfg: &Config) -> Result<Box<dyn Firewall>> {
    anyhow::bail!("WFP 只在 Windows 上可用；在其他平台请使用 --dry-run")
}
