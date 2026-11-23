//! 后台引擎：在独立线程中运行事件循环（定时检测、网络变化、配置变更、退出）。
//! 命令行和图形界面共用。

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};

use crate::config::Config;
use crate::controller::{Controller, DryRunFirewall, Egress, Firewall};
use crate::discovery::{self, ExtraApp, WatchSettings};
use crate::egress::Detectors;
use crate::leaktest::ifaces::Adapter;
use crate::{logbuf, vpn};

/// 阻断规则同步失败后的重试间隔。
const RETRY_INTERVAL: Duration = Duration::from_secs(5);

/// 发给引擎的事件。
pub enum Event {
    /// 网卡/地址/路由发生变化。
    NetworkChanged,
    /// 立即检测一次出口 IP。
    CheckNow,
    /// 应用新配置。
    /// 应用新配置；第二项是保存时分配的配置版本（单调递增），应用后写入 [`Status::config_version`]。
    Reconfigure(Box<Config>, u64),
    /// 退出（移除全部阻断规则）。
    Shutdown,
    /// 内部：检测线程返回结果。
    Detected { generation: u64, result: Result<Egress> },
    /// 内部：网卡发生变化（VPN 守护用）。
    Adapters(Vec<Adapter>),
    /// 内部：自动识别到的关联程序发生变化。
    ExtraApps(Vec<ExtraApp>),
    /// 清空子进程识别记录。
    ClearLearned,
    /// 只刷新状态（例如 macOS 网络扩展连上或断开）。
    Refresh,
}

/// 引擎对外报告的状态快照。macOS 上由后台服务通过本地套接字发给界面。
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct Status {
    /// 最近一次检测到的出口 IP。
    pub egress_ip: Option<IpAddr>,
    /// 该 IP 是否命中白名单。
    pub whitelisted: Option<bool>,
    /// 与出口 IP 不同的 IPv6 出口（检测 IPv6 出口、且本机能直连 IPv6 时）。
    pub egress_v6: Option<IpAddr>,
    /// IPv6 出口是否命中白名单。
    pub v6_whitelisted: Option<bool>,
    /// 当前是否处于阻断状态。
    pub blocked: bool,
    /// 阻断的原因（阻断时）。
    pub block_reason: Option<String>,
    /// 现在连着的 VPN 网卡。
    pub vpn_connected: Vec<String>,
    /// 放行时记下、正在守护的 VPN 网卡：任何一块断开就立即阻断。
    pub vpn_guarded: Vec<String>,
    /// 阻断范围是全部网络（全局断网已开启）。
    pub block_all: bool,
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
    /// 上一次阻断/放行没能生效的原因（正在每 5 秒重试）。
    pub apply_error: Option<String>,
    /// 拦截后端的其他问题（例如 macOS 网络扩展版本太旧，不支持当前设置）。
    pub degraded: Option<String>,
    /// 保护范围的已知限制（不是故障）：例如 macOS 没有网络扩展时，全局断网的例外对受控应用同样放行。
    pub limitation: Option<String>,
    /// 网络 / 配置代次：网络变化、VPN 网卡增减、应用新配置时加一。界面的后台任务据此丢弃过期的结果。
    pub generation: u64,
    /// 最近一次检测结果所属的代次（这一代上真正测过出口）。与 `generation` 不同时，
    /// 上面的出口 IP 只是上一代的结果，可以显示，但自动诊断等不能据此认为当前网络已经验证。
    /// 旧版本的服务没有这一项（None）。
    pub verified_generation: Option<u64>,
    /// 模拟模式（--dry-run 或拦截后端打开失败）。
    pub simulated: bool,
    /// 拦截后端现在能否按应用阻断（macOS 需要网络扩展已连接；否则只有 pf 全局断网）。
    pub per_app: bool,
    /// 已连接的 macOS 网络扩展的版本。
    pub filter_ext: Option<String>,
    /// 引擎是否在运行。
    pub running: bool,
    /// 自动识别到、一并阻断的关联程序。
    pub extra_apps: Vec<ExtraApp>,
    /// 引擎已经处理到的配置版本（界面保存后据此判断规则是否已应用）。
    pub config_version: u64,
    /// 应用这个版本的配置时出错（配置已保存，但规则没有按它更新）。
    pub config_apply_error: Option<String>,
}

pub type Reporter = Arc<dyn Fn(&Status) + Send + Sync>;

/// 网卡变化监听用的通知端：一批连续的系统通知只给引擎发一个 [`Event::NetworkChanged`]。
///
/// 第一个通知立即发出（不推迟阻断）；引擎取到这个事件、开始处理之前清掉标志，
/// 处理期间再来的通知会再发一个，所以不会漏掉最后一次变化。
#[derive(Clone)]
pub struct NetNotifier {
    tx: Sender<Event>,
    pending: Arc<AtomicBool>,
}

impl NetNotifier {
    pub fn new(tx: Sender<Event>) -> Self {
        Self { tx, pending: Arc::new(AtomicBool::new(false)) }
    }

    /// 报告一次网络变化。引擎已经退出时返回 false。
    pub fn notify(&self) -> bool {
        if self.pending.swap(true, Ordering::AcqRel) {
            return true;
        }
        self.tx.send(Event::NetworkChanged).is_ok()
    }

    /// 引擎开始处理网络变化：之后的通知要再发一次。
    pub fn taken(&self) {
        self.pending.store(false, Ordering::Release);
    }
}

pub struct EngineHandle {
    tx: Sender<Event>,
    join: Mutex<Option<JoinHandle<Result<()>>>>,
}

impl EngineHandle {
    pub fn send(&self, e: Event) {
        let _ = self.tx.send(e);
    }

    /// 发送事件；引擎已经停止时返回错误。
    pub fn try_send(&self, e: Event) -> Result<()> {
        self.tx.send(e).map_err(|_| anyhow!("引擎已经停止"))
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
    let mut status = Status { running: true, per_app: true, ..Default::default() };

    // 网卡变化监听，需在整个循环期间保持存活；注册失败时稍后重试（见下面的 recover）
    let net = NetNotifier::new(tx.clone());
    let mut watcher = start_netwatch(net.clone());
    // VPN 守护：定时检查网卡（变化通知之外的兜底，也覆盖「网络变化时先阻断」关闭的情况）。
    // 通过 VPN 放行时每 0.25 秒一次，其余时候每 2 秒；引擎退出时 vpn_watch 被丢弃，线程随之结束
    let vpn_watch = vpn::spawn_engine_watch(tx.clone());
    let mut adapters: Vec<Adapter> = vpn::scan().unwrap_or_default();
    // 守护中的 VPN 网卡（名称 + 稳定标识）与上一次看到的 VPN 网卡（含地址，用来发现同名换址）
    let mut guarded: Vec<vpn::Link> = Vec::new();
    let mut vpn_links: Vec<vpn::Link> = vpn::links(&adapters, &cfg.vpn);

    let fw: Box<dyn Firewall> = if dry_run {
        status.simulated = true;
        Box::new(DryRunFirewall::default())
    } else {
        match open_backend(&cfg, tx.clone()) {
            Ok(fw) => fw,
            Err(e) if strict => {
                status.running = false;
                reporter(&status);
                return Err(e);
            }
            Err(e) => {
                log::error!("拦截引擎不可用，暂时进入模拟模式，稍后重试: {e:#}");
                status.simulated = true;
                status.backend_error = Some(format!("{e:#}"));
                // 启动时先阻断的设置照样记下，后端恢复时按它提交
                Box::new(DryRunFirewall::default())
            }
        }
    };

    log::info!(
        "引擎启动：受控应用 {} 个，白名单 {} 条，检测间隔 {}s{}{}",
        cfg.apps.len(),
        cfg.whitelist.len(),
        cfg.detect.interval_secs,
        if cfg.block_all.enabled { "，不在白名单时切断全部网络" } else { "" },
        if status.simulated { "（模拟模式）" } else { "" }
    );

    let mut ctrl = Controller::new(cfg.clone(), fw);
    if let Err(e) = ctrl.apply_rules() {
        log::error!("{e:#}");
    }

    // 先阻断配置的受控应用，再载入关联程序，避免启动扫描期间出现放行空档
    if cfg.behavior.start_blocked {
        if let Err(e) = ctrl.block_for("启动时先阻断，等待首次检测出口 IP") {
            log::error!("{e:#}");
        }
    }

    // 关联程序识别：先同步载入已知的，再启动后台线程持续识别
    let system_dirs = discovery::default_system_dirs();
    let mut watch_version = 0u64;
    let watch = Arc::new(Mutex::new(WatchSettings::from_config(&cfg, watch_version)));
    let initial = discovery::initial_extra(&watch.lock().unwrap(), learned_file.clone(), &system_dirs);
    if !initial.is_empty() {
        log::info!("载入 {} 个已识别的关联程序", initial.len());
    }
    if let Err(e) = ctrl.set_extra(initial.iter().map(|x| x.path.clone()).collect()) {
        log::error!("{e:#}");
    }
    status.extra_apps = initial;
    discovery::spawn(watch.clone(), learned_file, snapshot_fn(), system_dirs, tx.clone());

    let mut detector = Arc::new(make_detector(&cfg));
    let mut generation: u64 = 0;
    let mut checking = false;
    let mut next_check: Option<Instant> = Some(Instant::now());
    let mut debounce_until: Option<Instant> = None;
    // 这一轮网络变化开始的时刻：变化一直不停时，防抖最多推迟到这之后 MAX_SETTLE
    let mut change_started: Option<Instant> = None;
    let mut after_change = false;
    // 规则同步失败或有程序暂未加上规则时，定时重试
    let mut next_retry: Option<Instant> = None;
    // 拦截后端打开失败（不是用户要求的模拟）、网卡变化监听注册失败时，按退避间隔重新尝试
    let mut backend_retry = Backoff::new(!dry_run && status.simulated && cfg!(any(windows, target_os = "macos")));
    let mut watch_retry = Backoff::new(watcher.is_none() && cfg!(any(windows, target_os = "macos")));

    let start_check = |checking: &mut bool, detector: &Arc<Detectors>, generation: u64| {
        if *checking {
            return;
        }
        *checking = true;
        let det = detector.clone();
        let tx = tx.clone();
        std::thread::spawn(move || {
            // 检测里出现 panic 也要回报结果，否则 checking 一直为真，之后再也不会检测
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| det.detect()))
                .unwrap_or_else(|_| Err(anyhow!("检测线程异常退出")));
            let _ = tx.send(Event::Detected { generation, result });
        });
    };

    // VPN 守护中的网卡断开时立即阻断。返回是否因此阻断了
    macro_rules! check_vpn {
        () => {{
            let cfg_vpn = &ctrl.config().vpn;
            vpn_links = vpn::links(&adapters, cfg_vpn);
            status.vpn_connected = vpn::names(&vpn_links);
            let mut blocked_now = false;
            if ctrl.wants_block() || !cfg_vpn.guard {
                guarded.clear();
            } else {
                let lost = vpn::lost(&guarded, &vpn_links);
                if !lost.is_empty() {
                    let reason = format!("VPN 断开（{}）", lost.join("、"));
                    // 阻断失败时控制器记着目标和原因，每 5 秒重试，直到生效或被新的检测结果取代
                    if let Err(e) = ctrl.block_for(reason) {
                        log::error!("{e:#}");
                    }
                    guarded.clear();
                    blocked_now = true;
                }
            }
            blocked_now
        }};
    }

    update_status(&mut status, &ctrl, checking);
    status.vpn_connected = vpn::names(&vpn_links);
    reporter(&status);
    // 上一次报告的状态：没有变化时不再报告（每个事件、每次定时器到期都会走一遍循环）
    let mut reported = status.clone();

    loop {
        if ctrl.needs_retry() {
            next_retry.get_or_insert_with(|| later(RETRY_INTERVAL));
        } else {
            next_retry = None;
        }
        let deadline =
            [next_check, debounce_until, next_retry, backend_retry.at, watch_retry.at].into_iter().flatten().min();
        let event = match deadline {
            Some(d) => rx.recv_timeout(d.saturating_duration_since(Instant::now())),
            None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };

        match event {
            Ok(Event::Shutdown) | Err(RecvTimeoutError::Disconnected) => break,
            Ok(Event::NetworkChanged) => {
                net.taken();
                // 先看是不是守护中的 VPN 断了（原因更明确，也不受「网络变化时先阻断」开关影响）
                // 列不出网卡时沿用上一次的结果（不当作全部断开）
                if let Some(a) = vpn::scan() {
                    adapters = a;
                }
                let vpn_blocked = check_vpn!();
                // 每次网络变化都作废之前的出口（包括还没生效的放行），并按设置先行阻断；
                // 防抖只合并之后的检测。防抖期间手动检测或改配置已经放行时，新的变化同样先阻断
                if !vpn_blocked {
                    if let Err(e) = ctrl.on_network_change() {
                        log::error!("{e:#}");
                    }
                }
                // 正在进行的检测结果作废；等网络安静下来再检测
                generation += 1;
                let now = Instant::now();
                let started = *change_started.get_or_insert(now);
                debounce_until = Some(settle_deadline(now, started, Duration::from_millis(ctrl.config().behavior.debounce_ms)));
                next_check = None;
            }
            Ok(Event::CheckNow) => {
                log::info!("手动触发检测");
                next_check = None;
                start_check(&mut checking, &detector, generation);
            }
            Ok(Event::Reconfigure(new_cfg, version)) => {
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
                status.config_version = version;
                status.config_apply_error = match ctrl.reconfigure(*new_cfg) {
                    Ok(()) => None,
                    Err(e) => {
                        log::error!("应用新配置失败: {e:#}");
                        Some(format!("{e:#}"))
                    }
                };
                // 守护的网卡设置可能变了：不再算 VPN 的网卡不再守护（而不是当作断开）
                vpn_links = vpn::links(&adapters, &ctrl.config().vpn);
                status.vpn_connected = vpn::names(&vpn_links);
                if !ctrl.config().vpn.guard {
                    guarded.clear();
                }
                guarded.retain(|g| vpn_links.iter().any(|l| l.same(g)));
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
            Ok(Event::Adapters(a)) => {
                adapters = a;
                let before = vpn_links.clone();
                // VPN 网卡有增减、被重建或换了地址时（包括阻断期间），正在进行的检测可能是在旧网络上测的，一律作废；
                // 之前的出口也作废（还没生效的放行取消），但不先行阻断：是否先阻断仍由「网络变化时先阻断」和系统的网络变化通知决定
                let vpn_blocked = check_vpn!();
                if vpn_blocked || vpn_links != before {
                    ctrl.invalidate();
                    // 等网络安静下来再重新检测（VPN 可能正在重连）
                    generation += 1;
                    next_check = None;
                    change_started.get_or_insert_with(Instant::now);
                    debounce_until.get_or_insert_with(|| later(Duration::from_millis(ctrl.config().behavior.debounce_ms)));
                }
            }
            Ok(Event::Refresh) => {}
            Ok(Event::Detected { generation: g, result }) => {
                checking = false;
                if g == generation {
                    let ok = result.is_ok();
                    if let Err(e) = ctrl.on_detection(result) {
                        log::error!("{e:#}");
                    }
                    status.verified_generation = if ok { Some(generation) } else { None };
                    status.last_check = Some(logbuf::now_hms());
                    // 放行时记下正在使用的 VPN 网卡，之后它一断开就立即阻断
                    let vcfg = &ctrl.config().vpn;
                    guarded = if !ctrl.is_blocked() && vcfg.guard { vpn::links(&adapters, vcfg) } else { Vec::new() };
                    if !guarded.is_empty() && status.vpn_guarded != vpn::names(&guarded) {
                        log::info!("VPN 守护：{}", vpn::names(&guarded).join("、"));
                    }
                    let mut interval = Duration::from_secs(ctrl.config().detect.interval_secs);
                    // 通过 VPN 放行期间检测得更勤：VPN 服务器那一侧换了出口、本机网卡又没有变化时也能尽快发现
                    if !guarded.is_empty() && vcfg.check_interval_secs > 0 {
                        interval = interval.min(Duration::from_secs(vcfg.check_interval_secs));
                    }
                    // 网络变化后的下一次检测提前，以便 VPN 等慢速连接建立后尽快放行
                    let wait = if after_change { interval.min(Duration::from_secs(15)) } else { interval };
                    after_change = false;
                    if debounce_until.is_none() {
                        next_check = Some(later(wait));
                    }
                } else if debounce_until.is_none() {
                    // 检测期间网络或配置变了，结果作废，立刻重测
                    log::debug!("丢弃过期的检测结果");
                    start_check(&mut checking, &detector, generation);
                }
            }
            // 到期的定时任务在下面统一处理：持续有事件时也照样按时执行
            Err(RecvTimeoutError::Timeout) => {}
        }

        // 到期的定时任务（防抖后的检测、定时检测、后端恢复、监听恢复、规则重试）。每处理一个事件之后都检查一次，
        // 而不只在等待超时时：网卡事件、刷新持续不断时，它们也不会被一直推迟
        {
            let now = Instant::now();
            if debounce_until.is_some_and(|d| d <= now) {
                debounce_until = None;
                change_started = None;
                after_change = true;
                log::info!("网络发生变化，重新检测出口 IP");
                start_check(&mut checking, &detector, generation);
            }
            if next_check.is_some_and(|d| d <= now) {
                next_check = None;
                start_check(&mut checking, &detector, generation);
            }
            if backend_retry.due(now) {
                match open_backend(ctrl.config(), tx.clone()) {
                    Ok(fw) => {
                        backend_retry.done();
                        log::info!("拦截引擎已恢复，退出模拟模式");
                        status.simulated = false;
                        status.backend_error = None;
                        if let Err(e) = ctrl.replace_firewall(fw) {
                            log::error!("{e:#}");
                        }
                        // 模拟期间的检测不算数：重新检测
                        generation += 1;
                        next_check = None;
                        start_check(&mut checking, &detector, generation);
                    }
                    Err(e) => {
                        let wait = backend_retry.failed();
                        log::warn!("拦截引擎仍不可用，{} 秒后再试: {e:#}", wait.as_secs());
                        status.backend_error = Some(format!("{e:#}"));
                    }
                }
            }
            if watch_retry.due(now) {
                watcher = start_netwatch(net.clone());
                if watcher.is_some() {
                    watch_retry.done();
                    log::info!("网卡变化监听已恢复");
                    // 监听中断期间可能错过了变化：按网络变化处理
                    let _ = tx.send(Event::NetworkChanged);
                } else {
                    watch_retry.failed();
                }
            }
            if next_retry.is_some_and(|d| d <= now) {
                next_retry = None;
                let was_blocked = ctrl.is_blocked();
                match ctrl.retry_pending() {
                    Err(e) => log::warn!("重试同步阻断规则失败，稍后再试: {e:#}"),
                    // 应用新配置时没完成的部分已经重试成功：这一版配置现在生效了
                    Ok(()) if !ctrl.needs_retry() && status.config_apply_error.take().is_some() => {
                        log::info!("配置（版本 {}）已生效", status.config_version);
                    }
                    Ok(()) => {}
                }
                // 重试让放行生效了：与检测后直接放行一样，开始守护正在使用的 VPN 网卡、按守护间隔检测
                if was_blocked && !ctrl.is_blocked() {
                    let vcfg = &ctrl.config().vpn;
                    guarded = if vcfg.guard { vpn::links(&adapters, vcfg) } else { Vec::new() };
                    if !guarded.is_empty() {
                        log::info!("VPN 守护：{}", vpn::names(&guarded).join("、"));
                        if vcfg.check_interval_secs > 0 && debounce_until.is_none() {
                            let soon = later(Duration::from_secs(vcfg.check_interval_secs));
                            next_check = Some(next_check.map_or(soon, |n| n.min(soon)));
                        }
                    }
                }
            }
        }

        if ctrl.wants_block() {
            guarded.clear();
        }
        status.vpn_guarded = vpn::names(&guarded);
        status.generation = generation;
        vpn_watch.set_active(!guarded.is_empty());
        update_status(&mut status, &ctrl, checking);
        if status != reported {
            reporter(&status);
            reported.clone_from(&status);
        }
    }

    log::info!("引擎退出，移除阻断规则");
    drop(ctrl); // 关闭 WFP 会话 / 清空 pf 规则
    status.running = false;
    status.checking = false;
    status.blocked = false;
    reporter(&status);
    Ok(())
}

/// 从现在起过 `d` 之后的时刻；`d` 大到超出时钟范围时取一个很远的时刻，而不是让引擎线程 panic
/// （引擎退出会移除全部阻断规则）。
fn later(d: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(d).or_else(|| now.checked_add(Duration::from_secs(10 * 365 * 86400))).unwrap_or(now)
}

/// 防抖的截止时刻：每次变化都从现在起再等 `debounce`，但从这一轮变化开始算最多等 [`max_settle`]。
/// 网络一直抖动（例如每 1.5 秒一次通知、防抖 2 秒）时，检测不会被无限期推迟，阻断也不会一直不解除。
fn settle_deadline(now: Instant, started: Instant, debounce: Duration) -> Instant {
    let cap = started.checked_add(max_settle(debounce)).unwrap_or(now);
    now.checked_add(debounce).map_or(cap, |d| d.min(cap)).max(now)
}

/// 一轮网络变化最多等多久就检测一次：防抖的 5 倍，至少 10 秒。
fn max_settle(debounce: Duration) -> Duration {
    debounce.saturating_mul(5).max(Duration::from_secs(10))
}

/// 有上限的指数退避：5 秒起，每次失败加倍，最多 5 分钟。
struct Backoff {
    at: Option<Instant>,
    delay: Duration,
}

impl Backoff {
    const FIRST: Duration = Duration::from_secs(5);
    const MAX: Duration = Duration::from_secs(300);

    fn new(active: bool) -> Self {
        Self { at: active.then(|| later(Self::FIRST)), delay: Self::FIRST }
    }

    fn due(&self, now: Instant) -> bool {
        self.at.is_some_and(|t| t <= now)
    }

    /// 又失败了一次：返回下次重试前等待的时间。
    fn failed(&mut self) -> Duration {
        self.delay = (self.delay * 2).min(Self::MAX);
        self.at = Some(later(self.delay));
        self.delay
    }

    fn done(&mut self) {
        self.at = None;
        self.delay = Self::FIRST;
    }
}

fn update_status(s: &mut Status, ctrl: &Controller, checking: bool) {
    s.egress_ip = ctrl.last_ip();
    s.whitelisted = ctrl.last_ip().map(|ip| ctrl.config().is_whitelisted(ip));
    s.egress_v6 = ctrl.last_v6();
    s.v6_whitelisted = ctrl.last_v6().map(|ip| ctrl.config().is_whitelisted(ip));
    s.blocked = ctrl.is_blocked();
    s.block_reason = ctrl.block_reason().map(str::to_owned);
    s.per_app = ctrl.per_app();
    s.filter_ext = ctrl.extension();
    s.block_all = ctrl.config().block_all.enabled;
    s.checking = checking;
    s.detect_error = ctrl.last_error().map(str::to_owned);
    s.failures = ctrl.failures();
    s.apply_error = ctrl.apply_error().map(str::to_owned);
    s.degraded = ctrl.degraded();
    s.limitation = ctrl.limitation();
}

fn make_detector(cfg: &Config) -> Detectors {
    Detectors::new(cfg)
}

/// 网卡/地址/路由变化监听；返回值需保持存活。
fn start_netwatch(net: NetNotifier) -> Option<Box<dyn std::any::Any>> {
    #[cfg(windows)]
    let r = crate::win::netwatch::NetWatcher::start(net).map(|w| Box::new(w) as Box<dyn std::any::Any>);
    #[cfg(target_os = "macos")]
    let r = crate::mac::netwatch::start(net).map(|w| Box::new(w) as Box<dyn std::any::Any>);
    #[cfg(not(any(windows, target_os = "macos")))]
    let r: Result<Box<dyn std::any::Any>> = {
        let _ = net;
        Err(anyhow!("此平台不支持"))
    };
    match r {
        Ok(w) => Some(w),
        Err(e) => {
            log::warn!("网卡变化监听启动失败，仅使用定时检测: {e:#}");
            None
        }
    }
}

#[cfg(windows)]
fn snapshot_fn() -> discovery::SnapshotFn {
    crate::win::procs::snapshot
}

#[cfg(target_os = "macos")]
fn snapshot_fn() -> discovery::SnapshotFn {
    crate::mac::procs::snapshot
}

#[cfg(not(any(windows, target_os = "macos")))]
fn snapshot_fn() -> discovery::SnapshotFn {
    Vec::new
}

#[cfg(windows)]
fn open_backend(cfg: &Config, tx: Sender<Event>) -> Result<Box<dyn Firewall>> {
    let _ = (cfg, tx);
    Ok(Box::new(crate::win::wfp::open()?))
}

/// macOS：pf 负责全局断网，网络扩展（连上后）负责按应用阻断。
#[cfg(target_os = "macos")]
fn open_backend(cfg: &Config, tx: Sender<Event>) -> Result<Box<dyn Firewall>> {
    Ok(Box::new(crate::mac::firewall::MacFirewall::open(tx, cfg.behavior.start_blocked)?))
}

#[cfg(not(any(windows, target_os = "macos")))]
fn open_backend(_cfg: &Config, _tx: Sender<Event>) -> Result<Box<dyn Firewall>> {
    anyhow::bail!("只支持 Windows（WFP）和 macOS（pf）；在其他平台请使用 --dry-run")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 一批通知只发一个事件；引擎开始处理之后再来的通知会再发一个。
    #[test]
    fn net_notifier_coalesces_bursts_but_keeps_trailing_change() {
        let (tx, rx) = mpsc::channel();
        let n = NetNotifier::new(tx);
        for _ in 0..30 {
            assert!(n.notify());
        }
        assert!(matches!(rx.try_recv(), Ok(Event::NetworkChanged)));
        assert!(rx.try_recv().is_err());
        n.taken();
        assert!(n.notify() && n.notify());
        assert!(matches!(rx.try_recv(), Ok(Event::NetworkChanged)));
        assert!(rx.try_recv().is_err());
        drop(rx);
        n.taken();
        assert!(!n.notify(), "引擎已退出");
    }

    #[test]
    fn settle_deadline_slides_but_is_capped() {
        let t0 = Instant::now();
        let d = Duration::from_secs(2);
        // 第一个通知：等满防抖
        assert_eq!(settle_deadline(t0, t0, d), t0 + d);
        // 之后的通知继续往后推
        let t = t0 + Duration::from_millis(1500);
        assert_eq!(settle_deadline(t, t0, d), t + d);
        // 推到上限（10 秒）为止
        let t = t0 + Duration::from_secs(9);
        assert_eq!(settle_deadline(t, t0, d), t0 + Duration::from_secs(10));
        // 已经过了上限：立刻检测
        let t = t0 + Duration::from_secs(12);
        assert_eq!(settle_deadline(t, t0, d), t);
        // 防抖很长时上限是它的 5 倍
        assert_eq!(max_settle(Duration::from_secs(5)), Duration::from_secs(25));
        assert_eq!(max_settle(Duration::ZERO), Duration::from_secs(10));
    }
}
