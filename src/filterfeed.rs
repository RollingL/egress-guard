//! 后台服务 → macOS 网络扩展（内容过滤系统扩展）的规则推送。
//!
//! 网络扩展以 root 运行，连接后台服务的本地套接字并发送 `filter_watch`，之后持续收到
//! [`FilterState`]：现在是否阻断、阻断哪些程序。扩展据此对每个新连接放行或丢弃。
//!
//! 与平台无关，便于在 Linux 上测试；只有 macOS 的后端会真正写入状态。

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::controller::{Firewall, Rules};

/// 推送给网络扩展的规则。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct FilterState {
    /// 是否阻断受控应用。
    pub blocked: bool,
    /// 放行期间也逐包检查受控应用的连接，切换为阻断时立即切断已有连接（对应「断开已有连接」）。
    pub inspect_existing: bool,
    /// 要阻断的程序：可执行文件完整路径，或 `.app` 应用包（包内全部程序都算）。
    pub apps: Vec<String>,
    /// 放行期间也阻断受控应用的 IPv6 连接（「始终阻断 IPv6」）。
    pub block_ipv6: bool,
    /// 规则的版本号（发送时填入）。支持 [`CAP_ACK`] 的扩展应用规则后回复 `filter_applied`。
    #[serde(skip_serializing_if = "is_zero")]
    pub rev: u64,
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}

/// 网络扩展支持「始终阻断 IPv6」（0.9.0 起）。
pub const CAP_BLOCK_IPV6: &str = "block_ipv6";
/// 网络扩展应用规则后会回复已应用的规则版本。
pub const CAP_ACK: &str = "ack";
/// 规则更新后等扩展确认的宽限时间，超过仍未确认时在界面上提示。
pub const ACK_GRACE: Duration = Duration::from_secs(3);

/// 网络扩展连接时报告的信息。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct FilterHello {
    /// 网络扩展的版本。
    pub version: String,
    /// 协议版本：0.9.0 及以前的扩展不发（0），之后为 1。
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub protocol: u32,
    /// 支持的功能（见 `CAP_*`）。旧扩展不发，按版本号推断。
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub caps: Vec<String>,
}

fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

/// 已连接的网络扩展。
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ExtInfo {
    pub version: String,
    pub caps: Vec<String>,
    /// 扩展确认已应用的规则版本（不支持确认时为 0）。
    pub applied: u64,
    /// 这个连接实际发出过的最新规则版本：只接受不超过它的确认。
    pub sent: u64,
}

impl ExtInfo {
    pub fn supports(&self, cap: &str) -> bool {
        if self.caps.iter().any(|c| c == cap) {
            return true;
        }
        // 没有能力列表的旧扩展：0.9.0 支持 block_ipv6，但不会确认
        cap == CAP_BLOCK_IPV6 && self.caps.is_empty() && crate::update::is_newer(&self.version, "0.8.99")
    }
}

/// 后台服务运行期间存在的标记文件（套接字旁的 `.running`）。
///
/// launchd 会在有人连接套接字时按需启动服务，所以网络扩展不能靠「连一下试试」判断服务是否在运行：
/// 用户选择「退出并解除阻断」后，扩展只在这个文件重新出现（界面再次打开、开机自启）时才重新连接。
/// 服务崩溃时文件留着，扩展照常重连，launchd 也会重启服务。
pub fn run_marker(socket: &std::path::Path) -> std::path::PathBuf {
    socket.with_extension("running")
}

type Notify = Box<dyn Fn() + Send + Sync>;

/// 最新规则 + 已连接的网络扩展。
#[derive(Default)]
pub struct FilterHub {
    state: Mutex<(u64, FilterState)>,
    /// 当前规则版本是什么时候设置的。
    since: Mutex<Option<std::time::Instant>>,
    cv: Condvar,
    clients: Mutex<HashMap<u64, ExtInfo>>,
    next_id: AtomicU64,
    /// 网络扩展连上或断开时调用（让引擎刷新状态）。
    notify: Mutex<Option<Notify>>,
}

fn version_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    use crate::update::is_newer;
    if is_newer(a, b) {
        std::cmp::Ordering::Greater
    } else if is_newer(b, a) {
        std::cmp::Ordering::Less
    } else {
        a.cmp(b)
    }
}

/// 后台服务进程里唯一的实例。
pub fn hub() -> &'static FilterHub {
    static HUB: OnceLock<FilterHub> = OnceLock::new();
    HUB.get_or_init(FilterHub::default)
}

/// 连接登记；释放时自动注销。
pub struct Registration<'a> {
    hub: &'a FilterHub,
    id: u64,
}

impl Drop for Registration<'_> {
    fn drop(&mut self) {
        self.hub.clients.lock().unwrap().remove(&self.id);
        self.hub.fire();
    }
}

impl FilterHub {
    /// 更新规则；与当前相同则不推送。
    pub fn set(&self, s: FilterState) {
        let mut g = self.state.lock().unwrap();
        if g.0 > 0 && g.1 == s {
            return;
        }
        g.0 += 1;
        g.1 = s;
        *self.since.lock().unwrap() = Some(std::time::Instant::now());
        self.cv.notify_all();
    }

    /// 当前规则的版本号（0 表示引擎还没写入过规则）。
    pub fn version(&self) -> u64 {
        self.state.lock().unwrap().0
    }

    /// 版本 `v` 设置以来过了多久（已经不是当前版本时为 0）。
    pub fn pending_for(&self, v: u64) -> Duration {
        if self.version() != v {
            return Duration::ZERO;
        }
        self.since.lock().unwrap().map(|t| t.elapsed()).unwrap_or_default()
    }

    pub fn current(&self) -> FilterState {
        self.state.lock().unwrap().1.clone()
    }

    /// 等待比 `seen` 更新的规则；超时返回当前规则（用作心跳，及时发现断开的连接）。
    pub fn wait_newer(&self, seen: u64, timeout: Duration) -> (u64, FilterState) {
        let g = self.state.lock().unwrap();
        let (g, _) = self.cv.wait_timeout_while(g, timeout, |(v, _)| *v == seen).unwrap();
        (g.0, g.1.clone())
    }

    pub fn register(&self, hello: FilterHello) -> Registration<'_> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let info = ExtInfo { version: hello.version, caps: hello.caps, applied: 0, sent: 0 };
        self.clients.lock().unwrap().insert(id, info);
        self.fire();
        Registration { hub: self, id }
    }

    /// 版本 `rev` 的规则已经写给这个连接。
    pub fn sent(&self, reg: &Registration<'_>, rev: u64) {
        if let Some(c) = self.clients.lock().unwrap().get_mut(&reg.id) {
            c.sent = c.sent.max(rev);
        }
    }

    /// 扩展确认已应用版本 `rev` 的规则。只接受这个连接确实收到过的版本
    /// （不能确认还没发给它的版本，也不能借别的连接的版本）。
    pub fn applied(&self, reg: &Registration<'_>, rev: u64) {
        let changed = {
            let mut g = self.clients.lock().unwrap();
            match g.get_mut(&reg.id) {
                Some(c) if rev > c.applied && rev <= c.sent => {
                    c.applied = rev;
                    true
                }
                _ => false,
            }
        };
        if changed {
            self.fire();
        }
    }

    /// 已连接网络扩展的版本；没有连接时为 None。
    pub fn connected(&self) -> Option<String> {
        self.connected_hello().map(|h| h.version)
    }

    /// 已连接的网络扩展。系统升级扩展时新旧两个进程可能短暂同时在线，取版本号最大的。
    pub fn connected_hello(&self) -> Option<ExtInfo> {
        let g = self.clients.lock().unwrap();
        g.values().max_by(|a, b| version_cmp(&a.version, &b.version)).cloned()
    }

    pub fn set_notify(&self, f: impl Fn() + Send + Sync + 'static) {
        *self.notify.lock().unwrap() = Some(Box::new(f));
    }

    fn fire(&self) {
        if let Some(f) = &*self.notify.lock().unwrap() {
            f();
        }
    }
}

/// 在另一个后端（macOS 上是 pf，负责全局断网）之外，把按应用阻断的规则推送给网络扩展。
///
/// 网络扩展没有连接时规则照常更新（扩展连上后立即拿到），但 [`Firewall::per_app`] 返回 false，
/// 界面据此提示「按应用断网未生效」。
pub struct FeedFirewall {
    inner: Box<dyn Firewall>,
    hub: &'static FilterHub,
    blocked: bool,
    rules: Rules,
    /// 引擎已经做出过第一次阻断/放行决定。在此之前不推送：扩展保留原来的规则
    /// （服务崩溃重启时是上次的规则，开机时是放行），不会在启动的一瞬间先收到一次「放行」。
    decided: bool,
    warned: bool,
}

impl FeedFirewall {
    pub fn new(inner: Box<dyn Firewall>, hub: &'static FilterHub) -> Self {
        Self { inner, hub, blocked: false, rules: Rules::default(), decided: false, warned: false }
    }

    fn publish(&self) {
        if !self.decided {
            return;
        }
        self.hub.set(FilterState {
            blocked: self.blocked,
            inspect_existing: self.rules.kill_existing_tcp,
            apps: self.rules.apps.iter().map(|p| p.to_string_lossy().into_owned()).collect(),
            block_ipv6: self.rules.block_ipv6,
            rev: 0,
        });
    }

    fn warn_if_inert(&mut self) {
        if self.blocked && !self.rules.apps.is_empty() && self.hub.connected().is_none() && !self.warned {
            self.warned = true;
            log::warn!("网络扩展没有连接，受控应用不会被断网（全局断网不受影响）");
        }
    }
}

impl Firewall for FeedFirewall {
    fn block(&mut self) -> Result<()> {
        // 先通知扩展（只是内存里的一次更新），再改 pf
        self.blocked = true;
        self.decided = true;
        self.publish();
        self.warn_if_inert();
        self.inner.block()
    }

    fn unblock(&mut self) -> Result<()> {
        self.blocked = false;
        self.decided = true;
        self.publish();
        self.inner.unblock()
    }

    /// 扩展和 pf 都已经阻断才算阻断（pf 没装上时控制器会重试，界面显示「阻断未生效」）。
    fn is_blocked(&self) -> bool {
        self.blocked && self.inner.is_blocked()
    }

    /// 还没有向扩展发过规则：第一次决定是「放行」时也要发，扩展才能拿到「始终阻断 IPv6」等规则。
    fn needs_initial_commit(&self) -> bool {
        !self.decided
    }

    /// 按实际规则报告缺了什么：网络扩展没有连接时，需要它的规则（阻断受控应用、受控应用的「始终阻断 IPv6」）
    /// 都不生效；全局断网（pf）开着时这两项都由 pf 覆盖（阻断时断全部网络，IPv6 整机阻断）。
    fn degraded(&self) -> Option<String> {
        let Some(ext) = self.hub.connected_hello() else {
            if self.rules.apps.is_empty() || self.rules.block_all.is_some() {
                return None;
            }
            let mut lost = Vec::new();
            if self.blocked {
                lost.push("受控应用不会被断网");
            }
            if self.rules.block_ipv6 {
                lost.push("受控应用的 IPv6 连接不会被阻断（「始终阻断 IPv6」）");
            }
            return (!lost.is_empty()).then(|| format!("网络扩展没有连接：{}", lost.join("，")));
        };
        if self.rules.block_ipv6 && !ext.supports(CAP_BLOCK_IPV6) {
            return Some(format!(
                "网络扩展 {} 不支持「始终阻断 IPv6」，受控应用的 IPv6 连接不会被阻断。请更新网络扩展（重新打开界面会自动更新）",
                ext.version
            ));
        }
        if self.decided && ext.supports(CAP_ACK) {
            let want = self.hub.version();
            if want > 0 && ext.applied < want && self.hub.pending_for(want) > ACK_GRACE {
                return Some(format!("网络扩展还没有确认收到最新规则（第 {want} 版，已确认第 {} 版）", ext.applied));
            }
        }
        None
    }

    /// 网络扩展没有连接、开着全局断网（pf）时，受控应用只由 pf 覆盖：pf 不能按程序区分，
    /// 全局断网放行的例外（DNS、局域网、例外地址）对受控应用同样放行。这是范围限制，不算故障。
    fn limitation(&self) -> Option<String> {
        if self.hub.connected().is_some() || self.rules.apps.is_empty() {
            return None;
        }
        let p = self.rules.block_all.as_ref()?;
        let mut ex = Vec::new();
        if p.allow_dns {
            ex.push("DNS");
        }
        if p.allow_lan {
            ex.push("局域网");
        }
        if !p.allow_remote.is_empty() {
            ex.push("例外地址");
        }
        (!ex.is_empty()).then(|| {
            format!(
                "网络扩展没有连接，受控应用由全局断网（pf）覆盖：全局断网放行的{}对受控应用同样放行",
                ex.join("、")
            )
        })
    }

    fn set_rules(&mut self, rules: Rules) -> Result<()> {
        self.rules = rules.clone();
        self.publish();
        self.warn_if_inert();
        self.inner.set_rules(rules)
    }

    fn has_pending(&self) -> bool {
        self.inner.has_pending()
    }

    fn per_app(&self) -> bool {
        self.hub.connected().is_some()
    }

    fn extension(&self) -> Option<String> {
        self.hub.connected()
    }
}

impl Drop for FeedFirewall {
    fn drop(&mut self) {
        // 退出时让扩展完全放行：发一份空规则（没有受控应用，也不再常驻阻断 IPv6），
        // 与 pf 清空锚点一致；inner 随后自己清理
        self.hub.set(FilterState::default());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    #[test]
    fn set_skips_duplicates_and_wakes_waiters() {
        let hub = Arc::new(FilterHub::default());
        let (v0, s0) = hub.wait_newer(u64::MAX, Duration::from_millis(1));
        assert_eq!((v0, s0), (0, FilterState::default()));

        hub.set(FilterState::default());
        let (v1, _) = hub.wait_newer(0, Duration::from_millis(1));
        assert_eq!(v1, 1, "第一次设置总要推送，扩展才知道服务已就绪");
        hub.set(FilterState::default());
        assert_eq!(hub.wait_newer(1, Duration::from_millis(1)).0, 1, "相同规则不重复推送");

        let h = hub.clone();
        let t = std::thread::spawn(move || h.wait_newer(1, Duration::from_secs(5)));
        std::thread::sleep(Duration::from_millis(50));
        hub.set(FilterState { blocked: true, apps: vec!["/Applications/A.app".into()], ..Default::default() });
        let (v, s) = t.join().unwrap();
        assert_eq!(v, 2);
        assert!(s.blocked);
    }

    #[test]
    fn clients_and_notify() {
        let hub = FilterHub::default();
        let fired = Arc::new(AtomicUsize::new(0));
        let f = fired.clone();
        hub.set_notify(move || {
            f.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(hub.connected(), None);
        let a = hub.register(FilterHello { version: "0.7.0".into(), ..Default::default() });
        let b = hub.register(FilterHello { version: "0.7.1".into(), ..Default::default() });
        assert_eq!(hub.connected().as_deref(), Some("0.7.1"));
        drop(b);
        assert_eq!(hub.connected().as_deref(), Some("0.7.0"));
        drop(a);
        assert_eq!(hub.connected(), None);
        assert_eq!(fired.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn feed_firewall_publishes() {
        use crate::controller::DryRunFirewall;
        let hub: &'static FilterHub = Box::leak(Box::default());
        let mut fw = FeedFirewall::new(Box::new(DryRunFirewall::default()), hub);
        assert!(!fw.per_app());
        fw.set_rules(Rules {
            apps: vec!["/Applications/A.app".into()],
            block_all: None,
            kill_existing_tcp: true,
            block_ipv6: false,
            v6_probe: false,
        })
        .unwrap();
        assert_eq!(hub.wait_newer(0, Duration::from_millis(1)).0, 0, "做出第一次决定之前不推送");
        fw.block().unwrap();
        let s = hub.current();
        assert!(s.blocked && s.inspect_existing && s.apps == ["/Applications/A.app"]);
        let reg = hub.register(FilterHello { version: "1".into(), ..Default::default() });
        assert!(fw.per_app());
        assert_eq!(fw.extension().as_deref(), Some("1"));
        drop(reg);
        fw.unblock().unwrap();
        assert!(!hub.current().blocked);
        fw.block().unwrap();
        drop(fw);
        assert!(!hub.current().blocked, "退出时放行");
    }

    /// start_blocked=false、「始终阻断 IPv6」、第一次检测就命中白名单：控制器不切换状态，
    /// 但扩展必须立即收到应用列表和 IPv6 规则。
    #[test]
    fn first_allow_decision_is_published() {
        use crate::config::Config;
        use crate::controller::{Controller, DryRunFirewall, Egress};
        let hub: &'static FilterHub = Box::leak(Box::default());
        let fw = FeedFirewall::new(Box::new(DryRunFirewall::default()), hub);
        let cfg = Config::parse(
            "whitelist=[\"203.0.113.0/24\"]\napps=['/Applications/A.app']\n[behavior]\nstart_blocked=false\n[ipv6]\nmode=\"block\"",
        )
        .unwrap();
        let mut c = Controller::new(cfg, Box::new(fw));
        c.apply_rules().unwrap();
        assert_eq!(hub.version(), 0, "做出第一次决定之前不推送");
        c.on_detection(Ok(Egress::v4("203.0.113.9".parse().unwrap()))).unwrap();
        assert!(!c.is_blocked());
        assert_eq!(hub.version(), 1, "第一次决定是放行也要推送");
        let s = hub.current();
        assert!(!s.blocked && s.block_ipv6 && s.apps == ["/Applications/A.app"]);
        // 之后同样的决定不再重复推送
        c.on_detection(Ok(Egress::v4("203.0.113.9".parse().unwrap()))).unwrap();
        assert_eq!(hub.version(), 1);
    }

    /// pf 失败：阻断没生效时不报告已阻断，控制器定时重试，成功后只记一次。
    #[test]
    fn pf_failure_is_reported_and_retried() {
        use crate::config::Config;
        use crate::controller::{Controller, Egress};
        struct FailingPf {
            fail: std::rc::Rc<std::cell::Cell<bool>>,
            blocked: bool,
        }
        impl Firewall for FailingPf {
            fn block(&mut self) -> Result<()> {
                if self.fail.get() {
                    anyhow::bail!("pfctl 失败");
                }
                self.blocked = true;
                Ok(())
            }
            fn unblock(&mut self) -> Result<()> {
                self.blocked = false;
                Ok(())
            }
            fn is_blocked(&self) -> bool {
                self.blocked
            }
            fn set_rules(&mut self, _: Rules) -> Result<()> {
                Ok(())
            }
        }
        let hub: &'static FilterHub = Box::leak(Box::default());
        let fail = std::rc::Rc::new(std::cell::Cell::new(true));
        let fw = FeedFirewall::new(Box::new(FailingPf { fail: fail.clone(), blocked: false }), hub);
        let cfg = Config::parse("whitelist=[\"203.0.113.0/24\"]\napps=['/Applications/A.app']\n[behavior]\nstart_blocked=false").unwrap();
        let mut c = Controller::new(cfg, Box::new(fw));
        assert!(c.on_detection(Ok(Egress::v4("198.51.100.1".parse().unwrap()))).is_err());
        assert!(!c.is_blocked(), "pf 没装上：不能报告已阻断");
        assert!(c.wants_block() && c.needs_retry());
        assert!(c.apply_error().unwrap().contains("阻断未生效"));
        assert!(hub.current().blocked, "扩展已经收到阻断");
        fail.set(false);
        c.retry_pending().unwrap();
        assert!(c.is_blocked() && !c.needs_retry() && c.apply_error().is_none());
    }

    /// 没有网络扩展、开着全局断网：受控应用只由 pf 覆盖，例外对它们同样放行。作为范围限制单独报告，不算降级。
    #[test]
    fn pf_only_reports_shared_exceptions_as_limitation() {
        let hub: &'static FilterHub = Box::leak(Box::default());
        let mut fw = FeedFirewall::new(Box::new(crate::controller::DryRunFirewall::default()), hub);
        let policy = crate::blockall::BlockAllPolicy { allow_dns: true, allow_lan: true, ..Default::default() };
        fw.set_rules(Rules { apps: vec!["/Applications/A.app".into()], block_all: Some(policy), ..Default::default() }).unwrap();
        fw.block().unwrap();
        assert!(fw.degraded().is_none());
        let l = fw.limitation().unwrap();
        assert!(l.contains("DNS、局域网"), "{l}");
        // 严格的全局断网（没有例外）、没有受控应用、扩展已连接：都没有这个限制
        fw.set_rules(Rules { apps: vec!["/Applications/A.app".into()], block_all: Some(Default::default()), ..Default::default() }).unwrap();
        assert!(fw.limitation().is_none());
        let ext = hub.register(FilterHello { version: "1".into(), protocol: 1, caps: vec!["ack".into()] });
        fw.set_rules(Rules { apps: vec!["/Applications/A.app".into()], block_all: Some(policy_dns()), ..Default::default() }).unwrap();
        assert!(fw.limitation().is_none());
        drop(ext);
        assert!(fw.limitation().is_some());
    }

    fn policy_dns() -> crate::blockall::BlockAllPolicy {
        crate::blockall::BlockAllPolicy { allow_dns: true, ..Default::default() }
    }

    /// 先登记已发送、再写出：扩展抢在写入返回前回复的确认也能被接受。
    #[test]
    fn ack_right_after_send_is_accepted() {
        let hub: &'static FilterHub = Box::leak(Box::default());
        hub.set(FilterState { apps: vec!["/Applications/A.app".into()], ..Default::default() });
        let reg = hub.register(FilterHello { version: "1".into(), protocol: 1, caps: vec!["ack".into()] });
        let v = hub.version();
        hub.applied(&reg, v);
        assert_eq!(hub.connected_hello().unwrap().applied, 0, "没发出过的版本不能确认");
        hub.sent(&reg, v);
        hub.applied(&reg, v);
        assert_eq!(hub.connected_hello().unwrap().applied, v);
        // 心跳重复确认同一版：幂等
        hub.applied(&reg, v);
        assert_eq!(hub.connected_hello().unwrap().applied, v);
    }

    #[test]
    fn old_extension_capabilities() {
        let hub: &'static FilterHub = Box::leak(Box::default());
        let mut fw = FeedFirewall::new(Box::new(crate::controller::DryRunFirewall::default()), hub);
        fw.set_rules(Rules { apps: vec!["/Applications/A.app".into()], block_ipv6: true, ..Default::default() }).unwrap();
        fw.unblock().unwrap();
        let d = fw.degraded().unwrap();
        assert!(d.contains("没有连接") && d.contains("IPv6") && !d.contains("断网"), "{d}");
        fw.block().unwrap();
        assert!(fw.degraded().unwrap().contains("受控应用不会被断网"));
        fw.unblock().unwrap();
        let old = hub.register(FilterHello { version: "0.8.0".into(), ..Default::default() });
        assert!(fw.degraded().unwrap().contains("不支持「始终阻断 IPv6」"));
        drop(old);
        // 0.9.0 的扩展没有能力列表但支持 IPv6，也不会确认
        let v090 = hub.register(FilterHello { version: "0.9.0".into(), ..Default::default() });
        assert_eq!(fw.degraded(), None);
        drop(v090);
        let new = hub.register(FilterHello {
            version: "0.9.1".into(),
            protocol: 1,
            caps: vec![CAP_BLOCK_IPV6.into(), CAP_ACK.into()],
        });
        assert_eq!(fw.degraded(), None, "宽限时间内不提示");
        hub.applied(&new, hub.version());
        assert_eq!(hub.connected_hello().unwrap().applied, 0, "还没发给这个扩展的版本不能被确认");
        hub.sent(&new, hub.version());
        hub.applied(&new, hub.version());
        assert_eq!(hub.connected_hello().unwrap().applied, hub.version());
        assert_eq!(fw.degraded(), None);
        hub.applied(&new, hub.version() + 5);
        assert_eq!(hub.connected_hello().unwrap().applied, hub.version(), "超前的确认被忽略");
        drop(new);
        drop(fw);
        let s = hub.current();
        assert!(!s.blocked && s.apps.is_empty() && !s.block_ipv6, "退出时清空规则");
    }

    #[test]
    fn marker_path() {
        assert_eq!(
            run_marker(std::path::Path::new("/var/run/egress-guard.sock")),
            std::path::PathBuf::from("/var/run/egress-guard.running")
        );
    }

    #[test]
    fn json_shape() {
        let s = FilterState { blocked: true, inspect_existing: false, apps: vec!["/Applications/A.app".into()], block_ipv6: false, rev: 0 };
        assert_eq!(
            serde_json::to_string(&s).unwrap(),
            r#"{"blocked":true,"inspect_existing":false,"apps":["/Applications/A.app"],"block_ipv6":false}"#
        );
        let s = FilterState { rev: 7, ..s };
        assert!(serde_json::to_string(&s).unwrap().ends_with(r#""block_ipv6":false,"rev":7}"#));
        assert_eq!(
            serde_json::to_string(&FilterHello { version: "1".into(), protocol: 1, caps: vec!["ack".into()] }).unwrap(),
            r#"{"version":"1","protocol":1,"caps":["ack"]}"#
        );
    }
}
