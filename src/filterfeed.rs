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
}

/// 网络扩展连接时报告的信息。
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct FilterHello {
    /// 网络扩展的版本。
    pub version: String,
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
    cv: Condvar,
    clients: Mutex<HashMap<u64, FilterHello>>,
    next_id: AtomicU64,
    /// 网络扩展连上或断开时调用（让引擎刷新状态）。
    notify: Mutex<Option<Notify>>,
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
        self.cv.notify_all();
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
        self.clients.lock().unwrap().insert(id, hello);
        self.fire();
        Registration { hub: self, id }
    }

    /// 已连接网络扩展的版本；没有连接时为 None。
    pub fn connected(&self) -> Option<String> {
        let g = self.clients.lock().unwrap();
        // 系统升级扩展时新旧两个进程可能短暂同时在线，取版本号最大的
        g.values().map(|h| h.version.clone()).max()
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

    fn is_blocked(&self) -> bool {
        self.blocked
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
        // 退出时让扩展放行；inner 随后自己清理（pf 清空锚点）
        self.blocked = false;
        self.decided = true;
        self.publish();
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
        let a = hub.register(FilterHello { version: "0.7.0".into() });
        let b = hub.register(FilterHello { version: "0.7.1".into() });
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
        })
        .unwrap();
        assert_eq!(hub.wait_newer(0, Duration::from_millis(1)).0, 0, "做出第一次决定之前不推送");
        fw.block().unwrap();
        let s = hub.current();
        assert!(s.blocked && s.inspect_existing && s.apps == ["/Applications/A.app"]);
        let reg = hub.register(FilterHello { version: "1".into() });
        assert!(fw.per_app());
        assert_eq!(fw.extension().as_deref(), Some("1"));
        drop(reg);
        fw.unblock().unwrap();
        assert!(!hub.current().blocked);
        fw.block().unwrap();
        drop(fw);
        assert!(!hub.current().blocked, "退出时放行");
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
        let s = FilterState { blocked: true, inspect_existing: false, apps: vec!["/Applications/A.app".into()], block_ipv6: false };
        assert_eq!(
            serde_json::to_string(&s).unwrap(),
            r#"{"blocked":true,"inspect_existing":false,"apps":["/Applications/A.app"],"block_ipv6":false}"#
        );
    }
}
