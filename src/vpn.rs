//! VPN 守护：识别本机的 VPN 网卡，并持续检查它们是否还在。
//!
//! 放行时引擎记下正在使用的 VPN 网卡（见 `engine`），之后任何一块断开（网卡消失、关闭或失去地址）
//! 就立即阻断，不必等下一次出口 IP 检测，也不受「网络变化时先阻断」开关的影响。
//!
//! 识别方式：用户在设置里列出的网卡名称；没有列出时按名称、描述和接口类型自动识别
//! （utun、tun、tap、ppp、wg、WireGuard、OpenVPN、Wintun 等）。只算有可用地址（不只是链路本地地址）的网卡：
//! macOS 自带的几个 utun（iCloud 专用代理、接力等）只有 fe80:: 地址，不会被当成 VPN。

use std::net::IpAddr;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::config::VpnConfig;
use crate::leaktest::ifaces::{self, Adapter};

/// 正在通过 VPN 放行（有守护中的网卡）时轮询网卡的间隔。Windows、macOS 上网卡一变化系统就会通知引擎、
/// 立即检查（毫秒级），轮询只是兜底（通知没来、或者本平台没有通知时）。
/// 这不是漏放窗口的上限：断线到规则生效还要加上网卡状态变化本身的延迟和防火墙提交的耗时。
pub const POLL_INTERVAL: Duration = Duration::from_millis(250);
/// 没有守护中的网卡（阻断中、没有 VPN、关闭了守护）时的轮询间隔：只用来刷新界面上的 VPN 状态。
pub const IDLE_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Windows 接口类型（IF_TYPE_*）。
const IF_TYPE_PPP: u32 = 23;
const IF_TYPE_PROP_VIRTUAL: u32 = 53;
const IF_TYPE_TUNNEL: u32 = 131;

/// Unix 网卡名前缀。
const UNIX_PREFIXES: &[&str] = &["utun", "tun", "tap", "ppp", "ipsec", "wg", "tailscale", "zt", "nordlynx"];

/// Windows 网卡名称或描述里出现这些词时当作 VPN。
const WIN_WORDS: &[&str] = &[
    "vpn", "tap-windows", "tap-", "wintun", "wireguard", "openvpn", "tunnel", "tun ", "tailscale", "zerotier",
    "anyconnect", "globalprotect", "pangp", "fortinet", "forticlient", "juniper", "pulse secure", "sstp", "l2tp",
    "pptp", "ikev2", "clash", "sing-box", "v2ray", "nekoray", "hysteria", "nordlynx", "proton",
];

/// 名称或描述里出现这些词时不当作 VPN（IPv6 过渡隧道、虚拟机网卡等）。
const WIN_EXCLUDE: &[&str] =
    &["teredo", "isatap", "6to4", "ip-https", "hyper-v", "vmware", "virtualbox", "loopback", "bluetooth", "kernel debug"];

/// 地址是否可以承载流量（不是链路本地、未指定地址）。
fn usable(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => !v.is_link_local() && !v.is_unspecified(),
        IpAddr::V6(v) => (v.segments()[0] & 0xffc0) != 0xfe80 && !v.is_unspecified(),
    }
}

/// 按名称、描述、接口类型判断是不是 VPN 网卡（不看地址）。
pub fn looks_like_vpn(a: &Adapter) -> bool {
    let name = a.name.to_ascii_lowercase();
    let desc = a.description.to_ascii_lowercase();
    if a.if_type == 0 && a.description.is_empty() {
        // Unix：只看名称前缀，如 utun3、wg0、ppp0
        return UNIX_PREFIXES.iter().any(|p| {
            name.strip_prefix(p).is_some_and(|rest| rest.is_empty() || rest.starts_with(|c: char| c.is_ascii_digit()))
        });
    }
    let text = format!("{name} {desc} ");
    if WIN_EXCLUDE.iter().any(|w| text.contains(w)) {
        return false;
    }
    matches!(a.if_type, IF_TYPE_PPP | IF_TYPE_TUNNEL | IF_TYPE_PROP_VIRTUAL) || WIN_WORDS.iter().any(|w| text.contains(w))
}

/// 用户列出的名称是否指这块网卡（名称或描述，不区分大小写）。
fn named(a: &Adapter, names: &[String]) -> bool {
    names.iter().any(|n| n.eq_ignore_ascii_case(&a.name) || (!a.description.is_empty() && n.eq_ignore_ascii_case(&a.description)))
}

/// 一块连着的 VPN 网卡：名称、稳定标识和可用地址（排序去重）。
/// 同名网卡被删掉重建（标识变了）不算同一块；同一块网卡换了地址时，引擎重新检测出口。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub name: String,
    pub id: String,
    pub addrs: Vec<IpAddr>,
}

impl Link {
    /// 是不是同一块网卡（名称和标识都相同，不看地址）。
    pub fn same(&self, other: &Link) -> bool {
        self.name == other.name && self.id == other.id
    }
}

fn usable_addrs(a: &Adapter) -> Vec<IpAddr> {
    let mut v: Vec<IpAddr> = a.addrs.iter().copied().filter(usable).collect();
    v.sort();
    v.dedup();
    v
}

/// 现在连着的 VPN 网卡（有可用地址），按名称排序。
pub fn links(adapters: &[Adapter], cfg: &VpnConfig) -> Vec<Link> {
    let mut v: Vec<Link> = adapters
        .iter()
        .filter(|a| if cfg.interfaces.is_empty() { looks_like_vpn(a) } else { named(a, &cfg.interfaces) })
        .map(|a| Link { name: a.name.clone(), id: a.id.clone(), addrs: usable_addrs(a) })
        .filter(|l| !l.addrs.is_empty())
        .collect();
    v.sort_by(|x, y| (&x.name, &x.id).cmp(&(&y.name, &y.id)));
    v.dedup();
    v
}

/// 网卡名称（去重，保持顺序）。
pub fn names(links: &[Link]) -> Vec<String> {
    let mut v: Vec<String> = links.iter().map(|l| l.name.clone()).collect();
    v.dedup();
    v
}

/// 现在连着的 VPN 网卡名称（有可用地址），按名称排序。
pub fn connected(adapters: &[Adapter], cfg: &VpnConfig) -> Vec<String> {
    names(&links(adapters, cfg))
}

/// 当前已启用的网卡；枚举失败时为 None（不知道现在的情况，不能当作「全部断开」或「全部还在」）。
pub fn scan() -> Option<Vec<Adapter>> {
    ifaces::try_adapters()
}

/// 有可用地址的网卡名称（供界面选择要守护的网卡），按名称排序。
pub fn candidates(adapters: &[Adapter]) -> Vec<(String, String, bool)> {
    let mut v: Vec<(String, String, bool)> = adapters
        .iter()
        .filter(|a| a.addrs.iter().any(usable))
        .map(|a| (a.name.clone(), a.description.clone(), looks_like_vpn(a)))
        .collect();
    v.sort();
    v.dedup();
    v
}

/// 网卡快照的指纹：标识、名称、描述、类型和可用地址。只在它变化时通知引擎，
/// 所以同名网卡换了地址、被删掉重建也会通知。
fn fingerprint(adapters: &[Adapter]) -> Vec<(String, String, String, u32, Vec<IpAddr>)> {
    let mut v: Vec<_> =
        adapters.iter().map(|a| (a.id.clone(), a.name.clone(), a.description.clone(), a.if_type, usable_addrs(a))).collect();
    v.sort();
    v
}

#[derive(Default)]
struct WatchState {
    active: bool,
    stop: bool,
}

type Shared = Arc<(Mutex<WatchState>, Condvar)>;

/// 网卡检查线程的控制：轮询间隔与停止信号。引擎退出时丢弃，线程随即被唤醒并结束。
pub struct Watch {
    shared: Shared,
}

impl Watch {
    /// 有守护中的网卡时勤一些，否则放慢。从放慢切换为勤查时立即唤醒检查线程。
    pub fn set_active(&self, active: bool) {
        let (m, cv) = &*self.shared;
        let mut st = m.lock().unwrap_or_else(|e| e.into_inner());
        if st.active != active {
            st.active = active;
            cv.notify_all();
        }
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        let (m, cv) = &*self.shared;
        m.lock().unwrap_or_else(|e| e.into_inner()).stop = true;
        cv.notify_all();
    }
}

/// 等到下一次检查的时间（从 `since` 起按当前间隔算）；要求停止时返回 false。
/// 间隔在等待期间缩短（进入守护）时按新的间隔算，已经超过就立即返回。
fn wait_next(shared: &Shared, since: Instant) -> bool {
    let (m, cv) = &**shared;
    let mut st = m.lock().unwrap_or_else(|e| e.into_inner());
    loop {
        if st.stop {
            return false;
        }
        let iv = if st.active { POLL_INTERVAL } else { IDLE_POLL_INTERVAL };
        let elapsed = since.elapsed();
        if elapsed >= iv {
            return true;
        }
        st = cv.wait_timeout(st, iv - elapsed).unwrap_or_else(|e| e.into_inner()).0;
    }
}

/// 在后台线程中按 [`Watch::set_active`] 设定的间隔检查网卡；有变化时调用 `send`（返回 false 时结束线程）。
/// 枚举失败的那一次跳过（不当作网卡全部消失）。
pub fn spawn_watch(send: impl Fn(Vec<Adapter>) -> bool + Send + 'static) -> Watch {
    spawn_watch_with(scan, send)
}

fn spawn_watch_with(
    mut scan: impl FnMut() -> Option<Vec<Adapter>> + Send + 'static,
    send: impl Fn(Vec<Adapter>) -> bool + Send + 'static,
) -> Watch {
    let shared: Shared = Arc::default();
    let sh = shared.clone();
    let r = std::thread::Builder::new().name("vpn-watch".into()).spawn(move || {
        let mut last = None;
        let mut warned = false;
        loop {
            let started = Instant::now();
            match scan() {
                Some(now) => {
                    warned = false;
                    let fp = fingerprint(&now);
                    if last.as_ref() != Some(&fp) {
                        last = Some(fp);
                        if !send(now) {
                            break;
                        }
                    }
                }
                None if !warned => {
                    warned = true;
                    log::warn!("无法列出网卡，VPN 守护暂时依赖系统的网络变化通知");
                }
                None => {}
            }
            if !wait_next(&sh, started) {
                break;
            }
        }
    });
    if let Err(e) = r {
        log::warn!("无法启动 VPN 网卡检查线程: {e}");
    }
    Watch { shared }
}

/// 便捷封装：把网卡变化发给引擎。
pub fn spawn_engine_watch(tx: Sender<crate::engine::Event>) -> Watch {
    spawn_watch(move |a| tx.send(crate::engine::Event::Adapters(a)).is_ok())
}

/// 守护中的网卡里，现在已经断开的那些（包括同名但被删掉重建的网卡）。
pub fn lost<'a>(guarded: &'a [Link], now: &[Link]) -> Vec<&'a str> {
    guarded.iter().filter(|g| !now.iter().any(|l| l.same(g))).map(|g| g.name.as_str()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unix(name: &str, addrs: &[&str]) -> Adapter {
        Adapter { name: name.into(), id: name.into(), description: String::new(), if_type: 0, addrs: addrs.iter().map(|a| a.parse().unwrap()).collect() }
    }

    fn win(name: &str, desc: &str, if_type: u32, addrs: &[&str]) -> Adapter {
        Adapter { name: name.into(), id: name.into(), description: desc.into(), if_type, addrs: addrs.iter().map(|a| a.parse().unwrap()).collect() }
    }

    #[test]
    fn auto_detect() {
        let cfg = VpnConfig::default();
        let list = vec![
            unix("en0", &["192.168.1.5", "fe80::1"]),
            unix("utun0", &["fe80::a"]),        // 系统自带，只有链路本地地址
            unix("utun4", &["10.8.0.2"]),       // VPN
            unix("wg0", &["fd00::2"]),
            unix("tunnelbroker", &["10.0.0.1"]), // 不是 tun<数字>
            unix("bridge100", &["192.168.64.1"]),
            win("WireGuard 隧道", "WireGuard Tunnel", IF_TYPE_PROP_VIRTUAL, &["10.2.0.2"]),
            win("以太网 2", "TAP-Windows Adapter V9", 6, &["10.9.0.6"]),
            win("以太网", "Intel(R) Ethernet Connection", 6, &["192.168.1.9"]),
            win("Teredo Tunneling Pseudo-Interface", "Teredo Tunneling Pseudo-Interface", IF_TYPE_TUNNEL, &["2001:0:1::1"]),
            win("vEthernet (Default Switch)", "Hyper-V Virtual Ethernet Adapter", 6, &["172.20.0.1"]),
            win("公司 VPN", "公司 VPN", IF_TYPE_PPP, &["10.1.1.1"]),
        ];
        assert_eq!(connected(&list, &cfg), vec!["WireGuard 隧道", "utun4", "wg0", "以太网 2", "公司 VPN"]);
    }

    #[test]
    fn named_interfaces() {
        let cfg = VpnConfig { interfaces: vec!["EN0".into(), "TAP-Windows Adapter V9".into()], ..Default::default() };
        let list = vec![
            unix("en0", &["192.168.1.5"]),
            unix("utun4", &["10.8.0.2"]),
            win("以太网 2", "TAP-Windows Adapter V9", 6, &["10.9.0.6"]),
            win("以太网 3", "TAP-Windows Adapter V9 #2", 6, &["169.254.3.3"]),
        ];
        assert_eq!(connected(&list, &cfg), vec!["en0", "以太网 2"]);
    }

    #[test]
    fn lost_ones() {
        let cfg = VpnConfig::default();
        let before = links(&[unix("utun4", &["10.8.0.2"]), unix("wg0", &["10.9.0.2"])], &cfg);
        assert_eq!(names(&before), vec!["utun4", "wg0"]);
        // 多个 VPN：只报告断开的那块
        let now = links(&[unix("wg0", &["10.9.0.2"])], &cfg);
        assert_eq!(lost(&before, &now), vec!["utun4"]);
        assert!(lost(&before, &before).is_empty());
        assert!(lost(&[], &[]).is_empty());
        // 同名网卡被删掉重建：算断开过
        let mut rebuilt = unix("utun4", &["10.8.0.2"]);
        rebuilt.id = "99".into();
        let now = links(&[rebuilt, unix("wg0", &["10.9.0.2"])], &cfg);
        assert_eq!(lost(&before, &now), vec!["utun4"]);
    }

    #[test]
    fn same_name_new_address() {
        let cfg = VpnConfig::default();
        let a = links(&[unix("utun4", &["10.8.0.2", "fe80::1"])], &cfg);
        let b = links(&[unix("utun4", &["10.8.0.7", "fe80::1"])], &cfg);
        assert!(lost(&a, &b).is_empty(), "换地址不算断开");
        assert_ne!(a, b, "但引擎能看出变化并重新检测");
        // 只是链路本地地址变化、地址顺序不同：不算变化
        let c = links(&[unix("utun4", &["fe80::2", "10.8.0.2", "10.8.0.2"])], &cfg);
        assert_eq!(a, c);
        // 指纹同样能看出同名换址
        assert_ne!(
            fingerprint(&[unix("utun4", &["10.8.0.2"])]),
            fingerprint(&[unix("utun4", &["10.8.0.7"])])
        );
    }

    /// 枚举偶发失败时跳过（不发空列表）；从空闲进入守护、退出时都能立即唤醒检查线程。
    #[test]
    fn watch_thread() {
        use std::sync::mpsc;
        let (scan_tx, scan_rx) = mpsc::channel::<()>();
        let mut n = 0;
        let scan = move || {
            n += 1;
            let _ = scan_tx.send(());
            match n {
                2 => None,
                _ => Some(vec![unix("utun4", if n < 3 { &["10.8.0.2"] } else { &["10.8.0.3"] })]),
            }
        };
        let (tx, rx) = mpsc::channel::<Vec<Adapter>>();
        let w = spawn_watch_with(scan, move |a| tx.send(a).is_ok());
        let first = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(first[0].addrs, vec!["10.8.0.2".parse::<IpAddr>().unwrap()]);
        scan_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        // 空闲时 2 秒一次；切换为守护后马上按 0.25 秒检查
        let t = Instant::now();
        w.set_active(true);
        scan_rx.recv_timeout(Duration::from_secs(1)).unwrap(); // 第 2 次：枚举失败
        let second = rx.recv_timeout(Duration::from_secs(1)).unwrap(); // 第 3 次：换了地址
        assert!(t.elapsed() < Duration::from_millis(1500), "{:?}", t.elapsed());
        assert_eq!(second[0].addrs, vec!["10.8.0.3".parse::<IpAddr>().unwrap()], "失败的那次没有发出空列表");
        // 退出时唤醒线程：不用等到下一次间隔
        w.set_active(false);
        while scan_rx.try_recv().is_ok() {}
        let t = Instant::now();
        drop(w);
        // 线程结束时 send 闭包被丢弃，rx 断开
        loop {
            match rx.recv_timeout(Duration::from_secs(1)) {
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => panic!("检查线程没有及时退出"),
                Ok(_) => {}
            }
        }
        assert!(t.elapsed() < Duration::from_millis(500), "{:?}", t.elapsed());
    }

}
