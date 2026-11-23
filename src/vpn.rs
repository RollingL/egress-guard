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
use std::time::Duration;

use crate::config::VpnConfig;
use crate::leaktest::ifaces::{self, Adapter};

/// 轮询网卡的间隔。Windows、macOS 上网卡一变化系统就会通知引擎、立即检查（毫秒级），
/// 轮询只是兜底（通知没来、或者本平台没有通知时）；列一次网卡只需几毫秒，所以可以轮询得很勤。
pub const POLL_INTERVAL: Duration = Duration::from_millis(250);

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

/// 现在连着的 VPN 网卡名称（有可用地址），按名称排序。
pub fn connected(adapters: &[Adapter], cfg: &VpnConfig) -> Vec<String> {
    let mut v: Vec<String> = adapters
        .iter()
        .filter(|a| a.addrs.iter().any(usable))
        .filter(|a| if cfg.interfaces.is_empty() { looks_like_vpn(a) } else { named(a, &cfg.interfaces) })
        .map(|a| a.name.clone())
        .collect();
    v.sort();
    v.dedup();
    v
}

/// 当前已启用的网卡。
pub fn scan() -> Vec<Adapter> {
    ifaces::adapters()
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

/// 网卡快照的指纹：名称 + 是否有可用地址。只在它变化时通知引擎。
fn fingerprint(adapters: &[Adapter]) -> Vec<(String, bool)> {
    let mut v: Vec<(String, bool)> = adapters.iter().map(|a| (a.name.clone(), a.addrs.iter().any(usable))).collect();
    v.sort();
    v
}

/// 在后台线程中每 [`POLL_INTERVAL`] 检查一次网卡；有变化时调用 `send`（返回 false 时结束线程）。
pub fn spawn_watch(send: impl Fn(Vec<Adapter>) -> bool + Send + 'static) {
    let r = std::thread::Builder::new().name("vpn-watch".into()).spawn(move || {
        let mut last = None;
        loop {
            let now = scan();
            let fp = fingerprint(&now);
            if last.as_ref() != Some(&fp) {
                last = Some(fp);
                if !send(now) {
                    break;
                }
            }
            std::thread::sleep(POLL_INTERVAL);
        }
    });
    if let Err(e) = r {
        log::warn!("无法启动 VPN 网卡检查线程: {e}");
    }
}

/// 便捷封装：把网卡变化发给引擎。
pub fn spawn_engine_watch(tx: Sender<crate::engine::Event>) {
    spawn_watch(move |a| tx.send(crate::engine::Event::Adapters(a)).is_ok());
}

/// 守护中的网卡里，现在已经断开的那些。
pub fn lost<'a>(guarded: &'a [String], connected: &[String]) -> Vec<&'a str> {
    guarded.iter().filter(|g| !connected.contains(g)).map(String::as_str).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unix(name: &str, addrs: &[&str]) -> Adapter {
        Adapter { name: name.into(), description: String::new(), if_type: 0, addrs: addrs.iter().map(|a| a.parse().unwrap()).collect() }
    }

    fn win(name: &str, desc: &str, if_type: u32, addrs: &[&str]) -> Adapter {
        Adapter { name: name.into(), description: desc.into(), if_type, addrs: addrs.iter().map(|a| a.parse().unwrap()).collect() }
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
        let g = vec!["utun4".to_owned(), "wg0".to_owned()];
        assert_eq!(lost(&g, &["wg0".to_owned()]), vec!["utun4"]);
        assert!(lost(&g, &g).is_empty());
        assert!(lost(&[], &[]).is_empty());
    }
}
