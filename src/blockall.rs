//! 全局断网：出口 IP 不在白名单时切断本机全部网络，只保留必要的例外。
//!
//! 始终放行：本工具自身（否则无法再检测出口 IP）、回环地址、DHCP（否则拿不到地址）。
//! 可选放行：局域网、DNS、指定的例外程序（如 VPN 客户端）和例外地址（如 VPN 服务器）。

use std::net::IpAddr;
use std::path::PathBuf;

use ipnet::IpNet;

/// 局域网、链路本地与组播地址。
pub const LAN_NETS: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255/32",
    "fe80::/10",
    "fc00::/7",
    "ff00::/8",
];

pub const DNS_PORT: u16 = 53;
/// DHCP 客户端端口：IPv4 为 68，DHCPv6 为 546。
pub const DHCP_V4_CLIENT_PORT: u16 = 68;
pub const DHCP_V6_CLIENT_PORT: u16 = 546;

/// 全局断网时的例外规则。
#[derive(Debug, Clone, PartialEq, Default)]
pub struct BlockAllPolicy {
    pub allow_lan: bool,
    pub allow_dns: bool,
    /// 例外程序（exe 完整路径）。本工具自身由后端自动加入，不必列出。
    pub allow_apps: Vec<PathBuf>,
    /// 例外远端地址/网段。
    pub allow_remote: Vec<IpNet>,
}

pub fn lan_nets() -> Vec<IpNet> {
    LAN_NETS.iter().map(|s| s.parse().expect("内置网段")).collect()
}

impl BlockAllPolicy {
    /// 按远端地址/端口判断是否属于例外（不含按程序放行与 DHCP）。
    pub fn permits_remote(&self, ip: IpAddr, port: u16) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            v4 => v4,
        };
        ip.is_loopback()
            || (self.allow_dns && port == DNS_PORT)
            || (self.allow_lan && lan_nets().iter().any(|n| n.contains(&ip)))
            || self.allow_remote.iter().any(|n| n.contains(&ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exceptions() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        let strict = BlockAllPolicy::default();
        assert!(strict.permits_remote(ip("127.0.0.1"), 443));
        assert!(strict.permits_remote(ip("::1"), 443));
        assert!(!strict.permits_remote(ip("192.168.1.1"), 80));
        assert!(!strict.permits_remote(ip("8.8.8.8"), 53));

        let p = BlockAllPolicy {
            allow_lan: true,
            allow_dns: true,
            allow_apps: vec![],
            allow_remote: vec!["198.51.100.7/32".parse().unwrap()],
        };
        assert!(p.permits_remote(ip("192.168.1.1"), 80));
        assert!(p.permits_remote(ip("172.31.255.1"), 80));
        assert!(!p.permits_remote(ip("172.32.0.1"), 80));
        assert!(p.permits_remote(ip("fe80::1"), 445));
        assert!(p.permits_remote(ip("::ffff:10.1.2.3"), 22));
        assert!(p.permits_remote(ip("8.8.8.8"), 53));
        assert!(!p.permits_remote(ip("8.8.8.8"), 443));
        assert!(p.permits_remote(ip("198.51.100.7"), 51820));
        assert!(!p.permits_remote(ip("198.51.100.8"), 51820));
    }
}
