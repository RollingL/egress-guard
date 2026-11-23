//! WebRTC 泄露测试。
//!
//! 网页里的 WebRTC 会收集两类 ICE 候选地址交给对方：
//! - host：本机网卡上的地址。浏览器默认用 mDNS 名称隐藏，网页获得摄像头/麦克风权限后能读到真实地址；
//! - srflx：向 STUN 服务器发绑定请求得到的公网映射地址。浏览器会从默认路由、获得权限后还会从每个网卡分别发送，
//!   所以 VPN 之外还能直连外网的网卡会暴露真实公网 IP，HTTP 代理也挡不住（STUN 走 UDP，不经过代理）。
//!
//! 这里用同样的方式在本机测一遍：列出网卡地址，从默认路由（IPv4、IPv6）和每个网卡地址分别向 STUN 服务器发送绑定请求。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use serde::Serialize;

use super::{ifaces, is_public, stun, Judge, Verdict};

/// 单个 STUN 服务器的等待时间（含一次重发）。
const PER_SERVER: Duration = Duration::from_millis(1600);
/// 最多从多少个网卡地址分别测试。
const MAX_BOUND: usize = 12;

/// 一条 STUN 测试路径的结果（srflx 候选）。
#[derive(Debug, Clone, Serialize)]
pub struct StunPath {
    /// 网卡名称；None 表示默认路由（不指定本地地址，与浏览器未获权限时一致）。
    pub iface: Option<String>,
    /// 绑定的本地地址；默认路由时为 0.0.0.0 / ::。
    pub local: IpAddr,
    /// STUN 服务器看到的公网地址。
    pub mapped: Option<SocketAddr>,
    /// 给出结果的 STUN 服务器。
    pub server: Option<String>,
    /// 没有结果时的原因。
    pub error: Option<String>,
    pub verdict: Verdict,
}

/// 网卡上的地址（host 候选）。
#[derive(Debug, Clone, Serialize)]
pub struct HostAddr {
    pub iface: String,
    pub ip: IpAddr,
    pub verdict: Verdict,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebRtcReport {
    pub paths: Vec<StunPath>,
    pub hosts: Vec<HostAddr>,
    /// 测试时的出口 IP（由出口检测得到，用于对照）。
    pub egress: Option<IpAddr>,
    /// 无法解析的 STUN 服务器及原因。
    pub unresolved: Vec<String>,
}

impl WebRtcReport {
    /// 按当前白名单重新判定（界面上修改白名单后立即生效）。
    pub fn judged(&self, j: &Judge) -> Self {
        let mut r = self.clone();
        for p in &mut r.paths {
            p.verdict = p.mapped.map(|m| j.mapped(m.ip())).unwrap_or(Verdict::NoResponse);
        }
        for h in &mut r.hosts {
            h.verdict = j.host(h.ip);
        }
        r
    }

    /// 会被暴露、且不在白名单内的公网 IP（去重）。
    pub fn leaked_ips(&self) -> Vec<IpAddr> {
        let mut v: Vec<IpAddr> = self.paths.iter().filter(|p| p.verdict.is_leak()).filter_map(|p| p.mapped.map(|m| m.ip())).collect();
        v.sort();
        v.dedup();
        v
    }

    /// 网卡上不在白名单的公网地址（网页获得权限时可见）。
    pub fn exposed_hosts(&self) -> usize {
        self.hosts.iter().filter(|h| h.verdict == Verdict::Exposed).count()
    }

    pub fn any_response(&self) -> bool {
        self.paths.iter().any(|p| p.mapped.is_some())
    }
}

/// 运行测试。`servers` 为「主机:端口」列表，按顺序尝试。
/// `cancel` 返回 true 时不再发出新的探测（例如自动测试期间网络变了），已经发出的照常收尾。
pub fn run(
    servers: &[String],
    egress: Option<IpAddr>,
    judge: &Judge,
    cancel: &(dyn Fn() -> bool + Sync),
) -> WebRtcReport {
    // 解析 STUN 服务器（每个服务器每种地址族只用第一个地址）
    let mut resolved: Vec<(String, Vec<SocketAddr>)> = Vec::new();
    let mut unresolved = Vec::new();
    for s in servers {
        // 解析也会发出 DNS 查询：取消后不再解析
        if cancel() {
            unresolved.push(format!("{s}：测试已取消"));
            continue;
        }
        match stun::resolve(s) {
            Ok(addrs) => {
                let mut pick = Vec::new();
                if let Some(a) = addrs.iter().find(|a| a.is_ipv4()) {
                    pick.push(*a);
                }
                if let Some(a) = addrs.iter().find(|a| a.is_ipv6()) {
                    pick.push(*a);
                }
                resolved.push((s.clone(), pick));
            }
            Err(e) => unresolved.push(format!("{s}：{e:#}")),
        }
    }

    let all = ifaces::list();
    let hosts: Vec<HostAddr> = all
        .iter()
        .filter(|a| candidate(a.ip))
        .map(|a| HostAddr { iface: a.name.clone(), ip: a.ip, verdict: judge.host(a.ip) })
        .collect();

    // 要测的路径：默认路由 IPv4；有公网 IPv6 地址时再测默认路由 IPv6；然后是每个网卡地址
    let mut binds: Vec<(Option<String>, IpAddr)> = vec![(None, IpAddr::V4(Ipv4Addr::UNSPECIFIED))];
    if hosts.iter().any(|h| h.ip.is_ipv6() && is_public(h.ip)) {
        binds.push((None, IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    }
    binds.extend(
        hosts
            .iter()
            // IPv6 只测全球单播地址（ULA 本来就上不了外网）
            .filter(|h| h.ip.is_ipv4() || is_public(h.ip))
            .take(MAX_BOUND)
            .map(|h| (Some(h.iface.clone()), h.ip)),
    );

    let paths = std::thread::scope(|s| {
        let jobs: Vec<_> = binds
            .into_iter()
            .map(|(iface, local)| {
                let resolved = &resolved;
                s.spawn(move || probe(iface, local, resolved, judge, cancel))
            })
            .collect();
        jobs.into_iter().filter_map(|j| j.join().ok()).collect()
    });

    WebRtcReport { paths, hosts, egress, unresolved }
}

/// 网卡地址里浏览器会当作候选的：去掉回环、未指定、IPv4 链路本地（169.254）、IPv6 链路本地（fe80::）。
fn candidate(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => !(v.is_loopback() || v.is_unspecified() || v.is_link_local()),
        IpAddr::V6(v) => !(v.is_loopback() || v.is_unspecified() || (v.segments()[0] & 0xffc0) == 0xfe80),
    }
}

fn probe(
    iface: Option<String>,
    local: IpAddr,
    servers: &[(String, Vec<SocketAddr>)],
    judge: &Judge,
    cancel: &(dyn Fn() -> bool + Sync),
) -> StunPath {
    let mut path = StunPath { iface, local, mapped: None, server: None, error: None, verdict: Verdict::NoResponse };
    let sock = match UdpSocket::bind(SocketAddr::new(local, 0)) {
        Ok(s) => s,
        Err(e) => {
            path.error = Some(format!("无法绑定本地地址：{e}"));
            return path;
        }
    };
    let mut last = None;
    let mut tried = 0;
    for (name, addrs) in servers {
        for a in addrs.iter().filter(|a| a.is_ipv4() == local.is_ipv4()) {
            if cancel() {
                path.error = Some("测试已取消".into());
                return path;
            }
            tried += 1;
            match stun::query(&sock, *a, PER_SERVER, cancel) {
                Ok(m) => {
                    path.mapped = Some(m);
                    path.server = Some(name.clone());
                    path.verdict = judge.mapped(m.ip());
                    return path;
                }
                Err(e) => last = Some(format!("{e:#}")),
            }
        }
    }
    path.error = Some(match last {
        Some(e) if tried > 1 => format!("{tried} 个 STUN 服务器都没有结果（最后一个：{e}）"),
        Some(e) => e,
        None => if local.is_ipv4() { "没有可用的 IPv4 STUN 服务器" } else { "没有可用的 IPv6 STUN 服务器" }.to_owned(),
    });
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancelled_run_sends_nothing() {
        let r = run(&["stun.example.invalid:3478".into()], None, &Judge::default(), &|| true);
        assert!(r.unresolved.iter().all(|u| u.contains("已取消")), "{:?}", r.unresolved);
        assert!(r.paths.iter().all(|p| p.mapped.is_none()));
    }

    fn path(iface: Option<&str>, mapped: Option<&str>) -> StunPath {
        StunPath {
            iface: iface.map(Into::into),
            local: "0.0.0.0".parse().unwrap(),
            mapped: mapped.map(|m| SocketAddr::new(m.parse().unwrap(), 5000)),
            server: None,
            error: None,
            verdict: Verdict::NoResponse,
        }
    }

    #[test]
    fn judging_and_summary() {
        let r = WebRtcReport {
            paths: vec![
                path(None, Some("203.0.113.7")),
                path(Some("WLAN"), Some("198.51.100.9")),
                path(Some("以太网"), Some("198.51.100.9")),
                path(Some("VPN"), None),
            ],
            hosts: vec![
                HostAddr { iface: "WLAN".into(), ip: "192.168.1.5".parse().unwrap(), verdict: Verdict::NoResponse },
                HostAddr { iface: "WLAN".into(), ip: "2001:db8:5::1".parse().unwrap(), verdict: Verdict::NoResponse },
            ],
            egress: None,
            unresolved: vec![],
        };
        let j = Judge::from_strings(&["203.0.113.0/24".to_owned()], &[]);
        let r = r.judged(&j);
        assert_eq!(r.paths[0].verdict, Verdict::Whitelisted);
        assert_eq!(r.paths[1].verdict, Verdict::Leak);
        assert_eq!(r.paths[3].verdict, Verdict::NoResponse);
        assert_eq!(r.leaked_ips(), vec!["198.51.100.9".parse::<IpAddr>().unwrap()]);
        assert_eq!(r.hosts[0].verdict, Verdict::Local);
        assert_eq!(r.exposed_hosts(), 1);
        assert!(r.any_response());
    }

    #[test]
    fn candidates() {
        assert!(candidate("192.168.1.5".parse().unwrap()));
        assert!(candidate("2001:db8::1".parse().unwrap()));
        assert!(!candidate("169.254.1.1".parse().unwrap()));
        assert!(!candidate("fe80::1".parse().unwrap()));
        assert!(!candidate("::".parse().unwrap()));
    }
}
