//! 泄露测试：检查域名解析（DNS）和 WebRTC 会不会绕过白名单出口、暴露真实 IP。
//!
//! - DNS（[`dns`]）：解析几个随机子域名，由 addr.tools 的 dnscheck 服务（开源，可自建）的权威服务器
//!   通过 WebSocket 实时告诉我们是哪些递归解析器来查询的，再与出口白名单、可信解析器对比。
//! - WebRTC（[`webrtc`]）：像浏览器收集 ICE 候选地址那样，列出本机各网卡的地址（host 候选），
//!   并从默认路由和每个网卡分别向 STUN 服务器发送绑定请求（srflx 候选），看 UDP 从哪个公网 IP 出去。
//!
//! 测试只在用户手动点「开始测试」或运行 `egress-guard leak-test` 时进行，不会定时运行。

pub mod dns;
pub mod ifaces;
pub mod stun;
pub mod webrtc;

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use anyhow::{bail, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::config::{format_net, normalize, parse_net};

/// 可信 DNS 解析器：单个 IP、网段，或者整个自治系统（如 Cloudflare 的 `AS13335`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trusted {
    Net(IpNet),
    Asn(u32),
}

impl Trusted {
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.get(..2).is_some_and(|p| p.eq_ignore_ascii_case("as")) {
            return match s[2..].parse::<u32>() {
                Ok(n) => Ok(Trusted::Asn(n)),
                Err(_) => bail!("无法解析为 IP、CIDR 或自治系统号（如 AS13335）: {s:?}"),
            };
        }
        match parse_net(s) {
            Ok(net) => Ok(Trusted::Net(net)),
            Err(_) => bail!("无法解析为 IP、CIDR 或自治系统号（如 AS13335）: {s:?}"),
        }
    }

    fn matches(&self, ip: IpAddr, asn: Option<u32>) -> bool {
        match self {
            Trusted::Net(net) => net.contains(&normalize(ip)),
            Trusted::Asn(a) => asn == Some(*a),
        }
    }
}

impl fmt::Display for Trusted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Trusted::Net(n) => f.write_str(&format_net(n)),
            Trusted::Asn(a) => write!(f, "AS{a}"),
        }
    }
}

/// DNS 测试服务的域名是否合法（只允许字母、数字、连字符组成的多级域名）。
pub fn valid_zone(zone: &str) -> bool {
    zone.len() <= 200
        && zone.contains('.')
        && zone.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// 单个结果的判定。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// 在出口 IP 白名单内。
    Whitelisted,
    /// 在可信 DNS 解析器列表内。
    Trusted,
    /// 与当前出口 IP 属于同一个自治系统（运营商 / VPN 服务商），且当前出口在白名单内。
    SameNetwork,
    /// 局域网地址（只在本地网络可见）。
    Local,
    /// 网卡上的公网地址：网页获得摄像头/麦克风权限时可以读到。
    Exposed,
    /// 不在白名单：可能泄露。
    Leak,
    /// STUN 无响应（这条路发不出去，也就不会泄露）。
    NoResponse,
}

impl Verdict {
    pub fn is_leak(self) -> bool {
        self == Verdict::Leak
    }

    pub fn ok(self) -> bool {
        matches!(self, Verdict::Whitelisted | Verdict::Trusted | Verdict::SameNetwork)
    }

    /// 界面上的简短说明。
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Whitelisted => "白名单内",
            Verdict::Trusted => "可信",
            Verdict::SameNetwork => "与出口同网络",
            Verdict::Local => "局域网",
            Verdict::Exposed => "公网地址",
            Verdict::Leak => "可能泄露",
            Verdict::NoResponse => "无响应",
        }
    }
}

/// 测试结论的级别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Level {
    /// 未发现泄露。
    Ok,
    /// 没有直接泄露，但有需要留意的地方。
    Warn,
    /// 发现泄露。
    Leak,
}

/// DNS 测试的一句话结论。
pub fn dns_summary(r: &dns::DnsReport) -> (Level, String) {
    let leaky = r.resolvers.iter().filter(|x| x.verdict.is_leak()).count();
    let ecs = r.client_subnets.iter().filter(|x| x.verdict.is_leak()).count();
    match (leaky, ecs) {
        (0, 0) => (Level::Ok, format!("未发现泄露：{} 个解析器都经白名单出口或可信", r.resolvers.len())),
        (n, 0) => (Level::Leak, format!("发现 {n} 个白名单以外的解析器，域名查询可能绕过了白名单出口")),
        (0, m) => (Level::Leak, format!("解析器向外透露了 {m} 个白名单以外的客户端网段（ECS）")),
        (n, m) => (Level::Leak, format!("发现 {n} 个白名单以外的解析器，并透露了 {m} 个客户端网段（ECS）")),
    }
}

/// WebRTC 测试的一句话结论。
pub fn webrtc_summary(r: &webrtc::WebRtcReport) -> (Level, String) {
    let leaked = r.leaked_ips();
    let exposed = r.exposed_hosts();
    if !leaked.is_empty() {
        let ips = leaked.iter().map(|i| i.to_string()).collect::<Vec<_>>().join("、");
        (Level::Leak, format!("WebRTC 会暴露白名单以外的公网 IP：{ips}"))
    } else if exposed > 0 {
        (Level::Warn, format!("网卡上有 {exposed} 个白名单以外的公网地址，网页获得摄像头/麦克风权限后可以读到"))
    } else if !r.any_response() {
        (Level::Ok, "STUN 服务器都没有响应：UDP 无法直接连到外网，WebRTC 不会暴露公网 IP".into())
    } else {
        (Level::Ok, "未发现泄露：WebRTC 能看到的公网 IP 都在白名单内".into())
    }
}

/// 判定依据：出口 IP 白名单与可信解析器。
#[derive(Debug, Clone, Default)]
pub struct Judge {
    pub whitelist: Vec<IpNet>,
    pub trusted: Vec<Trusted>,
}

impl Judge {
    /// 从（可能正在编辑、尚未校验的）配置文字构造；无法解析的条目忽略。
    pub fn from_strings<'a>(
        whitelist: impl IntoIterator<Item = &'a String>,
        trusted: impl IntoIterator<Item = &'a String>,
    ) -> Self {
        Self {
            whitelist: whitelist.into_iter().filter_map(|s| parse_net(s).ok()).collect(),
            trusted: trusted.into_iter().filter_map(|s| Trusted::parse(s).ok()).collect(),
        }
    }

    pub fn whitelisted(&self, ip: IpAddr) -> bool {
        let ip = normalize(ip);
        self.whitelist.iter().any(|n| n.contains(&ip))
    }

    /// 递归解析器（权威服务器看到的查询来源）。
    ///
    /// `egress` 是测试时的出口 IP 及其自治系统号：解析器与出口同属一个自治系统、而出口又在白名单内，
    /// 说明查询和其他流量走的是同一家（多半是 VPN 服务商自己的解析器）。
    pub fn resolver(&self, ip: IpAddr, asn: Option<u32>, egress: Option<(IpAddr, Option<u32>)>) -> Verdict {
        if self.whitelisted(ip) {
            Verdict::Whitelisted
        } else if self.trusted.iter().any(|t| t.matches(ip, asn)) {
            Verdict::Trusted
        } else if let (Some(a), Some((eip, Some(ea)))) = (asn, egress) {
            if a == ea && self.whitelisted(eip) {
                Verdict::SameNetwork
            } else {
                Verdict::Leak
            }
        } else if !is_public(ip) {
            Verdict::Local
        } else {
            Verdict::Leak
        }
    }

    /// 解析器转发给权威服务器的客户端网段（EDNS Client Subnet）。
    /// 这是解析器看到的「你」的网段：它与白名单或出口不重合，说明查询是从白名单以外的出口发给解析器的。
    pub fn client_subnet(&self, subnet: IpNet, egress: Option<IpAddr>) -> Verdict {
        let overlaps = |n: &IpNet| n.contains(&subnet.network()) || subnet.contains(&n.network());
        if self.whitelist.iter().any(overlaps) || egress.is_some_and(|e| subnet.contains(&normalize(e))) {
            Verdict::Whitelisted
        } else {
            Verdict::Leak
        }
    }

    /// STUN 返回的公网地址（WebRTC srflx 候选）。
    pub fn mapped(&self, ip: IpAddr) -> Verdict {
        if self.whitelisted(ip) {
            Verdict::Whitelisted
        } else {
            Verdict::Leak
        }
    }

    /// 网卡上的地址（WebRTC host 候选）。
    pub fn host(&self, ip: IpAddr) -> Verdict {
        if !is_public(ip) {
            Verdict::Local
        } else if self.whitelisted(ip) {
            Verdict::Whitelisted
        } else {
            Verdict::Exposed
        }
    }
}

/// 是否为公网地址（不是私有、回环、链路本地、运营商级 NAT、组播等特殊地址）。
pub fn is_public(ip: IpAddr) -> bool {
    match normalize(ip) {
        IpAddr::V4(v) => {
            let o = v.octets();
            !(v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_unspecified()
                || v.is_broadcast()
                || v.is_multicast()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xC0) == 64)
                || (o[0] == 198 && (o[1] & 0xFE) == 18)
                || o[0] >= 240)
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            // 全球单播 2000::/3
            (s[0] & 0xE000) == 0x2000
        }
    }
}

/// 随机数（不需要密码学强度：只用来生成测试 ID 和 STUN 事务 ID）。
pub fn random_u64() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    h.write_u128(now.as_nanos());
    h.write_u32(std::process::id());
    h.finish()
}

/// IP 的归属信息（来自 ip.addr.tools）。
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
pub struct IpInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub city: Option<String>,
}

impl IpInfo {
    /// 「Google LLC · AS15169 · US」这样的一行说明。
    pub fn describe(&self) -> String {
        let place = [&self.city, &self.region, &self.country]
            .iter()
            .filter_map(|x| x.as_deref())
            .filter(|x| !x.is_empty())
            .collect::<Vec<_>>()
            .join(", ");
        [self.org.clone(), self.asn.map(|a| format!("AS{a}")), (!place.is_empty()).then_some(place)]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" · ")
    }
}

/// 同时进行的归属查询数上限（解析器可能有几十个，不要一下子开几十个连接）。
const LOOKUP_PARALLEL: usize = 8;

/// 查询多个 IP 的归属（并行，失败的为 None）。
pub fn lookup_info(ips: &[IpAddr]) -> Vec<Option<IpInfo>> {
    use ureq::tls::{TlsConfig, TlsProvider};
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .tls_config(TlsConfig::builder().provider(TlsProvider::NativeTls).build())
        .timeout_global(Some(Duration::from_secs(6)))
        .user_agent(concat!("egress-guard/", env!("CARGO_PKG_VERSION")))
        .build()
        .into();
    // 同一个 IP 只查一次（例如 ECS 网段与出口相同时）
    let mut uniq: Vec<IpAddr> = ips.to_vec();
    uniq.sort();
    uniq.dedup();
    let found = parallel_map(&uniq, LOOKUP_PARALLEL, |ip| -> Option<IpInfo> {
        let body = agent
            .get(&format!("https://ip.addr.tools/{ip}"))
            .header("Accept", "application/json")
            .call()
            .ok()?
            .body_mut()
            .with_config()
            .limit(16 * 1024)
            .read_to_string()
            .ok()?;
        serde_json::from_str(&body).ok()
    });
    ips.iter().map(|ip| uniq.binary_search(ip).ok().and_then(|i| found[i].clone().flatten())).collect()
}

/// 用最多 `workers` 个线程对每一项执行 `f`，结果按原顺序返回（线程异常退出时对应项为 None）。
fn parallel_map<T: Sync, R: Send>(items: &[T], workers: usize, f: impl Fn(&T) -> R + Sync) -> Vec<Option<R>> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let next = AtomicUsize::new(0);
    let done: Vec<(usize, R)> = std::thread::scope(|s| {
        let jobs: Vec<_> = (0..workers.min(items.len()))
            .map(|_| {
                s.spawn(|| {
                    let mut done = Vec::new();
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some(item) = items.get(i) else { break };
                        done.push((i, f(item)));
                    }
                    done
                })
            })
            .collect();
        jobs.into_iter().flat_map(|j| j.join().unwrap_or_default()).collect()
    });
    let mut out: Vec<Option<R>> = items.iter().map(|_| None).collect();
    for (i, r) in done {
        out[i] = Some(r);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn trusted_entries() {
        assert_eq!(Trusted::parse("AS13335").unwrap(), Trusted::Asn(13335));
        assert_eq!(Trusted::parse(" as15169 ").unwrap().to_string(), "AS15169");
        assert_eq!(Trusted::parse("aS64500").unwrap(), Trusted::Asn(64500));
        assert_eq!(Trusted::parse("1.1.1.1").unwrap().to_string(), "1.1.1.1");
        assert_eq!(Trusted::parse("172.70.9.9/16").unwrap().to_string(), "172.70.0.0/16");
        assert!(Trusted::parse("AS").is_err());
        assert!(Trusted::parse("ASdf").is_err());
        assert!(Trusted::parse("cloudflare").is_err());
    }

    #[test]
    fn zones() {
        assert!(valid_zone("dnscheck.tools"));
        assert!(valid_zone("dns-check.example.org"));
        assert!(!valid_zone("tools"));
        assert!(!valid_zone("a..b"));
        assert!(!valid_zone("-a.b"));
        assert!(!valid_zone("a b.c"));
        assert!(!valid_zone("a/b.c"));
    }

    #[test]
    fn public_addresses() {
        assert!(is_public(ip("8.8.8.8")));
        assert!(is_public(ip("203.0.113.5")));
        assert!(!is_public(ip("192.168.1.5")));
        assert!(!is_public(ip("10.8.0.2")));
        assert!(!is_public(ip("100.64.1.1")));
        assert!(!is_public(ip("169.254.3.3")));
        assert!(!is_public(ip("127.0.0.1")));
        assert!(is_public(ip("2001:db8::1")));
        assert!(!is_public(ip("fe80::1")));
        assert!(!is_public(ip("fd00::1")));
        assert!(!is_public(ip("::1")));
        assert!(is_public(ip("::ffff:8.8.4.4")));
    }

    #[test]
    fn judging() {
        let wl = vec!["203.0.113.0/24".to_owned(), "2001:db8:1::/48".to_owned()];
        let tr = vec!["AS13335".to_owned(), "9.9.9.9".to_owned(), "bad".to_owned()];
        let j = Judge::from_strings(&wl, &tr);
        assert_eq!(j.trusted.len(), 2);
        let egress = Some((ip("203.0.113.7"), Some(64500)));
        assert_eq!(j.resolver(ip("203.0.113.53"), None, egress), Verdict::Whitelisted);
        assert_eq!(j.resolver(ip("172.70.1.1"), Some(13335), egress), Verdict::Trusted);
        assert_eq!(j.resolver(ip("9.9.9.9"), None, None), Verdict::Trusted);
        assert_eq!(j.resolver(ip("198.51.100.53"), Some(64500), egress), Verdict::SameNetwork);
        // 出口本身不在白名单：同网络不算数
        assert_eq!(j.resolver(ip("198.51.100.53"), Some(64500), Some((ip("192.0.2.1"), Some(64500)))), Verdict::Leak);
        assert_eq!(j.resolver(ip("198.51.100.53"), Some(64501), egress), Verdict::Leak);
        assert_eq!(j.resolver(ip("198.51.100.53"), None, None), Verdict::Leak);

        let net = |s: &str| s.parse::<IpNet>().unwrap();
        assert_eq!(j.client_subnet(net("203.0.113.0/24"), None), Verdict::Whitelisted);
        assert_eq!(j.client_subnet(net("203.0.0.0/16"), None), Verdict::Whitelisted);
        assert_eq!(j.client_subnet(net("198.51.100.0/24"), Some(ip("198.51.100.9"))), Verdict::Whitelisted);
        assert_eq!(j.client_subnet(net("198.51.100.0/24"), Some(ip("203.0.113.7"))), Verdict::Leak);

        assert_eq!(j.mapped(ip("203.0.113.7")), Verdict::Whitelisted);
        assert_eq!(j.mapped(ip("2001:db8:1::5")), Verdict::Whitelisted);
        assert_eq!(j.mapped(ip("2001:db8:2::5")), Verdict::Leak);
        assert_eq!(j.host(ip("192.168.1.5")), Verdict::Local);
        assert_eq!(j.host(ip("2001:db8:1::5")), Verdict::Whitelisted);
        assert_eq!(j.host(ip("2001:db8:2::5")), Verdict::Exposed);
    }

    #[test]
    fn summaries() {
        use super::webrtc::{HostAddr, StunPath, WebRtcReport};
        let mut r = WebRtcReport { paths: vec![], hosts: vec![], egress: None, unresolved: vec![] };
        assert_eq!(webrtc_summary(&r).0, Level::Ok);
        r.hosts.push(HostAddr { iface: "en0".into(), ip: ip("2001:db8::9"), verdict: Verdict::Exposed });
        assert_eq!(webrtc_summary(&r).0, Level::Warn);
        r.paths.push(StunPath {
            iface: None,
            local: ip("0.0.0.0"),
            mapped: Some("198.51.100.9:4000".parse().unwrap()),
            server: None,
            error: None,
            verdict: Verdict::Leak,
        });
        let (l, t) = webrtc_summary(&r);
        assert_eq!(l, Level::Leak);
        assert!(t.contains("198.51.100.9"), "{t}");
    }

    #[test]
    fn parallel_map_keeps_order() {
        let items: Vec<u32> = (0..37).collect();
        let out = parallel_map(&items, 8, |x| x * 2);
        assert_eq!(out, items.iter().map(|x| Some(x * 2)).collect::<Vec<_>>());
        assert!(parallel_map(&Vec::<u32>::new(), 8, |x| *x).is_empty());
    }

    #[test]
    fn info_line() {
        let i: IpInfo = serde_json::from_str(r#"{"ip":"8.8.8.8","asn":15169,"org":"Google LLC","country":"US"}"#).unwrap();
        assert_eq!(i.describe(), "Google LLC · AS15169 · US");
        assert_eq!(IpInfo::default().describe(), "");
    }
}
