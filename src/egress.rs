//! 通过公网 IP 查询服务检测本机出口 IP。

use std::net::IpAddr;
use std::time::Duration;

use anyhow::{anyhow, Result};
use ureq::config::IpFamily;

use crate::config::{Config, Ipv6Mode};
use crate::controller::Egress;
use ureq::tls::{TlsConfig, TlsProvider};
use ureq::Agent;

/// 检测用的地址族。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// 按系统默认（通常 IPv6 优先、不通时用 IPv4），依次尝试各服务。
    Any,
    /// 只走 IPv4（「始终阻断 IPv6」时：应用的流量只能走 IPv4，出口也只看 IPv4；
    /// 而且 IPv6 被防火墙丢弃，按默认顺序先试 IPv6 地址会一直等到超时）。
    V4,
    /// 只走 IPv6，同时请求各服务，第一个成功的结果生效（IPv6 不通时尽快结束）。
    V6,
}

impl Family {
    /// 主出口检测用的地址族：「始终阻断 IPv6」时只走 IPv4，其余按系统默认。
    pub fn for_main(mode: crate::config::Ipv6Mode) -> Self {
        if mode == crate::config::Ipv6Mode::Block {
            Family::V4
        } else {
            Family::Any
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Family::Any => "any",
            Family::V4 => "v4",
            Family::V6 => "v6",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "any" => Some(Family::Any),
            "v4" => Some(Family::V4),
            "v6" => Some(Family::V6),
            _ => None,
        }
    }
}

pub struct EgressDetector {
    agent: Agent,
    services: Vec<String>,
    family: Family,
    #[cfg_attr(windows, allow(dead_code))]
    timeout: Duration,
}

impl EgressDetector {
    pub fn new(services: Vec<String>, timeout: Duration) -> Self {
        Self::with_family(services, timeout, Family::Any)
    }

    pub fn with_family(services: Vec<String>, timeout: Duration, family: Family) -> Self {
        let agent: Agent = Agent::config_builder()
            // 使用系统 TLS（Windows 上为 SChannel，macOS 上为 Security.framework），无需额外证书
            .tls_config(TlsConfig::builder().provider(TlsProvider::NativeTls).build())
            .timeout_global(Some(timeout))
            .ip_family(match family {
                Family::Any => IpFamily::Any,
                Family::V4 => IpFamily::Ipv4Only,
                Family::V6 => IpFamily::Ipv6Only,
            })
            .user_agent(concat!("egress-guard/", env!("CARGO_PKG_VERSION")))
            // 出口检测决定是否放行直连的受控应用，必须看本机直连的出口：
            // 不能用环境变量里的代理（ureq 默认会读 HTTP(S)_PROXY / ALL_PROXY），否则可能测到的是代理的出口
            .proxy(None)
            // 不复用连接：网络变化后旧连接可能还走着原来的路由
            .max_idle_connections(0)
            .max_idle_connections_per_host(0)
            .build()
            .into();
        Self { agent, services, family, timeout }
    }

    /// 检测出口 IP。
    ///
    /// macOS 上以 root 运行时（后台服务），检测放在以 `nobody` 身份运行的子进程中进行：
    /// 全局断网的 pf 规则按套接字所属用户放行它，而不必放行所有 root 进程。
    pub fn detect(&self) -> Result<IpAddr> {
        #[cfg(target_os = "macos")]
        if unsafe { libc::geteuid() } == 0 {
            return self.detect_unprivileged();
        }
        self.detect_direct()
    }

    /// 在子进程中以 nobody 身份检测（子进程运行 `egress-guard probe`）。
    #[cfg(unix)]
    pub fn detect_unprivileged(&self) -> Result<IpAddr> {
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};
        use std::time::Instant;

        let (uid, gid) = unsafe {
            let pw = libc::getpwnam(c"nobody".as_ptr());
            if pw.is_null() {
                return Err(anyhow!("系统中没有 nobody 用户"));
            }
            ((*pw).pw_uid, (*pw).pw_gid)
        };
        let exe = std::env::current_exe()?;
        let mut child = Command::new(exe)
            .arg("probe")
            .arg("--timeout")
            .arg(self.timeout.as_secs().max(1).to_string())
            .arg("--family")
            .arg(self.family.name())
            .args(&self.services)
            .uid(uid)
            .gid(gid)
            .env("HOME", "/var/empty")
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow!("无法启动检测子进程: {e}"))?;
        // 每个服务最多 timeout（IPv6 同时请求，总共最多 timeout），再留一些余量
        let n = if self.family == Family::V6 { 1 } else { (self.services.len() as u32).max(1) };
        let deadline = Instant::now() + self.timeout * n + Duration::from_secs(5);
        loop {
            if child.try_wait()?.is_some() {
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(anyhow!("检测子进程超时"));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let out = child.wait_with_output()?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        if out.status.success() {
            if let Ok(ip) = stdout.trim().parse() {
                return Ok(ip);
            }
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        let msg = stderr.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("检测子进程异常退出");
        Err(anyhow!("{}", msg.trim()))
    }

    /// 先看本机有没有这个地址族的路由，再检测出口。只用于 V4、V6。
    pub fn probe(&self) -> Probe {
        let v6 = match self.family {
            Family::V4 => false,
            Family::V6 => true,
            Family::Any => {
                return match self.detect() {
                    Ok(ip) => Probe::Verified(ip),
                    Err(e) => Probe::Failed(format!("{e:#}")),
                }
            }
        };
        if !has_route(v6) {
            return Probe::NoRoute;
        }
        match self.detect() {
            Ok(ip) => Probe::Verified(ip),
            Err(e) => Probe::Failed(format!("{e:#}")),
        }
    }

    /// 依次尝试各服务（IPv6 时同时请求），返回第一个成功解析的出口 IP。
    pub fn detect_direct(&self) -> Result<IpAddr> {
        if self.family == Family::V6 {
            return self.detect_parallel();
        }
        let mut errors = Vec::new();
        for url in &self.services {
            match self.query(url).and_then(|ip| self.check_family(ip)) {
                Ok(ip) => {
                    log::debug!("{url} 返回出口 IP {ip}");
                    return Ok(ip);
                }
                Err(e) => {
                    log::debug!("{url} 查询失败: {e:#}");
                    errors.push(format!("{url}: {e}"));
                }
            }
        }
        Err(anyhow!("所有出口 IP 服务均失败: {}", errors.join("; ")))
    }

    /// 同时请求所有服务，第一个成功的结果立即返回（其余请求在后台自行超时结束）；全部失败时返回所有错误。
    fn detect_parallel(&self) -> Result<IpAddr> {
        let (tx, rx) = std::sync::mpsc::channel();
        for url in &self.services {
            let (tx, agent, url) = (tx.clone(), self.agent.clone(), url.clone());
            std::thread::spawn(move || {
                let r = query(&agent, &url);
                let _ = tx.send((url, r));
            });
        }
        drop(tx);
        let mut errors = Vec::new();
        for (url, r) in rx.iter() {
            match r.and_then(|ip| self.check_family(ip)) {
                Ok(ip) => {
                    log::debug!("{url} 返回出口 IP {ip}");
                    return Ok(ip);
                }
                Err(e) => errors.push(format!("{url}: {e}")),
            }
        }
        Err(anyhow!("所有出口 IP 服务均失败: {}", errors.join("; ")))
    }

    fn query(&self, url: &str) -> Result<IpAddr> {
        query(&self.agent, url)
    }

    /// 只走某个地址族时，服务返回的地址必须属于这个地址族（IPv4 映射地址算 IPv4）。
    fn check_family(&self, ip: IpAddr) -> Result<IpAddr> {
        let ip = crate::config::normalize(ip);
        match self.family {
            Family::V4 if !ip.is_ipv4() => Err(anyhow!("返回的不是 IPv4 地址（{ip}）")),
            Family::V6 if !ip.is_ipv6() => Err(anyhow!("返回的不是 IPv6 地址（{ip}）")),
            _ => Ok(ip),
        }
    }
}

/// 单个地址族的检测结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    /// 测到了这个地址族的出口。
    Verified(IpAddr),
    /// 本机没有这个地址族的可用路由（流量走不出去，不需要验证）。
    NoRoute,
    /// 有路由但检测失败（超时、DNS/TLS 错误等）：不知道这个地址族的流量从哪里出去。
    Failed(String),
}

/// 本机有没有通往公网的 IPv4 / IPv6 路由。
///
/// 用 UDP 套接字 connect 一个公网地址：只查路由表、不发任何数据包；没有路由时 connect 失败，
/// 或者系统只能选出未指定 / 链路本地的源地址。
pub fn has_route(v6: bool) -> bool {
    use std::net::UdpSocket;
    let (bind, target) =
        if v6 { ("[::]:0", "[2001:4860:4860::8888]:443") } else { ("0.0.0.0:0", "8.8.8.8:443") };
    let Ok(s) = UdpSocket::bind(bind) else { return false };
    if s.connect(target).is_err() {
        return false;
    }
    match s.local_addr().map(|a| a.ip()) {
        Ok(IpAddr::V4(a)) => !v6 && !a.is_unspecified() && !a.is_loopback() && !a.is_link_local(),
        Ok(IpAddr::V6(a)) => {
            // fe80::/10
            v6 && !a.is_unspecified() && !a.is_loopback() && (a.segments()[0] & 0xffc0) != 0xfe80
        }
        Err(_) => false,
    }
}

/// 「检测 IPv6 出口」时把 IPv4、IPv6 两个地址族各自的检测结果合成一次检测结果。
///
/// - 每个有路由的地址族都必须测到出口；有路由却测不到时不能放行（返回错误，按检测失败处理），
///   除非另一个地址族已经测到了不在白名单的出口（那样无论如何都要阻断）。
/// - 没有路由的地址族不需要验证；两个都没有路由时视为检测失败。
pub fn combine(v4: Probe, v6: Probe, whitelisted: impl Fn(IpAddr) -> bool) -> Result<Egress> {
    use Probe::*;
    match (v4, v6) {
        (Verified(a), Verified(b)) => Ok(Egress { ip: a, v6: Some(b) }),
        (Verified(a), NoRoute) => Ok(Egress { ip: a, v6: None }),
        (NoRoute, Verified(b)) => Ok(Egress { ip: b, v6: None }),
        (Verified(a), Failed(_)) if !whitelisted(a) => Ok(Egress { ip: a, v6: None }),
        (Failed(_), Verified(b)) if !whitelisted(b) => Ok(Egress { ip: b, v6: None }),
        (Verified(_), Failed(e)) => Err(anyhow!(
            "IPv6 出口检测失败（本机有 IPv6 路由，无法确认 IPv6 流量从哪里出去）：{e}。\
             如果 VPN 不支持 IPv6，可以在设置里把 IPv6 改为「始终阻断」"
        )),
        (Failed(e), Verified(_)) => Err(anyhow!("IPv4 出口检测失败（本机有 IPv4 路由）：{e}")),
        (Failed(e), NoRoute) | (NoRoute, Failed(e)) => Err(anyhow!("{e}")),
        (Failed(a), Failed(b)) => Err(anyhow!("IPv4：{a}；IPv6：{b}")),
        (NoRoute, NoRoute) => Err(anyhow!("本机没有可用的 IPv4、IPv6 网络")),
    }
}

/// 引擎和 `egress-guard ip` 共用的出口检测：按 IPv6 处理方式选地址族。
pub struct Detectors {
    mode: Ipv6Mode,
    main: EgressDetector,
    v6: Option<EgressDetector>,
    whitelist: Vec<ipnet::IpNet>,
}

impl Detectors {
    pub fn new(cfg: &Config) -> Self {
        let timeout = Duration::from_secs(cfg.detect.timeout_secs);
        let mode = cfg.ipv6.mode;
        let main_family = match mode {
            // 检测 IPv6 出口 / 始终阻断 IPv6：IPv4 单独验证
            Ipv6Mode::Check | Ipv6Mode::Block => Family::V4,
            Ipv6Mode::Off => Family::Any,
        };
        Self {
            mode,
            main: EgressDetector::with_family(cfg.detect.services.clone(), timeout, main_family),
            v6: (mode == Ipv6Mode::Check)
                .then(|| EgressDetector::with_family(cfg.ipv6.services.clone(), timeout, Family::V6)),
            whitelist: cfg.whitelist.clone(),
        }
    }

    fn whitelisted(&self, ip: IpAddr) -> bool {
        let ip = crate::config::normalize(ip);
        self.whitelist.iter().any(|n| n.contains(&ip))
    }

    /// 检测一次。「检测 IPv6 出口」时 IPv4、IPv6 同时检测。
    pub fn detect(&self) -> Result<Egress> {
        match self.mode {
            Ipv6Mode::Off => Ok(Egress { ip: self.main.detect()?, v6: None }),
            Ipv6Mode::Block => match self.main.probe() {
                Probe::Verified(ip) => Ok(Egress { ip, v6: None }),
                Probe::NoRoute => Err(anyhow!("本机没有可用的 IPv4 网络（IPv6 已设为始终阻断）")),
                Probe::Failed(e) => Err(anyhow!("{e}")),
            },
            Ipv6Mode::Check => {
                let v6det = self.v6.as_ref().expect("检测 IPv6 出口时有 IPv6 检测器");
                let (v4, v6) = std::thread::scope(|s| {
                    let h = s.spawn(|| v6det.probe());
                    let v4 = self.main.probe();
                    // 线程 panic 也算检测失败，而不是「没有 IPv6」
                    let v6 = h.join().unwrap_or_else(|_| Probe::Failed("IPv6 检测线程异常退出".into()));
                    (v4, v6)
                });
                log::debug!("出口检测：IPv4 {v4:?}，IPv6 {v6:?}");
                combine(v4, v6, |ip| self.whitelisted(ip))
            }
        }
    }
}

fn query(agent: &Agent, url: &str) -> Result<IpAddr> {
    let body = agent.get(url).call()?.body_mut().with_config().limit(4096).read_to_string()?;
    extract_ip(&body).ok_or_else(|| anyhow!("响应中没有 IP: {:?}", truncate(&body)))
}

/// 从响应文本中提取第一个合法 IP。兼容纯文本（"1.2.3.4\n"）
/// 和带说明文字的响应（如 "当前 IP：1.2.3.4 来自于：…"）。
pub fn extract_ip(body: &str) -> Option<IpAddr> {
    body.split(|c: char| !(c.is_ascii_hexdigit() || c == '.' || c == ':'))
        .filter(|t| !t.is_empty())
        .find_map(|t| t.trim_matches(|c| c == '.' || c == ':').parse().ok())
}

fn truncate(s: &str) -> String {
    s.chars().take(80).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_plain_and_decorated() {
        assert_eq!(extract_ip("203.0.113.5\n"), Some("203.0.113.5".parse().unwrap()));
        assert_eq!(
            extract_ip("当前 IP：198.51.100.7  来自于：中国"),
            Some("198.51.100.7".parse().unwrap())
        );
        assert_eq!(extract_ip("2001:db8::1"), Some("2001:db8::1".parse().unwrap()));
        assert_eq!(extract_ip("ip=203.0.113.9."), Some("203.0.113.9".parse().unwrap()));
        assert_eq!(extract_ip("<html>error</html>"), None);
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn combine_requires_every_routed_family() {
        use Probe::*;
        let wl = |i: IpAddr| i == ip("203.0.113.9") || i == ip("2001:db8::9");
        let v4 = || Verified(ip("203.0.113.9"));
        let v6 = || Verified(ip("2001:db8::9"));
        let bad4 = || Verified(ip("198.51.100.1"));
        let fail = || Failed("超时".into());
        // 双栈：两个都测到
        assert_eq!(combine(v4(), v6(), wl).unwrap(), Egress { ip: ip("203.0.113.9"), v6: Some(ip("2001:db8::9")) });
        // 单栈
        assert_eq!(combine(v4(), NoRoute, wl).unwrap(), Egress { ip: ip("203.0.113.9"), v6: None });
        assert_eq!(combine(NoRoute, v6(), wl).unwrap(), Egress { ip: ip("2001:db8::9"), v6: None });
        // IPv4 在白名单，但有 IPv6 路由却测不到：不能放行
        let e = combine(v4(), fail(), wl).unwrap_err().to_string();
        assert!(e.contains("IPv6 出口检测失败"), "{e}");
        assert!(combine(fail(), v6(), wl).is_err());
        // 另一个地址族已经不在白名单：直接给出结果（反正要阻断）
        assert_eq!(combine(bad4(), fail(), wl).unwrap().ip, ip("198.51.100.1"));
        // 双栈出口相反：IPv4 在白名单、IPv6 不在
        let r = combine(v4(), Verified(ip("2001:db8:ffff::1")), wl).unwrap();
        assert_eq!(r.v6, Some(ip("2001:db8:ffff::1")));
        assert!(combine(NoRoute, NoRoute, wl).is_err());
        assert!(combine(fail(), NoRoute, wl).is_err());
        assert!(combine(fail(), fail(), wl).is_err());
    }

    #[test]
    fn family_of_answer_is_checked() {
        let d4 = EgressDetector::with_family(vec![], Duration::from_secs(1), Family::V4);
        assert!(d4.check_family(ip("2001:db8::1")).is_err());
        assert_eq!(d4.check_family(ip("::ffff:203.0.113.5")).unwrap(), ip("203.0.113.5"));
        let d6 = EgressDetector::with_family(vec![], Duration::from_secs(1), Family::V6);
        assert!(d6.check_family(ip("203.0.113.5")).is_err());
        assert!(d6.check_family(ip("::ffff:203.0.113.5")).is_err());
        assert!(d6.check_family(ip("2001:db8::1")).is_ok());
    }

    /// 环境变量里的代理不能影响出口检测：用本地假代理（返回代理出口）和假探测服务（返回直连出口）验证。
    #[test]
    fn ignores_proxy_from_environment() {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;

        fn serve(body: &'static str) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = l.local_addr().unwrap();
            let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let h = hits.clone();
            std::thread::spawn(move || {
                for c in l.incoming().flatten() {
                    h.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let mut r = BufReader::new(c.try_clone().unwrap());
                    let mut line = String::new();
                    while r.read_line(&mut line).is_ok_and(|n| n > 2) {
                        line.clear();
                    }
                    let mut c = c;
                    let _ = write!(c, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                }
            });
            (format!("http://{addr}"), hits)
        }
        let (proxy, proxy_hits) = serve("203.0.113.9"); // 代理的出口（在白名单）
        let (direct, _) = serve("198.51.100.1"); // 直连的出口（不在白名单）
        // 测试进程里其他测试不读这些变量
        for k in ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
            std::env::set_var(k, &proxy);
        }
        std::env::remove_var("NO_PROXY");
        std::env::remove_var("no_proxy");
        let d = EgressDetector::with_family(vec![format!("{direct}/ip")], Duration::from_secs(5), Family::Any);
        let got = d.detect_direct();
        for k in ["HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
            std::env::remove_var(k);
        }
        assert_eq!(got.unwrap(), ip("198.51.100.1"));
        assert_eq!(proxy_hits.load(std::sync::atomic::Ordering::SeqCst), 0, "不应经过代理");
    }
}
