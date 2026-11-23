//! 通过公网 IP 查询服务检测本机出口 IP。

use std::net::IpAddr;
use std::time::Duration;

use anyhow::{anyhow, Result};
use ureq::config::IpFamily;

use crate::config::{redact_proxy, scrub_proxy, Config, Ipv6Mode};
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
    /// 用户在设置里明确填写的代理（默认没有：检测直连）。
    proxy: Option<String>,
    /// 代理地址无法解析时的错误：检测一律失败，而不是悄悄改为直连。
    proxy_error: Option<String>,
    #[cfg_attr(windows, allow(dead_code))]
    timeout: Duration,
}

impl EgressDetector {
    pub fn with_family(services: Vec<String>, timeout: Duration, family: Family) -> Self {
        Self::with_proxy(services, timeout, family, None)
    }

    /// `proxy` 为用户明确填写的代理地址（`http://`、`https://`、`socks5://` 等）；`None` 或空串时直连。
    pub fn with_proxy(services: Vec<String>, timeout: Duration, family: Family, proxy: Option<&str>) -> Self {
        let proxy = proxy.map(str::trim).filter(|p| !p.is_empty()).map(str::to_owned);
        let (parsed, proxy_error) = match proxy.as_deref().map(ureq::Proxy::new) {
            None => (None, None),
            Some(Ok(p)) => (Some(p), None),
            Some(Err(e)) => {
                let p = proxy.as_deref().unwrap_or_default();
                (None, Some(format!("代理地址有误（{}）：{}", redact_proxy(p), scrub_proxy(&e.to_string(), p))))
            }
        };
        let agent: Agent = Agent::config_builder()
            // 使用系统 TLS（Windows 上为 SChannel，macOS 上为 Security.framework），无需额外证书
            .tls_config(TlsConfig::builder().provider(TlsProvider::NativeTls).build())
            .timeout_global(Some(timeout))
            // 走代理时这里限制的是连到代理的地址族（代理多半在 127.0.0.1），出口的地址族由返回的地址校验
            .ip_family(match (family, proxy.is_some()) {
                (_, true) | (Family::Any, _) => IpFamily::Any,
                (Family::V4, false) => IpFamily::Ipv4Only,
                (Family::V6, false) => IpFamily::Ipv6Only,
            })
            .user_agent(concat!("egress-guard/", env!("CARGO_PKG_VERSION")))
            // 出口检测决定是否放行直连的受控应用，默认必须看本机直连的出口：
            // 不能用环境变量里的代理（ureq 默认会读 HTTP(S)_PROXY / ALL_PROXY），否则可能测到的是代理的出口。
            // 只有用户在设置里明确填写代理时才走代理
            .proxy(parsed)
            // 不复用连接：网络变化后旧连接可能还走着原来的路由
            .max_idle_connections(0)
            .max_idle_connections_per_host(0)
            .build()
            .into();
        Self { agent, services, family, proxy, proxy_error, timeout }
    }

    /// 是否通过代理检测。
    pub fn via_proxy(&self) -> bool {
        self.proxy.is_some()
    }

    /// 检测出口 IP。
    ///
    /// macOS 上以 root 运行时（后台服务），检测放在以 `nobody` 身份运行的子进程中进行：
    /// 全局断网的 pf 规则按套接字所属用户放行它，而不必放行所有 root 进程。
    pub fn detect(&self) -> Result<IpAddr> {
        if let Some(e) = &self.proxy_error {
            return Err(anyhow!("{e}"));
        }
        #[cfg(target_os = "macos")]
        if unsafe { libc::geteuid() } == 0 {
            return self.detect_unprivileged().map_err(|e| self.label(e));
        }
        self.detect_direct().map_err(|e| self.label(e))
    }

    /// 走代理时在错误前注明代理（用户名密码换成 ***），便于用户分辨是代理的问题。
    /// 错误会进入状态、日志和连接记录，第三方库的错误里可能带着代理凭据，一并遮掉。
    fn label(&self, e: anyhow::Error) -> anyhow::Error {
        match &self.proxy {
            Some(p) => anyhow!("通过代理 {} 检测：{}", redact_proxy(p), scrub_proxy(&format!("{e:#}"), p)),
            None => e,
        }
    }

    /// 遮掉文本里的代理凭据。
    fn scrub(&self, text: &str) -> String {
        match &self.proxy {
            Some(p) => scrub_proxy(text, p),
            None => text.to_owned(),
        }
    }

    /// 在子进程中以 nobody 身份检测（子进程运行 `egress-guard probe`）。
    #[cfg(unix)]
    pub fn detect_unprivileged(&self) -> Result<IpAddr> {
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};

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
            // 代理地址可能带密码：通过管道传给子进程，不放在命令行（其他账户能看到进程参数）
            .args(self.proxy.iter().map(|_| "--proxy-stdin"))
            .arg("--")
            .args(&self.services)
            .uid(uid)
            .gid(gid)
            .env("HOME", "/var/empty")
            .current_dir("/")
            .stdin(if self.proxy.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow!("无法启动检测子进程: {e}"))?;
        if let (Some(p), Some(mut stdin)) = (&self.proxy, child.stdin.take()) {
            use std::io::Write;
            // 一行，写完关闭；子进程只读这一行
            if let Err(e) = stdin.write_all(format!("{p}\n").as_bytes()) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(anyhow!("无法把代理设置传给检测子进程: {e}"));
            }
        }
        // 每个服务最多 timeout（IPv6 同时请求，总共最多 timeout），再留一些余量
        let n = if self.family == Family::V6 { 1 } else { (self.services.len() as u32).max(1) };
        let wait = self.timeout.saturating_mul(n).saturating_add(Duration::from_secs(5));
        // 在单独的线程里读完子进程的输出（子进程退出时管道关闭），这里阻塞等它，不再每 50ms 醒来看一次。
        // 子进程本身留在这里：超时时还没回收，PID 仍属于它，可以安全地结束它
        let (mut so, mut se) = (child.stdout.take(), child.stderr.take());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::Builder::new()
            .name("probe-read".into())
            .spawn(move || {
                use std::io::Read;
                let (mut out, mut err) = (Vec::new(), Vec::new());
                if let Some(p) = so.as_mut() {
                    let _ = p.read_to_end(&mut out);
                }
                if let Some(p) = se.as_mut() {
                    let _ = p.read_to_end(&mut err);
                }
                let _ = tx.send((out, err));
            })
            .map_err(|e| anyhow!("无法创建读取检测子进程输出的线程: {e}"))?;
        let Ok((stdout, stderr)) = rx.recv_timeout(wait.min(Duration::from_secs(3600))) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(anyhow!("检测子进程超时"));
        };
        let out = std::process::Output { status: child.wait()?, stdout, stderr };
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
        // 走代理时本机路由无关：要验证的是代理的出口，连不上代理、代理没有这个地址族的出口都算失败。
        // 判断不了有没有路由时照常检测：测不到就是 Failed，而不是当作没有路由跳过验证
        let route = if self.via_proxy() { Route::Yes } else { has_route(v6) };
        probe_with(v6, route, || self.detect())
    }

    /// 依次尝试各服务（IPv6 时同时请求），返回第一个成功解析的出口 IP。
    pub fn detect_direct(&self) -> Result<IpAddr> {
        if let Some(e) = &self.proxy_error {
            return Err(anyhow!("{e}"));
        }
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
                    log::debug!("{url} 查询失败: {}", self.scrub(&format!("{e:#}")));
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

/// 本机有没有某个地址族通往公网的路由。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// 系统为公网地址选出了可用的源地址。
    Yes,
    /// 确认没有：系统不支持这个地址族、没有通往公网的路由，或只能选出链路本地 / 未指定的源地址。
    No,
    /// 无法判断（权限、资源不足等临时错误）：不能当作「没有路由」而跳过验证，要按配置的服务实际检测。
    Unknown,
}

/// 按路由判断的结果决定是否检测：没有路由的地址族不需要验证，其余（包括判断不了的）都按配置的服务实际检测。
pub fn probe_with(v6: bool, route: Route, detect: impl FnOnce() -> Result<IpAddr>) -> Probe {
    match route {
        Route::Yes => {}
        Route::No => return Probe::NoRoute,
        Route::Unknown => log::debug!("无法确认本机有没有{}路由，按有路由检测", if v6 { " IPv6 " } else { " IPv4 " }),
    }
    match detect() {
        Ok(ip) => Probe::Verified(ip),
        Err(e) => Probe::Failed(format!("{e:#}")),
    }
}

/// 本机有没有通往公网的 IPv4 / IPv6 路由。
///
/// 用 UDP 套接字 connect 一个固定的公网地址：只查路由表、不发任何数据包。一个目的地不能代表整个地址族
/// （更具体的路由、VPN 分流、临时地址切换都可能让它单独不可达），所以只有系统级的证据才算没有路由：
/// 系统不支持这个地址族，或者本机根本没有这个地址族可用于公网的地址（IPv4：非回环、非链路本地；
/// IPv6：全球单播 2000::/3）。到这个目的地不可达、选不出可用的源地址，而本机又有这样的地址时是
/// [`Route::Unknown`]，照样按配置的服务检测。
pub fn has_route(v6: bool) -> Route {
    use std::net::UdpSocket;
    let (bind, target) =
        if v6 { ("[::]:0", "[2001:4860:4860::8888]:443") } else { ("0.0.0.0:0", "8.8.8.8:443") };
    let source = UdpSocket::bind(bind).and_then(|s| {
        s.connect(target)?;
        Ok(s.local_addr()?.ip())
    });
    classify_route(v6, source, || {
        crate::leaktest::ifaces::try_adapters().map(|a| a.into_iter().flat_map(|x| x.addrs).collect())
    })
}

/// [`has_route`] 的判断部分：`source` 是系统为固定目的地选出的源地址（或出错原因），
/// `addrs` 列出本机网卡上的地址（列不出时为 None）。
pub fn classify_route(
    v6: bool,
    source: std::io::Result<IpAddr>,
    addrs: impl FnOnce() -> Option<Vec<IpAddr>>,
) -> Route {
    let single = match &source {
        Ok(src) => route_from_source(v6, *src),
        Err(e) => route_error(e),
    };
    if single != Route::No {
        return single;
    }
    if let Err(e) = &source {
        if family_unsupported(e) {
            return Route::No;
        }
    }
    // 只是这一个目的地走不通：看本机还有没有这个地址族可用于公网的地址
    match addrs() {
        Some(list) if !list.iter().any(|a| usable_for_family(v6, *a)) => Route::No,
        Some(_) => {
            log::debug!("{}固定目的地不可达，但本机有可用地址，照常检测", if v6 { "IPv6 " } else { "IPv4 " });
            Route::Unknown
        }
        None => Route::Unknown,
    }
}

/// 本机地址能否用于这个地址族的公网通信。
fn usable_for_family(v6: bool, a: IpAddr) -> bool {
    match crate::config::normalize(a) {
        IpAddr::V4(a) => !v6 && !a.is_unspecified() && !a.is_loopback() && !a.is_link_local(),
        // 全球单播 2000::/3（ULA、链路本地都不能直接上公网）。休眠的 Teredo 隧道（2001::/32）
        // 在只有 IPv4 的 Windows 上也常带着地址，不算证据
        IpAddr::V6(a) => {
            let s = a.segments();
            v6 && (s[0] & 0xe000) == 0x2000 && !(s[0] == 0x2001 && s[1] == 0)
        }
    }
}

#[cfg(unix)]
const AF_NOT_SUPPORTED: [i32; 2] = [libc::EAFNOSUPPORT, libc::EPROTONOSUPPORT];
#[cfg(windows)]
const AF_NOT_SUPPORTED: [i32; 2] = [10047 /* WSAEAFNOSUPPORT */, 10043 /* WSAEPROTONOSUPPORT */];
#[cfg(not(any(unix, windows)))]
const AF_NOT_SUPPORTED: [i32; 0] = [];

/// 系统不支持这个地址族（例如关闭了 IPv6）。
fn family_unsupported(e: &std::io::Error) -> bool {
    e.raw_os_error().is_some_and(|c| AF_NOT_SUPPORTED.contains(&c))
}

/// 按系统为公网目的地选出的源地址判断。
pub fn route_from_source(v6: bool, src: IpAddr) -> Route {
    let usable = match src {
        IpAddr::V4(a) => !v6 && !a.is_unspecified() && !a.is_loopback() && !a.is_link_local(),
        // fe80::/10
        IpAddr::V6(a) => v6 && !a.is_unspecified() && !a.is_loopback() && (a.segments()[0] & 0xffc0) != 0xfe80,
    };
    if usable { Route::Yes } else { Route::No }
}

/// 单个目的地的错误：只有「地址族不受支持」和「网络 / 主机不可达、没有可用的源地址」才可能是没有路由
/// （后者还要看本机地址，见 [`classify_route`]）；其他错误（权限、资源不足等）是 [`Route::Unknown`]。
pub fn route_error(e: &std::io::Error) -> Route {
    use std::io::ErrorKind::*;
    if matches!(e.kind(), NetworkUnreachable | HostUnreachable | AddrNotAvailable) || family_unsupported(e) {
        Route::No
    } else {
        Route::Unknown
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
        (Verified(a), Verified(b)) => Ok(Egress::dual(a, Some(b))),
        (Verified(a), NoRoute) => Ok(Egress::dual(a, None)),
        (NoRoute, Verified(b)) => Ok(Egress::dual(b, None)),
        // 另一个地址族没测到：结果只够用来阻断，标记出来，之后改白名单时不能据此放行
        (Verified(a), Failed(_)) if !whitelisted(a) => Ok(Egress { ip: a, v6: None, v6_unverified: true }),
        (Failed(_), Verified(b)) if !whitelisted(b) => Ok(Egress { ip: b, v6: None, v6_unverified: true }),
        (Verified(_), Failed(e)) => Err(anyhow!(
            "IPv6 出口检测失败，无法确认 IPv6 流量从哪里出去：{e}。\
             如果 VPN 或代理不支持 IPv6，可以在设置里把 IPv6 改为「始终阻断」"
        )),
        (Failed(e), Verified(_)) => Err(anyhow!("IPv4 出口检测失败，无法确认 IPv4 流量从哪里出去：{e}")),
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
            main: EgressDetector::with_proxy(cfg.detect.services.clone(), timeout, main_family, Some(&cfg.detect.proxy)),
            v6: (mode == Ipv6Mode::Check)
                .then(|| EgressDetector::with_proxy(cfg.ipv6.services.clone(), timeout, Family::V6, Some(&cfg.detect.proxy))),
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
            Ipv6Mode::Off => Ok(Egress::v4(self.main.detect()?)),
            Ipv6Mode::Block => match self.main.probe() {
                Probe::Verified(ip) => Ok(Egress::v4(ip)),
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
        .find_map(parse_candidate)
}

/// 解析一个候选片段：先按完整地址解析（保留 `::`、末尾压缩和 IPv4 映射地址），
/// 不行时再去掉说明文字带来的外层标点（句尾的 `.`、「IP:」后面的 `:`）。
fn parse_candidate(t: &str) -> Option<IpAddr> {
    let ok = |ip: IpAddr| (!ip.is_unspecified()).then_some(ip);
    if let Ok(ip) = t.parse() {
        return ok(ip);
    }
    // 句尾的点：「…是 203.0.113.9.」「…是 2001:db8::.」
    let t = t.trim_end_matches('.');
    if let Ok(ip) = t.parse() {
        return ok(ip);
    }
    // 前面的点、单个冒号（「IP:2001:db8::1」）；`::` 开头 / 结尾是地址本身的一部分，不能去掉
    let t = t.trim_start_matches('.');
    let t = if t.starts_with("::") { t } else { t.strip_prefix(':').unwrap_or(t) };
    let t = if t.ends_with("::") { t } else { t.strip_suffix(':').unwrap_or(t) };
    t.parse().ok().and_then(ok)
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

    #[test]
    fn extracts_compressed_and_mapped_ipv6() {
        // 末尾压缩、IPv4 映射地址：以前会被去掉首尾的冒号而解析失败
        assert_eq!(extract_ip("2001:db8:1234::"), Some(ip("2001:db8:1234::")));
        assert_eq!(extract_ip("2001:db8:1234::\n"), Some(ip("2001:db8:1234::")));
        assert_eq!(extract_ip("::ffff:192.0.2.8"), Some(ip("::ffff:192.0.2.8")));
        // 映射地址规范化后按 IPv4 分类
        assert_eq!(crate::config::normalize(extract_ip("::ffff:192.0.2.8").unwrap()), ip("192.0.2.8"));
        let v4 = EgressDetector::with_family(vec![], Duration::from_secs(1), Family::V4);
        assert_eq!(v4.check_family(ip("::ffff:192.0.2.8")).unwrap(), ip("192.0.2.8"));
        let v6 = EgressDetector::with_family(vec![], Duration::from_secs(1), Family::V6);
        assert!(v6.check_family(ip("::ffff:192.0.2.8")).is_err());
        // 普通双栈地址、括号、句尾标点、前缀说明
        assert_eq!(extract_ip("2001:db8::9"), Some(ip("2001:db8::9")));
        assert_eq!(extract_ip("[2001:db8::9]:443"), Some(ip("2001:db8::9")));
        assert_eq!(extract_ip("你的地址是 2001:db8:1234::。"), Some(ip("2001:db8:1234::")));
        assert_eq!(extract_ip("addr 2001:db8:1234::."), Some(ip("2001:db8:1234::")));
        assert_eq!(extract_ip("IP:2001:db8::1"), Some(ip("2001:db8::1")));
        assert_eq!(extract_ip("ip: 203.0.113.7."), Some(ip("203.0.113.7")));
        // 错误文本、孤立的 `::` 不是出口地址
        assert_eq!(extract_ip("error: bad gateway"), None);
        assert_eq!(extract_ip("a :: b"), None);
    }

    #[test]
    fn route_errors_are_not_all_no_route() {
        use std::io::{Error, ErrorKind};
        assert_eq!(route_error(&Error::from(ErrorKind::NetworkUnreachable)), Route::No);
        assert_eq!(route_error(&Error::from(ErrorKind::HostUnreachable)), Route::No);
        assert_eq!(route_error(&Error::from(ErrorKind::AddrNotAvailable)), Route::No);
        // 权限、资源不足等临时错误：不知道，不能跳过验证
        assert_eq!(route_error(&Error::from(ErrorKind::PermissionDenied)), Route::Unknown);
        assert_eq!(route_error(&Error::other("资源不足")), Route::Unknown);
        #[cfg(unix)]
        {
            assert_eq!(route_error(&Error::from_raw_os_error(libc::EAFNOSUPPORT)), Route::No);
            assert_eq!(route_error(&Error::from_raw_os_error(libc::EMFILE)), Route::Unknown);
        }
        assert_eq!(route_from_source(false, ip("192.168.1.5")), Route::Yes);
        assert_eq!(route_from_source(false, ip("0.0.0.0")), Route::No);
        assert_eq!(route_from_source(false, ip("169.254.1.1")), Route::No);
        assert_eq!(route_from_source(true, ip("2001:db8::5")), Route::Yes);
        assert_eq!(route_from_source(true, ip("fe80::1")), Route::No);
        assert_eq!(route_from_source(true, ip("::")), Route::No);
    }

    /// 固定目的地不可达不能代表整个地址族：本机有可用地址时照常检测；只有系统级证据才跳过。
    #[test]
    fn single_destination_unreachable_is_not_no_route() {
        use std::io::{Error, ErrorKind};
        let unreachable = || Err(Error::from(ErrorKind::NetworkUnreachable));
        let addrs = |list: &'static [&'static str]| move || Some(list.iter().map(|a| ip(a)).collect::<Vec<_>>());
        // 有全球单播 IPv6 地址（例如 VPN 分流、只有更具体的路由）：不确定，要检测
        assert_eq!(classify_route(true, unreachable(), addrs(&["192.168.1.5", "fe80::1", "2001:db8::5"])), Route::Unknown);
        assert_eq!(classify_route(true, Err(Error::from(ErrorKind::AddrNotAvailable)), addrs(&["2001:db8::5"])), Route::Unknown);
        assert_eq!(classify_route(true, Ok(ip("fe80::1")), addrs(&["2001:db8::5"])), Route::Unknown);
        // 真单栈：只有链路本地 / ULA 的 IPv6，没有全球单播地址
        assert_eq!(classify_route(true, unreachable(), addrs(&["192.168.1.5", "fe80::1", "fd00::5", "2001:0:4136:e378::1"])), Route::No);
        assert_eq!(classify_route(false, unreachable(), addrs(&["2001:db8::5", "169.254.3.3"])), Route::No);
        assert_eq!(classify_route(false, unreachable(), addrs(&["10.8.0.2"])), Route::Unknown);
        // 列不出网卡：不确定
        assert_eq!(classify_route(true, unreachable(), || None), Route::Unknown);
        // 系统不支持这个地址族：不看网卡
        #[cfg(unix)]
        assert_eq!(classify_route(true, Err(Error::from_raw_os_error(libc::EAFNOSUPPORT)), addrs(&["2001:db8::5"])), Route::No);
        // 权限不足等：不确定
        assert_eq!(classify_route(true, Err(Error::from(ErrorKind::PermissionDenied)), addrs(&[])), Route::Unknown);
        assert_eq!(classify_route(true, Ok(ip("2001:db8::5")), addrs(&[])), Route::Yes);
    }

    /// 固定目的地不可达、同族检测服务仍可达并返回白名单外地址：最终阻断；检测失败时按检测失败处理（不放行）。
    #[test]
    fn unreachable_probe_target_still_verifies_family() {
        let cfg = Config::parse("whitelist=[\"203.0.113.0/24\"]\n[ipv6]\nmode=\"check\"").unwrap();
        let wl = |a: IpAddr| cfg.is_whitelisted(a);
        let v4 = Probe::Verified(ip("203.0.113.9"));
        let v6 = probe_with(true, Route::Unknown, || Ok(ip("2001:db8::9")));
        assert_eq!(v6, Probe::Verified(ip("2001:db8::9")));
        let e = combine(v4.clone(), v6, wl).unwrap();
        assert!(!crate::controller::egress_allowed(&cfg, &e));
        let failed = probe_with(true, Route::Unknown, || Err(anyhow!("超时")));
        assert!(combine(v4.clone(), failed, wl).is_err(), "未验证，不能放行");
        // 真单栈才跳过
        assert_eq!(probe_with(true, Route::No, || panic!("不应检测")), Probe::NoRoute);
        assert!(crate::controller::egress_allowed(&cfg, &combine(v4, Probe::NoRoute, wl).unwrap()));
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
        assert_eq!(combine(v4(), v6(), wl).unwrap(), Egress::dual(ip("203.0.113.9"), Some(ip("2001:db8::9"))));
        // 单栈
        assert_eq!(combine(v4(), NoRoute, wl).unwrap(), Egress::v4(ip("203.0.113.9")));
        assert_eq!(combine(NoRoute, v6(), wl).unwrap(), Egress::v4(ip("2001:db8::9")));
        // IPv4 在白名单，但有 IPv6 路由却测不到：不能放行
        let e = combine(v4(), fail(), wl).unwrap_err().to_string();
        assert!(e.contains("IPv6 出口检测失败"), "{e}");
        assert!(combine(fail(), v6(), wl).is_err());
        // 另一个地址族已经不在白名单：直接给出结果（反正要阻断）
        assert_eq!(combine(bad4(), fail(), wl).unwrap().ip, ip("198.51.100.1"));
        // 这样的结果标记为 IPv6 未验证：之后改白名单时不能据此放行
        assert!(combine(bad4(), fail(), wl).unwrap().v6_unverified);
        assert!(!combine(v4(), v6(), wl).unwrap().v6_unverified);
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

    /// 设置里明确填了代理时才走代理：测到的是代理的出口；不看本机路由；代理地址有误时检测失败而不是改为直连。
    #[test]
    fn uses_configured_proxy() {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;

        // 假代理：CONNECT 时先回「已建立」再读隧道里的请求；直接收到请求时直接回答
        fn fake_proxy(body: &'static str) -> String {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = l.local_addr().unwrap();
            std::thread::spawn(move || {
                for c in l.incoming().flatten() {
                    let mut r = BufReader::new(c.try_clone().unwrap());
                    let mut c = c;
                    let read_head = |r: &mut BufReader<std::net::TcpStream>| {
                        let mut first = String::new();
                        let _ = r.read_line(&mut first);
                        let mut line = String::new();
                        while r.read_line(&mut line).is_ok_and(|n| n > 2) {
                            line.clear();
                        }
                        first
                    };
                    if read_head(&mut r).starts_with("CONNECT") {
                        let _ = write!(c, "HTTP/1.1 200 Connection established\r\n\r\n");
                        read_head(&mut r);
                    }
                    let _ = write!(c, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                }
            });
            format!("http://{addr}")
        }
        // 目标地址不会被真正连接（由代理回答）
        let svc = vec!["http://192.0.2.1/ip".to_owned()];
        let t = Duration::from_secs(5);

        let p4 = fake_proxy("203.0.113.9");
        let d = EgressDetector::with_proxy(svc.clone(), t, Family::V4, Some(&p4));
        assert!(d.via_proxy());
        assert_eq!(d.probe(), Probe::Verified(ip("203.0.113.9")));

        // IPv6：代理在 127.0.0.1 也能连上，不看本机有没有 IPv6 路由；返回的地址族照样校验
        let p6 = fake_proxy("2001:db8::9");
        let d = EgressDetector::with_proxy(svc.clone(), t, Family::V6, Some(&p6));
        assert_eq!(d.probe(), Probe::Verified(ip("2001:db8::9")));
        let d = EgressDetector::with_proxy(svc.clone(), t, Family::V6, Some(&p4));
        assert!(matches!(d.probe(), Probe::Failed(e) if e.contains("通过代理") && e.contains("不是 IPv6")));

        // 空白 = 直连
        assert!(!EgressDetector::with_proxy(svc.clone(), t, Family::V4, Some("  ")).via_proxy());
        // 地址有误：失败，不悄悄直连
        let d = EgressDetector::with_proxy(svc, t, Family::V4, Some("ftp://127.0.0.1:1"));
        assert!(d.detect().unwrap_err().to_string().contains("代理地址有误"));
    }
}
