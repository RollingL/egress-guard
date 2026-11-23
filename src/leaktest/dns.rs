//! DNS 泄露测试（使用 addr.tools 的 dnscheck 服务，方法与 dnscheck.tools 网页相同）。
//!
//! 1. 生成随机测试 ID，连接 `wss://ws.<zone>/watch/<ID>`：之后权威服务器每收到一个含这个 ID 的查询，
//!    都会把查询来源（递归解析器的 IP、协议、转发的客户端网段 ECS）实时推送过来；
//! 2. 用系统解析器（和普通应用一样，走 getaddrinfo）查询几个含 ID 的随机子域名：
//!    `a.<ID>-nxdomain.test.<zone>` 等不存在的名字（解析器不会缓存，也可能换别的上游重试），
//!    `<ID>.test.<zone>`，以及只有 IPv6 权威服务器的 `<ID>.test-ipv6.<zone>`；
//! 3. 收集一会儿推送，按解析器汇总，再查询各解析器的运营商归属（ip.addr.tools）。
//!
//! 另外还并行使用几个「一次 HTTP 请求」式的检测源（做法参考 MyIP 项目）：访问一个随机子域名，
//! 对方的权威服务器记下是哪个解析器来查的，直接在 HTTP 响应里返回。它们每个只能看到一个解析器，
//! 但不依赖 WebSocket，在 dnscheck 连不上时也能给出结果，结果会与 dnscheck 合并。
//!
//! 出现白名单出口以外的解析器（例如本地运营商的 DNS），说明域名查询没有走白名单出口，
//! 对方可以据此知道你访问了哪些网站、以及你真实所在的网络。

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Shutdown, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use super::{lookup_info, IpInfo, Judge, Verdict};

/// 所有查询发出后，再等多久收集迟到的推送。
const GRACE: Duration = Duration::from_secs(3);
/// 整个测试的上限。
const MAX_TOTAL: Duration = Duration::from_secs(25);

/// 推送消息（dnscheck 的 WebSocket 每收到一个查询发一条 JSON）。
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WatchMsg {
    pub remote_ip: String,
    #[serde(default)]
    pub proto: String,
    #[serde(default)]
    pub qname: String,
    #[serde(default)]
    pub client_subnet: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Resolver {
    pub ip: IpAddr,
    /// dnscheck 收到的查询数（只由其他检测源发现时为 0）。
    pub queries: u32,
    /// 发现它的检测源。
    pub sources: Vec<String>,
    /// 用到的协议（UDP、TCP、TLS、QUIC）。
    pub protos: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<IpInfo>,
    pub verdict: Verdict,
}

/// 解析器转发的客户端网段（EDNS Client Subnet）。
#[derive(Debug, Clone, Serialize)]
pub struct ClientSubnet {
    pub subnet: IpNet,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<IpInfo>,
    pub verdict: Verdict,
}

#[derive(Debug, Clone, Serialize)]
pub struct DnsReport {
    pub resolvers: Vec<Resolver>,
    pub client_subnets: Vec<ClientSubnet>,
    /// 测试时的出口 IP 及其归属。
    pub egress: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub egress_info: Option<IpInfo>,
    /// dnscheck 收到的查询总数。
    pub queries: u32,
    /// 各检测源的结果。
    pub sources: Vec<SourceStatus>,
}

/// 一个检测源的运行结果。
#[derive(Debug, Clone, Serialize)]
pub struct SourceStatus {
    pub name: String,
    pub ok: bool,
    /// 成功时为发现的解析器数 / 查询数，失败时为原因。
    pub detail: String,
}

impl DnsReport {
    /// 按当前白名单、可信解析器重新判定。
    pub fn judged(&self, j: &Judge) -> Self {
        let mut r = self.clone();
        let egress = r.egress.map(|e| (e, r.egress_info.as_ref().and_then(|i| i.asn)));
        for x in &mut r.resolvers {
            x.verdict = j.resolver(x.ip, x.info.as_ref().and_then(|i| i.asn), egress);
        }
        for x in &mut r.client_subnets {
            x.verdict = j.client_subnet(x.subnet, r.egress);
        }
        r
    }

    pub fn leaks(&self) -> usize {
        self.resolvers.iter().filter(|x| x.verdict.is_leak()).count()
            + self.client_subnets.iter().filter(|x| x.verdict.is_leak()).count()
    }
}

/// 按解析器汇总推送消息（只保留属于本次测试 ID 的查询）。
pub fn aggregate(msgs: &[WatchMsg], id: &str) -> (Vec<Resolver>, Vec<IpNet>, u32) {
    let id = id.to_ascii_lowercase();
    let mut map: BTreeMap<IpAddr, Resolver> = BTreeMap::new();
    let mut subnets: Vec<IpNet> = Vec::new();
    let mut total = 0;
    for m in msgs {
        // 解析器可能随机改变查询名的大小写（0x20 编码）
        if !m.qname.to_ascii_lowercase().contains(&id) {
            continue;
        }
        let Ok(ip) = m.remote_ip.parse::<IpAddr>() else { continue };
        let ip = crate::config::normalize(ip);
        total += 1;
        let r = map.entry(ip).or_insert_with(|| Resolver {
            ip,
            queries: 0,
            sources: vec![DNSCHECK.to_owned()],
            protos: Vec::new(),
            info: None,
            verdict: Verdict::Leak,
        });
        r.queries += 1;
        let proto = m.proto.to_ascii_uppercase();
        if !proto.is_empty() && !r.protos.contains(&proto) {
            r.protos.push(proto);
        }
        // 「/0」表示解析器支持 ECS 但没有透露网段
        if let Some(net) = m.client_subnet.as_deref().and_then(|s| s.parse::<IpNet>().ok()) {
            if net.prefix_len() > 0 && !subnets.contains(&net.trunc()) {
                subnets.push(net.trunc());
            }
        }
    }
    (map.into_values().collect(), subnets, total)
}

/// 本次测试要查询的域名。
pub fn query_names(zone: &str, id: &str) -> Vec<String> {
    let mut v: Vec<String> = ["a", "b", "c", "d"].iter().map(|c| format!("{c}.{id}-nxdomain.test.{zone}")).collect();
    v.push(format!("{id}.test.{zone}"));
    v.push(format!("{id}.test-ipv6.{zone}"));
    v
}

enum Note {
    Msg(WatchMsg),
    /// 服务器关闭了连接（4000 = 这个 ID 已经有人在用）。
    Closed(Option<u16>),
    LookupsDone,
}

/// dnscheck（WebSocket 推送）检测源的名称。
pub const DNSCHECK: &str = "dnscheck";

/// 运行测试。`sources` 为要使用的检测源（[`DNSCHECK`] 与 [`HttpSource`] 的名称），
/// `progress` 在 dnscheck 每收到一个查询时调用（参数为已收到的数量）。
/// `cancel` 为真时不再发出新的查询（DNS、HTTP、归属查询），已经发出的照常收尾，结果为「已取消」。
pub fn run(
    zone: &str,
    sources: &[String],
    egress: Option<IpAddr>,
    judge: &Judge,
    progress: &(dyn Fn(u32) + Sync),
    cancel: &(dyn Fn() -> bool + Sync),
) -> Result<DnsReport> {
    let use_dnscheck = sources.iter().any(|s| s == DNSCHECK);
    let http: Vec<HttpSource> = sources.iter().filter_map(|s| HttpSource::from_name(s)).collect();
    if !use_dnscheck && http.is_empty() {
        bail!("没有启用任何 DNS 检测源");
    }

    let (dnscheck, http_results) = std::thread::scope(|s| {
        let d = use_dnscheck.then(|| s.spawn(|| run_dnscheck(zone, progress, cancel)));
        let agent = http_agent();
        let h: Vec<_> = http
            .iter()
            .map(|src| {
                let agent = agent.clone();
                (*src, s.spawn(move || if cancel() { Err(anyhow!("测试已取消")) } else { src.run(&agent) }))
            })
            .collect();
        let d = d.map(|j| j.join().unwrap_or_else(|_| Err(anyhow!("检测线程异常退出"))));
        let h: Vec<_> =
            h.into_iter().map(|(src, j)| (src, j.join().unwrap_or_else(|_| Err(anyhow!("检测线程异常退出"))))).collect();
        (d, h)
    });

    let mut statuses = Vec::new();
    let (mut resolvers, subnets, total) = match dnscheck {
        Some(Ok((msgs, id))) => {
            let (r, s, t) = aggregate(&msgs, &id);
            statuses.push(SourceStatus {
                name: DNSCHECK.into(),
                ok: t > 0,
                detail: if t > 0 { format!("{} 个解析器，{t} 次查询", r.len()) } else { "没有收到查询".into() },
            });
            (r, s, t)
        }
        Some(Err(e)) => {
            statuses.push(SourceStatus { name: DNSCHECK.into(), ok: false, detail: format!("{e:#}") });
            (Vec::new(), Vec::new(), 0)
        }
        None => (Vec::new(), Vec::new(), 0),
    };
    for (src, r) in http_results {
        match r {
            Ok(ips) => {
                statuses.push(SourceStatus { name: src.name().into(), ok: true, detail: format!("{} 个解析器", ips.len()) });
                for ip in ips {
                    let ip = crate::config::normalize(ip);
                    match resolvers.iter_mut().find(|r| r.ip == ip) {
                        Some(r) => {
                            if !r.sources.iter().any(|x| x == src.name()) {
                                r.sources.push(src.name().into());
                            }
                        }
                        None => resolvers.push(Resolver {
                            ip,
                            queries: 0,
                            sources: vec![src.name().into()],
                            protos: Vec::new(),
                            info: None,
                            verdict: Verdict::Leak,
                        }),
                    }
                }
            }
            Err(e) => statuses.push(SourceStatus { name: src.name().into(), ok: false, detail: format!("{e:#}") }),
        }
    }
    if cancel() {
        bail!("测试已取消（网络或设置变了）");
    }
    if resolvers.is_empty() {
        let why = statuses.iter().map(|s| format!("{}：{}", s.name, s.detail)).collect::<Vec<_>>().join("；");
        bail!(
            "没有发现任何 DNS 解析器。可能是 DNS 查询被拦截了，或者本机用的是 fake-ip 之类的本地解析\
             （这时应用的域名查询不会直接发往外部解析器）。{why}"
        );
    }

    // 查询归属：各解析器、各网段、出口 IP
    let mut ips: Vec<IpAddr> = resolvers.iter().map(|r| r.ip).collect();
    ips.extend(subnets.iter().map(|n| n.network()));
    ips.extend(egress);
    let mut infos = lookup_info(&ips, cancel).into_iter();
    if cancel() {
        bail!("测试已取消（网络或设置变了）");
    }
    for r in &mut resolvers {
        r.info = infos.next().flatten();
    }
    let client_subnets =
        subnets.into_iter().map(|subnet| ClientSubnet { subnet, info: infos.next().flatten(), verdict: Verdict::Leak }).collect();
    let egress_info = infos.next().flatten();
    // 发现次数多的排前面
    resolvers.sort_by(|a, b| (b.queries, b.sources.len()).cmp(&(a.queries, a.sources.len())).then(a.ip.cmp(&b.ip)));
    Ok(DnsReport { resolvers, client_subnets, egress, egress_info, queries: total, sources: statuses }.judged(judge))
}

/// 全部检测源的名称（配置文件默认值）。
pub fn all_source_names() -> Vec<String> {
    std::iter::once(DNSCHECK).chain(HttpSource::ALL.iter().map(|s| s.name())).map(Into::into).collect()
}

fn run_dnscheck(
    zone: &str,
    progress: &(dyn Fn(u32) + Sync),
    cancel: &(dyn Fn() -> bool + Sync),
) -> Result<(Vec<WatchMsg>, String)> {
    for _ in 0..3 {
        if cancel() {
            bail!("测试已取消");
        }
        let id = format!("{:08x}", super::random_u64() as u32);
        if let Some(m) = collect(zone, &id, progress, cancel)? {
            return Ok((m, id));
        }
        // ID 冲突，换一个
    }
    bail!("测试 ID 一直冲突")
}

/// 「一次 HTTP 请求」式的 DNS 检测源：访问一个随机子域名，响应里是权威服务器看到的解析器 IP。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpSource {
    IpApi,
    Every1Dns,
    Fastly,
    Surfshark,
    IpLeak,
    BrowserLeaks,
}

impl HttpSource {
    pub const ALL: [HttpSource; 6] = [
        HttpSource::IpApi,
        HttpSource::Every1Dns,
        HttpSource::Fastly,
        HttpSource::Surfshark,
        HttpSource::IpLeak,
        HttpSource::BrowserLeaks,
    ];

    pub fn name(self) -> &'static str {
        match self {
            HttpSource::IpApi => "ip-api",
            HttpSource::Every1Dns => "every1dns",
            HttpSource::Fastly => "fastly",
            HttpSource::Surfshark => "surfshark",
            HttpSource::IpLeak => "ipleak",
            HttpSource::BrowserLeaks => "browserleaks",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|x| x.name() == s)
    }

    /// 本次请求的网址（含随机子域名）。
    pub fn url(self) -> String {
        match self {
            // ip-api 的免费接口只有 HTTP；标签需要 32 个字符
            HttpSource::IpApi => format!("http://{}.edns.ip-api.com/json", random_label(32)),
            HttpSource::Every1Dns => format!("https://{}.map.help.every1dns.net/", random_label(32)),
            HttpSource::Fastly => format!("https://{}.u.fastly-analytics.com/debug_resolver", random_label(30)),
            HttpSource::Surfshark => format!("https://{}.ipv4.surfsharkdns.com/", random_label(13)),
            HttpSource::IpLeak => format!("https://{}-1.ipleak.net/dnsdetection/", random_label(40)),
            HttpSource::BrowserLeaks => format!("https://{}.dns4.browserleaks.net/", random_label(12)),
        }
    }

    /// 从响应 JSON 中取出解析器 IP。
    pub fn parse(self, v: &serde_json::Value) -> Vec<IpAddr> {
        let ip = |x: &serde_json::Value| x.as_str().and_then(|s| s.trim().parse::<IpAddr>().ok());
        let mut out: Vec<IpAddr> = match self {
            HttpSource::IpApi => ip(&v["dns"]["ip"]).into_iter().collect(),
            HttpSource::Every1Dns => ip(&v["ip"]).into_iter().collect(),
            HttpSource::Fastly => ip(&v["dns_resolver_info"]["ip"]).into_iter().collect(),
            // { "0": { "IP": "1.2.3.4", ... }, "1": { ... } }
            HttpSource::Surfshark => {
                v.as_object().map(|o| o.values().filter_map(|x| ip(&x["IP"])).collect()).unwrap_or_default()
            }
            // { "ip": { "1.2.3.4": 3, ... } }
            HttpSource::IpLeak => {
                v["ip"].as_object().map(|o| o.keys().filter_map(|k| k.parse().ok()).collect()).unwrap_or_default()
            }
            // { "1.2.3.4": [ ... ], ... }
            HttpSource::BrowserLeaks => v
                .as_object()
                .map(|o| {
                    o.iter()
                        .filter(|(_, x)| x.as_array().is_some_and(|a| !a.is_empty()))
                        .filter_map(|(k, _)| k.parse().ok())
                        .collect()
                })
                .unwrap_or_default(),
        };
        out.sort();
        out.dedup();
        out
    }

    fn run(self, agent: &ureq::Agent) -> Result<Vec<IpAddr>> {
        let body = agent
            .get(&self.url())
            .header("Accept", "application/json")
            .call()
            .map_err(|e| anyhow!("{e}"))?
            .body_mut()
            .with_config()
            .limit(64 * 1024)
            .read_to_string()?;
        let v: serde_json::Value = serde_json::from_str(&body).map_err(|_| anyhow!("响应不是 JSON"))?;
        let ips = self.parse(&v);
        if ips.is_empty() {
            bail!("响应里没有解析器 IP");
        }
        Ok(ips)
    }
}

/// HTTP 检测源用的客户端。不走代理：域名必须由本机的系统解析器解析，测的才是本机的 DNS。
fn http_agent() -> ureq::Agent {
    use ureq::tls::{TlsConfig, TlsProvider};
    ureq::Agent::config_builder()
        .tls_config(TlsConfig::builder().provider(TlsProvider::NativeTls).build())
        .proxy(None)
        .timeout_global(Some(Duration::from_secs(10)))
        .user_agent(concat!("egress-guard/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

/// 随机的小写字母数字标签（以字母开头）。
fn random_label(n: usize) -> String {
    const ABC: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut s = String::with_capacity(n);
    let mut r = super::random_u64();
    for i in 0..n {
        if i % 8 == 0 {
            r = super::random_u64();
        }
        let m = if i == 0 { 26 } else { ABC.len() as u64 };
        s.push(ABC[(r % m) as usize] as char);
        r /= ABC.len() as u64;
    }
    s
}

/// 连接推送、发出查询、收集结果。ID 已被占用时返回 None。
fn collect(
    zone: &str,
    id: &str,
    progress: &(dyn Fn(u32) + Sync),
    cancel: &(dyn Fn() -> bool + Sync),
) -> Result<Option<Vec<WatchMsg>>> {
    let host = format!("ws.{zone}");
    let url = format!("wss://{host}/watch/{id}");
    let addrs: Vec<_> = (host.as_str(), 443).to_socket_addrs().with_context(|| format!("无法解析 {host}"))?.collect();
    let mut last = anyhow!("无法解析 {host}");
    let mut stream = None;
    for a in addrs {
        match TcpStream::connect_timeout(&a, Duration::from_secs(8)) {
            Ok(s) => {
                stream = Some(s);
                break;
            }
            Err(e) => last = anyhow!("无法连接 {host}（{a}）：{e}"),
        }
    }
    let stream = stream.ok_or(last)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let control = stream.try_clone()?;
    let (mut ws, _) = tungstenite::client_tls(url.as_str(), stream).map_err(|e| anyhow!("无法连接 {host}：{e}"))?;
    // 握手完成后读取不再超时，由下面的 shutdown 结束
    control.set_read_timeout(None)?;

    let (tx, rx) = mpsc::channel::<Note>();
    std::thread::scope(|s| -> Result<Option<Vec<WatchMsg>>> {
        let reader_tx = tx.clone();
        s.spawn(move || read_loop(&mut ws, reader_tx));

        // 服务器在握手应答之后才登记这个 ID；稍等一下再发查询
        std::thread::sleep(Duration::from_millis(300));
        let names = query_names(zone, id);
        let lookup_tx = tx.clone();
        // 取消后查询线程不再发出新的查询
        let stop = Arc::new(AtomicBool::new(false));
        let stop_lookups = stop.clone();
        // getaddrinfo 没有超时，放在独立线程里，不等它结束
        std::thread::spawn(move || {
            for n in names {
                if stop_lookups.load(Ordering::SeqCst) {
                    break;
                }
                let _ = (n.as_str(), 443).to_socket_addrs();
            }
            let _ = lookup_tx.send(Note::LookupsDone);
        });
        drop(tx);

        let start = Instant::now();
        let mut deadline = start + MAX_TOTAL;
        let mut msgs = Vec::new();
        let mut taken = false;
        let id_lc = id.to_ascii_lowercase();
        loop {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            if cancel() {
                stop.store(true, Ordering::SeqCst);
                break;
            }
            // 分段等待，及时发现取消
            match rx.recv_timeout((deadline - now).min(Duration::from_millis(250))) {
                Ok(Note::Msg(m)) => {
                    if m.qname.to_ascii_lowercase().contains(&id_lc) {
                        msgs.push(m);
                        progress(msgs.len() as u32);
                    }
                }
                Ok(Note::LookupsDone) => deadline = deadline.min(Instant::now() + GRACE),
                Ok(Note::Closed(code)) => {
                    taken = code == Some(4000);
                    break;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        stop.store(true, Ordering::SeqCst);
        let _ = control.shutdown(Shutdown::Both);
        if taken && msgs.is_empty() {
            return Ok(None);
        }
        Ok(Some(msgs))
    })
}

fn read_loop<S: Read + Write>(ws: &mut tungstenite::WebSocket<S>, tx: mpsc::Sender<Note>) {
    use tungstenite::Message;
    loop {
        match ws.read() {
            Ok(Message::Text(t)) => match serde_json::from_str::<WatchMsg>(t.as_str()) {
                Ok(m) => {
                    if tx.send(Note::Msg(m)).is_err() {
                        return;
                    }
                }
                Err(e) => log::debug!("无法解析 dnscheck 推送：{e}：{}", t.as_str()),
            },
            Ok(Message::Close(f)) => {
                let _ = tx.send(Note::Closed(f.map(|f| u16::from(f.code))));
                return;
            }
            Ok(_) => {}
            Err(e) => {
                log::debug!("dnscheck 推送连接结束：{e}");
                let _ = tx.send(Note::Closed(None));
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancelled_run_stops_before_requests() {
        let started = Instant::now();
        let err = run("dnscheck.tools", &all_source_names(), None, &Judge::default(), &|_| {}, &|| true).unwrap_err();
        assert!(format!("{err:#}").contains("已取消"), "{err:#}");
        // 没有发出任何网络请求，立即返回
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    fn msg(ip: &str, proto: &str, qname: &str, ecs: Option<&str>) -> WatchMsg {
        WatchMsg { remote_ip: ip.into(), proto: proto.into(), qname: qname.into(), client_subnet: ecs.map(Into::into) }
    }

    #[test]
    fn parses_push_message() {
        let m: WatchMsg = serde_json::from_str(
            r#"{"time":1763860000,"proto":"UDP","remoteIp":"172.70.9.1","remotePort":53211,
                "qname":"a.1f2e3d4c-NXDOMAIN.test.dnscheck.tools.","qtype":"A","isEdns0":true,"udpSize":1232,
                "clientSubnet":"198.51.100.0/24"}"#,
        )
        .unwrap();
        assert_eq!(m.remote_ip, "172.70.9.1");
        assert_eq!(m.client_subnet.as_deref(), Some("198.51.100.0/24"));
    }

    #[test]
    fn aggregates_by_resolver() {
        let id = "1f2e3d4c";
        let msgs = vec![
            msg("172.70.9.1", "UDP", "a.1F2E3D4C-nxdomain.test.dnscheck.tools.", Some("198.51.100.0/24")),
            msg("172.70.9.1", "TCP", "b.1f2e3d4c-nxdomain.test.dnscheck.tools.", Some("198.51.100.0/24")),
            msg("2001:db8::53", "udp", "1f2e3d4c.test-ipv6.dnscheck.tools.", Some("::/0")),
            msg("::ffff:203.0.113.53", "UDP", "1f2e3d4c.test.dnscheck.tools.", None),
            // 别的测试的查询
            msg("192.0.2.53", "UDP", "a.99999999-nxdomain.test.dnscheck.tools.", None),
            msg("not-an-ip", "UDP", "a.1f2e3d4c-nxdomain.test.dnscheck.tools.", None),
        ];
        let (rs, subnets, total) = aggregate(&msgs, id);
        assert_eq!(total, 4);
        assert_eq!(rs.len(), 3);
        let cf = rs.iter().find(|r| r.ip.to_string() == "172.70.9.1").unwrap();
        assert_eq!(cf.queries, 2);
        assert_eq!(cf.protos, vec!["UDP", "TCP"]);
        // IPv4 映射地址还原
        assert!(rs.iter().any(|r| r.ip.to_string() == "203.0.113.53"));
        assert_eq!(subnets, vec!["198.51.100.0/24".parse::<IpNet>().unwrap()]);
    }

    #[test]
    fn judged_report() {
        let r = DnsReport {
            resolvers: vec![
                Resolver {
                    ip: "203.0.113.53".parse().unwrap(),
                    queries: 3,
                    sources: vec![],
                    protos: vec![],
                    info: None,
                    verdict: Verdict::Leak,
                },
                Resolver {
                    ip: "198.51.100.53".parse().unwrap(),
                    queries: 1,
                    sources: vec![],
                    protos: vec![],
                    info: Some(IpInfo { asn: Some(4134), ..Default::default() }),
                    verdict: Verdict::Leak,
                },
            ],
            client_subnets: vec![ClientSubnet { subnet: "198.51.100.0/24".parse().unwrap(), info: None, verdict: Verdict::Leak }],
            egress: Some("203.0.113.7".parse().unwrap()),
            egress_info: Some(IpInfo { asn: Some(64500), ..Default::default() }),
            queries: 4,
            sources: vec![],
        };
        let j = Judge::from_strings(&["203.0.113.0/24".to_owned()], &[]);
        let a = r.judged(&j);
        assert_eq!(a.resolvers[0].verdict, Verdict::Whitelisted);
        assert_eq!(a.resolvers[1].verdict, Verdict::Leak);
        assert_eq!(a.client_subnets[0].verdict, Verdict::Leak);
        assert_eq!(a.leaks(), 2);
        // 把 AS4134 加入可信后只剩 ECS 网段
        let j = Judge::from_strings(&["203.0.113.0/24".to_owned()], &["AS4134".to_owned()]);
        assert_eq!(r.judged(&j).leaks(), 1);
    }

    #[test]
    fn http_sources() {
        let j = |s: &str| serde_json::from_str::<serde_json::Value>(s).unwrap();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(HttpSource::IpApi.parse(&j(r#"{"dns":{"geo":"US - Google","ip":"74.125.0.1"},"edns":{}}"#)), vec![ip("74.125.0.1")]);
        assert_eq!(HttpSource::Every1Dns.parse(&j(r#"{"ip":"1.0.0.9","protocol":"udp"}"#)), vec![ip("1.0.0.9")]);
        assert_eq!(HttpSource::Fastly.parse(&j(r#"{"dns_resolver_info":{"ip":"2001:db8::53"}}"#)), vec![ip("2001:db8::53")]);
        assert_eq!(
            HttpSource::Surfshark.parse(&j(r#"{"0":{"IP":"198.51.100.1"},"1":{"IP":"198.51.100.2"},"x":{}}"#)),
            vec![ip("198.51.100.1"), ip("198.51.100.2")]
        );
        assert_eq!(HttpSource::IpLeak.parse(&j(r#"{"ip":{"203.0.113.9":3,"bogus":1}}"#)), vec![ip("203.0.113.9")]);
        assert_eq!(
            HttpSource::BrowserLeaks.parse(&j(r#"{"192.0.2.53":["US","X"],"192.0.2.54":[]}"#)),
            vec![ip("192.0.2.53")]
        );
        assert!(HttpSource::IpApi.parse(&j("[]")).is_empty());
        for s in HttpSource::ALL {
            assert_eq!(HttpSource::from_name(s.name()), Some(s));
            let url = s.url();
            assert!(url.starts_with("http") && url.is_ascii(), "{url}");
        }
        let l = random_label(40);
        assert_eq!(l.len(), 40);
        assert!(l.as_bytes()[0].is_ascii_lowercase());
        assert!(l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()));
    }

    #[test]
    fn names() {
        let n = query_names("dnscheck.tools", "abc");
        assert_eq!(n[0], "a.abc-nxdomain.test.dnscheck.tools");
        assert!(n.contains(&"abc.test-ipv6.dnscheck.tools".to_owned()));
    }
}
