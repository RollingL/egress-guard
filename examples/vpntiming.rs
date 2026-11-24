//! VPN 断开 → 阻断生效的时序测量（审查用的临时程序，不随发布）。
//!
//! - `vpntiming sim [次数]`（Linux，root）：用真实的 tun 网卡模拟 VPN，防火墙为模拟模式。Linux 没有网络变化通知，
//!   测的是 0.25 秒轮询这条兜底路径（最坏情况）。
//! - `vpntiming real --up 脚本 --down 脚本 [--n 次数] [--dry-run] [--guard-only] [--block-all] [--kids 个数]`
//!   （Windows 管理员 / macOS root）：真实拦截后端 + 真实网卡（例如 WireGuard 隧道），由 up/down 脚本连上、断开 VPN。
//!   本程序复制一份自己作为受控应用（probe），它持续新建 IPv4/IPv6 连接并保持一条长连接，
//!   用单调时钟记录：网卡消失、规则生效、受控应用最后一次连通 / 第一次失败。
//!   `--kids`：阻断期间受控应用启动新的子程序（不同 exe），测它在被识别、加上规则之前能连网多久。
//!   没有 up/down 脚本时提示手动断开 VPN（真机手动测）。

#![allow(dead_code, unused_imports)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use egress_guard::config::{Config, Ipv6Mode, RawConfig};
use egress_guard::engine::{self, EngineHandle, Event, Status};
use egress_guard::vpn;

// ───────────────────────────── 公共 ─────────────────────────────

struct Rig {
    h: EngineHandle,
    rx: Receiver<(Instant, Status)>,
    last: Arc<Mutex<Status>>,
}

fn rig(raw: RawConfig, dry_run: bool) -> Rig {
    let (tx, rx) = mpsc::channel();
    let last = Arc::new(Mutex::new(Status::default()));
    let l2 = last.clone();
    let h = engine::spawn(
        Config::from_raw(raw).unwrap(),
        dry_run,
        true,
        None,
        Arc::new(move |s: &Status| {
            let now = Instant::now();
            *l2.lock().unwrap() = s.clone();
            let _ = tx.send((now, s.clone()));
        }),
    );
    Rig { h, rx, last }
}

impl Rig {
    fn wait(&self, what: &str, timeout: Duration, f: impl Fn(&Status) -> bool) -> Option<Instant> {
        let t = Instant::now();
        if f(&self.last.lock().unwrap()) {
            return Some(Instant::now());
        }
        while t.elapsed() < timeout {
            match self.rx.recv_timeout(Duration::from_millis(50)) {
                Ok((at, s)) if f(&s) => return Some(at),
                _ => {}
            }
        }
        let s = self.last.lock().unwrap().clone();
        eprintln!(
            "  等待「{what}」超时：blocked={} guarded={:?} connected={:?} reason={:?} err={:?}",
            s.blocked, s.vpn_guarded, s.vpn_connected, s.block_reason, s.detect_error
        );
        None
    }

    fn drain(&self) {
        while self.rx.try_recv().is_ok() {}
    }
}

fn rand_ms(max: u64) -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u128(Instant::now().elapsed().as_nanos());
    h.finish() % max.max(1)
}

fn pct(v: &mut [f64], p: f64) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((v.len() as f64 - 1.0) * p).round() as usize]
}

fn report(name: &str, mut v: Vec<f64>, fails: usize) {
    if v.is_empty() {
        println!("{name}: 没有数据（失败 {fails} 次）");
        return;
    }
    let mean = v.iter().sum::<f64>() / v.len() as f64;
    println!(
        "{name}: n={} 失败={fails}  min={:.1}  p50={:.1}  p90={:.1}  max={:.1}  mean={:.1}（毫秒）",
        v.len(),
        pct(&mut v, 0.0),
        pct(&mut v, 0.5),
        pct(&mut v, 0.9),
        pct(&mut v, 1.0),
        mean
    );
}

fn ms(a: Instant, b: Instant) -> f64 {
    if b >= a {
        b.duration_since(a).as_secs_f64() * 1000.0
    } else {
        -(a.duration_since(b).as_secs_f64() * 1000.0)
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("probe-child") => probe_child(&args[2..]),
        Some("real") => real(&args[2..]),
        #[cfg(target_os = "linux")]
        Some("sim") | None => sim::run(args.get(2).and_then(|a| a.parse().ok()).unwrap_or(30)),
        _ => eprintln!("用法见文件开头的说明"),
    }
}

// ───────────────────────────── 受控测试进程 ─────────────────────────────

const V4: &str = "1.1.1.1:80";
const V6: &str = "[2606:4700:4700::1111]:80";

/// 受控测试进程：持续新建连接（IPv4、IPv6），并保持一条 IPv4 长连接（HTTP keep-alive），每个结果打印一行。
/// 读到 stdin 的 `spawn <exe>` 时启动一个子程序（不同 exe），把它的输出转发出去。stdin 关闭时退出。
/// 参数：标签 [存活秒数]
fn probe_child(args: &[String]) {
    let tag = args.first().cloned().unwrap_or_else(|| "probe".into());
    let life = args.get(1).and_then(|a| a.parse::<u64>().ok());
    let out = Arc::new(Mutex::new(std::io::stdout()));
    let say = {
        let out = out.clone();
        let tag = tag.clone();
        move |what: &str| {
            let mut o = out.lock().unwrap();
            let _ = writeln!(o, "{tag} {what}");
            let _ = o.flush();
        }
    };
    for (name, addr) in [("n4", V4), ("n6", V6)] {
        let say = say.clone();
        std::thread::spawn(move || {
            let addr: SocketAddr = addr.parse().unwrap();
            loop {
                match TcpStream::connect_timeout(&addr, Duration::from_millis(400)) {
                    Ok(_) => say(&format!("{name} ok")),
                    Err(e) => say(&format!("{name} fail {}", e.kind())),
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
    }
    {
        let say = say.clone();
        std::thread::spawn(move || {
            let addr: SocketAddr = V4.parse().unwrap();
            loop {
                let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_millis(400)) else {
                    say("l4 fail connect");
                    std::thread::sleep(Duration::from_millis(20));
                    continue;
                };
                let _ = s.set_read_timeout(Some(Duration::from_millis(400)));
                let mut first = true;
                loop {
                    match http_once(&mut s) {
                        Ok(()) => say(if first { "l4 ok new" } else { "l4 ok" }),
                        Err(e) => {
                            say(&format!("l4 fail {e}"));
                            break;
                        }
                    }
                    first = false;
                    std::thread::sleep(Duration::from_millis(30));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
    }
    if let Some(secs) = life {
        std::thread::sleep(Duration::from_secs(secs));
        std::process::exit(0);
    }
    let mut kids: Vec<Child> = Vec::new();
    for line in std::io::stdin().lock().lines() {
        let Ok(line) = line else { break };
        if let Some(exe) = line.strip_prefix("spawn ") {
            let (exe, ktag) = exe.split_once(' ').unwrap_or((exe, "kid"));
            match Command::new(exe).args(["probe-child", ktag, "6"]).stdout(Stdio::piped()).stdin(Stdio::null()).spawn() {
                Ok(mut c) => {
                    let o = c.stdout.take().unwrap();
                    let out = out.clone();
                    std::thread::spawn(move || {
                        for l in BufReader::new(o).lines().map_while(Result::ok) {
                            let mut o = out.lock().unwrap();
                            let _ = writeln!(o, "{l}");
                            let _ = o.flush();
                        }
                    });
                    kids.push(c);
                }
                Err(e) => say(&format!("spawn-error {e}")),
            }
        }
    }
    for mut k in kids {
        let _ = k.kill();
    }
    std::process::exit(0);
}

/// 在长连接上发一次 HTTP 请求并读完响应。
fn http_once(s: &mut TcpStream) -> std::io::Result<()> {
    s.write_all(b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: keep-alive\r\n\r\n")?;
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = s.read(&mut tmp)?;
        if n == 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "closed"));
        }
        buf.extend_from_slice(&tmp[..n]);
        let Some(he) = buf.windows(4).position(|w| w == b"\r\n\r\n") else { continue };
        let head = String::from_utf8_lossy(&buf[..he]).to_ascii_lowercase();
        let body = &buf[he + 4..];
        if let Some(cl) = head.lines().find_map(|l| l.strip_prefix("content-length:")).and_then(|v| v.trim().parse::<usize>().ok()) {
            if body.len() >= cl {
                return Ok(());
            }
        } else if head.contains("chunked") {
            if body.ends_with(b"0\r\n\r\n") {
                return Ok(());
            }
        } else {
            return Ok(());
        }
    }
}

// ───────────────────────────── 真实后端 ─────────────────────────────

fn shell(script: &str) -> Command {
    if cfg!(windows) {
        let mut c = Command::new("cmd");
        c.args(["/C", script]);
        c
    } else {
        let mut c = Command::new("sh");
        c.args(["-c", script]);
        c
    }
}

fn exe_name(base: &str) -> String {
    if cfg!(windows) { format!("{base}.exe") } else { base.to_owned() }
}

type Log = Arc<Mutex<Vec<(Instant, String)>>>;

struct Probe {
    child: Child,
    log: Log,
}

impl Probe {
    fn start(exe: &Path) -> Probe {
        let mut child = Command::new(exe)
            .args(["probe-child", "probe"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("启动受控测试进程");
        let log: Log = Arc::default();
        let l = log.clone();
        let o = child.stdout.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(o).lines().map_while(Result::ok) {
                let now = Instant::now();
                l.lock().unwrap().push((now, line));
            }
        });
        Probe { child, log }
    }

    fn send(&mut self, line: &str) {
        let i = self.child.stdin.as_mut().unwrap();
        let _ = writeln!(i, "{line}");
        let _ = i.flush();
    }

    /// `from` 之后某一类结果（前缀，例如 "probe n4 ok"）的时刻。
    fn times(&self, from: Instant, prefix: &str) -> Vec<Instant> {
        self.log.lock().unwrap().iter().filter(|(t, l)| *t >= from && l.starts_with(prefix)).map(|(t, _)| *t).collect()
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

/// 高频（约 3 毫秒）查看 VPN 网卡，记录每次变化的时刻。
type AdapterLog = Arc<Mutex<Vec<(Instant, Vec<String>)>>>;

fn adapter_log(cfg: egress_guard::config::VpnConfig) -> AdapterLog {
    let log: AdapterLog = Arc::default();
    let l = log.clone();
    std::thread::spawn(move || {
        let mut last: Option<Vec<String>> = None;
        loop {
            if let Some(a) = vpn::scan() {
                let now = vpn::names(&vpn::links(&a, &cfg));
                if last.as_ref() != Some(&now) {
                    l.lock().unwrap().push((Instant::now(), now.clone()));
                    last = Some(now);
                }
            }
            std::thread::sleep(Duration::from_millis(3));
        }
    });
    log
}

fn flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn opt<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
}

#[derive(Default)]
struct Trial {
    teardown: Option<f64>,
    react: Option<f64>,
    from_cut: Option<f64>,
    leak: [Option<f64>; 3],
    first_fail: [Option<f64>; 3],
    ok_before: [bool; 3],
    reason: String,
}

fn real(args: &[String]) {
    egress_guard::logbuf::init(if flag(args, "-v") { "info" } else { "warn" }, true, None);
    let n: usize = opt(args, "--n").and_then(|v| v.parse().ok()).unwrap_or(15);
    let up = opt(args, "--up");
    let down = opt(args, "--down");
    let dry = flag(args, "--dry-run");
    let kids: usize = opt(args, "--kids").and_then(|v| v.parse().ok()).unwrap_or(0);

    // 受控测试进程：复制一份自己（不同路径），只有它被阻断
    let dir = std::env::temp_dir().join(format!("vpntiming-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let me = std::env::current_exe().unwrap();
    let probe_exe = dir.join(exe_name("probe"));
    std::fs::copy(&me, &probe_exe).unwrap();
    let probe_exe = std::fs::canonicalize(&probe_exe).unwrap();
    let probe_exe = PathBuf::from(probe_exe.to_string_lossy().trim_start_matches(r"\\?\").to_owned());
    let kid_exes: Vec<PathBuf> = (0..kids)
        .map(|i| {
            let p = dir.join(exe_name(&format!("kid{i}")));
            std::fs::copy(&me, &p).unwrap();
            PathBuf::from(std::fs::canonicalize(&p).unwrap().to_string_lossy().trim_start_matches(r"\\?\").to_owned())
        })
        .collect();

    let mut raw = RawConfig { whitelist: vec!["0.0.0.0/0".into(), "::/0".into()], apps: vec![probe_exe.clone()], ..Default::default() };
    raw.ipv6.mode = Ipv6Mode::Check;
    if let Some(u) = opt(args, "--service") {
        raw.detect.services = vec![u.to_owned()];
    }
    raw.behavior.block_on_network_change = !flag(args, "--guard-only");
    raw.behavior.debounce_ms = opt(args, "--debounce").and_then(|v| v.parse().ok()).unwrap_or(500);
    raw.block_all.enabled = flag(args, "--block-all");
    let vcfg = raw.vpn.clone();
    let raw_blocked = RawConfig { whitelist: vec!["192.0.2.1/32".into()], ..raw.clone() };

    println!(
        "设置：{}，{}，「网络变化时先阻断」{}，防抖 {} 毫秒，受控测试进程 {}",
        if dry { "模拟模式" } else { "真实拦截后端" },
        if raw.block_all.enabled { "全局断网" } else { "按应用" },
        if raw.behavior.block_on_network_change { "开" } else { "关" },
        raw.behavior.debounce_ms,
        probe_exe.display()
    );
    let adapters = adapter_log(vcfg);
    let r = rig(raw.clone(), dry);
    let mut probe = Probe::start(&probe_exe);
    if r.wait("首次检测放行", Duration::from_secs(60), |s| !s.blocked && s.running).is_none() {
        return;
    }
    std::thread::sleep(Duration::from_secs(2));
    let t = Instant::now() - Duration::from_secs(1);
    let have = ["probe n4 ok", "probe n6 ok", "probe l4 ok"].map(|p| !probe.times(t, p).is_empty());
    println!("放行时的连通性：IPv4 新连接 {}，IPv6 新连接 {}，IPv4 长连接 {}", have[0], have[1], have[2]);

    let mut trials: Vec<Trial> = Vec::new();
    for i in 0..n {
        if let Some(up) = up {
            let st = shell(up).status();
            if !st.as_ref().is_ok_and(|s| s.success()) {
                eprintln!("up 脚本失败：{st:?}");
            }
        } else if i == 0 {
            println!("请连上 VPN");
        }
        if r.wait("放行并守护 VPN 网卡", Duration::from_secs(120), |s| !s.blocked && !s.vpn_guarded.is_empty()).is_none() {
            continue;
        }
        let guarded = r.last.lock().unwrap().vpn_guarded.clone();
        std::thread::sleep(Duration::from_millis(1500 + rand_ms(1000)));
        r.drain();
        let t0 = Instant::now();
        let dn = match down {
            Some(d) => Some(shell(d).spawn().expect("down 脚本")),
            None => {
                println!("第 {} 次：请断开 VPN（{}）", i + 1, guarded.join("、"));
                None
            }
        };
        let blocked = r.wait("断开后阻断", Duration::from_secs(if down.is_some() { 15 } else { 300 }), |s| s.blocked);
        let reason = r.last.lock().unwrap().block_reason.clone().unwrap_or_default();
        std::thread::sleep(Duration::from_millis(2500));
        if let Some(mut d) = dn {
            let _ = d.wait();
        }
        let gone = adapters
            .lock()
            .unwrap()
            .iter()
            .find(|(t, names)| *t >= t0 && guarded.iter().any(|g| !names.contains(g)))
            .map(|(t, _)| *t);
        let mut tr = Trial { reason, ..Default::default() };
        let base = if down.is_some() { Some(t0) } else { gone };
        tr.teardown = gone.map(|g| ms(t0, g)).filter(|_| down.is_some());
        tr.react = match (gone, blocked) {
            (Some(g), Some(b)) => Some(ms(g, b)),
            _ => None,
        };
        tr.from_cut = match (base, blocked) {
            (Some(a), Some(b)) => Some(ms(a, b)),
            _ => None,
        };
        if let Some(g) = gone {
            for (k, p) in ["probe n4", "probe n6", "probe l4"].iter().enumerate() {
                let before = g - Duration::from_millis(500);
                tr.ok_before[k] = !probe.times(before, &format!("{p} ok")).into_iter().filter(|t| *t < g).collect::<Vec<_>>().is_empty();
                tr.leak[k] = probe.times(g, &format!("{p} ok")).into_iter().max().map(|t| ms(g, t));
                tr.first_fail[k] = probe.times(g, &format!("{p} fail")).into_iter().min().map(|t| ms(g, t));
            }
        }
        println!(
            "第 {:>2} 次：{}网卡消失→阻断 {}；受控进程在网卡消失后的最后一次连通 IPv4 {} / IPv6 {} / 长连接 {}；原因「{}」",
            i + 1,
            tr.teardown.map(|v| format!("断开脚本→网卡消失 {v:.0}ms，")).unwrap_or_default(),
            tr.react.map(|v| format!("{v:.1}ms")).unwrap_or("—".into()),
            fmt_leak(tr.ok_before[0], tr.leak[0]),
            fmt_leak(tr.ok_before[1], tr.leak[1]),
            fmt_leak(tr.ok_before[2], tr.leak[2]),
            tr.reason
        );
        trials.push(tr);
        let _ = r.wait("恢复放行（没有 VPN）", Duration::from_secs(60), |s| !s.blocked && !s.checking);
    }

    println!("\n== 汇总（{} 次）==", trials.len());
    let col = |f: &dyn Fn(&Trial) -> Option<f64>| trials.iter().filter_map(f).collect::<Vec<f64>>();
    if down.is_some() {
        report("断开脚本 → 网卡消失", col(&|t| t.teardown), 0);
        report("断开脚本 → 规则生效", col(&|t| t.from_cut), 0);
    }
    report("网卡消失 → 规则生效（引擎反应 + 提交）", col(&|t| t.react), trials.iter().filter(|t| t.react.is_none()).count());
    for (k, name) in ["IPv4 新连接", "IPv6 新连接", "IPv4 长连接"].iter().enumerate() {
        if trials.iter().any(|t| t.ok_before[k]) {
            report(&format!("网卡消失 → {name}最后一次连通（≤0 表示消失后没有再连通）"), col(&|t| t.ok_before[k].then(|| t.leak[k].unwrap_or(0.0))), 0);
            report(&format!("网卡消失 → {name}第一次失败"), col(&|t| t.ok_before[k].then_some(t.first_fail[k]).flatten()), 0);
        } else {
            println!("{name}：放行时就不通，跳过");
        }
    }
    let mut reasons: Vec<String> = trials.iter().map(|t| t.reason.clone()).collect();
    reasons.sort();
    reasons.dedup();
    println!("阻断原因：{}", reasons.join(" / "));

    if !kid_exes.is_empty() && !dry {
        println!("\n== 阻断期间受控应用启动新的子程序（不同 exe），到被识别并阻断之前能连网多久 ==");
        // 白名单换成不会命中的地址：检测之后一直阻断
        let _ = r.h.try_send(Event::Reconfigure(Box::new(Config::from_raw(raw_blocked).unwrap()), 1));
        r.wait("一直阻断", Duration::from_secs(60), |s| s.blocked && !s.checking && s.config_version == 1);
        std::thread::sleep(Duration::from_secs(1));
        let mut v = Vec::new();
        let mut never = 0;
        for (i, kid) in kid_exes.iter().enumerate() {
            std::thread::sleep(Duration::from_millis(rand_ms(2000)));
            let tag = format!("kid{i}");
            let t0 = Instant::now();
            probe.send(&format!("spawn {} {tag}", kid.display()));
            std::thread::sleep(Duration::from_millis(5000));
            let oks = probe.times(t0, &format!("{tag} n4 ok"));
            let fails = probe.times(t0, &format!("{tag} n4 fail"));
            let first = probe.log.lock().unwrap().iter().find(|(t, l)| *t >= t0 && l.starts_with(&tag)).map(|(t, _)| *t);
            match (first, oks.iter().max(), fails.iter().min()) {
                (Some(f), Some(last_ok), _) => {
                    println!("  {tag}：启动后 {:.0}ms 内能连网（共 {} 次成功），{}", ms(f, *last_ok), oks.len(), fails.first().map(|x| format!("{:.0}ms 起失败", ms(f, *x))).unwrap_or("一直没有失败".into()));
                    v.push(ms(t0, *last_ok));
                }
                (Some(_), None, Some(_)) => {
                    println!("  {tag}：一开始就连不上");
                    v.push(0.0);
                }
                _ => {
                    never += 1;
                    println!("  {tag}：没有输出");
                }
            }
        }
        report("新子程序启动 → 最后一次连通", v, never);
        let extra = r.last.lock().unwrap().extra_apps.len();
        println!("识别到的关联程序：{extra} 个");
    }

    drop(probe);
    let _ = r.h.shutdown();
    let _ = std::fs::remove_dir_all(&dir);
}

fn fmt_leak(ok_before: bool, leak: Option<f64>) -> String {
    match (ok_before, leak) {
        (false, _) => "—".into(),
        (true, None) => "无".into(),
        (true, Some(v)) => format!("+{v:.0}ms"),
    }
}

// ───────────────────────────── Linux 模拟 ─────────────────────────────

#[cfg(target_os = "linux")]
mod sim {
    use super::*;

    const TUNSETIFF: libc::c_ulong = 0x400454ca;
    const IFF_TUN: libc::c_short = 1;
    const IFF_NO_PI: libc::c_short = 0x1000;

    #[repr(C)]
    struct IfreqFlags {
        name: [u8; 16],
        flags: libc::c_short,
        _pad: [u8; 22],
    }

    #[repr(C)]
    struct IfreqAddr {
        name: [u8; 16],
        addr: libc::sockaddr_in,
        _pad: [u8; 8],
    }

    fn ifname(n: &str) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[..n.len()].copy_from_slice(n.as_bytes());
        b
    }

    /// 一块 tun 网卡：fd 关闭时内核删除网卡（相当于 VPN 客户端退出）。
    pub struct Tun {
        fd: i32,
        name: String,
    }

    impl Tun {
        pub fn up(name: &str, ip: [u8; 4]) -> Tun {
            unsafe {
                let fd = libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR);
                assert!(fd >= 0, "open /dev/net/tun");
                let mut r = IfreqFlags { name: ifname(name), flags: IFF_TUN | IFF_NO_PI, _pad: [0; 22] };
                assert_eq!(libc::ioctl(fd, TUNSETIFF, &mut r), 0, "TUNSETIFF");
                let t = Tun { fd, name: name.into() };
                t.set_addr(ip);
                t.set_flags(libc::IFF_UP as libc::c_short);
                t
            }
        }

        fn ctl(&self, req: libc::c_ulong, arg: *mut libc::c_void) {
            unsafe {
                let s = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
                let r = libc::ioctl(s, req, arg);
                libc::close(s);
                assert_eq!(r, 0, "ioctl {req:#x} on {}", self.name);
            }
        }

        pub fn set_addr(&self, ip: [u8; 4]) {
            let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            sa.sin_family = libc::AF_INET as libc::sa_family_t;
            sa.sin_addr.s_addr = u32::from_ne_bytes(ip);
            let mut r = IfreqAddr { name: ifname(&self.name), addr: sa, _pad: [0; 8] };
            self.ctl(libc::SIOCSIFADDR, &mut r as *mut _ as *mut libc::c_void);
        }

        pub fn set_flags(&self, f: libc::c_short) {
            let mut r = IfreqFlags { name: ifname(&self.name), flags: f, _pad: [0; 22] };
            self.ctl(libc::SIOCSIFFLAGS, &mut r as *mut _ as *mut libc::c_void);
        }
    }

    impl Drop for Tun {
        fn drop(&mut self) {
            unsafe { libc::close(self.fd) };
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Cut {
        /// 网卡消失（VPN 客户端退出）
        Destroy,
        /// 网卡关闭（IFF_UP 去掉）
        Down,
        /// 网卡还在，但没有地址了
        NoAddr,
    }

    fn http_egress(delay: Arc<Mutex<Duration>>) -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for s in l.incoming().flatten() {
                let delay = delay.clone();
                std::thread::spawn(move || {
                    let mut s = s;
                    let mut b = [0u8; 2048];
                    let _ = s.read(&mut b);
                    let d = *delay.lock().unwrap();
                    std::thread::sleep(d);
                    let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\n203.0.113.9\n");
                });
            }
        });
        port
    }

    fn sim_rig(block_on_change: bool, debounce_ms: u64, delay: Arc<Mutex<Duration>>) -> Rig {
        let port = http_egress(delay);
        let mut raw = RawConfig { whitelist: vec!["203.0.113.0/24".into()], apps: vec!["/usr/bin/curl".into()], ..Default::default() };
        raw.detect.services = vec![format!("http://127.0.0.1:{port}/")];
        raw.behavior.block_on_network_change = block_on_change;
        raw.behavior.debounce_ms = debounce_ms;
        raw.ipv6.mode = Ipv6Mode::Off;
        rig(raw, true)
    }

    /// 一组试验：每次建好 VPN 网卡、等引擎放行并守护它，随机等一会儿后断开，测到阻断生效的时间。
    fn scenario(name: &str, r: &Rig, cut: Cut, n: usize, during: &dyn Fn()) {
        let mut v = Vec::new();
        let mut held = Vec::new();
        let mut fails = 0;
        for i in 0..n {
            let tun = Tun::up("wg9", [10, 77, 0, 2]);
            if r.wait("放行并守护 wg9", Duration::from_secs(30), |s| !s.blocked && s.vpn_guarded == ["wg9"]).is_none() {
                fails += 1;
                continue;
            }
            during();
            std::thread::sleep(Duration::from_millis(300 + rand_ms(500)));
            r.drain();
            let t0 = Instant::now();
            let keep = match cut {
                Cut::Destroy => {
                    drop(tun);
                    None
                }
                Cut::Down => {
                    tun.set_flags(0);
                    Some(tun)
                }
                Cut::NoAddr => {
                    tun.set_addr([0, 0, 0, 0]);
                    Some(tun)
                }
            };
            match r.wait("VPN 断开后阻断", Duration::from_secs(5), |s| s.blocked) {
                Some(t1) => {
                    if i == 0 {
                        println!("  （阻断原因：{}）", r.last.lock().unwrap().block_reason.clone().unwrap_or_default());
                    }
                    v.push(ms(t0, t1));
                }
                None => fails += 1,
            }
            drop(keep);
            if let Some(t2) = r.wait("恢复放行（无 VPN）", Duration::from_secs(30), |s| !s.blocked && s.vpn_guarded.is_empty() && !s.checking) {
                held.push(ms(t0, t2) / 1000.0);
            }
        }
        report(name, v, fails);
        if !held.is_empty() {
            println!("  断开后到重新放行（无 VPN）：p50={:.2}s min={:.2}s", pct(&mut held, 0.5), pct(&mut held, 0.0));
        }
    }

    pub fn run(n: usize) {
        egress_guard::logbuf::init("error", true, None);
        let delay = Arc::new(Mutex::new(Duration::ZERO));

        let mut e = Vec::new();
        for _ in 0..200 {
            let t = Instant::now();
            let _ = vpn::scan();
            e.push(t.elapsed().as_secs_f64() * 1000.0);
        }
        println!("网卡枚举 p50={:.3}ms max={:.3}ms", pct(&mut e, 0.5), pct(&mut e, 1.0));

        println!("\n== 1. 安静网络，「网络变化时先阻断」关闭（只有 VPN 守护）==");
        let r = sim_rig(false, 300, delay.clone());
        r.wait("启动检测完成", Duration::from_secs(10), |s| !s.blocked);
        scenario("1a 网卡消失", &r, Cut::Destroy, n, &|| {});
        scenario("1b 网卡关闭", &r, Cut::Down, n, &|| {});
        scenario("1c 网卡失去地址", &r, Cut::NoAddr, n, &|| {});

        println!("\n== 2. 网络持续抖动（每 1.5 秒一次网络变化通知，防抖 2 秒），先阻断关闭 ==");
        let stop = Arc::new(AtomicBool::new(false));
        let r2 = sim_rig(false, 2000, delay.clone());
        r2.wait("启动检测完成", Duration::from_secs(10), |s| !s.blocked);
        {
            let (tx, stop) = (r2.h.sender(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    let _ = tx.send(Event::NetworkChanged);
                    std::thread::sleep(Duration::from_millis(1500));
                }
            });
        }
        scenario("2a 抖动中网卡消失", &r2, Cut::Destroy, n.min(15), &|| {});
        stop.store(true, Ordering::SeqCst);
        let _ = r2.h.shutdown();

        println!("\n== 3. 引擎忙：每秒约 5 万个刷新事件 ==");
        let flood = Arc::new(AtomicBool::new(false));
        {
            let (tx, f) = (r.h.sender(), flood.clone());
            std::thread::spawn(move || loop {
                if f.load(Ordering::SeqCst) {
                    return;
                }
                for _ in 0..500 {
                    let _ = tx.send(Event::Refresh);
                }
                std::thread::sleep(Duration::from_millis(10));
            });
        }
        scenario("3a 事件洪流中网卡消失", &r, Cut::Destroy, n.min(15), &|| {});
        flood.store(true, Ordering::SeqCst);

        println!("\n== 4. 断开时正有一次很慢的检测（3 秒）在进行，结果在断开之后才回来 ==");
        *delay.lock().unwrap() = Duration::from_secs(3);
        let tx = r.h.sender();
        scenario("4a 检测进行中网卡消失", &r, Cut::Destroy, n.min(10), &|| {
            let _ = tx.send(Event::CheckNow);
        });
        *delay.lock().unwrap() = Duration::ZERO;

        println!("\n== 5. 两块 VPN，断开其中一块 ==");
        let other = Tun::up("tun9", [10, 78, 0, 2]);
        let mut v = Vec::new();
        for _ in 0..n.min(10) {
            let wg = Tun::up("wg9", [10, 77, 0, 2]);
            if r.wait("守护两块", Duration::from_secs(30), |s| !s.blocked && s.vpn_guarded.len() == 2).is_none() {
                continue;
            }
            std::thread::sleep(Duration::from_millis(300 + rand_ms(500)));
            r.drain();
            let t0 = Instant::now();
            drop(wg);
            if let Some(t1) = r.wait("断开一块后阻断", Duration::from_secs(5), |s| s.blocked) {
                v.push(ms(t0, t1));
            }
            let _ = r.wait("恢复放行", Duration::from_secs(30), |s| !s.blocked && s.vpn_guarded == ["tun9"] && !s.checking);
        }
        report("5a 两块中断开一块", v, 0);
        drop(other);
        let _ = r.h.shutdown();
    }
}
