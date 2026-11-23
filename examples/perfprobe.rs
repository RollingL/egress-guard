//! 性能测量（只读，不改网络）：网卡枚举、VPN 轮询线程、进程扫描、引擎稳态、托盘图标、序列化、子进程开销，
//! 以及 WFP 重试复现。用法：cargo run --release --example perfprobe -- [秒数] [要扫描的目录]

#[cfg(any(windows, target_os = "macos"))]
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use egress_guard::config::{Config, RawConfig};
use egress_guard::controller::Controller;
use egress_guard::engine::{self, Status};
use egress_guard::vpn;
use egress_guard::wfpcore::{Api, Filter, Kill, Layer, Wfp};

fn cpu() -> Duration {
    #[cfg(unix)]
    unsafe {
        let mut r: libc::rusage = std::mem::zeroed();
        libc::getrusage(libc::RUSAGE_SELF, &mut r);
        let us = |t: libc::timeval| t.tv_sec as u64 * 1_000_000 + t.tv_usec as u64;
        Duration::from_micros(us(r.ru_utime) + us(r.ru_stime))
    }
    #[cfg(windows)]
    unsafe {
        use windows::Win32::Foundation::FILETIME;
        use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};
        let (mut c, mut e, mut k, mut u) = (FILETIME::default(), FILETIME::default(), FILETIME::default(), FILETIME::default());
        let _ = GetProcessTimes(GetCurrentProcess(), &mut c, &mut e, &mut k, &mut u);
        let t = |f: FILETIME| ((f.dwHighDateTime as u64) << 32 | f.dwLowDateTime as u64) * 100;
        Duration::from_nanos(t(k) + t(u))
    }
}

/// 进程的线程数、句柄数（取得到时）。
fn threads_handles() -> String {
    #[cfg(target_os = "linux")]
    {
        let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let th = s.lines().find(|l| l.starts_with("Threads:")).unwrap_or("").trim().to_owned();
        let fds = std::fs::read_dir("/proc/self/fd").map(|d| d.count()).unwrap_or(0);
        let rss = s.lines().find(|l| l.starts_with("VmRSS:")).unwrap_or("").split_whitespace().collect::<Vec<_>>().join(" ");
        format!("{th} fds: {fds} {rss}")
    }
    #[cfg(windows)]
    unsafe {
        use windows::Win32::System::Diagnostics::ToolHelp::*;
        use windows::Win32::System::Threading::{GetCurrentProcess, GetCurrentProcessId, GetProcessHandleCount};
        let mut handles = 0u32;
        let _ = GetProcessHandleCount(GetCurrentProcess(), &mut handles);
        let me = GetCurrentProcessId();
        let mut n = 0;
        if let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
            let mut e = THREADENTRY32 { dwSize: std::mem::size_of::<THREADENTRY32>() as u32, ..Default::default() };
            let mut ok = Thread32First(snap, &mut e).is_ok();
            while ok {
                if e.th32OwnerProcessID == me {
                    n += 1;
                }
                ok = Thread32Next(snap, &mut e).is_ok();
            }
            let _ = windows::Win32::Foundation::CloseHandle(snap);
        }
        format!("Threads: {n} handles: {handles}")
    }
    #[cfg(target_os = "macos")]
    {
        let pid = std::process::id().to_string();
        let out = std::process::Command::new("ps").args(["-M", "-p", &pid]).output().map(|o| o.stdout).unwrap_or_default();
        let th = String::from_utf8_lossy(&out).lines().count().saturating_sub(1);
        let rss = std::process::Command::new("ps").args(["-o", "rss=", "-p", &pid]).output().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned()).unwrap_or_default();
        format!("Threads: {th} RSS: {rss} kB")
    }
}

fn stats(name: &str, mut v: Vec<Duration>) {
    v.sort();
    let n = v.len();
    let sum: Duration = v.iter().sum();
    println!(
        "{name}: n={n} mean={:.1}µs p50={:.1}µs p99={:.1}µs max={:.1}µs",
        sum.as_secs_f64() * 1e6 / n as f64,
        v[n / 2].as_secs_f64() * 1e6,
        v[(n * 99 / 100).min(n - 1)].as_secs_f64() * 1e6,
        v[n - 1].as_secs_f64() * 1e6
    );
}

fn bench<T>(name: &str, n: usize, mut f: impl FnMut() -> T) {
    let _ = f();
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        let t = Instant::now();
        std::hint::black_box(f());
        v.push(t.elapsed());
    }
    stats(name, v);
}

/// 在给定时长内测进程 CPU（毫秒）与 CPU 占比。
fn measure(name: &str, secs: u64, f: impl FnOnce()) {
    let c0 = cpu();
    let t0 = Instant::now();
    f();
    std::thread::sleep(Duration::from_secs(secs));
    let c = cpu() - c0;
    let wall = t0.elapsed();
    println!(
        "{name}: {secs}s 内进程 CPU {:.1} ms（{:.3}% 单核）｜{}",
        c.as_secs_f64() * 1e3,
        c.as_secs_f64() / wall.as_secs_f64() * 100.0,
        threads_handles()
    );
}

/// 本地出口查询服务：总是回答 203.0.113.9。
fn local_service() -> (String, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            let mut s = s;
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf);
            h.fetch_add(1, Ordering::SeqCst);
            let body = "203.0.113.9\n";
            let _ = write!(s, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
        }
    });
    (format!("http://127.0.0.1:{port}/"), hits)
}

// ---------------- WFP：缺失程序时的重试 ----------------

#[derive(Default)]
struct Count {
    begins: usize,
    adds: usize,
    deletes: usize,
}

struct CountingApi(Arc<Mutex<Count>>, u64);

impl Api for CountingApi {
    fn begin(&mut self) -> anyhow::Result<()> {
        self.0.lock().unwrap().begins += 1;
        Ok(())
    }
    fn commit(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
    fn abort(&mut self) {}
    fn add(&mut self, _: &Layer, _: &Filter<'_>) -> anyhow::Result<u64> {
        self.0.lock().unwrap().adds += 1;
        self.1 += 1;
        Ok(self.1)
    }
    fn delete(&mut self, _: u64) -> anyhow::Result<()> {
        self.0.lock().unwrap().deletes += 1;
        Ok(())
    }
    fn kill(&self, _: Kill) {}
}

fn wfp_retry_repro() {
    let count = Arc::new(Mutex::new(Count::default()));
    let fw = Wfp::new(CountingApi(count.clone(), 0), None);
    let exe = std::env::current_exe().unwrap();
    let missing = PathBuf::from(if cfg!(windows) { r"C:\NotInstalled\app.exe" } else { "/nonexistent/app" });
    let raw = RawConfig { whitelist: vec!["198.51.100.0/24".into()], apps: vec![exe, missing], ..Default::default() };
    let cfg = Config::from_raw(raw).unwrap();
    let mut ctrl = Controller::new(cfg, Box::new(fw));
    ctrl.apply_rules().unwrap();
    ctrl.block_for("测试").unwrap();
    let before = { let c = count.lock().unwrap(); (c.begins, c.adds, c.deletes) };
    let mut retries = 0;
    for _ in 0..12 {
        // 引擎：needs_retry 为真时每 5 秒调用一次 retry_pending（这里不等，直接调 12 次 = 1 分钟）
        if ctrl.needs_retry() {
            retries += 1;
            ctrl.retry_pending().unwrap();
        }
    }
    let c = count.lock().unwrap();
    println!(
        "WFP 重试复现：阻断中、1 个受控程序不存在 → 1 分钟内 retry_pending {retries} 次，WFP 事务 {} 次，新增过滤器 {}，删除 {}；needs_retry 仍为 {}",
        c.begins - before.0,
        c.adds - before.1,
        c.deletes - before.2,
        ctrl.needs_retry()
    );
}

// ---------------- 引擎稳态 ----------------

fn engine_steady(secs: u64, guarded_iface: Option<String>, apps: Vec<PathBuf>) {
    let (url, hits) = local_service();
    let mut raw = RawConfig { whitelist: vec!["203.0.113.0/24".into()], apps, ..Default::default() };
    raw.detect.services = vec![url];
    if let Some(i) = &guarded_iface {
        raw.vpn.interfaces = vec![i.clone()];
    }
    let cfg = Config::from_raw(raw).unwrap();
    let reports = Arc::new(AtomicU64::new(0));
    let last = Arc::new(Mutex::new(Status::default()));
    let (r, l) = (reports.clone(), last.clone());
    let reporter: engine::Reporter = Arc::new(move |s: &Status| {
        r.fetch_add(1, Ordering::SeqCst);
        *l.lock().unwrap() = s.clone();
    });
    let h = engine::spawn(cfg, true, false, None, reporter);
    // 等第一次检测放行、守护生效
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(10) {
        let s = last.lock().unwrap().clone();
        if s.last_check.is_some() && !s.blocked && (guarded_iface.is_none() || !s.vpn_guarded.is_empty()) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let (r0, h0) = (reports.load(Ordering::SeqCst), hits.load(Ordering::SeqCst));
    let label = match &guarded_iface {
        Some(i) => format!("引擎稳态（守护 {i}，dry-run，受控应用 {}）", last.lock().unwrap().extra_apps.len()),
        None => "引擎稳态（无守护，dry-run）".to_owned(),
    };
    measure(&label, secs, || {});
    let s = last.lock().unwrap().clone();
    println!(
        "  └ 状态上报 {} 次，出口检测 {} 次；blocked={} guarded={:?}",
        reports.load(Ordering::SeqCst) - r0,
        hits.load(Ordering::SeqCst) - h0,
        s.blocked,
        s.vpn_guarded
    );
    let _ = h.shutdown();
}

/// 一次系统网络变化会产生多少个 NetworkChanged（每个都会让引擎枚举一次网卡、上报一次状态）。
#[cfg(any(windows, target_os = "macos"))]
fn netwatch_burst() {
    use egress_guard::engine::{Event, NetNotifier};
    let (tx, rx) = std::sync::mpsc::channel::<Event>();
    let net = NetNotifier::new(tx);
    #[cfg(windows)]
    let _w = egress_guard::win::netwatch::NetWatcher::start(net.clone()).unwrap();
    #[cfg(target_os = "macos")]
    let _w = egress_guard::mac::netwatch::start(net.clone()).unwrap();
    // 像引擎一样：每取到一个事件就清掉合并标志（每 5ms 取一次，相当于引擎处理得很快）
    let count = |rx: &std::sync::mpsc::Receiver<Event>, wait: Duration| {
        let end = Instant::now() + wait;
        let mut c = 0;
        while Instant::now() < end {
            while let Ok(e) = rx.try_recv() {
                if matches!(e, Event::NetworkChanged) {
                    c += 1;
                    net.taken();
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        c
    };
    println!("网络变化通知：空闲 30 秒内 {} 个", count(&rx, Duration::from_secs(30)));
    let run = |args: &[&str]| {
        let out = std::process::Command::new(args[0]).args(&args[1..]).output();
        match out {
            Ok(o) if o.status.success() => {}
            Ok(o) => println!("  （{} 失败：{}{}）", args.join(" "), String::from_utf8_lossy(&o.stdout).trim(), String::from_utf8_lossy(&o.stderr).trim()),
            Err(e) => println!("  （无法运行 {}：{e}）", args[0]),
        }
    };
    #[cfg(windows)]
    let steps: Vec<(&str, Vec<&str>)> = vec![
        ("添加一条 IPv4 路由", vec!["route", "ADD", "198.51.100.0", "MASK", "255.255.255.0", "127.0.0.1"]),
        ("删除这条路由", vec!["route", "DELETE", "198.51.100.0"]),
        ("添加一个 IPv6 地址（环回网卡）", vec!["netsh", "interface", "ipv6", "add", "address", "Loopback Pseudo-Interface 1", "2001:db8:77::7"]),
        ("删除这个地址", vec!["netsh", "interface", "ipv6", "delete", "address", "Loopback Pseudo-Interface 1", "2001:db8:77::7"]),
    ];
    #[cfg(target_os = "macos")]
    let steps: Vec<(&str, Vec<&str>)> = vec![
        ("添加一条 IPv4 路由", vec!["/sbin/route", "-n", "add", "-net", "198.51.100.0/24", "127.0.0.1"]),
        ("删除这条路由", vec!["/sbin/route", "-n", "delete", "-net", "198.51.100.0/24"]),
        ("给 lo0 加一个地址", vec!["/sbin/ifconfig", "lo0", "alias", "198.51.100.7"]),
        ("删除这个地址", vec!["/sbin/ifconfig", "lo0", "-alias", "198.51.100.7"]),
    ];
    for (what, args) in steps {
        run(&args);
        println!("网络变化通知：{what} → {} 个", count(&rx, Duration::from_secs(2)));
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
fn netwatch_burst() {}

fn main() {
    egress_guard::logbuf::init("warn", true, None);
    let args: Vec<String> = std::env::args().collect();
    let secs: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(20);
    let dir = args.get(2).map(PathBuf::from);
    println!("平台 {} {}，CPU {} 核", std::env::consts::OS, std::env::consts::ARCH, std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0));
    println!("基线：{}", threads_handles());

    // 1. 网卡枚举
    let adapters = vpn::scan().unwrap_or_default();
    let addrs: usize = adapters.iter().map(|a| a.addrs.len()).sum();
    println!("网卡 {} 块，地址 {} 个：{:?}", adapters.len(), addrs, adapters.iter().map(|a| &a.name).collect::<Vec<_>>());
    bench("vpn::scan()（一次枚举）", 2000, vpn::scan);
    let cfg = egress_guard::config::VpnConfig::default();
    bench("vpn::links()（识别 VPN）", 2000, || vpn::links(&adapters, &cfg));

    // 2. 轮询线程本身
    let n = Arc::new(AtomicUsize::new(0));
    measure("vpn-watch 空闲（2s 一次）", secs, || {
        let n = n.clone();
        let w = vpn::spawn_watch(move |_| {
            n.fetch_add(1, Ordering::SeqCst);
            true
        });
        std::mem::forget(w);
    });
    let n2 = Arc::new(AtomicUsize::new(0));
    let w = {
        let n2 = n2.clone();
        vpn::spawn_watch(move |_| {
            n2.fetch_add(1, Ordering::SeqCst);
            true
        })
    };
    measure("vpn-watch 守护（0.25s 一次，另一条空闲线程仍在）", secs, || w.set_active(true));
    drop(w);

    // 3. 进程扫描
    #[cfg(any(windows, target_os = "macos"))]
    {
        #[cfg(windows)]
        let snap = egress_guard::win::procs::snapshot;
        #[cfg(target_os = "macos")]
        let snap = egress_guard::mac::procs::snapshot;
        let t = Instant::now();
        let procs = snap();
        println!("进程快照（首次）：{} 个进程，{:.2} ms", procs.len(), t.elapsed().as_secs_f64() * 1e3);
        bench("进程快照（稳态，每秒一次的那一步）", 50, snap);
        let target = procs.iter().find(|p| !p.path.is_empty()).map(|p| egress_guard::discovery::normalize(&p.path)).unwrap_or_default();
        let targets: HashMap<String, egress_guard::discovery::Roots> = [(target.clone(), [target].into())].into();
        bench("descendants_of_targets（1 个受控应用）", 200, || egress_guard::discovery::descendants_of_targets(&procs, &targets));
        let c0 = cpu();
        let t0 = Instant::now();
        for _ in 0..secs {
            std::hint::black_box(snap());
            std::thread::sleep(Duration::from_secs(1));
        }
        let c = cpu() - c0;
        println!("每秒一次进程快照：{secs}s 内 CPU {:.1} ms（{:.3}% 单核）", c.as_secs_f64() * 1e3, c.as_secs_f64() / t0.elapsed().as_secs_f64() * 100.0);
    }

    // 4. 目录扫描（include_app_dir：每 30 秒一次）
    if let Some(d) = &dir {
        let t = Instant::now();
        let v = egress_guard::discovery::scan_dir_exes(d, 12, 1000);
        println!("scan_dir_exes({})：找到 {} 个程序，{:.1} ms", d.display(), v.len(), t.elapsed().as_secs_f64() * 1e3);
    }

    // 5. 托盘图标、状态序列化
    bench("shield_rgba(32)（托盘图标每次更新都重画）", 200, || egress_guard::gui::icons::shield_rgba(32, egress_guard::gui::icons::Shade::Green));
    let st = Status {
        running: true,
        egress_ip: Some("203.0.113.9".parse().unwrap()),
        whitelisted: Some(true),
        vpn_connected: vec!["utun4".into()],
        vpn_guarded: vec!["utun4".into()],
        last_check: Some("12:00:00".into()),
        extra_apps: (0..20).map(|i| egress_guard::discovery::ExtraApp { path: format!("/Applications/Foo.app/Contents/Helpers/h{i}").into(), source: egress_guard::discovery::Source::Child }).collect(),
        ..Default::default()
    };
    let json = serde_json::to_string(&st).unwrap();
    println!("Status JSON {} 字节（20 个关联程序）", json.len());
    bench("Status 序列化", 2000, || serde_json::to_string(&st).unwrap());
    bench("Status clone", 2000, || st.clone());

    // 6. 子进程（macOS 出口检测、pfctl 每次都起一个进程）
    #[cfg(unix)]
    bench("启动并等待一个子进程（/usr/bin/true）", 30, || std::process::Command::new("/usr/bin/true").status().unwrap());
    #[cfg(windows)]
    bench("启动并等待一个子进程（cmd /c exit）", 30, || std::process::Command::new("cmd").args(["/c", "exit"]).status().unwrap());

    // 7. WFP 重试复现（与平台无关）
    wfp_retry_repro();

    // 8. 引擎稳态
    engine_steady(secs, None, Vec::new());
    if let Some(a) = adapters.first() {
        engine_steady(secs, Some(a.name.clone()), Vec::new());
        #[cfg(any(windows, target_os = "macos"))]
        engine_steady(secs, Some(a.name.clone()), vec![std::env::current_exe().unwrap()]);
    }
    netwatch_burst();
    std::thread::sleep(Duration::from_secs(2));
    println!("结束：{}", threads_handles());
}
