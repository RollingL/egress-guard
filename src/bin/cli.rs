//! 命令行版本：egress-guard（Windows 上为 egress-guard.exe）。
//!
//! macOS 上它同时是 root 后台服务（`daemon`）和服务的管理工具（`service`、`status`、`apply` 等）。

use std::path::PathBuf;
use std::sync::Arc;
#[cfg(unix)]
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use egress_guard::config::Config;
#[cfg(unix)]
use egress_guard::egress::EgressDetector;
use egress_guard::{engine, exe_dir, learned_file, logbuf};

#[derive(Parser)]
#[command(version, about = "根据出口 IP 白名单阻断/放行网络（Windows：WFP；macOS：pf 全局断网 + 网络扩展按应用断网）")]
struct Cli {
    /// 配置文件路径（默认：当前目录或程序所在目录下的 config.toml；macOS 后台服务见 daemon）
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// 日志级别：error / warn / info / debug
    #[arg(long, global = true, default_value = "info")]
    log_level: String,

    /// 后台服务的本地套接字（macOS，默认 /var/run/egress-guard.sock）
    #[cfg(unix)]
    #[arg(long, global = true)]
    socket: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// 在前台持续运行，按出口 IP 自动阻断/放行（默认命令，需要管理员 / root 权限）
    Run {
        /// 只打印决策，不真正修改网络规则（不需要管理员权限）
        #[arg(long)]
        dry_run: bool,
    },
    /// 检测一次当前出口 IP，并显示是否命中白名单
    Ip,
    /// 校验配置文件，并检查应用路径是否存在
    Check,
    /// DNS 与 WebRTC 泄露测试（不需要管理员权限）
    LeakTest {
        /// 只测 DNS
        #[arg(long, conflicts_with = "webrtc")]
        dns: bool,
        /// 只测 WebRTC
        #[arg(long)]
        webrtc: bool,
        /// 以 JSON 输出
        #[arg(long)]
        json: bool,
        /// 发现泄露（直接观察到白名单以外的地址）时以退出码 2 结束；证据不足、需要留意不算
        #[arg(long)]
        fail_on_leak: bool,
    },
    /// 作为后台服务运行（由 launchd 启动；也可以 sudo 手动运行调试）
    #[cfg(unix)]
    Daemon {
        /// 只模拟，不修改网络
        #[arg(long)]
        dry_run: bool,
    },
    /// 查询后台服务的状态（JSON）
    #[cfg(unix)]
    Status,
    /// 把配置文件交给后台服务校验、保存并立即生效
    #[cfg(unix)]
    Apply {
        /// TOML 配置文件
        file: PathBuf,
    },
    /// 立即检测一次出口 IP（后台服务）
    #[cfg(unix)]
    CheckNow,
    /// 让后台服务移除全部阻断规则并退出
    #[cfg(unix)]
    Stop,
    /// 紧急恢复：清空 pf 中本工具的全部规则（需要 sudo）
    #[cfg(target_os = "macos")]
    Unblock,
    /// 安装 / 卸载后台服务（需要 sudo）
    #[cfg(target_os = "macos")]
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// 内部使用：以低权限检测出口 IP 并打印
    #[cfg(unix)]
    #[command(hide = true)]
    Probe {
        #[arg(long, default_value_t = 5)]
        timeout: u64,
        /// any / v6
        #[arg(long, default_value = "any")]
        family: String,
        /// 从标准输入读取一行作为检测代理（代理地址可能带密码，不放在命令行）
        #[arg(long)]
        proxy_stdin: bool,
        services: Vec<String>,
    },
}

#[cfg(target_os = "macos")]
#[derive(Subcommand)]
enum ServiceAction {
    /// 安装或更新后台服务，并立即启动
    Install,
    /// 停止并卸载后台服务（保留配置）
    Uninstall,
}

fn main() {
    let cli = Cli::parse();
    #[cfg(unix)]
    if let Some(Command::Probe { timeout, family, proxy_stdin, services }) = &cli.command {
        // 检测子进程：结果打印到 stdout，错误打印到 stderr 最后一行
        logbuf::init("error", true, None);
        let family = egress_guard::egress::Family::from_name(family).unwrap_or(egress_guard::egress::Family::Any);
        let mut proxy = None;
        if *proxy_stdin {
            let mut line = String::new();
            if let Err(e) = std::io::stdin().read_line(&mut line) {
                eprintln!("无法读取代理设置: {e}");
                std::process::exit(1);
            }
            // 要求走代理却没读到：明确失败，不能改成直连检测
            if line.trim().is_empty() {
                eprintln!("没有收到代理设置");
                std::process::exit(1);
            }
            proxy = Some(line.trim().to_owned());
        }
        let det = EgressDetector::with_proxy(services.clone(), Duration::from_secs(*timeout), family, proxy.as_deref());
        match det.detect_direct() {
            Ok(ip) => println!("{ip}"),
            Err(e) => {
                eprintln!("{e:#}");
                std::process::exit(1);
            }
        }
        return;
    }
    #[cfg(unix)]
    if matches!(cli.command, Some(Command::Daemon { .. })) {
        // launchd 把 stderr 重定向到单独的文件（只用来收集崩溃信息），日志只写日志文件；手动 sudo 运行时也打印到终端
        use std::io::IsTerminal;
        logbuf::init(&cli.log_level, std::io::stderr().is_terminal(), Some(&daemon_log_path()));
    }
    logbuf::init(&cli.log_level, true, None);
    if let Err(e) = real_main(cli) {
        log::error!("{e:#}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "macos")]
fn daemon_log_path() -> PathBuf {
    egress_guard::mac::paths::LOG_FILE.into()
}

#[cfg(all(unix, not(target_os = "macos")))]
fn daemon_log_path() -> PathBuf {
    std::env::temp_dir().join("egress-guard-daemon.log")
}

#[cfg(unix)]
fn default_socket(cli_socket: &Option<PathBuf>) -> PathBuf {
    if let Some(s) = cli_socket {
        return s.clone();
    }
    #[cfg(target_os = "macos")]
    return egress_guard::mac::paths::SOCKET.into();
    #[cfg(not(target_os = "macos"))]
    std::env::temp_dir().join("egress-guard.sock")
}

#[cfg(unix)]
fn default_daemon_config() -> PathBuf {
    #[cfg(target_os = "macos")]
    return egress_guard::mac::paths::config_path();
    #[cfg(not(target_os = "macos"))]
    PathBuf::from("config.toml")
}

fn real_main(cli: Cli) -> Result<()> {
    #[cfg(unix)]
    {
        use egress_guard::ipc::{Client, Request};
        let socket = default_socket(&cli.socket);
        let client = Client::new(&socket);
        let t = Duration::from_secs(10);
        match &cli.command {
            Some(Command::Daemon { dry_run }) => {
                return egress_guard::daemon::run(egress_guard::daemon::Options {
                    config_path: cli.config.clone().unwrap_or_else(default_daemon_config),
                    socket,
                    log_path: daemon_log_path(),
                    dry_run: *dry_run,
                });
            }
            Some(Command::Status) => {
                let out = serde_json::json!({ "service": client.hello()?, "status": client.status()? });
                println!("{}", serde_json::to_string_pretty(&out)?);
                return Ok(());
            }
            Some(Command::Apply { file }) => {
                let text = std::fs::read_to_string(file).with_context(|| format!("无法读取 {}", file.display()))?;
                let cfg = Config::parse(&text).with_context(|| format!("{} 有误", file.display()))?;
                let version = client.set_config(cfg.to_raw(), t)?;
                // 保存不等于生效：等服务按这一版配置更新规则（旧版本的服务不返回版本，无法确认）
                if version == 0 {
                    println!("已保存 {}（服务版本较旧，无法确认规则是否已按它更新）", file.display());
                    return Ok(());
                }
                let deadline = std::time::Instant::now() + Duration::from_secs(15);
                loop {
                    let s = client.status()?;
                    if s.config_version >= version {
                        match &s.config_apply_error {
                            None => println!("已保存并生效 {}", file.display()),
                            Some(e) if s.config_version == version => {
                                anyhow::bail!("已保存 {}，但规则没有按它更新（服务每 5 秒重试）：{e}", file.display())
                            }
                            Some(_) => println!("已保存 {}（之后又有更新的配置）", file.display()),
                        }
                        return Ok(());
                    }
                    if std::time::Instant::now() >= deadline {
                        anyhow::bail!("已保存 {}，但服务还没有应用它（第 {version} 版）", file.display());
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
            Some(Command::CheckNow) => return client.command(&Request::CheckNow, t),
            Some(Command::Stop) => return client.command(&Request::Stop, t),
            #[cfg(target_os = "macos")]
            Some(Command::Unblock) => {
                let active = egress_guard::mac::pf::anchor_in_use();
                egress_guard::mac::pf::flush_anchor()?;
                println!("已清空 pf 锚点 {} 中的规则", egress_guard::pfrules::ANCHOR);
                if active {
                    println!(
                        "注意：后台服务正在运行，它下次切换或同步规则时会重新装上。要持续解除，请在界面里停止服务，或执行 service uninstall"
                    );
                }
                return Ok(());
            }
            #[cfg(target_os = "macos")]
            Some(Command::Service { action }) => {
                return match action {
                    ServiceAction::Install => {
                        egress_guard::mac::service::install(&std::env::current_exe()?)
                    }
                    ServiceAction::Uninstall => egress_guard::mac::service::uninstall(),
                };
            }
            _ => {}
        }
    }

    // macOS：没有指定 -c 时，泄露测试用后台服务的配置（白名单、可信解析器）
    #[cfg(target_os = "macos")]
    let config_path = match (&cli.config, &cli.command) {
        (None, Some(Command::LeakTest { .. })) => default_daemon_config(),
        _ => resolve_config_path(cli.config.clone())?,
    };
    #[cfg(not(target_os = "macos"))]
    let config_path = resolve_config_path(cli.config.clone())?;
    if let Some(Command::LeakTest { dns, webrtc, json, fail_on_leak }) = cli.command {
        // 没有配置文件时按默认设置测试（白名单为空）
        let cfg = if cli.config.is_some() {
            Config::load(&config_path)?
        } else {
            // 没有用 -c 指定时，默认配置读不了（不存在、macOS 上没有权限读后台服务的配置等）也照样测试
            match config_path.exists().then(|| Config::load(&config_path)) {
                Some(Ok(c)) => c,
                Some(Err(e)) => {
                    eprintln!("警告：无法读取配置文件 {}，按默认设置测试（白名单为空）：{e:#}", config_path.display());
                    Config::from_raw(Default::default())?
                }
                None => Config::from_raw(Default::default())?,
            }
        };
        return leak_test(&cfg, !webrtc, !dns, json, fail_on_leak);
    }
    let cfg = Config::load(&config_path)?;
    log::debug!("使用配置文件 {}", config_path.display());

    match cli.command.unwrap_or(Command::Run { dry_run: false }) {
        Command::Run { dry_run } => {
            egress_guard::eventlog::init(&egress_guard::events_file(&config_path));
            run(cfg, dry_run, learned_file(&config_path))
        }
        Command::Ip => {
            let egress = egress_guard::egress::Detectors::new(&cfg).detect()?;
            let ip = egress.ip;
            println!("出口 IP: {ip}（{}）", if cfg.is_whitelisted(ip) { "在白名单内" } else { "不在白名单内" });
            match egress.extra_v6() {
                Some(v) => {
                    println!("IPv6 出口: {v}（{}）", if cfg.is_whitelisted(v) { "在白名单内" } else { "不在白名单内" })
                }
                None if cfg.ipv6.mode == egress_guard::config::Ipv6Mode::Check && ip.is_ipv4() => {
                    println!("IPv6 出口: 本机没有 IPv6 路由")
                }
                None => {}
            }
            let ok = egress_guard::controller::egress_allowed(&cfg, &egress);
            println!("白名单: {}", if ok { "命中 → 放行" } else { "未命中 → 阻断" });
            Ok(())
        }
        Command::Check => {
            println!("配置文件: {}", config_path.display());
            println!("白名单 {} 条:", cfg.whitelist.len());
            for net in &cfg.whitelist {
                println!("  {net}");
            }
            println!("受控应用 {} 个:", cfg.apps.len());
            for app in &cfg.apps {
                let mark = if app.exists() { "存在" } else { "不存在！" };
                println!("  [{mark}] {}", app.display());
            }
            Ok(())
        }
        #[allow(unreachable_patterns)]
        _ => unreachable!("已在上面处理"),
    }
}

fn leak_test(cfg: &Config, do_dns: bool, do_webrtc: bool, json: bool, fail_on_leak: bool) -> Result<()> {
    use egress_guard::leaktest::{self, dns, webrtc, Judge, Level};

    let lt = &cfg.leak_test;
    let judge = Judge { whitelist: cfg.whitelist.clone(), trusted: lt.trusted_dns.iter().filter_map(|s| leaktest::Trusted::parse(s).ok()).collect() };
    // 出口基线与引擎相同（同样的代理设置和地址族），对照的才是引擎据以放行的那个出口
    let egress = match egress_guard::egress::Detectors::new(cfg).detect() {
        Ok(e) => Some(e.ip),
        Err(e) => {
            log::warn!("无法检测出口 IP：{e:#}");
            None
        }
    };
    let (dns_r, rtc_r) = std::thread::scope(|s| {
        let d = do_dns.then(|| s.spawn(|| dns::run(&lt.dnscheck_zone, &lt.dns_sources, egress, &judge, &|_| {}, &|| false)));
        let w = do_webrtc.then(|| s.spawn(|| webrtc::run(&lt.stun_servers, egress, &judge, &|| false)));
        (d.map(|j| j.join().expect("DNS 测试线程异常")), w.map(|j| j.join().expect("WebRTC 测试线程异常")))
    });

    let mut leak = false;
    if json {
        let out = serde_json::json!({
            "egress": egress,
            "egress_whitelisted": egress.map(|ip| cfg.is_whitelisted(ip)),
            "dns": dns_r.as_ref().map(|r| match r {
                Ok(r) => serde_json::json!({ "summary": dns_summary_json(r), "report": r }),
                Err(e) => serde_json::json!({ "error": format!("{e:#}") }),
            }),
            "webrtc": rtc_r.as_ref().map(|r| {
                let (level, text) = leaktest::webrtc_summary(r);
                serde_json::json!({ "summary": { "level": level, "text": text }, "report": r })
            }),
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    }

    match egress {
        Some(ip) if !json => {
            let wl = if cfg.is_whitelisted(ip) { "在白名单内" } else { "不在白名单内" };
            println!("出口 IP：{ip}（{wl}）");
        }
        None if !json => println!("出口 IP：未知"),
        _ => {}
    }
    if let Some(r) = &dns_r {
        if !json {
            println!("\n== DNS 泄露测试 ==");
        }
        match r {
            Ok(r) => {
                let (level, text) = leaktest::dns_summary(r);
                leak |= level == Level::Leak;
                if !json {
                    for s in &r.sources {
                        println!("  检测源 {}：{}{}", s.name, if s.ok { "" } else { "失败，" }, s.detail);
                    }
                    for x in &r.resolvers {
                        let info = x.info.as_ref().map(|i| i.describe()).unwrap_or_default();
                        let mut extra = x.sources.join("、");
                        if x.queries > 0 {
                            extra = format!("{} {} 次查询，{extra}", x.protos.join("/"), x.queries);
                        }
                        println!("  [{}] {}  {info}（{extra}）", x.verdict.label(), x.ip);
                    }
                    for x in &r.client_subnets {
                        let info = x.info.as_ref().map(|i| i.describe()).unwrap_or_default();
                        println!("  [{}] ECS 客户端网段 {}  {info}", x.verdict.label(), x.subnet);
                    }
                    println!("结论：{text}");
                }
            }
            Err(e) if !json => println!("测试失败：{e:#}"),
            Err(_) => {}
        }
    }
    if let Some(r) = &rtc_r {
        let (level, text) = leaktest::webrtc_summary(r);
        leak |= level == Level::Leak;
        if !json {
            println!("\n== WebRTC 泄露测试 ==");
            for u in &r.unresolved {
                println!("  STUN 服务器无法解析：{u}");
            }
            for p in &r.paths {
                let from = match &p.iface {
                    None => format!("默认路由（{}）", if p.local.is_ipv4() { "IPv4" } else { "IPv6" }),
                    Some(n) => format!("{n} {}", p.local),
                };
                match (&p.mapped, &p.server) {
                    (Some(m), Some(s)) => println!("  [{}] {from} → {}（{s}）", p.verdict.label(), m.ip()),
                    _ => println!("  [{}] {from}：{}", p.verdict.label(), p.error.as_deref().unwrap_or("")),
                }
            }
            for h in &r.hosts {
                println!("  [{}] 网卡地址 {} {}", h.verdict.label(), h.iface, h.ip);
            }
            println!("结论：{text}");
        }
    }
    if fail_on_leak && leak {
        std::process::exit(2);
    }
    Ok(())
}

fn dns_summary_json(r: &egress_guard::leaktest::dns::DnsReport) -> serde_json::Value {
    let (level, text) = egress_guard::leaktest::dns_summary(r);
    serde_json::json!({ "level": level, "text": text })
}

fn resolve_config_path(arg: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = arg {
        return Ok(p);
    }
    let cwd = PathBuf::from("config.toml");
    if cwd.exists() {
        return Ok(cwd);
    }
    Ok(exe_dir().context("无法确定程序所在目录")?.join("config.toml"))
}

fn run(cfg: Config, dry_run: bool, learned_file: PathBuf) -> Result<()> {
    if cfg.apps.is_empty() && !cfg.block_all.enabled {
        log::warn!("配置中没有受控应用，也没有开启全局断网，不会阻断任何连接");
    }
    let handle = Arc::new(engine::spawn(cfg, dry_run, true, Some(learned_file), Arc::new(|_| {})));
    {
        let tx = handle.sender();
        ctrlc::set_handler(move || {
            let _ = tx.send(engine::Event::Shutdown);
        })
        .context("无法注册 Ctrl+C 处理")?;
    }
    handle.join()
}
