//! 命令行版本：egress-guard（Windows 上为 egress-guard.exe）。
//!
//! macOS 上它同时是 root 后台服务（`daemon`）和服务的管理工具（`service`、`status`、`apply` 等）。

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use egress_guard::config::Config;
use egress_guard::egress::EgressDetector;
use egress_guard::{engine, exe_dir, learned_file, logbuf};

#[derive(Parser)]
#[command(version, about = "根据出口 IP 白名单阻断/放行网络（Windows：WFP 按应用；macOS：pf 全局断网）")]
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
    if let Some(Command::Probe { timeout, services }) = &cli.command {
        // 检测子进程：结果打印到 stdout，错误打印到 stderr 最后一行
        logbuf::init("error", true, None);
        let det = EgressDetector::new(services.clone(), Duration::from_secs(*timeout));
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
        logbuf::init(&cli.log_level, true, Some(&daemon_log_path()));
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
                client.command(&Request::SetConfig(Box::new(cfg.to_raw())), t)?;
                println!("已应用 {}", file.display());
                return Ok(());
            }
            Some(Command::CheckNow) => return client.command(&Request::CheckNow, t),
            Some(Command::Stop) => return client.command(&Request::Stop, t),
            #[cfg(target_os = "macos")]
            Some(Command::Unblock) => {
                egress_guard::mac::pf::flush_anchor()?;
                println!("已清空 pf 锚点 {} 中的规则", egress_guard::pfrules::ANCHOR);
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

    let config_path = resolve_config_path(cli.config)?;
    let cfg = Config::load(&config_path)?;
    log::debug!("使用配置文件 {}", config_path.display());

    match cli.command.unwrap_or(Command::Run { dry_run: false }) {
        Command::Run { dry_run } => run(cfg, dry_run, learned_file(&config_path)),
        Command::Ip => {
            let det = EgressDetector::new(
                cfg.detect.services.clone(),
                Duration::from_secs(cfg.detect.timeout_secs),
            );
            let ip = det.detect()?;
            let ok = cfg.is_whitelisted(ip);
            println!("出口 IP: {ip}");
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
