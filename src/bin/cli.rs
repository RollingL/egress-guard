//! 命令行版本：egress-guard.exe

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use egress_guard::config::Config;
use egress_guard::egress::EgressDetector;
use egress_guard::{engine, exe_dir, logbuf};

#[derive(Parser)]
#[command(version, about = "根据出口 IP 白名单，用 WFP 阻断/放行选中应用的网络")]
struct Cli {
    /// 配置文件路径（默认：当前目录或 exe 所在目录下的 config.toml）
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,

    /// 日志级别：error / warn / info / debug
    #[arg(long, global = true, default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// 持续运行，按出口 IP 自动阻断/放行（默认命令，需要管理员权限）
    Run {
        /// 只打印决策，不真正修改网络规则（不需要管理员权限）
        #[arg(long)]
        dry_run: bool,
    },
    /// 检测一次当前出口 IP，并显示是否命中白名单
    Ip,
    /// 校验配置文件，并检查应用路径是否存在
    Check,
}

fn main() {
    let cli = Cli::parse();
    logbuf::init(&cli.log_level, true, None);
    if let Err(e) = real_main(cli) {
        log::error!("{e:#}");
        std::process::exit(1);
    }
}

fn real_main(cli: Cli) -> Result<()> {
    let config_path = resolve_config_path(cli.config)?;
    let cfg = Config::load(&config_path)?;
    log::debug!("使用配置文件 {}", config_path.display());

    match cli.command.unwrap_or(Command::Run { dry_run: false }) {
        Command::Run { dry_run } => run(cfg, dry_run),
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
    Ok(exe_dir().context("无法确定 exe 所在目录")?.join("config.toml"))
}

fn run(cfg: Config, dry_run: bool) -> Result<()> {
    if cfg.apps.is_empty() {
        log::warn!("配置中没有受控应用，不会阻断任何程序");
    }
    let handle = Arc::new(engine::spawn(cfg, dry_run, true, Arc::new(|_| {})));
    {
        let tx = handle.sender();
        ctrlc::set_handler(move || {
            let _ = tx.send(engine::Event::Shutdown);
        })
        .context("无法注册 Ctrl+C 处理")?;
    }
    handle.join()
}
