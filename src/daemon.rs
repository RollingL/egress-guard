//! 后台服务：以 root 运行引擎，并通过本地套接字为界面提供状态与设置（macOS 使用）。

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};

use crate::config::{Config, RawConfig};
use crate::engine::{self, Event};
use crate::ipc::{self, Handler, HelloInfo, StatusHub};

pub struct Options {
    pub config_path: PathBuf,
    /// 监听的套接字路径（不是由 launchd 启动时使用）。
    pub socket: PathBuf,
    pub log_path: PathBuf,
    /// 只模拟，不修改网络（测试用）。
    pub dry_run: bool,
}

struct Daemon {
    tx: Mutex<std::sync::mpsc::Sender<Event>>,
    config_path: PathBuf,
    log_path: PathBuf,
    raw: Mutex<RawConfig>,
    /// 配置文件读取失败的原因；成功保存一次新配置后清除。
    config_error: Mutex<Option<String>>,
}

impl Handler for Daemon {
    fn hello(&self) -> HelloInfo {
        HelloInfo {
            version: env!("CARGO_PKG_VERSION").into(),
            config_path: self.config_path.display().to_string(),
            log_path: self.log_path.display().to_string(),
            autostart: autostart_enabled(),
            config_error: self.config_error.lock().unwrap().clone(),
        }
    }

    fn get_config(&self) -> RawConfig {
        self.raw.lock().unwrap().clone()
    }

    fn set_config(&self, raw: RawConfig) -> Result<()> {
        let cfg = Config::from_raw(raw)?;
        cfg.save(&self.config_path)?;
        *self.raw.lock().unwrap() = cfg.to_raw();
        *self.config_error.lock().unwrap() = None;
        log::info!("界面保存了新配置");
        self.send(Event::Reconfigure(cfg));
        Ok(())
    }

    fn check_now(&self) {
        self.send(Event::CheckNow);
    }

    fn clear_learned(&self) {
        self.send(Event::ClearLearned);
    }

    fn set_autostart(&self, on: bool) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            crate::mac::service::set_run_at_load(on)?;
            log::info!("开机自动启动后台服务：{}", if on { "开" } else { "关" });
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = on;
            anyhow::bail!("此平台不支持")
        }
    }

    fn stop(&self) {
        log::info!("界面请求退出：移除阻断规则并停止后台服务");
        self.send(Event::Shutdown);
    }
}

impl Daemon {
    fn send(&self, e: Event) {
        let _ = self.tx.lock().unwrap().send(e);
    }
}

fn autostart_enabled() -> bool {
    #[cfg(target_os = "macos")]
    return crate::mac::service::run_at_load();
    #[cfg(not(target_os = "macos"))]
    false
}

/// 读取配置；不存在时创建默认配置（与 Windows 相同，默认不开启全局断网，安装后不会立刻断网）。
fn load_or_create(path: &Path) -> Result<Config> {
    if path.exists() {
        return Config::load(path);
    }
    let cfg = Config::from_raw(RawConfig::default())?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("无法创建 {}", dir.display()))?;
    }
    cfg.save(path)?;
    log::info!("已创建默认配置 {}", path.display());
    Ok(cfg)
}

fn listener(socket: &Path) -> Result<std::os::unix::net::UnixListener> {
    #[cfg(target_os = "macos")]
    if let Some(l) = crate::mac::service::launchd_listener()? {
        return Ok(l);
    }
    ipc::bind(socket)
}

/// 运行后台服务，直到收到 SIGTERM/SIGINT 或界面请求退出。
pub fn run(opts: Options) -> Result<()> {
    let (cfg, load_error) = match load_or_create(&opts.config_path) {
        Ok(c) => (c, None),
        Err(e) => {
            // 配置损坏时仍然启动，并按最安全的方式（全局断网）运行，界面可以重新保存
            log::error!("{e:#}");
            let mut raw = RawConfig::default();
            raw.block_all.enabled = true;
            (Config::from_raw(raw)?, Some(e))
        }
    };
    if load_error.is_some() {
        log::warn!("配置文件有误，按默认设置并开启全局断网运行；在界面里保存设置会覆盖损坏的配置文件");
    }
    let listener = listener(&opts.socket)?;
    let hub = Arc::new(StatusHub::default());
    let reporter: engine::Reporter = {
        let hub = hub.clone();
        Arc::new(move |s| hub.publish(s))
    };
    let learned = crate::learned_file(&opts.config_path);
    let handle = engine::spawn(cfg.clone(), opts.dry_run, false, Some(learned), reporter);
    let daemon = Arc::new(Daemon {
        tx: Mutex::new(handle.sender()),
        config_path: opts.config_path.clone(),
        log_path: opts.log_path.clone(),
        raw: Mutex::new(cfg.to_raw()),
        config_error: Mutex::new(load_error.map(|e| format!("{e:#}"))),
    });
    ipc::serve(listener, daemon, hub);
    // 告诉网络扩展服务在运行。扩展只在这个文件存在时才连接套接字，
    // 否则「退出」后扩展一重连，launchd 就会按需把服务重新拉起来
    let marker = crate::filterfeed::run_marker(&opts.socket);
    if let Err(e) = std::fs::write(&marker, format!("{}\n", std::process::id())) {
        log::warn!("无法写入 {}: {e}", marker.display());
    }
    {
        let tx = handle.sender();
        ctrlc::set_handler(move || {
            let _ = tx.send(Event::Shutdown);
        })
        .context("无法注册退出信号处理")?;
    }
    log::info!("后台服务 {} 已启动", env!("CARGO_PKG_VERSION"));
    let r = handle.join();
    let _ = std::fs::remove_file(&marker);
    log::info!("后台服务退出");
    r
}
