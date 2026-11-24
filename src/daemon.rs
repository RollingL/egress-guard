//! 后台服务：以 root 运行引擎，并通过本地套接字为界面提供状态与设置（macOS 使用）。

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};

use crate::config::{Config, Loaded, RawConfig};
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
    /// 配置提交锁和最近分配的配置版本：校验、写盘、更新共享配置、通知引擎在锁内依次完成，
    /// 两个界面同时保存时，磁盘、共享配置和引擎收到的顺序一致。
    commit: Mutex<u64>,
}

impl Handler for Daemon {
    fn hello(&self) -> HelloInfo {
        HelloInfo {
            version: env!("CARGO_PKG_VERSION").into(),
            config_path: self.config_path.display().to_string(),
            log_path: self.log_path.display().to_string(),
            autostart: autostart_enabled(),
            config_error: self.config_error.lock().unwrap().clone(),
            // 由 ipc::serve 填写
            features: Vec::new(),
        }
    }

    fn get_config(&self) -> RawConfig {
        self.raw.lock().unwrap().clone()
    }

    fn set_config(&self, raw: RawConfig) -> Result<u64> {
        let mut version = self.commit.lock().unwrap();
        let cfg = Config::from_raw(raw)?;
        cfg.save(&self.config_path)?;
        *version += 1;
        *self.raw.lock().unwrap() = cfg.to_raw();
        *self.config_error.lock().unwrap() = None;
        log::info!("界面保存了新配置（版本 {}）", *version);
        self.tx
            .lock()
            .unwrap()
            .send(Event::Reconfigure(Box::new(cfg), *version))
            .map_err(|_| anyhow::anyhow!("配置已保存，但引擎已经停止，规则没有更新"))?;
        Ok(*version)
    }

    fn check_now(&self) {
        self.send(Event::CheckNow);
    }

    fn clear_learned(&self) {
        self.send(Event::ClearLearned);
    }

    fn confirm_child(&self, path: std::path::PathBuf) {
        self.send(Event::ConfirmChild(path));
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

/// 读取配置；只有配置文件和最近有效配置的副本都不存在（真正的首次启动）时才创建默认配置
/// （与 Windows 相同，默认不开启全局断网，安装后不会立刻断网）。
/// 配置文件丢失、有误或读不了时改用最近一次有效的配置；那时不创建默认配置，副本不会被覆盖。
fn load_or_create(path: &Path) -> Loaded {
    match Config::load_startup(path) {
        Loaded::Missing => match create_default(path) {
            Ok(cfg) => Loaded::Ok(cfg),
            Err(e) => Loaded::Failed { error: format!("{e:#}"), broken: None },
        },
        other => other,
    }
}

fn create_default(path: &Path) -> Result<Config> {
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
    let saved_as = |broken: &Option<std::path::PathBuf>| match broken {
        Some(b) => format!("原文件已另存为 {}。", b.display()),
        None => String::new(),
    };
    let (cfg, load_error) = match load_or_create(&opts.config_path) {
        Loaded::Ok(c) => (c, None),
        Loaded::LastGood { cfg: c, error, broken } => {
            let msg = format!(
                "后台服务已改用最近一次有效的配置运行（保护设置与上次成功保存时相同）。{}检查各项设置后点「保存并应用」，会覆盖有误的文件。{error}",
                saved_as(&broken)
            );
            (c, Some(msg))
        }
        Loaded::Missing => unreachable!("load_or_create 已经处理"),
        Loaded::Failed { error: e, broken } => {
            // 配置损坏、也没有最近有效的配置时仍然启动，并按最安全的方式（全局断网）运行，界面可以重新保存
            log::error!("{e}");
            log::warn!("配置文件有误，按默认设置并开启全局断网运行；在界面里保存设置会覆盖损坏的配置文件");
            let mut raw = RawConfig::default();
            raw.block_all.enabled = true;
            let msg = format!(
                "为安全起见，后台服务正按默认设置运行并开启了全局断网。{}检查各项设置后点「保存并应用」，会覆盖损坏的文件。{e}",
                saved_as(&broken)
            );
            (Config::from_raw(raw)?, Some(msg))
        }
    };
    let listener = listener(&opts.socket)?;
    let hub = Arc::new(StatusHub::default());
    let reporter: engine::Reporter = {
        let hub = hub.clone();
        Arc::new(move |s| hub.publish(s))
    };
    let learned = crate::learned_file(&opts.config_path);
    crate::eventlog::init(&crate::events_file(&opts.config_path));
    let handle = engine::spawn(cfg.clone(), opts.dry_run, false, Some(learned), reporter);
    let daemon = Arc::new(Daemon {
        tx: Mutex::new(handle.sender()),
        config_path: opts.config_path.clone(),
        log_path: opts.log_path.clone(),
        raw: Mutex::new(cfg.to_raw()),
        config_error: Mutex::new(load_error),
        commit: Mutex::new(0),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 两个界面同时保存：磁盘、共享配置和引擎最后收到的是同一份，版本单调递增；引擎停止时报错。
    #[test]
    fn concurrent_saves_stay_in_order() {
        let dir = std::env::temp_dir().join(format!("egress-guard-daemon-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        let (tx, rx) = std::sync::mpsc::channel();
        let d = Arc::new(Daemon {
            tx: Mutex::new(tx),
            config_path: path.clone(),
            log_path: dir.join("log"),
            raw: Mutex::new(RawConfig::default()),
            config_error: Mutex::new(None),
            commit: Mutex::new(0),
        });
        let threads: Vec<_> = (0..2)
            .map(|t| {
                let d = d.clone();
                std::thread::spawn(move || {
                    for i in 0..20 {
                        let raw = RawConfig { whitelist: vec![format!("10.{t}.{i}.0/24")], ..Default::default() };
                        d.set_config(raw).unwrap();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let got: Vec<(Config, u64)> = rx
            .try_iter()
            .map(|e| match e {
                Event::Reconfigure(c, v) => (*c, v),
                _ => panic!("意外的事件"),
            })
            .collect();
        assert_eq!(got.iter().map(|(_, v)| *v).collect::<Vec<_>>(), (1..=40).collect::<Vec<_>>());
        let (last, _) = got.last().unwrap();
        let disk = Config::load(&path).unwrap();
        assert_eq!(disk.to_raw(), last.to_raw());
        assert_eq!(*d.raw.lock().unwrap(), last.to_raw());
        // 引擎停了：配置照样保存，但要报告规则没有更新
        drop(rx);
        let raw = RawConfig { whitelist: vec!["192.0.2.0/24".into()], ..Default::default() };
        let err = d.set_config(raw).unwrap_err();
        assert!(format!("{err:#}").contains("引擎已经停止"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 服务的启动入口：主文件被删、副本还在时用副本恢复，不创建默认配置、不覆盖副本；
    /// 两者都不存在才创建默认配置。
    #[test]
    fn startup_recovers_instead_of_overwriting_last_good() {
        let dir = std::env::temp_dir().join(format!("eg-daemon-startup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("config.toml");
        let Loaded::Ok(fresh) = load_or_create(&path) else { panic!("首次启动应创建默认配置") };
        assert!(path.exists() && !fresh.block_all.enabled);

        let mut raw = RawConfig { whitelist: vec!["203.0.113.0/24".into()], apps: vec!["/Applications/A.app".into()], ..Default::default() };
        raw.block_all.enabled = true;
        let cfg = Config::from_raw(raw).unwrap();
        cfg.save(&path).unwrap();
        let good = std::fs::read_to_string(crate::config::last_good_path(&path)).unwrap();
        std::fs::remove_file(&path).unwrap();
        match load_or_create(&path) {
            Loaded::LastGood { cfg: c, .. } => assert_eq!(c.to_raw(), cfg.to_raw()),
            other => panic!("{other:?}"),
        }
        assert!(!path.exists(), "不能用默认配置补上主文件");
        assert_eq!(std::fs::read_to_string(crate::config::last_good_path(&path)).unwrap(), good);
        let _ = std::fs::remove_dir_all(&dir);
    }

}
