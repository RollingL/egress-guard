//! 界面背后的引擎。
//!
//! - Windows / Linux：引擎运行在界面进程里（界面以管理员身份运行）。
//! - macOS：引擎运行在 root 后台服务里（pf 需要 root），界面以普通用户运行，通过本地套接字通信。

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Result};

use crate::config::{Config, RawConfig};
use crate::engine::{EngineHandle, Event};
use crate::eventlog::{self, ConnEvent};
use crate::logbuf;

/// macOS 后台服务的状态。
#[derive(Debug, Clone, PartialEq)]
pub enum ServiceState {
    /// 本平台不需要后台服务。
    NotApplicable,
    NotInstalled,
    /// 已安装但连不上（正在启动，或启动失败）。
    Unreachable(String),
    Running { version: String },
}

pub trait Backend: Send + Sync {
    fn check_now(&self);
    fn clear_learned(&self);
    /// 校验、保存并应用配置。
    fn apply(&self, cfg: &Config) -> Result<()>;
    fn logs(&self) -> Vec<String>;
    fn clear_logs(&self);
    /// 连接记录（阻断、恢复、泄露），从旧到新。
    fn events(&self) -> Vec<ConnEvent>;
    fn clear_events(&self) -> Result<()>;
    /// 写入一条泄露测试的结果。
    fn record_event(&self, e: ConnEvent);
    /// 完整日志文件的位置。
    fn log_location(&self) -> Option<String>;
    fn config_location(&self) -> String;
    fn autostart_enabled(&self) -> bool;
    fn set_autostart(&self, on: bool) -> Result<()>;
    /// 后台服务重新连上后取得的最新配置（界面没有未保存修改时采用）。
    fn take_new_config(&self) -> Option<RawConfig> {
        None
    }
    fn service(&self) -> ServiceState {
        ServiceState::NotApplicable
    }
    /// 后台服务读取配置文件失败（正在按默认设置并开启全局断网运行）的原因。
    fn config_error(&self) -> Option<String> {
        None
    }
    /// 安装或更新后台服务（会弹出管理员密码对话框，阻塞直到完成）。
    fn install_service(&self) -> Result<()> {
        bail!("此平台不需要后台服务")
    }
    fn uninstall_service(&self) -> Result<()> {
        bail!("此平台不需要后台服务")
    }
    /// 退出程序：移除全部阻断规则后结束进程。
    fn quit(&self) -> !;
}

/// 引擎在界面进程里运行。
pub struct Local {
    pub engine: Arc<EngineHandle>,
    pub config_path: PathBuf,
}

impl Backend for Local {
    fn check_now(&self) {
        self.engine.send(Event::CheckNow);
    }

    fn clear_learned(&self) {
        self.engine.send(Event::ClearLearned);
    }

    fn apply(&self, cfg: &Config) -> Result<()> {
        cfg.save(&self.config_path)?;
        self.engine.send(Event::Reconfigure(Box::new(cfg.clone())));
        Ok(())
    }

    fn logs(&self) -> Vec<String> {
        logbuf::recent_lines()
    }

    fn clear_logs(&self) {
        logbuf::clear();
    }

    fn events(&self) -> Vec<ConnEvent> {
        eventlog::recent()
    }

    fn clear_events(&self) -> Result<()> {
        eventlog::clear();
        Ok(())
    }

    fn record_event(&self, e: ConnEvent) {
        eventlog::record(e);
    }

    fn log_location(&self) -> Option<String> {
        crate::exe_dir().map(|d| d.join("egress-guard.log").display().to_string())
    }

    fn config_location(&self) -> String {
        self.config_path.display().to_string()
    }

    fn autostart_enabled(&self) -> bool {
        super::platform::autostart::is_enabled()
    }

    fn set_autostart(&self, on: bool) -> Result<()> {
        if on {
            super::platform::autostart::enable(&std::env::current_exe()?)
        } else {
            super::platform::autostart::disable()
        }
    }

    fn quit(&self) -> ! {
        log::info!("用户选择退出");
        let _ = self.engine.shutdown();
        std::process::exit(0);
    }
}

#[cfg(target_os = "macos")]
pub use remote::Remote;

#[cfg(target_os = "macos")]
mod remote {
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use anyhow::{Context, Result};

    use super::{Backend, ServiceState};
    use crate::config::{Config, RawConfig};
    use crate::engine::Status;
    use crate::eventlog::ConnEvent;
    use crate::ipc::{Client, HelloInfo, Request};
    use crate::mac::{paths, service};

    const T: Duration = Duration::from_secs(10);

    pub struct Remote {
        client: Client,
        hello: Mutex<Option<HelloInfo>>,
        last_error: Mutex<String>,
        new_config: Mutex<Option<RawConfig>>,
        logs: Mutex<(Option<Instant>, Vec<String>)>,
        events: Mutex<(Option<Instant>, Vec<ConnEvent>)>,
    }

    impl Remote {
        /// 连接后台服务，并在后台线程中持续接收状态（断开后自动重连）。
        pub fn start(report: Arc<dyn Fn(&Status) + Send + Sync>) -> Arc<Self> {
            let me = Arc::new(Self {
                client: Client::new(paths::SOCKET),
                hello: Mutex::new(None),
                last_error: Mutex::new(String::new()),
                new_config: Mutex::new(None),
                logs: Mutex::new((None, Vec::new())),
                events: Mutex::new((None, Vec::new())),
            });
            // 先同步取一次配置，界面打开时就能显示
            if service::is_installed() {
                if let Ok(c) = me.client.get_config() {
                    *me.new_config.lock().unwrap() = Some(c);
                }
            }
            let w = me.clone();
            std::thread::Builder::new()
                .name("service-watch".into())
                .spawn(move || w.watch_loop(report))
                .expect("无法创建服务连接线程");
            me
        }

        fn watch_loop(&self, report: Arc<dyn Fn(&Status) + Send + Sync>) {
            loop {
                let err = if !service::is_installed() {
                    "后台服务未安装".to_owned()
                } else {
                    match self.client.hello() {
                        Ok(h) => {
                            log::info!("已连接后台服务 {}", h.version);
                            *self.hello.lock().unwrap() = Some(h);
                            if let Ok(c) = self.client.get_config() {
                                *self.new_config.lock().unwrap() = Some(c);
                            }
                            let e = self.client.watch(|s| report(&s)).unwrap_err();
                            format!("与后台服务的连接断开：{e:#}")
                        }
                        Err(e) => format!("{e:#}"),
                    }
                };
                *self.hello.lock().unwrap() = None;
                *self.last_error.lock().unwrap() = err.clone();
                report(&Status { running: false, backend_error: Some(err), ..Default::default() });
                std::thread::sleep(Duration::from_secs(2));
            }
        }

        /// .app 包里的命令行程序（与界面程序在同一目录）。
        fn cli_path() -> Result<PathBuf> {
            let exe = std::env::current_exe()?;
            let cli = exe.parent().context("无法确定程序目录")?.join("egress-guard");
            anyhow::ensure!(cli.exists(), "找不到 {}", cli.display());
            Ok(cli)
        }
    }

    impl Backend for Remote {
        fn check_now(&self) {
            if let Err(e) = self.client.command(&Request::CheckNow, T) {
                log::warn!("{e:#}");
            }
        }

        fn clear_learned(&self) {
            if let Err(e) = self.client.command(&Request::ClearLearned, T) {
                log::warn!("{e:#}");
            }
        }

        fn apply(&self, cfg: &Config) -> Result<()> {
            self.client.command(&Request::SetConfig(Box::new(cfg.to_raw())), T)?;
            // 服务保存成功后损坏的配置已被覆盖
            if let Some(h) = self.hello.lock().unwrap().as_mut() {
                h.config_error = None;
            }
            Ok(())
        }

        fn logs(&self) -> Vec<String> {
            // 日志页每帧都会取；最多每秒向服务请求一次
            let mut g = self.logs.lock().unwrap();
            if g.0.is_none_or(|t| t.elapsed() >= Duration::from_secs(1)) {
                g.0 = Some(Instant::now());
                match self.client.logs() {
                    Ok(l) => g.1 = l,
                    Err(e) => g.1 = vec![format!("（无法读取后台服务日志：{e:#}）")],
                }
            }
            g.1.clone()
        }

        fn clear_logs(&self) {
            let _ = self.client.command(&Request::ClearLogs, T);
            *self.logs.lock().unwrap() = (None, Vec::new());
        }

        fn events(&self) -> Vec<ConnEvent> {
            // 连接记录页每帧都会取；最多每 2 秒向服务请求一次
            let mut g = self.events.lock().unwrap();
            if g.0.is_none_or(|t| t.elapsed() >= Duration::from_secs(2)) {
                g.0 = Some(Instant::now());
                match self.client.events() {
                    Ok(l) => g.1 = l,
                    Err(e) => log::debug!("无法读取连接记录: {e:#}"),
                }
            }
            g.1.clone()
        }

        fn clear_events(&self) -> Result<()> {
            self.client.command(&Request::ClearEvents, T)?;
            *self.events.lock().unwrap() = (None, Vec::new());
            Ok(())
        }

        fn record_event(&self, e: ConnEvent) {
            if let Err(err) = self.client.command(&Request::RecordEvent(Box::new(e)), T) {
                log::warn!("无法写入连接记录: {err:#}");
            }
            self.events.lock().unwrap().0 = None;
        }

        fn log_location(&self) -> Option<String> {
            Some(paths::LOG_FILE.into())
        }

        fn config_location(&self) -> String {
            paths::config_path().display().to_string()
        }

        fn autostart_enabled(&self) -> bool {
            service::login_item_enabled()
        }

        fn set_autostart(&self, on: bool) -> Result<()> {
            let exe = std::env::current_exe()?;
            if on && exe.to_string_lossy().contains("/AppTranslocation/") {
                anyhow::bail!("请先把 Egress Guard 拖到「应用程序」文件夹，再从那里打开，然后开启自动启动");
            }
            // 后台服务开机启动 + 界面登录时在菜单栏启动
            self.client.command(&Request::SetAutostart(on), T).context("无法修改后台服务的自动启动")?;
            service::set_login_item(on, &exe)
        }

        fn take_new_config(&self) -> Option<RawConfig> {
            self.new_config.lock().unwrap().take()
        }

        fn service(&self) -> ServiceState {
            if !service::is_installed() {
                return ServiceState::NotInstalled;
            }
            match &*self.hello.lock().unwrap() {
                Some(h) => ServiceState::Running { version: h.version.clone() },
                None => ServiceState::Unreachable(self.last_error.lock().unwrap().clone()),
            }
        }

        fn config_error(&self) -> Option<String> {
            self.hello.lock().unwrap().as_ref().and_then(|h| h.config_error.clone())
        }

        fn install_service(&self) -> Result<()> {
            let cli = Self::cli_path()?;
            service::run_as_admin(
                &[&cli.to_string_lossy(), "service", "install"],
                "Egress Guard 要安装后台服务，用 pf 防火墙在出口 IP 不在白名单时断网。",
            )
        }

        fn uninstall_service(&self) -> Result<()> {
            let cli = Self::cli_path()?;
            service::run_as_admin(
                &[&cli.to_string_lossy(), "service", "uninstall"],
                "Egress Guard 要卸载后台服务并移除全部 pf 规则。",
            )?;
            // 服务没了，登录时自动打开界面也就没有意义了
            if let Err(e) = service::set_login_item(false, Path::new("")) {
                log::warn!("无法移除登录项: {e:#}");
            }
            // 网络扩展也一并停用（系统可能再要求输入一次密码）；没有服务时它本来就放行全部连接
            let ext = crate::netext::state();
            if ext.signed() && (ext.ext_enabled == Some(true) || ext.filter_configured) {
                log::info!("停用网络扩展");
                crate::netext::deactivate();
            }
            Ok(())
        }

        fn quit(&self) -> ! {
            log::info!("用户选择退出");
            let connected = self.hello.lock().unwrap().is_some();
            if connected {
                if let Err(e) = self.client.command(&Request::Stop, Duration::from_secs(5)) {
                    log::warn!("无法停止后台服务: {e:#}");
                    // 菜单写的是「退出并解除阻断」，做不到时必须告诉用户网络仍可能被切断
                    rfd::MessageDialog::new()
                        .set_level(rfd::MessageLevel::Warning)
                        .set_title("后台服务仍在运行")
                        .set_description(format!(
                            "无法停止后台服务，阻断规则仍然有效：{e:#}\n\n\
                             修改或停止后台服务需要管理员账户。可以用管理员账户打开 Egress Guard 退出，\
                             或在终端用 sudo 运行 .app 里的 Contents/MacOS/egress-guard stop。"
                        ))
                        .set_buttons(rfd::MessageButtons::Ok)
                        .show();
                }
            }
            std::process::exit(0);
        }
    }
}
