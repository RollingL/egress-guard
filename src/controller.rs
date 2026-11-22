//! 决策逻辑：根据出口 IP 检测结果决定阻断还是放行。

use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::Result;

use crate::config::{Config, FailMode};

/// 防火墙后端抽象。Windows 上由 WFP 实现，--dry-run 时只打日志。
pub trait Firewall {
    fn block(&mut self) -> Result<()>;
    fn unblock(&mut self) -> Result<()>;
    fn is_blocked(&self) -> bool;
    /// 更换受控应用列表；若当前处于阻断状态，新列表立即生效。
    fn set_apps(&mut self, apps: Vec<PathBuf>, kill_existing_tcp: bool) -> Result<()>;
}

/// 根据检测结果计算目标状态：Some(true)=阻断，Some(false)=放行，None=保持不变。
pub fn decide(
    cfg: &Config,
    detection: &Result<IpAddr>,
    consecutive_failures: u32,
) -> Option<bool> {
    match detection {
        Ok(ip) => Some(!cfg.is_whitelisted(*ip)),
        Err(_) if consecutive_failures < cfg.detect.failure_threshold.max(1) => None,
        Err(_) => match cfg.detect.fail_mode {
            FailMode::Block => Some(true),
            FailMode::Allow => Some(false),
            FailMode::Keep => None,
        },
    }
}

pub struct Controller {
    cfg: Config,
    /// 自动识别到的关联程序（子进程 / 同目录）。
    extra: Vec<PathBuf>,
    fw: Box<dyn Firewall>,
    failures: u32,
    last_ip: Option<IpAddr>,
    last_error: Option<String>,
}

impl Controller {
    pub fn new(cfg: Config, fw: Box<dyn Firewall>) -> Self {
        Self { cfg, extra: Vec::new(), fw, failures: 0, last_ip: None, last_error: None }
    }

    pub fn firewall(&mut self) -> &mut dyn Firewall {
        self.fw.as_mut()
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    pub fn is_blocked(&self) -> bool {
        self.fw.is_blocked()
    }

    pub fn last_ip(&self) -> Option<IpAddr> {
        self.last_ip
    }

    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    pub fn failures(&self) -> u32 {
        self.failures
    }

    /// 实际需要阻断的程序：配置的受控应用 + 自动识别的关联程序（去重）。
    pub fn effective_apps(&self) -> Vec<PathBuf> {
        let mut seen = std::collections::HashSet::new();
        self.cfg
            .apps
            .iter()
            .chain(self.extra.iter())
            .filter(|p| seen.insert(crate::discovery::normalize_path(p)))
            .cloned()
            .collect()
    }

    /// 更新自动识别到的关联程序；若当前处于阻断状态，新程序立即被阻断。
    pub fn set_extra(&mut self, extra: Vec<PathBuf>) -> Result<()> {
        if extra == self.extra {
            return Ok(());
        }
        self.extra = extra;
        self.fw.set_apps(self.effective_apps(), self.cfg.behavior.kill_existing_tcp)
    }

    /// 应用新配置。受控应用变化会立即反映到防火墙规则上。
    pub fn reconfigure(&mut self, cfg: Config) -> Result<()> {
        let changed = cfg.apps != self.cfg.apps
            || cfg.behavior.kill_existing_tcp != self.cfg.behavior.kill_existing_tcp;
        self.cfg = cfg;
        if changed {
            self.fw.set_apps(self.effective_apps(), self.cfg.behavior.kill_existing_tcp)?;
        }
        // 白名单可能已变化：用最近一次的出口 IP 立即重新决策
        if let Some(ip) = self.last_ip {
            let want_block = !self.cfg.is_whitelisted(ip);
            if want_block && !self.fw.is_blocked() {
                log::warn!("新白名单不包含当前出口 IP {ip}，切换为【阻断】");
                self.fw.block()?;
            } else if !want_block && self.fw.is_blocked() {
                log::info!("新白名单包含当前出口 IP {ip}，切换为【放行】");
                self.fw.unblock()?;
            }
        }
        Ok(())
    }

    /// 网络变化时调用：按配置先行阻断。
    pub fn on_network_change(&mut self) -> Result<()> {
        if self.cfg.behavior.block_on_network_change && !self.fw.is_blocked() {
            log::info!("网络发生变化，先阻断受控应用，等待重新检测出口 IP");
            self.fw.block()?;
        }
        Ok(())
    }

    /// 处理一次检测结果。
    pub fn on_detection(&mut self, detection: Result<IpAddr>) -> Result<()> {
        match &detection {
            Ok(ip) => {
                self.failures = 0;
                self.last_error = None;
                if self.last_ip != Some(*ip) {
                    log::info!(
                        "出口 IP: {ip}（{}）",
                        if self.cfg.is_whitelisted(*ip) { "在白名单内" } else { "不在白名单内" }
                    );
                    self.last_ip = Some(*ip);
                }
            }
            Err(e) => {
                self.failures += 1;
                self.last_ip = None;
                self.last_error = Some(format!("{e:#}"));
                log::warn!("出口 IP 检测失败（连续 {} 次）: {e:#}", self.failures);
            }
        }

        match decide(&self.cfg, &detection, self.failures) {
            Some(true) if !self.fw.is_blocked() => {
                log::warn!("切换为【阻断】受控应用");
                self.fw.block()
            }
            Some(false) if self.fw.is_blocked() => {
                log::info!("切换为【放行】受控应用");
                self.fw.unblock()
            }
            _ => Ok(()),
        }
    }
}

/// 只记录日志、不真正改动网络的后端，用于 --dry-run。
#[derive(Default)]
pub struct DryRunFirewall {
    blocked: bool,
}

impl Firewall for DryRunFirewall {
    fn block(&mut self) -> Result<()> {
        log::info!("[dry-run] 将阻断受控应用");
        self.blocked = true;
        Ok(())
    }
    fn unblock(&mut self) -> Result<()> {
        log::info!("[dry-run] 将放行受控应用");
        self.blocked = false;
        Ok(())
    }
    fn is_blocked(&self) -> bool {
        self.blocked
    }
    fn set_apps(&mut self, apps: Vec<PathBuf>, _kill: bool) -> Result<()> {
        log::info!("[dry-run] 受控应用更新为 {} 个", apps.len());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    fn cfg(extra: &str) -> Config {
        Config::parse(&format!(
            "whitelist=[\"203.0.113.0/24\"]\napps=['C:\\a.exe']\n{extra}"
        ))
        .unwrap()
    }

    #[test]
    fn whitelisted_ip_unblocks_and_other_blocks() {
        let mut c = Controller::new(cfg(""), Box::new(DryRunFirewall { blocked: true }));
        c.on_detection(Ok("203.0.113.9".parse().unwrap())).unwrap();
        assert!(!c.fw.is_blocked());
        c.on_detection(Ok("198.51.100.1".parse().unwrap())).unwrap();
        assert!(c.fw.is_blocked());
    }

    #[test]
    fn failure_threshold_and_modes() {
        // 默认：连续 2 次失败后阻断
        let mut c = Controller::new(cfg(""), Box::new(DryRunFirewall::default()));
        c.on_detection(Err(anyhow!("x"))).unwrap();
        assert!(!c.fw.is_blocked());
        c.on_detection(Err(anyhow!("x"))).unwrap();
        assert!(c.fw.is_blocked());

        // keep：失败时保持原状
        let mut c = Controller::new(
            cfg("[detect]\nfail_mode=\"keep\"\nfailure_threshold=1"),
            Box::new(DryRunFirewall::default()),
        );
        c.on_detection(Err(anyhow!("x"))).unwrap();
        assert!(!c.fw.is_blocked());

        // allow：失败时放行
        let mut c = Controller::new(
            cfg("[detect]\nfail_mode=\"allow\"\nfailure_threshold=1"),
            Box::new(DryRunFirewall { blocked: true }),
        );
        c.on_detection(Err(anyhow!("x"))).unwrap();
        assert!(!c.fw.is_blocked());
    }

    #[test]
    fn reconfigure_rechecks_last_ip() {
        let mut c = Controller::new(cfg(""), Box::new(DryRunFirewall::default()));
        c.on_detection(Ok("198.51.100.1".parse().unwrap())).unwrap();
        assert!(c.is_blocked());
        let new = Config::parse("whitelist=[\"198.51.100.0/24\"]\napps=[]").unwrap();
        c.reconfigure(new).unwrap();
        assert!(!c.is_blocked());
    }

    #[test]
    fn network_change_blocks_first() {
        let mut c = Controller::new(cfg(""), Box::new(DryRunFirewall::default()));
        c.on_network_change().unwrap();
        assert!(c.fw.is_blocked());
        let mut c = Controller::new(
            cfg("[behavior]\nblock_on_network_change=false"),
            Box::new(DryRunFirewall::default()),
        );
        c.on_network_change().unwrap();
        assert!(!c.fw.is_blocked());
    }
}
