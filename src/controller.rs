//! 决策逻辑：根据出口 IP 检测结果决定阻断还是放行。

use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::Result;

use crate::blockall::BlockAllPolicy;
use crate::config::{Config, FailMode};

/// 阻断时要生效的规则。
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Rules {
    /// 受控应用（含自动识别的关联程序）：阻断时完全断网，不受全局断网例外影响。
    pub apps: Vec<PathBuf>,
    /// 全局断网的例外规则；None 表示只阻断受控应用。
    pub block_all: Option<BlockAllPolicy>,
    /// 切换为阻断时主动断开现有 IPv4 TCP 连接。
    pub kill_existing_tcp: bool,
}

/// 防火墙后端抽象。Windows 上由 WFP 实现，--dry-run 时只打日志。
pub trait Firewall {
    fn block(&mut self) -> Result<()>;
    fn unblock(&mut self) -> Result<()>;
    fn is_blocked(&self) -> bool;
    /// 更换规则；若当前处于阻断状态，新规则立即生效。
    fn set_rules(&mut self, rules: Rules) -> Result<()>;
    /// 是否有程序暂未能加上规则（文件暂不存在或单个程序添加失败），需要稍后重试。
    fn has_pending(&self) -> bool {
        false
    }
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
    /// 上次把程序列表同步到防火墙失败，需要重试。
    apps_dirty: bool,
}

impl Controller {
    pub fn new(cfg: Config, fw: Box<dyn Firewall>) -> Self {
        Self {
            cfg,
            extra: Vec::new(),
            fw,
            failures: 0,
            last_ip: None,
            last_error: None,
            apps_dirty: false,
        }
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

    /// 阻断范围的描述，用于日志。
    fn scope(&self) -> &'static str {
        if self.cfg.block_all.enabled { "全部网络" } else { "受控应用" }
    }

    /// 当前应生效的规则。
    pub fn rules(&self) -> Rules {
        Rules {
            apps: self.effective_apps(),
            block_all: self.cfg.block_all_policy(),
            kill_existing_tcp: self.cfg.behavior.kill_existing_tcp,
        }
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
        if extra == self.extra && !self.apps_dirty {
            return Ok(());
        }
        self.extra = extra;
        self.push_apps()
    }

    /// 把当前程序列表推送到防火墙；失败时记下，等 `retry_pending` 重试。
    fn push_apps(&mut self) -> Result<()> {
        let r = self.fw.set_rules(self.rules());
        self.apps_dirty = r.is_err();
        r
    }

    /// 按当前配置把规则推送到防火墙（启动时调用一次）。
    pub fn apply_rules(&mut self) -> Result<()> {
        self.push_apps()
    }

    /// 是否有未完成的规则同步需要重试。
    pub fn needs_retry(&self) -> bool {
        self.apps_dirty || self.fw.has_pending()
    }

    /// 重试之前失败或未完成的规则同步。
    pub fn retry_pending(&mut self) -> Result<()> {
        if !self.needs_retry() {
            return Ok(());
        }
        self.push_apps()
    }

    /// 应用新配置。受控应用变化会立即反映到防火墙规则上。
    pub fn reconfigure(&mut self, cfg: Config) -> Result<()> {
        let before = self.rules();
        self.cfg = cfg;
        let changed = self.rules() != before;
        // 规则同步失败也继续按新白名单决策，错误最后再返回
        let sync = if changed || self.apps_dirty { self.push_apps() } else { Ok(()) };
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
        sync
    }

    /// 网络变化时调用：按配置先行阻断。
    pub fn on_network_change(&mut self) -> Result<()> {
        if self.cfg.behavior.block_on_network_change && !self.fw.is_blocked() {
            log::info!("网络发生变化，先阻断{}，等待重新检测出口 IP", self.scope());
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
                log::warn!("切换为【阻断】{}", self.scope());
                self.fw.block()
            }
            Some(false) if self.fw.is_blocked() => {
                log::info!("切换为【放行】{}", self.scope());
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
        log::info!("[dry-run] 将阻断");
        self.blocked = true;
        Ok(())
    }
    fn unblock(&mut self) -> Result<()> {
        log::info!("[dry-run] 将放行");
        self.blocked = false;
        Ok(())
    }
    fn is_blocked(&self) -> bool {
        self.blocked
    }
    fn set_rules(&mut self, rules: Rules) -> Result<()> {
        log::info!(
            "[dry-run] 规则更新：受控应用 {} 个{}",
            rules.apps.len(),
            if rules.block_all.is_some() { "，全局断网" } else { "" }
        );
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

    /// set_rules 前 N 次失败的测试后端。
    struct FlakyFirewall {
        fail_left: std::rc::Rc<std::cell::Cell<u32>>,
        applied: std::rc::Rc<std::cell::RefCell<Rules>>,
    }

    impl Firewall for FlakyFirewall {
        fn block(&mut self) -> Result<()> {
            Ok(())
        }
        fn unblock(&mut self) -> Result<()> {
            Ok(())
        }
        fn is_blocked(&self) -> bool {
            true
        }
        fn set_rules(&mut self, rules: Rules) -> Result<()> {
            if self.fail_left.get() > 0 {
                self.fail_left.set(self.fail_left.get() - 1);
                return Err(anyhow!("WFP 暂时不可用"));
            }
            *self.applied.borrow_mut() = rules;
            Ok(())
        }
    }

    #[test]
    fn failed_sync_is_retried() {
        let fail_left = std::rc::Rc::new(std::cell::Cell::new(1));
        let applied = std::rc::Rc::new(std::cell::RefCell::new(Rules::default()));
        let fw = FlakyFirewall { fail_left: fail_left.clone(), applied: applied.clone() };
        let mut c = Controller::new(cfg(""), Box::new(fw));
        let extra = vec![PathBuf::from("C:\\b.exe")];

        assert!(c.set_extra(extra.clone()).is_err());
        assert!(c.needs_retry());
        // 同样的列表再次到达时不能因"没变化"而跳过
        c.set_extra(extra.clone()).unwrap();
        assert!(!c.needs_retry());
        assert_eq!(applied.borrow().apps.len(), 2);

        // 定时重试路径
        fail_left.set(1);
        assert!(c.set_extra(vec![]).is_err());
        c.retry_pending().unwrap();
        assert!(!c.needs_retry());
        assert_eq!(applied.borrow().apps.len(), 1);
    }

    #[test]
    fn block_all_follows_config() {
        let applied = std::rc::Rc::new(std::cell::RefCell::new(Rules::default()));
        let fw = FlakyFirewall { fail_left: Default::default(), applied: applied.clone() };
        let mut c = Controller::new(cfg(""), Box::new(fw));
        c.apply_rules().unwrap();
        assert!(applied.borrow().block_all.is_none());

        c.reconfigure(cfg("[block_all]\nenabled=true\nallow_lan=false\nallow_remote=['198.51.100.7']")).unwrap();
        let p = applied.borrow().block_all.clone().unwrap();
        assert!(!p.allow_lan && p.allow_dns);
        assert_eq!(p.allow_remote.len(), 1);
        // 受控应用不受全局断网影响，仍在阻断列表里
        assert_eq!(applied.borrow().apps.len(), 1);

        c.reconfigure(cfg("")).unwrap();
        assert!(applied.borrow().block_all.is_none());
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
