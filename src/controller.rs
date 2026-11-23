//! 决策逻辑：根据出口 IP 检测结果决定阻断还是放行。

use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::Result;

use crate::blockall::BlockAllPolicy;
use crate::config::{Config, FailMode, Ipv6Mode};
use crate::eventlog::{self, ConnEvent, Kind};

/// 一次出口 IP 检测的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Egress {
    /// 按系统默认路由检测到的出口 IP（多数情况下是 IPv4）。
    pub ip: IpAddr,
    /// 只走 IPv6 检测到的出口（「检测 IPv6 出口」开启、且本机能直连 IPv6 时）。
    pub v6: Option<IpAddr>,
    /// 「检测 IPv6 出口」时 IPv6 没有验证成功（IPv4 出口已经不在白名单，所以照样能决定阻断）。
    /// 这样的结果只能用来收紧：之后即使把这个 IPv4 加进白名单，也要重新检测才能放行。
    pub v6_unverified: bool,
}

impl Egress {
    pub fn v4(ip: IpAddr) -> Self {
        Self { ip, v6: None, v6_unverified: false }
    }

    /// 两个地址族的出口（`v6` 为 None 表示没有单独的 IPv6 出口）。
    pub fn dual(ip: IpAddr, v6: Option<IpAddr>) -> Self {
        Self { ip, v6, v6_unverified: false }
    }

    /// 与主出口不同的 IPv6 出口。
    pub fn extra_v6(&self) -> Option<IpAddr> {
        self.v6.filter(|v| *v != self.ip)
    }
}

/// 阻断时要生效的规则。
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Rules {
    /// 受控应用（含自动识别的关联程序）：阻断时完全断网，不受全局断网例外影响。
    pub apps: Vec<PathBuf>,
    /// 全局断网的例外规则；None 表示只阻断受控应用。
    pub block_all: Option<BlockAllPolicy>,
    /// 切换为阻断时主动断开现有 IPv4 TCP 连接。
    pub kill_existing_tcp: bool,
    /// 放行期间也始终阻断 IPv6（受控应用；开启全局断网时为全部 IPv6）。
    pub block_ipv6: bool,
}

/// 防火墙后端抽象。Windows 上由 WFP 实现，macOS 上由 pf 实现，--dry-run 时只打日志。
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
    /// 能否按应用阻断。不能时（macOS pf）只有全局断网生效。
    fn per_app(&self) -> bool {
        true
    }
    /// 负责按应用阻断的 macOS 网络扩展的版本（已连接时）。
    fn extension(&self) -> Option<String> {
        None
    }
    /// 后端还没有提交过任何阻断/放行状态（例如 macOS 网络扩展还没收到第一份规则）。
    /// 这时即使目标状态与 `is_blocked()` 相同，也要调用一次 block/unblock 把规则发下去。
    fn needs_initial_commit(&self) -> bool {
        false
    }
    /// 只是模拟（--dry-run 或拦截后端打不开），规则没有真正生效。
    fn simulated(&self) -> bool {
        false
    }
    /// 拦截后端的其他问题（例如网络扩展不支持当前规则用到的功能），界面上提示。
    fn degraded(&self) -> Option<String> {
        None
    }
}

/// 出口是否通过白名单：主出口在白名单内，并且（检测 IPv6 出口时）IPv6 出口也在白名单内。
pub fn egress_allowed(cfg: &Config, e: &Egress) -> bool {
    cfg.is_whitelisted(e.ip)
        && (cfg.ipv6.mode != Ipv6Mode::Check || (!e.v6_unverified && e.v6.is_none_or(|v| cfg.is_whitelisted(v))))
}

/// 出口没有通过白名单的原因。
fn rejection(cfg: &Config, e: &Egress) -> String {
    if !cfg.is_whitelisted(e.ip) {
        format!("出口 IP {} 不在白名单", e.ip)
    } else {
        match e.v6 {
            Some(v) if cfg.ipv6.mode == Ipv6Mode::Check && !cfg.is_whitelisted(v) => {
                format!("IPv6 出口 {v} 不在白名单（IPv6 流量没有走白名单出口）")
            }
            _ if e.v6_unverified => "IPv6 出口没有验证成功，需要重新检测".to_owned(),
            _ => "出口不在白名单".to_owned(),
        }
    }
}

/// 一次检测用的测量路径：IPv6 处理方式（决定验证哪些地址族）、代理、查询服务。
/// 任何一项变了，之前的结果都不是按现在的路径测的，只能用来收紧。
#[derive(Debug, Clone, PartialEq, Eq)]
struct MeasureKey {
    ipv6: Ipv6Mode,
    proxy: String,
    services: Vec<String>,
    v6_services: Vec<String>,
}

impl MeasureKey {
    fn of(cfg: &Config) -> Self {
        Self {
            ipv6: cfg.ipv6.mode,
            proxy: cfg.detect.proxy.clone(),
            services: cfg.detect.services.clone(),
            v6_services: if cfg.ipv6.mode == Ipv6Mode::Check { cfg.ipv6.services.clone() } else { Vec::new() },
        }
    }
}

/// 根据检测结果计算目标状态：Some(true)=阻断，Some(false)=放行，None=保持不变。
pub fn decide(
    cfg: &Config,
    detection: &Result<Egress>,
    consecutive_failures: u32,
) -> Option<bool> {
    match detection {
        Ok(e) => Some(!egress_allowed(cfg, e)),
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
    last_v6: Option<IpAddr>,
    last_error: Option<String>,
    /// 最近一次切换（阻断或恢复）的原因。
    reason: Option<String>,
    /// 上次把程序列表同步到防火墙失败，需要重试。
    apps_dirty: bool,
    /// 最近一次检测到的出口已经过时（VPN 断开、网络变化之后），在下一次检测前不能据此放行。
    stale: bool,
    /// 没能提交的切换（目标是否阻断、原因）：定时重试切换本身，直到成功或被新的决定取代。
    pending_switch: Option<(bool, String)>,
    /// 上一次切换失败的原因（界面显示「阻断未生效」）。
    apply_error: Option<String>,
    /// 最近一次完整检测所用的测量路径（IPv6 处理方式、代理、查询服务）。换了路径之后，旧结果没有覆盖
    /// 新路径要求验证的内容，只能用来收紧；IPv6 没有验证成功的结果也记为 None。
    measured: Option<MeasureKey>,
    /// 从「始终阻断 IPv6」改为「检测 IPv6 出口」后，IPv6 还没有验证过：常驻的 IPv6 阻断先保留，
    /// 等第一次完整的双栈检测之后再撤掉，而不是改设置的那一刻就放开受控应用的 IPv6。
    hold_v6_block: bool,
}

impl Controller {
    pub fn new(cfg: Config, fw: Box<dyn Firewall>) -> Self {
        Self {
            cfg,
            extra: Vec::new(),
            fw,
            failures: 0,
            last_ip: None,
            last_v6: None,
            last_error: None,
            reason: None,
            apps_dirty: false,
            stale: false,
            pending_switch: None,
            apply_error: None,
            measured: None,
            hold_v6_block: false,
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

    pub fn per_app(&self) -> bool {
        self.fw.per_app()
    }

    pub fn extension(&self) -> Option<String> {
        self.fw.extension()
    }

    pub fn last_ip(&self) -> Option<IpAddr> {
        self.last_ip
    }

    /// 最近一次检测到的、与主出口不同的 IPv6 出口。
    pub fn last_v6(&self) -> Option<IpAddr> {
        self.last_v6
    }

    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    /// 当前处于阻断状态时，阻断的原因。
    pub fn block_reason(&self) -> Option<&str> {
        self.reason.as_deref().filter(|_| self.fw.is_blocked())
    }

    pub fn failures(&self) -> u32 {
        self.failures
    }

    /// 上一次切换没能生效的原因（正在重试）。
    pub fn apply_error(&self) -> Option<&str> {
        self.apply_error.as_deref()
    }

    /// 目标是阻断：已经阻断，或者正在重试一次没能生效的阻断。
    pub fn wants_block(&self) -> bool {
        self.pending_switch.as_ref().map_or_else(|| self.fw.is_blocked(), |p| p.0)
    }

    /// 拦截后端的其他问题。
    pub fn degraded(&self) -> Option<String> {
        self.fw.degraded()
    }

    /// 阻断范围的描述，用于日志。
    fn scope(&self) -> &'static str {
        if self.cfg.block_all.enabled { "全部网络" } else { "受控应用" }
    }

    /// 切换为阻断或放行，并写入连接记录。已经处于目标状态时什么也不做。
    ///
    /// 后端失败时记下目标状态，`retry_pending` 定时重试切换本身；新的决定会取代还没生效的旧决定。
    /// 连接记录只在切换真正生效时写一次。
    fn switch(&mut self, block: bool, reason: String) -> Result<()> {
        let was = self.fw.is_blocked();
        if block == was && self.pending_switch.is_none() && !self.fw.needs_initial_commit() {
            // 已经在阻断：更新为最新的原因（例如启动时先阻断，之后检测到出口不在白名单）
            if block && self.reason.as_deref() != Some(&reason) {
                log::info!("保持阻断：{reason}");
                self.reason = Some(reason);
            }
            return Ok(());
        }
        // 有还没生效的切换、或者后端还没提交过规则时，即使看起来已经是目标状态也再提交一次：
        // 上一次失败可能留下了一半（例如网络扩展已经收到阻断，pf 没装上）
        if block != was {
            if block {
                log::warn!("切换为【阻断】{}：{reason}", self.scope());
            } else {
                log::info!("切换为【放行】{}：{reason}", self.scope());
            }
        }
        let r = if block { self.fw.block() } else { self.fw.unblock() };
        if let Err(e) = r {
            let what = if block { "阻断" } else { "放行" };
            self.apply_error = Some(format!("{what}未生效（{reason}）：{e:#}"));
            self.pending_switch = Some((block, reason));
            return Err(e.context(format!("{what}未生效，5 秒后重试")));
        }
        if self.apply_error.take().is_some() {
            log::info!("{}已生效", if block { "阻断" } else { "放行" });
        }
        self.pending_switch = None;
        if block != was {
            let mut e = ConnEvent::now(if block { Kind::Block } else { Kind::Restore }, reason.clone());
            e.egress = self.last_ip;
            e.egress_v6 = self.last_v6;
            // 记录里区分：模拟模式（规则没有真正生效）、阻断时有程序暂未加上规则
            e.scope = self.scope().to_owned();
            if self.fw.simulated() {
                e.scope.push_str("（模拟模式，未生效）");
            } else if block && self.fw.has_pending() {
                e.scope.push_str("（部分程序暂未加上规则）");
            }
            eventlog::record(e);
        }
        self.reason = Some(reason);
        Ok(())
    }

    /// 以给定原因阻断（启动时先阻断、VPN 断开等）。之前检测到的出口随之作废，等下一次检测再决定是否放行。
    pub fn block_for(&mut self, reason: impl Into<String>) -> Result<()> {
        self.stale = true;
        self.switch(true, reason.into())
    }

    /// 当前的出口（检测成功过时）。
    fn last_egress(&self) -> Option<Egress> {
        self.last_ip.map(|ip| Egress::dual(ip, self.last_v6))
    }

    /// 当前应生效的规则。
    pub fn rules(&self) -> Rules {
        Rules {
            apps: self.effective_apps(),
            block_all: self.cfg.block_all_policy(),
            kill_existing_tcp: self.cfg.behavior.kill_existing_tcp,
            block_ipv6: self.cfg.ipv6.mode == Ipv6Mode::Block || self.hold_v6_block,
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

    /// 是否有没能生效的切换、或未完成的规则同步需要重试。
    pub fn needs_retry(&self) -> bool {
        self.pending_switch.is_some() || self.apps_dirty || self.fw.has_pending()
    }

    /// 出口已经过时（网络变化、VPN 断开）时，丢掉还没生效的放行：它依据的是旧网络上的检测，
    /// 不能在之后的重试里生效。已经生效的规则不动，等新的检测结果再决定。
    fn drop_stale_unblock(&mut self) {
        if self.stale && matches!(self.pending_switch, Some((false, _))) {
            log::info!("网络已变化，取消还没生效的放行，等待重新检测");
            self.pending_switch = None;
            self.apply_error = None;
        }
    }

    /// 重试之前失败的切换，以及失败或未完成的规则同步。
    pub fn retry_pending(&mut self) -> Result<()> {
        self.drop_stale_unblock();
        if let Some((block, reason)) = self.pending_switch.clone() {
            self.switch(block, reason)?;
        }
        if self.apps_dirty || self.fw.has_pending() {
            self.push_apps()?;
        }
        Ok(())
    }

    /// 应用新配置。受控应用变化会立即反映到防火墙规则上。
    pub fn reconfigure(&mut self, cfg: Config) -> Result<()> {
        let before = self.rules();
        self.cfg = cfg;
        // 从「始终阻断 IPv6」改为「检测 IPv6 出口」：IPv6 验证之前保留常驻的 IPv6 阻断。
        // 改为「不单独处理」是用户明确不管 IPv6，立即撤掉
        self.hold_v6_block = match self.cfg.ipv6.mode {
            Ipv6Mode::Check => self.hold_v6_block || before.block_ipv6,
            Ipv6Mode::Block | Ipv6Mode::Off => false,
        };
        let changed = self.rules() != before;
        // 规则同步失败也继续按新白名单决策，错误最后再返回
        let sync = if changed || self.apps_dirty { self.push_apps() } else { Ok(()) };
        // 不再检测 IPv6 出口时，之前测到的也不再参与决策
        if self.cfg.ipv6.mode != Ipv6Mode::Check {
            self.last_v6 = None;
        }
        // 白名单可能已变化：用最近一次的出口 IP 立即重新决策。
        // 出口已经过时（VPN 断开、网络变化后还没重新检测）、是按另一条测量路径测的（IPv6 处理方式、
        // 代理或查询服务变了），或者有地址族没验证成功时只能收紧，不能据此放行
        let stale = self.stale || self.measured.as_ref() != Some(&MeasureKey::of(&self.cfg));
        if let Some(e) = self.last_egress() {
            if egress_allowed(&self.cfg, &e) {
                if stale {
                    return sync;
                }
                self.switch(false, format!("新白名单包含当前出口 IP {}", e.ip))?;
            } else {
                self.switch(true, format!("新配置下{}", rejection(&self.cfg, &e)))?;
            }
        }
        sync
    }

    /// 网络变化时调用：按配置先行阻断。
    pub fn on_network_change(&mut self) -> Result<()> {
        self.stale = true;
        self.drop_stale_unblock();
        if self.cfg.behavior.block_on_network_change && !self.fw.is_blocked() {
            self.switch(true, "网络发生变化，等待重新检测出口 IP".into())?;
        }
        Ok(())
    }

    /// 处理一次检测结果。
    pub fn on_detection(&mut self, detection: Result<Egress>) -> Result<()> {
        self.stale = false;
        match &detection {
            Ok(e) => {
                self.failures = 0;
                self.last_error = None;
                self.measured = (!e.v6_unverified).then(|| MeasureKey::of(&self.cfg));
                let v6 = if self.cfg.ipv6.mode == Ipv6Mode::Check { e.extra_v6() } else { None };
                if self.last_ip != Some(e.ip) {
                    log::info!(
                        "出口 IP: {}（{}）",
                        e.ip,
                        if self.cfg.is_whitelisted(e.ip) { "在白名单内" } else { "不在白名单内" }
                    );
                    self.last_ip = Some(e.ip);
                }
                if self.last_v6 != v6 {
                    match v6 {
                        Some(v) => log::info!(
                            "IPv6 出口: {v}（{}）",
                            if self.cfg.is_whitelisted(v) { "在白名单内" } else { "不在白名单内" }
                        ),
                        None => log::info!("没有单独的 IPv6 出口"),
                    }
                    self.last_v6 = v6;
                }
            }
            Err(e) => {
                self.failures += 1;
                self.last_ip = None;
                self.last_v6 = None;
                self.last_error = Some(format!("{e:#}"));
                log::warn!("出口 IP 检测失败（连续 {} 次）: {e:#}", self.failures);
            }
        }

        let target = decide(&self.cfg, &detection, self.failures);
        let reason = match (&detection, target) {
            (Ok(e), Some(true)) => rejection(&self.cfg, e),
            (Ok(e), _) => match self.last_v6 {
                Some(v) => format!("出口 IP {}、IPv6 出口 {v} 都在白名单内", e.ip),
                None => format!("出口 IP {} 在白名单内", e.ip),
            },
            (Err(_), Some(true)) => format!("连续 {} 次无法检测出口 IP（检测失败时阻断）", self.failures),
            (Err(_), _) => format!("连续 {} 次无法检测出口 IP（检测失败时放行）", self.failures),
        };
        let r = match target {
            Some(block) => self.switch(block, reason),
            None => Ok(()),
        };
        // 完整的双栈检测已经验证了 IPv6：撤掉改设置时保留的 IPv6 阻断（要阻断时上面已经先阻断了）
        let verified = matches!(&detection, Ok(e) if !e.v6_unverified) && self.cfg.ipv6.mode == Ipv6Mode::Check;
        if self.hold_v6_block && verified {
            log::info!("IPv6 出口已验证，撤掉切换设置时保留的 IPv6 阻断");
            self.hold_v6_block = false;
            if let Err(e) = self.push_apps() {
                log::warn!("撤掉保留的 IPv6 阻断失败，稍后重试: {e:#}");
            }
        }
        r
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
    fn simulated(&self) -> bool {
        true
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
        c.on_detection(Ok(eg("203.0.113.9", None))).unwrap();
        assert!(!c.fw.is_blocked());
        c.on_detection(Ok(eg("198.51.100.1", None))).unwrap();
        assert!(c.fw.is_blocked());
        assert_eq!(c.block_reason(), Some("出口 IP 198.51.100.1 不在白名单"));
    }

    fn eg(ip: &str, v6: Option<&str>) -> Egress {
        Egress::dual(ip.parse().unwrap(), v6.map(|v| v.parse().unwrap()))
    }

    #[test]
    fn ipv6_egress_is_checked() {
        let check = "[ipv6]\nmode=\"check\"";
        let mut c = Controller::new(cfg(check), Box::new(DryRunFirewall { blocked: true }));
        // IPv4 走白名单出口（VPN），IPv6 直连运营商：阻断
        c.on_detection(Ok(eg("203.0.113.9", Some("2001:db8::9")))).unwrap();
        assert!(c.is_blocked());
        assert!(c.block_reason().unwrap().contains("IPv6 出口 2001:db8::9"), "{:?}", c.block_reason());
        assert_eq!(c.last_v6(), Some("2001:db8::9".parse().unwrap()));
        // 本机没有 IPv6：只看 IPv4
        c.on_detection(Ok(eg("203.0.113.9", None))).unwrap();
        assert!(!c.is_blocked());
        // IPv6 出口加进白名单后放行
        let wl = cfg(check).to_raw();
        let mut raw = wl.clone();
        raw.whitelist.push("2001:db8::/32".into());
        c.reconfigure(Config::from_raw(raw).unwrap()).unwrap();
        c.on_detection(Ok(eg("203.0.113.9", Some("2001:db8::9")))).unwrap();
        assert!(!c.is_blocked());
        // 白名单移除 IPv6 网段：用最近一次的结果立即重新决策
        c.reconfigure(Config::from_raw(wl).unwrap()).unwrap();
        assert!(c.is_blocked());

        // 关闭 IPv6 检测：IPv6 出口不参与决策；「始终阻断 IPv6」时规则里带上 block_ipv6
        let mut c = Controller::new(cfg("[ipv6]\nmode=\"off\""), Box::new(DryRunFirewall { blocked: true }));
        c.on_detection(Ok(eg("203.0.113.9", Some("2001:db8::9")))).unwrap();
        assert!(!c.is_blocked());
        assert!(c.last_v6().is_none());
        assert!(!c.rules().block_ipv6);
        let c = Controller::new(cfg("[ipv6]\nmode=\"block\""), Box::new(DryRunFirewall::default()));
        assert!(c.rules().block_ipv6);
        // 默认就是始终阻断
        assert!(Controller::new(cfg(""), Box::new(DryRunFirewall::default())).rules().block_ipv6);
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
        c.on_detection(Ok(eg("198.51.100.1", None))).unwrap();
        assert!(c.is_blocked());
        let new = Config::parse("whitelist=[\"198.51.100.0/24\"]\napps=[]").unwrap();
        c.reconfigure(new).unwrap();
        assert!(!c.is_blocked());
    }

    #[test]
    fn stale_egress_never_unblocks() {
        // 放行中 VPN 断开 → 阻断；重新检测前保存设置不能按断开前的出口放行
        let wl = |net: &str| Config::parse(&format!("whitelist=[\"{net}\"]\napps=['C:\\a.exe']")).unwrap();
        let mut c = Controller::new(wl("198.51.100.0/24"), Box::new(DryRunFirewall::default()));
        c.on_detection(Ok(eg("198.51.100.1", None))).unwrap();
        assert!(!c.is_blocked());
        c.block_for("VPN 断开（utun4）").unwrap();
        c.reconfigure(wl("198.51.100.0/24")).unwrap();
        assert!(c.is_blocked());
        // 新配置不再允许旧出口时仍然可以收紧
        c.reconfigure(wl("203.0.113.0/24")).unwrap();
        assert!(c.is_blocked());
        // 网络变化后同样如此
        let mut c = Controller::new(wl("198.51.100.0/24"), Box::new(DryRunFirewall::default()));
        c.on_detection(Ok(eg("198.51.100.1", None))).unwrap();
        c.on_network_change().unwrap();
        assert!(c.is_blocked());
        c.reconfigure(wl("198.51.100.0/24")).unwrap();
        assert!(c.is_blocked());
        // 重新检测之后恢复正常
        c.on_detection(Ok(eg("198.51.100.1", None))).unwrap();
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

    /// 记录调用顺序、可以让放行失败的测试后端。
    #[derive(Default)]
    struct Rec {
        blocked: bool,
        fail_unblock: bool,
        /// 依次的调用："block" / "unblock" / "rules v6=<bool>"
        calls: Vec<String>,
        rules: Rules,
    }

    struct RecFirewall(std::rc::Rc<std::cell::RefCell<Rec>>);

    impl Firewall for RecFirewall {
        fn block(&mut self) -> Result<()> {
            let mut r = self.0.borrow_mut();
            r.calls.push("block".into());
            r.blocked = true;
            Ok(())
        }
        fn unblock(&mut self) -> Result<()> {
            let mut r = self.0.borrow_mut();
            if r.fail_unblock {
                return Err(anyhow!("WFP 暂时不可用"));
            }
            r.calls.push("unblock".into());
            r.blocked = false;
            Ok(())
        }
        fn is_blocked(&self) -> bool {
            self.0.borrow().blocked
        }
        fn set_rules(&mut self, rules: Rules) -> Result<()> {
            let mut r = self.0.borrow_mut();
            r.calls.push(format!("rules v6={}", rules.block_ipv6));
            r.rules = rules;
            Ok(())
        }
    }

    fn rec(blocked: bool) -> (std::rc::Rc<std::cell::RefCell<Rec>>, Box<RecFirewall>) {
        let r = std::rc::Rc::new(std::cell::RefCell::new(Rec { blocked, ..Default::default() }));
        (r.clone(), Box::new(RecFirewall(r)))
    }

    #[test]
    fn failed_unblock_is_not_retried_after_network_change() {
        let (r, fw) = rec(true);
        let mut c = Controller::new(cfg("[ipv6]\nmode=\"off\""), fw);
        r.borrow_mut().fail_unblock = true;
        assert!(c.on_detection(Ok(eg("203.0.113.9", None))).is_err());
        assert!(c.needs_retry() && c.apply_error().is_some());
        // 换网：底层已经是阻断，旧的放行不能在之后的重试里生效
        c.on_network_change().unwrap();
        r.borrow_mut().fail_unblock = false;
        c.retry_pending().unwrap();
        assert!(c.is_blocked());
        assert!(!c.needs_retry() && c.apply_error().is_none());
        assert!(!r.borrow().calls.contains(&"unblock".to_owned()));
        // 新网络上检测通过后照常放行
        c.on_detection(Ok(eg("203.0.113.9", None))).unwrap();
        assert!(!c.is_blocked());

        // 关闭「网络变化时先阻断」也一样：没生效的放行作废，已经生效的规则不动
        let (r, fw) = rec(true);
        let mut c = Controller::new(cfg("[ipv6]\nmode=\"off\"\n[behavior]\nblock_on_network_change=false"), fw);
        r.borrow_mut().fail_unblock = true;
        assert!(c.on_detection(Ok(eg("203.0.113.9", None))).is_err());
        c.on_network_change().unwrap();
        r.borrow_mut().fail_unblock = false;
        c.retry_pending().unwrap();
        assert!(c.is_blocked());

        // 没有换网时，失败的放行照常重试
        let (r, fw) = rec(true);
        let mut c = Controller::new(cfg("[ipv6]\nmode=\"off\""), fw);
        r.borrow_mut().fail_unblock = true;
        assert!(c.on_detection(Ok(eg("203.0.113.9", None))).is_err());
        r.borrow_mut().fail_unblock = false;
        c.retry_pending().unwrap();
        assert!(!c.is_blocked());
    }

    #[test]
    fn network_change_blocks_even_right_after_an_allow() {
        // 防抖期间手动检测已经放行，同一窗口里再次换网：仍然先阻断（引擎每次网络变化都调用）
        let (_, fw) = rec(true);
        let mut c = Controller::new(cfg("[ipv6]\nmode=\"off\""), fw);
        c.on_network_change().unwrap();
        c.on_detection(Ok(eg("203.0.113.9", None))).unwrap();
        assert!(!c.is_blocked());
        c.on_network_change().unwrap();
        assert!(c.is_blocked());
    }

    fn check_cfg(whitelist: &[&str], extra: &str) -> Config {
        let wl: Vec<String> = whitelist.iter().map(|w| format!("\"{w}\"")).collect();
        Config::parse(&format!("whitelist=[{}]\napps=['C:\\a.exe']\n[ipv6]\nmode=\"check\"\n{extra}", wl.join(","))).unwrap()
    }

    #[test]
    fn incomplete_dual_stack_result_only_tightens() {
        let (_, fw) = rec(false);
        let mut c = Controller::new(check_cfg(&["203.0.113.0/24"], ""), fw);
        // IPv4 不在白名单、IPv6 检测失败：阻断，但这份结果没有验证 IPv6
        let det = crate::egress::combine(
            crate::egress::Probe::Verified("198.51.100.1".parse().unwrap()),
            crate::egress::Probe::Failed("超时".into()),
            |ip| c.config().is_whitelisted(ip),
        );
        c.on_detection(det).unwrap();
        assert!(c.is_blocked());
        // 把这个 IPv4 加进白名单：不能据此放行，要等重新检测
        c.reconfigure(check_cfg(&["203.0.113.0/24", "198.51.100.1/32"], "")).unwrap();
        assert!(c.is_blocked());
        // 完整的双栈结果才放行
        c.on_detection(Ok(eg("198.51.100.1", Some("2001:db8::1")))).unwrap();
        assert!(c.is_blocked(), "IPv6 出口不在白名单");
        c.on_detection(Ok(eg("198.51.100.1", None))).unwrap();
        assert!(!c.is_blocked());
        // 不完整的结果本身也不会放行（即使 IPv4 在白名单）
        let e = Egress { ip: "198.51.100.1".parse().unwrap(), v6: None, v6_unverified: true };
        assert!(!egress_allowed(c.config(), &e));
        c.on_detection(Ok(e)).unwrap();
        assert!(c.is_blocked());
        assert_eq!(c.block_reason(), Some("IPv6 出口没有验证成功，需要重新检测"));
    }

    #[test]
    fn complete_result_survives_whitelist_only_edit() {
        let (_, fw) = rec(true);
        let mut c = Controller::new(check_cfg(&["203.0.113.0/24"], ""), fw);
        c.on_detection(Ok(eg("198.51.100.1", Some("2001:db8::1")))).unwrap();
        assert!(c.is_blocked());
        // 只改白名单：完整的双栈结果可以直接用
        c.reconfigure(check_cfg(&["198.51.100.1/32", "2001:db8::/32"], "")).unwrap();
        assert!(!c.is_blocked());
    }

    #[test]
    fn measurement_path_change_only_tightens() {
        for change in ["[detect]\nproxy=\"socks5://127.0.0.1:1080\"", "[detect]\nservices=[\"https://ip.example.org\"]"] {
            let (_, fw) = rec(false);
            let mut c = Controller::new(cfg("[ipv6]\nmode=\"off\""), fw);
            c.on_detection(Ok(eg("198.51.100.1", None))).unwrap();
            assert!(c.is_blocked());
            // 换了代理 / 查询服务，同时把旧出口加进白名单：旧结果不是按新路径测的，不能放行
            let new = Config::parse(&format!("whitelist=[\"198.51.100.0/24\"]\napps=['C:\\a.exe']\n[ipv6]\nmode=\"off\"\n{change}")).unwrap();
            c.reconfigure(new.clone()).unwrap();
            assert!(c.is_blocked(), "{change}");
            // 但收紧照样立即生效
            c.on_detection(Ok(eg("198.51.100.1", None))).unwrap();
            assert!(!c.is_blocked());
            let tighter = Config::parse(&format!("whitelist=[\"203.0.113.0/24\"]\napps=['C:\\a.exe']\n[ipv6]\nmode=\"off\"\n{change}")).unwrap();
            c.reconfigure(tighter).unwrap();
            assert!(c.is_blocked());
        }
    }

    #[test]
    fn block_to_check_keeps_ipv6_block_until_verified() {
        let (r, fw) = rec(false);
        let mut c = Controller::new(cfg("[ipv6]\nmode=\"block\""), fw);
        c.apply_rules().unwrap();
        c.on_detection(Ok(eg("203.0.113.9", None))).unwrap();
        assert!(!c.is_blocked() && r.borrow().rules.block_ipv6);
        // 改为检测 IPv6 出口：还没验证 IPv6，常驻阻断保留
        let check = cfg("[ipv6]\nmode=\"check\"");
        c.reconfigure(check.clone()).unwrap();
        assert!(!c.is_blocked());
        assert!(r.borrow().rules.block_ipv6, "{:?}", r.borrow().calls);
        // 检测失败（未到阈值）：继续保留
        c.on_detection(Err(anyhow!("超时"))).unwrap();
        assert!(r.borrow().rules.block_ipv6);
        // 完整的双栈结果在白名单内：撤掉
        c.on_detection(Ok(eg("203.0.113.9", Some("203.0.113.10")))).unwrap();
        assert!(!c.is_blocked() && !r.borrow().rules.block_ipv6);

        // IPv6 出口不在白名单：先阻断，再撤掉常驻的 IPv6 阻断（不留空档）
        let (r, fw) = rec(false);
        let mut c = Controller::new(cfg("[ipv6]\nmode=\"block\""), fw);
        c.apply_rules().unwrap();
        c.on_detection(Ok(eg("203.0.113.9", None))).unwrap();
        c.reconfigure(check.clone()).unwrap();
        r.borrow_mut().calls.clear();
        c.on_detection(Ok(eg("203.0.113.9", Some("2001:db8::9")))).unwrap();
        assert!(c.is_blocked());
        assert_eq!(r.borrow().calls, vec!["block".to_owned(), "rules v6=false".to_owned()]);

        // 改为「不单独处理」是用户明确不管 IPv6：立即撤掉；从 off 改为 check 不新增阻断（本来就没有）
        let (r, fw) = rec(false);
        let mut c = Controller::new(cfg("[ipv6]\nmode=\"block\""), fw);
        c.apply_rules().unwrap();
        c.reconfigure(cfg("[ipv6]\nmode=\"off\"")).unwrap();
        assert!(!r.borrow().rules.block_ipv6);
        c.reconfigure(check).unwrap();
        assert!(!r.borrow().rules.block_ipv6);
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

    /// block/unblock 前 N 次失败的测试后端。
    struct SwitchFlaky {
        fail_left: std::rc::Rc<std::cell::Cell<u32>>,
        blocked: bool,
    }

    impl Firewall for SwitchFlaky {
        fn block(&mut self) -> Result<()> {
            if self.fail_left.get() > 0 {
                self.fail_left.set(self.fail_left.get() - 1);
                return Err(anyhow!("FwpmTransactionCommit0 失败"));
            }
            self.blocked = true;
            Ok(())
        }
        fn unblock(&mut self) -> Result<()> {
            if self.fail_left.get() > 0 {
                self.fail_left.set(self.fail_left.get() - 1);
                return Err(anyhow!("FwpmTransactionCommit0 失败"));
            }
            self.blocked = false;
            Ok(())
        }
        fn is_blocked(&self) -> bool {
            self.blocked
        }
        fn set_rules(&mut self, _: Rules) -> Result<()> {
            Ok(())
        }
    }

    fn recorded() -> Vec<ConnEvent> {
        crate::eventlog::TEST_RECORDED.with(|r| r.borrow_mut().drain(..).collect())
    }

    #[test]
    fn failed_first_block_is_retried_without_new_events() {
        recorded();
        let fail = std::rc::Rc::new(std::cell::Cell::new(2));
        let mut c = Controller::new(cfg(""), Box::new(SwitchFlaky { fail_left: fail.clone(), blocked: false }));
        // VPN 断开：第一次阻断失败
        assert!(c.block_for("VPN 断开（utun4）").is_err());
        assert!(!c.is_blocked() && c.wants_block() && c.needs_retry());
        assert!(c.apply_error().unwrap().starts_with("阻断未生效（VPN 断开（utun4））"));
        // 没有新的网络事件或检测结果：只靠定时重试
        assert!(c.retry_pending().is_err());
        assert!(c.needs_retry());
        c.retry_pending().unwrap();
        assert!(c.is_blocked() && !c.needs_retry() && c.apply_error().is_none());
        assert_eq!(c.block_reason(), Some("VPN 断开（utun4）"), "成功前保留断线原因");
        let ev = recorded();
        assert_eq!(ev.len(), 1, "只记一次成功的阻断");
        assert_eq!(ev[0].kind, Kind::Block);
        c.retry_pending().unwrap();
        assert!(recorded().is_empty());
    }

    #[test]
    fn failed_first_unblock_is_retried_and_can_be_superseded() {
        recorded();
        let fail = std::rc::Rc::new(std::cell::Cell::new(1));
        let mut c = Controller::new(cfg(""), Box::new(SwitchFlaky { fail_left: fail.clone(), blocked: true }));
        assert!(c.on_detection(Ok(eg("203.0.113.9", None))).is_err());
        assert!(c.is_blocked() && !c.wants_block() && c.needs_retry());
        assert!(c.apply_error().unwrap().starts_with("放行未生效"));
        c.retry_pending().unwrap();
        assert!(!c.is_blocked() && !c.needs_retry());
        assert_eq!(recorded().len(), 1);

        // 阻断失败后，新的检测结果（回到白名单）取代还没生效的阻断：不再重试，也不记录
        fail.set(1);
        assert!(c.on_detection(Ok(eg("198.51.100.1", None))).is_err());
        assert!(c.wants_block());
        c.on_detection(Ok(eg("203.0.113.9", None))).unwrap();
        assert!(!c.is_blocked() && !c.wants_block() && !c.needs_retry() && c.apply_error().is_none());
        assert!(recorded().is_empty());
    }

    #[test]
    fn switching_to_ipv6_check_waits_for_new_detection() {
        // 「不单独处理 IPv6」时测到的结果不能在改为「检测 IPv6 出口」后直接用来放行
        let mut c = Controller::new(cfg("[ipv6]\nmode=\"off\""), Box::new(DryRunFirewall { blocked: true }));
        c.on_detection(Ok(eg("203.0.113.9", None))).unwrap();
        assert!(!c.is_blocked());
        c.block_for("网络发生变化").unwrap();
        c.on_detection(Ok(eg("203.0.113.9", None))).unwrap();
        c.on_network_change().unwrap();
        c.on_detection(Ok(eg("198.51.100.1", None))).unwrap();
        assert!(c.is_blocked());
        // off 下测到 198.51.100.1（阻断）；改白名单让它命中、同时改成 check：不能放行
        let mut raw = cfg("").to_raw();
        raw.whitelist.push("198.51.100.0/24".into());
        c.reconfigure(Config::from_raw(raw.clone()).unwrap()).unwrap();
        assert!(c.is_blocked(), "IPv6 处理方式变了，要等新的检测");
        c.on_detection(Ok(eg("198.51.100.1", None))).unwrap();
        assert!(!c.is_blocked());
        // 方式不变时照常用最近的结果
        raw.whitelist.retain(|w| w != "198.51.100.0/24");
        c.reconfigure(Config::from_raw(raw).unwrap()).unwrap();
        assert!(c.is_blocked());
    }

    #[test]
    fn network_change_blocks_first() {
        let mut c = Controller::new(cfg(""), Box::new(DryRunFirewall::default()));
        c.on_network_change().unwrap();
        assert!(c.fw.is_blocked());
        assert!(c.block_reason().unwrap().contains("网络发生变化"));
        let mut c = Controller::new(
            cfg("[behavior]\nblock_on_network_change=false"),
            Box::new(DryRunFirewall::default()),
        );
        c.on_network_change().unwrap();
        assert!(!c.fw.is_blocked());
    }
}
