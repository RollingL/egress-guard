//! macOS pf 防火墙后端：全局断网。
//!
//! - 规则装入 `com.apple/egress-guard` 子锚点（主规则集默认就会评估 `com.apple/*`），不改 `/etc/pf.conf`。
//! - 阻断时用 `pfctl -E` 取得启用令牌，放行时用 `pfctl -X` 归还；pf 原本是否开启都不受影响。
//! - pf 规则不随进程退出自动消失：正常退出、收到 SIGTERM 时会清空；异常退出后由 launchd 重启服务，
//!   启动时先清空残留规则。也可以手动执行 `sudo egress-guard unblock`。
//! - pf 只能按地址/端口/用户过滤，**不能按应用**区分，所以受控应用列表和例外程序在这里不生效。

use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};

use crate::controller::{Firewall, Rules};
use crate::pfrules::{self, ANCHOR};

const PFCTL: &str = "/sbin/pfctl";

pub struct PfFirewall {
    blocked: bool,
    rules: Rules,
    /// `pfctl -E` 返回的启用令牌。
    token: Option<String>,
    /// 已经提示过的限制，避免日志刷屏。
    warned_apps: bool,
    warned_allow_apps: bool,
}

fn pfctl(args: &[&str], stdin: Option<&str>) -> Result<String> {
    let mut cmd = Command::new(PFCTL);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() });
    let mut child = cmd.spawn().context("无法运行 pfctl")?;
    if let Some(text) = stdin {
        child.stdin.take().context("pfctl stdin")?.write_all(text.as_bytes())?;
    }
    let out = child.wait_with_output()?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    if !out.status.success() {
        bail!("pfctl {} 失败: {}", args.join(" "), text.trim());
    }
    Ok(text)
}

/// 清空本工具锚点里的规则（用于退出、放行，以及从异常退出中恢复）。
pub fn flush_anchor() -> Result<()> {
    pfctl(&["-a", ANCHOR, "-F", "rules"], None).map(|_| ())
}

/// 确保主规则集会评估 `com.apple/*` 子锚点；没有加载时按 /etc/pf.conf 加载。
fn ensure_main_anchor() -> Result<()> {
    let main = pfctl(&["-s", "rules"], None)?;
    if pfrules::has_apple_anchor(&main) {
        return Ok(());
    }
    let conf = std::fs::read_to_string("/etc/pf.conf").unwrap_or_default();
    if !pfrules::has_apple_anchor(&conf) {
        bail!("/etc/pf.conf 中没有 anchor \"com.apple/*\"，无法装入规则（请恢复系统默认的 pf.conf）");
    }
    log::info!("pf 主规则集未加载，按 /etc/pf.conf 加载");
    pfctl(&["-f", "/etc/pf.conf"], None)?;
    Ok(())
}

impl PfFirewall {
    pub fn open() -> Result<Self> {
        if unsafe { libc::geteuid() } != 0 {
            bail!("pf 需要 root 权限：请安装后台服务，或用 sudo 运行命令行版本");
        }
        ensure_main_anchor()?;
        // 上次异常退出可能留下规则
        flush_anchor()?;
        Ok(Self {
            blocked: false,
            rules: Rules::default(),
            token: None,
            warned_apps: false,
            warned_allow_apps: false,
        })
    }

    fn warn_limits(&mut self) {
        if self.rules.block_all.is_none() && !self.rules.apps.is_empty() && !self.warned_apps {
            self.warned_apps = true;
            log::warn!("macOS pf 不能按应用阻断：受控应用不会被断网。请开启「全局断网」");
        }
        if let Some(p) = &self.rules.block_all {
            if !p.allow_apps.is_empty() && !self.warned_allow_apps {
                self.warned_allow_apps = true;
                log::warn!("macOS pf 不能按程序放行：例外程序不生效，请改用例外地址（如 VPN 服务器 IP）");
            }
        }
    }

    fn enable(&mut self) -> Result<()> {
        if self.token.is_none() {
            let out = pfctl(&["-E"], None)?;
            self.token = pfrules::parse_token(&out);
            if self.token.is_none() {
                log::warn!("pfctl -E 没有返回令牌，退出时不会关闭 pf: {}", out.trim());
            }
        }
        Ok(())
    }

    fn release(&mut self) {
        if let Some(t) = self.token.take() {
            if let Err(e) = pfctl(&["-X", &t], None) {
                log::warn!("{e:#}");
            }
        }
    }

    /// 让 pf 中的规则与当前状态一致。
    fn sync(&mut self) -> Result<()> {
        match (self.rules.block_all.clone(), self.blocked) {
            (Some(policy), true) => {
                let text = pfrules::render(&policy);
                log::debug!("装入 pf 规则:\n{text}");
                // 先装规则再启用，避免 pf 已启用但规则还没到位的空档
                pfctl(&["-a", ANCHOR, "-f", "-"], Some(&text))?;
                self.enable()?;
                log::info!("pf 规则已生效（{}）", pfrules::summary(&policy));
                Ok(())
            }
            _ => {
                flush_anchor()?;
                self.release();
                Ok(())
            }
        }
    }
}

impl Firewall for PfFirewall {
    fn block(&mut self) -> Result<()> {
        self.blocked = true;
        self.sync()
    }

    fn unblock(&mut self) -> Result<()> {
        self.blocked = false;
        self.sync()
    }

    fn is_blocked(&self) -> bool {
        self.blocked
    }

    fn set_rules(&mut self, rules: Rules) -> Result<()> {
        let changed = rules.block_all != self.rules.block_all;
        self.rules = rules;
        self.warn_limits();
        if changed && self.blocked {
            self.sync()?;
        }
        Ok(())
    }

    fn per_app(&self) -> bool {
        false
    }
}

impl Drop for PfFirewall {
    fn drop(&mut self) {
        if let Err(e) = flush_anchor() {
            log::error!("清空 pf 规则失败: {e:#}");
        }
        self.release();
    }
}
