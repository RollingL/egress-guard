//! macOS pf 防火墙后端：全局断网。
//!
//! - 规则装入 `com.apple/egress-guard` 子锚点（主规则集默认就会评估 `com.apple/*`），不改 `/etc/pf.conf`。
//! - 阻断时用 `pfctl -E` 取得启用令牌，放行时用 `pfctl -X` 归还；pf 原本是否开启都不受影响。
//! - pf 规则不随进程退出自动消失：正常退出、收到 SIGTERM 时会清空；异常退出后由 launchd 重启服务，
//!   启动后第一次同步时用目标规则原子替换残留规则。也可以手动执行 `sudo egress-guard unblock`。
//! - 同一时间只有一个进程拥有锚点：打开时取得 [`PF_LOCK`] 的独占锁（进程退出时系统自动释放），
//!   第二个实例（例如后台服务运行时又用 sudo 运行命令行版本）打不开，不会清掉正在工作的保护。
//! - 「始终阻断 IPv6」且开启了全局断网时，放行期间也装着只针对 IPv6 的规则（见 `pfrules::render_v6`）。
//! - pf 只能按地址/端口/用户过滤，**不能按应用**区分：受控应用由网络扩展负责（见 `mac::firewall`），
//!   例外程序在这里不生效。

use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};

use super::paths::PF_LOCK;
use crate::controller::{Firewall, Rules};
use crate::pfrules::{self, ANCHOR};

const PFCTL: &str = "/sbin/pfctl";

pub struct PfFirewall {
    blocked: bool,
    rules: Rules,
    /// `pfctl -E` 返回的启用令牌。
    token: Option<String>,
    /// 已经提示过的限制，避免日志刷屏。
    warned_allow_apps: bool,
    /// set_rules 已经调用过（启动时第一次要同步）。
    synced_once: bool,
    /// 上次同步 pf 规则失败：引擎会定时重试（见 has_pending），直到规则真正装上。
    dirty: bool,
    /// 锚点的所有权锁，随本对象（进程）存在。
    _lock: std::fs::File,
}

/// 取得锚点的独占锁；已被其他进程持有时返回 Ok(None)。
fn try_lock() -> Result<Option<std::fs::File>> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        // /var/run 只有 root 能写；仍然不跟随符号链接
        .custom_flags(libc::O_NOFOLLOW)
        .open(PF_LOCK)
        .with_context(|| format!("无法打开 {PF_LOCK}"))?;
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        return Ok(Some(f));
    }
    let e = std::io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
        Ok(None)
    } else {
        Err(anyhow::Error::new(e).context(format!("无法锁定 {PF_LOCK}")))
    }
}

/// 是否有其他进程（通常是后台服务）正在管理本工具的 pf 锚点。
pub fn anchor_in_use() -> bool {
    matches!(try_lock(), Ok(None))
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

/// 确保主规则集会评估 `com.apple/*` 子锚点；主规则集还没加载（为空）时按 /etc/pf.conf 加载。
/// 已经加载了不含这个锚点的自定义规则集时报告原因，而不是用 /etc/pf.conf 把它整个替换掉。
fn ensure_main_anchor() -> Result<()> {
    let main = pfctl(&["-s", "rules"], None)?;
    if pfrules::has_apple_anchor(&main) {
        return Ok(());
    }
    if pfrules::has_loaded_rules(&main) {
        bail!(
            "当前加载的 pf 主规则集不包含 anchor \"com.apple/*\"（可能是其他防火墙软件或自定义的规则），\
             无法装入本工具的规则。为避免覆盖它，本工具不会重新加载 /etc/pf.conf；请在该规则集中加入这个锚点"
        );
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
    /// 打开 pf 后端。`start_blocked`：启动时先阻断，第一次同步直接装入阻断规则，
    /// 不会先按「放行」同步一次再阻断。
    pub fn open(start_blocked: bool) -> Result<Self> {
        if unsafe { libc::geteuid() } != 0 {
            bail!("pf 需要 root 权限：请安装后台服务，或用 sudo 运行命令行版本");
        }
        // 先取得锚点的所有权，再做任何 pfctl 操作。更新后台服务时旧进程可能还在清理退出，稍等几秒
        let mut lock = try_lock()?;
        for _ in 0..50 {
            if lock.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
            lock = try_lock()?;
        }
        let Some(lock) = lock else {
            bail!("另一个 egress-guard 实例（通常是后台服务）正在管理 pf 规则；同一时间只能运行一个实例");
        };
        ensure_main_anchor()?;
        // 上次异常退出可能留下规则：不先清空，第一次同步时用目标规则原子替换（失败时保留原规则）
        Ok(Self {
            blocked: start_blocked,
            rules: Rules::default(),
            token: None,
            warned_allow_apps: false,
            synced_once: false,
            dirty: false,
            _lock: lock,
        })
    }

    fn warn_limits(&mut self) {
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

    /// 让 pf 中的规则与当前状态一致；失败时记下，稍后重试。
    fn sync(&mut self) -> Result<()> {
        let r = self.sync_inner();
        self.dirty = r.is_err();
        r
    }

    fn sync_inner(&mut self) -> Result<()> {
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
            // 放行期间「始终阻断 IPv6」：只装 IPv6 的规则
            (Some(policy), false) if self.rules.block_ipv6 => {
                let text = pfrules::render_v6(&policy);
                log::debug!("装入 pf 规则:\n{text}");
                pfctl(&["-a", ANCHOR, "-f", "-"], Some(&text))?;
                self.enable()?;
                log::info!("pf 规则已生效：始终阻断 IPv6（{}）", pfrules::summary(&policy));
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

impl PfFirewall {
    /// 切换阻断状态。规则装上之后才改 `blocked`：失败时仍报告原来的状态（控制器会重试这次切换），
    /// 不会让界面先显示目标状态。
    fn set_blocked(&mut self, blocked: bool) -> Result<()> {
        // 还没收到规则：只记下状态，第一次 set_rules 按它装入（避免用空规则同步一次）
        if !self.synced_once {
            self.blocked = blocked;
            return Ok(());
        }
        let before = self.blocked;
        self.blocked = blocked;
        let r = self.sync();
        if r.is_err() {
            self.blocked = before;
        }
        r
    }
}

impl Firewall for PfFirewall {
    fn block(&mut self) -> Result<()> {
        self.set_blocked(true)
    }

    fn unblock(&mut self) -> Result<()> {
        self.set_blocked(false)
    }

    fn is_blocked(&self) -> bool {
        self.blocked
    }

    fn set_rules(&mut self, rules: Rules) -> Result<()> {
        let changed = rules.block_all != self.rules.block_all || rules.block_ipv6 != self.rules.block_ipv6;
        // 第一次设置规则时（启动）也同步一次：「始终阻断 IPv6」在放行状态下也要生效
        let first = !self.synced_once;
        self.synced_once = true;
        self.rules = rules;
        self.warn_limits();
        if changed || first || self.dirty {
            self.sync()?;
        }
        Ok(())
    }

    fn has_pending(&self) -> bool {
        self.dirty
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
