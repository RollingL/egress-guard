//! 通过公网 IP 查询服务检测本机出口 IP。

use std::net::IpAddr;
use std::time::Duration;

use anyhow::{anyhow, Result};
use ureq::config::IpFamily;
use ureq::tls::{TlsConfig, TlsProvider};
use ureq::Agent;

/// 检测用的地址族。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    /// 按系统默认（通常 IPv6 优先、不通时用 IPv4），依次尝试各服务。
    Any,
    /// 只走 IPv4（「始终阻断 IPv6」时：应用的流量只能走 IPv4，出口也只看 IPv4；
    /// 而且 IPv6 被防火墙丢弃，按默认顺序先试 IPv6 地址会一直等到超时）。
    V4,
    /// 只走 IPv6，同时请求各服务，第一个成功的结果生效（IPv6 不通时尽快结束）。
    V6,
}

impl Family {
    /// 主出口检测用的地址族：「始终阻断 IPv6」时只走 IPv4，其余按系统默认。
    pub fn for_main(mode: crate::config::Ipv6Mode) -> Self {
        if mode == crate::config::Ipv6Mode::Block {
            Family::V4
        } else {
            Family::Any
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Family::Any => "any",
            Family::V4 => "v4",
            Family::V6 => "v6",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "any" => Some(Family::Any),
            "v4" => Some(Family::V4),
            "v6" => Some(Family::V6),
            _ => None,
        }
    }
}

pub struct EgressDetector {
    agent: Agent,
    services: Vec<String>,
    family: Family,
    #[cfg_attr(windows, allow(dead_code))]
    timeout: Duration,
}

impl EgressDetector {
    pub fn new(services: Vec<String>, timeout: Duration) -> Self {
        Self::with_family(services, timeout, Family::Any)
    }

    pub fn with_family(services: Vec<String>, timeout: Duration, family: Family) -> Self {
        let agent: Agent = Agent::config_builder()
            // 使用系统 TLS（Windows 上为 SChannel，macOS 上为 Security.framework），无需额外证书
            .tls_config(TlsConfig::builder().provider(TlsProvider::NativeTls).build())
            .timeout_global(Some(timeout))
            .ip_family(match family {
                Family::Any => IpFamily::Any,
                Family::V4 => IpFamily::Ipv4Only,
                Family::V6 => IpFamily::Ipv6Only,
            })
            .user_agent(concat!("egress-guard/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Self { agent, services, family, timeout }
    }

    /// 检测出口 IP。
    ///
    /// macOS 上以 root 运行时（后台服务），检测放在以 `nobody` 身份运行的子进程中进行：
    /// 全局断网的 pf 规则按套接字所属用户放行它，而不必放行所有 root 进程。
    pub fn detect(&self) -> Result<IpAddr> {
        #[cfg(target_os = "macos")]
        if unsafe { libc::geteuid() } == 0 {
            return self.detect_unprivileged();
        }
        self.detect_direct()
    }

    /// 在子进程中以 nobody 身份检测（子进程运行 `egress-guard probe`）。
    #[cfg(unix)]
    pub fn detect_unprivileged(&self) -> Result<IpAddr> {
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};
        use std::time::Instant;

        let (uid, gid) = unsafe {
            let pw = libc::getpwnam(c"nobody".as_ptr());
            if pw.is_null() {
                return Err(anyhow!("系统中没有 nobody 用户"));
            }
            ((*pw).pw_uid, (*pw).pw_gid)
        };
        let exe = std::env::current_exe()?;
        let mut child = Command::new(exe)
            .arg("probe")
            .arg("--timeout")
            .arg(self.timeout.as_secs().max(1).to_string())
            .arg("--family")
            .arg(self.family.name())
            .args(&self.services)
            .uid(uid)
            .gid(gid)
            .env("HOME", "/var/empty")
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow!("无法启动检测子进程: {e}"))?;
        // 每个服务最多 timeout（IPv6 同时请求，总共最多 timeout），再留一些余量
        let n = if self.family == Family::V6 { 1 } else { (self.services.len() as u32).max(1) };
        let deadline = Instant::now() + self.timeout * n + Duration::from_secs(5);
        loop {
            if child.try_wait()?.is_some() {
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(anyhow!("检测子进程超时"));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let out = child.wait_with_output()?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        if out.status.success() {
            if let Ok(ip) = stdout.trim().parse() {
                return Ok(ip);
            }
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        let msg = stderr.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("检测子进程异常退出");
        Err(anyhow!("{}", msg.trim()))
    }

    /// 依次尝试各服务（IPv6 时同时请求），返回第一个成功解析的出口 IP。
    pub fn detect_direct(&self) -> Result<IpAddr> {
        if self.family == Family::V6 {
            return self.detect_parallel();
        }
        let mut errors = Vec::new();
        for url in &self.services {
            match self.query(url) {
                Ok(ip) => {
                    log::debug!("{url} 返回出口 IP {ip}");
                    return Ok(ip);
                }
                Err(e) => {
                    log::debug!("{url} 查询失败: {e:#}");
                    errors.push(format!("{url}: {e}"));
                }
            }
        }
        Err(anyhow!("所有出口 IP 服务均失败: {}", errors.join("; ")))
    }

    /// 同时请求所有服务，第一个成功的结果立即返回（其余请求在后台自行超时结束）；全部失败时返回所有错误。
    fn detect_parallel(&self) -> Result<IpAddr> {
        let (tx, rx) = std::sync::mpsc::channel();
        for url in &self.services {
            let (tx, agent, url) = (tx.clone(), self.agent.clone(), url.clone());
            std::thread::spawn(move || {
                let r = query(&agent, &url);
                let _ = tx.send((url, r));
            });
        }
        drop(tx);
        let mut errors = Vec::new();
        for (url, r) in rx.iter() {
            match r {
                Ok(ip) if self.family != Family::V6 || ip.is_ipv6() => {
                    log::debug!("{url} 返回出口 IP {ip}");
                    return Ok(ip);
                }
                Ok(ip) => errors.push(format!("{url}: 返回的不是 IPv6 地址（{ip}）")),
                Err(e) => errors.push(format!("{url}: {e}")),
            }
        }
        Err(anyhow!("所有出口 IP 服务均失败: {}", errors.join("; ")))
    }

    fn query(&self, url: &str) -> Result<IpAddr> {
        query(&self.agent, url)
    }
}

fn query(agent: &Agent, url: &str) -> Result<IpAddr> {
    let body = agent.get(url).call()?.body_mut().with_config().limit(4096).read_to_string()?;
    extract_ip(&body).ok_or_else(|| anyhow!("响应中没有 IP: {:?}", truncate(&body)))
}

/// 从响应文本中提取第一个合法 IP。兼容纯文本（"1.2.3.4\n"）
/// 和带说明文字的响应（如 "当前 IP：1.2.3.4 来自于：…"）。
pub fn extract_ip(body: &str) -> Option<IpAddr> {
    body.split(|c: char| !(c.is_ascii_hexdigit() || c == '.' || c == ':'))
        .filter(|t| !t.is_empty())
        .find_map(|t| t.trim_matches(|c| c == '.' || c == ':').parse().ok())
}

fn truncate(s: &str) -> String {
    s.chars().take(80).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_plain_and_decorated() {
        assert_eq!(extract_ip("203.0.113.5\n"), Some("203.0.113.5".parse().unwrap()));
        assert_eq!(
            extract_ip("当前 IP：198.51.100.7  来自于：中国"),
            Some("198.51.100.7".parse().unwrap())
        );
        assert_eq!(extract_ip("2001:db8::1"), Some("2001:db8::1".parse().unwrap()));
        assert_eq!(extract_ip("ip=203.0.113.9."), Some("203.0.113.9".parse().unwrap()));
        assert_eq!(extract_ip("<html>error</html>"), None);
    }
}
