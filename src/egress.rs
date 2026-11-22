//! 通过公网 IP 查询服务检测本机出口 IP。

use std::net::IpAddr;
use std::time::Duration;

use anyhow::{anyhow, Result};
use ureq::tls::{TlsConfig, TlsProvider};
use ureq::Agent;

pub struct EgressDetector {
    agent: Agent,
    services: Vec<String>,
    #[cfg_attr(windows, allow(dead_code))]
    timeout: Duration,
}

impl EgressDetector {
    pub fn new(services: Vec<String>, timeout: Duration) -> Self {
        let agent: Agent = Agent::config_builder()
            // 使用系统 TLS（Windows 上为 SChannel，macOS 上为 Security.framework），无需额外证书
            .tls_config(TlsConfig::builder().provider(TlsProvider::NativeTls).build())
            .timeout_global(Some(timeout))
            .user_agent("egress-guard/0.6")
            .build()
            .into();
        Self { agent, services, timeout }
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
        // 每个服务最多 timeout，再留一些余量
        let deadline = Instant::now() + self.timeout * (self.services.len() as u32).max(1) + Duration::from_secs(5);
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

    /// 依次尝试各服务，返回第一个成功解析的出口 IP。
    pub fn detect_direct(&self) -> Result<IpAddr> {
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

    fn query(&self, url: &str) -> Result<IpAddr> {
        let body = self
            .agent
            .get(url)
            .call()?
            .body_mut()
            .with_config()
            .limit(4096)
            .read_to_string()?;
        extract_ip(&body).ok_or_else(|| anyhow!("响应中没有 IP: {:?}", truncate(&body)))
    }
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
