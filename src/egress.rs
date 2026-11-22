//! 通过公网 IP 查询服务检测本机出口 IP。

use std::net::IpAddr;
use std::time::Duration;

use anyhow::{anyhow, Result};
use ureq::tls::{TlsConfig, TlsProvider};
use ureq::Agent;

pub struct EgressDetector {
    agent: Agent,
    services: Vec<String>,
}

impl EgressDetector {
    pub fn new(services: Vec<String>, timeout: Duration) -> Self {
        let agent: Agent = Agent::config_builder()
            // 使用系统 TLS（Windows 上为 SChannel），无需额外证书
            .tls_config(TlsConfig::builder().provider(TlsProvider::NativeTls).build())
            .timeout_global(Some(timeout))
            .user_agent("egress-guard/0.5")
            .build()
            .into();
        Self { agent, services }
    }

    /// 依次尝试各服务，返回第一个成功解析的出口 IP。
    pub fn detect(&self) -> Result<IpAddr> {
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
