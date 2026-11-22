//! 配置文件（TOML）解析与白名单匹配。

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// 出口 IP 检测失败时的处理方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FailMode {
    /// 视为不在白名单内，阻断（默认，最安全）。
    #[default]
    Block,
    /// 视为在白名单内，放行。
    Allow,
    /// 保持当前状态不变。
    Keep,
}

#[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RawConfig {
    /// 出口 IP 白名单，支持单个 IP（v4/v6）与 CIDR。
    #[serde(default)]
    pub whitelist: Vec<String>,
    /// 受控应用的完整 exe 路径。
    #[serde(default)]
    pub apps: Vec<PathBuf>,
    #[serde(default)]
    pub detect: DetectConfig,
    #[serde(default)]
    pub behavior: BehaviorConfig,
    #[serde(default)]
    pub ui: UiConfig,
    #[serde(default)]
    pub children: ChildrenConfig,
}

/// 子进程识别模式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ChildMode {
    /// 不识别子进程。
    Off,
    /// 受控应用的整棵进程树（含不同 exe 的子进程）一起阻断（默认）。
    #[default]
    Tree,
}

/// 关联程序的自动识别。
#[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct ChildrenConfig {
    pub mode: ChildMode,
    /// 同时阻断受控应用 exe 所在目录（含子目录）下的全部 exe。
    pub include_app_dir: bool,
    /// 不自动阻断的程序（exe 完整路径）。
    pub exclude: Vec<PathBuf>,
}

/// 界面外观。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Appearance {
    /// 跟随系统浅色/深色设置。
    #[default]
    System,
    Light,
    Dark,
}

/// 界面相关设置（命令行版本忽略）。
#[derive(Debug, Clone, PartialEq, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct UiConfig {
    pub appearance: Appearance,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct DetectConfig {
    /// 定时检测间隔（秒）。
    pub interval_secs: u64,
    /// 单次 HTTP 请求超时（秒）。
    pub timeout_secs: u64,
    /// 公网 IP 查询服务，按顺序尝试，第一个成功的结果生效。
    pub services: Vec<String>,
    /// 检测失败时的处理方式。
    pub fail_mode: FailMode,
    /// 连续失败多少次后才执行 fail_mode（避免偶发抖动）。
    pub failure_threshold: u32,
}

impl Default for DetectConfig {
    fn default() -> Self {
        Self {
            interval_secs: 60,
            timeout_secs: 5,
            services: vec![
                "https://4.ipw.cn".into(),
                "https://api.ipify.org".into(),
                "https://ifconfig.me/ip".into(),
                "https://checkip.amazonaws.com".into(),
            ],
            fail_mode: FailMode::Block,
            failure_threshold: 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct BehaviorConfig {
    /// 启动时先阻断，确认出口 IP 在白名单后再放行（避免启动瞬间泄漏）。
    pub start_blocked: bool,
    /// 检测到网卡/地址/路由变化时立即先阻断，再重新检测出口 IP。
    pub block_on_network_change: bool,
    /// 切换到阻断时，强制断开受控应用现有的 IPv4 TCP 连接。
    pub kill_existing_tcp: bool,
    /// 网络变化事件的防抖时间（毫秒）。
    pub debounce_ms: u64,
}

impl Default for BehaviorConfig {
    fn default() -> Self {
        Self {
            start_blocked: true,
            block_on_network_change: true,
            kill_existing_tcp: true,
            debounce_ms: 2000,
        }
    }
}

/// 校验后的配置。
#[derive(Debug, Clone)]
pub struct Config {
    pub whitelist: Vec<IpNet>,
    pub apps: Vec<PathBuf>,
    pub detect: DetectConfig,
    pub behavior: BehaviorConfig,
    pub ui: UiConfig,
    pub children: ChildrenConfig,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("无法读取配置文件 {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("配置文件 {} 有误", path.display()))
    }

    pub fn parse(text: &str) -> Result<Self> {
        let raw: RawConfig = toml::from_str(text)?;
        Self::from_raw(raw)
    }

    /// 校验原始配置。apps 允许为空（此时没有应用会被阻断）。
    pub fn from_raw(raw: RawConfig) -> Result<Self> {
        let whitelist = raw
            .whitelist
            .iter()
            .map(|s| parse_net(s))
            .collect::<Result<Vec<_>>>()?;
        for app in &raw.apps {
            if !is_windows_absolute(&app.to_string_lossy()) {
                bail!("应用路径必须是完整路径: {}", app.display());
            }
        }
        if raw.detect.services.iter().all(|s| s.trim().is_empty()) {
            bail!("至少需要一个出口 IP 查询服务");
        }
        if raw.detect.interval_secs == 0 {
            bail!("检测间隔必须大于 0");
        }
        if raw.detect.timeout_secs == 0 {
            bail!("超时时间必须大于 0");
        }
        let mut detect = raw.detect;
        detect.services.retain(|s| !s.trim().is_empty());
        Ok(Self { whitelist, apps: raw.apps, detect, behavior: raw.behavior, ui: raw.ui, children: raw.children })
    }

    /// 转回可序列化/可编辑的原始配置。
    pub fn to_raw(&self) -> RawConfig {
        RawConfig {
            whitelist: self.whitelist.iter().map(format_net).collect(),
            apps: self.apps.clone(),
            detect: self.detect.clone(),
            behavior: self.behavior.clone(),
            ui: self.ui.clone(),
            children: self.children.clone(),
        }
    }

    /// 写入 TOML 文件（注释不会保留）。
    pub fn save(&self, path: &Path) -> Result<()> {
        let text = format!(
            "# egress-guard 配置（由程序保存，说明见 config.example.toml）\n\n{}",
            toml::to_string_pretty(&self.to_raw())?
        );
        std::fs::write(path, text).with_context(|| format!("无法写入 {}", path.display()))
    }

    /// 出口 IP 是否命中白名单。
    pub fn is_whitelisted(&self, ip: IpAddr) -> bool {
        let ip = normalize(ip);
        self.whitelist.iter().any(|net| net.contains(&ip))
    }
}

/// 解析单个 IP 或 CIDR。
pub fn parse_net(s: &str) -> Result<IpNet> {
    let s = s.trim();
    if let Ok(net) = s.parse::<IpNet>() {
        return Ok(net.trunc());
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(IpNet::from(normalize(ip)));
    }
    bail!("白名单条目无法解析为 IP 或 CIDR: {s:?}")
}

/// 单个主机显示为纯 IP，网段显示为 CIDR。
pub fn format_net(net: &IpNet) -> String {
    if net.prefix_len() == net.max_prefix_len() {
        net.addr().to_string()
    } else {
        net.to_string()
    }
}

/// 判断是否为 Windows 完整路径（C:\... 或 \\server\share\...），与运行平台无关。
pub fn is_windows_absolute(p: &str) -> bool {
    let b = p.as_bytes();
    (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/'))
        || p.starts_with("\\\\")
}

/// 把 IPv4 映射的 IPv6 地址（::ffff:a.b.c.d）还原成 IPv4。
fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
whitelist = ["203.0.113.10", "198.51.100.0/24", "2001:db8::/32", "192.0.2.77/16"]
apps = ['C:\Program Files\App\app.exe']
"#;

    #[test]
    fn parses_and_matches() {
        let cfg = Config::parse(SAMPLE).unwrap();
        assert!(cfg.is_whitelisted("203.0.113.10".parse().unwrap()));
        assert!(!cfg.is_whitelisted("203.0.113.11".parse().unwrap()));
        assert!(cfg.is_whitelisted("198.51.100.200".parse().unwrap()));
        assert!(cfg.is_whitelisted("2001:db8:1::5".parse().unwrap()));
        assert!(!cfg.is_whitelisted("2001:db9::1".parse().unwrap()));
        // 非规范 CIDR 会被截断为网段
        assert!(cfg.is_whitelisted("192.0.9.9".parse().unwrap()));
        // IPv4 映射地址
        assert!(cfg.is_whitelisted("::ffff:203.0.113.10".parse().unwrap()));
        assert_eq!(cfg.detect.interval_secs, 60);
        assert!(cfg.behavior.start_blocked);
    }

    #[test]
    fn rejects_bad_entries() {
        assert!(Config::parse("whitelist=[\"1.2.3\"]\napps=['C:\\a.exe']").is_err());
        assert!(Config::parse("whitelist=[]\napps=[]").is_ok());
        assert!(Config::parse("whitelist=[]\napps=['a.exe']").is_err());
        assert!(Config::parse("whitelist=[]\napps=['C:\\a.exe']\nbogus=1").is_err());
    }

    #[test]
    fn roundtrip_raw() {
        let cfg = Config::parse(SAMPLE).unwrap();
        let raw = cfg.to_raw();
        assert_eq!(raw.whitelist[0], "203.0.113.10");
        assert_eq!(raw.whitelist[3], "192.0.0.0/16");
        let text = toml::to_string_pretty(&raw).unwrap();
        let back = Config::parse(&text).unwrap();
        assert_eq!(back.to_raw(), raw);
    }

    #[test]
    fn example_config_is_valid() {
        let text = include_str!("../config.example.toml");
        Config::parse(text).unwrap();
    }
}
