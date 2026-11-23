//! 配置文件（TOML）解析与白名单匹配。

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::blockall::BlockAllPolicy;

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
    #[serde(default)]
    pub block_all: BlockAllConfig,
    #[serde(default)]
    pub leak_test: LeakTestConfig,
}

/// 泄露测试（DNS、WebRTC）。只在手动点「开始测试」或运行 `egress-guard leak-test` 时使用。
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct LeakTestConfig {
    /// 可信的 DNS 解析器：IP、CIDR 或自治系统号（如 `AS13335`）。
    /// DNS 泄露测试发现的解析器在这里、或在出口 IP 白名单内时不算泄露。
    pub trusted_dns: Vec<String>,
    /// DNS 泄露测试服务的域名（addr.tools 的 dnscheck，开源可自建）。
    pub dnscheck_zone: String,
    /// 使用的 DNS 检测源：dnscheck（WebSocket 推送，能看到全部解析器和 ECS），
    /// 以及 ip-api、every1dns、fastly、surfshark、ipleak、browserleaks（每个一次 HTTP 请求）。
    pub dns_sources: Vec<String>,
    /// WebRTC 泄露测试用的 STUN 服务器（主机:端口），按顺序尝试。
    pub stun_servers: Vec<String>,
}

impl Default for LeakTestConfig {
    fn default() -> Self {
        Self {
            trusted_dns: Vec::new(),
            dnscheck_zone: "dnscheck.tools".into(),
            dns_sources: crate::leaktest::dns::all_source_names(),
            stun_servers: vec![
                "myip.addr.tools:3478".into(),
                "stun.cloudflare.com:3478".into(),
                "stun.l.google.com:19302".into(),
                "stun.miwifi.com:3478".into(),
            ],
        }
    }
}

/// 全局断网：出口 IP 不在白名单时切断本机全部网络（而不只是受控应用）。
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct BlockAllConfig {
    pub enabled: bool,
    /// 放行局域网（私有网段、链路本地、组播）。
    pub allow_lan: bool,
    /// 放行 DNS 查询（远端端口 53）。关闭后本工具也可能无法检测出口 IP。
    pub allow_dns: bool,
    /// 例外程序（exe 完整路径），如 VPN 客户端。
    pub allow_apps: Vec<PathBuf>,
    /// 例外远端地址/网段，如 VPN 服务器地址。
    pub allow_remote: Vec<String>,
}

impl Default for BlockAllConfig {
    fn default() -> Self {
        Self { enabled: false, allow_lan: true, allow_dns: true, allow_apps: Vec::new(), allow_remote: Vec::new() }
    }
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
    pub block_all: BlockAllConfig,
    pub leak_test: LeakTestConfig,
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
            if !is_absolute_app_path(&app.to_string_lossy()) {
                bail!("应用路径必须是完整路径: {}", app.display());
            }
        }
        for app in &raw.block_all.allow_apps {
            if !is_absolute_app_path(&app.to_string_lossy()) {
                bail!("例外程序路径必须是完整路径: {}", app.display());
            }
        }
        let mut block_all = raw.block_all;
        block_all.allow_remote = block_all
            .allow_remote
            .iter()
            .filter(|s| !s.trim().is_empty())
            .map(|s| parse_net(s).map(|n| format_net(&n)).with_context(|| "例外地址有误"))
            .collect::<Result<Vec<_>>>()?;
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
        let mut leak_test = raw.leak_test;
        leak_test.trusted_dns = leak_test
            .trusted_dns
            .iter()
            .filter(|s| !s.trim().is_empty())
            .map(|s| crate::leaktest::Trusted::parse(s).map(|t| t.to_string()).with_context(|| "可信 DNS 解析器有误"))
            .collect::<Result<Vec<_>>>()?;
        leak_test.dnscheck_zone = leak_test.dnscheck_zone.trim().trim_matches('.').to_ascii_lowercase();
        if !crate::leaktest::valid_zone(&leak_test.dnscheck_zone) {
            bail!("DNS 泄露测试服务的域名有误: {:?}", leak_test.dnscheck_zone);
        }
        leak_test.dns_sources.retain(|s| !s.trim().is_empty());
        for s in &mut leak_test.dns_sources {
            *s = s.trim().to_ascii_lowercase();
            if !crate::leaktest::dns::all_source_names().contains(s) {
                bail!("未知的 DNS 检测源: {s:?}（可用：{}）", crate::leaktest::dns::all_source_names().join("、"));
            }
        }
        leak_test.stun_servers = leak_test.stun_servers.iter().map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()).collect();
        for s in &leak_test.stun_servers {
            crate::leaktest::stun::split_host_port(s).with_context(|| format!("STUN 服务器有误: {s:?}"))?;
        }
        Ok(Self {
            whitelist,
            apps: raw.apps,
            detect,
            behavior: raw.behavior,
            ui: raw.ui,
            children: raw.children,
            block_all,
            leak_test,
        })
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
            block_all: self.block_all.clone(),
            leak_test: self.leak_test.clone(),
        }
    }

    /// 全局断网开启时返回其例外规则。
    pub fn block_all_policy(&self) -> Option<BlockAllPolicy> {
        let b = &self.block_all;
        b.enabled.then(|| BlockAllPolicy {
            allow_lan: b.allow_lan,
            allow_dns: b.allow_dns,
            allow_apps: b.allow_apps.clone(),
            allow_remote: b.allow_remote.iter().filter_map(|s| parse_net(s).ok()).collect(),
        })
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

/// 程序路径是否为完整路径：Windows 形式（C:\... 或 \\server\...）在任何平台都接受，
/// 便于在其他平台上开发测试；非 Windows 平台还接受 `/` 开头的路径（macOS 上可以是 .app 包）。
pub fn is_absolute_app_path(p: &str) -> bool {
    is_windows_absolute(p) || (cfg!(not(windows)) && p.starts_with('/'))
}

/// 判断是否为 Windows 完整路径（C:\... 或 \\server\share\...），与运行平台无关。
pub fn is_windows_absolute(p: &str) -> bool {
    let b = p.as_bytes();
    (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/'))
        || p.starts_with("\\\\")
}

/// 把 IPv4 映射的 IPv6 地址（::ffff:a.b.c.d）还原成 IPv4。
pub fn normalize(ip: IpAddr) -> IpAddr {
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
        // Unix 完整路径只在非 Windows 平台接受
        assert_eq!(Config::parse("whitelist=[]\napps=['/Applications/Foo.app']").is_ok(), cfg!(not(windows)));
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
    fn block_all_section() {
        let cfg = Config::parse(SAMPLE).unwrap();
        assert!(cfg.block_all_policy().is_none());
        let cfg = Config::parse(&format!(
            "{SAMPLE}\n[block_all]\nenabled=true\nallow_dns=false\nallow_apps=['C:\\vpn\\vpn.exe']\nallow_remote=[\"198.51.100.7\", \"203.0.113.9/24\"]"
        ))
        .unwrap();
        let p = cfg.block_all_policy().unwrap();
        assert!(p.allow_lan && !p.allow_dns);
        assert_eq!(p.allow_apps.len(), 1);
        assert_eq!(cfg.block_all.allow_remote, vec!["198.51.100.7", "203.0.113.0/24"]);
        assert!(Config::parse(&format!("{SAMPLE}\n[block_all]\nallow_remote=[\"x\"]")).is_err());
        assert!(Config::parse(&format!("{SAMPLE}\n[block_all]\nallow_apps=['vpn.exe']")).is_err());
    }

    #[test]
    fn leak_test_section() {
        let cfg = Config::parse(SAMPLE).unwrap();
        assert_eq!(cfg.leak_test.dnscheck_zone, "dnscheck.tools");
        assert!(!cfg.leak_test.stun_servers.is_empty());
        let cfg = Config::parse(&format!(
            "{SAMPLE}\n[leak_test]\ntrusted_dns=[\"as13335\", \"203.0.113.9/24\", \" \"]\ndnscheck_zone=\"Example.ORG.\"\nstun_servers=[\"stun.example.org:3478\", \"[2001:db8::1]:3478\"]"
        ))
        .unwrap();
        assert_eq!(cfg.leak_test.trusted_dns, vec!["AS13335", "203.0.113.0/24"]);
        assert_eq!(cfg.leak_test.dnscheck_zone, "example.org");
        assert_eq!(cfg.leak_test.stun_servers.len(), 2);
        assert!(Config::parse(&format!("{SAMPLE}\n[leak_test]\ntrusted_dns=[\"ASx\"]")).is_err());
        assert!(Config::parse(&format!("{SAMPLE}\n[leak_test]\nstun_servers=[\"stun.example.org\"]")).is_err());
        assert!(Config::parse(&format!("{SAMPLE}\n[leak_test]\ndnscheck_zone=\"a b\"")).is_err());
        assert!(Config::parse(&format!("{SAMPLE}\n[leak_test]\ndns_sources=[\"Fastly\", \"dnscheck\"]")).is_ok());
        assert!(Config::parse(&format!("{SAMPLE}\n[leak_test]\ndns_sources=[\"nope\"]")).is_err());
    }

    #[test]
    fn example_config_is_valid() {
        let text = include_str!("../config.example.toml");
        Config::parse(text).unwrap();
    }
}
