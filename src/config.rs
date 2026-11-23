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
    #[serde(default)]
    pub vpn: VpnConfig,
    #[serde(default)]
    pub ipv6: Ipv6Config,
    #[serde(default)]
    pub update: UpdateConfig,
}

/// VPN 守护：放行时记下正在使用的 VPN 网卡，它一断开就立即阻断，不等下一次出口 IP 检测。
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct VpnConfig {
    /// VPN 断开时立即阻断。
    pub guard: bool,
    /// 要守护的 VPN 网卡名称（不区分大小写；Windows 也可以填网卡描述）。为空时自动识别。
    pub interfaces: Vec<String>,
    /// 通过 VPN 放行期间的出口 IP 检测间隔（秒），比平时更勤，0 表示与平时相同。
    pub check_interval_secs: u64,
}

impl Default for VpnConfig {
    fn default() -> Self {
        Self { guard: true, interfaces: Vec::new(), check_interval_secs: 15 }
    }
}

/// IPv6 的处理方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Ipv6Mode {
    /// 另外检测 IPv6 出口：本机能直连 IPv6、而它的出口不在白名单时也阻断。
    Check,
    /// 始终阻断 IPv6（受控应用，或开启全局断网时的全部 IPv6），IPv4 照常按白名单放行（默认）。
    /// 适合不支持 IPv6 的 VPN：IPv6 流量会绕过 VPN 直接出去。
    #[default]
    Block,
    /// 不单独处理 IPv6（0.8 及以前的行为）。
    Off,
}

/// IPv6 防护。
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Ipv6Config {
    pub mode: Ipv6Mode,
    /// 只走 IPv6 的出口 IP 查询服务（同时尝试，第一个成功的结果生效）。
    pub services: Vec<String>,
}

impl Default for Ipv6Config {
    fn default() -> Self {
        Self {
            mode: Ipv6Mode::Block,
            services: vec!["https://6.ipw.cn".into(), "https://api6.ipify.org".into(), "https://v6.ident.me".into()],
        }
    }
}

/// 检查新版本（界面使用）。
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct UpdateConfig {
    /// 启动时和之后每天检查一次 GitHub 上的最新发布版本。
    pub check: bool,
    /// GitHub 仓库（owner/name）。
    pub repo: String,
    /// 访问令牌（仓库是私有的时候需要，只要 Contents 只读权限）。
    pub token: String,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self { check: true, repo: "RollingL/egress-guard".into(), token: String::new() }
    }
}

/// 泄露测试（DNS、WebRTC）：手动点「开始测试」、运行 `egress-guard leak-test`，或者由界面自动运行。
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
    /// 允许界面在后台自动测试（总开关，默认关闭）。自动测试会绕过系统代理直连上面的 DNS 检测源，
    /// 用系统 DNS 解析它们的随机子域名，并从默认路由和每个网卡地址向 STUN 服务器发 UDP：
    /// 只靠代理上网的用户会因此向这些第三方暴露直连的公网地址。0.9.0 的配置升级后也是关闭的。
    pub auto: bool,
    /// 网络变化后、出口刚回到白名单时自动测试一次（界面运行、`auto` 开启时）。
    pub auto_after_change: bool,
    /// 放行期间每隔多少分钟自动测试一次，0 表示不定时测试。
    pub interval_mins: u64,
    /// 自动测试发现泄露时发系统通知。
    pub notify: bool,
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
            auto: false,
            auto_after_change: true,
            interval_mins: 60,
            notify: true,
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
    /// 检测出口时使用的代理（如 `http://127.0.0.1:7890`、`socks5://127.0.0.1:7891`）。默认为空：直连检测。
    /// 只有受控应用的流量全部经过这个代理时才适合填写，否则测到的是代理的出口，直连的应用会被误放行。
    /// 不读 `HTTP(S)_PROXY` 等环境变量。
    pub proxy: String,
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
            proxy: String::new(),
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
    pub vpn: VpnConfig,
    pub ipv6: Ipv6Config,
    pub update: UpdateConfig,
}

/// 把一节配置从第二个参数复制到第一个参数。
type CopySection = fn(&mut RawConfig, &RawConfig);

/// 读取配置文件的结果（见 [`Config::load_recovering`]）。
#[derive(Debug)]
pub enum Loaded {
    /// 配置文件正常。
    Ok(Config),
    /// 配置文件有误，已改用最近一次有效的配置；原文件另存在 `broken`（另存失败或读不了时为 None）。
    LastGood { cfg: Config, error: String, broken: Option<PathBuf> },
    /// 配置文件有误，也没有可用的最近有效配置。
    Failed { error: String, broken: Option<PathBuf> },
    /// 真正的首次启动：配置文件和最近有效配置的副本都确实不存在。调用方可以创建默认配置。
    Missing,
}

/// 最近一次有效配置的副本：每次保存、每次成功读取后更新，配置文件损坏时用它恢复保护。
pub fn last_good_path(path: &Path) -> PathBuf {
    sibling(path, "last-good")
}

/// 无法解析的配置文件另存的位置（之后保存设置会覆盖原文件，这里留一份供用户找回）。
pub fn broken_path(path: &Path) -> PathBuf {
    sibling(path, "broken")
}

fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "config.toml".into());
    path.with_file_name(format!("{name}.{suffix}"))
}

/// 时间类设置的上限。
pub const MAX_INTERVAL_SECS: u64 = 7 * 86400;
pub const MAX_TIMEOUT_SECS: u64 = 600;
pub const MAX_DEBOUNCE_MS: u64 = 600_000;
pub const MAX_LEAK_INTERVAL_MINS: u64 = 30 * 24 * 60;

fn clamp_field(name: &str, v: u64, max: u64) -> u64 {
    if v > max {
        log::warn!("{name} = {v} 超出范围，按上限 {max} 处理");
        max
    } else {
        v
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("无法读取配置文件 {}", path.display()))?;
        Self::parse_lenient(&text).with_context(|| format!("配置文件 {} 有误", path.display()))
    }

    /// 启动时读取配置（界面和后台服务共用）。区分：
    ///
    /// - 配置文件和最近有效配置的副本都确实不存在：[`Loaded::Missing`]（首次启动，可以创建默认配置）；
    /// - 配置文件不存在、但副本还在（例如被误删）：用副本恢复（[`Loaded::LastGood`]），副本不能被默认配置覆盖；
    /// - 其他情况（包括无法判断文件是否存在的权限、I/O 错误）：见 [`Config::load_recovering`]。
    pub fn load_startup(path: &Path) -> Loaded {
        let exists = |p: &Path| !matches!(std::fs::symlink_metadata(p), Err(e) if e.kind() == std::io::ErrorKind::NotFound);
        if exists(path) {
            return Self::load_recovering(path);
        }
        if !exists(&last_good_path(path)) {
            return Loaded::Missing;
        }
        Self::from_last_good(path, format!("配置文件 {} 不存在", path.display()), None)
    }

    /// 读取配置文件；读取失败或内容有误时改用最近一次有效的配置（[`last_good_path`]），
    /// 无法解析的原文件另存为 [`broken_path`]。没有可用的最近有效配置时返回 `Err`（调用方决定怎么退回）。
    ///
    /// 成功读取后顺便更新最近有效配置。
    pub fn load_recovering(path: &Path) -> Loaded {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) => {
                // 读不了（权限、I/O 错误）：内容未必有问题，不另存，只尝试最近有效的配置
                let error = format!("无法读取配置文件 {}：{e}", path.display());
                return Self::from_last_good(path, error, None);
            }
        };
        match Self::parse_lenient(&text) {
            Ok(cfg) => {
                // 副本按校验后的配置重新生成（不是原文）：原文里写错、被忽略的一节可能带着令牌等凭据
                cfg.write_last_good(path);
                Loaded::Ok(cfg)
            }
            Err(e) => {
                let error = format!("配置文件 {} 有误：{e:#}", path.display());
                // 原文件可能含令牌等凭据：另存的副本一律只让所有者读写
                let broken = broken_path(path);
                let broken = match write_atomic(&broken, text.as_bytes(), Some(true)) {
                    Ok(()) => Some(broken),
                    Err(e) => {
                        log::warn!("无法另存损坏的配置文件: {e:#}");
                        None
                    }
                };
                Self::from_last_good(path, error, broken)
            }
        }
    }

    fn from_last_good(path: &Path, error: String, broken: Option<PathBuf>) -> Loaded {
        let good = last_good_path(path);
        match std::fs::read_to_string(&good).map_err(anyhow::Error::from).and_then(|t| Self::parse_lenient(&t)) {
            Ok(cfg) => {
                log::warn!("{error}；已改用最近一次有效的配置 {}", good.display());
                Loaded::LastGood { cfg, error, broken }
            }
            Err(e) => {
                log::debug!("没有可用的最近有效配置（{}）: {e:#}", good.display());
                Loaded::Failed { error, broken }
            }
        }
    }

    /// 配置里有凭据（GitHub 令牌、代理地址里的用户名密码）：文件只让所有者读写。
    pub fn has_secrets(&self) -> bool {
        !self.update.token.is_empty() || proxy_has_credentials(&self.detect.proxy)
    }

    /// 读取配置文件用：泄露测试、IPv6 查询服务、检查更新这几项与断网保护无关，写错时改用默认值并记日志，
    /// 不让整份配置失效（失效时后台服务会退回默认配置，可能把整个网络断掉）。
    ///
    /// 各节分别校验：只把写错的那一节改回默认值，其余各节（包括同样可容错的节）保留用户的设置。
    pub fn parse_lenient(text: &str) -> Result<Self> {
        let mut raw: RawConfig = parse_toml(text)?;
        let err = match Self::from_raw(raw.clone()) {
            Ok(c) => return Ok(c),
            Err(e) => e,
        };
        let d = RawConfig::default();
        let sections: [(&str, CopySection); 3] = [
            ("[leak_test]", |to, from| to.leak_test = from.leak_test.clone()),
            // 查询服务能不能为空取决于 IPv6 处理方式，一起放进去校验；改回默认值时只改服务
            ("[ipv6] services", |to, from| {
                to.ipv6.mode = from.ipv6.mode;
                to.ipv6.services = from.ipv6.services.clone();
            }),
            ("[update]", |to, from| to.update = from.update.clone()),
        ];
        let mut fixed = Vec::new();
        for (name, copy) in sections {
            // 只带这一节的默认配置：校验不过就是这一节写错了
            let mut probe = d.clone();
            copy(&mut probe, &raw);
            if let Err(e) = Self::from_raw(probe) {
                if name == "[ipv6] services" {
                    raw.ipv6.services = d.ipv6.services.clone();
                } else {
                    copy(&mut raw, &d);
                }
                fixed.push(format!("{name}（{e:#}）"));
            }
        }
        if fixed.is_empty() {
            return Err(err);
        }
        match Self::from_raw(raw) {
            Ok(c) => {
                log::warn!("配置有误，以下各项改用默认值，其余设置保留：{}", fixed.join("；"));
                Ok(c)
            }
            // 其他节（与保护有关的）也有错：报告最初的错误
            Err(_) => Err(err),
        }
    }

    pub fn parse(text: &str) -> Result<Self> {
        let raw: RawConfig = parse_toml(text)?;
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
        // 时间类设置的上限：过大的值换算或与时钟相加时会溢出。超出时取上限（不让保护相关的配置因此失效），
        // 0 表示关闭的项保持可用
        detect.interval_secs = clamp_field("[detect] interval_secs", detect.interval_secs, MAX_INTERVAL_SECS);
        detect.timeout_secs = clamp_field("[detect] timeout_secs", detect.timeout_secs, MAX_TIMEOUT_SECS);
        let mut behavior = raw.behavior;
        behavior.debounce_ms = clamp_field("[behavior] debounce_ms", behavior.debounce_ms, MAX_DEBOUNCE_MS);
        detect.services.retain(|s| !s.trim().is_empty());
        detect.proxy = detect.proxy.trim().to_owned();
        if !detect.proxy.is_empty() {
            if let Err(e) = ureq::Proxy::new(&detect.proxy) {
                bail!("检测代理地址有误（{}）: {}", redact_proxy(&detect.proxy), scrub_proxy(&e.to_string(), &detect.proxy));
            }
        }
        let mut leak_test = raw.leak_test;
        leak_test.interval_mins = clamp_field("[leak_test] interval_mins", leak_test.interval_mins, MAX_LEAK_INTERVAL_MINS);
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
        // 未知的检测源只忽略、不报错：检测源以后可能增删，不能因为这一项让整个配置（以及断网保护）失效
        let known = crate::leaktest::dns::all_source_names();
        let mut sources: Vec<String> = Vec::new();
        for s in &leak_test.dns_sources {
            let s = s.trim().to_ascii_lowercase();
            if s.is_empty() || sources.contains(&s) {
                continue;
            }
            if known.contains(&s) {
                sources.push(s);
            } else {
                log::warn!("忽略未知的 DNS 检测源: {s:?}（可用：{}）", known.join("、"));
            }
        }
        leak_test.dns_sources = sources;
        leak_test.stun_servers = leak_test.stun_servers.iter().map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()).collect();
        for s in &leak_test.stun_servers {
            crate::leaktest::stun::split_host_port(s).with_context(|| format!("STUN 服务器有误: {s:?}"))?;
        }
        let mut vpn = raw.vpn;
        let mut names: Vec<String> = Vec::new();
        for n in vpn.interfaces.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
            if !names.iter().any(|x| x.eq_ignore_ascii_case(n)) {
                names.push(n.to_owned());
            }
        }
        vpn.interfaces = names;
        vpn.check_interval_secs = clamp_field("[vpn] check_interval_secs", vpn.check_interval_secs, MAX_INTERVAL_SECS);
        let mut ipv6 = raw.ipv6;
        ipv6.services.retain(|s| !s.trim().is_empty());
        if ipv6.mode == Ipv6Mode::Check && ipv6.services.is_empty() {
            bail!("检测 IPv6 出口需要至少一个 IPv6 查询服务");
        }
        let mut update = raw.update;
        update.repo = update.repo.trim().trim_matches('/').to_owned();
        update.token = update.token.trim().to_owned();
        if update.check && !crate::update::valid_repo(&update.repo) {
            bail!("检查更新的仓库应为 owner/name 的形式: {:?}", update.repo);
        }
        Ok(Self {
            whitelist,
            apps: raw.apps,
            detect,
            behavior,
            ui: raw.ui,
            children: raw.children,
            block_all,
            leak_test,
            vpn,
            ipv6,
            update,
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
            vpn: self.vpn.clone(),
            ipv6: self.ipv6.clone(),
            update: self.update.clone(),
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
    ///
    /// 先在同一目录写临时文件再替换：写到一半中断时原配置保持完整。带 GitHub 令牌时临时文件一创建就只有
    /// 所有者能读写（Unix 0600；Windows 只给 SYSTEM、管理员组和所有者），令牌不会经过可读的窗口。
    pub fn save(&self, path: &Path) -> Result<()> {
        let text = self.to_text()?;
        let private = self.has_secrets();
        write_atomic(path, text.as_bytes(), Some(private).filter(|p| *p))?;
        // 刚保存的是校验过的配置：同时更新最近有效配置的副本（失败不影响保存本身）
        self.write_last_good(path);
        Ok(())
    }

    /// 保存时写入的文本。
    fn to_text(&self) -> Result<String> {
        Ok(format!(
            "# egress-guard 配置（由程序保存，说明见 config.example.toml）\n\n{}",
            toml::to_string_pretty(&self.to_raw())?
        ))
    }

    /// 更新最近有效配置的副本：按校验后的配置生成，一律只让所有者读写（Unix 0600，Windows 私有 ACL；
    /// 已有的宽权限副本被替换后同样收紧）。失败只记日志。
    fn write_last_good(&self, path: &Path) {
        let r = self.to_text().and_then(|t| write_atomic(&last_good_path(path), t.as_bytes(), Some(true)));
        if let Err(e) = r {
            log::warn!("无法更新最近有效配置的副本: {e:#}");
        }
    }

    /// 出口 IP 是否命中白名单。
    pub fn is_whitelisted(&self, ip: IpAddr) -> bool {
        let ip = normalize(ip);
        self.whitelist.iter().any(|net| net.contains(&ip))
    }
}

/// 解析 TOML。出错时的说明会带上出错的那几行原文，里面可能有令牌或代理密码，先遮掉。
fn parse_toml(text: &str) -> Result<RawConfig> {
    toml::from_str(text).map_err(|e| anyhow::anyhow!("{}", redact_text(&e.to_string())))
}

/// URL 中 `scheme://` 之后、主机之前的用户名密码部分（不含 `@`）的范围。
fn userinfo_range(url: &str, start: usize) -> Option<(usize, usize)> {
    let rest = &url[start..];
    let end = rest.find(['/', '?', '#', '"', '\'', ' ', '\t', '\n', '\r']).unwrap_or(rest.len());
    let at = rest[..end].rfind('@')?;
    Some((start, start + at))
}

/// 代理地址是否带用户名或密码。
pub fn proxy_has_credentials(proxy: &str) -> bool {
    let p = proxy.trim();
    let start = p.find("://").map_or(0, |i| i + 3);
    userinfo_range(p, start).is_some()
}

/// 把代理地址里的用户名和密码换成 `***`，用于显示、日志和错误信息。
pub fn redact_proxy(proxy: &str) -> String {
    let p = proxy.trim();
    let start = p.find("://").map_or(0, |i| i + 3);
    match userinfo_range(p, start) {
        Some((a, b)) => format!("{}***{}", &p[..a], &p[b..]),
        None => p.to_owned(),
    }
}

/// 遮掉文本里所有 URL 的用户名密码，以及 `token = ...` 这样的行（TOML 出错时的原文片段）。
pub fn redact_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(i) = rest.find("://") {
        let start = i + 3;
        match userinfo_range(rest, start) {
            Some((a, b)) => {
                out.push_str(&rest[..a]);
                out.push_str("***");
                rest = &rest[b..];
            }
            None => {
                out.push_str(&rest[..start]);
                rest = &rest[start..];
            }
        }
    }
    out.push_str(rest);
    out.lines()
        .map(|line| match line.find("token") {
            Some(i) if line[i..].contains('=') => {
                let eq = i + line[i..].find('=').unwrap_or(0);
                format!("{} ***", &line[..=eq])
            }
            _ => line.to_owned(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// 遮掉文本里出现的这个代理的用户名密码（包括第三方库只打印出密码、或解码后的形式）。
pub fn scrub_proxy(text: &str, proxy: &str) -> String {
    let mut out = redact_text(text);
    let p = proxy.trim();
    let start = p.find("://").map_or(0, |i| i + 3);
    let Some((a, b)) = userinfo_range(p, start) else { return out };
    let userinfo = &p[a..b];
    let password = userinfo.split_once(':').map(|(_, pw)| pw).unwrap_or("");
    let mut secrets = vec![userinfo.to_owned(), percent_decode(userinfo)];
    if !password.is_empty() {
        secrets.push(password.to_owned());
        secrets.push(percent_decode(password));
    }
    secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
    for s in secrets.iter().filter(|s| !s.is_empty()) {
        out = out.replace(s.as_str(), "***");
    }
    out
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// 原子地写入文件：在同一目录用 `create_new` 创建临时文件，写完并同步到磁盘后替换原文件。
/// 任何一步失败时删除临时文件，原文件保持不变。
///
/// `private = Some(true)`：只让所有者读写（Unix 上临时文件创建时就是 0600；Windows 上创建时就带受保护的 ACL）。
/// 否则 Unix 上沿用原文件的权限（显式设置，不受进程 umask 影响）；没有原文件时按 0644 创建，受 umask 约束。
pub fn write_atomic(path: &Path, data: &[u8], private: Option<bool>) -> Result<()> {
    use std::io::Write;
    let private = private.unwrap_or(false);
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into());
    // 原文件（普通文件）的权限：替换后保持不变
    #[cfg(unix)]
    let keep_mode = {
        use std::os::unix::fs::MetadataExt;
        std::fs::symlink_metadata(path).ok().filter(|m| m.is_file()).map(|m| m.mode() & 0o777)
    };
    let mut tmp = None;
    for i in 0..100u32 {
        let candidate = dir.join(format!(".{name}.tmp-{}-{i}", std::process::id()));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // 创建时最多给到原文件的权限（umask 只会再去掉一些），写入前再显式恢复成原文件的权限
            let mode = if private { 0o600 } else { keep_mode.unwrap_or(0o644) };
            opts.mode(mode);
        }
        // Windows：含凭据的文件在创建时就只给 SYSTEM、管理员组和所有者访问
        #[cfg(windows)]
        let opened = if private { create_new_private(&candidate) } else { opts.open(&candidate) };
        #[cfg(not(windows))]
        let opened = opts.open(&candidate);
        match opened {
            Ok(f) => {
                tmp = Some((candidate, f));
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(anyhow::Error::new(e).context(format!("无法写入 {}", path.display()))),
        }
    }
    let Some((tmp_path, mut f)) = tmp else { bail!("无法在 {} 创建临时文件", dir.display()) };
    let result = (|| -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if private {
                // umask 只会去掉权限，不会加；再确认一次
                f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
            } else if let Some(mode) = keep_mode {
                // 通过已打开的文件设置，不受 umask 影响：替换后与原文件相同
                f.set_permissions(std::fs::Permissions::from_mode(mode))?;
            }
        }
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    })();
    if let Err(e) = result {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e.context(format!("无法写入 {}", path.display())));
    }
    Ok(())
}

/// Windows：创建新文件，创建时就只让 SYSTEM、管理员组和文件所有者访问（不继承目录的权限）。
#[cfg(windows)]
fn create_new_private(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::io::FromRawHandle;
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
    };
    let to_io = |e: windows::core::Error| std::io::Error::from_raw_os_error(e.code().0 & 0xFFFF);
    let sddl = HSTRING::from("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)");
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(sddl.as_ptr()), 1, &mut sd, None).map_err(to_io)?;
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: false.into(),
        };
        let name = HSTRING::from(path.as_os_str());
        let h = CreateFileW(
            PCWSTR(name.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_READ,
            Some(&sa),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            None,
        );
        LocalFree(Some(HLOCAL(sd.0)));
        Ok(std::fs::File::from_raw_handle(h.map_err(to_io)?.0))
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

    #[test]
    fn proxy_credentials_are_redacted() {
        assert!(proxy_has_credentials("http://u:p@127.0.0.1:8080"));
        assert!(proxy_has_credentials("socks5://u@h:1"));
        assert!(proxy_has_credentials("u:p@h:1"));
        assert!(!proxy_has_credentials("http://127.0.0.1:8080"));
        assert!(!proxy_has_credentials("http://127.0.0.1:8080/a@b"));
        assert_eq!(redact_proxy("http://alice:pa@ss@127.0.0.1:8080"), "http://***@127.0.0.1:8080");
        assert_eq!(redact_proxy(" u:p@h:1 "), "***@h:1");
        assert_eq!(redact_proxy("http://127.0.0.1:8080"), "http://127.0.0.1:8080");
        let text = "connect http://alice:s3cret@proxy:1/x failed; also https://ok.example/a@b";
        assert_eq!(redact_text(text), "connect http://***@proxy:1/x failed; also https://ok.example/a@b");
        // 第三方库只打印密码或解码后的用户名密码
        let p = "http://alice:p%40ss@proxy:1";
        let msg = scrub_proxy("auth failed for alice:p@ss (p%40ss)", p);
        assert!(!msg.contains("p@ss") && !msg.contains("p%40ss"), "{msg}");
        assert_eq!(scrub_proxy("plain error", "http://proxy:1"), "plain error");
    }

    #[test]
    fn config_errors_hide_credentials() {
        // 代理地址写错时不回显密码
        let err = Config::parse(&format!("{SAMPLE}\n[detect]\nproxy=\"ftp://alice:s3cret@x\"")).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("ftp://***@x") && !msg.contains("s3cret"), "{msg}");
        // TOML 语法错误时的原文片段里不带令牌、代理密码
        for bad in ["[update]\ntoken = \"ghp_abcdef", "[detect]\nproxy = \"http://alice:s3cret@h:1\" x"] {
            let msg = format!("{:#}", Config::parse_lenient(&format!("{SAMPLE}\n{bad}")).unwrap_err());
            assert!(!msg.contains("ghp_abcdef") && !msg.contains("s3cret"), "{msg}");
        }
    }

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
        let cfg = Config::parse(&format!("{SAMPLE}\n[leak_test]\ndns_sources=[\"Fastly\", \"dnscheck\", \"fastly\", \"nope\"]")).unwrap();
        assert_eq!(cfg.leak_test.dns_sources, vec!["fastly", "dnscheck"]);
    }

    #[test]
    fn optional_sections_do_not_break_loading() {
        let text = "whitelist=[\"203.0.113.0/24\"]\n[leak_test]\nstun_servers=[\"stun.example.org\"]\n[update]\nrepo=\"bad repo\"";
        assert!(Config::parse(text).is_err());
        let c = Config::parse_lenient(text).unwrap();
        assert_eq!(c.whitelist.len(), 1);
        assert_eq!(c.leak_test.stun_servers, LeakTestConfig::default().stun_servers);
        assert_eq!(c.update.repo, UpdateConfig::default().repo);
        // 保护相关的错误仍然报错
        assert!(Config::parse_lenient("whitelist=[\"not-an-ip\"]").is_err());
    }

    #[test]
    fn lenient_repairs_only_the_broken_section() {
        // 只写错更新仓库：泄露测试和 IPv6 查询服务的自定义设置都保留
        let text = "whitelist=[\"203.0.113.0/24\"]\n[leak_test]\ntrusted_dns=[\"1.1.1.1\"]\nauto=true\n\
                    [ipv6]\nmode=\"check\"\nservices=[\"https://v6.example.org/\"]\n[update]\nrepo=\"bad repo\"";
        let c = Config::parse_lenient(text).unwrap();
        assert_eq!(c.leak_test.trusted_dns, vec!["1.1.1.1"]);
        assert!(c.leak_test.auto);
        assert_eq!(c.ipv6.mode, Ipv6Mode::Check);
        assert_eq!(c.ipv6.services, vec!["https://v6.example.org/"]);
        assert_eq!(c.update.repo, UpdateConfig::default().repo);

        // 两节分别写错：各自改回默认值，第三节保留
        let text = "whitelist=[\"203.0.113.0/24\"]\n[leak_test]\nstun_servers=[\"stun.example.org\"]\nauto=true\n\
                    [ipv6]\nmode=\"check\"\nservices=[\"https://v6.example.org/\"]\n[update]\nrepo=\"bad repo\"";
        let c = Config::parse_lenient(text).unwrap();
        assert_eq!(c.leak_test, LeakTestConfig::default());
        assert_eq!(c.ipv6.services, vec!["https://v6.example.org/"]);
        assert_eq!(c.update.repo, UpdateConfig::default().repo);

        // 检测 IPv6 出口却没有查询服务：只补上默认服务，处理方式保持「检测」
        let text = "whitelist=[\"203.0.113.0/24\"]\n[leak_test]\nauto=true\n[ipv6]\nmode=\"check\"\nservices=[]";
        let c = Config::parse_lenient(text).unwrap();
        assert_eq!(c.ipv6.mode, Ipv6Mode::Check);
        assert_eq!(c.ipv6.services, Ipv6Config::default().services);
        assert!(c.leak_test.auto);

        // 可容错的节之外也有错：整份配置报错（保护相关的设置不能悄悄改掉）
        let text = "whitelist=[\"not-an-ip\"]\n[update]\nrepo=\"bad repo\"";
        assert!(Config::parse_lenient(text).is_err());
        let text = "whitelist=[\"203.0.113.0/24\"]\napps=['relative.exe']\n[update]\nrepo=\"bad repo\"";
        assert!(Config::parse_lenient(text).is_err());
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("eg-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn broken_config_falls_back_to_last_good() {
        let dir = temp_dir("lastgood");
        let path = dir.join("config.toml");
        // 首次启动：没有任何文件
        assert!(matches!(Config::load_recovering(&path), Loaded::Failed { broken: None, .. }));

        // 保存过一次有效配置后，配置文件被写坏
        let mut cfg = Config::parse(SAMPLE).unwrap();
        cfg.block_all.enabled = true;
        cfg.save(&path).unwrap();
        assert!(last_good_path(&path).exists());
        let bad = "whitelist=[\"not-an-ip\"]\n# 用户写坏的文件\n";
        std::fs::write(&path, bad).unwrap();
        match Config::load_recovering(&path) {
            Loaded::LastGood { cfg: c, error, broken } => {
                assert_eq!(c.apps, cfg.apps);
                assert!(c.block_all.enabled);
                assert!(error.contains("有误"), "{error}");
                // 原文件另存一份，保存设置之后也能找回
                assert_eq!(std::fs::read_to_string(broken.unwrap()).unwrap(), bad);
            }
            other => panic!("{other:?}"),
        }

        // 读不了配置文件（这里用目录代替）：不另存，照样用最近有效的配置
        let odd = dir.join("dir.toml");
        std::fs::create_dir_all(&odd).unwrap();
        std::fs::copy(last_good_path(&path), last_good_path(&odd)).unwrap();
        assert!(matches!(Config::load_recovering(&odd), Loaded::LastGood { broken: None, .. }));

        // 没有最近有效配置时报告失败（调用方按平台的安全方式退回）
        std::fs::remove_file(last_good_path(&path)).unwrap();
        assert!(matches!(Config::load_recovering(&path), Loaded::Failed { broken: Some(_), .. }));

        // 正常读取会刷新最近有效配置（包括手工编辑的有效配置），内容按校验后的配置生成
        std::fs::write(&path, SAMPLE).unwrap();
        let Loaded::Ok(c) = Config::load_recovering(&path) else { panic!() };
        let good = std::fs::read_to_string(last_good_path(&path)).unwrap();
        assert_eq!(Config::parse(&good).unwrap().to_raw(), c.to_raw());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn upgraded_090_config_loads_and_records_last_good() {
        // 0.9.0 保存的配置：有 auto_after_change、interval_mins，没有 auto、ipv6、proxy
        let dir = temp_dir("upgrade");
        let path = dir.join("my config 配置.toml");
        let text = format!("{SAMPLE}\n[leak_test]\nauto_after_change=true\ninterval_mins=60\n[vpn]\nguard=true\n");
        std::fs::write(&path, &text).unwrap();
        let Loaded::Ok(c) = Config::load_recovering(&path) else { panic!() };
        assert_eq!(c.apps.len(), 1);
        assert!(!c.leak_test.auto);
        let good = std::fs::read_to_string(last_good_path(&path)).unwrap();
        assert_eq!(Config::parse(&good).unwrap().to_raw(), c.to_raw());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn huge_time_settings_are_clamped() {
        let text = format!(
            "{SAMPLE}\n[detect]\ninterval_secs={max}\ntimeout_secs={max}\n[behavior]\ndebounce_ms={max}\n\
             [vpn]\ncheck_interval_secs={max}\n[leak_test]\ninterval_mins={max}",
            max = u64::MAX
        );
        let c = Config::parse(&text).unwrap();
        assert_eq!(c.detect.interval_secs, MAX_INTERVAL_SECS);
        assert_eq!(c.detect.timeout_secs, MAX_TIMEOUT_SECS);
        assert_eq!(c.behavior.debounce_ms, MAX_DEBOUNCE_MS);
        assert_eq!(c.vpn.check_interval_secs, MAX_INTERVAL_SECS);
        assert_eq!(c.leak_test.interval_mins, MAX_LEAK_INTERVAL_MINS);
        // 上限换算成时刻也不会溢出
        let now = std::time::Instant::now();
        assert!(now.checked_add(std::time::Duration::from_secs(MAX_INTERVAL_SECS)).is_some());
        assert!(now.checked_add(std::time::Duration::from_secs(MAX_LEAK_INTERVAL_MINS * 60)).is_some());
        // 0 表示关闭的项保持可用
        let c = Config::parse(&format!("{SAMPLE}\n[vpn]\ncheck_interval_secs=0\n[leak_test]\ninterval_mins=0")).unwrap();
        assert_eq!((c.vpn.check_interval_secs, c.leak_test.interval_mins), (0, 0));
    }

    #[test]
    fn new_sections() {
        let cfg = Config::parse(SAMPLE).unwrap();
        assert!(cfg.vpn.guard && cfg.vpn.interfaces.is_empty());
        // 0.9.2 起默认始终阻断 IPv6
        assert_eq!(cfg.ipv6.mode, Ipv6Mode::Block);
        assert!(!cfg.ipv6.services.is_empty());
        assert!(cfg.update.check && cfg.update.repo == "RollingL/egress-guard");
        assert!(cfg.leak_test.auto_after_change && cfg.leak_test.notify);
        // 后台直连探测默认关闭，0.9.0 保存的配置（有 auto_after_change、interval_mins，没有 auto）升级后也关闭
        assert!(!cfg.leak_test.auto);
        let old = Config::parse(&format!("{SAMPLE}\n[leak_test]\nauto_after_change=true\ninterval_mins=60")).unwrap();
        assert!(!old.leak_test.auto);
        let cfg = Config::parse(&format!(
            "{SAMPLE}\n[vpn]\ninterfaces=[\" utun4 \", \"\"]\n[ipv6]\nmode=\"block\"\nservices=[]\n[update]\nrepo=\" a/b/ \""
        ))
        .unwrap();
        assert_eq!(cfg.vpn.interfaces, vec!["utun4"]);
        assert_eq!(cfg.ipv6.mode, Ipv6Mode::Block);
        assert_eq!(cfg.update.repo, "a/b");
        // 检测 IPv6 出口时必须有查询服务
        assert!(Config::parse(&format!("{SAMPLE}\n[ipv6]\nmode=\"check\"\nservices=[]")).is_err());
        // 检测代理：默认为空；填了就要能解析
        assert!(cfg.detect.proxy.is_empty());
        let c = Config::parse(&format!("{SAMPLE}\n[detect]\nproxy=\" http://127.0.0.1:7890 \"")).unwrap();
        assert_eq!(c.detect.proxy, "http://127.0.0.1:7890");
        assert!(Config::parse(&format!("{SAMPLE}\n[detect]\nproxy=\"socks5://127.0.0.1:7891\"")).is_ok());
        assert!(Config::parse(&format!("{SAMPLE}\n[detect]\nproxy=\"ftp://x\"")).is_err());
        assert!(Config::parse(&format!("{SAMPLE}\n[update]\nrepo=\"nope\"")).is_err());
        // 关闭检查更新时仓库可以留空
        assert!(Config::parse(&format!("{SAMPLE}\n[update]\ncheck=false\nrepo=\"\"")).is_ok());
    }

    #[test]
    fn save_is_atomic_and_private() {
        let dir = std::env::temp_dir().join(format!("eg-save-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        #[cfg_attr(not(unix), allow(unused_mut))]
        let mut cfg = Config::parse(SAMPLE).unwrap();
        cfg.save(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // 已有一份大家都能读的配置，第一次加入令牌
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            cfg.update.token = "ghp_secret".into();
            cfg.save(&path).unwrap();
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
            assert!(std::fs::read_to_string(&path).unwrap().contains("ghp_secret"));
            // 最近有效配置的副本同样只有所有者能读写
            assert_eq!(std::fs::metadata(last_good_path(&path)).unwrap().permissions().mode() & 0o777, 0o600);
            // 代理地址里带用户名密码时也一样
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            let mut with_proxy = cfg.clone();
            with_proxy.update.token.clear();
            with_proxy.detect.proxy = "http://user:pass@127.0.0.1:8080".into();
            with_proxy.save(&path).unwrap();
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
            // 没有令牌时沿用原来的权限
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
            cfg.update.token.clear();
            cfg.save(&path).unwrap();
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o640);
        }
        // 替换失败（目标是目录）时原文件不变，也不留临时文件
        let before = std::fs::read_to_string(&path).unwrap();
        let blocker = dir.join("blocker");
        std::fs::create_dir_all(blocker.join("x")).unwrap();
        assert!(cfg.save(&blocker).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 启动入口：首次启动、主文件丢失（副本还在）、损坏、读不了，分别处理；主文件丢失时不能用默认配置覆盖副本。
    #[test]
    fn startup_entry_distinguishes_first_run_and_recovery() {
        let dir = temp_dir("startup");
        let path = dir.join("config.toml");
        assert!(matches!(Config::load_startup(&path), Loaded::Missing));

        let mut cfg = Config::parse(SAMPLE).unwrap();
        cfg.block_all.enabled = true;
        cfg.save(&path).unwrap();
        let good = std::fs::read_to_string(last_good_path(&path)).unwrap();
        // 主文件被删：用副本恢复，而不是当作首次启动
        std::fs::remove_file(&path).unwrap();
        match Config::load_startup(&path) {
            Loaded::LastGood { cfg: c, error, broken: None } => {
                assert_eq!(c.to_raw(), cfg.to_raw());
                assert!(error.contains("不存在"), "{error}");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(std::fs::read_to_string(last_good_path(&path)).unwrap(), good, "副本不能被改动");
        // 主文件丢失、副本也坏了：报告失败，不当作首次启动（调用方不会创建默认配置覆盖它）
        std::fs::write(last_good_path(&path), "whitelist=[\"x\"]").unwrap();
        assert!(matches!(Config::load_startup(&path), Loaded::Failed { broken: None, .. }));
        std::fs::write(last_good_path(&path), &good).unwrap();
        // 主文件损坏：副本恢复，原文另存
        std::fs::write(&path, "apps = [").unwrap();
        assert!(matches!(Config::load_startup(&path), Loaded::LastGood { broken: Some(_), .. }));
        // 主文件读不了（这里用目录代替）
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir_all(&path).unwrap();
        assert!(matches!(Config::load_startup(&path), Loaded::LastGood { broken: None, .. }));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 最近有效配置的副本：按校验后的配置生成（写错而被忽略的一节里的令牌不会进副本），一律私有。
    #[test]
    fn last_good_copy_is_validated_and_private() {
        let dir = temp_dir("lastgood-private");
        let path = dir.join("config.toml");
        // [update] 写错（仓库格式不对）：整节改用默认值，令牌随之丢弃；它不能出现在副本里
        let text = format!("{SAMPLE}\n[update]\ncheck=true\nrepo=\"not a repo\"\ntoken=\"TEST-MARKER-123\"\n");
        std::fs::write(&path, &text).unwrap();
        let Loaded::Ok(c) = Config::load_recovering(&path) else { panic!() };
        assert!(c.update.token.is_empty());
        let good = std::fs::read_to_string(last_good_path(&path)).unwrap();
        assert!(!good.contains("TEST-MARKER-123"), "{good}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&last_good_path(&path)), 0o600);
            // 已有的宽权限副本在下一次刷新时收紧
            std::fs::set_permissions(last_good_path(&path), std::fs::Permissions::from_mode(0o644)).unwrap();
            std::fs::write(&path, SAMPLE).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(matches!(Config::load_recovering(&path), Loaded::Ok(_)));
            assert_eq!(mode(&last_good_path(&path)), 0o600);
            // 保存不带凭据的配置：主文件沿用原权限，副本仍然私有
            Config::parse(SAMPLE).unwrap().save(&path).unwrap();
            assert_eq!(mode(&path), 0o644);
            assert_eq!(mode(&last_good_path(&path)), 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn example_config_is_valid() {
        let text = include_str!("../config.example.toml");
        Config::parse(text).unwrap();
    }
}
