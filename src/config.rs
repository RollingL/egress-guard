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

/// 把一节配置改回默认值。
type Repair = fn(&mut RawConfig, &RawConfig);

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("无法读取配置文件 {}", path.display()))?;
        Self::parse_lenient(&text).with_context(|| format!("配置文件 {} 有误", path.display()))
    }

    /// 读取配置文件用：泄露测试、IPv6 查询服务、检查更新这几项与断网保护无关，写错时改用默认值并记日志，
    /// 不让整份配置失效（失效时后台服务会退回默认配置，可能把整个网络断掉）。
    pub fn parse_lenient(text: &str) -> Result<Self> {
        let mut raw: RawConfig = toml::from_str(text)?;
        let err = match Self::from_raw(raw.clone()) {
            Ok(c) => return Ok(c),
            Err(e) => e,
        };
        let d = RawConfig::default();
        let repairs: [(&str, Repair); 3] = [
            ("[leak_test]", |r, d| r.leak_test = d.leak_test.clone()),
            ("[ipv6] services", |r, d| r.ipv6.services = d.ipv6.services.clone()),
            ("[update]", |r, d| r.update = d.update.clone()),
        ];
        let mut fixed = Vec::new();
        for (name, repair) in repairs {
            repair(&mut raw, &d);
            fixed.push(name);
            if let Ok(c) = Self::from_raw(raw.clone()) {
                log::warn!("配置有误（{err:#}）：{} 改用默认值", fixed.join("、"));
                return Ok(c);
            }
        }
        Err(err)
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
        detect.proxy = detect.proxy.trim().to_owned();
        if !detect.proxy.is_empty() {
            ureq::Proxy::new(&detect.proxy).with_context(|| format!("检测代理地址有误: {:?}", detect.proxy))?;
        }
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
            behavior: raw.behavior,
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
        let text = format!(
            "# egress-guard 配置（由程序保存，说明见 config.example.toml）\n\n{}",
            toml::to_string_pretty(&self.to_raw())?
        );
        let private = !self.update.token.is_empty();
        write_atomic(path, text.as_bytes(), Some(private).filter(|p| *p))
    }

    /// 出口 IP 是否命中白名单。
    pub fn is_whitelisted(&self, ip: IpAddr) -> bool {
        let ip = normalize(ip);
        self.whitelist.iter().any(|net| net.contains(&ip))
    }
}

/// 原子地写入文件：在同一目录用 `create_new` 创建临时文件，写完并同步到磁盘后替换原文件。
/// 任何一步失败时删除临时文件，原文件保持不变。
///
/// `private = Some(true)`：只让所有者读写（Unix 上临时文件创建时就是 0600；Windows 上设置受保护的 ACL）。
/// 否则 Unix 上沿用原文件的权限（没有原文件时为 0644）。
pub fn write_atomic(path: &Path, data: &[u8], private: Option<bool>) -> Result<()> {
    use std::io::Write;
    let private = private.unwrap_or(false);
    let dir = path.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into());
    let mut tmp = None;
    for i in 0..100u32 {
        let candidate = dir.join(format!(".{name}.tmp-{}-{i}", std::process::id()));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
            let mode = if private {
                0o600
            } else {
                std::fs::metadata(path).map(|m| m.mode() & 0o777).unwrap_or(0o644)
            };
            opts.mode(mode);
        }
        match opts.open(&candidate) {
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
        if private {
            // umask 只会去掉权限，不会加；再确认一次
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        #[cfg(windows)]
        if private {
            restrict_acl(&tmp_path)?;
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

/// Windows：只让 SYSTEM、管理员组和文件所有者访问（不继承目录的权限）。
#[cfg(windows)]
fn restrict_acl(path: &Path) -> Result<()> {
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
    use windows::Win32::Security::{
        SetFileSecurityW, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };
    let sddl = HSTRING::from("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)");
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(sddl.as_ptr()), 1, &mut sd, None)
            .context("无法生成文件权限")?;
        let file = HSTRING::from(path.as_os_str());
        let ok = SetFileSecurityW(
            PCWSTR(file.as_ptr()),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            sd,
        );
        let err = std::io::Error::last_os_error();
        LocalFree(Some(HLOCAL(sd.0)));
        if !ok.as_bool() {
            bail!("无法设置 {} 的权限: {err}", path.display());
        }
    }
    Ok(())
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

    #[test]
    fn example_config_is_valid() {
        let text = include_str!("../config.example.toml");
        Config::parse(text).unwrap();
    }
}
