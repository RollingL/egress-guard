//! 检查新版本：读取 GitHub 仓库最新的发布版本（Release），与本程序的版本比较。
//!
//! 只读取、不下载：发现新版本后由界面提示，用户自己打开发布页下载。

use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use serde::Deserialize;

/// 本程序的版本。
pub const CURRENT: &str = env!("CARGO_PKG_VERSION");

/// 一个发布版本。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    /// 版本号（去掉开头的 v）。
    pub version: String,
    /// 发布页地址。
    pub url: String,
    /// 本平台的安装包下载地址（找不到时为 None）。
    pub download: Option<String>,
    /// 发布说明（Markdown，可能很长）。
    pub notes: String,
}

#[derive(Deserialize)]
struct ApiRelease {
    tag_name: String,
    html_url: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    assets: Vec<ApiAsset>,
}

#[derive(Deserialize)]
struct ApiAsset {
    name: String,
    browser_download_url: String,
}

/// 仓库名是否为 `owner/name` 的形式。
pub fn valid_repo(repo: &str) -> bool {
    let mut parts = repo.split('/');
    let ok = |s: Option<&str>| {
        s.is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)))
    };
    ok(parts.next()) && ok(parts.next()) && parts.next().is_none()
}

/// 把 "v0.9.1"、"0.10.0-beta.1" 解析成可比较的数字（预发布部分忽略）。
pub fn parse_version(s: &str) -> Option<(u64, u64, u64)> {
    let s = s.trim().trim_start_matches(['v', 'V']);
    let core = s.split(['-', '+']).next()?;
    let mut it = core.split('.').map(|x| x.parse::<u64>());
    let major = it.next()?.ok()?;
    let minor = it.next().unwrap_or(Ok(0)).ok()?;
    let patch = it.next().unwrap_or(Ok(0)).ok()?;
    Some((major, minor, patch))
}

/// `latest` 是否比 `current` 新。
pub fn is_newer(latest: &str, current: &str) -> bool {
    match (parse_version(latest), parse_version(current)) {
        (Some(a), Some(b)) => a > b,
        _ => false,
    }
}

/// 本平台安装包的名字里应该带的词。
fn platform_word() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(windows) {
        "windows"
    } else {
        "linux"
    }
}

fn parse_release(body: &str) -> Result<Release> {
    let r: ApiRelease = serde_json::from_str(body).map_err(|e| anyhow!("无法解析发布信息: {e}"))?;
    if r.draft || r.prerelease {
        bail!("最新的是草稿或预发布版本");
    }
    let version = r.tag_name.trim().trim_start_matches(['v', 'V']).to_owned();
    if parse_version(&version).is_none() {
        bail!("无法识别的版本号: {:?}", r.tag_name);
    }
    let word = platform_word();
    let download = r
        .assets
        .iter()
        .find(|a| a.name.to_ascii_lowercase().contains(word))
        .map(|a| a.browser_download_url.clone());
    Ok(Release { version, url: r.html_url, download, notes: r.body.unwrap_or_default() })
}

/// 查询仓库最新的正式发布版本。
pub fn fetch_latest(repo: &str, token: &str, timeout: Duration) -> Result<Release> {
    use ureq::tls::{TlsConfig, TlsProvider};
    if !valid_repo(repo) {
        bail!("仓库应为 owner/name 的形式: {repo:?}");
    }
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .tls_config(TlsConfig::builder().provider(TlsProvider::NativeTls).build())
        .timeout_global(Some(timeout))
        .http_status_as_error(false)
        .user_agent(concat!("egress-guard/", env!("CARGO_PKG_VERSION")))
        .build()
        .into();
    let mut req = agent
        .get(&format!("https://api.github.com/repos/{repo}/releases/latest"))
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28");
    if !token.is_empty() {
        req = req.header("Authorization", &format!("Bearer {token}"));
    }
    let mut resp = req.call()?;
    let status = resp.status().as_u16();
    let body = resp.body_mut().with_config().limit(1 << 20).read_to_string()?;
    match status {
        200 => parse_release(&body),
        404 if token.is_empty() => bail!("找不到发布版本：仓库还没有发布过版本，或者是私有仓库（私有仓库需要填写访问令牌）"),
        404 => bail!("找不到发布版本：仓库还没有发布过版本，或者令牌没有这个仓库的读取权限"),
        401 => bail!("访问令牌无效或已过期"),
        403 | 429 => bail!("GitHub 拒绝了请求（可能是访问太频繁），稍后再试"),
        s => bail!("GitHub 返回 HTTP {s}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(parse_version("v0.9.1"), Some((0, 9, 1)));
        assert_eq!(parse_version("1.2"), Some((1, 2, 0)));
        assert_eq!(parse_version("0.10.0-beta.1"), Some((0, 10, 0)));
        assert_eq!(parse_version("latest"), None);
        assert!(is_newer("v0.10.0", "0.9.9"));
        assert!(!is_newer("0.9.0", "0.9.0"));
        assert!(!is_newer("0.8.5", "0.9.0"));
        assert!(!is_newer("garbage", "0.9.0"));
    }

    #[test]
    fn repos() {
        assert!(valid_repo("RollingL/egress-guard"));
        assert!(valid_repo("a.b/c_d"));
        assert!(!valid_repo("nope"));
        assert!(!valid_repo("a/b/c"));
        assert!(!valid_repo("a/"));
        assert!(!valid_repo("a b/c"));
    }

    #[test]
    fn release_json() {
        let body = r#"{"tag_name":"v0.9.2","html_url":"https://github.com/o/r/releases/tag/v0.9.2","body":"说明",
            "draft":false,"prerelease":false,"assets":[
              {"name":"egress-guard-v0.9.2-windows.zip","browser_download_url":"https://x/w.zip"},
              {"name":"egress-guard-v0.9.2-macos.zip","browser_download_url":"https://x/m.zip"}]}"#;
        let r = parse_release(body).unwrap();
        assert_eq!(r.version, "0.9.2");
        assert_eq!(r.notes, "说明");
        if cfg!(windows) {
            assert_eq!(r.download.as_deref(), Some("https://x/w.zip"));
        } else if cfg!(target_os = "macos") {
            assert_eq!(r.download.as_deref(), Some("https://x/m.zip"));
        }
        assert!(parse_release(r#"{"tag_name":"v1.0.0","html_url":"u","prerelease":true}"#).is_err());
        assert!(parse_release(r#"{"tag_name":"nightly","html_url":"u"}"#).is_err());
    }
}
