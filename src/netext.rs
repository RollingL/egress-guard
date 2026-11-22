//! macOS 网络扩展（按应用断网）的安装与开关，界面使用。
//!
//! 实际工作由 `macos/Bridge/NetExtBridge.swift` 完成（build.rs 把它编译成静态库链接进来，并设置 `eg_netext`）。
//! 操作都是异步的：调用后界面定时读取 [`state`]。
//!
//! 其他平台（以及设置了 `EGRESS_GUARD_NO_NETEXT` 编译的 macOS）没有网络扩展，[`supported`] 返回 false。
//! 开发时可以设置环境变量 `EG_PREVIEW_NETEXT=unsigned|ready|approval|enabled` 在任何平台上预览界面。

use serde::Deserialize;

/// Swift 一侧报告的状态（字段与 `BridgeState` 对应，JSON 用 snake_case）。
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct State {
    /// 主程序签名的团队 ID；未签名（ad-hoc）时为 None。
    pub team_id: Option<String>,
    /// .app 包里是否带着网络扩展。
    pub bundled: bool,
    /// idle / activating / needs_approval / activated / reboot_required / deactivating / deactivated / error
    pub phase: String,
    pub error: Option<String>,
    pub ext_enabled: Option<bool>,
    pub ext_awaiting_approval: Option<bool>,
    pub ext_version: Option<String>,
    pub filter_configured: bool,
    pub filter_enabled: bool,
    pub filter_error: Option<String>,
    /// 已经查询过一次系统状态。
    pub loaded: bool,
}

impl State {
    pub fn signed(&self) -> bool {
        self.team_id.as_deref().is_some_and(|t| !t.is_empty())
    }

    /// 正在等待系统或用户（显示转圈）。
    pub fn busy(&self) -> bool {
        matches!(self.phase.as_str(), "activating" | "deactivating")
    }

    /// 等待用户在「系统设置 → 隐私与安全性」里允许。
    pub fn awaiting_approval(&self) -> bool {
        self.phase == "needs_approval" || (self.phase == "idle" && self.ext_awaiting_approval == Some(true))
    }

    /// 最近一次操作的错误（系统扩展或内容过滤）。
    pub fn last_error(&self) -> Option<&str> {
        if self.phase == "error" {
            self.error.as_deref()
        } else {
            self.filter_error.as_deref()
        }
    }
}

#[cfg(eg_netext)]
mod imp {
    use std::ffi::{c_char, CStr};

    extern "C" {
        fn eg_netext_state_json() -> *mut c_char;
        fn eg_netext_activate();
        fn eg_netext_deactivate();
        fn eg_netext_refresh();
        fn eg_netext_set_filter(on: bool);
        fn eg_netext_selftest(seconds: f64);
    }

    pub fn supported() -> bool {
        true
    }

    pub fn state() -> super::State {
        unsafe {
            let p = eg_netext_state_json();
            if p.is_null() {
                return Default::default();
            }
            let text = CStr::from_ptr(p).to_string_lossy().into_owned();
            libc::free(p.cast());
            serde_json::from_str(&text).unwrap_or_default()
        }
    }

    pub fn activate() {
        unsafe { eg_netext_activate() }
    }

    pub fn deactivate() {
        unsafe { eg_netext_deactivate() }
    }

    pub fn refresh() {
        unsafe { eg_netext_refresh() }
    }

    pub fn set_filter(on: bool) {
        unsafe { eg_netext_set_filter(on) }
    }

    /// CI 自检：查询状态并尝试安装扩展，运行主线程的 run loop `seconds` 秒后打印状态（JSON）。必须在主线程调用。
    pub fn selftest(seconds: f64) {
        unsafe { eg_netext_selftest(seconds) }
    }
}

#[cfg(not(eg_netext))]
mod imp {
    use super::State;

    fn preview() -> Option<String> {
        std::env::var("EG_PREVIEW_NETEXT").ok().filter(|s| !s.is_empty())
    }

    pub fn supported() -> bool {
        preview().is_some()
    }

    pub fn state() -> State {
        let base = State { bundled: true, phase: "idle".into(), loaded: true, ..Default::default() };
        let signed = State { team_id: Some("ABCDE12345".into()), ..base.clone() };
        match preview().as_deref() {
            Some("unsigned") => base,
            Some("ready") => signed,
            Some("approval") => State { phase: "needs_approval".into(), ..signed },
            Some("enabled") => State {
                phase: "activated".into(),
                ext_enabled: Some(true),
                ext_version: Some(env!("CARGO_PKG_VERSION").into()),
                filter_configured: true,
                filter_enabled: true,
                ..signed
            },
            _ => State::default(),
        }
    }

    pub fn activate() {}
    pub fn deactivate() {}
    pub fn refresh() {}
    pub fn set_filter(_on: bool) {}
    pub fn selftest(_seconds: f64) {
        println!("{{}}");
    }
}

pub use imp::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bridge_json() {
        let s: State = serde_json::from_str(
            r#"{"team_id":"ABCDE12345","bundled":true,"phase":"error","error":"缺少权限","filter_configured":false,"filter_enabled":false,"loaded":true}"#,
        )
        .unwrap();
        assert!(s.signed() && s.bundled && s.loaded);
        assert_eq!(s.last_error(), Some("缺少权限"));
        let s: State = serde_json::from_str(r#"{"phase":"idle","ext_awaiting_approval":true}"#).unwrap();
        assert!(!s.signed() && s.awaiting_approval());
    }
}
