//! 系统通知：自动泄露测试发现泄露、发现新版本时提醒用户（窗口通常隐藏在托盘 / 菜单栏里）。
//!
//! - Windows：Toast 通知。程序没有安装包，先在 `HKCU\Software\Classes\AppUserModelId` 下登记
//!   一个应用 ID（显示名称和图标），再以这个 ID 发通知；失败时改用 PowerShell 的应用 ID 再试一次。
//! - macOS：UserNotifications（第一次会请求权限）；不可用或被拒绝时改用 `osascript` 的 `display notification`。
//! - 其他平台：`notify-send`（有的话）。
//!
//! 通知在调用线程里同步发出，请在后台线程调用。

/// 发一条通知；失败只记日志。
pub fn show(title: &str, body: &str) {
    log::info!("系统通知：{title}：{body}");
    if let Err(e) = try_show(title, body) {
        log::warn!("无法发送系统通知: {e:#}");
    }
}

/// 发一条通知，返回实际使用的方式（自检用）。
pub fn try_show(title: &str, body: &str) -> anyhow::Result<&'static str> {
    imp::show(title, body)
}

#[cfg(windows)]
mod imp {
    use anyhow::{Context, Result};
    use windows::core::{HSTRING, PCWSTR};
    use windows::Data::Xml::Dom::XmlDocument;
    use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_CURRENT_USER, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ,
    };

    const AUMID: &str = "EgressGuard.App";
    /// 应用 ID 登记失败时借用 PowerShell 的（通知上会显示 Windows PowerShell）。
    const FALLBACK_AUMID: &str = r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe";

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// 通知图标：把程序图标写到 %LOCALAPPDATA%\EgressGuard\notify.ico。
    fn icon_path() -> Option<String> {
        let dir = std::path::PathBuf::from(std::env::var_os("LOCALAPPDATA")?).join("EgressGuard");
        std::fs::create_dir_all(&dir).ok()?;
        let path = dir.join("notify.ico");
        let bytes = include_bytes!("../../assets/icon.ico");
        if std::fs::read(&path).ok().as_deref() != Some(&bytes[..]) {
            std::fs::write(&path, bytes).ok()?;
        }
        Some(path.display().to_string())
    }

    fn set_value(key: HKEY, name: &str, value: &str) -> Result<()> {
        let name = wide(name);
        let data = wide(value);
        // SAFETY: data 是以 0 结尾的 UTF-16 字符串，按字节传入
        let bytes = unsafe { std::slice::from_raw_parts(data.as_ptr() as *const u8, data.len() * 2) };
        unsafe { RegSetValueExW(key, PCWSTR(name.as_ptr()), None, REG_SZ, Some(bytes)) }.ok().context("RegSetValueExW")
    }

    /// 登记应用 ID（每次启动写一次，图标路径可能变化）。
    fn register() -> Result<()> {
        let sub = wide(&format!(r"Software\Classes\AppUserModelId\{AUMID}"));
        let mut key = HKEY::default();
        unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(sub.as_ptr()),
                None,
                PCWSTR::null(),
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                None,
                &mut key,
                None,
            )
        }
        .ok()
        .context("RegCreateKeyExW")?;
        let r = set_value(key, "DisplayName", "Egress Guard").and_then(|_| match icon_path() {
            Some(p) => set_value(key, "IconUri", &p),
            None => Ok(()),
        });
        unsafe {
            let _ = RegCloseKey(key);
        }
        r
    }

    fn escape(s: &str) -> String {
        s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
    }

    fn toast(aumid: &str, title: &str, body: &str) -> Result<()> {
        let xml = XmlDocument::new()?;
        xml.LoadXml(&HSTRING::from(format!(
            r#"<toast><visual><binding template="ToastGeneric"><text>{}</text><text>{}</text></binding></visual></toast>"#,
            escape(title),
            escape(body)
        )))?;
        let n = ToastNotification::CreateToastNotification(&xml)?;
        ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(aumid))?.Show(&n)?;
        Ok(())
    }

    pub fn show(title: &str, body: &str) -> Result<&'static str> {
        static REGISTERED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        let ok = *REGISTERED.get_or_init(|| match register() {
            Ok(()) => true,
            Err(e) => {
                log::warn!("无法登记通知用的应用 ID: {e:#}");
                false
            }
        });
        if ok {
            match toast(AUMID, title, body) {
                Ok(()) => return Ok("Toast（应用 ID EgressGuard.App）"),
                Err(e) => log::warn!("发送通知失败，改用 PowerShell 的应用 ID: {e:#}"),
            }
        }
        toast(FALLBACK_AUMID, title, body).map(|_| "Toast（借用 PowerShell 的应用 ID）")
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use anyhow::{bail, Result};

    #[cfg(eg_netext)]
    extern "C" {
        /// 1 = 已发送，0 = 没有权限或失败，-1 = 等待用户授权超时（之后系统仍会发送）。
        fn eg_notify(title: *const std::ffi::c_char, body: *const std::ffi::c_char) -> i32;
    }

    fn osascript(title: &str, body: &str) -> Result<()> {
        let q = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
        let script = format!("display notification \"{}\" with title \"Egress Guard\" subtitle \"{}\"", q(body), q(title));
        let st = std::process::Command::new("/usr/bin/osascript").arg("-e").arg(script).status()?;
        if !st.success() {
            bail!("osascript 退出码 {st}");
        }
        Ok(())
    }

    pub fn show(title: &str, body: &str) -> Result<&'static str> {
        #[cfg(eg_netext)]
        {
            let t = std::ffi::CString::new(title.replace('\0', "")).unwrap_or_default();
            let b = std::ffi::CString::new(body.replace('\0', "")).unwrap_or_default();
            match unsafe { eg_notify(t.as_ptr(), b.as_ptr()) } {
                1 => return Ok("UserNotifications"),
                -1 => return Ok("UserNotifications（等待用户授权）"),
                _ => log::info!("UserNotifications 不可用（未授权或未签名），改用 osascript"),
            }
        }
        osascript(title, body).map(|_| "osascript")
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
mod imp {
    use anyhow::Result;

    pub fn show(title: &str, body: &str) -> Result<&'static str> {
        // 开发用：有 notify-send 就用，没有也不算错误
        let _ = std::process::Command::new("notify-send").arg(title).arg(body).status();
        Ok("notify-send")
    }
}
