//! 开机（登录）自启：用任务计划程序以最高权限启动界面程序，避免每次弹出 UAC。
//!
//! 任务记录程序和配置文件的绝对路径；schtasks 用系统目录里的那份；
//! 任务定义写在创建时就只有 SYSTEM 和管理员组能访问的唯一临时文件里。

use std::ffi::c_void;
use std::fs::File;
use std::io::Write;
use std::os::windows::io::FromRawHandle;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use windows::core::{HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
};
use windows::Win32::Security::{
    GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_READ};
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub const TASK_NAME: &str = "egress-guard";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// 系统目录里的 schtasks.exe（不依赖 PATH 和当前目录）
fn schtasks() -> Result<Command> {
    let mut buf = [0u16; 520];
    let n = unsafe { GetSystemDirectoryW(Some(&mut buf)) } as usize;
    if n == 0 || n >= buf.len() {
        bail!("无法确定系统目录");
    }
    let exe = PathBuf::from(String::from_utf16_lossy(&buf[..n])).join("schtasks.exe");
    let mut c = Command::new(exe);
    c.creation_flags(CREATE_NO_WINDOW);
    Ok(c)
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn is_enabled() -> bool {
    schtasks()
        .and_then(|mut c| Ok(c.args(["/Query", "/TN", TASK_NAME]).output()?))
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// 某个 SID 的字符串形式
unsafe fn sid_string(sid: PSID) -> Result<String> {
    let mut s = PWSTR::null();
    unsafe {
        ConvertSidToStringSidW(sid, &mut s).context("无法读取账户 SID")?;
        let out = s.to_string().unwrap_or_default();
        LocalFree(Some(HLOCAL(s.0 as *mut c_void)));
        Ok(out)
    }
}

/// 当前进程的账户 SID（不读环境变量）
fn current_user_sid() -> Result<String> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).context("无法读取当前账户")?;
        let mut len = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
        let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
        let r = GetTokenInformation(token, TokenUser, Some(buf.as_mut_ptr().cast()), len, &mut len);
        let _ = CloseHandle(token);
        r.context("无法读取当前账户")?;
        let tu = &*(buf.as_ptr() as *const TOKEN_USER);
        sid_string(tu.User.Sid)
    }
}

/// 在临时目录里创建只有 SYSTEM 和管理员组能访问的唯一临时文件（创建时就带权限，其他进程改不了）。
fn create_private_file(dir: &Path) -> Result<(PathBuf, File)> {
    let sddl = HSTRING::from("D:P(A;;FA;;;SY)(A;;FA;;;BA)");
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(sddl.as_ptr()), 1, &mut sd, None)
            .context("无法生成文件权限")?;
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: false.into(),
    };
    let mut result = Err(anyhow::anyhow!("无法在 {} 创建临时任务文件", dir.display()));
    for i in 0..100u32 {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.subsec_nanos());
        let path = dir.join(format!("egress-guard-task-{}-{nanos}-{i}.xml", std::process::id()));
        let name = HSTRING::from(path.as_os_str());
        let h = unsafe {
            CreateFileW(
                PCWSTR(name.as_ptr()),
                FILE_GENERIC_WRITE.0,
                FILE_SHARE_READ,
                Some(&sa),
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        };
        match h {
            Ok(h) => {
                result = Ok((path, unsafe { File::from_raw_handle(h.0) }));
                break;
            }
            Err(e) if e.code() == windows::Win32::Foundation::ERROR_FILE_EXISTS.to_hresult() => continue,
            Err(e) => {
                result = Err(anyhow::Error::new(e).context(format!("无法在 {} 创建临时任务文件", dir.display())));
                break;
            }
        }
    }
    unsafe {
        LocalFree(Some(HLOCAL(sd.0)));
    }
    result
}

/// 命令行参数里的一个路径（Windows 路径不会含双引号，也不会以反斜杠结尾的文件名）
fn quote_arg(p: &Path) -> String {
    format!("\"{}\"", p.display())
}

/// 注册登录时启动的计划任务（不限运行时长、使用电池时也运行）。`config` 写入任务参数，登录后加载同一份配置。
pub fn enable(exe: &Path, config: &Path) -> Result<()> {
    let exe = std::path::absolute(exe).context("无法确定程序路径")?;
    let dir = exe.parent().context("无法确定程序目录")?.to_path_buf();
    let config = std::path::absolute(config).context("无法确定配置文件路径")?;
    let user = current_user_sid()?;
    let args = format!("--minimized --config {}", quote_arg(&config));
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>egress-guard：按出口 IP 控制应用联网</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{user}</UserId></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><UserId>{user}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author"><Exec><Command>{exe}</Command><Arguments>{args}</Arguments><WorkingDirectory>{dir}</WorkingDirectory></Exec></Actions>
</Task>
"#,
        user = xml_escape(&user),
        exe = xml_escape(&exe.to_string_lossy()),
        args = xml_escape(&args),
        dir = xml_escape(&dir.to_string_lossy()),
    );

    // 任务计划程序要求 XML 为 UTF-16（带 BOM）
    let mut bytes = vec![0xFF, 0xFE];
    for u in xml.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    let (path, mut f) = create_private_file(&std::env::temp_dir())?;
    let result = (|| -> Result<()> {
        f.write_all(&bytes).context("无法写入临时任务文件")?;
        drop(f);
        let out = schtasks()?
            .args(["/Create", "/F", "/TN", TASK_NAME, "/XML"])
            .arg(&path)
            .output()
            .context("无法运行 schtasks")?;
        if !out.status.success() {
            bail!("创建计划任务失败: {}", decode(&out.stderr));
        }
        Ok(())
    })();
    let _ = std::fs::remove_file(&path);
    result
}

pub fn disable() -> Result<()> {
    let out = schtasks()?
        .args(["/Delete", "/F", "/TN", TASK_NAME])
        .output()
        .context("无法运行 schtasks")?;
    if !out.status.success() {
        bail!("删除计划任务失败: {}", decode(&out.stderr));
    }
    Ok(())
}

fn contains(hay: &[u8], needle: &str) -> bool {
    let utf16: Vec<u8> = needle.encode_utf16().flat_map(u16::to_le_bytes).collect();
    hay.windows(needle.len()).any(|w| w == needle.as_bytes()) || hay.windows(utf16.len()).any(|w| w == utf16)
}

/// 旧版本注册的任务没有记录配置路径：启动时发现这种任务就重新注册一次，登录后加载同一份配置。
pub fn upgrade_legacy(config: &Path) {
    let Ok(out) = schtasks().and_then(|mut c| Ok(c.args(["/Query", "/TN", TASK_NAME, "/XML", "ONE"]).output()?))
    else {
        return;
    };
    if !out.status.success() || contains(&out.stdout, "--config") {
        return;
    }
    let result = std::env::current_exe().context("无法确定程序路径").and_then(|exe| enable(&exe, config));
    match result {
        Ok(()) => log::info!("已更新开机自启任务（记录配置文件路径）"),
        Err(e) => log::warn!("旧版本创建的开机自启任务没能更新：{e:#}"),
    }
}

/// schtasks 输出使用系统代码页（中文系统为 GBK），这里尽力解码。
fn decode(b: &[u8]) -> String {
    match String::from_utf8(b.to_vec()) {
        Ok(s) => s.trim().to_owned(),
        Err(_) => format!("（输出无法解码，{} 字节）", b.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_temp_file_is_unique() {
        let dir = std::env::temp_dir();
        let (a, fa) = create_private_file(&dir).unwrap();
        let (b, fb) = create_private_file(&dir).unwrap();
        drop((fa, fb));
        assert_ne!(a, b);
        let _ = std::fs::remove_file(a);
        let _ = std::fs::remove_file(b);
    }

    #[test]
    fn finds_ascii_and_utf16() {
        assert!(contains(b"<Arguments>--minimized --config x</Arguments>", "--config"));
        let utf16: Vec<u8> = "a --config b".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert!(contains(&utf16, "--config"));
        assert!(!contains(b"--minimized", "--config"));
    }
}
