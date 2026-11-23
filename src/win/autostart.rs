//! 开机（登录）自启：用任务计划程序以最高权限启动界面程序，避免每次弹出 UAC。
//!
//! 任务记录程序和配置文件的绝对路径。任务定义通过任务计划程序的 COM 接口直接从内存提交，
//! 不经过临时文件：其他进程没有机会在注册前替换要注册的内容。查询、删除仍用系统目录里的 schtasks。

use std::ffi::c_void;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Context, Result};
use windows::core::{BSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{GetTokenInformation, TokenUser, PSID, TOKEN_QUERY, TOKEN_USER};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows::Win32::System::TaskScheduler::{
    ITaskFolder, ITaskService, TaskScheduler, TASK_CREATE_OR_UPDATE, TASK_LOGON_INTERACTIVE_TOKEN,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::System::Variant::VARIANT;

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
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .context("无法读取当前账户")?;
        let mut len = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
        let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
        let r = GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr().cast()),
            len,
            &mut len,
        );
        let _ = CloseHandle(token);
        r.context("无法读取当前账户")?;
        let tu = &*(buf.as_ptr() as *const TOKEN_USER);
        sid_string(tu.User.Sid)
    }
}

/// 命令行参数里的一个路径（Windows 路径不会含双引号，也不会以反斜杠结尾的文件名）
fn quote_arg(p: &Path) -> String {
    format!("\"{}\"", p.display())
}

/// 注册登录时启动的计划任务（不限运行时长、使用电池时也运行）。`config` 写入任务参数，登录后加载同一份配置。
pub fn enable(exe: &Path, config: &Path) -> Result<()> {
    enable_named(TASK_NAME, exe, config)
}

fn enable_named(name: &str, exe: &Path, config: &Path) -> Result<()> {
    let exe = std::path::absolute(exe).context("无法确定程序路径")?;
    let dir = exe.parent().context("无法确定程序目录")?.to_path_buf();
    let config = std::path::absolute(config).context("无法确定配置文件路径")?;
    let user = current_user_sid()?;
    let args = format!("--minimized --config {}", quote_arg(&config));
    let xml = task_xml(&user, &exe, &args, &dir);
    with_tasks(|folder| unsafe {
        let empty = VARIANT::default();
        folder
            .RegisterTask(
                &BSTR::from(name),
                &BSTR::from(xml.as_str()),
                TASK_CREATE_OR_UPDATE.0,
                &empty,
                &empty,
                TASK_LOGON_INTERACTIVE_TOKEN,
                &empty,
            )
            .map(|_| ())
            .map_err(|e| anyhow!("创建计划任务失败：{e}"))
    })
}

/// 任务定义（XML）。
fn task_xml(user: &str, exe: &Path, args: &str, dir: &Path) -> String {
    format!(
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
        user = xml_escape(user),
        exe = xml_escape(&exe.to_string_lossy()),
        args = xml_escape(args),
        dir = xml_escape(&dir.to_string_lossy()),
    )
}

/// 在独立线程里初始化 COM、连接本机任务计划程序，对根目录执行 `f`。
/// 独立线程避免与界面线程已有的 COM 套间设置冲突。
fn with_tasks<T: Send>(f: impl FnOnce(&ITaskFolder) -> Result<T> + Send) -> Result<T> {
    std::thread::scope(|s| {
        s.spawn(move || unsafe {
            CoInitializeEx(None, COINIT_MULTITHREADED)
                .ok()
                .context("无法初始化 COM")?;
            let r = (|| -> Result<T> {
                let svc: ITaskService =
                    CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)
                        .context("无法打开任务计划程序")?;
                let empty = VARIANT::default();
                svc.Connect(&empty, &empty, &empty, &empty)
                    .context("无法连接任务计划程序")?;
                let folder = svc
                    .GetFolder(&BSTR::from("\\"))
                    .context("无法打开任务计划程序的根目录")?;
                f(&folder)
            })();
            CoUninitialize();
            r
        })
        .join()
        .map_err(|_| anyhow!("访问任务计划程序的线程异常退出"))?
    })
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
    hay.windows(needle.len()).any(|w| w == needle.as_bytes())
        || hay.windows(utf16.len()).any(|w| w == utf16)
}

/// 旧版本注册的任务没有记录配置路径：启动时发现这种任务就重新注册一次，登录后加载同一份配置。
pub fn upgrade_legacy(config: &Path) {
    let Ok(out) = schtasks().and_then(|mut c| {
        Ok(c.args(["/Query", "/TN", TASK_NAME, "/XML", "ONE"])
            .output()?)
    }) else {
        return;
    };
    if !out.status.success() || contains(&out.stdout, "--config") {
        return;
    }
    let result = std::env::current_exe()
        .context("无法确定程序路径")
        .and_then(|exe| enable(&exe, config));
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

    /// 实际注册一个测试任务，读回任务计划程序里保存的定义，核对账户 SID、命令和配置参数，然后删除。
    /// 需要管理员权限（GitHub 的 Windows 虚拟机满足）；没有权限时跳过。
    #[test]
    fn registers_task_from_memory() {
        let name = format!("egress-guard-test-{}", std::process::id());
        let exe = std::env::current_exe().unwrap();
        let config = std::env::temp_dir().join("eg 测试 & config.toml");
        match enable_named(&name, &exe, &config) {
            Err(e) if format!("{e:#}").contains("0x80070005") => {
                eprintln!("没有管理员权限，跳过：{e:#}");
                return;
            }
            r => r.unwrap(),
        }
        let n = name.clone();
        let xml = with_tasks(move |folder| unsafe {
            let task = folder.GetTask(&BSTR::from(n.as_str()))?;
            let xml = task.Xml()?.to_string();
            folder.DeleteTask(&BSTR::from(n.as_str()), 0)?;
            Ok(xml)
        })
        .unwrap();
        let user = current_user_sid().unwrap();
        // 任务计划程序可能把 SID 换成账户名保存
        let name_ok = std::env::var("USERNAME").is_ok_and(|u| !u.is_empty() && xml.to_lowercase().contains(&u.to_lowercase()));
        assert!(xml.contains(&user) || name_ok, "{xml}");
        assert!(xml.contains(&xml_escape(&exe.to_string_lossy())), "{xml}");
        assert!(xml.contains("--minimized --config"), "{xml}");
        assert!(
            xml.contains(&xml_escape(
                &std::path::absolute(&config).unwrap().to_string_lossy()
            )),
            "{xml}"
        );
        assert!(xml.contains("HighestAvailable"), "{xml}");
        // 已删除
        let n = name.clone();
        assert!(with_tasks(move |folder| unsafe {
            Ok(folder.GetTask(&BSTR::from(n.as_str())).is_err())
        })
        .unwrap());
    }

    #[test]
    fn task_xml_escapes_paths() {
        let x = task_xml(
            "S-1-5-21-1",
            Path::new("C:\\A&B\\eg.exe"),
            "--config \"C:\\<x>.toml\"",
            Path::new("C:\\A&B"),
        );
        assert!(x.contains("<Command>C:\\A&amp;B\\eg.exe</Command>"), "{x}");
        assert!(x.contains("&quot;C:\\&lt;x&gt;.toml&quot;"), "{x}");
        assert!(x.contains("<UserId>S-1-5-21-1</UserId>"));
    }

    #[test]
    fn finds_ascii_and_utf16() {
        assert!(contains(
            b"<Arguments>--minimized --config x</Arguments>",
            "--config"
        ));
        let utf16: Vec<u8> = "a --config b"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert!(contains(&utf16, "--config"));
        assert!(!contains(b"--minimized", "--config"));
    }
}
