//! 开机（登录）自启：用任务计划程序以最高权限启动界面程序，避免每次弹出 UAC。
//!
//! 任务以管理员权限运行，所以只在程序、配置和它们的上层目录都只有 SYSTEM、管理员组和
//! TrustedInstaller 能修改时才注册（见 [`crate::trustedpath`]）；否则别的程序可以替换 exe
//! 或在旁边放 DLL，在下次登录时拿到管理员权限。

use std::ffi::c_void;
use std::fs::File;
use std::io::Write;
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::FromRawHandle;
use std::os::windows::process::CommandExt;
use std::path::{Component, Path, PathBuf, Prefix};
use std::process::Command;

use anyhow::{bail, Context, Result};
use windows::core::{HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, ERROR_SUCCESS, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW,
    SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    GetAce, GetTokenInformation, TokenUser, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE, FILE_SHARE_READ};
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::trustedpath::{self, Ace, Kind};

pub const TASK_NAME: &str = "egress-guard";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

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

/// 去掉 canonicalize 加上的 `\\?\`，用于显示和写入任务（只处理本机磁盘路径）。
fn plain(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    match s.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC\\") => PathBuf::from(rest),
        _ => p.to_path_buf(),
    }
}

/// 解析出最终路径（经过所有符号链接和目录联接），并要求在本机磁盘上。
fn final_path(p: &Path) -> Result<PathBuf> {
    let c = std::fs::canonicalize(p).with_context(|| format!("无法解析 {}", p.display()))?;
    match c.components().next() {
        Some(Component::Prefix(pre)) if matches!(pre.kind(), Prefix::VerbatimDisk(_)) => Ok(c),
        _ => bail!("{} 不在本机磁盘上", p.display()),
    }
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

/// 读取对象的所有者和 DACL（None 表示没有 DACL）。
fn read_acl(path: &Path) -> Result<(String, Option<Vec<Ace>>)> {
    let name = HSTRING::from(path.as_os_str());
    let mut owner = PSID::default();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        let err = GetNamedSecurityInfoW(
            PCWSTR(name.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut dacl),
            None,
            &mut sd,
        );
        if err != ERROR_SUCCESS {
            bail!("无法读取 {} 的权限: {}", plain(path).display(), std::io::Error::from_raw_os_error(err.0 as i32));
        }
        let result = (|| -> Result<(String, Option<Vec<Ace>>)> {
            let owner = sid_string(owner)?;
            if dacl.is_null() {
                return Ok((owner, None));
            }
            let mut aces = Vec::new();
            for i in 0..(*dacl).AceCount as u32 {
                let mut p: *mut c_void = std::ptr::null_mut();
                GetAce(dacl, i, &mut p).context("无法读取权限项")?;
                let header = *(p as *const ACE_HEADER);
                // 允许项与回调允许项的布局相同：头、权限、SID
                let (mask, sid) = if header.AceType == 0 || header.AceType == 9 {
                    let ace = p as *const ACCESS_ALLOWED_ACE;
                    let sid = PSID(std::ptr::addr_of!((*ace).SidStart) as *mut c_void);
                    ((*ace).Mask, Some(sid_string(sid)?))
                } else {
                    // 其他类型的权限字段同样紧跟在头后面
                    (*(p as *const ACE_HEADER).add(1).cast::<u32>(), None)
                };
                aces.push(Ace { ace_type: header.AceType, flags: header.AceFlags, mask, sid });
            }
            Ok((owner, Some(aces)))
        })();
        LocalFree(Some(HLOCAL(sd.0)));
        result
    }
}

fn check_one(path: &Path, kind: Kind) -> Result<()> {
    let meta = std::fs::symlink_metadata(path).with_context(|| format!("无法读取 {}", plain(path).display()))?;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        bail!("{} 是链接或挂载点", plain(path).display());
    }
    let (owner, dacl) = read_acl(path)?;
    trustedpath::check(kind, &owner, dacl.as_deref()).map_err(|why| anyhow::anyhow!("{}：{why}", plain(path).display()))
}

/// 检查文件（可以不存在）、所在目录和所有上层目录。传入的必须是最终路径。
fn check_tree(file: &Path, file_exists: bool) -> Result<()> {
    if file_exists {
        check_one(file, Kind::File)?;
    }
    let dir = file.parent().context("无法确定所在目录")?;
    check_one(dir, Kind::Dir)?;
    for a in dir.ancestors().skip(1) {
        check_one(a, Kind::Ancestor)?;
    }
    Ok(())
}

/// 程序和配置的最终路径（已检查）
struct Location {
    exe: PathBuf,
    dir: PathBuf,
    config: PathBuf,
}

fn verify_location(exe: &Path, config: &Path) -> Result<Location> {
    let exe = final_path(exe)?;
    let config = std::path::absolute(config).context("无法确定配置文件路径")?;
    let (config, config_exists) = match final_path(&config) {
        Ok(c) => (c, true),
        Err(_) if !config.exists() => {
            let parent = config.parent().context("无法确定配置文件目录")?;
            (final_path(parent)?.join(config.file_name().context("配置文件路径无效")?), false)
        }
        Err(e) => return Err(e),
    };
    let unsafe_location = |e: anyhow::Error| {
        e.context(
            "程序或配置所在的位置普通账户也能修改，不能注册以管理员权限运行的开机自启任务。\
             请把 egress-guard-gui.exe 移到 C:\\Program Files\\egress-guard\\ 这样只有管理员能修改的文件夹\
             （配置默认在程序旁边），从那里运行后再开启。手动启动不受影响",
        )
    };
    check_tree(&exe, true).map_err(unsafe_location)?;
    check_tree(&config, config_exists).map_err(unsafe_location)?;
    let dir = exe.parent().context("无法确定程序目录")?.to_path_buf();
    Ok(Location { exe: plain(&exe), dir: plain(&dir), config: plain(&config) })
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

/// 在已检查过的程序目录里创建只有 SYSTEM 和管理员组能访问的唯一临时文件。
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
        let path = dir.join(format!(".egress-guard-task-{}-{i}.xml", std::process::id()));
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
    let loc = verify_location(exe, config)?;
    let user = current_user_sid()?;
    let args = format!("--minimized --config {}", quote_arg(&loc.config));
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
        exe = xml_escape(&loc.exe.to_string_lossy()),
        args = xml_escape(&args),
        dir = xml_escape(&loc.dir.to_string_lossy()),
    );

    // 任务计划程序要求 XML 为 UTF-16（带 BOM）
    let mut bytes = vec![0xFF, 0xFE];
    for u in xml.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    let (path, mut f) = create_private_file(&loc.dir)?;
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

/// 旧版本注册的任务没有记录配置路径，也没有检查程序位置。启动时发现这种任务就按新规则重新注册；
/// 位置不安全时删除任务（它会以管理员权限运行别人能替换的程序），并在日志里说明。
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
        Ok(()) => log::info!("已按新规则更新开机自启任务（记录配置文件路径）"),
        Err(e) => {
            log::warn!("旧版本创建的开机自启任务没能更新，已关闭开机自启：{e:#}");
            if let Err(e) = disable() {
                log::warn!("{e:#}");
            }
        }
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

    fn system_dir() -> PathBuf {
        let mut buf = [0u16; 520];
        let n = unsafe { GetSystemDirectoryW(Some(&mut buf)) } as usize;
        PathBuf::from(String::from_utf16_lossy(&buf[..n]))
    }

    #[test]
    fn system_directory_is_trusted() {
        let cmd = final_path(&system_dir().join("cmd.exe")).unwrap();
        check_tree(&cmd, true).unwrap();
    }

    #[test]
    fn temp_directory_is_rejected() {
        let dir = std::env::temp_dir().join(format!("egress-guard-autostart-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("egress-guard-gui.exe");
        std::fs::write(&exe, b"x").unwrap();
        let err = verify_location(&exe, &dir.join("config.toml")).err().expect("temp dir must be rejected");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(format!("{err:#}").contains("Program Files"), "{err:#}");
    }

    #[test]
    fn plain_strips_verbatim_prefix() {
        assert_eq!(plain(Path::new(r"\\?\C:\Program Files\x.exe")), PathBuf::from(r"C:\Program Files\x.exe"));
        assert_eq!(plain(Path::new(r"\\?\UNC\srv\share")), PathBuf::from(r"\\?\UNC\srv\share"));
    }

    #[test]
    fn finds_ascii_and_utf16() {
        assert!(contains(b"<Arguments>--minimized --config x</Arguments>", "--config"));
        let utf16: Vec<u8> = "a --config b".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert!(contains(&utf16, "--config"));
        assert!(!contains(b"--minimized", "--config"));
    }
}
