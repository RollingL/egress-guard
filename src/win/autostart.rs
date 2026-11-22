//! 开机（登录）自启：用任务计划程序以最高权限启动界面程序，避免每次弹出 UAC。

use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};

pub const TASK_NAME: &str = "egress-guard";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn schtasks() -> Command {
    let mut c = Command::new("schtasks.exe");
    c.creation_flags(CREATE_NO_WINDOW);
    c
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn is_enabled() -> bool {
    schtasks()
        .args(["/Query", "/TN", TASK_NAME])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// 注册登录时启动的计划任务（不限运行时长、使用电池时也运行）。
pub fn enable(exe: &Path) -> Result<()> {
    let user = match (std::env::var("USERDOMAIN"), std::env::var("USERNAME")) {
        (Ok(d), Ok(u)) => format!("{d}\\{u}"),
        (_, Ok(u)) => u,
        _ => bail!("无法确定当前用户名"),
    };
    let dir = exe.parent().context("无法确定程序目录")?;
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
  <Actions Context="Author"><Exec><Command>{exe}</Command><Arguments>--minimized</Arguments><WorkingDirectory>{dir}</WorkingDirectory></Exec></Actions>
</Task>
"#,
        user = xml_escape(&user),
        exe = xml_escape(&exe.to_string_lossy()),
        dir = xml_escape(&dir.to_string_lossy()),
    );

    // 任务计划程序要求 XML 为 UTF-16（带 BOM）
    let path = std::env::temp_dir().join("egress-guard-task.xml");
    let mut bytes = vec![0xFF, 0xFE];
    for u in xml.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    std::fs::write(&path, bytes).context("无法写入临时任务文件")?;

    let out = schtasks()
        .args(["/Create", "/F", "/TN", TASK_NAME, "/XML"])
        .arg(&path)
        .output()
        .context("无法运行 schtasks")?;
    let _ = std::fs::remove_file(&path);
    if !out.status.success() {
        bail!("创建计划任务失败: {}", decode(&out.stderr));
    }
    Ok(())
}

pub fn disable() -> Result<()> {
    let out = schtasks()
        .args(["/Delete", "/F", "/TN", TASK_NAME])
        .output()
        .context("无法运行 schtasks")?;
    if !out.status.success() {
        bail!("删除计划任务失败: {}", decode(&out.stderr));
    }
    Ok(())
}

/// schtasks 输出使用系统代码页（中文系统为 GBK），这里尽力解码。
fn decode(b: &[u8]) -> String {
    match String::from_utf8(b.to_vec()) {
        Ok(s) => s.trim().to_owned(),
        Err(_) => format!("（输出无法解码，{} 字节）", b.len()),
    }
}
