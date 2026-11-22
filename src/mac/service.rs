//! macOS 后台服务（LaunchDaemon）与登录项（LaunchAgent）。
//!
//! - 后台服务以 root 运行引擎（pf 需要 root），界面以普通用户运行，二者经本地套接字通信。
//! - 套接字由 launchd 创建（`Sockets`），界面连接时服务会被按需拉起；
//!   「退出」时服务正常退出（退出码 0，`KeepAlive.SuccessfulExit = false` 不会重启），
//!   崩溃时由 launchd 重启。`RunAtLoad` 对应「开机/登录自动启动」。
//! - 安装、卸载需要管理员密码：界面通过 osascript 以管理员权限运行 `egress-guard service install`。

use std::os::fd::FromRawFd;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};

use super::paths::{self, DAEMON_LABEL, DAEMON_PLIST, LOG_FILE, SOCKET, SUPPORT_DIR};

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn bool_tag(b: bool) -> &'static str {
    if b { "<true/>" } else { "<false/>" }
}

/// 后台服务的 plist。
pub fn daemon_plist(bin: &Path, run_at_load: bool) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{DAEMON_LABEL}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{bin}</string>
		<string>daemon</string>
	</array>
	<key>RunAtLoad</key>
	{run}
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>Sockets</key>
	<dict>
		<key>Listeners</key>
		<dict>
			<key>SockPathName</key>
			<string>{SOCKET}</string>
			<key>SockPathMode</key>
			<integer>438</integer>
		</dict>
	</dict>
	<key>ProcessType</key>
	<string>Interactive</string>
	<key>StandardErrorPath</key>
	<string>/Library/Logs/egress-guard.stderr.log</string>
</dict>
</plist>
"#,
        bin = xml_escape(&bin.to_string_lossy()),
        run = bool_tag(run_at_load),
    )
}

/// 当前用户登录时启动界面的 LaunchAgent plist。
pub fn gui_agent_plist(exe: &Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{label}</string>
	<key>ProgramArguments</key>
	<array>
		<string>{exe}</string>
		<string>--minimized</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>LimitLoadToSessionType</key>
	<string>Aqua</string>
	<key>ProcessType</key>
	<string>Interactive</string>
</dict>
</plist>
"#,
        label = paths::GUI_LABEL,
        exe = xml_escape(&exe.to_string_lossy()),
    )
}

pub fn is_installed() -> bool {
    Path::new(DAEMON_PLIST).exists()
}

/// 已安装服务的 plist 里 RunAtLoad 是否开启。
pub fn run_at_load() -> bool {
    std::fs::read_to_string(DAEMON_PLIST)
        .map(|t| {
            t.split("<key>RunAtLoad</key>").nth(1).is_some_and(|rest| rest.trim_start().starts_with("<true/>"))
        })
        .unwrap_or(false)
}

fn require_root() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("需要 root 权限（sudo）");
    }
    Ok(())
}

fn launchctl(args: &[&str]) -> Result<()> {
    let out = Command::new("/bin/launchctl").args(args).output().context("无法运行 launchctl")?;
    if !out.status.success() {
        bail!(
            "launchctl {} 失败: {}{}",
            args.join(" "),
            String::from_utf8_lossy(&out.stdout).trim(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn write_root_file(path: &Path, text: &str, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, text).with_context(|| format!("无法写入 {}", tmp.display()))?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
    std::fs::rename(&tmp, path).with_context(|| format!("无法写入 {}", path.display()))
}

/// 安装（或更新）后台服务并启动。需要 root。
///
/// `src_bin` 是 .app 包里的命令行程序；会被复制到 `/Library/Application Support/EgressGuard/bin/`。
pub fn install(src_bin: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    require_root()?;
    let bin = paths::daemon_bin();
    let dir = bin.parent().context("服务程序目录")?;
    std::fs::create_dir_all(dir).with_context(|| format!("无法创建 {}", dir.display()))?;
    for d in [Path::new(SUPPORT_DIR), dir] {
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o755))?;
    }
    if src_bin != bin {
        let tmp = bin.with_extension("new");
        std::fs::copy(src_bin, &tmp).with_context(|| format!("无法复制 {}", src_bin.display()))?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
        // 从网上下载的 .app 带有隔离属性，复制出来的程序也会带上；launchd 启动前去掉
        if let Ok(c) = std::ffi::CString::new(tmp.as_os_str().as_encoded_bytes()) {
            unsafe { libc::removexattr(c.as_ptr(), c"com.apple.quarantine".as_ptr(), 0) };
        }
        std::fs::rename(&tmp, &bin)?;
    }
    // 重新安装时保留原来的「自动启动」设置；首次安装默认关闭（与界面的开关一致，开启后才开机自动保护）
    let run = is_installed() && run_at_load();
    // 先停止旧服务（它收到 SIGTERM 后会清空自己的规则）
    let target = format!("system/{DAEMON_LABEL}");
    let _ = launchctl(&["bootout", &target]);
    write_root_file(Path::new(DAEMON_PLIST), &daemon_plist(&bin, run), 0o644)?;

    // bootout 是异步的，刚停掉时 bootstrap 可能报 "Input/output error"，稍等重试
    let mut last = Ok(());
    for _ in 0..20 {
        last = launchctl(&["bootstrap", "system", DAEMON_PLIST]);
        if last.is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    last?;
    // 立即启动一次（RunAtLoad 关闭时也让保护马上生效）
    let _ = launchctl(&["kickstart", &target]);
    println!("后台服务已安装：{}", bin.display());
    Ok(())
}

/// 卸载后台服务（保留配置文件）。需要 root。
pub fn uninstall() -> Result<()> {
    require_root()?;
    let _ = launchctl(&["bootout", &format!("system/{DAEMON_LABEL}")]);
    let _ = std::fs::remove_file(DAEMON_PLIST);
    if let Err(e) = super::pf::flush_anchor() {
        log::warn!("{e:#}");
    }
    let _ = std::fs::remove_dir_all(paths::daemon_bin().parent().unwrap_or(Path::new("/nonexistent")));
    let _ = std::fs::remove_file(SOCKET);
    println!("后台服务已卸载；配置保留在 {SUPPORT_DIR}，日志在 {LOG_FILE}");
    Ok(())
}

/// 修改「开机自动启动」（服务自己以 root 调用）。下次开机生效；当前运行状态不受影响。
pub fn set_run_at_load(on: bool) -> Result<()> {
    require_root()?;
    if !is_installed() {
        bail!("后台服务未安装");
    }
    write_root_file(Path::new(DAEMON_PLIST), &daemon_plist(&paths::daemon_bin(), on), 0o644)
}

/// 取得 launchd 为服务创建的监听套接字；不是由 launchd 启动时返回 None。
pub fn launchd_listener() -> Result<Option<UnixListener>> {
    extern "C" {
        fn launch_activate_socket(name: *const libc::c_char, fds: *mut *mut libc::c_int, cnt: *mut libc::size_t) -> libc::c_int;
    }
    let mut fds: *mut libc::c_int = std::ptr::null_mut();
    let mut cnt: libc::size_t = 0;
    let r = unsafe { launch_activate_socket(c"Listeners".as_ptr(), &mut fds, &mut cnt) };
    if r != 0 {
        // ESRCH：不是由 launchd 管理；ENOENT：plist 里没有这个套接字
        if r == libc::ESRCH || r == libc::ENOENT {
            return Ok(None);
        }
        bail!("launch_activate_socket 失败: {}", std::io::Error::from_raw_os_error(r));
    }
    let list = unsafe { std::slice::from_raw_parts(fds, cnt) }.to_vec();
    unsafe { libc::free(fds.cast()) };
    let mut it = list.into_iter();
    let first = it.next().context("launchd 没有提供套接字")?;
    for extra in it {
        unsafe { libc::close(extra) };
    }
    Ok(Some(unsafe { UnixListener::from_raw_fd(first) }))
}

// ---------------- 界面一侧（普通用户） ----------------

/// 界面登录项是否已开启。
pub fn login_item_enabled() -> bool {
    paths::gui_agent_plist().is_some_and(|p| p.exists())
}

pub fn set_login_item(on: bool, exe: &Path) -> Result<()> {
    let path = paths::gui_agent_plist().context("无法确定用户主目录")?;
    if on {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&path, gui_agent_plist(exe)).with_context(|| format!("无法写入 {}", path.display()))
    } else {
        match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        }
    }
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn applescript_string(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

/// 以管理员权限运行命令（弹出系统的密码对话框）。用户取消时返回错误"已取消"。
pub fn run_as_admin(args: &[&str], prompt: &str) -> Result<()> {
    let cmd: Vec<String> = args.iter().map(|a| shell_quote(a)).collect();
    let script = format!(
        "do shell script {} with prompt {} with administrator privileges",
        applescript_string(&cmd.join(" ")),
        applescript_string(prompt)
    );
    let out = Command::new("/usr/bin/osascript").arg("-e").arg(script).output().context("无法运行 osascript")?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        if err.contains("-128") {
            bail!("已取消");
        }
        bail!("{}", err.trim());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting() {
        assert_eq!(shell_quote("/Applications/Egress Guard.app/x"), "'/Applications/Egress Guard.app/x'");
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
        assert_eq!(applescript_string("say \"hi\" \\"), "\"say \\\"hi\\\" \\\\\"");
    }

    #[test]
    fn plist_contents() {
        let p = daemon_plist(Path::new("/Library/Application Support/EgressGuard/bin/egress-guard"), false);
        assert!(p.contains("<string>daemon</string>"));
        assert!(p.contains("<key>RunAtLoad</key>\n\t<false/>"));
        assert!(p.contains("<integer>438</integer>"));
        let g = gui_agent_plist(Path::new("/Applications/A&B.app/Contents/MacOS/egress-guard-gui"));
        assert!(g.contains("A&amp;B.app"));
    }
}
