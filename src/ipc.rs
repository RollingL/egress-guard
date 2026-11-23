//! 后台服务与界面之间的本地通信（Unix 域套接字，每行一个 JSON）。
//!
//! macOS 上引擎运行在 root 后台服务里，界面以普通用户运行，通过这里查询状态、修改配置。
//! 只读请求（状态、配置、日志）任何本机用户都可以发；修改类请求只接受 root 和管理员组成员。

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::RawConfig;
use crate::engine::Status;
use crate::eventlog::{self, ConnEvent};
use crate::filterfeed::{self, FilterHello, FilterState};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", content = "arg", rename_all = "snake_case")]
pub enum Request {
    Hello,
    /// 当前状态（一次）。
    GetStatus,
    /// 持续推送状态，直到连接断开。
    Watch,
    GetConfig,
    /// 校验、保存并应用配置。
    SetConfig(Box<RawConfig>),
    CheckNow,
    ClearLearned,
    Logs,
    ClearLogs,
    /// 连接记录（阻断、恢复、泄露）。
    Events,
    ClearEvents,
    /// 界面的自动泄露测试发现泄露时写入连接记录（只接受「泄露」类型）。
    RecordEvent(Box<ConnEvent>),
    /// 开机自动启动后台服务。
    SetAutostart(bool),
    /// 移除全部阻断规则并退出服务。
    Stop,
    /// macOS 网络扩展：持续接收按应用阻断的规则，直到连接断开。只接受 root。
    FilterWatch(FilterHello),
    /// 网络扩展（在 filter_watch 连接里）确认已应用这个版本的规则。
    FilterApplied(u64),
}

impl Request {
    fn mutating(&self) -> bool {
        !matches!(
            self,
            Request::Hello
                | Request::GetStatus
                | Request::Watch
                | Request::GetConfig
                | Request::Logs
                | Request::Events
                | Request::FilterWatch(_)
                | Request::FilterApplied(_)
        )
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct HelloInfo {
    pub version: String,
    pub config_path: String,
    pub log_path: String,
    /// 开机自动启动是否开启。
    pub autostart: bool,
    /// 配置文件损坏、服务正在用默认设置（全局断网）运行时的原因。
    pub config_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum Reply {
    Hello(HelloInfo),
    Status(Box<Status>),
    Config(Box<RawConfig>),
    Logs(Vec<String>),
    Events(Vec<ConnEvent>),
    /// 推送给网络扩展的规则。
    Filter(FilterState),
    /// 配置已保存，值是分配的配置版本（引擎应用后出现在状态的 config_version 里）。
    Saved(u64),
    Ok,
    Err(String),
}

/// 服务端对请求的处理。
pub trait Handler: Send + Sync + 'static {
    fn hello(&self) -> HelloInfo;
    fn get_config(&self) -> RawConfig;
    /// 保存并应用配置，返回分配的配置版本。
    fn set_config(&self, raw: RawConfig) -> Result<u64>;
    fn check_now(&self);
    fn clear_learned(&self);
    fn set_autostart(&self, on: bool) -> Result<()>;
    fn stop(&self);
}

/// 最新状态，供多个 Watch 连接等待变化。
#[derive(Default)]
pub struct StatusHub {
    state: Mutex<(u64, Status)>,
    cv: Condvar,
}

impl StatusHub {
    pub fn publish(&self, s: &Status) {
        let mut g = self.state.lock().unwrap();
        g.0 += 1;
        g.1 = s.clone();
        self.cv.notify_all();
    }

    /// 等待比 `seen` 更新的状态；超时返回 None（用于检测断开的连接）。
    fn wait_newer(&self, seen: u64, timeout: Duration) -> Option<(u64, Status)> {
        let g = self.state.lock().unwrap();
        let (g, _) = self.cv.wait_timeout_while(g, timeout, |(v, _)| *v == seen).unwrap();
        (g.0 != seen).then(|| (g.0, g.1.clone()))
    }
}

// ---------------- 身份 ----------------

#[cfg(target_os = "macos")]
fn peer_uid(s: &UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd;
    let (mut uid, mut gid) = (0, 0);
    (unsafe { libc::getpeereid(s.as_raw_fd(), &mut uid, &mut gid) } == 0).then_some(uid)
}

#[cfg(not(target_os = "macos"))]
fn peer_uid(s: &UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd;
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let r = unsafe {
        libc::getsockopt(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&mut cred as *mut libc::ucred).cast(), &mut len)
    };
    (r == 0).then_some(cred.uid)
}

/// root、与服务相同的用户，以及（macOS）管理员组成员可以修改设置。
/// 读配置的回复：GitHub 令牌、代理地址里的用户名密码只给能修改设置的账户（管理员）。
/// 其他账户读到的配置里没有令牌，代理显示为 `***`（他们也不能保存设置，不会把 *** 写回去）。
fn config_for(mut raw: RawConfig, admin: bool) -> RawConfig {
    if !admin {
        raw.update.token.clear();
        raw.detect.proxy = crate::config::redact_proxy(&raw.detect.proxy);
    }
    raw
}

fn may_modify(uid: u32) -> bool {
    uid == 0 || uid == unsafe { libc::geteuid() } || is_admin(uid)
}

#[cfg(target_os = "macos")]
fn is_admin(uid: u32) -> bool {
    const ADMIN_GID: i32 = 80;
    unsafe {
        let pw = libc::getpwuid(uid);
        if pw.is_null() {
            return false;
        }
        let mut groups = vec![0i32; 256];
        let mut n = groups.len() as i32;
        if libc::getgrouplist((*pw).pw_name, (*pw).pw_gid as i32, groups.as_mut_ptr(), &mut n) < 0 {
            return false;
        }
        groups.truncate(n.max(0) as usize);
        groups.contains(&ADMIN_GID)
    }
}

#[cfg(not(target_os = "macos"))]
fn is_admin(_uid: u32) -> bool {
    false
}

// ---------------- 服务端 ----------------

fn write_reply(w: &mut impl Write, r: &Reply) -> std::io::Result<()> {
    let mut line = serde_json::to_string(r).map_err(std::io::Error::other)?;
    line.push('\n');
    w.write_all(line.as_bytes())?;
    w.flush()
}

/// 单个请求的最大长度（配置远小于这个值）。
const MAX_REQUEST: u64 = 1 << 20;
/// 空闲连接在这么久没有新请求后关闭（界面每个请求都用新连接，Watch 只写不读）。
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

fn handle_conn(stream: UnixStream, handler: &dyn Handler, hub: &StatusHub) -> std::io::Result<()> {
    use std::io::Read;
    let uid = peer_uid(&stream);
    stream.set_read_timeout(Some(IDLE_TIMEOUT))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;
    let mut w = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    loop {
        let mut line = String::new();
        let n = (&mut reader).take(MAX_REQUEST).read_line(&mut line)?;
        if n == 0 {
            return Ok(());
        }
        if !line.ends_with('\n') && n as u64 >= MAX_REQUEST {
            write_reply(&mut w, &Reply::Err("请求过长".into()))?;
            return Ok(());
        }
        if line.trim().is_empty() {
            continue;
        }
        let req: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                write_reply(&mut w, &Reply::Err(format!("无法解析请求: {e}")))?;
                continue;
            }
        };
        if req.mutating() && !uid.is_some_and(may_modify) {
            write_reply(&mut w, &Reply::Err("只有管理员账户可以修改设置".into()))?;
            continue;
        }
        // 网络扩展以 root 运行；其他进程冒充扩展会让界面误以为按应用断网已生效
        if matches!(req, Request::FilterWatch(_)) && uid != Some(0) && uid != Some(unsafe { libc::geteuid() }) {
            write_reply(&mut w, &Reply::Err("只接受 root 进程（网络扩展）".into()))?;
            return Ok(());
        }
        let reply = match req {
            Request::Hello => Reply::Hello(handler.hello()),
            Request::GetStatus => Reply::Status(Box::new(hub.state.lock().unwrap().1.clone())),
            Request::GetConfig => Reply::Config(Box::new(config_for(handler.get_config(), uid.is_some_and(may_modify)))),
            Request::SetConfig(raw) => match handler.set_config(*raw) {
                Ok(v) => Reply::Saved(v),
                Err(e) => Reply::Err(format!("{e:#}")),
            },
            Request::CheckNow => {
                handler.check_now();
                Reply::Ok
            }
            Request::ClearLearned => {
                handler.clear_learned();
                Reply::Ok
            }
            Request::Logs => Reply::Logs(crate::logbuf::recent_lines()),
            Request::ClearLogs => {
                crate::logbuf::clear();
                Reply::Ok
            }
            Request::Events => Reply::Events(eventlog::recent()),
            Request::ClearEvents => match eventlog::clear() {
                Ok(()) => {
                    log::info!("界面清空了连接记录");
                    Reply::Ok
                }
                Err(e) => Reply::Err(format!("无法清空连接记录：{e:#}")),
            },
            Request::RecordEvent(e) if e.kind == eventlog::Kind::Leak => {
                eventlog::record(*e);
                Reply::Ok
            }
            Request::RecordEvent(_) => Reply::Err("只能写入泄露测试的结果".into()),
            Request::SetAutostart(on) => match handler.set_autostart(on) {
                Ok(()) => Reply::Ok,
                Err(e) => Reply::Err(format!("{e:#}")),
            },
            Request::Stop => {
                write_reply(&mut w, &Reply::Ok)?;
                handler.stop();
                return Ok(());
            }
            Request::FilterWatch(hello) => return filter_watch(w, reader, hello),
            Request::FilterApplied(_) => Reply::Err("filter_applied 只能在 filter_watch 连接里发送".into()),
            Request::Watch => {
                let mut seen = 0;
                loop {
                    // 定时发送一次（即使没变化），以便尽快发现已断开的连接
                    match hub.wait_newer(seen, Duration::from_secs(5)) {
                        Some((v, s)) => {
                            seen = v;
                            write_reply(&mut w, &Reply::Status(Box::new(s)))?;
                        }
                        None => {
                            let s = hub.state.lock().unwrap().1.clone();
                            write_reply(&mut w, &Reply::Status(Box::new(s)))?;
                        }
                    }
                }
            }
        };
        write_reply(&mut w, &reply)?;
    }
}

/// 网络扩展的连接：登记后持续推送规则，至少每 5 秒一次（心跳）。
/// 支持确认的扩展在同一连接上回复 `filter_applied`，由单独的线程读取。
fn filter_watch(mut w: UnixStream, reader: BufReader<UnixStream>, hello: FilterHello) -> std::io::Result<()> {
    let hub = filterfeed::hub();
    log::info!(
        "网络扩展已连接（{}{}）",
        if hello.version.is_empty() { "版本未知" } else { &hello.version },
        if hello.caps.is_empty() { String::new() } else { format!("，支持 {}", hello.caps.join("、")) }
    );
    let reg = hub.register(hello);
    std::thread::scope(|scope| {
        let reg = &reg;
        scope.spawn(move || {
            let mut reader = reader;
            loop {
                let mut line = String::new();
                match std::io::Read::take(&mut reader, 4096).read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => {
                        if let Ok(Request::FilterApplied(rev)) = serde_json::from_str(&line) {
                            hub.applied(reg, rev);
                        }
                    }
                    // 旧扩展从不回复：读超时不算断开，连接是否还在由写入（心跳）判断
                    Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
                    Err(_) => break,
                }
            }
        });
        // 引擎还没写入过规则时先不发：扩展收到第一条规则前保持原来的状态
        let mut seen = 0;
        let r = loop {
            let (v, mut s) = hub.wait_newer(seen, Duration::from_secs(5));
            if v == 0 {
                continue;
            }
            seen = v;
            s.rev = v;
            if let Err(e) = write_reply(&mut w, &Reply::Filter(s)) {
                break Err(e);
            }
        };
        // 让读取线程结束
        let _ = w.shutdown(std::net::Shutdown::Both);
        log::info!("网络扩展已断开");
        r
    })
}

/// 在后台线程中接受连接，每个连接一个线程。
pub fn serve(listener: UnixListener, handler: Arc<dyn Handler>, hub: Arc<StatusHub>) {
    std::thread::Builder::new()
        .name("ipc".into())
        .spawn(move || {
            for conn in listener.incoming() {
                let Ok(stream) = conn else { continue };
                let (handler, hub) = (handler.clone(), hub.clone());
                let _ = std::thread::Builder::new().name("ipc-conn".into()).spawn(move || {
                    if let Err(e) = handle_conn(stream, handler.as_ref(), &hub) {
                        log::debug!("界面连接断开: {e}");
                    }
                });
            }
        })
        .expect("无法创建通信线程");
}

/// 自己创建监听套接字（手动运行服务、测试时使用；launchd 启动时由 launchd 创建）。
pub fn bind(path: &Path) -> Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    if UnixStream::connect(path).is_ok() {
        bail!("{} 已有服务在监听，请先停止它", path.display());
    }
    let _ = std::fs::remove_file(path);
    let l = UnixListener::bind(path).with_context(|| format!("无法监听 {}", path.display()))?;
    // 任何用户都能连接；能否修改设置由对端身份决定
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    Ok(l)
}

// ---------------- 客户端 ----------------

#[derive(Debug, Clone)]
pub struct Client {
    pub path: PathBuf,
}

impl Client {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    fn connect(&self, timeout: Option<Duration>) -> Result<UnixStream> {
        let s = UnixStream::connect(&self.path).with_context(|| format!("无法连接后台服务（{}）", self.path.display()))?;
        s.set_read_timeout(timeout)?;
        s.set_write_timeout(Some(Duration::from_secs(5)))?;
        Ok(s)
    }

    /// 发送一个请求并等待回复。
    pub fn request(&self, req: &Request, timeout: Duration) -> Result<Reply> {
        let mut s = self.connect(Some(timeout))?;
        let mut line = serde_json::to_string(req)?;
        line.push('\n');
        s.write_all(line.as_bytes())?;
        let mut reader = BufReader::new(s);
        let mut reply = String::new();
        if reader.read_line(&mut reply).context("后台服务没有回复")? == 0 {
            bail!("后台服务关闭了连接");
        }
        Ok(serde_json::from_str(&reply)?)
    }

    /// 发送请求，期望回复 Ok。
    pub fn command(&self, req: &Request, timeout: Duration) -> Result<()> {
        match self.request(req, timeout)? {
            Reply::Ok => Ok(()),
            Reply::Err(e) => Err(anyhow!(e)),
            other => bail!("意外的回复: {other:?}"),
        }
    }

    /// 保存配置，返回配置版本（旧版本的服务不返回版本，这时为 0）。
    pub fn set_config(&self, raw: RawConfig, timeout: Duration) -> Result<u64> {
        match self.request(&Request::SetConfig(Box::new(raw)), timeout)? {
            Reply::Saved(v) => Ok(v),
            Reply::Ok => Ok(0),
            Reply::Err(e) => Err(anyhow!(e)),
            other => bail!("意外的回复: {other:?}"),
        }
    }

    pub fn hello(&self) -> Result<HelloInfo> {
        match self.request(&Request::Hello, Duration::from_secs(5))? {
            Reply::Hello(h) => Ok(h),
            other => bail!("意外的回复: {other:?}"),
        }
    }

    pub fn status(&self) -> Result<Status> {
        match self.request(&Request::GetStatus, Duration::from_secs(5))? {
            Reply::Status(s) => Ok(*s),
            other => bail!("意外的回复: {other:?}"),
        }
    }

    pub fn get_config(&self) -> Result<RawConfig> {
        match self.request(&Request::GetConfig, Duration::from_secs(5))? {
            Reply::Config(c) => Ok(*c),
            Reply::Err(e) => Err(anyhow!(e)),
            other => bail!("意外的回复: {other:?}"),
        }
    }

    pub fn events(&self) -> Result<Vec<ConnEvent>> {
        match self.request(&Request::Events, Duration::from_secs(5))? {
            Reply::Events(l) => Ok(l),
            other => bail!("意外的回复: {other:?}"),
        }
    }

    pub fn logs(&self) -> Result<Vec<String>> {
        match self.request(&Request::Logs, Duration::from_secs(5))? {
            Reply::Logs(l) => Ok(l),
            other => bail!("意外的回复: {other:?}"),
        }
    }

    /// 以网络扩展的身份接收规则，直到连接断开（返回错误）。测试与 `filter-watch` 子命令使用。
    pub fn filter_watch(&self, hello: FilterHello, mut on_state: impl FnMut(FilterState) -> bool) -> Result<()> {
        let mut s = self.connect(Some(Duration::from_secs(15)))?;
        let ack = hello.caps.iter().any(|c| c == filterfeed::CAP_ACK);
        let mut line = serde_json::to_string(&Request::FilterWatch(hello))?;
        line.push('\n');
        s.write_all(line.as_bytes())?;
        let mut w = s.try_clone()?;
        for line in BufReader::new(s).lines() {
            match serde_json::from_str::<Reply>(&line?)? {
                Reply::Filter(st) => {
                    let rev = st.rev;
                    let more = on_state(st);
                    if ack && rev > 0 {
                        let mut a = serde_json::to_string(&Request::FilterApplied(rev))?;
                        a.push('\n');
                        w.write_all(a.as_bytes())?;
                    }
                    if !more {
                        return Ok(());
                    }
                }
                Reply::Err(e) => bail!(e),
                _ => {}
            }
        }
        bail!("后台服务关闭了连接")
    }

    /// 持续接收状态，直到连接断开（返回错误）。
    pub fn watch(&self, mut on_status: impl FnMut(Status)) -> Result<()> {
        // 服务端至少每 5 秒推送一次；超过 15 秒没有消息视为断开
        let mut s = self.connect(Some(Duration::from_secs(15)))?;
        s.write_all(b"{\"cmd\":\"watch\"}\n")?;
        for line in BufReader::new(s).lines() {
            match serde_json::from_str::<Reply>(&line?)? {
                Reply::Status(st) => on_status(*st),
                Reply::Err(e) => bail!(e),
                _ => {}
            }
        }
        bail!("后台服务关闭了连接")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn non_admin_config_hides_credentials() {
        let mut raw = RawConfig::default();
        raw.update.token = "ghp_secret".into();
        raw.detect.proxy = "http://alice:s3cret@127.0.0.1:8080".into();
        let shown = config_for(raw.clone(), false);
        assert!(shown.update.token.is_empty());
        assert_eq!(shown.detect.proxy, "http://***@127.0.0.1:8080");
        // 管理员原样拿到，编辑后保存不会丢掉凭据
        let admin = config_for(raw.clone(), true);
        assert_eq!(admin.update.token, raw.update.token);
        assert_eq!(admin.detect.proxy, raw.detect.proxy);
    }

    struct TestHandler {
        cfg: Mutex<RawConfig>,
        stopped: AtomicBool,
    }

    impl Handler for TestHandler {
        fn hello(&self) -> HelloInfo {
            HelloInfo { version: "test".into(), ..Default::default() }
        }
        fn get_config(&self) -> RawConfig {
            self.cfg.lock().unwrap().clone()
        }
        fn set_config(&self, raw: RawConfig) -> Result<u64> {
            crate::config::Config::from_raw(raw.clone())?;
            *self.cfg.lock().unwrap() = raw;
            Ok(7)
        }
        fn check_now(&self) {}
        fn clear_learned(&self) {}
        fn set_autostart(&self, _on: bool) -> Result<()> {
            bail!("不支持")
        }
        fn stop(&self) {
            self.stopped.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn roundtrip_over_socket() {
        let path = std::env::temp_dir().join(format!("eg-ipc-{}.sock", std::process::id()));
        let listener = bind(&path).unwrap();
        let handler = Arc::new(TestHandler { cfg: Mutex::new(RawConfig::default()), stopped: AtomicBool::new(false) });
        let hub = Arc::new(StatusHub::default());
        hub.publish(&Status { running: true, egress_ip: Some("203.0.113.9".parse().unwrap()), ..Default::default() });
        serve(listener, handler.clone(), hub.clone());
        // 第二个服务不能抢占同一个套接字
        assert!(bind(&path).is_err());

        let c = Client::new(&path);
        assert_eq!(c.hello().unwrap().version, "test");
        assert!(c.status().unwrap().running);

        let raw = RawConfig { whitelist: vec!["198.51.100.0/24".into()], ..Default::default() };
        assert_eq!(c.set_config(raw.clone(), Duration::from_secs(5)).unwrap(), 7);
        assert_eq!(c.get_config().unwrap().whitelist, raw.whitelist);
        // 校验失败的配置被拒绝，原配置不变
        let mut bad = raw.clone();
        bad.whitelist = vec!["1.2.3".into()];
        assert!(c.set_config(bad, Duration::from_secs(5)).is_err());
        assert_eq!(c.get_config().unwrap().whitelist, raw.whitelist);

        // 状态推送：先收到当前状态，再收到新状态
        let (tx, rx) = std::sync::mpsc::channel();
        let c2 = c.clone();
        std::thread::spawn(move || {
            let _ = c2.watch(|s| {
                let _ = tx.send(s);
            });
        });
        let first = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(first.egress_ip, Some("203.0.113.9".parse().unwrap()));
        hub.publish(&Status { running: true, blocked: true, ..Default::default() });
        let next = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(next.blocked);

        // 超长请求被拒绝并断开，服务继续可用
        {
            let mut s = UnixStream::connect(&path).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let junk = vec![b'x'; MAX_REQUEST as usize + 10];
            let _ = s.write_all(&junk);
            let mut reply = String::new();
            let _ = BufReader::new(s).read_line(&mut reply);
            assert!(reply.contains("请求过长"), "{reply}");
        }
        assert!(c.status().unwrap().running);

        // 连接记录：界面只能写入泄露类型
        let leak = eventlog::ConnEvent::now(eventlog::Kind::Leak, "ipc-test-leak");
        c.command(&Request::RecordEvent(Box::new(leak)), Duration::from_secs(5)).unwrap();
        assert!(c.events().unwrap().iter().any(|e| e.reason == "ipc-test-leak"));
        let fake = eventlog::ConnEvent::now(eventlog::Kind::Restore, "ipc-test-fake");
        assert!(c.command(&Request::RecordEvent(Box::new(fake)), Duration::from_secs(5)).is_err());
        assert!(!c.events().unwrap().iter().any(|e| e.reason == "ipc-test-fake"));

        c.command(&Request::Stop, Duration::from_secs(5)).unwrap();
        // 服务先回复再调用 stop()（stop 可能直接退出进程），所以这里稍等片刻
        let t = std::time::Instant::now();
        while !handler.stopped.load(Ordering::SeqCst) && t.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(handler.stopped.load(Ordering::SeqCst));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn filter_watch_over_socket() {
        let path = std::env::temp_dir().join(format!("eg-filter-{}.sock", std::process::id()));
        let listener = bind(&path).unwrap();
        let handler = Arc::new(TestHandler { cfg: Mutex::new(RawConfig::default()), stopped: AtomicBool::new(false) });
        serve(listener, handler, Arc::new(StatusHub::default()));
        let hub = filterfeed::hub();
        hub.set(FilterState { blocked: true, inspect_existing: true, apps: vec!["/Applications/A.app".into()], block_ipv6: false, rev: 0 });

        let (tx, rx) = std::sync::mpsc::channel();
        let c = Client::new(&path);
        let t = std::thread::spawn(move || {
            c.filter_watch(FilterHello { version: "9.9.9".into(), protocol: 1, caps: vec!["ack".into()] }, |s| {
                let _ = tx.send(s.clone());
                s.blocked // 收到放行后退出
            })
        });
        let first = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(first.blocked && first.apps == ["/Applications/A.app"]);
        assert!(first.rev > 0, "规则带版本号");
        assert_eq!(hub.connected().as_deref(), Some("9.9.9"));
        // 支持确认的扩展回复已应用的版本
        for _ in 0..100 {
            if hub.connected_hello().is_some_and(|h| h.applied == first.rev) {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(hub.connected_hello().unwrap().applied, first.rev);
        hub.set(FilterState::default());
        assert!(!rx.recv_timeout(Duration::from_secs(5)).unwrap().blocked);
        t.join().unwrap().unwrap();
        // 服务端在下一次写入（心跳）失败时注销
        for _ in 0..100 {
            if hub.connected().is_none() {
                break;
            }
            hub.set(FilterState { apps: vec![format!("{:?}", std::time::Instant::now())], ..Default::default() });
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(hub.connected(), None);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn request_json_shape() {
        assert_eq!(serde_json::to_string(&Request::Watch).unwrap(), "{\"cmd\":\"watch\"}");
        assert_eq!(serde_json::to_string(&Request::SetAutostart(true)).unwrap(), "{\"cmd\":\"set_autostart\",\"arg\":true}");
        assert!(Request::Stop.mutating() && !Request::Logs.mutating());
        assert_eq!(serde_json::to_string(&Request::FilterApplied(3)).unwrap(), "{\"cmd\":\"filter_applied\",\"arg\":3}");
        assert_eq!(
            serde_json::to_string(&Request::FilterWatch(FilterHello { version: "0.7.0".into(), ..Default::default() })).unwrap(),
            "{\"cmd\":\"filter_watch\",\"arg\":{\"version\":\"0.7.0\"}}"
        );
        assert_eq!(
            serde_json::to_string(&Reply::Filter(FilterState::default())).unwrap(),
            "{\"kind\":\"filter\",\"data\":{\"blocked\":false,\"inspect_existing\":false,\"apps\":[],\"block_ipv6\":false}}"
        );
    }
}
