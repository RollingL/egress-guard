//! 日志：输出到 stderr / 日志文件，并保留最近若干行供界面显示。

use std::collections::VecDeque;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use log::{Level, LevelFilter, Log, Metadata, Record};

const MAX_LINES: usize = 500;

/// 日志文件超过这个大小时轮转：当前文件改名为 `<文件名>.1`（覆盖上一份），再新建一个。
/// 后台服务可能几个月不重启，以前日志文件只增不减。
const MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;

/// 日志文件及已写入的字节数。
struct FileSink {
    path: PathBuf,
    file: Option<File>,
    written: u64,
    limit: u64,
}

impl FileSink {
    fn create(path: &Path, limit: u64) -> Option<Self> {
        let file = File::create(path).ok()?;
        Some(Self { path: path.to_path_buf(), file: Some(file), written: 0, limit })
    }

    fn write_line(&mut self, line: &str) {
        if self.written >= self.limit {
            self.rotate();
        }
        if let Some(f) = self.file.as_mut() {
            if writeln!(f, "{line}").is_ok() {
                self.written += line.len() as u64 + 1;
            }
        }
    }

    fn rotate(&mut self) {
        self.file = None; // 先关闭（Windows 上打开的文件不能改名）
        let mut old = self.path.clone().into_os_string();
        old.push(".1");
        let _ = std::fs::rename(&self.path, &old);
        // 新建失败时不再写文件（stderr 和界面里的日志照常）
        self.file = File::create(&self.path).ok();
        self.written = 0;
    }
}

struct Logger {
    level: LevelFilter,
    stderr: bool,
    file: Mutex<Option<FileSink>>,
    lines: Mutex<VecDeque<String>>,
}

static LOGGER: std::sync::OnceLock<Logger> = std::sync::OnceLock::new();

impl Log for Logger {
    fn enabled(&self, m: &Metadata) -> bool {
        // 本程序按配置级别输出；第三方库（ureq 等）只输出警告以上
        if m.target().starts_with("egress_guard") {
            m.level() <= self.level
        } else {
            m.level() <= Level::Warn
        }
    }

    fn log(&self, r: &Record) {
        if !self.enabled(r.metadata()) {
            return;
        }
        let line = format!("{} {:<5} {}", now_string(), r.level(), r.args());
        if self.stderr {
            eprintln!("{line}");
        }
        if let Some(f) = self.file.lock().unwrap().as_mut() {
            f.write_line(&line);
        }
        let mut lines = self.lines.lock().unwrap();
        if lines.len() >= MAX_LINES {
            lines.pop_front();
        }
        lines.push_back(line);
    }

    fn flush(&self) {}
}

/// 初始化全局日志。`file` 为 Some 时同时写入（覆盖）该文件，超过 5 MB 时轮转一次。
pub fn init(level: &str, stderr: bool, file: Option<&Path>) {
    let level = level.parse().unwrap_or(LevelFilter::Info);
    let file = file.and_then(|p| FileSink::create(p, MAX_FILE_BYTES));
    let logger = LOGGER.get_or_init(|| Logger {
        level,
        stderr,
        file: Mutex::new(file),
        lines: Mutex::new(VecDeque::new()),
    });
    let _ = log::set_logger(logger);
    log::set_max_level(LevelFilter::Trace);
}

/// 最近的日志行。
pub fn recent_lines() -> Vec<String> {
    LOGGER
        .get()
        .map(|l| l.lines.lock().unwrap().iter().cloned().collect())
        .unwrap_or_default()
}

pub fn clear() {
    if let Some(l) = LOGGER.get() {
        l.lines.lock().unwrap().clear();
    }
}

/// 当前本地时间 "YYYY-MM-DD HH:MM:SS"。
pub fn now_string() -> String {
    let (y, mo, d, h, mi, s) = local_now();
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}")
}

/// 当前本地时间 "HH:MM:SS"。
pub fn now_hms() -> String {
    let (_, _, _, h, mi, s) = local_now();
    format!("{h:02}:{mi:02}:{s:02}")
}

#[cfg(windows)]
fn local_now() -> (u32, u32, u32, u32, u32, u32) {
    let t = unsafe { windows::Win32::System::SystemInformation::GetLocalTime() };
    (
        t.wYear as u32,
        t.wMonth as u32,
        t.wDay as u32,
        t.wHour as u32,
        t.wMinute as u32,
        t.wSecond as u32,
    )
}

/// macOS 等 Unix：按系统时区（/etc/localtime，launchd 启动的后台服务也一样）换算。
#[cfg(unix)]
fn local_now() -> (u32, u32, u32, u32, u32, u32) {
    let t: libc::time_t = unsafe { libc::time(std::ptr::null_mut()) };
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
        return utc_now();
    }
    (
        (tm.tm_year + 1900) as u32,
        (tm.tm_mon + 1) as u32,
        tm.tm_mday as u32,
        tm.tm_hour as u32,
        tm.tm_min as u32,
        tm.tm_sec as u32,
    )
}

#[cfg(not(any(windows, unix)))]
fn local_now() -> (u32, u32, u32, u32, u32, u32) {
    utc_now()
}

/// UTC 时间（取不到本地时区时退回）。
#[cfg(not(windows))]
fn utc_now() -> (u32, u32, u32, u32, u32, u32) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    // 公历换算（Howard Hinnant 算法）
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    (
        y as u32,
        m as u32,
        d as u32,
        (rem / 3600) as u32,
        (rem % 3600 / 60) as u32,
        (rem % 60) as u32,
    )
}

#[cfg(test)]
mod rotate_tests {
    use super::*;

    #[test]
    fn log_file_rotates_at_limit() {
        let dir = std::env::temp_dir().join(format!("eg-logrot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.log");
        let mut sink = FileSink::create(&path, 1024).unwrap();
        for i in 0..100 {
            sink.write_line(&format!("{i:03} {}", "x".repeat(40)));
        }
        let mut names: Vec<String> =
            std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        assert_eq!(names, vec!["t.log", "t.log.1"]);
        let total: u64 = ["t.log", "t.log.1"].iter().map(|n| std::fs::metadata(dir.join(n)).unwrap().len()).sum();
        assert!(total <= 2 * 1024 + 64, "{total}");
        assert!(std::fs::read_to_string(&path).unwrap().contains("099 "), "最新的行在当前文件里");
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// 本地时间 = UTC + 系统时区的偏移（以前非 Windows 直接显示 UTC，却称本地时间）。
    #[test]
    fn local_time_follows_system_timezone() {
        let t: libc::time_t = unsafe { libc::time(std::ptr::null_mut()) };
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        assert!(!unsafe { libc::localtime_r(&t, &mut tm) }.is_null());
        let off = tm.tm_gmtoff as i64;
        let (_, _, _, lh, lm, _) = local_now();
        let (_, _, _, uh, um, _) = utc_now();
        let local = (lh * 60 + lm) as i64;
        let utc = (uh * 60 + um) as i64;
        let diff = (local - utc - off / 60).rem_euclid(24 * 60);
        // 两次取时间之间可能跨过一分钟
        assert!(diff == 0 || diff == 1 || diff == 24 * 60 - 1, "local {lh}:{lm} utc {uh}:{um} off {off}");
    }
}
