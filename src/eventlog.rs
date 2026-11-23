//! 连接记录：每次阻断、恢复，以及自动泄露测试发现的泄露，带时间、原因、当时的出口 IP。
//!
//! 记录保存在配置文件旁的 `connection-log.jsonl`（每行一条 JSON），程序重启后仍在。
//! 只保留最近 [`MAX_EVENTS`] 条；文件超过两倍时整体重写一次。
//! macOS 上由后台服务写入，界面通过本地套接字读取。

use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};

/// 最多保留的记录数。
pub const MAX_EVENTS: usize = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// 切换为阻断。
    Block,
    /// 恢复放行。
    Restore,
    /// 自动泄露测试发现泄露。
    Leak,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Block => "阻断",
            Kind::Restore => "恢复",
            Kind::Leak => "泄露",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnEvent {
    /// 本地时间 "YYYY-MM-DD HH:MM:SS"。
    pub time: String,
    pub kind: Kind,
    /// 原因，例如「出口 IP 不在白名单」「VPN 断开（utun4）」。
    pub reason: String,
    /// 当时的出口 IP。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<IpAddr>,
    /// 当时的 IPv6 出口（与 egress 不同时）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_v6: Option<IpAddr>,
    /// 阻断范围：「受控应用」「全部网络」「IPv6」等。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub scope: String,
}

impl ConnEvent {
    pub fn now(kind: Kind, reason: impl Into<String>) -> Self {
        Self {
            time: crate::logbuf::now_string(),
            kind,
            reason: reason.into(),
            egress: None,
            egress_v6: None,
            scope: String::new(),
        }
    }
}

/// 记录本（进程内唯一的实例由 [`global`] 提供；测试可以单独创建）。
#[derive(Default)]
pub struct EventLog {
    path: Option<PathBuf>,
    items: VecDeque<ConnEvent>,
    /// 文件里的行数（含无法解析的行），用来决定何时重写。
    file_lines: usize,
}

impl EventLog {
    /// 打开（或创建）记录文件，载入最近的记录。
    pub fn open(path: &Path) -> Self {
        let mut me = Self { path: Some(path.to_path_buf()), ..Default::default() };
        if let Ok(text) = std::fs::read_to_string(path) {
            for line in text.lines().filter(|l| !l.trim().is_empty()) {
                me.file_lines += 1;
                if let Ok(e) = serde_json::from_str::<ConnEvent>(line) {
                    me.push_mem(e);
                }
            }
        }
        me
    }

    fn push_mem(&mut self, e: ConnEvent) {
        if self.items.len() >= MAX_EVENTS {
            self.items.pop_front();
        }
        self.items.push_back(e);
    }

    pub fn record(&mut self, e: ConnEvent) {
        let line = serde_json::to_string(&e).unwrap_or_default();
        self.push_mem(e);
        let Some(path) = &self.path else { return };
        if self.file_lines >= 2 * MAX_EVENTS {
            self.rewrite();
            return;
        }
        let r = OpenOptions::new().create(true).append(true).open(path).and_then(|mut f| writeln!(f, "{line}"));
        match r {
            Ok(()) => self.file_lines += 1,
            Err(e) => log::warn!("无法写入连接记录 {}: {e}", path.display()),
        }
    }

    /// 只保留内存里的最近记录，重写文件。
    fn rewrite(&mut self) {
        let Some(path) = &self.path else { return };
        let text: String =
            self.items.iter().filter_map(|e| serde_json::to_string(e).ok()).map(|l| l + "\n").collect();
        match std::fs::write(path, text) {
            Ok(()) => self.file_lines = self.items.len(),
            Err(e) => log::warn!("无法写入连接记录 {}: {e}", path.display()),
        }
    }

    pub fn recent(&self) -> Vec<ConnEvent> {
        self.items.iter().cloned().collect()
    }

    pub fn clear(&mut self) {
        self.items.clear();
        self.rewrite();
    }
}

fn global() -> &'static Mutex<EventLog> {
    static LOG: OnceLock<Mutex<EventLog>> = OnceLock::new();
    LOG.get_or_init(|| Mutex::new(EventLog::default()))
}

/// 指定记录文件（程序启动时调用一次）。之前记在内存里的会一并写入。
pub fn init(path: &Path) {
    let mut g = global().lock().unwrap();
    let pending: Vec<ConnEvent> = g.items.drain(..).collect();
    *g = EventLog::open(path);
    for e in pending {
        g.record(e);
    }
}

pub fn record(e: ConnEvent) {
    global().lock().unwrap().record(e);
}

pub fn recent() -> Vec<ConnEvent> {
    global().lock().unwrap().recent()
}

pub fn clear() {
    global().lock().unwrap().clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persists_and_trims() {
        let path = std::env::temp_dir().join(format!("eg-events-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let mut l = EventLog::open(&path);
            let mut e = ConnEvent::now(Kind::Block, "出口 IP 不在白名单");
            e.egress = Some("198.51.100.7".parse().unwrap());
            l.record(e);
            l.record(ConnEvent::now(Kind::Restore, "出口 IP 回到白名单"));
        }
        // 无法解析的行跳过
        OpenOptions::new().append(true).open(&path).unwrap().write_all(b"garbage\n").unwrap();
        let mut l = EventLog::open(&path);
        let r = l.recent();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].kind, Kind::Block);
        assert_eq!(r[0].egress, Some("198.51.100.7".parse().unwrap()));
        assert_eq!(r[1].reason, "出口 IP 回到白名单");

        for i in 0..(2 * MAX_EVENTS + 5) {
            l.record(ConnEvent::now(Kind::Leak, format!("{i}")));
        }
        assert_eq!(l.recent().len(), MAX_EVENTS);
        assert_eq!(l.recent().last().unwrap().reason, format!("{}", 2 * MAX_EVENTS + 4));
        let lines = std::fs::read_to_string(&path).unwrap().lines().count();
        assert!(lines <= 2 * MAX_EVENTS, "{lines}");
        // 重新打开后最新的那条还在
        assert_eq!(EventLog::open(&path).recent().last(), l.recent().last());

        l.clear();
        assert!(EventLog::open(&path).recent().is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn json_shape() {
        let e = ConnEvent { time: "t".into(), kind: Kind::Restore, reason: "r".into(), egress: None, egress_v6: None, scope: String::new() };
        assert_eq!(serde_json::to_string(&e).unwrap(), r#"{"time":"t","kind":"restore","reason":"r"}"#);
    }
}
