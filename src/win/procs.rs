//! 进程枚举与进程路径查询。

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, FILETIME};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

#[derive(Debug, Clone)]
pub struct ProcInfo {
    pub pid: u32,
    pub name: String,
    pub path: String,
}

pub use crate::discovery::normalize as normalize_path;
use crate::discovery::ProcEntry;

/// 查询进程的 exe 路径和创建时间。`buf` 由调用方复用，避免每个进程都分配 64KB。
fn path_and_time(pid: u32, buf: &mut [u16]) -> (Option<String>, u64) {
    unsafe {
        let Ok(h) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return (None, 0);
        };
        let mut len = buf.len() as u32;
        let path = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len)
            .ok()
            .map(|_| String::from_utf16_lossy(&buf[..len as usize]));
        let (mut c, mut e, mut k, mut u) =
            (FILETIME::default(), FILETIME::default(), FILETIME::default(), FILETIME::default());
        let created = if GetProcessTimes(h, &mut c, &mut e, &mut k, &mut u).is_ok() {
            ((c.dwHighDateTime as u64) << 32) | c.dwLowDateTime as u64
        } else {
            0
        };
        let _ = CloseHandle(h);
        (path, created)
    }
}

/// 快照缓存的一项：同一 PID、同一父进程、同一创建时间（一次系统调用就能拿到全部进程的这三项）时
/// 直接复用路径，不再打开进程。
struct Cached {
    ppid: u32,
    created: u64,
    /// exe 路径；打不开的进程（受保护）为空。
    path: String,
    /// 能否打开这个进程。打不开时对外报告的创建时间为 0，识别时会断开祖先链（与以前一致）。
    opened: bool,
}

#[derive(Default)]
struct Scanner {
    cache: HashMap<u32, Cached>,
    /// NtQuerySystemInformation 的缓冲区（u64 保证对齐），按需增长、反复使用。
    buf: Vec<u64>,
    path_buf: Vec<u16>,
}

thread_local! {
    static SCANNER: RefCell<Scanner> = RefCell::new(Scanner::default());
}

/// 进程树快照（含父进程 ID、创建时间、exe 路径），用于识别子进程。
///
/// 每秒调用一次。用 NtQuerySystemInformation 一次取到全部进程的 PID、父 PID 和创建时间；
/// 三项都没变的进程直接用缓存，只对新进程调用 OpenProcess 查路径。已退出进程的缓存项随之清掉。
/// 系统调用失败时退回逐个打开进程的旧做法。
pub fn snapshot() -> Vec<ProcEntry> {
    SCANNER.with(|s| {
        let mut s = s.borrow_mut();
        match system_processes(&mut s.buf) {
            Some(list) => s.resolve(list),
            None => toolhelp_snapshot(&mut s.path_buf),
        }
    })
}

impl Scanner {
    fn resolve(&mut self, list: Vec<(u32, u32, u64)>) -> Vec<ProcEntry> {
        if self.path_buf.is_empty() {
            self.path_buf = vec![0u16; 32768];
        }
        let mut out = Vec::with_capacity(list.len());
        let mut next: HashMap<u32, Cached> = HashMap::with_capacity(list.len());
        for (pid, ppid, created) in list {
            if pid <= 4 {
                continue;
            }
            // PID 可能在两次快照之间被复用：父进程和创建时间都一致才算同一个进程
            let hit = self.cache.remove(&pid).filter(|c| c.ppid == ppid && c.created == created && created != 0);
            let entry = hit.unwrap_or_else(|| {
                let (path, opened) = match path_and_time(pid, &mut self.path_buf) {
                    (_, 0) => (None, false),
                    (path, _) => (path, true),
                };
                Cached { ppid, created, path: path.unwrap_or_default(), opened }
            });
            let created = if entry.opened { entry.created } else { 0 };
            out.push(ProcEntry { pid, ppid, created, path: entry.path.clone() });
            next.insert(pid, entry);
        }
        self.cache = next;
        out
    }
}

/// 全部进程的 (PID, 父 PID, 创建时间)。创建时间与 GetProcessTimes 的单位相同（FILETIME）。
fn system_processes(buf: &mut Vec<u64>) -> Option<Vec<(u32, u32, u64)>> {
    use windows::Wdk::System::SystemInformation::{NtQuerySystemInformation, SystemProcessInformation};
    use windows::Win32::System::WindowsProgramming::SYSTEM_PROCESS_INFORMATION;
    const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;
    if buf.is_empty() {
        buf.resize(64 * 1024, 0);
    }
    let mut tries = 0;
    loop {
        let bytes = (buf.len() * 8) as u32;
        let mut need = 0u32;
        let st = unsafe { NtQuerySystemInformation(SystemProcessInformation, buf.as_mut_ptr().cast(), bytes, &mut need) };
        if st.0 == STATUS_INFO_LENGTH_MISMATCH && tries < 4 {
            // 两次调用之间可能又多了进程：多留一些余量
            buf.resize((need as usize).max(bytes as usize * 2) / 8 + 4096, 0);
            tries += 1;
            continue;
        }
        if st.is_err() {
            return None;
        }
        break;
    }
    let mut out = Vec::with_capacity(512);
    let base = buf.as_ptr() as *const u8;
    let len = buf.len() * 8;
    let mut off = 0usize;
    loop {
        if off + std::mem::size_of::<SYSTEM_PROCESS_INFORMATION>() > len {
            break;
        }
        // SAFETY: 偏移在缓冲区内，系统按 8 字节对齐每一项
        let e = unsafe { &*(base.add(off) as *const SYSTEM_PROCESS_INFORMATION) };
        // Reserved1 的第 24..32 字节是 CreateTime，Reserved2 是 InheritedFromUniqueProcessId（父 PID）
        let created = u64::from_le_bytes(e.Reserved1[24..32].try_into().unwrap());
        out.push((e.UniqueProcessId.0 as usize as u32, e.Reserved2 as usize as u32, created));
        if e.NextEntryOffset == 0 {
            break;
        }
        off += e.NextEntryOffset as usize;
    }
    Some(out)
}

/// 退回的做法：ToolHelp 枚举，再逐个打开进程查路径和创建时间。
fn toolhelp_snapshot(buf: &mut Vec<u16>) -> Vec<ProcEntry> {
    if buf.is_empty() {
        buf.resize(32768, 0);
    }
    let mut out = Vec::new();
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return out;
        };
        let mut e = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
        let mut ok = Process32FirstW(snap, &mut e).is_ok();
        while ok {
            let pid = e.th32ProcessID;
            if pid > 4 {
                // 无法打开的进程（受保护）创建时间未知，记为 0，识别时会断开祖先链
                let (path, created) = path_and_time(pid, buf);
                out.push(ProcEntry { pid, ppid: e.th32ParentProcessID, created, path: path.unwrap_or_default() });
            }
            ok = Process32NextW(snap, &mut e).is_ok();
        }
        let _ = CloseHandle(snap);
    }
    out
}

/// 查询进程的完整 exe 路径。
pub fn process_image_path(pid: u32) -> Option<String> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = vec![0u16; 32768];
        let mut len = buf.len() as u32;
        let r = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len);
        let _ = CloseHandle(h);
        r.ok()?;
        Some(String::from_utf16_lossy(&buf[..len as usize]))
    }
}

/// 列出正在运行、能取到路径的进程（按路径去重，按名称排序）。
pub fn list_processes() -> Vec<ProcInfo> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return out;
        };
        let mut e = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut ok = Process32FirstW(snap, &mut e).is_ok();
        while ok {
            let pid = e.th32ProcessID;
            let n = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(e.szExeFile.len());
            let name = String::from_utf16_lossy(&e.szExeFile[..n]);
            if pid > 4 {
                if let Some(path) = process_image_path(pid) {
                    if seen.insert(normalize_path(&path)) {
                        out.push(ProcInfo { pid, name, path });
                    }
                }
            }
            ok = Process32NextW(snap, &mut e).is_ok();
        }
        let _ = CloseHandle(snap);
    }
    out.sort_by_key(|p| p.name.to_lowercase());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 系统调用取到的父 PID、创建时间与逐个打开进程查到的一致（结构体里保留字段的偏移没有取错）。
    #[test]
    fn system_snapshot_matches_per_process_query() {
        let me = std::process::id();
        let list = system_processes(&mut Vec::new()).expect("NtQuerySystemInformation");
        assert!(list.len() > 10, "{}", list.len());
        let &(_, ppid, created) = list.iter().find(|(p, _, _)| *p == me).expect("找不到本进程");
        let (path, want) = path_and_time(me, &mut vec![0u16; 32768]);
        assert_eq!(created, want);
        assert!(ppid > 0 && list.iter().any(|(p, _, _)| *p == ppid), "父进程 {ppid}");
        let snap = snapshot();
        let e = snap.iter().find(|e| e.pid == me).unwrap();
        assert_eq!(normalize_path(&e.path), normalize_path(&path.unwrap()));
        assert_eq!((e.ppid, e.created), (ppid, created));
        // 第二次走缓存，结果一样
        let again = snapshot();
        let e2 = again.iter().find(|e| e.pid == me).unwrap();
        assert_eq!((e2.ppid, e2.created, &e2.path), (e.ppid, e.created, &e.path));
    }
}
