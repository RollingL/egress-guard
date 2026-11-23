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

/// 进程的创建时间；打不开时为 0。
fn created_time(pid: u32) -> u64 {
    unsafe {
        let Ok(h) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return 0;
        };
        let (mut c, mut e, mut k, mut u) =
            (FILETIME::default(), FILETIME::default(), FILETIME::default(), FILETIME::default());
        let created = if GetProcessTimes(h, &mut c, &mut e, &mut k, &mut u).is_ok() {
            ((c.dwHighDateTime as u64) << 32) | c.dwLowDateTime as u64
        } else {
            0
        };
        let _ = CloseHandle(h);
        created
    }
}

/// 快照缓存的一项：同一 PID、同一父进程、同一 exe 名、同一创建时间时直接复用路径，不再查询路径。
struct Cached {
    ppid: u32,
    name: [u16; 260],
    path: String,
    created: u64,
}

thread_local! {
    static CACHE: RefCell<HashMap<u32, Cached>> = RefCell::new(HashMap::new());
}

/// 进程树快照（含父进程 ID、创建时间、exe 路径），用于识别子进程。
///
/// 每秒调用一次。已见过的进程（PID、父 PID、exe 名都没变）直接用缓存，
/// 只对新进程调用 OpenProcess；已退出进程的缓存项随之清掉。
pub fn snapshot() -> Vec<ProcEntry> {
    CACHE.with(|c| snapshot_cached(&mut c.borrow_mut()))
}

fn snapshot_cached(cache: &mut HashMap<u32, Cached>) -> Vec<ProcEntry> {
    let mut out = Vec::new();
    let mut buf = vec![0u16; 32768];
    let mut next: HashMap<u32, Cached> = HashMap::with_capacity(cache.len());
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
            if pid > 4 {
                let ppid = e.th32ParentProcessID;
                // PID 可能在两次快照之间被同名的新进程复用（路径可能不同）：创建时间也要一致。
                // 创建时间未知（0）的项不复用，每次重新查询
                let hit = cache
                    .remove(&pid)
                    .filter(|c| c.ppid == ppid && c.name == e.szExeFile && c.created != 0)
                    .filter(|c| created_time(pid) == c.created);
                let entry = hit.unwrap_or_else(|| {
                    // 无法打开的进程（受保护）创建时间未知，记为 0，识别时会断开祖先链
                    let (path, created) = path_and_time(pid, &mut buf);
                    Cached { ppid, name: e.szExeFile, path: path.unwrap_or_default(), created }
                });
                out.push(ProcEntry { pid, ppid, created: entry.created, path: entry.path.clone() });
                next.insert(pid, entry);
            }
            ok = Process32NextW(snap, &mut e).is_ok();
        }
        let _ = CloseHandle(snap);
    }
    *cache = next;
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
