//! 进程枚举与进程路径查询（libproc）。

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ffi::c_void;

pub use crate::discovery::normalize as normalize_path;
use crate::discovery::ProcEntry;

#[derive(Debug, Clone)]
pub struct ProcInfo {
    pub pid: u32,
    pub name: String,
    pub path: String,
}

const PATH_MAX: usize = 4 * libc::MAXPATHLEN as usize;

fn all_pids() -> Vec<i32> {
    let n = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    if n <= 0 {
        return Vec::new();
    }
    let mut pids = vec![0i32; n as usize + 64];
    let bytes = (pids.len() * std::mem::size_of::<i32>()) as libc::c_int;
    let n = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast::<c_void>(), bytes) };
    pids.truncate(n.max(0) as usize);
    pids
}

/// 进程的可执行文件完整路径。
pub fn process_image_path(pid: u32) -> Option<String> {
    image_path(pid, &mut vec![0u8; PATH_MAX])
}

fn image_path(pid: u32, buf: &mut [u8]) -> Option<String> {
    let n = unsafe { libc::proc_pidpath(pid as i32, buf.as_mut_ptr().cast(), buf.len() as u32) };
    (n > 0).then(|| String::from_utf8_lossy(&buf[..n as usize]).into_owned())
}

/// (父进程 ID, 创建时间（微秒）)
fn parent_and_start(pid: i32) -> Option<(u32, u64)> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    let n = unsafe {
        libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&mut info as *mut libc::proc_bsdinfo).cast(), size)
    };
    (n == size).then(|| (info.pbi_ppid, info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec))
}

thread_local! {
    /// PID → (父 PID, 创建时间, 路径)：父进程和创建时间都没变时直接复用路径，不再调用 proc_pidpath。
    static CACHE: RefCell<HashMap<u32, (u32, u64, String)>> = RefCell::new(HashMap::new());
}

/// 进程树快照（含父进程 ID、创建时间、可执行文件路径），用于识别子进程。
///
/// 每秒调用一次。父 PID 与创建时间每次都查（判断 PID 复用要用），路径只对新进程查；
/// 已退出进程的缓存项随之清掉。
pub fn snapshot() -> Vec<ProcEntry> {
    CACHE.with(|c| {
        let mut cache = c.borrow_mut();
        let mut next = HashMap::with_capacity(cache.len());
        let mut buf = Vec::new();
        let out = all_pids()
            .into_iter()
            .filter(|&pid| pid > 1)
            .filter_map(|pid| {
                let (ppid, created) = parent_and_start(pid)?;
                let pid = pid as u32;
                let path = match cache.remove(&pid) {
                    Some((pp, cr, path)) if pp == ppid && cr == created => path,
                    _ => {
                        if buf.is_empty() {
                            buf = vec![0u8; PATH_MAX];
                        }
                        image_path(pid, &mut buf).unwrap_or_default()
                    }
                };
                next.insert(pid, (ppid, created, path.clone()));
                Some(ProcEntry { pid, ppid, created, path })
            })
            .collect();
        *cache = next;
        out
    })
}

/// 显示用的程序名：可执行文件名（.app 包里的辅助程序如 "Google Chrome Helper (Renderer)" 也显示自己的名字）。
fn display_name(path: &str) -> String {
    path.rsplit('/').next().unwrap_or(path).to_owned()
}

/// 列出正在运行、能取到路径的进程（按路径去重，按名称排序）。
pub fn list_processes() -> Vec<ProcInfo> {
    let mut seen = HashSet::new();
    let mut out: Vec<ProcInfo> = all_pids()
        .into_iter()
        .filter(|&pid| pid > 1)
        .filter_map(|pid| {
            let path = process_image_path(pid as u32)?;
            seen.insert(normalize_path(&path)).then(|| ProcInfo { pid: pid as u32, name: display_name(&path), path })
        })
        .collect();
    out.sort_by_key(|p| p.name.to_lowercase());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_reuses_paths_for_unchanged_processes() {
        let me = std::process::id();
        let first = snapshot();
        let e = first.iter().find(|e| e.pid == me).expect("找不到本进程");
        let exe = std::env::current_exe().unwrap();
        assert_eq!(normalize_path(&e.path), normalize_path(&exe.to_string_lossy()));
        let second = snapshot();
        let e2 = second.iter().find(|e| e.pid == me).unwrap();
        assert_eq!((e2.ppid, e2.created, &e2.path), (e.ppid, e.created, &e.path));
        assert!(CACHE.with(|c| c.borrow().contains_key(&me)));
    }
}
