//! 强制断开已有的 IPv4 TCP 连接（SetTcpEntry + DELETE_TCB，需要管理员）。
//!
//! WFP 的 ALE 层主要在建立连接时授权；新增过滤器后系统会对已有流量重新授权，
//! 这里再额外主动断开 IPv4 TCP 连接，使应用尽快感知断网。
//! 注意：Windows 只支持对 IPv4 TCP 执行该操作，IPv6 连接依赖 WFP 重新授权。

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::path::PathBuf;

use anyhow::{bail, Result};
use windows::Win32::NetworkManagement::IpHelper::*;
use windows::Win32::Networking::WinSock::AF_INET;

use super::procs::process_image_path;
use crate::discovery::normalize as normalize_path;

const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

fn tcp4_table() -> Result<Vec<MIB_TCPROW_OWNER_PID>> {
    let mut size = 0u32;
    for _ in 0..5 {
        let mut buf = vec![0u8; size as usize + 1024];
        size = buf.len() as u32;
        let r = unsafe {
            GetExtendedTcpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut size,
                false,
                AF_INET.0 as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        match r {
            0 => {
                let table = buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
                let n = unsafe { (*table).dwNumEntries } as usize;
                let rows = unsafe { std::slice::from_raw_parts((*table).table.as_ptr(), n) };
                return Ok(rows.to_vec());
            }
            ERROR_INSUFFICIENT_BUFFER => continue,
            c => bail!("GetExtendedTcpTable 失败: {c}"),
        }
    }
    bail!("GetExtendedTcpTable 缓冲区反复不足")
}

/// 断开属于 apps 的 IPv4 TCP 连接，返回成功断开的数量。
pub fn kill_tcp_connections(apps: &[PathBuf]) -> Result<usize> {
    let targets: HashSet<String> = apps.iter().map(|p| normalize_path(&p.to_string_lossy())).collect();
    kill_tcp_where(|path, _, _| path.is_some_and(|p| targets.contains(p)))
}

/// 断开满足条件的 IPv4 TCP 连接。`should_kill(规范化的进程路径, 远端地址, 远端端口)`；
/// 取不到路径的进程（系统进程等）路径为 None。返回成功断开的数量。
pub fn kill_tcp_where(mut should_kill: impl FnMut(Option<&str>, Ipv4Addr, u16) -> bool) -> Result<usize> {
    let mut paths: HashMap<u32, Option<String>> = HashMap::new();
    let mut killed = 0;

    for row in tcp4_table()? {
        let state = MIB_TCP_STATE(row.dwState as i32);
        if state == MIB_TCP_STATE_LISTEN || state == MIB_TCP_STATE_TIME_WAIT {
            continue;
        }
        // 地址与端口均为网络字节序
        let remote = Ipv4Addr::from(row.dwRemoteAddr.to_ne_bytes());
        let port = u16::from_be((row.dwRemotePort & 0xFFFF) as u16);
        let path = paths
            .entry(row.dwOwningPid)
            .or_insert_with(|| process_image_path(row.dwOwningPid).map(|p| normalize_path(&p)));
        if !should_kill(path.as_deref(), remote, port) {
            continue;
        }
        let kill = MIB_TCPROW_LH {
            Anonymous: MIB_TCPROW_LH_0 { State: MIB_TCP_STATE_DELETE_TCB },
            dwLocalAddr: row.dwLocalAddr,
            dwLocalPort: row.dwLocalPort,
            dwRemoteAddr: row.dwRemoteAddr,
            dwRemotePort: row.dwRemotePort,
        };
        match unsafe { SetTcpEntry(&kill) } {
            0 => killed += 1,
            c => log::debug!("SetTcpEntry 失败 pid={} code={c}", row.dwOwningPid),
        }
    }
    Ok(killed)
}
