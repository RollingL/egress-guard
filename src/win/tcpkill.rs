//! 强制断开受控应用已有的 IPv4 TCP 连接（SetTcpEntry + DELETE_TCB，需要管理员）。
//!
//! WFP 的 ALE 层主要在建立连接时授权；新增过滤器后系统会对已有流量重新授权，
//! 这里再额外主动断开 IPv4 TCP 连接，使应用尽快感知断网。
//! 注意：Windows 只支持对 IPv4 TCP 执行该操作，IPv6 连接依赖 WFP 重新授权。

use std::collections::HashMap;
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
    let targets: Vec<String> =
        apps.iter().map(|p| normalize_path(&p.to_string_lossy())).collect();
    let mut pid_match: HashMap<u32, bool> = HashMap::new();
    let mut killed = 0;

    for row in tcp4_table()? {
        let state = MIB_TCP_STATE(row.dwState as i32);
        if state == MIB_TCP_STATE_LISTEN || state == MIB_TCP_STATE_TIME_WAIT {
            continue;
        }
        let is_target = *pid_match.entry(row.dwOwningPid).or_insert_with(|| {
            process_image_path(row.dwOwningPid)
                .map(|p| targets.contains(&normalize_path(&p)))
                .unwrap_or(false)
        });
        if !is_target {
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
