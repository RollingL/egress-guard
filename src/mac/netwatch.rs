//! 监听网卡、IP 地址和默认路由的变化（PF_ROUTE 路由套接字），用于立即触发出口 IP 重新检测。
//!
//! 路由套接字很"吵"：ARP/邻居表项、按目的地克隆的主机路由都会产生消息。这里只关心
//! 地址增删、网卡状态变化和非主机路由的增删改；AirDrop 等使用的 awdl/llw 接口频繁开关，忽略。

use std::ffi::CStr;

use anyhow::{bail, Result};

use crate::engine::NetNotifier;

const RTM_ADD: u8 = 0x1;
const RTM_DELETE: u8 = 0x2;
const RTM_CHANGE: u8 = 0x3;
const RTM_NEWADDR: u8 = 0xc;
const RTM_DELADDR: u8 = 0xd;
const RTM_IFINFO: u8 = 0xe;

const RTF_HOST: i32 = 0x4;
const RTF_LLINFO: i32 = 0x400;
const RTF_WASCLONED: i32 = 0x20000;

/// 监听线程的句柄（线程随进程结束）。
pub struct Watcher;

/// 被忽略的接口名前缀。
fn ignored_interface(name: &str) -> bool {
    ["awdl", "llw", "anpi", "ap", "bridge", "gif", "stf"].iter().any(|p| name.starts_with(p))
}

fn if_name(index: u16) -> String {
    let mut buf = [0 as libc::c_char; libc::IF_NAMESIZE];
    let p = unsafe { libc::if_indextoname(index as libc::c_uint, buf.as_mut_ptr()) };
    if p.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(buf.as_ptr()) }.to_string_lossy().into_owned()
}

fn u16_at(b: &[u8], off: usize) -> u16 {
    u16::from_ne_bytes([b[off], b[off + 1]])
}

fn i32_at(b: &[u8], off: usize) -> i32 {
    i32::from_ne_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// 判断一条路由消息是否值得重新检测出口 IP。
fn relevant(msg: &[u8]) -> bool {
    if msg.len() < 14 {
        return false;
    }
    match msg[3] {
        // rt_msghdr：u16 msglen, u8 version, u8 type, u16 index, (2 字节填充), i32 flags
        RTM_ADD | RTM_DELETE | RTM_CHANGE => {
            let flags = i32_at(msg, 8);
            flags & (RTF_HOST | RTF_LLINFO | RTF_WASCLONED) == 0 && !ignored_interface(&if_name(u16_at(msg, 4)))
        }
        // ifa_msghdr / if_msghdr：u16 msglen, u8 version, u8 type, i32 addrs, i32 flags, u16 index
        RTM_NEWADDR | RTM_DELADDR | RTM_IFINFO => !ignored_interface(&if_name(u16_at(msg, 12))),
        _ => false,
    }
}

pub fn start(tx: NetNotifier) -> Result<Watcher> {
    let fd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_UNSPEC) };
    if fd < 0 {
        bail!("无法打开路由套接字: {}", std::io::Error::last_os_error());
    }
    std::thread::Builder::new()
        .name("netwatch".into())
        .spawn(move || {
            let mut buf = vec![0u8; 8192];
            loop {
                let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
                if n < 0 {
                    let e = std::io::Error::last_os_error();
                    if e.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    log::warn!("路由套接字读取失败，停止监听网络变化: {e}");
                    break;
                }
                let msg = &buf[..n as usize];
                if relevant(msg) {
                    log::debug!("路由消息 type={} 触发网络变化", msg[3]);
                    // 一连串路由消息只给引擎发一个事件（见 NetNotifier）
                    if !tx.notify() {
                        break;
                    }
                }
            }
            unsafe { libc::close(fd) };
        })?;
    Ok(Watcher)
}
