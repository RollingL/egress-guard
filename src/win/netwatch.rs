//! 监听网卡、IP 地址和路由变化（IP Helper 通知），用于立即触发出口 IP 重新检测。

use std::ffi::c_void;
use std::sync::Mutex;

use anyhow::Result;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::IpHelper::*;
use windows::Win32::Networking::WinSock::AF_UNSPEC;

use crate::engine::NetNotifier;

/// 回调里用的通知端。注册失败后引擎会重新调用 start，这里每次换成最新的。
/// 一次网络变化通常触发好几个回调（一次 IPv6 地址变化 3–4 个），通知端把它们合并成一个事件。
static TX: Mutex<Option<NetNotifier>> = Mutex::new(None);

fn notify() {
    if let Some(n) = TX.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
        n.notify();
    }
}

unsafe extern "system" fn on_interface(
    _ctx: *const c_void,
    _row: *const MIB_IPINTERFACE_ROW,
    _t: MIB_NOTIFICATION_TYPE,
) {
    notify();
}

unsafe extern "system" fn on_address(
    _ctx: *const c_void,
    _row: *const MIB_UNICASTIPADDRESS_ROW,
    _t: MIB_NOTIFICATION_TYPE,
) {
    notify();
}

unsafe extern "system" fn on_route(
    _ctx: *const c_void,
    _row: *const MIB_IPFORWARD_ROW2,
    _t: MIB_NOTIFICATION_TYPE,
) {
    notify();
}

pub struct NetWatcher {
    handles: Vec<HANDLE>,
}

impl NetWatcher {
    pub fn start(tx: NetNotifier) -> Result<Self> {
        *TX.lock().unwrap_or_else(|e| e.into_inner()) = Some(tx);
        // 中途注册失败时 w 被丢弃，已经注册的通知随之取消
        let mut w = Self { handles: Vec::new() };
        unsafe {
            let mut h = HANDLE::default();
            NotifyIpInterfaceChange(AF_UNSPEC, Some(on_interface), None, false, &mut h).ok()?;
            w.handles.push(h);

            let mut h = HANDLE::default();
            NotifyUnicastIpAddressChange(AF_UNSPEC, Some(on_address), None, false, &mut h).ok()?;
            w.handles.push(h);

            // 路由变化可捕获 VPN 连接/断开导致的默认路由切换
            let mut h = HANDLE::default();
            NotifyRouteChange2(AF_UNSPEC, Some(on_route), std::ptr::null(), false, &mut h).ok()?;
            w.handles.push(h);
        }
        Ok(w)
    }
}

impl Drop for NetWatcher {
    fn drop(&mut self) {
        for h in self.handles.drain(..) {
            unsafe {
                let _ = CancelMibChangeNotify2(h);
            }
        }
    }
}
