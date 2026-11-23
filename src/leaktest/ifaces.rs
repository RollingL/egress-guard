//! 列出本机已启用网卡上的 IP 地址（不含回环）。

use std::net::IpAddr;

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct IfAddr {
    /// 网卡名称（Windows 为「以太网」「WLAN」这样的友好名称，macOS 为 en0、utun3 等）。
    pub name: String,
    pub ip: IpAddr,
}

/// 一块已启用的网卡（不含回环）。
#[derive(Debug, Clone, PartialEq)]
pub struct Adapter {
    /// 与 [`IfAddr::name`] 相同。
    pub name: String,
    /// Windows 上的网卡描述（如「WireGuard Tunnel」「TAP-Windows Adapter V9」）；其他平台为空。
    pub description: String,
    /// Windows 上的接口类型（IF_TYPE_*）；其他平台为 0。
    pub if_type: u32,
    pub addrs: Vec<IpAddr>,
}

/// 已启用网卡上的地址（不含回环）。
pub fn list() -> Vec<IfAddr> {
    adapters()
        .into_iter()
        .flat_map(|a| {
            let name = a.name;
            a.addrs.into_iter().map(move |ip| IfAddr { name: name.clone(), ip })
        })
        .collect()
}

/// 已启用的网卡；枚举失败时返回空列表（泄露测试等用途）。
pub fn adapters() -> Vec<Adapter> {
    try_adapters().unwrap_or_default()
}

/// 已启用的网卡；系统调用失败时返回 None（「不知道」，而不是「没有网卡」）。
#[cfg(unix)]
pub fn try_adapters() -> Option<Vec<Adapter>> {
    use std::ffi::CStr;
    use std::net::{Ipv4Addr, Ipv6Addr};

    let mut out: Vec<Adapter> = Vec::new();
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs 分配的链表在 freeifaddrs 之前一直有效；只读取其中的地址结构。
    unsafe {
        if libc::getifaddrs(&mut ifap) != 0 {
            return None;
        }
        let mut p = ifap;
        while !p.is_null() {
            let i = &*p;
            p = i.ifa_next;
            let flags = i.ifa_flags as libc::c_int;
            if i.ifa_addr.is_null() || flags & libc::IFF_UP == 0 || flags & libc::IFF_LOOPBACK != 0 {
                continue;
            }
            let ip = match (*i.ifa_addr).sa_family as libc::c_int {
                libc::AF_INET => {
                    let sa = &*(i.ifa_addr as *const libc::sockaddr_in);
                    IpAddr::V4(Ipv4Addr::from(u32::from_be(sa.sin_addr.s_addr)))
                }
                libc::AF_INET6 => {
                    let sa = &*(i.ifa_addr as *const libc::sockaddr_in6);
                    IpAddr::V6(Ipv6Addr::from(sa.sin6_addr.s6_addr))
                }
                _ => continue,
            };
            let name = CStr::from_ptr(i.ifa_name).to_string_lossy().into_owned();
            match out.iter_mut().find(|a| a.name == name) {
                Some(a) => a.addrs.push(ip),
                None => out.push(Adapter { name, description: String::new(), if_type: 0, addrs: vec![ip] }),
            }
        }
        libc::freeifaddrs(ifap);
    }
    Some(out)
}

#[cfg(windows)]
pub fn try_adapters() -> Option<Vec<Adapter>> {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use windows::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
        IF_TYPE_SOFTWARE_LOOPBACK, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6};

    let mut out = Vec::new();
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 32 * 1024;
    let mut buf: Vec<u64>;
    let mut tries = 0;
    // SAFETY: 缓冲区按 8 字节对齐、大小由系统告知；链表只在 buf 存活期间读取。
    unsafe {
        loop {
            buf = vec![0u64; (size as usize).div_ceil(8)];
            let r = GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                flags,
                None,
                Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
                &mut size,
            );
            if r == ERROR_BUFFER_OVERFLOW.0 && tries < 3 {
                tries += 1;
                continue;
            }
            if r != 0 {
                log::warn!("GetAdaptersAddresses 失败：{r}");
                return None;
            }
            break;
        }
        let mut p = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !p.is_null() {
            let a = &*p;
            p = a.Next;
            if a.OperStatus != IfOperStatusUp || a.IfType == IF_TYPE_SOFTWARE_LOOPBACK {
                continue;
            }
            let mut adapter = Adapter {
                name: a.FriendlyName.to_string().unwrap_or_default(),
                description: a.Description.to_string().unwrap_or_default(),
                if_type: a.IfType,
                addrs: Vec::new(),
            };
            let mut u = a.FirstUnicastAddress;
            while !u.is_null() {
                let ua = &*u;
                u = ua.Next;
                let sa = ua.Address.lpSockaddr;
                if sa.is_null() {
                    continue;
                }
                let ip = if (*sa).sa_family == AF_INET {
                    let v = &*(sa as *const SOCKADDR_IN);
                    IpAddr::V4(Ipv4Addr::from(u32::from_be(v.sin_addr.S_un.S_addr)))
                } else if (*sa).sa_family == AF_INET6 {
                    let v = &*(sa as *const SOCKADDR_IN6);
                    IpAddr::V6(Ipv6Addr::from(v.sin6_addr.u.Byte))
                } else {
                    continue;
                };
                adapter.addrs.push(ip);
            }
            out.push(adapter);
        }
    }
    Some(out)
}

#[cfg(not(any(unix, windows)))]
pub fn try_adapters() -> Option<Vec<Adapter>> {
    Some(Vec::new())
}

#[cfg(test)]
mod tests {
    #[test]
    fn lists_without_loopback() {
        // 结果取决于运行环境，这里只检查不会出现回环地址
        for a in super::list() {
            assert!(!a.ip.is_loopback(), "{a:?}");
        }
    }
}
