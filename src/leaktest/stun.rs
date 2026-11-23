//! 最小的 STUN 客户端（RFC 5389 绑定请求），用于取得 UDP 的公网映射地址。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};

const MAGIC: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// 早期草案使用的 XOR-MAPPED-ADDRESS 编号，个别老服务器仍在用。
const ATTR_XOR_MAPPED_ADDRESS_OLD: u16 = 0x8020;

/// 拆分「主机:端口」（IPv6 写成 `[2001:db8::1]:3478`）。
pub fn split_host_port(s: &str) -> Result<(String, u16)> {
    let s = s.trim();
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (h, p) = rest.split_once("]:").context("IPv6 地址要写成 [地址]:端口")?;
        (h, p)
    } else {
        s.rsplit_once(':').context("需要写成 主机:端口，例如 stun.l.google.com:19302")?
    };
    if host.is_empty() || host.contains(char::is_whitespace) || (!s.starts_with('[') && host.contains(':')) {
        bail!("主机名有误");
    }
    let port: u16 = port.parse().ok().filter(|p| *p != 0).context("端口有误")?;
    Ok((host.to_owned(), port))
}

/// 解析 STUN 服务器地址。
pub fn resolve(server: &str) -> Result<Vec<SocketAddr>> {
    let (host, port) = split_host_port(server)?;
    let addrs: Vec<SocketAddr> =
        (host.as_str(), port).to_socket_addrs().with_context(|| format!("无法解析 {host}"))?.collect();
    if addrs.is_empty() {
        bail!("无法解析 {host}");
    }
    Ok(addrs)
}

/// 构造绑定请求（不带任何属性）。
pub fn binding_request(txid: &[u8; 12]) -> [u8; 20] {
    let mut m = [0u8; 20];
    m[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    // 长度为 0
    m[4..8].copy_from_slice(&MAGIC.to_be_bytes());
    m[8..20].copy_from_slice(txid);
    m
}

/// 解析绑定成功响应，返回映射地址。不是对应事务的响应、或格式不对时返回 None。
pub fn parse_binding_response(buf: &[u8], txid: &[u8; 12]) -> Option<SocketAddr> {
    if buf.len() < 20 || u16::from_be_bytes([buf[0], buf[1]]) != BINDING_SUCCESS {
        return None;
    }
    if u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) != MAGIC || &buf[8..20] != txid {
        return None;
    }
    let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let body = buf.get(20..20 + len)?;
    let mut plain = None;
    let mut i = 0;
    while i + 4 <= body.len() {
        let ty = u16::from_be_bytes([body[i], body[i + 1]]);
        let alen = u16::from_be_bytes([body[i + 2], body[i + 3]]) as usize;
        let val = body.get(i + 4..i + 4 + alen)?;
        match ty {
            ATTR_XOR_MAPPED_ADDRESS | ATTR_XOR_MAPPED_ADDRESS_OLD => {
                if let Some(a) = decode_address(val, Some(txid)) {
                    return Some(a);
                }
            }
            ATTR_MAPPED_ADDRESS => plain = plain.or_else(|| decode_address(val, None)),
            _ => {}
        }
        // 属性按 4 字节对齐
        i += 4 + alen.div_ceil(4) * 4;
    }
    plain
}

/// 解码（XOR-）MAPPED-ADDRESS 属性的值。`xor` 为 Some 时按 XOR-MAPPED-ADDRESS 还原。
fn decode_address(v: &[u8], xor: Option<&[u8; 12]>) -> Option<SocketAddr> {
    if v.len() < 4 {
        return None;
    }
    let mut port = u16::from_be_bytes([v[2], v[3]]);
    let magic = MAGIC.to_be_bytes();
    if xor.is_some() {
        port ^= (MAGIC >> 16) as u16;
    }
    let ip = match v[1] {
        0x01 => {
            let mut o: [u8; 4] = v.get(4..8)?.try_into().ok()?;
            if xor.is_some() {
                for (b, m) in o.iter_mut().zip(magic) {
                    *b ^= m;
                }
            }
            IpAddr::V4(Ipv4Addr::from(o))
        }
        0x02 => {
            let mut o: [u8; 16] = v.get(4..20)?.try_into().ok()?;
            if let Some(txid) = xor {
                let key: Vec<u8> = magic.iter().chain(txid.iter()).copied().collect();
                for (b, k) in o.iter_mut().zip(key) {
                    *b ^= k;
                }
            }
            IpAddr::V6(Ipv6Addr::from(o))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

/// 新的事务 ID。
pub fn new_txid() -> [u8; 12] {
    let a = super::random_u64().to_be_bytes();
    let b = super::random_u64().to_be_bytes();
    let mut t = [0u8; 12];
    t[..8].copy_from_slice(&a);
    t[8..].copy_from_slice(&b[..4]);
    t
}

/// 用给定的套接字向一个 STUN 服务器发送绑定请求，等待映射地址（中途重发一次；`cancel` 为真时不再重发）。
pub fn query(
    sock: &UdpSocket,
    server: SocketAddr,
    timeout: Duration,
    cancel: &(dyn Fn() -> bool + Sync),
) -> Result<SocketAddr> {
    let txid = new_txid();
    let req = binding_request(&txid);
    let start = Instant::now();
    let deadline = start + timeout;
    let resend_at = start + timeout / 2;
    let mut resent = false;
    let mut refused = false;
    sock.send_to(&req, server).map_err(|e| anyhow!("发送失败：{e}"))?;
    let mut buf = [0u8; 1024];
    loop {
        let now = Instant::now();
        if now >= deadline {
            if refused {
                bail!("{server} 拒绝连接");
            }
            bail!("{server} 无响应");
        }
        let wait = if resent { deadline - now } else { resend_at.saturating_duration_since(now).max(Duration::from_millis(1)) };
        sock.set_read_timeout(Some(wait))?;
        match sock.recv_from(&mut buf) {
            Ok((n, from)) if from.ip() == server.ip() => {
                if let Some(a) = parse_binding_response(&buf[..n], &txid) {
                    return Ok(a);
                }
            }
            Ok(_) => {}
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                if !resent {
                    resent = true;
                    if !cancel() {
                        let _ = sock.send_to(&req, server);
                    }
                }
            }
            // Windows：之前发出的包收到 ICMP 端口不可达时，下一次接收会报 ConnectionReset。
            // 同一个套接字先前问过别的服务器，这个错误可能是那边迟到的，所以不立即放弃，继续等到超时。
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => refused = true,
            Err(e) => bail!("接收失败：{e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5769 第 2.2、2.3 节测试向量中的事务 ID。
    const TXID: [u8; 12] = [0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae];

    fn response(attrs: &[u8]) -> Vec<u8> {
        let mut m = vec![0x01, 0x01];
        m.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        m.extend_from_slice(&MAGIC.to_be_bytes());
        m.extend_from_slice(&TXID);
        m.extend_from_slice(attrs);
        m
    }

    #[test]
    fn request_layout() {
        let r = binding_request(&TXID);
        assert_eq!(&r[..8], &[0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42]);
        assert_eq!(&r[8..], &TXID);
    }

    #[test]
    fn rfc5769_ipv4() {
        // SOFTWARE "test vector"（11 字节 + 1 字节填充）+ XOR-MAPPED-ADDRESS
        let mut attrs = vec![0x80, 0x22, 0x00, 0x0b];
        attrs.extend_from_slice(b"test vector ");
        attrs.extend_from_slice(&[0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43]);
        let a = parse_binding_response(&response(&attrs), &TXID).unwrap();
        assert_eq!(a, "192.0.2.1:32853".parse().unwrap());
        // 事务 ID 不对：不是我们的响应
        let mut other = TXID;
        other[0] ^= 1;
        assert_eq!(parse_binding_response(&response(&attrs), &other), None);
    }

    #[test]
    fn rfc5769_ipv6() {
        let attrs = [
            0x00, 0x20, 0x00, 0x14, 0x00, 0x02, 0xa1, 0x47, 0x01, 0x13, 0xa9, 0xfa, 0xa5, 0xd3, 0xf1, 0x79, 0xbc, 0x25,
            0xf4, 0xb5, 0xbe, 0xd2, 0xb9, 0xd9,
        ];
        let a = parse_binding_response(&response(&attrs), &TXID).unwrap();
        assert_eq!(a, "[2001:db8:1234:5678:11:2233:4455:6677]:32853".parse().unwrap());
    }

    #[test]
    fn plain_mapped_address_and_garbage() {
        let attrs = [0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0x0d, 0x96, 198, 51, 100, 7];
        assert_eq!(parse_binding_response(&response(&attrs), &TXID), Some("198.51.100.7:3478".parse().unwrap()));
        // 属性长度超出消息
        let attrs = [0x00, 0x20, 0x00, 0x40, 0x00, 0x01];
        assert_eq!(parse_binding_response(&response(&attrs), &TXID), None);
        assert_eq!(parse_binding_response(&[0u8; 8], &TXID), None);
        // 错误响应（0x0111）
        let mut r = response(&[]);
        r[1] = 0x11;
        assert_eq!(parse_binding_response(&r, &TXID), None);
    }

    #[test]
    fn host_port() {
        assert_eq!(split_host_port("stun.l.google.com:19302").unwrap(), ("stun.l.google.com".into(), 19302));
        assert_eq!(split_host_port("[2001:db8::1]:3478").unwrap(), ("2001:db8::1".into(), 3478));
        assert!(split_host_port("stun.l.google.com").is_err());
        assert!(split_host_port("2001:db8::1:3478").is_err());
        assert!(split_host_port("host:0").is_err());
        assert!(split_host_port(":3478").is_err());
        assert!(split_host_port("a b:3478").is_err());
    }

    /// 本机回环上的假 STUN 服务器：检查收发、重发和事务 ID 匹配。
    #[test]
    fn query_loopback_server() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = server.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let mut buf = [0u8; 64];
            // 第一个请求故意不回，等客户端重发
            let _ = server.recv_from(&mut buf).unwrap();
            let (n, from) = server.recv_from(&mut buf).unwrap();
            assert_eq!(n, 20);
            let txid: [u8; 12] = buf[8..20].try_into().unwrap();
            // 先回一个别的事务，再回正确的
            let mut wrong = txid;
            wrong[11] ^= 0xff;
            let enc = |txid: &[u8; 12]| {
                let mut m = vec![0x01, 0x01, 0x00, 0x0c];
                m.extend_from_slice(&MAGIC.to_be_bytes());
                m.extend_from_slice(txid);
                m.extend_from_slice(&[0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43]);
                m
            };
            server.send_to(&enc(&wrong), from).unwrap();
            server.send_to(&enc(&txid), from).unwrap();
        });
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let a = query(&sock, addr, Duration::from_millis(1500), &|| false).unwrap();
        assert_eq!(a, "192.0.2.1:32853".parse().unwrap());
        t.join().unwrap();
    }

    #[test]
    fn no_resend_after_cancel() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server.set_read_timeout(Some(Duration::from_millis(700))).unwrap();
        let addr = server.local_addr().unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert!(query(&sock, addr, Duration::from_millis(400), &|| true).is_err());
        let mut buf = [0u8; 64];
        let mut got = 0;
        while server.recv_from(&mut buf).is_ok() {
            got += 1;
        }
        // 已经发出的第一个请求照常，取消后不再重发
        assert_eq!(got, 1);
    }

}
