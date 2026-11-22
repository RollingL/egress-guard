//! macOS pf 规则文本生成（与运行平台无关，便于在任意平台测试）。
//!
//! 规则装入主规则集已引用的 `com.apple/*` 子锚点，不修改 `/etc/pf.conf`。
//! 全部规则带 `quick`，命中即终止评估：
//!
//! 1. 始终放行：回环（lo0）、DHCP / DHCPv6、IPv6 邻居发现与路由通告；
//! 2. 放行本工具的出口 IP 检测：检测在以 `nobody` 身份运行的子进程中进行，按套接字所属用户放行 TCP；
//! 3. 可选放行：DNS（端口 53）、局域网网段、例外地址。这些例外不建立状态（`no state`，双向各一条），
//!    所以开始阻断前已经存在的例外连接（例如局域网 SSH）不会因为缺少状态而被切断；
//! 4. 其余进出流量全部丢弃。没有状态的已有连接在下一个数据包就会被拦截。

use std::fmt::Write;

use crate::blockall::{lan_nets, BlockAllPolicy, DHCP_V4_CLIENT_PORT, DHCP_V6_CLIENT_PORT, DNS_PORT};

/// 规则装入的锚点。主规则集（/etc/pf.conf）里的 `anchor "com.apple/*"` 会评估它。
pub const ANCHOR: &str = "com.apple/egress-guard";

/// 运行出口 IP 检测子进程的用户。
pub const PROBE_USER: &str = "nobody";

/// 生成全局断网的规则文本。
pub fn render(policy: &BlockAllPolicy) -> String {
    let mut s = String::from("# egress-guard：出口 IP 不在白名单内，切断全部网络\n");
    let mut line = |l: &str| {
        s.push_str(l);
        s.push('\n');
    };
    line("pass quick on lo0 all no state");
    line(&format!(
        "pass out quick inet proto udp from any port {DHCP_V4_CLIENT_PORT} to any port 67 no state"
    ));
    line(&format!(
        "pass in quick inet proto udp from any port 67 to any port {DHCP_V4_CLIENT_PORT} no state"
    ));
    line(&format!(
        "pass out quick inet6 proto udp from any port {DHCP_V6_CLIENT_PORT} to any port 547 no state"
    ));
    line(&format!(
        "pass in quick inet6 proto udp from any port 547 to any port {DHCP_V6_CLIENT_PORT} no state"
    ));
    line("pass quick inet6 proto ipv6-icmp all icmp6-type { routersol, routeradv, neighbrsol, neighbradv } no state");
    line(&format!("pass out quick proto tcp from any to any user {PROBE_USER} flags S/SA keep state"));
    if policy.allow_dns {
        line(&format!("pass out quick proto {{ tcp, udp }} from any to any port {DNS_PORT} no state"));
        line(&format!("pass in quick proto {{ tcp, udp }} from any port {DNS_PORT} to any no state"));
    }
    let mut nets: Vec<String> = Vec::new();
    if policy.allow_lan {
        nets.extend(lan_nets().iter().map(|n| n.to_string()));
    }
    nets.extend(policy.allow_remote.iter().map(|n| n.trunc().to_string()));
    if !nets.is_empty() {
        let list = nets.join(", ");
        line(&format!("pass out quick from any to {{ {list} }} no state"));
        line(&format!("pass in quick from {{ {list} }} to any no state"));
    }
    line("block drop out quick all");
    line("block drop in quick all");
    s
}

/// 从 `pfctl -E` 的输出中取出启用令牌（"Token : 1234…"）。
pub fn parse_token(output: &str) -> Option<String> {
    output.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        (k.trim().eq_ignore_ascii_case("token")).then(|| v.trim().to_owned()).filter(|v| !v.is_empty())
    })
}

/// 主规则集（`pfctl -sr` 的输出）是否会评估 `com.apple/*` 子锚点。
pub fn has_apple_anchor(main_rules: &str) -> bool {
    main_rules.lines().any(|l| {
        let l = l.trim_start();
        l.starts_with("anchor \"com.apple/*\"")
    })
}

/// 便于日志显示的规则摘要。
pub fn summary(policy: &BlockAllPolicy) -> String {
    let mut s = String::new();
    let _ = write!(
        s,
        "局域网 {}，DNS {}，例外地址 {} 条",
        if policy.allow_lan { "放行" } else { "阻断" },
        if policy.allow_dns { "放行" } else { "阻断" },
        policy.allow_remote.len()
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_policy() {
        let text = render(&BlockAllPolicy::default());
        assert!(text.contains("pass quick on lo0 all no state"));
        assert!(text.contains("port 68 to any port 67"));
        assert!(text.contains("user nobody"));
        assert!(!text.contains("port 53"));
        assert!(!text.contains("192.168.0.0/16"));
        // 兜底阻断在最后
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[lines.len() - 2], "block drop out quick all");
        assert_eq!(lines[lines.len() - 1], "block drop in quick all");
        // 所有规则都带 quick
        assert!(lines.iter().filter(|l| !l.starts_with('#')).all(|l| l.contains(" quick ")));
    }

    #[test]
    fn exceptions() {
        let p = BlockAllPolicy {
            allow_lan: true,
            allow_dns: true,
            allow_apps: vec![],
            allow_remote: vec!["198.51.100.7/32".parse().unwrap(), "2001:db8::/32".parse().unwrap()],
        };
        let text = render(&p);
        assert!(text.contains("pass out quick proto { tcp, udp } from any to any port 53 no state"));
        assert!(text.contains("pass in quick proto { tcp, udp } from any port 53 to any no state"));
        assert!(text.contains("pass out quick from any to { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16"));
        assert!(text.contains("198.51.100.7/32, 2001:db8::/32 }"));
        assert!(text.contains("pass in quick from { 10.0.0.0/8"));
    }

    #[test]
    fn token_and_anchor() {
        assert_eq!(parse_token("No ALTQ support in kernel\npf enabled\nToken : 13951471871829225487\n").as_deref(), Some("13951471871829225487"));
        assert_eq!(parse_token("pf enabled\n"), None);
        let main = "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n";
        assert!(has_apple_anchor(main));
        assert!(!has_apple_anchor("scrub-anchor \"com.apple/*\" all fragment reassemble\n"));
    }
}
