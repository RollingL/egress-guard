// 按应用阻断的规则（网络扩展与测试共用，不依赖 NetworkExtension）。
//
// 后台服务推送的 JSON：
//   {"kind":"filter","data":{"blocked":true,"inspect_existing":true,"apps":["/Applications/Foo.app", "/usr/local/bin/x"],"block_ipv6":false}}
// block_ipv6：放行期间也丢弃受控应用的 IPv6 连接（「始终阻断 IPv6」）。
// rev：规则版本号。扩展应用后回复 {"cmd":"filter_applied","arg":rev}，后台服务据此确认扩展用的是最新规则。
// apps 里的条目可以是可执行文件的完整路径，也可以是 .app 应用包（包里的所有程序都算）。
// 路径比较不区分大小写（与 Rust 一侧的 discovery::normalize 一致；APFS 默认也不区分大小写）。

import Foundation

enum FilterDecision: Equatable {
    /// 不是受控应用，或者现在放行且不需要逐包检查。
    case allow
    /// 受控应用，现在阻断。
    case block
    /// 受控应用，现在放行，但继续检查这个连接，切换为阻断时立即切断。
    case watch
}

struct FilterRules: Equatable {
    var blocked: Bool
    var inspectExisting: Bool
    /// 放行期间也阻断受控应用的 IPv6 连接。
    var blockIPv6: Bool
    /// 规范化后的路径：小写、去掉结尾的 "/"。
    private(set) var apps: [String]

    static let allowAll = FilterRules(blocked: false, inspectExisting: false, apps: [])

    init(blocked: Bool, inspectExisting: Bool, apps: [String], blockIPv6: Bool = false) {
        self.blocked = blocked
        self.inspectExisting = inspectExisting
        self.blockIPv6 = blockIPv6
        self.apps = apps.map(FilterRules.normalize).filter { !$0.isEmpty }
    }

    /// 远端地址是不是真正的 IPv6（IPv4 映射地址 ::ffff:a.b.c.d 走的是 IPv4，不算）。不是 IP 地址时为 false。
    static func isIPv6(host: String) -> Bool {
        ipv6Literal(host: host) ?? false
    }

    /// 按地址解析判断：IPv6 地址返回 true，IPv4 地址和 IPv4 映射地址（任何写法）返回 false，
    /// 不是 IP 地址（主机名）时返回 nil，由调用方按套接字的地址族判断。
    static func ipv6Literal(host: String) -> Bool? {
        var h = host
        if h.hasPrefix("[") && h.hasSuffix("]") { h = String(h.dropFirst().dropLast()) }
        if let pct = h.firstIndex(of: "%") { h = String(h[..<pct]) } // fe80::1%en0
        var v4 = in_addr()
        if inet_pton(AF_INET, h, &v4) == 1 { return false }
        var v6 = in6_addr()
        guard inet_pton(AF_INET6, h, &v6) == 1 else { return nil }
        let b = withUnsafeBytes(of: &v6) { Array($0) }
        let mapped = b[0..<10].allSatisfy { $0 == 0 } && b[10] == 0xff && b[11] == 0xff
        return !mapped
    }

    static func normalize(_ path: String) -> String {
        var p = path.lowercased()
        while p.count > 1 && p.hasSuffix("/") {
            p.removeLast()
        }
        return p
    }

    /// 解析后台服务的一行回复；不是规则（例如错误）时返回 nil。
    static func parse(line: Data) -> FilterRules? {
        guard let obj = try? JSONSerialization.jsonObject(with: line) as? [String: Any],
              obj["kind"] as? String == "filter",
              let data = obj["data"] as? [String: Any]
        else { return nil }
        return FilterRules(
            blocked: data["blocked"] as? Bool ?? false,
            inspectExisting: data["inspect_existing"] as? Bool ?? false,
            apps: data["apps"] as? [String] ?? [],
            blockIPv6: data["block_ipv6"] as? Bool ?? false
        )
    }

    /// 规则的版本号（data.rev，0.9.1 起）；没有时为 nil。扩展应用规则后回复 filter_applied。
    static func parseRev(line: Data) -> UInt64? {
        guard let obj = try? JSONSerialization.jsonObject(with: line) as? [String: Any],
              obj["kind"] as? String == "filter",
              let data = obj["data"] as? [String: Any],
              let rev = data["rev"] as? NSNumber
        else { return nil }
        return rev.uint64Value
    }

    /// 后台服务回复的错误文字（{"kind":"err","data":"..."}）。
    static func parseError(line: Data) -> String? {
        guard let obj = try? JSONSerialization.jsonObject(with: line) as? [String: Any],
              obj["kind"] as? String == "err"
        else { return nil }
        return obj["data"] as? String ?? "未知错误"
    }

    /// 这个程序（可执行文件完整路径）是否受控。
    func controls(_ path: String) -> Bool {
        let p = FilterRules.normalize(path)
        for a in apps {
            if p == a {
                return true
            }
            if a.hasSuffix(".app") && p.hasPrefix(a + "/") {
                return true
            }
        }
        return false
    }

    /// 任意一个路径受控即受控（例如连接既有发起进程，也有代为发起的应用）。
    /// `remoteIPv6`：连接的远端是 IPv6 地址。
    func decide(_ paths: [String], remoteIPv6: Bool = false) -> FilterDecision {
        guard paths.contains(where: controls) else { return .allow }
        if blocked || (blockIPv6 && remoteIPv6) { return .block }
        return inspectExisting ? .watch : .allow
    }
}
