// 按应用阻断的规则（网络扩展与测试共用，不依赖 NetworkExtension）。
//
// 后台服务推送的 JSON：
//   {"kind":"filter","data":{"blocked":true,"inspect_existing":true,"apps":["/Applications/Foo.app", "/usr/local/bin/x"]}}
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
    /// 规范化后的路径：小写、去掉结尾的 "/"。
    private(set) var apps: [String]

    static let allowAll = FilterRules(blocked: false, inspectExisting: false, apps: [])

    init(blocked: Bool, inspectExisting: Bool, apps: [String]) {
        self.blocked = blocked
        self.inspectExisting = inspectExisting
        self.apps = apps.map(FilterRules.normalize).filter { !$0.isEmpty }
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
            apps: data["apps"] as? [String] ?? []
        )
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
    func decide(_ paths: [String]) -> FilterDecision {
        guard paths.contains(where: controls) else { return .allow }
        if blocked { return .block }
        return inspectExisting ? .watch : .allow
    }
}
