// 网络扩展共用代码的测试（CI 在 macOS 上编译运行，不需要签名）。
//
//   feedtest                      规则匹配的单元测试
//   feedtest --feed SOCKET MARKER --expect-app PATH --expect blocked,allowed [--timeout 秒]
//       以网络扩展的身份连接后台服务（需要 root），依次等到「阻断」「放行」两次规则，
//       并检查 PATH（.app 包里的程序）被判定为受控。用的是扩展里同一份 DaemonFeed 代码。

import Foundation

var failures = 0
func check(_ ok: Bool, _ what: String, line: Int = #line) {
    if !ok {
        failures += 1
        print("FAIL（第 \(line) 行）：\(what)")
    }
}

func unitTests() {
    let r = FilterRules(blocked: true, inspectExisting: true, apps: ["/Applications/Foo.app/", "/usr/local/bin/Tool"])
    check(r.apps == ["/applications/foo.app", "/usr/local/bin/tool"], "规范化：小写、去掉结尾的 /")
    check(r.controls("/Applications/Foo.app/Contents/MacOS/Foo"), "应用包里的主程序")
    check(r.controls("/applications/foo.app/Contents/Frameworks/Foo Helper.app/Contents/MacOS/Foo Helper"), "应用包里的辅助程序，大小写不同")
    check(r.controls("/usr/local/bin/tool"), "可执行文件完整路径")
    check(!r.controls("/Applications/Foo.appx/Contents/MacOS/x"), "名字前缀相同的其他应用")
    check(!r.controls("/usr/local/bin/tool2"), "名字前缀相同的其他程序")
    check(!r.controls("/usr/local/bin/tool/x"), "可执行文件不当作目录")
    check(r.decide(["/usr/bin/curl"]) == .allow, "不受控的程序放行")
    check(r.decide(["/usr/bin/curl", "/Applications/Foo.app/Contents/MacOS/Foo"]) == .block, "任意一个路径受控即阻断")
    check(r.decide([]) == .allow, "取不到路径时放行")

    var allowed = r
    allowed.blocked = false
    check(allowed.decide(["/usr/local/bin/tool"]) == .watch, "放行期间继续检查受控应用的连接")
    allowed.inspectExisting = false
    check(allowed.decide(["/usr/local/bin/tool"]) == .allow, "关闭「断开已有连接」后直接放行")
    check(FilterRules.allowAll.decide(["/usr/local/bin/tool"]) == .allow, "没有规则时放行")

    var v6 = FilterRules(blocked: false, inspectExisting: false, apps: ["/usr/local/bin/tool"], blockIPv6: true)
    check(v6.decide(["/usr/local/bin/tool"], remoteIPv6: true) == .block, "始终阻断 IPv6：放行期间受控应用的 IPv6 连接被丢弃")
    check(v6.decide(["/usr/local/bin/tool"], remoteIPv6: false) == .allow, "始终阻断 IPv6：IPv4 照常放行")
    check(v6.decide(["/usr/bin/curl"], remoteIPv6: true) == .allow, "始终阻断 IPv6：不受控的程序不受影响")
    v6.blockIPv6 = false
    check(v6.decide(["/usr/local/bin/tool"], remoteIPv6: true) == .allow, "关闭后 IPv6 照常放行")
    check(FilterRules.isIPv6(host: "2001:db8::1"), "IPv6 地址")
    check(!FilterRules.isIPv6(host: "::ffff:192.0.2.1"), "IPv4 映射地址不算 IPv6")
    check(!FilterRules.isIPv6(host: "192.0.2.1"), "IPv4 地址")

    let line = Data(#"{"kind":"filter","data":{"blocked":true,"inspect_existing":false,"apps":["/Applications/A.app"]}}"#.utf8)
    let p = FilterRules.parse(line: line)
    check(p == FilterRules(blocked: true, inspectExisting: false, apps: ["/applications/a.app"]), "解析后台服务的规则")
    let line6 = Data(#"{"kind":"filter","data":{"blocked":false,"inspect_existing":false,"apps":[],"block_ipv6":true}}"#.utf8)
    check(FilterRules.parse(line: line6)?.blockIPv6 == true, "解析 block_ipv6")
    check(FilterRules.parseRev(line: line6) == nil, "旧服务不带版本号")
    let lineRev = Data(#"{"kind":"filter","data":{"blocked":false,"inspect_existing":false,"apps":[],"block_ipv6":true,"rev":42}}"#.utf8)
    check(FilterRules.parseRev(line: lineRev) == 42, "解析规则版本号")
    check(FilterRules.parse(line: Data(#"{"kind":"status","data":{}}"#.utf8)) == nil, "忽略其他回复")
    check(FilterRules.parseError(line: Data(#"{"kind":"err","data":"只接受 root"}"#.utf8)) == "只接受 root", "解析错误回复")
    check(FilterRules.parse(line: Data("garbage".utf8)) == nil, "无法解析的行")
}

func feedTest(_ args: [String]) -> Bool {
    func value(_ name: String) -> String? {
        guard let i = args.firstIndex(of: name), i + 1 < args.count else { return nil }
        return args[i + 1]
    }
    guard let i = args.firstIndex(of: "--feed"), i + 2 < args.count else {
        print("用法：--feed SOCKET MARKER --expect-app PATH --expect blocked,allowed")
        return false
    }
    let socket = args[i + 1], marker = args[i + 2]
    let expectApp = value("--expect-app")
    let expect = (value("--expect") ?? "blocked,allowed").split(separator: ",").map { $0 == "blocked" }
    let timeout = Double(value("--timeout") ?? "120") ?? 120

    let lock = NSLock()
    var seen: [FilterRules] = []
    let sem = DispatchSemaphore(value: 0)
    let feed = DaemonFeed(socketPath: socket, markerPath: marker, version: "ci-feedtest") { print("[feed] \($0)") }
    feed.onChange = { r in
        lock.lock()
        // 只记录阻断状态的变化
        if seen.last?.blocked != r.blocked || seen.isEmpty {
            seen.append(r)
            print("[feed] 收到规则：\(r.blocked ? "阻断" : "放行")，\(r.apps.count) 个程序：\(r.apps)")
            fflush(stdout)
            sem.signal()
        }
        lock.unlock()
    }
    feed.start()
    let deadline = Date().addingTimeInterval(timeout)
    while true {
        lock.lock()
        let blocks = seen.map(\.blocked)
        let rules = seen
        lock.unlock()
        // 期望的序列是收到的序列的子序列（中间可能有额外的切换）
        var k = 0
        for b in blocks where k < expect.count && b == expect[k] { k += 1 }
        if k == expect.count {
            if let app = expectApp {
                let exe = app.hasSuffix(".app") ? app + "/Contents/MacOS/x" : app
                let first = rules.first { $0.blocked }
                check(first?.controls(exe) == true, "阻断时 \(exe) 应被判定为受控")
                check(first?.decide([exe]) == .block, "阻断时 \(exe) 的新连接应被丢弃")
                check(first?.decide(["/usr/bin/curl"]) == .allow, "阻断时其他程序照常放行")
            }
            feed.stop()
            return true
        }
        if Date() > deadline {
            print("FAIL：超时，期望 \(expect)，收到 \(blocks)")
            failures += 1
            feed.stop()
            return false
        }
        _ = sem.wait(timeout: .now() + 1)
    }
}

let args = Array(CommandLine.arguments.dropFirst())
if args.contains("--feed") {
    _ = feedTest(args)
} else {
    unitTests()
}
if failures > 0 {
    print("\(failures) 项失败")
    exit(1)
}
print("全部通过")
