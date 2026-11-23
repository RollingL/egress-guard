// Egress Guard 网络扩展：内容过滤（NEFilterDataProvider），按应用放行或丢弃连接。
//
// 规则来自 root 后台服务（见 DaemonFeed）：出口 IP 不在白名单时 blocked = true，
// 受控应用（含自动识别的子进程）的新连接直接丢弃；「断开已有连接」开启时，
// 放行期间受控应用的连接会被持续检查，切换为阻断后在下一个数据包被切断。
// 其他程序的连接一律放行，全局断网由后台服务的 pf 规则负责。
// 「始终阻断 IPv6」开启时，放行期间受控应用的 IPv6 连接也被丢弃。

import Foundation
import NetworkExtension
import os.log

let socketPath = "/var/run/egress-guard.sock"
let markerPath = "/var/run/egress-guard.running"
private let logger = Logger(subsystem: "com.egressguard.app.filter", category: "filter")

final class FilterDataProvider: NEFilterDataProvider {
    /// 持续检查的连接每次最多看多少字节（看完放行这部分，再看下一段）。
    private static let peekBytes = 256 * 1024

    private let feed: DaemonFeed = {
        let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "?"
        return DaemonFeed(socketPath: socketPath, markerPath: markerPath, version: version) { msg in
            logger.log("\(msg, privacy: .public)")
        }
    }()

    /// 正在持续检查的连接 → 发起程序的路径（规则里去掉某个应用后，它的连接不应再被切断）、远端是否为 IPv6。
    private let watchedLock = NSLock()
    private var watched: [UUID: (paths: [String], v6: Bool)] = [:]

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        // 所有 TCP/UDP、进出两个方向都交给 handleNewFlow 决定
        let any = NENetworkRule(
            remoteNetwork: nil, remotePrefix: 0,
            localNetwork: nil, localPrefix: 0,
            protocol: .any, direction: .any
        )
        let settings = NEFilterSettings(rules: [NEFilterRule(networkRule: any, action: .filterData)], defaultAction: .allow)
        apply(settings) { [weak self] error in
            if let error {
                logger.error("应用过滤设置失败：\(error.localizedDescription, privacy: .public)")
            } else {
                logger.log("内容过滤已启动")
                self?.feed.start()
            }
            completionHandler(error)
        }
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        logger.log("内容过滤停止（原因 \(reason.rawValue)）")
        feed.stop()
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        let paths = Self.sourcePaths(of: flow)
        if paths.isEmpty { return .allow() }
        let rules = feed.rules
        let v6 = Self.remoteIsIPv6(flow)
        switch rules.decide(paths, remoteIPv6: v6) {
        case .allow:
            return .allow()
        case .block:
            logger.log("阻断 \(paths.first ?? "", privacy: .public) → \(Self.remote(of: flow), privacy: .public)")
            return .drop()
        case .watch:
            watchedLock.lock()
            if watched.count > 20000 { watched.removeAll() } // 兜底：没收到结束回调的连接
            watched[flow.identifier] = (paths, v6)
            watchedLock.unlock()
            return .filterDataVerdict(
                withFilterInbound: true, peekInboundBytes: Self.peekBytes,
                filterOutbound: true, peekOutboundBytes: Self.peekBytes
            )
        }
    }

    override func handleInboundData(from flow: NEFilterFlow, readBytesStartOffset offset: Int, readBytes: Data) -> NEFilterDataVerdict {
        dataVerdict(flow, passing: readBytes.count)
    }

    override func handleOutboundData(from flow: NEFilterFlow, readBytesStartOffset offset: Int, readBytes: Data) -> NEFilterDataVerdict {
        dataVerdict(flow, passing: readBytes.count)
    }

    override func handleInboundDataComplete(for flow: NEFilterFlow) -> NEFilterDataVerdict {
        finish(flow)
    }

    override func handleOutboundDataComplete(for flow: NEFilterFlow) -> NEFilterDataVerdict {
        finish(flow)
    }

    private func dataVerdict(_ flow: NEFilterFlow, passing n: Int) -> NEFilterDataVerdict {
        let rules = feed.rules
        watchedLock.lock()
        let entry = watched[flow.identifier]
        watchedLock.unlock()
        switch rules.decide(entry?.paths ?? [], remoteIPv6: entry?.v6 ?? false) {
        case .block:
            forget(flow)
            logger.log("切断已有连接 \(entry?.paths.first ?? "", privacy: .public) → \(Self.remote(of: flow), privacy: .public)")
            return .drop()
        case .watch:
            return NEFilterDataVerdict(passBytes: n, peekBytes: Self.peekBytes)
        case .allow:
            // 「断开已有连接」被关闭，或这个程序不再受控：不再检查
            forget(flow)
            return .allow()
        }
    }

    private func finish(_ flow: NEFilterFlow) -> NEFilterDataVerdict {
        let rules = feed.rules
        watchedLock.lock()
        let v6 = watched[flow.identifier]?.v6 ?? false
        watchedLock.unlock()
        forget(flow)
        return rules.blocked || (rules.blockIPv6 && v6) ? .drop() : .allow()
    }

    private func forget(_ flow: NEFilterFlow) {
        watchedLock.lock()
        watched.removeValue(forKey: flow.identifier)
        watchedLock.unlock()
    }

    /// 连接所属的程序：代为发起连接的应用（sourceAppAuditToken）和实际发起的进程（macOS 13+）。
    static func sourcePaths(of flow: NEFilterFlow) -> [String] {
        var tokens: [Data] = []
        if let t = flow.sourceAppAuditToken { tokens.append(t) }
        if #available(macOS 13.0, *), let t = flow.sourceProcessAuditToken, t != flow.sourceAppAuditToken {
            tokens.append(t)
        }
        return tokens.compactMap(path(ofAuditToken:))
    }

    /// audit_token_t 的第 6 个字段是 PID（与 audit_token_to_pid 相同）。
    static func path(ofAuditToken data: Data) -> String? {
        guard data.count == MemoryLayout<audit_token_t>.size else { return nil }
        let token = data.withUnsafeBytes { $0.loadUnaligned(as: audit_token_t.self) }
        let pid = pid_t(bitPattern: token.val.5)
        guard pid > 0 else { return nil }
        var buf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let n = proc_pidpath(pid, &buf, UInt32(buf.count))
        guard n > 0 else { return nil }
        return String(cString: buf)
    }

    /// 连接的远端是不是 IPv6 地址（IPv4 映射地址不算）。
    static func remoteIsIPv6(_ flow: NEFilterFlow) -> Bool {
        guard let s = flow as? NEFilterSocketFlow else { return false }
        if let ep = s.remoteEndpoint as? NWHostEndpoint {
            return FilterRules.isIPv6(host: ep.hostname)
        }
        return s.socketFamily == AF_INET6
    }

    static func remote(of flow: NEFilterFlow) -> String {
        if let s = flow as? NEFilterSocketFlow, let ep = s.remoteEndpoint as? NWHostEndpoint {
            return "\(ep.hostname):\(ep.port)"
        }
        return "?"
    }
}
