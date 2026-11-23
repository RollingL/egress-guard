// 从后台服务接收按应用阻断的规则（网络扩展与测试共用）。
//
// - 只在后台服务的运行标记文件存在时连接本地套接字：launchd 会在有人连接时按需启动服务，
//   如果扩展一直重连，用户「退出并解除阻断」后服务马上又会被拉起来。
// - 套接字另一端必须是 root（后台服务）；否则拒绝使用。
// - 连接意外断开（服务崩溃、正在重启）时保留最后收到的规则，避免出现放行空档；
//   标记文件消失（服务正常退出、被卸载）后放行全部连接。

import Foundation

enum FeedError: Error, CustomStringConvertible {
    case sys(String, Int32)
    case msg(String)

    var description: String {
        switch self {
        case let .sys(what, code): return "\(what) 失败：\(String(cString: strerror(code)))"
        case let .msg(m): return m
        }
    }
}

final class DaemonFeed {
    /// 与后台服务的协议版本，以及支持的功能（见 Rust 一侧 filterfeed 的 CAP_*）。
    static let protocolVersion = 1
    static let capabilities = ["block_ipv6", "ack"]

    let socketPath: String
    let markerPath: String
    let version: String
    private let log: (String) -> Void
    /// 规则变化时调用（在接收线程上）。
    var onChange: ((FilterRules) -> Void)?

    private let lock = NSLock()
    private var _rules = FilterRules.allowAll
    private var _connected = false
    private var running = false
    private var fd: Int32 = -1

    init(socketPath: String, markerPath: String, version: String, log: @escaping (String) -> Void) {
        self.socketPath = socketPath
        self.markerPath = markerPath
        self.version = version
        self.log = log
    }

    private func locked<T>(_ f: () -> T) -> T {
        lock.lock()
        defer { lock.unlock() }
        return f()
    }

    var rules: FilterRules { locked { _rules } }
    var connected: Bool { locked { _connected } }
    private var isRunning: Bool { locked { running } }

    func start() {
        let already = locked { () -> Bool in
            defer { running = true }
            return running
        }
        if already { return }
        let t = Thread { [weak self] in self?.loop() }
        t.name = "daemon-feed"
        t.start()
    }

    func stop() {
        locked {
            running = false
            if fd >= 0 { shutdown(fd, SHUT_RDWR) }
        }
    }

    private func set(_ r: FilterRules) {
        let changed = locked { () -> Bool in
            defer { _rules = r }
            return _rules != r
        }
        if changed { onChange?(r) }
    }

    private func loop() {
        var lastError = ""
        while isRunning {
            if !FileManager.default.fileExists(atPath: markerPath) {
                if rules != .allowAll {
                    log("后台服务没有运行，放行全部连接")
                }
                set(.allowAll)
                lastError = ""
                sleep(2)
                continue
            }
            do {
                try session()
            } catch {
                let msg = "\(error)"
                if msg != lastError {
                    log("与后台服务的连接：\(msg)（保留最后的规则，稍后重连）")
                    lastError = msg
                }
            }
            locked { _connected = false }
            if isRunning { sleep(1) }
        }
    }

    private func connectSocket() throws -> Int32 {
        let s = socket(AF_UNIX, SOCK_STREAM, 0)
        guard s >= 0 else { throw FeedError.sys("socket", errno) }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let path = Array(socketPath.utf8CString).map { UInt8(bitPattern: $0) } // 含结尾的 0
        guard path.count <= MemoryLayout.size(ofValue: addr.sun_path) else {
            close(s)
            throw FeedError.msg("套接字路径太长")
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { $0.copyBytes(from: path) }
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let r = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(s, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard r == 0 else {
            let e = errno
            close(s)
            throw FeedError.sys("连接 \(socketPath)", e)
        }
        return s
    }

    private func sendLine(_ s: Int32, _ text: String) throws {
        let bytes = Array((text + "\n").utf8)
        var sent = 0
        while sent < bytes.count {
            let n = bytes[sent...].withUnsafeBytes { write(s, $0.baseAddress, $0.count) }
            if n < 0 {
                if errno == EINTR { continue }
                throw FeedError.sys("发送", errno)
            }
            sent += n
        }
    }

    private func session() throws {
        let s = try connectSocket()
        locked { fd = s }
        defer {
            locked { fd = -1 }
            close(s)
        }
        var uid: uid_t = 0
        var gid: gid_t = 0
        guard getpeereid(s, &uid, &gid) == 0 else { throw FeedError.sys("getpeereid", errno) }
        guard uid == 0 || uid == geteuid() else {
            throw FeedError.msg("套接字另一端的用户是 \(uid)，不是 root，拒绝使用")
        }
        // 服务端至少每 5 秒发一次；15 秒收不到视为断开
        var tv = timeval(tv_sec: 15, tv_usec: 0)
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var one: Int32 = 1
        setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))

        let v = version.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        // protocol / caps：告诉后台服务这个扩展支持哪些规则，以及会确认已应用的规则版本
        let caps = DaemonFeed.capabilities.map { "\"\($0)\"" }.joined(separator: ",")
        try sendLine(s, "{\"cmd\":\"filter_watch\",\"arg\":{\"version\":\"\(v)\",\"protocol\":\(DaemonFeed.protocolVersion),\"caps\":[\(caps)]}}")

        var buf = Data()
        var chunk = [UInt8](repeating: 0, count: 64 * 1024)
        var first = true
        var acked: UInt64 = 0
        while isRunning {
            let n = chunk.withUnsafeMutableBytes { read(s, $0.baseAddress, $0.count) }
            if n == 0 { throw FeedError.msg("后台服务关闭了连接") }
            if n < 0 {
                if errno == EINTR { continue }
                if errno == EAGAIN || errno == EWOULDBLOCK { throw FeedError.msg("后台服务 15 秒没有消息") }
                throw FeedError.sys("接收", errno)
            }
            buf.append(contentsOf: chunk[0..<n])
            while let nl = buf.firstIndex(of: 0x0A) {
                let line = Data(buf[buf.startIndex..<nl])
                buf.removeSubrange(buf.startIndex...nl)
                if let r = FilterRules.parse(line: line) {
                    if first {
                        first = false
                        locked { _connected = true }
                        log("已连接后台服务，收到规则：\(r.blocked ? "阻断" : "放行") \(r.apps.count) 个程序")
                    }
                    set(r)
                    // 规则已经生效（之后的连接都按它判断）：确认版本。心跳重发的同一版本不再确认；
                    // 0.9.0 及以前的服务不带版本号，也就不会收到确认（它们不读这些回复）
                    if let rev = FilterRules.parseRev(line: line), rev > acked {
                        acked = rev
                        try sendLine(s, "{\"cmd\":\"filter_applied\",\"arg\":\(rev)}")
                    }
                } else if let e = FilterRules.parseError(line: line) {
                    throw FeedError.msg("后台服务拒绝：\(e)")
                }
            }
            if buf.count > 4 << 20 { throw FeedError.msg("回复过长") }
        }
    }
}
