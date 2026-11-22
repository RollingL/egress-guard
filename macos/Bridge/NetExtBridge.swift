// 界面（Rust）调用的网络扩展管理：安装/卸载系统扩展、开启/关闭内容过滤。
//
// 编译为静态库，由 build.rs 链接进 egress-guard-gui。对外只有几个 C 函数：
// 操作都是异步的，结果写进一份状态，界面定时用 eg_netext_state_json() 读取（JSON）。
//
// 注意：安装系统扩展、配置内容过滤需要受限权限，只有用 Developer ID 签名、
// 带描述文件（provisioning profile）的版本才能成功；未签名版本会得到系统返回的错误，原样显示给用户。

import Foundation
import NetworkExtension
import Security
import SystemExtensions

let extensionID = "com.egressguard.app.filter"

struct BridgeState: Codable {
    /// 主程序签名的团队 ID；ad-hoc 签名（未签名）时为空。
    var teamId: String?
    /// .app 包里有没有网络扩展。
    var bundled = false
    /// idle / activating / needs_approval / activated / reboot_required / deactivating / deactivated / error
    var phase = "idle"
    var error: String?
    /// 系统中已安装的扩展是否已启用（macOS 12+ 才能查询）。
    var extEnabled: Bool?
    var extAwaitingApproval: Bool?
    var extVersion: String?
    /// 内容过滤配置是否存在、是否开启。
    var filterConfigured = false
    var filterEnabled = false
    var filterError: String?
    /// 是否已经查询过一次（界面在此之前显示「正在检查」）。
    var loaded = false
}

enum RequestKind {
    case activate, deactivate, properties
}

final class Bridge: NSObject, OSSystemExtensionRequestDelegate {
    static let shared = Bridge()

    let queue = DispatchQueue(label: "com.egressguard.netext")
    private let lock = NSLock()
    private var state = BridgeState()
    private var kinds: [ObjectIdentifier: RequestKind] = [:]

    override init() {
        super.init()
        state.teamId = Bridge.signingTeam()
        state.bundled = FileManager.default.fileExists(atPath: Bridge.extensionURL.path)
    }

    static var extensionURL: URL {
        Bundle.main.bundleURL.appendingPathComponent("Contents/Library/SystemExtensions/\(extensionID).systemextension")
    }

    static func signingTeam() -> String? {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { return nil }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let dict = info as? [String: Any]
        else { return nil }
        return dict[kSecCodeInfoTeamIdentifier as String] as? String
    }

    func update(_ f: (inout BridgeState) -> Void) {
        lock.lock()
        f(&state)
        lock.unlock()
    }

    func json() -> String {
        lock.lock()
        let s = state
        lock.unlock()
        let enc = JSONEncoder()
        enc.keyEncodingStrategy = .convertToSnakeCase
        return (try? enc.encode(s)).flatMap { String(data: $0, encoding: .utf8) } ?? "{}"
    }

    private func submit(_ req: OSSystemExtensionRequest, _ kind: RequestKind) {
        lock.lock()
        kinds[ObjectIdentifier(req)] = kind
        lock.unlock()
        req.delegate = self
        OSSystemExtensionManager.shared.submitRequest(req)
    }

    private func kind(of req: OSSystemExtensionRequest, remove: Bool) -> RequestKind? {
        lock.lock()
        defer { lock.unlock() }
        let k = kinds[ObjectIdentifier(req)]
        if remove { kinds.removeValue(forKey: ObjectIdentifier(req)) }
        return k
    }

    // MARK: 操作

    /// 安装（或更新）系统扩展；完成后自动开启内容过滤。
    func activate() {
        queue.async {
            self.update { $0.phase = "activating"; $0.error = nil }
            self.submit(OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier: extensionID, queue: self.queue), .activate)
        }
    }

    /// 关闭内容过滤并卸载系统扩展。
    func deactivate() {
        queue.async {
            self.update { $0.phase = "deactivating"; $0.error = nil }
            self.removeFilter {
                self.submit(OSSystemExtensionRequest.deactivationRequest(forExtensionWithIdentifier: extensionID, queue: self.queue), .deactivate)
            }
        }
    }

    func refresh() {
        queue.async {
            if #available(macOS 12.0, *) {
                self.submit(OSSystemExtensionRequest.propertiesRequest(forExtensionWithIdentifier: extensionID, queue: self.queue), .properties)
            }
            self.refreshFilter()
        }
    }

    func refreshFilter() {
        let m = NEFilterManager.shared()
        m.loadFromPreferences { err in
            self.update {
                $0.loaded = true
                $0.filterError = err.map(Bridge.describe)
                $0.filterConfigured = m.providerConfiguration != nil
                $0.filterEnabled = m.isEnabled
            }
        }
    }

    /// 开启或关闭内容过滤。第一次开启时系统会询问是否允许“Egress Guard”过滤网络内容。
    func setFilter(_ on: Bool) {
        let m = NEFilterManager.shared()
        m.loadFromPreferences { err in
            if let err {
                self.update { $0.filterError = Bridge.describe(err) }
                return
            }
            if on {
                if m.providerConfiguration == nil {
                    let c = NEFilterProviderConfiguration()
                    c.filterSockets = true
                    c.filterPackets = false
                    c.filterDataProviderBundleIdentifier = extensionID
                    c.organization = "Egress Guard"
                    m.providerConfiguration = c
                }
                m.localizedDescription = "Egress Guard"
            }
            m.isEnabled = on
            m.saveToPreferences { err in
                self.update { $0.filterError = err.map(Bridge.describe) }
                self.refreshFilter()
            }
        }
    }

    private func removeFilter(then next: @escaping () -> Void) {
        let m = NEFilterManager.shared()
        m.loadFromPreferences { _ in
            guard m.providerConfiguration != nil else {
                self.queue.async(execute: next)
                return
            }
            m.removeFromPreferences { err in
                self.update { $0.filterError = err.map(Bridge.describe) }
                self.refreshFilter()
                self.queue.async(execute: next)
            }
        }
    }

    // MARK: OSSystemExtensionRequestDelegate

    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        // 新版本的 .app 带着新版本的扩展：总是替换
        .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        update { $0.phase = "needs_approval" }
    }

    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        switch kind(of: request, remove: true) {
        case .activate:
            if result == .willCompleteAfterReboot {
                update { $0.phase = "reboot_required" }
            } else {
                update { $0.phase = "activated"; $0.extEnabled = true }
                setFilter(true)
            }
        case .deactivate:
            update {
                $0.phase = result == .willCompleteAfterReboot ? "reboot_required" : "deactivated"
                $0.extEnabled = false
            }
        case .properties, .none:
            break
        }
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        let k = kind(of: request, remove: true)
        guard k != .properties else { return }
        update { $0.phase = "error"; $0.error = Bridge.describe(error) }
    }

    @available(macOS 12.0, *)
    func request(_ request: OSSystemExtensionRequest, foundProperties properties: [OSSystemExtensionProperties]) {
        let live = properties.filter { !$0.isUninstalling }
        let enabled = live.first { $0.isEnabled }
        update {
            $0.extEnabled = enabled != nil
            $0.extAwaitingApproval = live.contains { $0.isAwaitingUserApproval }
            $0.extVersion = enabled?.bundleShortVersion
        }
    }

    // MARK: 错误说明

    static func describe(_ error: Error) -> String {
        let e = error as NSError
        var hint: String?
        if e.domain == OSSystemExtensionErrorDomain {
            switch e.code {
            case OSSystemExtensionError.missingEntitlement.rawValue:
                hint = "程序缺少安装系统扩展的权限：需要用 Developer ID 签名并带上描述文件（当前版本未签名）"
            case OSSystemExtensionError.unsupportedParentBundleLocation.rawValue:
                hint = "请先把 Egress Guard 移到「应用程序」文件夹，再从那里打开"
            case OSSystemExtensionError.extensionNotFound.rawValue:
                hint = "应用包里找不到网络扩展"
            case OSSystemExtensionError.codeSignatureInvalid.rawValue:
                hint = "网络扩展的签名无效：需要用 Developer ID 签名并经过公证"
            case OSSystemExtensionError.validationFailed.rawValue:
                hint = "系统校验网络扩展失败（签名、权限或 Info.plist 不符合要求）"
            case OSSystemExtensionError.forbiddenBySystemPolicy.rawValue:
                hint = "系统策略禁止加载这个扩展（例如被设备管理描述文件限制）"
            case OSSystemExtensionError.requestCanceled.rawValue:
                hint = "请求已取消"
            case OSSystemExtensionError.requestSuperseded.rawValue:
                hint = "请求被新的请求取代"
            case OSSystemExtensionError.authorizationRequired.rawValue:
                hint = "需要管理员授权"
            default:
                break
            }
        } else if e.domain == NEFilterErrorDomain {
            switch e.code {
            case NEFilterManagerError.configurationPermissionDenied.rawValue:
                hint = "没有配置内容过滤的权限：需要用 Developer ID 签名并带上描述文件（当前版本未签名）"
            case NEFilterManagerError.configurationInvalid.rawValue:
                hint = "内容过滤配置无效"
            case NEFilterManagerError.configurationDisabled.rawValue:
                hint = "内容过滤已被关闭"
            case NEFilterManagerError.configurationStale.rawValue:
                hint = "内容过滤配置已被其他程序修改，请重试"
            case NEFilterManagerError.configurationCannotBeRemoved.rawValue:
                hint = "内容过滤配置无法删除"
            default:
                break
            }
        }
        let raw = "\(e.domain) \(e.code)：\(e.localizedDescription)"
        return hint.map { "\($0)（\(raw)）" } ?? raw
    }
}

// MARK: C 接口（Rust 调用）

@_cdecl("eg_netext_state_json")
public func eg_netext_state_json() -> UnsafeMutablePointer<CChar>? {
    strdup(Bridge.shared.json())
}

@_cdecl("eg_netext_activate")
public func eg_netext_activate() {
    Bridge.shared.activate()
}

@_cdecl("eg_netext_deactivate")
public func eg_netext_deactivate() {
    Bridge.shared.deactivate()
}

@_cdecl("eg_netext_refresh")
public func eg_netext_refresh() {
    Bridge.shared.refresh()
}

@_cdecl("eg_netext_set_filter")
public func eg_netext_set_filter(_ on: Bool) {
    Bridge.shared.queue.async { Bridge.shared.setFilter(on) }
}

/// CI 自检：查询状态并尝试安装扩展，主线程运行 `seconds` 秒后把状态打印到标准输出。
@_cdecl("eg_netext_selftest")
public func eg_netext_selftest(_ seconds: Double) {
    Bridge.shared.refresh()
    Bridge.shared.activate()
    RunLoop.main.run(until: Date(timeIntervalSinceNow: seconds))
    print(Bridge.shared.json())
    fflush(stdout)
}
