// 系统通知（界面的自动泄露测试、新版本提醒）。Rust 一侧见 src/gui/notify.rs。

import Foundation
import UserNotifications

/// 发一条通知。返回 1 = 已交给系统，0 = 没有权限或失败（Rust 一侧改用 osascript），
/// -1 = 第一次请求权限、用户还没有回应（等用户允许后系统仍会显示，不必再用别的方式重发）。
/// 在回调线程里写、在调用线程里读的结果（加锁）。
private final class NotifyResult: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Int32 = -1
    let done = DispatchSemaphore(value: 0)

    func finish(_ v: Int32) {
        lock.lock(); value = v; lock.unlock()
        done.signal()
    }

    func get() -> Int32 {
        lock.lock(); defer { lock.unlock() }
        return value
    }
}

@_cdecl("eg_notify")
public func eg_notify(_ title: UnsafePointer<CChar>, _ body: UnsafePointer<CChar>) -> Int32 {
    // 不在 .app 包里运行（例如直接运行编译出的程序）时 UNUserNotificationCenter 会直接崩溃
    guard Bundle.main.bundleIdentifier != nil, Bundle.main.bundleURL.pathExtension == "app" else { return 0 }
    let t = String(cString: title)
    let b = String(cString: body)
    let center = UNUserNotificationCenter.current()
    let r = NotifyResult()
    center.requestAuthorization(options: [.alert, .sound]) { granted, _ in
        guard granted else {
            r.finish(0)
            return
        }
        let content = UNMutableNotificationContent()
        content.title = t
        content.body = b
        content.sound = .default
        let req = UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)
        UNUserNotificationCenter.current().add(req) { error in
            r.finish(error == nil ? 1 : 0)
        }
    }
    _ = r.done.wait(timeout: .now() + 15)
    return r.get()
}
