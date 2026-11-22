// 系统扩展入口：把进程交给 NetworkExtension 框架，它会按 Info.plist 的 NEProviderClasses 创建 FilterDataProvider。

import Foundation
import NetworkExtension

autoreleasepool {
    NEProvider.startSystemExtensionMode()
}
dispatchMain()
