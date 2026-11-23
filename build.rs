use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=assets");
    println!("cargo:rustc-check-cfg=cfg(eg_netext)");
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if os == "windows" {
        // 界面程序：图标 + 清单（requireAdministrator、PerMonitorV2 DPI、通用控件 v6）
        embed_resource::compile_for("assets/gui.rc", ["egress-guard-gui"], embed_resource::NONE)
            .manifest_required()
            .unwrap();
        // 命令行程序：只加图标，不强制管理员（ip/check 子命令无需提权）
        embed_resource::compile_for("assets/cli.rc", ["egress-guard"], embed_resource::NONE)
            .manifest_optional()
            .unwrap();
    }
    if os == "macos" {
        println!("cargo:rerun-if-changed=macos/Bridge");
        println!("cargo:rerun-if-env-changed=EGRESS_GUARD_NO_NETEXT");
        if std::env::var_os("EGRESS_GUARD_NO_NETEXT").is_none() {
            build_netext_bridge();
            println!("cargo:rustc-cfg=eg_netext");
        }
    }
}

fn run(cmd: &mut Command) -> String {
    let out = cmd.output().unwrap_or_else(|e| panic!("无法运行 {cmd:?}: {e}"));
    if !out.status.success() {
        panic!(
            "{cmd:?} 失败：\n{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// 把 macos/Bridge/*.swift（安装网络扩展、开关内容过滤）编译成静态库并链接。
/// 需要 Xcode 或 Xcode 命令行工具；没有 Swift 时可以设置 EGRESS_GUARD_NO_NETEXT=1 跳过（界面里不显示网络扩展）。
fn build_netext_bridge() {
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let target = std::env::var("TARGET").unwrap();
    let arch = match target.split('-').next() {
        Some("aarch64") => "arm64",
        Some(a) => a,
        None => "arm64",
    };
    let sdk = run(Command::new("xcrun").args(["--sdk", "macosx", "--show-sdk-path"]));
    let swiftc = run(Command::new("xcrun").args(["--sdk", "macosx", "-f", "swiftc"]));
    let mut sources: Vec<PathBuf> = std::fs::read_dir("macos/Bridge")
        .expect("macos/Bridge")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "swift"))
        .collect();
    sources.sort();
    let lib = out.join("libEgressBridge.a");
    run(Command::new(&swiftc)
        .args(["-target", &format!("{arch}-apple-macos11.0"), "-sdk", &sdk])
        .args(["-O", "-parse-as-library", "-emit-library", "-static", "-module-name", "EgressBridge"])
        .arg("-module-cache-path")
        .arg(out.join("swift-module-cache"))
        .arg("-o")
        .arg(&lib)
        .args(&sources));

    // Swift 运行库：系统自带（/usr/lib/swift，macOS 11 起）+ 工具链里的兼容库（静态）
    let toolchain_lib = Path::new(&swiftc).parent().and_then(Path::parent).map(|d| d.join("lib/swift/macosx"));
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=EgressBridge");
    if let Some(d) = toolchain_lib {
        println!("cargo:rustc-link-search=native={}", d.display());
    }
    println!("cargo:rustc-link-search=native={sdk}/usr/lib/swift");
    for fw in ["Foundation", "NetworkExtension", "SystemExtensions", "Security", "UserNotifications"] {
        println!("cargo:rustc-link-lib=framework={fw}");
    }
    println!("cargo:rustc-link-arg=-Wl,-rpath,/usr/lib/swift");
}
