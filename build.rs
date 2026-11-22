fn main() {
    println!("cargo:rerun-if-changed=assets");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        // 界面程序：图标 + 清单（requireAdministrator、PerMonitorV2 DPI、通用控件 v6）
        embed_resource::compile_for("assets/gui.rc", ["egress-guard-gui"], embed_resource::NONE)
            .manifest_required()
            .unwrap();
        // 命令行程序：只加图标，不强制管理员（ip/check 子命令无需提权）
        embed_resource::compile_for("assets/cli.rc", ["egress-guard"], embed_resource::NONE)
            .manifest_optional()
            .unwrap();
    }
}
