//! 生成 macOS 应用图标用的 PNG：`cargo run --example app_icon -- <输出目录>`
//! 输出 icon_16x16.png … icon_512x512@2x.png，供 iconutil 生成 AppIcon.icns。

fn main() {
    let dir = std::path::PathBuf::from(std::env::args().nth(1).unwrap_or_else(|| "AppIcon.iconset".into()));
    std::fs::create_dir_all(&dir).unwrap();
    for base in [16u32, 32, 128, 256, 512] {
        for scale in [1u32, 2] {
            let px = base * scale;
            let name = if scale == 1 { format!("icon_{base}x{base}.png") } else { format!("icon_{base}x{base}@2x.png") };
            let png = egress_guard::gui::icons::encode_png(&egress_guard::gui::icons::app_icon_rgba(px), px, px);
            std::fs::write(dir.join(name), png).unwrap();
        }
    }
}
