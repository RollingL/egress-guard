#!/bin/bash
# 打包 macOS 应用：target/macos/Egress Guard.app 和 target/macos/egress-guard-<版本>-macos.zip
#
#   scripts/macos/bundle.sh              # 本机架构
#   scripts/macos/bundle.sh --universal  # Apple 芯片 + Intel 通用版本
#
# 默认做 ad-hoc 签名（不需要开发者账号）。设置 SIGN_IDENTITY="Developer ID Application: …"
# 时改用该证书签名并开启 hardened runtime，之后可以用 notarytool 公证。
set -euo pipefail
cd "$(dirname "$0")/../.."

VERSION=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
OUT=target/macos
APP="$OUT/Egress Guard.app"
BINS=(egress-guard egress-guard-gui)

if [[ "${1:-}" == "--universal" ]]; then
  for t in aarch64-apple-darwin x86_64-apple-darwin; do
    rustup target add "$t" >/dev/null
    cargo build --release --target "$t" --bins
  done
  mkdir -p target/universal
  for b in "${BINS[@]}"; do
    lipo -create -output "target/universal/$b" \
      "target/aarch64-apple-darwin/release/$b" "target/x86_64-apple-darwin/release/$b"
  done
  BIN_DIR=target/universal
else
  cargo build --release --bins
  BIN_DIR=target/release
fi

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
for b in "${BINS[@]}"; do
  cp "$BIN_DIR/$b" "$APP/Contents/MacOS/$b"
done
sed "s/@VERSION@/$VERSION/g" scripts/macos/Info.plist > "$APP/Contents/Info.plist"

# 应用图标：运行时绘制的图标导出为 PNG，再用 iconutil 生成 icns
rm -rf "$OUT/AppIcon.iconset"
cargo run --quiet --release --example app_icon -- "$OUT/AppIcon.iconset"
iconutil -c icns -o "$APP/Contents/Resources/AppIcon.icns" "$OUT/AppIcon.iconset"

if [[ -n "${SIGN_IDENTITY:-}" ]]; then
  for b in "${BINS[@]}"; do
    codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" "$APP/Contents/MacOS/$b"
  done
  codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY" "$APP"
else
  codesign --force --deep --sign - "$APP"
fi
codesign --verify --verbose "$APP"

ZIP="$OUT/egress-guard-$VERSION-macos.zip"
rm -f "$ZIP"
ditto -c -k --keepParent "$APP" "$ZIP"
echo "已生成：$APP"
echo "已生成：$ZIP"
