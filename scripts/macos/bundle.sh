#!/bin/bash
# 打包 macOS 应用：target/macos/Egress Guard.app 和 target/macos/egress-guard-<版本>-macos.zip
#
#   scripts/macos/bundle.sh              # 本机架构
#   scripts/macos/bundle.sh --universal  # Apple 芯片 + Intel 通用版本
#
# 默认做 ad-hoc 签名（不需要开发者账号）：全局断网（pf）可以正常使用，
# 网络扩展（按应用断网）会被打进包里，但系统不会加载未签名的扩展。
#
# 用 Developer ID 签名（按应用断网需要），设置下面的环境变量，详见 docs/macos-network-extension.md：
#   SIGN_IDENTITY="Developer ID Application: 名字 (TEAMID)"
#   TEAM_ID=TEAMID
#   APP_PROFILE=主程序的描述文件 .provisionprofile（App ID com.egressguard.app）
#   EXT_PROFILE=网络扩展的描述文件 .provisionprofile（App ID com.egressguard.app.filter）
#   NOTARY_PROFILE=notarytool 保存的钥匙串配置名（可选；设置后自动公证并装订）
set -euo pipefail
cd "$(dirname "$0")/../.."

VERSION=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
OUT=target/macos
APP="$OUT/Egress Guard.app"
BINS=(egress-guard egress-guard-gui)
EXT_ID=com.egressguard.app.filter
EXT="$APP/Contents/Library/SystemExtensions/$EXT_ID.systemextension"

if [[ -n "${SIGN_IDENTITY:-}" ]]; then
  for v in TEAM_ID APP_PROFILE EXT_PROFILE; do
    [[ -n "${!v:-}" ]] || { echo "用 Developer ID 签名时还需要设置 $v（见 docs/macos-network-extension.md）" >&2; exit 1; }
  done
  [[ -f "$APP_PROFILE" && -f "$EXT_PROFILE" ]] || { echo "找不到描述文件 $APP_PROFILE 或 $EXT_PROFILE" >&2; exit 1; }
fi
TEAM="${TEAM_ID:-UNSIGNED}"

SDK=$(xcrun --sdk macosx --show-sdk-path)
# 网络扩展（Swift）：$1 = arm64 / x86_64，$2 = 输出文件
build_ext() {
  xcrun --sdk macosx swiftc -target "$1-apple-macos11.0" -sdk "$SDK" -O \
    -module-name EgressFilter -o "$2" \
    macos/FilterExtension/*.swift macos/Shared/*.swift
}

mkdir -p "$OUT"
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
  build_ext arm64 "$OUT/filter-arm64"
  build_ext x86_64 "$OUT/filter-x86_64"
  lipo -create -output "$OUT/filter" "$OUT/filter-arm64" "$OUT/filter-x86_64"
else
  cargo build --release --bins
  BIN_DIR=target/release
  build_ext "$(uname -m)" "$OUT/filter"
fi

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$EXT/Contents/MacOS"
for b in "${BINS[@]}"; do
  cp "$BIN_DIR/$b" "$APP/Contents/MacOS/$b"
done
sed "s/@VERSION@/$VERSION/g" scripts/macos/Info.plist > "$APP/Contents/Info.plist"
cp "$OUT/filter" "$EXT/Contents/MacOS/$EXT_ID"
sed -e "s/@VERSION@/$VERSION/g" -e "s/@TEAM_ID@/$TEAM/g" macos/FilterExtension/Info.plist > "$EXT/Contents/Info.plist"
plutil -lint "$APP/Contents/Info.plist" "$EXT/Contents/Info.plist"

# 应用图标：运行时绘制的图标导出为 PNG，再用 iconutil 生成 icns
rm -rf "$OUT/AppIcon.iconset"
cargo run --quiet --release --example app_icon -- "$OUT/AppIcon.iconset"
iconutil -c icns -o "$APP/Contents/Resources/AppIcon.icns" "$OUT/AppIcon.iconset"

# 由内向外签名：网络扩展 → 命令行程序 → 整个 .app（主程序随 .app 一起签）
if [[ -n "${SIGN_IDENTITY:-}" ]]; then
  sed "s/@TEAM_ID@/$TEAM_ID/g" macos/FilterExtension/FilterExtension.entitlements > "$OUT/filter.entitlements"
  sed "s/@TEAM_ID@/$TEAM_ID/g" macos/App.entitlements > "$OUT/app.entitlements"
  cp "$EXT_PROFILE" "$EXT/Contents/embedded.provisionprofile"
  cp "$APP_PROFILE" "$APP/Contents/embedded.provisionprofile"
  SIGN=(codesign --force --options runtime --timestamp --sign "$SIGN_IDENTITY")
  "${SIGN[@]}" --entitlements "$OUT/filter.entitlements" "$EXT"
  "${SIGN[@]}" "$APP/Contents/MacOS/egress-guard"
  "${SIGN[@]}" --entitlements "$OUT/app.entitlements" "$APP"
else
  # ad-hoc 签名不能带受限权限（带了系统会拒绝启动程序），所以这里什么权限都不加
  codesign --force --sign - "$EXT"
  codesign --force --sign - "$APP/Contents/MacOS/egress-guard"
  codesign --force --sign - "$APP"
fi
codesign --verify --deep --strict --verbose=2 "$APP"

ZIP="$OUT/egress-guard-$VERSION-macos.zip"
rm -f "$ZIP"
ditto -c -k --keepParent "$APP" "$ZIP"

if [[ -n "${SIGN_IDENTITY:-}" && -n "${NOTARY_PROFILE:-}" ]]; then
  echo "提交 Apple 公证…"
  xcrun notarytool submit "$ZIP" --keychain-profile "$NOTARY_PROFILE" --wait
  xcrun stapler staple "$APP"
  rm -f "$ZIP"
  ditto -c -k --keepParent "$APP" "$ZIP"
  spctl --assess --type execute --verbose=2 "$APP"
fi
echo "已生成：$APP"
echo "已生成：$ZIP"
