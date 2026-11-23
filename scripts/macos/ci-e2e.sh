#!/bin/bash
# 在 GitHub 的 macOS 虚拟机上做端到端测试（需要免密 sudo）：
# 界面与系统剪贴板互通（复制、⌘V 粘贴）→
# 安装后台服务 → 按应用断网的规则推送（用测试客户端代替网络扩展）→ 全局断网生效（检测仍可用、例外地址可达）
# → 出口进入白名单后放行 → 退出 → 卸载。中间启动界面截图，保存到 target/macos/shots/。
#
# 网络扩展本身（NEFilterDataProvider）需要 Developer ID 签名才能被系统加载，CI 里测不到；
# 这里测的是它与后台服务之间的协议，用的是扩展里同一份 Swift 代码（macos/Shared）。
#
# 注意：断网期间 Actions runner 自己也连不上 GitHub，所以断网阶段尽量短。
set -uo pipefail
cd "$(dirname "$0")/../.."

APP="$PWD/target/macos/Egress Guard.app"
CLI="$APP/Contents/MacOS/egress-guard"
GUI="$APP/Contents/MacOS/egress-guard-gui"
SHOTS="$PWD/target/macos/shots"
FEEDTEST="$PWD/target/macos/feedtest"
SOCK=/var/run/egress-guard.sock
MARKER=/var/run/egress-guard.running
mkdir -p "$SHOTS"
FAILED=0

step() { echo; echo "==== $* ===="; }
fail() { echo "FAIL: $*"; FAILED=1; }

status_json() { "$CLI" status 2>/dev/null; }
# 等待状态满足条件（python 表达式，s 为 status 字典）
wait_for() {
  local expr="$1" secs="${2:-60}"
  for _ in $(seq 1 "$secs"); do
    if status_json | python3 -c "import json,sys; s=json.load(sys.stdin)['status']; sys.exit(0 if ($expr) else 1)" 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "等待超时：$expr"
  status_json
  return 1
}
field() { status_json | python3 -c "import json,sys; print(json.load(sys.stdin)['status'].get('$1') or '')"; }
can_reach() { curl -sS -m 8 -o /dev/null "$1"; }

# 截图：启动界面打开指定页面，截全屏
shot() {
  local name="$1" page="$2"
  # 第 4 个参数是额外的界面参数（如 --leak-test）
  # shellcheck disable=SC2086
  "$GUI" --page "$page" ${4:-} >/dev/null 2>&1 &
  local pid=$!
  sleep "${3:-6}"
  screencapture -x "$SHOTS/$name.png" || echo "截图失败：$name"
  kill "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
  sleep 1
}

write_cfg() { # $1 = 白名单（TOML 数组内容）$2 = 外观
  cat > /tmp/eg.toml <<TOML
whitelist = [$1]
[detect]
interval_secs = 10
[ui]
appearance = "$2"
[block_all]
enabled = true
allow_lan = true
allow_dns = true
allow_remote = ["1.1.1.1"]
TOML
}

step "环境"
sw_vers
sudo pfctl -s info | head -3
sudo pfctl -s rules 2>/dev/null | head -20

step "未安装服务时的界面"
shot 0-not-installed overview 5

step "网络扩展自检（未签名：预期系统拒绝安装，这里只确认桥接代码能运行并给出原因）"
sudo rm -rf "/Applications/Egress Guard.app"
sudo ditto "$APP" "/Applications/Egress Guard.app"
SELF=$("/Applications/Egress Guard.app/Contents/MacOS/egress-guard-gui" --netext-selftest 8 | tail -1)
echo "$SELF"
echo "$SELF" | python3 -c "import json,sys; s=json.load(sys.stdin); print('bundled', s['bundled'], 'team', s.get('team_id'), 'phase', s['phase']); sys.exit(0 if s['bundled'] and s['loaded'] else 1)" \
  || fail "网络扩展自检失败：$SELF"
sudo rm -rf "/Applications/Egress Guard.app"

step "复制粘贴：界面与系统剪贴板互通（⌘C / ⌘V）"
CLIP_OUT=/tmp/eg-clipboard.json
rm -f "$CLIP_OUT"
printf 'before' | pbcopy
"$GUI" --clipboard-selftest "$CLIP_OUT" 10 >/tmp/eg-clipboard.log 2>&1 &
CPID=$!
sleep 5
COPIED=$(pbpaste)
[[ "$COPIED" == "egress-guard-copy-ok" ]] && echo "OK：界面里复制的文字到了系统剪贴板" \
  || fail "界面里复制的文字没有到系统剪贴板（pbpaste：${COPIED}）"
printf '203.0.113.7' | pbcopy
# 模拟按下 ⌘V（发给前台程序，需要辅助功能权限；GitHub 的 macOS 虚拟机一般已授予）
KEYED=0
if osascript -e 'tell application "System Events" to keystroke "v" using command down' 2>/tmp/eg-key.err; then
  KEYED=1
else
  echo "System Events 发送按键失败：$(cat /tmp/eg-key.err)；改用 CGEvent"
  osascript -l JavaScript -e "ObjC.import('CoreGraphics');
    for (const down of [true, false]) {
      const e = \$.CGEventCreateKeyboardEvent(null, 9, down);
      \$.CGEventSetFlags(e, \$.kCGEventFlagMaskCommand);
      \$.CGEventPost(\$.kCGHIDEventTap, e);
    }" && KEYED=2
fi
sleep 2
screencapture -x "$SHOTS/10-clipboard-paste.png" || true
wait "$CPID"
PASTED=$(python3 -c "import json; print(json.load(open('$CLIP_OUT'))['pasted'])" 2>/dev/null)
echo "输入框内容：${PASTED}（按键方式 ${KEYED}）"
if [[ "$PASTED" == "203.0.113.7" ]]; then
  echo "OK：⌘V 把系统剪贴板的内容粘贴进了输入框"
elif [[ "$KEYED" == 1 ]]; then
  fail "按下 ⌘V 后输入框里没有系统剪贴板的内容"
  cat /tmp/eg-clipboard.log
else
  echo "WARN：没能模拟按键（没有辅助功能权限），只验证了复制"
fi

step "安装后台服务"
sudo "$CLI" service install || fail "安装失败"
ls -l /Library/LaunchDaemons/com.egressguard.daemon.plist /var/run/egress-guard.sock
wait_for "s.get('running') and s.get('egress_ip')" 60 || fail "服务没有检测到出口 IP"
IP=$(field egress_ip)
echo "出口 IP：$IP"
"$CLI" status
can_reach https://example.com || fail "默认配置（未开启全局断网）不应断网"
[[ -e "$MARKER" ]] && echo "OK：运行标记 $MARKER 存在" || fail "服务运行时没有 $MARKER"

step "按应用断网：没有网络扩展时规则不生效、不影响其他程序"
cat > /tmp/eg.toml <<TOML
whitelist = []
apps = ["/Applications/Safari.app", "/System/Applications/Calculator.app"]
[detect]
interval_secs = 10
[ui]
appearance = "light"
TOML
"$CLI" apply /tmp/eg.toml || fail "apply 失败"
wait_for "s.get('blocked') and not s.get('block_all')" 30 || fail "没有进入阻断"
[[ "$(field per_app)" == "" ]] && echo "OK：没有网络扩展时 per_app = false" || fail "没有网络扩展却报告 per_app"
can_reach https://example.com && echo "OK：其他程序不受影响" || fail "按应用阻断不应影响其他程序"
shot 7-apps-unsigned-light apps 5

step "按应用断网：测试客户端以网络扩展的身份接收规则"
sudo "$FEEDTEST" --feed "$SOCK" "$MARKER" --expect-app /Applications/Safari.app --expect blocked,allowed --timeout 120 \
  > /tmp/feedtest.log 2>&1 &
FEED_PID=$!
wait_for "s.get('filter_ext') and s.get('per_app')" 30 || fail "后台服务没有看到网络扩展连接"
"$CLI" status
shot 8-perapp-blocked-light overview 6
shot 9-apps-connected-light apps 5
write_cfg_apps_ok() {
  cat > /tmp/eg.toml <<TOML
whitelist = ["$IP"]
apps = ["/Applications/Safari.app", "/System/Applications/Calculator.app"]
[detect]
interval_secs = 10
[ui]
appearance = "dark"
TOML
}
write_cfg_apps_ok
"$CLI" apply /tmp/eg.toml || fail "apply 失败"
wait_for "not s.get('blocked')" 30 || fail "出口进入白名单后没有放行"
if wait "$FEED_PID"; then echo "OK：网络扩展依次收到 阻断 → 放行"; else fail "网络扩展测试客户端失败"; fi
cat /tmp/feedtest.log
wait_for "not s.get('filter_ext')" 30 || fail "网络扩展断开后后台服务仍报告已连接"

step "全局断网：白名单为空"
write_cfg "" light
"$CLI" apply /tmp/eg.toml || fail "apply 失败"
wait_for "s.get('blocked') and s.get('block_all')" 30 || fail "没有进入阻断"
sudo pfctl -a com.apple/egress-guard -s rules
# 断网时出口 IP 检测必须仍然可用（以 nobody 运行，被 pf 放行）
BEFORE=$(field last_check)
"$CLI" check-now
wait_for "s.get('last_check') != '$BEFORE' and not s.get('checking')" 40 || fail "断网时检测没有完成"
[[ -z "$(field detect_error)" ]] || fail "断网时检测失败：$(field detect_error)"
if can_reach https://example.com; then fail "全局断网没有生效：example.com 仍可访问"; else echo "OK：example.com 已被阻断"; fi
can_reach https://1.1.1.1 && echo "OK：例外地址 1.1.1.1 可访问" || fail "例外地址 1.1.1.1 不可访问"
dig +short +time=3 +tries=1 example.com | head -2 && echo "OK：DNS 可用" || fail "DNS 被阻断"
shot 1-blocked-light overview
shot 2-network-light network 4

step "出口 IP 加入白名单 → 放行"
write_cfg "\"$IP\"" dark
"$CLI" apply /tmp/eg.toml || fail "apply 失败"
wait_for "not s.get('blocked')" 30 || fail "没有放行"
can_reach https://example.com && echo "OK：已放行" || fail "放行后仍不能访问"
[[ -z "$(sudo pfctl -a com.apple/egress-guard -s rules 2>/dev/null)" ]] || fail "放行后锚点里仍有规则"
shot 3-allowed-dark overview
shot 4-settings-dark settings 4
shot 5-whitelist-dark whitelist 4

step "泄露测试（DNS、WebRTC）：以普通用户运行，结果与白名单对比"
"$CLI" -c /tmp/eg.toml leak-test || fail "泄露测试命令失败"
"$CLI" -c /tmp/eg.toml leak-test --json > /tmp/leak.json 2>/tmp/leak.err || fail "泄露测试（JSON）失败：$(cat /tmp/leak.err)"
# 依赖外部服务：结果只打印、不作为失败条件；但输出必须是完整的 JSON，并且至少测了默认路由
python3 - /tmp/leak.json <<'PY' || fail "泄露测试输出不完整"
import json, sys
r = json.load(open(sys.argv[1]))
d, w = r["dns"], r["webrtc"]
print("DNS：", d.get("summary", {}).get("text") or d.get("error"))
print("WebRTC：", w["summary"]["text"])
assert w["report"]["paths"], "WebRTC 没有测试任何路径"
assert "summary" in d or "error" in d
PY
shot 11-leaktest-dark leaktest 35 --leak-test
write_cfg "\"$IP\"" light
"$CLI" apply /tmp/eg.toml || fail "apply 失败"
shot 12-leaktest-light leaktest 35 --leak-test

step "菜单栏应用：窗口隐藏后再次打开应用会显示窗口"
pkill -f "$GUI" 2>/dev/null
open "$APP" --args --minimized
sleep 6
GPID=$(pgrep -f "$GUI" | head -1)
# 本进程在屏幕上的普通窗口数（CGWindowList，不需要辅助功能权限）
windows() {
  osascript -l JavaScript -e "ObjC.import('CoreGraphics');
    const l = ObjC.deepUnwrap(ObjC.castRefToObject(\$.CGWindowListCopyWindowInfo(\$.kCGWindowListOptionOnScreenOnly, 0)));
    l.filter(w => w.kCGWindowOwnerPID == $GPID && w.kCGWindowLayer == 0).length" 2>/dev/null
}
echo "界面进程 ${GPID}，隐藏时窗口数：$(windows)"
open "$APP"
sleep 3
N=$(windows)
echo "再次打开后窗口数：$N"
screencapture -x "$SHOTS/6-reopened.png" || true
[[ "$N" == "0" ]] && fail "再次打开应用没有显示窗口"
[[ "$(pgrep -f "$GUI" | wc -l | tr -d ' ')" == "1" ]] || fail "再次打开应用启动了第二个界面进程"
pkill -f "$GUI" 2>/dev/null

step "退出（stop）后不再阻断"
write_cfg "" light
"$CLI" apply /tmp/eg.toml
wait_for "s.get('blocked')" 30 || fail "没有再次阻断"
"$CLI" stop || fail "stop 失败"
sleep 2
can_reach https://example.com && echo "OK：退出后网络恢复" || fail "退出后仍然断网"
[[ ! -e "$MARKER" ]] && echo "OK：退出后运行标记已删除（网络扩展不会再把服务拉起来）" || fail "退出后 $MARKER 仍存在"
[[ -z "$(sudo pfctl -a com.apple/egress-guard -s rules 2>/dev/null)" ]] || fail "退出后锚点里仍有规则"

step "卸载"
sudo "$CLI" service uninstall || fail "卸载失败"
[[ ! -e /Library/LaunchDaemons/com.egressguard.daemon.plist ]] || fail "plist 未删除"
can_reach https://example.com || fail "卸载后不能联网"

step "服务日志"
sudo tail -n 80 /Library/Logs/egress-guard.log
sudo cat /Library/Logs/egress-guard.stderr.log 2>/dev/null | tail -20

exit $FAILED
