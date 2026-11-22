#!/bin/bash
# 在 GitHub 的 macOS 虚拟机上做端到端测试（需要免密 sudo）：
# 安装后台服务 → 全局断网生效（检测仍可用、例外地址可达）→ 出口进入白名单后放行 → 退出 → 卸载。
# 中间启动界面截图，保存到 target/macos/shots/。
#
# 注意：断网期间 Actions runner 自己也连不上 GitHub，所以断网阶段尽量短。
set -uo pipefail
cd "$(dirname "$0")/../.."

APP="$PWD/target/macos/Egress Guard.app"
CLI="$APP/Contents/MacOS/egress-guard"
GUI="$APP/Contents/MacOS/egress-guard-gui"
SHOTS="$PWD/target/macos/shots"
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
  "$GUI" --page "$page" >/dev/null 2>&1 &
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

step "安装后台服务"
sudo "$CLI" service install || fail "安装失败"
ls -l /Library/LaunchDaemons/com.egressguard.daemon.plist /var/run/egress-guard.sock
wait_for "s.get('running') and s.get('egress_ip')" 60 || fail "服务没有检测到出口 IP"
IP=$(field egress_ip)
echo "出口 IP：$IP"
"$CLI" status
can_reach https://example.com || fail "默认配置（未开启全局断网）不应断网"

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
[[ -z "$(sudo pfctl -a com.apple/egress-guard -s rules 2>/dev/null)" ]] || fail "退出后锚点里仍有规则"

step "卸载"
sudo "$CLI" service uninstall || fail "卸载失败"
[[ ! -e /Library/LaunchDaemons/com.egressguard.daemon.plist ]] || fail "plist 未删除"
can_reach https://example.com || fail "卸载后不能联网"

step "服务日志"
sudo tail -n 80 /Library/Logs/egress-guard.log
sudo cat /Library/Logs/egress-guard.stderr.log 2>/dev/null | tail -20

exit $FAILED
