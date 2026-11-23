#!/usr/bin/env bash
# 用假 gh（fake-gh.py）测试 publish.sh 的各种情况：新建、续传、已公开、冲突草稿、标签冲突与并发、
# 鉴权失败、远端摘要不符、缺少安装包。失败的情况必须保持未公开，正常重跑只产生一个 Release。
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin" "$WORK/dist"
cp "$HERE/fake-gh.py" "$WORK/bin/gh"
export PATH="$WORK/bin:$PATH" GITHUB_REPOSITORY=owner/repo FAKE_GH_STATE="$WORK/state.json"
V=1.2.3
SHA=1111111111111111111111111111111111111111
OTHER=2222222222222222222222222222222222222222
MARK="<!-- egress-guard-release sha=$SHA -->"
printf 'windows' >"$WORK/dist/egress-guard-v$V-windows.zip"
printf 'macos-zip' >"$WORK/dist/egress-guard-v$V-macos.zip"
digest() { echo "sha256:$(printf '%s' "$1" | sha256sum | cut -d' ' -f1)"; }

failed=0
run() { "$HERE/publish.sh" "$V" "$SHA" "$WORK/dist" >"$WORK/out" 2>&1; }
state() { jq -r "$1" "$FAKE_GH_STATE"; }
check() {
  local name=$1 expect=$2 cond=$3
  local rc=0
  run || rc=$?
  if [[ "$expect" == ok && $rc -ne 0 ]] || [[ "$expect" == fail && $rc -eq 0 ]]; then
    echo "FAIL $name：退出码 $rc"; cat "$WORK/out"; failed=1; return
  fi
  if [[ "$(state "$cond")" != true ]]; then
    echo "FAIL $name：状态不符（$cond）"; cat "$WORK/out"; jq . "$FAKE_GH_STATE"; failed=1; return
  fi
  echo "ok   $name"
}
published_once='([.releases[] | select(.tag_name == "v'$V'" and .draft == false)] | length == 1) and (.releases | length == 1) and .refs["v'$V'"].sha == "'$SHA'" and (.releases[0].assets | length == 2)'
none_public='([.releases[] | select(.draft == false)] | length == 0)'

echo '{}' >"$FAKE_GH_STATE"
check "全新发布" ok "$published_once"

# 再跑一次：已公开，跳过，不新建
check "同版本已公开时跳过" ok "$published_once and (([.calls[] | select(startswith(\"POST\"))] | length == 4))"

# 上传中断后重跑：草稿里一个资产没传完，另一个缺
jq -n --arg m "$MARK" --arg s "$SHA" '{releases: [{id: 7, tag_name: "v1.2.3", target_commitish: $s, name: "x", body: ("notes\n" + $m), draft: true,
  assets: [{id: 8, name: "egress-guard-v1.2.3-windows.zip", size: 3, state: "starter", digest: null}]}]}' >"$FAKE_GH_STATE"
check "中断后续传同一个草稿" ok "$published_once and .releases[0].id == 7 and (([.calls[] | select(. == \"DELETE repos/owner/repo/releases/assets/8\")] | length == 1))"

# 续传时已有的资产完全一致：不重传
jq -n --arg m "$MARK" --arg s "$SHA" --arg d "$(digest windows)" '{releases: [{id: 7, tag_name: "v1.2.3", target_commitish: $s, name: "x", body: $m, draft: true,
  assets: [{id: 8, name: "egress-guard-v1.2.3-windows.zip", size: 7, state: "uploaded", digest: $d}]}]}' >"$FAKE_GH_STATE"
check "一致的资产不重传" ok "$published_once and (([.calls[] | select(startswith(\"POST\") and contains(\"assets\"))] | length == 1))"

# 已有资产没有摘要、下载核对时服务出错（503），上传也 503：保留现有资产，不删除，保持草稿
jq -n --arg m "$MARK" --arg s "$SHA" '{fail: {"GET repos/owner/repo/releases/assets": 503, "POST https://uploads.github.com": 503},
  releases: [{id: 7, tag_name: "v1.2.3", target_commitish: $s, name: "x", body: $m, draft: true,
  assets: [{id: 8, name: "egress-guard-v1.2.3-windows.zip", size: 7, state: "uploaded", digest: null, content: "windows"}]}]}' >"$FAKE_GH_STATE"
check "暂时无法核实时保留资产" fail "$none_public and (.releases[0].assets | length == 1) and (([.calls[] | select(startswith(\"DELETE\"))] | length == 0))"
jq 'del(.fail)' "$FAKE_GH_STATE" >"$WORK/s" && mv "$WORK/s" "$FAKE_GH_STATE"
check "恢复后重跑：没有摘要但下载核对一致，不重传" ok "$published_once and (([.calls[] | select(startswith(\"DELETE\"))] | length == 0))"

# 没有摘要、下载下来内容不符：确定不同，替换
jq -n --arg m "$MARK" --arg s "$SHA" '{releases: [{id: 7, tag_name: "v1.2.3", target_commitish: $s, name: "x", body: $m, draft: true,
  assets: [{id: 8, name: "egress-guard-v1.2.3-windows.zip", size: 7, state: "uploaded", digest: null, content: "WINDOWS"}]}]}' >"$FAKE_GH_STATE"
check "下载核对内容不符时替换" ok "$published_once and (([.calls[] | select(. == \"DELETE repos/owner/repo/releases/assets/8\")] | length == 1))"

# 403（例如令牌权限不足）：同样不删除
jq -n --arg m "$MARK" --arg s "$SHA" '{fail: {"GET repos/owner/repo/releases/assets": 403},
  releases: [{id: 7, tag_name: "v1.2.3", target_commitish: $s, name: "x", body: $m, draft: true,
  assets: [{id: 8, name: "egress-guard-v1.2.3-windows.zip", size: 7, state: "uploaded", digest: null, content: "windows"}]}]}' >"$FAKE_GH_STATE"
check "下载 403 时保留资产" fail "$none_public and (.releases[0].assets | length == 1)"

# 两层附注标签剥离后指向本次提交
jq -n --arg s "$SHA" '{refs: {"v1.2.3": {type: "tag", sha: "t1"}}, tag_objects: {t1: {type: "tag", sha: "t2"}, t2: {type: "commit", sha: $s}}}' >"$FAKE_GH_STATE"
check "两层附注标签剥离后一致" ok "([.releases[] | select(.draft == false)] | length == 1)"

# 别的提交留下的草稿：不碰它
jq -n --arg o "$OTHER" '{releases: [{id: 7, tag_name: "v1.2.3", target_commitish: $o, name: "x", body: "", draft: true, assets: []}]}' >"$FAKE_GH_STATE"
check "冲突草稿时失败" fail "$none_public and (.releases | length == 1) and (.refs | length == 0)"

# 同提交但不是本流程创建（没有标记）
jq -n --arg s "$SHA" '{releases: [{id: 7, tag_name: "v1.2.3", target_commitish: $s, name: "x", body: "manual", draft: true, assets: []}]}' >"$FAKE_GH_STATE"
check "没有标记的草稿也不碰" fail "$none_public and (.releases | length == 1)"

# 标签已存在、指向别的提交
jq -n --arg o "$OTHER" '{refs: {"v1.2.3": {type: "commit", sha: $o}}}' >"$FAKE_GH_STATE"
check "标签指向别的提交时失败" fail "$none_public and (.releases | length == 0)"

# 附注标签指向本次提交：可以
jq -n --arg s "$SHA" '{refs: {"v1.2.3": {type: "tag", sha: "abc"}}, tag_objects: {abc: {type: "commit", sha: $s}}}' >"$FAKE_GH_STATE"
check "附注标签剥离后一致" ok "([.releases[] | select(.draft == false)] | length == 1)"

# 创建标签时别人刚建好：指向本次提交可以，指向别的提交失败
jq -n --arg s "$SHA" '{ref_race: $s}' >"$FAKE_GH_STATE"
check "并发创建标签（同一提交）" ok "$published_once"
jq -n --arg o "$OTHER" '{ref_race: $o}' >"$FAKE_GH_STATE"
check "并发创建标签（别的提交）" fail "$none_public"

# 鉴权失败：不能当作「还没发布」
echo '{"fail": {"GET repos/owner/repo/releases": 401}}' >"$FAKE_GH_STATE"
check "鉴权失败" fail "$none_public and (.releases | length == 0)"

# 远端摘要与本地不符
echo '{"corrupt_uploads": true}' >"$FAKE_GH_STATE"
check "远端摘要不符时不公开" fail "$none_public"

# 公开这一步失败：保持草稿，重跑后只有一个 Release
echo '{"fail": {"PATCH repos/owner/repo/releases": 500}}' >"$FAKE_GH_STATE"
check "公开失败时保持草稿" fail "$none_public and (.releases | length == 1)"
jq 'del(.fail)' "$FAKE_GH_STATE" >"$WORK/s" && mv "$WORK/s" "$FAKE_GH_STATE"
check "公开失败后重跑" ok "$published_once"

# 缺少安装包
rm "$WORK/dist/egress-guard-v$V-macos.zip"
echo '{}' >"$FAKE_GH_STATE"
check "缺少安装包" fail "(.releases | length == 0) and (.calls | length == 0)"

exit $failed
