#!/usr/bin/env bash
# 创建或续传 GitHub Release，核对后才公开。由 .github/workflows/release.yml 调用，
# 也可以用 scripts/release/test-publish.sh 里的假 gh 在本地测试。
#
# 用法：publish.sh <版本> <提交 SHA> <安装包目录>，需要 GITHUB_REPOSITORY 和 gh 的鉴权。
#
# 规则：
# - 同版本已经公开：跳过（成功退出）。
# - 同提交、由本流程创建的草稿（目标提交和正文里的标记都对得上）：按它的 release ID 续传。
# - 其他同标签草稿：报错，不动它。
# - 资产按名字、大小和 SHA-256 与本地安装包核对；确定对不上的删掉重传，暂时无法核实（下载失败）时保留并失败退出。
# - 公开前确认标签剥离到的提交就是本次提交；标签不存在时先绑定到本次提交，并发创建时读回再核对。
# - 任何一步失败都保持草稿状态。
set -euo pipefail

V=${1:?版本}
SHA=${2:?提交}
DIST=${3:?安装包目录}
R=${GITHUB_REPOSITORY:?GITHUB_REPOSITORY}
TAG="v$V"
MARK="<!-- egress-guard-release sha=$SHA -->"
ASSETS=("egress-guard-v$V-windows.zip" "egress-guard-v$V-macos.zip")

die() { echo "::error::$*" >&2; exit 1; }
sha256() { sha256sum "$1" | cut -d' ' -f1; }
size() { stat -c %s "$1" 2>/dev/null || stat -f %z "$1"; }

# 调用 gh api；失败时把 HTTP 状态码放进 $HTTP，输出放进 $OUT
api() {
  HTTP=""
  if OUT=$(gh api "$@" 2>&1); then
    return 0
  fi
  HTTP=$(grep -oE 'HTTP [0-9]{3}' <<<"$OUT" | tail -1 | cut -d' ' -f2 || true)
  return 1
}

for f in "${ASSETS[@]}"; do
  [[ -s "$DIST/$f" ]] || die "缺少安装包 $f"
done

# 标签剥离到的提交；标签不存在时输出空
tag_commit() {
  if ! api "repos/$R/git/ref/tags/$TAG"; then
    [[ "$HTTP" == 404 ]] && return 0
    die "查询标签失败：$OUT"
  fi
  local type obj
  type=$(jq -r .object.type <<<"$OUT")
  obj=$(jq -r .object.sha <<<"$OUT")
  # 附注标签可能套几层
  for _ in 1 2 3 4 5; do
    [[ "$type" == tag ]] || break
    api "repos/$R/git/tags/$obj" || die "读取标签对象失败：$OUT"
    type=$(jq -r .object.type <<<"$OUT")
    obj=$(jq -r .object.sha <<<"$OUT")
  done
  [[ "$type" == commit ]] || die "标签 $TAG 指向 $type，不是提交"
  echo "$obj"
}

# 1. 现有的同标签发布（草稿只能从列表里找）
api --paginate "repos/$R/releases?per_page=100" || die "查询发布列表失败：$OUT"
same=$(jq -c --arg t "$TAG" '.[] | select(.tag_name == $t)' <<<"$OUT")
published=$(jq -c 'select(.draft == false)' <<<"$same")
if [[ -n "$published" ]]; then
  echo "$TAG 已经公开，跳过"
  exit 0
fi
ours=$(jq -c --arg s "$SHA" --arg m "$MARK" 'select(.target_commitish == $s and ((.body // "") | contains($m)))' <<<"$same")
n_same=$(grep -c . <<<"$same" || true)
n_ours=$(grep -c . <<<"$ours" || true)
if (( n_same > n_ours )); then
  die "已有不是本流程（提交 $SHA）创建的 $TAG 草稿，请先人工处理"
fi
(( n_ours <= 1 )) || die "有 $n_ours 个本流程的 $TAG 草稿，请先删掉多余的"

# 2. 标签如果已经存在，必须指向本次提交
existing=$(tag_commit)
[[ -z "$existing" || "$existing" == "$SHA" ]] || die "标签 $TAG 已存在并指向 $existing，不是 $SHA"

# 3. 续用或新建草稿
if (( n_ours == 1 )); then
  ID=$(jq -r .id <<<"$ours")
  echo "续传草稿 $ID"
else
  body=$(jq -n --arg t "$TAG" --arg s "$SHA" --arg n "Egress Guard $V" --arg b "$MARK" \
    '{tag_name: $t, target_commitish: $s, name: $n, body: $b, draft: true, generate_release_notes: true}')
  api -X POST "repos/$R/releases" --input - <<<"$body" || die "创建草稿失败：$OUT"
  ID=$(jq -r .id <<<"$OUT")
  echo "已创建草稿 $ID"
fi

# 远端资产与本地是否一致：名字、状态、大小、SHA-256（没有摘要时下载下来算）。
# 返回 0：一致；1：确定不一致（没传完、大小或摘要不同）；2：暂时无法核实（下载失败等）。
# 只有确定不一致才替换；暂时无法核实时保留现有资产，本次失败退出，下次重跑再核对。
remote_ok() {
  local asset=$1 f=$2 digest id
  [[ "$(jq -r .state <<<"$asset")" == uploaded ]] || return 1
  [[ "$(jq -r .size <<<"$asset")" == "$(size "$f")" ]] || return 1
  digest=$(jq -r '.digest // ""' <<<"$asset")
  if [[ -z "$digest" ]]; then
    id=$(jq -r .id <<<"$asset")
    local tmp
    tmp=$(mktemp)
    if ! gh api -H "Accept: application/octet-stream" "repos/$R/releases/assets/$id" >"$tmp" 2>/dev/null; then
      rm -f "$tmp"
      return 2
    fi
    digest="sha256:$(sha256 "$tmp")"
    rm -f "$tmp"
  fi
  [[ "$digest" == "sha256:$(sha256 "$f")" ]] || return 1
}

list_assets() {
  api --paginate "repos/$R/releases/$ID/assets?per_page=100" || die "读取草稿资产失败：$OUT"
  jq -c '.[]' <<<"$OUT"
}

# 4. 上传缺少或不一致的资产
assets=$(list_assets)
for f in "${ASSETS[@]}"; do
  a=$(jq -c --arg n "$f" 'select(.name == $n)' <<<"$assets")
  if [[ -n "$a" ]]; then
    rc=0
    remote_ok "$a" "$DIST/$f" || rc=$?
    if (( rc == 0 )); then
      echo "$f 已上传且一致"
      continue
    fi
    (( rc == 1 )) || die "暂时无法核实已上传的 $f（下载失败），保留现有资产，请稍后重跑"
  fi
  if [[ -n "$a" ]]; then
    echo "$f 与本地不一致或没有传完，重传"
    api -X DELETE "repos/$R/releases/assets/$(jq -r .id <<<"$a")" || die "删除旧资产失败：$OUT"
  fi
  api -X POST "https://uploads.github.com/repos/$R/releases/$ID/assets?name=$f" \
    -H "Content-Type: application/zip" --input "$DIST/$f" || die "上传 $f 失败：$OUT"
done

# 5. 全部核对：只有这两个资产，且都与本地一致
verify_assets() {
  local assets names
  assets=$(list_assets)
  names=$(jq -r .name <<<"$assets" | sort | tr '\n' ' ')
  [[ "$names" == "$(printf '%s\n' "${ASSETS[@]}" | sort | tr '\n' ' ')" ]] || die "草稿资产不符：$names"
  for f in "${ASSETS[@]}"; do
    remote_ok "$(jq -c --arg n "$f" 'select(.name == $n)' <<<"$assets")" "$DIST/$f" || die "$f 远端大小或摘要与本地不一致"
  done
}
verify_assets

# 6. 标签绑定到本次提交（不存在时创建；并发创建时读回核对）
existing=$(tag_commit)
if [[ -z "$existing" ]]; then
  if ! api -X POST "repos/$R/git/refs" -f "ref=refs/tags/$TAG" -f "sha=$SHA"; then
    [[ "$HTTP" == 422 ]] || die "创建标签失败：$OUT"
  fi
  existing=$(tag_commit)
fi
[[ "$existing" == "$SHA" ]] || die "标签 $TAG 指向 ${existing:-（不存在）}，不是 $SHA"

# 7. 公开前最后确认草稿本身没被改过
api "repos/$R/releases/$ID" || die "读取草稿失败：$OUT"
[[ "$(jq -r .tag_name <<<"$OUT")" == "$TAG" && "$(jq -r .draft <<<"$OUT")" == true ]] || die "草稿 $ID 已被修改：$OUT"
api -X PATCH "repos/$R/releases/$ID" -F draft=false || die "公开失败：$OUT"

# 8. 公开后再核对一次（审计用）
[[ "$(tag_commit)" == "$SHA" ]] || die "公开后标签 $TAG 不再指向 $SHA"
verify_assets
echo "已公开 $TAG（$SHA）"
