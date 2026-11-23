#!/usr/bin/env python3
"""测试用的假 gh：只实现 publish.sh 用到的 `gh api` 调用，状态存在 $FAKE_GH_STATE（JSON）里。

状态里的开关：
  fail: {"<方法> <路径前缀>": 状态码}   让匹配的请求失败
  corrupt_uploads: true                  上传后远端摘要与内容不符
  ref_race: "<sha>"                      创建标签时假装别人刚建好、指向这个提交
资产可以带 content（文本）：下载资产时返回它；没有 content 的资产无法下载（404）。
"""
import hashlib
import json
import os
import sys

state_path = os.environ["FAKE_GH_STATE"]
with open(state_path) as f:
    st = json.load(f)
st.setdefault("releases", [])
st.setdefault("refs", {})
st.setdefault("next_id", 100)
st.setdefault("calls", [])


def save():
    with open(state_path, "w") as f:
        json.dump(st, f)


def fail(code, msg="error"):
    save()
    sys.stderr.write(f"gh: {msg} (HTTP {code})\n")
    sys.exit(1)


def out(obj):
    save()
    sys.stdout.write(json.dumps(obj))
    sys.exit(0)


args = sys.argv[1:]
if not args or args[0] != "api":
    fail(400, "only api supported")
args = args[1:]
method, fields, raw_fields, headers, input_file, path = "GET", {}, {}, [], None, None
i = 0
while i < len(args):
    a = args[i]
    if a == "-X":
        method = args[i + 1]; i += 2
    elif a == "-f":
        k, v = args[i + 1].split("=", 1); raw_fields[k] = v; i += 2
    elif a == "-F":
        k, v = args[i + 1].split("=", 1); fields[k] = {"true": True, "false": False}.get(v, v); i += 2
    elif a == "-H":
        headers.append(args[i + 1]); i += 2
    elif a == "--input":
        input_file = args[i + 1]; i += 2
    elif a == "--paginate":
        i += 1
    else:
        path = a; i += 1
if raw_fields or fields:
    if method == "GET":
        method = "POST"
body = {**raw_fields, **fields}
data = None
if input_file is not None:
    data = sys.stdin.buffer.read() if input_file == "-" else open(input_file, "rb").read()
if data is not None and path.startswith("repos/") and method in ("POST", "PATCH"):
    body = json.loads(data)

st["calls"].append(f"{method} {path}")
for key, code in st.get("fail", {}).items():
    m, p = key.split(" ", 1)
    if m == method and path.startswith(p):
        fail(code)

path = path.replace("https://uploads.github.com/", "")
parts = path.split("?")[0].split("/")
query = path.split("?")[1] if "?" in path else ""


def find_release(rid):
    for r in st["releases"]:
        if str(r["id"]) == str(rid):
            return r
    fail(404, "Not Found")


def new_id():
    st["next_id"] += 1
    return st["next_id"]


# repos/O/N/...
rest = parts[3:]
if rest == ["releases"] and method == "GET":
    out([{k: v for k, v in r.items() if k != "assets"} for r in st["releases"]])
if rest == ["releases"] and method == "POST":
    r = {"id": new_id(), "tag_name": body["tag_name"], "target_commitish": body["target_commitish"],
         "name": body["name"], "body": body.get("body", "") + "\n\n## What's Changed\n...", "draft": body["draft"],
         "assets": []}
    st["releases"].append(r)
    out(r)
if len(rest) == 2 and rest[0] == "releases" and method == "GET":
    out({k: v for k, v in find_release(rest[1]).items() if k != "assets"})
if len(rest) == 2 and rest[0] == "releases" and method == "PATCH":
    r = find_release(rest[1])
    r.update(body)
    out(r)
if len(rest) == 3 and rest[0] == "releases" and rest[2] == "assets" and method == "GET":
    out(find_release(rest[1])["assets"])
if len(rest) == 3 and rest[0] == "releases" and rest[2] == "assets" and method == "POST":
    r = find_release(rest[1])
    name = dict(q.split("=", 1) for q in query.split("&"))["name"]
    if any(a["name"] == name for a in r["assets"]):
        fail(422, "already_exists")
    digest = hashlib.sha256(data + (b"x" if st.get("corrupt_uploads") else b"")).hexdigest()
    a = {"id": new_id(), "name": name, "size": len(data), "state": "uploaded", "digest": "sha256:" + digest}
    r["assets"].append(a)
    out(a)
if len(rest) == 3 and rest[:2] == ["releases", "assets"] and method == "GET":
    for r in st["releases"]:
        for a in r["assets"]:
            if str(a["id"]) == rest[2] and "content" in a:
                save()
                sys.stdout.write(a["content"])
                sys.exit(0)
    fail(404, "Not Found")
if len(rest) == 3 and rest[:2] == ["releases", "assets"] and method == "DELETE":
    for r in st["releases"]:
        r["assets"] = [a for a in r["assets"] if str(a["id"]) != rest[2]]
    out({})
if len(rest) == 4 and rest[:3] == ["git", "ref", "tags"] and method == "GET":
    ref = st["refs"].get(rest[3])
    if ref is None:
        fail(404, "Not Found")
    out({"ref": "refs/tags/" + rest[3], "object": ref})
if len(rest) == 3 and rest[:2] == ["git", "tags"] and method == "GET":
    tag = st.get("tag_objects", {}).get(rest[2])
    if tag is None:
        fail(404, "Not Found")
    out({"object": tag})
if rest == ["git", "refs"] and method == "POST":
    name = body["ref"].removeprefix("refs/tags/")
    if st.get("ref_race"):
        st["refs"][name] = {"type": "commit", "sha": st["ref_race"]}
        fail(422, "Reference already exists")
    if name in st["refs"]:
        fail(422, "Reference already exists")
    st["refs"][name] = {"type": "commit", "sha": body["sha"]}
    out({"ref": body["ref"]})
fail(404, f"fake gh: unhandled {method} {path}")
