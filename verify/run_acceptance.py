"""verify 容器验收入口：

  1. 构建检查（compileall）；
  2. 解码规则测试（tests.test_pack，含真实 git pack 交叉验证）；
  3. HTTP 冒烟：/health、有效嵌套 OFS_DELTA 成功证据、损坏尾部摘要、
     差分复制越界、非法类型、偏移未落在对象起点；
  4. 任一步失败即以非零退出码报告验收结果。

环境变量：
  TARGET_URL  被测服务地址，默认 http://verifier:8080（compose 网络）
"""

from __future__ import annotations

import base64
import compileall
import io
import json
import os
import sys
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tests import packbuilder as B  # noqa: E402
from app import pack as P  # noqa: E402

TARGET_URL = os.environ.get("TARGET_URL", "http://verifier:8080").rstrip("/")

PASS = "\033[32m通过\033[0m"
FAIL = "\033[31m失败\033[0m"

failures: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    print(f"  [{PASS if ok else FAIL}] {name}" + (f" — {detail}" if detail else ""))
    if not ok:
        failures.append(name)
    return ok


# --------------------------------------------------------------------------
# 1. 构建检查
# --------------------------------------------------------------------------

def step_build() -> bool:
    print("\n=== 1. 构建检查（字节码编译）===")
    ok = compileall.compile_dir(str(ROOT / "app"), quiet=1, maxlevels=10)
    ok = compileall.compile_dir(str(ROOT / "tests"), quiet=1, maxlevels=10) and ok
    ok = compileall.compile_file(str(Path(__file__)), quiet=1) and ok
    check("compileall app/ tests/ verify/", ok)
    return ok


# --------------------------------------------------------------------------
# 2. 解码规则测试
# --------------------------------------------------------------------------

def step_unit_tests() -> bool:
    print("\n=== 2. 解码规则测试 ===")
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromName("tests.test_pack")
    stream = io.StringIO()
    runner = unittest.TextTestRunner(stream=stream, verbosity=2)
    result = runner.run(suite)
    print(stream.getvalue())
    ok = result.wasSuccessful()
    check(f"解码规则测试（{result.testsRun} 项）", ok,
          "全部通过" if ok else
          f"{len(result.failures)} 失败 / {len(result.errors)} 错误")
    return ok


# --------------------------------------------------------------------------
# 3. HTTP 冒烟
# --------------------------------------------------------------------------

def http_post(path: str, payload: dict, timeout: int = 10):
    req = urllib.request.Request(
        TARGET_URL + path,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


def http_get(path: str, timeout: int = 10):
    with urllib.request.urlopen(TARGET_URL + path, timeout=timeout) as resp:
        return resp.status, resp.read()


def wait_for_service(timeout: float = 30.0) -> bool:
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        try:
            status, body = http_get("/health", timeout=3)
            data = json.loads(body)
            if status == 200 and data.get("status") == "ok":
                return True
        except Exception as exc:  # noqa: BLE001
            last = str(exc)
        time.sleep(0.5)
    print(f"  等待 {TARGET_URL}/health 超时：{last}")
    return False


def _nested_pack():
    """与单测一致的三层包：blob -> delta1 -> delta2。"""
    base = b"BASE-PAYLOAD:" + b"0123456789" * 8
    mid = base[:20] + b"-MID-INSERT-" + base[40:]
    final = b"[FINAL]" + mid + b"<<END"
    ops1 = (B.op_copy(0, 20) + B.op_insert(b"-MID-INSERT-")
            + B.op_copy(40, len(base) - 40))
    ops2 = (B.op_insert(b"[FINAL]") + B.op_copy(0, len(mid))
            + B.op_insert(b"<<END"))
    d1 = B.make_delta(len(base), len(mid), ops1)
    d2 = B.make_delta(len(mid), len(final), ops2)
    pb = B.PackBuilder()
    i0 = pb.add(B.OBJ_BLOB, base)
    i1 = pb.add(B.OBJ_OFS_DELTA, d1, base_idx=i0)
    pb.add(B.OBJ_OFS_DELTA, d2, base_idx=i1)
    return pb.build(), base, mid, final


def _copy_oor_pack():
    base = b"abcdefghij" * 10
    bad_ops = B.op_copy(0, 10) + B.op_copy(95, 20)  # 95+20 > 100
    d = B.make_delta(100, 30, bad_ops)
    pb = B.PackBuilder()
    i0 = pb.add(B.OBJ_BLOB, base)
    i1 = pb.add(B.OBJ_OFS_DELTA, d, base_idx=i0)
    return pb.build(), i1


def step_http_smoke() -> bool:
    print("\n=== 3. HTTP 冒烟 ===")
    ok = wait_for_service()
    check(f"健康响应 GET {TARGET_URL}/health", ok)
    if not ok:
        return False

    # 3.1 有效嵌套差分
    raw, base, mid, final = _nested_pack()
    count, records = P._walk_pack(raw)
    target_off = records[-1].offset
    status, data = http_post("/api/verify", {
        "pack_base64": base64.b64encode(raw).decode(),
        "offset": target_off})
    good = (status == 200 and data.get("ok")
            and data.get("type") == "blob"
            and data.get("length") == len(final)
            and data.get("sha1") == P.canonical_blob_sha1(final)
            and [c["type"] for c in data["chain"]]
            == ["blob", "ofs_delta", "ofs_delta"])
    check("有效嵌套 OFS_DELTA：类型/长度/规范 SHA-1", good,
          f"sha1={data.get('sha1')}")
    if good:
        for layer in data["layers"]:
            sizes_ok = (layer["declared_source_size"]
                        == layer["actual_source_size"]
                        and layer["declared_target_size"]
                        == layer["actual_target_size"])
            check(f"第 {layer['layer']} 层声明长度==实际长度 且 "
                  f"复制/插入证据齐备",
                  sizes_ok and bool(layer["copies"]) and bool(layer["inserts"]),
                  f"copies={len(layer['copies'])} "
                  f"inserts={len(layer['inserts'])}")
        # 偏移链严格前向：每层 base_offset < delta_offset
        chain_ok = all(
            c.get("base_offset", c["offset"]) < c["offset"]
            for c in data["chain"][1:])
        check("基对象偏移链严格指向更早对象", chain_ok)

    # 3.2 损坏尾部摘要：翻转尾部首字节，期望 TRAILER_MISMATCH 且无成功证据
    bad = bytearray(raw)
    bad[-20] ^= 0xFF
    status, data = http_post("/api/verify", {
        "pack_base64": base64.b64encode(bytes(bad)).decode(),
        "offset": target_off})
    err = data.get("error", {})
    check("损坏尾部摘要被拒绝",
          status == 200 and not data.get("ok")
          and err.get("code") == "TRAILER_MISMATCH"
          and err.get("offset") == len(raw) - 20
          and "layers" not in data and "chain" not in data,
          f"offset={err.get('offset')}")

    # 3.3 差分复制越界（包摘要正确，delta 内部 copy 越界）
    oor_raw, oor_idx = _copy_oor_pack()
    _, oor_records = P._walk_pack(oor_raw)
    status, data = http_post("/api/verify", {
        "pack_base64": base64.b64encode(oor_raw).decode(),
        "offset": oor_records[oor_idx].offset})
    err = data.get("error", {})
    check("差分复制越界被拒绝并给出失败字节偏移",
          not data.get("ok")
          and err.get("code") == "DELTA_COPY_OUT_OF_RANGE"
          and isinstance(err.get("offset"), int)
          and "layers" not in data,
          f"offset={err.get('offset')}")

    # 3.4 非法目标类型（commit）
    pb = B.PackBuilder()
    pb.add(B.OBJ_COMMIT, b"tree 0000000000000000000000000000000000000000\n"
                         b"author t <t@x> 1 +0000\n\nmsg\n")
    commit_pack = pb.build()
    status, data = http_post("/api/verify", {
        "pack_base64": base64.b64encode(commit_pack).decode(), "offset": 12})
    err = data.get("error", {})
    check("commit 类型目标被拒绝",
          not data.get("ok") and err.get("code") == "TYPE_NOT_ALLOWED"
          and err.get("offset") == 12)

    # 3.5 偏移未落在对象起点
    status, data = http_post("/api/verify", {
        "pack_base64": base64.b64encode(raw).decode(),
        "offset": target_off + 1})
    err = data.get("error", {})
    check("非对象起点偏移被拒绝",
          not data.get("ok")
          and err.get("code") == "OFFSET_NOT_OBJECT_START"
          and err.get("offset") == target_off + 1)

    # 3.6 页面可达且经真实 API 提交（页面含 fetch('/api/verify')）
    status, html = http_get("/")
    check("校验页面可访问并调用真实 API",
          status == 200 and b"/api/verify" in html)


def main() -> int:
    print("============================================================")
    print(" 星载增量包地面复原校验 —— verify 容器验收")
    print(f" 被测服务：{TARGET_URL}")
    print("============================================================")
    step_build()
    step_unit_tests()
    step_http_smoke()

    print("\n============================================================")
    if failures:
        print(f"验收结论：{FAIL} —— {len(failures)} 项未通过：")
        for f in failures:
            print(f"  - {f}")
        print("============================================================")
        return 1
    print(f"验收结论：{PASS} —— 全部检查项通过，退出码 0")
    print("============================================================")
    return 0


if __name__ == "__main__":
    sys.exit(main())
