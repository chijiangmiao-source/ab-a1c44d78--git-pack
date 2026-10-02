"""针对运行中服务的 HTTP 冒烟测试。

环境变量：
  BASE_URL   服务地址，默认 http://127.0.0.1:8080
覆盖：健康检查、合法两层嵌套 OFS_DELTA 复原、损坏尾部 SHA-1、
复制越界、偏移不落对象起点、非法 Base64。
失败时以非零退出码结束。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.fixtures import (  # noqa: E402
    build_copy_oob_pack,
    build_nested_pack,
    flip_trailer_byte,
)

BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:8080")
failures: list[str] = []


def request(method: str, path: str, payload: dict | None = None):
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(
        BASE_URL + path, data=data, headers=headers, method=method
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def check(name: str, cond: bool, detail: str = "") -> None:
    mark = "PASS" if cond else "FAIL"
    print(f"[{mark}] {name}" + (f" — {detail}" if detail and not cond else ""))
    if not cond:
        failures.append(name)


def main() -> int:
    print(f"冒烟目标: {BASE_URL}")

    # 1. 健康响应
    status, body = request("GET", "/healthz")
    check("GET /healthz 返回 200 且 status=ok",
          status == 200 and body.get("status") == "ok",
          f"got {status} {body}")

    # 2. 合法两层嵌套 OFS_DELTA
    fx = build_nested_pack()
    b64 = base64.b64encode(fx["pack"]).decode()
    status, body = request("POST", "/api/verify",
                           {"pack_base64": b64, "offset": fx["delta2_off"]})
    want_sha = hashlib.sha1(
        f"blob {len(fx['v2'])}\0".encode() + fx["v2"]).hexdigest()
    check("嵌套 OFS_DELTA: HTTP 200", status == 200, str(body)[:300])
    check("嵌套 OFS_DELTA: ok=true", body.get("ok") is True, str(body)[:300])
    check(
        "嵌套 OFS_DELTA: 基链偏移为 根->l1->l2",
        body.get("base_chain_offsets")
        == [fx["blob_off"], fx["delta1_off"], fx["delta2_off"]],
        str(body.get("base_chain_offsets")),
    )
    check("嵌套 OFS_DELTA: 最终 SHA-1 正确",
          body.get("final_sha1") == want_sha, str(body.get("final_sha1")))
    check("嵌套 OFS_DELTA: 最终长度正确",
          body.get("final_length") == len(fx["v2"]),
          str(body.get("final_length")))
    layers = body.get("layers", [])
    check("嵌套 OFS_DELTA: 报告两层差分", len(layers) == 2, str(len(layers)))
    all_steps = [s for l in layers for s in l.get("steps", [])]
    kinds = {s.get("kind") for s in all_steps}
    check("嵌套 OFS_DELTA: 证据同时含 copy 与 insert",
          kinds == {"copy", "insert"}, str(kinds))
    check("嵌套 OFS_DELTA: 每层声明源/目标长度与实际一致",
          all(l["base_size_declared"] == l["base_size_actual"]
              and l["result_size_declared"] == l["result_size_actual"]
              for l in layers),
          str(layers))
    # 同一包对根 blob 的直接验证
    status, body = request("POST", "/api/verify",
                           {"pack_base64": b64, "offset": fx["blob_off"]})
    check("根 blob: ok=true 且无差分层",
          status == 200 and body.get("ok") is True
          and body.get("layers") == []
          and body.get("target", {}).get("type") == "blob",
          str(body)[:300])

    # 3. 损坏尾部摘要（在有效包上翻转尾部 SHA-1 首字节）
    bad = flip_trailer_byte(fx["pack"])
    body_end = len(fx["pack"]) - 20
    status, body = request("POST", "/api/verify",
                           {"pack_base64": base64.b64encode(bad).decode(),
                            "offset": fx["delta2_off"]})
    check("损坏尾部: HTTP 200 且 ok=false",
          status == 200 and body.get("ok") is False, str(body)[:300])
    check("损坏尾部: 提示 SHA-1 不符",
          "SHA-1" in (body.get("error") or ""), body.get("error", ""))
    check("损坏尾部: 首个失败偏移为正文末尾",
          body.get("offset") == body_end,
          f"{body.get('offset')} != {body_end}")

    # 4. 差分复制越界（包尾摘要正确，失败在应用阶段）
    oob_pack, oob_off = build_copy_oob_pack()
    status, body = request("POST", "/api/verify",
                           {"pack_base64": base64.b64encode(oob_pack).decode(),
                            "offset": oob_off})
    check("复制越界: ok=false 且提示复制越界",
          body.get("ok") is False and "复制越界" in (body.get("error") or ""),
          str(body)[:300])
    check("复制越界: 主偏移指向 delta 对象起点",
          body.get("offset") == oob_off, str(body.get("offset")))
    # 该差分 = varint(10)(1B) + varint(18)(1B) + 复制指令，故指令内偏移为 2。
    check("复制越界: detail_offset 指向解压差分内第 2 字节的复制指令",
          body.get("detail_offset") == 2, str(body.get("detail_offset")))

    # 5. 目标偏移不落对象起点
    status, body = request("POST", "/api/verify",
                           {"pack_base64": b64,
                            "offset": fx["delta2_off"] + 1})
    check("偏移不落起点: ok=false 且回传首个失败偏移",
          body.get("ok") is False
          and body.get("offset") == fx["delta2_off"] + 1,
          str(body)[:300])

    # 6. 非法 Base64
    status, body = request("POST", "/api/verify",
                           {"pack_base64": "@@@not-base64@@@", "offset": 0})
    check("非法 Base64: 400", status == 400, str(body)[:200])

    # 7. 首页可获取（真实页面而非 API 桩）
    try:
        with urllib.request.urlopen(BASE_URL + "/", timeout=10) as resp:
            html = resp.read().decode("utf-8", "replace")
        check("GET / 返回含表单的页面",
              resp.status == 200 and "pack_base64" in html, str(resp.status))
    except Exception as exc:  # noqa: BLE001
        check("GET / 返回含表单的页面", False, str(exc))

    print()
    if failures:
        print(f"冒烟失败 {len(failures)} 项: {failures}")
        return 1
    print("全部冒烟检查通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
