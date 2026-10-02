"""Pack 校验 HTTP 服务（仅使用 Python 标准库）。

路由：
  GET  /                 静态校验页面
  GET  /health           健康检查
  POST /api/verify       入参 JSON {"pack_base64": ..., "offset": ...}
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from pack import MAX_PACK_SIZE, PackError, verify_pack  # noqa: E402

STATIC_DIR = Path(__file__).resolve().parent / "static"
# 粘贴的 Base64 文本上限 256 KiB，外加 JSON 包装余量。
MAX_B64_TEXT = 256 * 1024
MAX_BODY = MAX_B64_TEXT + 4096

_BASE64_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")


def decode_pack_input(raw_text: str) -> bytes:
    """严格解码 Base64：拒绝空白以外的任何非法字符并报告首个失败位置。"""
    text = raw_text.strip()
    if not text:
        raise PackError("EMPTY_INPUT", "未提供 Base64 数据")
    filtered = []
    for i, ch in enumerate(text):
        if ch in " \t\r\n":
            continue
        if ch not in _BASE64_ALPHABET:
            raise PackError(
                "BAD_BASE64",
                f"Base64 第 {i} 个字符 {ch!r} 非法",
                i)
        filtered.append(ch)
    compact = "".join(filtered)
    if len(compact) > MAX_B64_TEXT:
        raise PackError(
            "INPUT_TOO_LARGE",
            f"Base64 输入 {len(compact)} 字符，超过 256 KiB 上限")
    try:
        decoded = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise PackError("BAD_BASE64", f"Base64 解码失败：{exc}") from exc
    if len(decoded) > MAX_PACK_SIZE:
        raise PackError(
            "PACK_TOO_LARGE",
            f"解码后 Pack 为 {len(decoded)} 字节，超过 {MAX_PACK_SIZE} 字节上限")
    return decoded


class Handler(BaseHTTPRequestHandler):
    server_version = "PackVerify/1.0"

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/", "/index.html"):
            self._serve_file(STATIC_DIR / "index.html",
                             "text/html; charset=utf-8")
        elif self.path == "/health":
            self._send_json(200, {"status": "ok",
                                  "service": "pack-verifier"})
        else:
            self._send_json(404, {"ok": False,
                                  "error": {"code": "NOT_FOUND",
                                            "message": "路径不存在"}})

    def _serve_file(self, path: Path, content_type: str) -> None:
        try:
            data = path.read_bytes()
        except OSError:
            self._send_json(404, {"ok": False,
                                  "error": {"code": "NOT_FOUND",
                                            "message": "页面缺失"}})
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/api/verify":
            self._send_json(404, {"ok": False,
                                  "error": {"code": "NOT_FOUND",
                                            "message": "路径不存在"}})
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            self._send_json(400, {"ok": False,
                                  "error": {"code": "EMPTY_BODY",
                                            "message": "请求体为空"}})
            return
        if length > MAX_BODY:
            self._send_json(413, {"ok": False,
                                  "error": {"code": "BODY_TOO_LARGE",
                                            "message": "请求体超过大小限制"}})
            return
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._send_json(400, {"ok": False,
                                  "error": {"code": "BAD_JSON",
                                            "message": f"JSON 解析失败：{exc}"}})
            return

        pack_text = payload.get("pack_base64", "")
        offset = payload.get("offset")
        if isinstance(offset, str):
            s = offset.strip()
            try:
                if s.lower().startswith("0x"):
                    offset = int(s, 16)
                else:
                    offset = int(s, 10)  # 明确十进制，拒绝 010 式八进制歧义
            except ValueError:
                offset = None
        if offset is None:
            self._send_json(400, {"ok": False,
                                  "error": {"code": "BAD_OFFSET",
                                            "message": "目标对象偏移缺失或不是整数"}})
            return

        try:
            pack_buf = decode_pack_input(pack_text if isinstance(pack_text, str)
                                         else "")
            result = verify_pack(pack_buf, offset)
        except PackError as exc:
            self._send_json(200, {"ok": False, "error": exc.to_dict()})
            return
        self._send_json(200, result.to_dict())

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(),
                                        fmt % args))


def main() -> None:
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8080"))
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"pack-verifier listening on {host}:{port}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
