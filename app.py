"""packv 校验服务（仅依赖 Python 标准库）。

路由：
  GET  /            单页前端
  GET  /healthz     健康响应
  POST /api/verify  请求 {"pack_base64": "...", "offset": 12}

POST 请求体限制 512 KiB（Base64 膨胀后仍在 256 KiB pack 上限内）。
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from packv import MAX_PACK_BYTES, VerificationError, verify_pack_object  # noqa: E402

STATIC_DIR = Path(__file__).resolve().parent / "static"
MAX_REQUEST_BODY = 512 * 1024

LOG = logging.getLogger("packv")


class Handler(BaseHTTPRequestHandler):
    server_version = "packv/1.0"

    def log_message(self, fmt, *args):  # 统一走 logging
        LOG.info("%s - %s", self.address_string(), fmt % args)

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            self._send_json(200, {"status": "ok"})
            return
        if path in ("/", "/index.html"):
            self._serve_file(STATIC_DIR / "index.html", "text/html; charset=utf-8")
            return
        if path == "/app.js":
            self._serve_file(STATIC_DIR / "app.js", "application/javascript; charset=utf-8")
            return
        if path == "/styles.css":
            self._serve_file(STATIC_DIR / "styles.css", "text/css; charset=utf-8")
            return
        self._send_json(404, {"ok": False, "error": "not found", "offset": None})

    def _serve_file(self, path: Path, content_type: str) -> None:
        try:
            body = path.read_bytes()
        except OSError:
            self._send_json(404, {"ok": False, "error": "静态资源缺失", "offset": None})
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        if path != "/api/verify":
            self._send_json(404, {"ok": False, "error": "not found", "offset": None})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_json(400, {"ok": False, "error": "Content-Length 非法", "offset": None})
            return
        if length <= 0:
            self._send_json(400, {"ok": False, "error": "请求体为空", "offset": None})
            return
        if length > MAX_REQUEST_BODY:
            self._send_json(413, {"ok": False, "error": "请求体超过 512 KiB 上限", "offset": None})
            return
        raw = self.rfile.read(length)
        try:
            req = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(400, {"ok": False, "error": "请求不是合法 JSON", "offset": None})
            return
        if not isinstance(req, dict):
            self._send_json(400, {"ok": False, "error": "请求体必须为 JSON 对象", "offset": None})
            return

        b64 = req.get("pack_base64")
        if not isinstance(b64, str) or not b64:
            self._send_json(400, {"ok": False, "error": "缺少 pack_base64 字段", "offset": None})
            return
        # 容忍粘贴时混入的空白。
        try:
            pack = base64.b64decode("".join(b64.split()), validate=True)
        except (binascii.Error, ValueError):
            self._send_json(400, {"ok": False, "error": "Base64 解码失败", "offset": None})
            return
        if len(pack) > MAX_PACK_BYTES:
            self._send_json(
                413,
                {"ok": False,
                 "error": f"解码后 pack 为 {len(pack)} 字节，超过 256 KiB 上限",
                 "offset": None},
            )
            return

        offset = req.get("offset")
        if isinstance(offset, bool) or not isinstance(offset, int):
            self._send_json(400, {"ok": False, "error": "offset 必须为整数", "offset": None})
            return

        try:
            result = verify_pack_object(pack, offset)
        except VerificationError as exc:
            self._send_json(
                200,
                {"ok": False,
                 "error": exc.message,
                 "offset": exc.offset,
                 "detail_offset": exc.detail_offset},
            )
            return
        self._send_json(200, result)


def main() -> int:
    host = os.environ.get("PACKV_HOST", "0.0.0.0")
    port = int(os.environ.get("PACKV_PORT", "8080"))
    logging.basicConfig(
        level=os.environ.get("PACKV_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    server = ThreadingHTTPServer((host, port), Handler)
    LOG.info("packv 监听 http://%s:%d", host, port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
