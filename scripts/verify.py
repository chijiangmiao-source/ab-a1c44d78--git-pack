"""验收入口：构建检查 -> 解码规则测试 -> HTTP 冒烟。

两种运行模式：
  本地模式（未设置 BASE_URL）：自行在 PACKV_PORT 上启动 app.py 再冒烟；
  外部模式（设置 BASE_URL，如容器内 http://web:8080）：等待该服务健康
  后直接冒烟，服务由 Compose 编排提供。

任意一步失败即以非零退出码结束。
"""

from __future__ import annotations

import compileall
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def step(title: str) -> None:
    print("\n" + "=" * 64)
    print(title)
    print("=" * 64, flush=True)


def wait_for_health(url: str, timeout: float = 30.0) -> bool:
    if url.endswith("/"):
        url = url[:-1]
    health = url if url.endswith("/healthz") else url + "/healthz"
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(health, timeout=2) as resp:
                if resp.status == 200:
                    return True
        except Exception:  # noqa: BLE001
            time.sleep(0.3)
    return False


def main() -> int:
    port = int(os.environ.get("PACKV_PORT", "8080"))
    external_url = os.environ.get("BASE_URL")

    step("[1/3] 构建检查：字节码编译全部 Python 源")
    ok = compileall.compile_dir(str(ROOT), quiet=1, maxlevels=10, force=True)
    if not ok:
        print("构建检查失败：存在语法错误的源文件")
        return 1
    print("构建检查通过")

    step("[2/3] 解码规则单元测试")
    rc = subprocess.call(
        [sys.executable, "-m", "unittest", "tests.test_pack", "-v"],
        cwd=ROOT,
    )
    if rc != 0:
        print(f"单元测试失败（退出码 {rc}）")
        return 2

    server = None
    if external_url:
        base_url = external_url.rstrip("/")
        step(f"[3/3] 等待 Compose 服务就绪并执行 HTTP 冒烟（{base_url}）")
        if not wait_for_health(base_url):
            print(f"{base_url}/healthz 未在超时内返回 200")
            return 3
    else:
        step("[3/3] 启动真实 HTTP 服务并执行 HTTP 冒烟")
        env = dict(os.environ, PACKV_HOST="127.0.0.1", PACKV_PORT=str(port))
        server = subprocess.Popen(
            [sys.executable, str(ROOT / "app.py")],
            cwd=ROOT, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        base_url = f"http://127.0.0.1:{port}"
        if not wait_for_health(base_url):
            print("本地服务未在超时内就绪")
            server.terminate()
            if server.stdout:
                print(server.stdout.read())
            return 3
        print(f"服务已在 {base_url} 就绪")

    try:
        smoke_env = dict(os.environ, BASE_URL=base_url)
        rc = subprocess.call(
            [sys.executable, str(ROOT / "scripts" / "smoke_http.py")],
            cwd=ROOT, env=smoke_env,
        )
        if rc != 0:
            print(f"HTTP 冒烟失败（退出码 {rc}）")
            return 4
        print("\n全部验收步骤通过 ✔")
        return 0
    finally:
        if server is not None:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()


if __name__ == "__main__":
    raise SystemExit(main())
