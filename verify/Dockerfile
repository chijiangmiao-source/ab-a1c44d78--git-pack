FROM python:3.11-slim

# 解码规则测试用真实 git 生成 pack 做交叉验证，故需要 git
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /srv

COPY app/ /srv/app/
COPY tests/ /srv/tests/
COPY verify/ /srv/verify/

ENV TARGET_URL=http://verifier:8080 \
    PYTHONUNBUFFERED=1

# 等待 verifier 健康后由 compose 触发；脚本内部也会轮询 /health。
CMD ["python", "verify/run_acceptance.py"]
