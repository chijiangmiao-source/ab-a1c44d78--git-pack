# packv 服务镜像：仅依赖 Python 标准库。
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PACKV_HOST=0.0.0.0 \
    PACKV_PORT=8080

WORKDIR /app

COPY app.py ./
COPY packv/ ./packv/
COPY static/ ./static/

EXPOSE 8080

# 内置健康检查与 Compose healthcheck 对应。
HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=5 \
  CMD python -c "import json,urllib.request,sys; r=urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=2); sys.exit(0 if r.status==200 and json.loads(r.read())['status']=='ok' else 1)"

CMD ["python", "app.py"]
