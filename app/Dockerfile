FROM python:3.11-slim

WORKDIR /srv/app

# 服务仅依赖 Python 标准库，无需安装第三方包
COPY app/ /srv/app/

# 以非 root 运行
RUN useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /srv/app
USER appuser

ENV HOST=0.0.0.0 PORT=8080
EXPOSE 8080

HEALTHCHECK --interval=5s --timeout=3s --retries=10 --start-period=2s \
    CMD python -c "import json,urllib.request,sys; r=urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=3); sys.exit(0 if json.load(r).get('status')=='ok' else 1)"

CMD ["python", "server.py"]
