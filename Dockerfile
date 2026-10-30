# syntax=docker/dockerfile:1
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY pyproject.toml README.md ./
COPY threattrove ./threattrove
COPY deploy ./deploy
COPY scripts ./scripts
RUN pip install --no-deps .

RUN useradd --system --home /app --shell /usr/sbin/nologin threattrove \
 && mkdir -p /data \
 && chown -R threattrove:threattrove /data /app

ENV TT_DB=/data/threattrove.db \
    TT_BIND=0.0.0.0:8080 \
    TT_HOST=0.0.0.0 \
    TT_PORT=8080 \
    TT_SITE_URL=https://threattrove.com \
    TT_SITE_NAME=ThreatTrove

USER threattrove
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/health || exit 1

CMD ["gunicorn", "--config", "deploy/gunicorn.conf.py", "threattrove.web:app"]
