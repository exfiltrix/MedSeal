# MedSeal backend: API (MEDSEAL_PROCESS_ROLE=api, several uvicorn workers) and the background
# worker (python -m app.worker) run from this same image. See deploy/docker-compose.prod.yml.
FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app

# AI stack (shield, detective, crash test) is part of the product; INSTALL_AI=0 builds a slimmer
# image for seal/verify-only nodes (the shield block of /verify is then null).
ARG INSTALL_AI=1
COPY requirements.txt requirements-ai.txt ./
RUN pip install -r requirements.txt \
 && if [ "$INSTALL_AI" = "1" ]; then pip install -r requirements-ai.txt --extra-index-url https://download.pytorch.org/whl/cpu; fi

COPY alembic.ini ./
COPY migrations ./migrations
COPY app ./app
COPY scripts ./scripts

# Unprivileged user; everything it writes lives on volumes under /data.
RUN useradd --system --uid 10001 --home-dir /data/home medseal \
 && mkdir -p /data/keys /data/storage /data/anchors /data/watch /data/home /data/datasets \
 && chown -R medseal:medseal /data
USER medseal
ENV HOME=/data/home \
    MEDSEAL_KEYS_DIR=/data/keys \
    MEDSEAL_ROOT_KEY_PATH=/data/keys/root.pem \
    MEDSEAL_ROOT_PUBKEY_PATH=/data/keys/root.pub \
    MEDSEAL_STORAGE_DIR=/data/storage \
    MEDSEAL_ANCHOR_PATH=/data/anchors/anchors.jsonl \
    MEDSEAL_WATCH_DIR=/data/watch \
    MEDSEAL_DATA_DIR=/data/datasets

EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=5s --retries=5 \
  CMD python -c "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health/live', timeout=4).status == 200 else 1)"
# --proxy-headers trusts X-Forwarded-For (real client IP for rate limits and the audit log): the API
# is reachable only from the reverse proxy on the internal network (deploy/docker-compose.prod.yml).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4", "--proxy-headers", "--forwarded-allow-ips", "*"]
