# syntax=docker/dockerfile:1.7
# ExtorQ backend image: ingest gateway, writer, migrations, detector, ai-worker, api.
# Build context: repository root (see .dockerignore: var/, .env, .venv, node_modules, .git
# are never sent to the daemon). Base images are pinned by digest.

FROM ghcr.io/astral-sh/uv:0.12.13@sha256:b485bd65cc2cf1c9a93b3554012c9c3778cf7b1b5fd3d3096ce9e1226c97e1e6 AS uv

FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PYTHON=/usr/local/bin/python3.12 \
    UV_PROJECT_ENVIRONMENT=/opt/venv
WORKDIR /src
# Workspace metadata first (cache layer for dependencies).
COPY pyproject.toml uv.lock ./
COPY backend/pyproject.toml backend/pyproject.toml
COPY collectors/pyproject.toml collectors/pyproject.toml
COPY scanners/pyproject.toml scanners/pyproject.toml
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --package extorq --no-install-workspace
# Backend sources, installed non-editable so the runtime image needs no /src.
COPY backend/src backend/src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --package extorq --no-editable

FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
LABEL org.opencontainers.image.title="extorq-backend" \
      org.opencontainers.image.description="ExtorQ backend services" \
      org.opencontainers.image.source="https://github.com/extorq/extorq"
RUN groupadd --system --gid 10001 extorq \
    && useradd --system --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent \
       --shell /usr/sbin/nologin extorq \
    && mkdir -p /var/lib/extorq/spool /app \
    && chown 10001:10001 /var/lib/extorq/spool \
    && chmod 0700 /var/lib/extorq/spool \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/venv /opt/venv
COPY infra/clickhouse/migrations /app/infra/clickhouse/migrations
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    EXTORQ_HOME=/app \
    EXTORQ_MIGRATIONS_DIR=/app/infra/clickhouse/migrations
WORKDIR /app
USER 10001:10001
ENTRYPOINT ["extorq"]
CMD ["--help"]
