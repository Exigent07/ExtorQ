# syntax=docker/dockerfile:1
# lab-portal container image for the extorq-lab cluster (owner: B2).
# The application source is owned by B1 (lab/apps/lab-portal, stdlib only).
#
# Build context is ONLY lab/apps/lab-portal (never the repository root, which
# holds var/ and .env):
#   docker build -f infra/kind/apps/lab-portal/Dockerfile -t extorq/lab-portal:<v> lab/apps/lab-portal
# infra/kind/kind.sh load-images does this and tags the image with a content hash.
ARG BASE_IMAGE=python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
FROM ${BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Dedicated unprivileged user; no home directory, no login shell.
RUN groupadd --system --gid 10001 labportal \
 && useradd --system --uid 10001 --gid 10001 --no-create-home \
      --home-dir /nonexistent --shell /usr/sbin/nologin labportal

WORKDIR /app
# Root-owned and read-only for the runtime user.
COPY --chown=root:root --chmod=0444 app.py /app/app.py

USER 10001:10001
EXPOSE 8080
# -I: isolated mode (ignore PYTHON* env vars, user site-packages and the CWD on sys.path).
ENTRYPOINT ["python3", "-I", "/app/app.py"]
