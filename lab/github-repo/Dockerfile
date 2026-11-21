# Lab inventory service image (disposable ExtorQ lab target; never deployed).
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /srv/app

RUN groupadd --system app && useradd --system --gid app --home-dir /srv/app --shell /usr/sbin/nologin app

COPY requirements.txt .
RUN python -m pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/

USER app
EXPOSE 8080

CMD ["python", "-m", "flask", "--app", "app.main", "run", "--host", "0.0.0.0", "--port", "8080"]
