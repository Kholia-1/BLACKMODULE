FROM python:3.11-slim@sha256:9534e5a8e315485d4061ed659af0fd78a284c015f9b73661b41d6bab25604534

WORKDIR /code

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc \
        libpq-dev \
        curl \
    && groupadd --gid 10001 blackmodule \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin blackmodule \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /code/requirements.txt

RUN pip install --upgrade pip \
    && pip install --no-cache-dir -r /code/requirements.txt

COPY --chown=10001:10001 blackmodule/app /code/app
COPY --chown=10001:10001 blackmodule/data /code/data
COPY --chown=10001:10001 alembic.ini /code/alembic.ini
COPY --chown=10001:10001 blackmodule/alembic /code/blackmodule/alembic

EXPOSE 10000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl --fail http://127.0.0.1:10000/health/live || exit 1

USER 10001:10001

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "10000"]
