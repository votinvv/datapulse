# Образ сервиса DataPulse: только прокси, Postgres в поставку не входит.
# Конфигурация — переменными среды (см. README): PG_HOST, PG_PORT,
# PG_USER, PG_PASSWORD, DP_PORT, DP_ENCRYPTION_KEY.
# Список зависимостей живёт здесь: docker — единственный заявленный
# способ запуска, пакет не публикуется.

FROM python:3.14-slim

LABEL org.opencontainers.image.title="DataPulse" \
      org.opencontainers.image.description="ELT-платформа: pgwire-прокси-расширение над Postgres" \
      org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /app

RUN pip install --no-cache-dir \
    "psycopg[binary]>=3.2" \
    "cryptography>=45" \
    "oracledb>=3"

COPY src ./src
ENV PYTHONPATH=/app/src

RUN useradd --system --no-create-home datapulse
USER datapulse

ENTRYPOINT ["python", "-m", "datapulse", "serve"]
