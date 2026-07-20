"""Конфигурация сервиса.

Источник — переменные среды (задаются при старте контейнера):

- PG_HOST, PG_PORT — адрес родительского кластера Postgres
  (PG_PORT необязателен, по умолчанию 5432);
- PG_USER, PG_PASSWORD — системная учётка движка: под ней исполняется
  DPL; пользовательский трафик идёт под учёткой самого пользователя
  (сквозной SCRAM-релей, прокси паролей пользователей не видит);
- DP_PORT — порт, на котором слушает прокси;
- DP_ENCRYPTION_KEY — ключ шифрования секретов (base64, 32 байта);
  не задан — генерируется случайный на время жизни процесса:
  секреты коннектов не переживут перезапуск (дев-режим).
"""

from __future__ import annotations

import base64
import logging
import os
from dataclasses import dataclass

log = logging.getLogger("datapulse.config")

LISTEN_HOST = "0.0.0.0"  # прокси живёт в контейнере — слушаем все интерфейсы

ENCRYPTION_KEY_ENV = "DP_ENCRYPTION_KEY"


class ConfigError(Exception):
    """Ошибка конфигурации сервиса."""


@dataclass(frozen=True)
class Config:
    pg_host: str
    pg_port: int
    pg_user: str
    pg_password: str
    dp_port: int
    encryption_key: bytes


def load_config(environ: dict[str, str] | None = None) -> Config:
    env = os.environ if environ is None else environ
    errors: list[str] = []

    def require(name: str) -> str:
        value = env.get(name, "").strip()
        if not value:
            errors.append(f"не задана обязательная переменная среды {name}")
        return value

    def port(name: str, raw: str) -> int:
        try:
            value = int(raw)
        except ValueError:
            errors.append(f"переменная {name} должна быть числом, получено {raw!r}")
            return 0
        if not 1 <= value <= 65535:
            errors.append(f"переменная {name} вне диапазона портов: {value}")
        return value

    pg_host = require("PG_HOST")
    pg_user = require("PG_USER")
    pg_password = require("PG_PASSWORD")
    pg_port = port("PG_PORT", env.get("PG_PORT", "").strip() or "5432")
    dp_port_raw = require("DP_PORT")
    dp_port = port("DP_PORT", dp_port_raw) if dp_port_raw else 0

    encryption_key = b""
    key_b64 = env.get(ENCRYPTION_KEY_ENV, "").strip()
    if key_b64:
        try:
            encryption_key = base64.b64decode(key_b64, validate=True)
        except Exception:
            errors.append(f"переменная {ENCRYPTION_KEY_ENV} — не base64")
        else:
            if len(encryption_key) != 32:
                errors.append(
                    f"ключ {ENCRYPTION_KEY_ENV} должен быть 32 байта,"
                    f" получено {len(encryption_key)}"
                )
    else:
        encryption_key = os.urandom(32)
        log.warning(
            "%s не задан: ключ шифрования сгенерирован случайно —"
            " секреты коннектов не переживут перезапуск сервиса",
            ENCRYPTION_KEY_ENV,
        )

    if errors:
        raise ConfigError("; ".join(errors))
    return Config(
        pg_host=pg_host,
        pg_port=pg_port,
        pg_user=pg_user,
        pg_password=pg_password,
        dp_port=dp_port,
        encryption_key=encryption_key,
    )
