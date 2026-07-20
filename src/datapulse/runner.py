"""Раннер инженерного кода — процесс-ребёнок сервера (python $$…$$ и
load-фаза билда).

Читает из stdin JSON: {"body": <python>, "connections": {имя:
{"class_code": ..., "params": {...открытые...}}}, "params": {...}}.
Исполняет тело exec-ом; в globals инъецируются фабрики коннектов —
функции, возвращающие контекст-менеджер поверх аутентифицированного
подключения (`with rbs() as v_rbs:`) — и, у билда, параметры запуска
(mode_code, from_build_id, to_build_id, previous_time, parallel_cnt).
warehouse — такой же postgres-коннект (в python-блоке — на БД
установки под системной учёткой, в билде — под временной учёткой
билда). Соединение коммитится при чистом выходе из with,
откатывается при исключении, закрывается всегда (семантика донора).
Неймспейс голый: платформенных функций нет.

Печать уходит в stdout построчно (line buffering) — сервер стримит её
клиенту NoticeResponse-ами (python) либо пишет в журнал билда.
Секреты в инженерный код не попадают: параметры живут в замыкании
фабрики.
"""

from __future__ import annotations

import datetime
import json
import sys
import textwrap
from contextlib import contextmanager


def _postgres_factory(params: dict):
    @contextmanager
    def factory():
        import psycopg  # ленивый импорт: драйвер нужен только при открытии

        conn = psycopg.connect(
            host=params["host_name"],
            port=int(params["port_num"]),
            dbname=params["database_name"],
            user=params["user_name"],
            password=params["password"],
        )
        try:
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    return factory


def _oracle_factory(params: dict):
    @contextmanager
    def factory():
        import oracledb  # ленивый импорт

        conn = oracledb.connect(
            host=params["host_name"],
            port=int(params["port_num"]),
            service_name=params["service_name"],
            user=params["user_name"],
            password=params["password"],
        )
        try:
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    return factory


_FACTORIES = {
    "postgres_connection": _postgres_factory,
    "oracle_connection": _oracle_factory,
}


def main() -> int:
    payload = json.load(sys.stdin)
    sys.stdout.reconfigure(line_buffering=True, encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(line_buffering=True, encoding="utf-8", errors="replace")
    namespace: dict = {"__name__": "__datapulse_python__"}
    for name, cfg in payload["connections"].items():
        namespace[name] = _FACTORIES[cfg["class_code"]](cfg["params"])
    params = payload.get("params") or {}
    if "previous_time" in params:   # timestamptz едет через JSON строкой ISO
        raw = params["previous_time"]
        params["previous_time"] = (
            datetime.datetime.fromisoformat(raw) if raw is not None else None
        )
    namespace.update(params)
    # dedent: однострочные тела (`python $$ print(...) $$`) несут ведущий
    # пробел — для Python это unexpected indent
    body = textwrap.dedent(payload["body"])
    del payload  # секреты — только в замыканиях фабрик
    exec(compile(body, "<python>", "exec"), namespace)
    return 0


if __name__ == "__main__":
    sys.exit(main())
