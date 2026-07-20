"""CLI сервиса: datapulse serve."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys

from . import __version__
from .config import ConfigError, load_config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="datapulse",
        description="DataPulse — pgwire-прокси-расширение над Postgres",
    )
    parser.add_argument(
        "--version", action="version", version=f"DataPulse {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("serve", help="запуск прокси (конфигурация — env)")

    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if args.command == "serve":
        try:
            config = load_config()
        except ConfigError as exc:
            print(f"ошибка конфигурации: {exc}", file=sys.stderr)
            return 2
        from .server import DataPulseServer

        try:
            _run(DataPulseServer(config).serve())
        except KeyboardInterrupt:
            print("остановлен")
        return 0

    return 2


def _run(coro) -> None:
    """asyncio.run с поправкой на Windows: psycopg-async требует
    selector-цикл (Proactor не поддерживается)."""
    if sys.platform == "win32":
        asyncio.run(coro, loop_factory=asyncio.SelectorEventLoop)
    else:
        asyncio.run(coro)


if __name__ == "__main__":
    sys.exit(main())
