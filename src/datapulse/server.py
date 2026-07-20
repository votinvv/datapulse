"""Сервер прокси: приём подключений, отказ в шифровании, форвард
CancelRequest, запуск релей-сессий, движок билдов.

Аутентификации у прокси нет — она сквозная до бэкенда (relay.py).
CancelRequest форвардится как есть: клиент видит настоящий
BackendKeyData бэкенда, ключ проверяет сам Postgres. Если ключ
принадлежит нашей сессии с активной перехваченной командой — прокси
ещё и отменяет её: убивает процесс-ребёнок python-блока либо
отцепляет attach (Postgres о перехваченной команде не знает,
отменить её сам не может). Билды живут в движке сервера и к
клиентским сессиям не привязаны."""

from __future__ import annotations

import asyncio
import logging

from . import __version__, pgwire as pg
from .config import LISTEN_HOST, Config
from .engine import BuildEngine
from .relay import RelaySession

log = logging.getLogger("datapulse.server")


class DataPulseServer:
    def __init__(self, config: Config) -> None:
        self.config = config
        self._server: asyncio.Server | None = None
        # BackendKeyData (pid+secret) → сессия; ведут relay-сессии
        self._sessions: dict[bytes, RelaySession] = {}
        self.engine = BuildEngine(config)

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._client, LISTEN_HOST, self.config.dp_port
        )
        log.info(
            "DataPulse %s слушает %s:%s, бэкенд %s:%s",
            __version__,
            LISTEN_HOST,
            self.config.dp_port,
            self.config.pg_host,
            self.config.pg_port,
        )

    async def serve(self) -> None:
        await self.start()
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    async def _client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        try:
            await self._handle(reader, writer)
        except pg.ProtocolViolation as exc:
            log.warning("нарушение протокола от %s: %s", peer, exc)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        except Exception:
            log.exception("необработанная ошибка соединения %s", peer)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        msg = await pg.read_startup(reader)
        while isinstance(msg, str):  # ssl | gssenc — шифрование не поддержано
            writer.write(b"N")
            await writer.drain()
            msg = await pg.read_startup(reader)

        if isinstance(msg, pg.CancelCall):
            self._cancel_intercepted(msg)
            await self._forward_cancel(msg)
            return

        session = RelaySession(
            self.config, reader, writer, msg, self._sessions, self.engine
        )
        log.info(
            "сессия: БД %r, пользователь %r, клиент %r",
            session.database,
            session.user,
            msg.params.get("application_name", ""),
        )
        try:
            await session.run()
        finally:
            log.info("сессия закрыта: БД %r, пользователь %r",
                     session.database, session.user)

    def _cancel_intercepted(self, cancel: pg.CancelCall) -> None:
        """Ключ CancelRequest наш и перехваченная команда активна —
        отменить её (kill ребёнка python-блока, отцепление attach)."""
        session = self._sessions.get(cancel.raw[8:16])
        if session is not None and session.cancel_active():
            log.info(
                "перехваченная команда отменена: БД %r, пользователь %r",
                session.database, session.user,
            )

    async def _forward_cancel(self, cancel: pg.CancelCall) -> None:
        try:
            reader, writer = await asyncio.open_connection(
                self.config.pg_host, self.config.pg_port
            )
        except OSError:
            return  # отмена — best effort, как и в самом Postgres
        try:
            writer.write(cancel.raw)
            await writer.drain()
            await reader.read()  # бэкенд молча закрывает соединение
        except (ConnectionError, OSError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
