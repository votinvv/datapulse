"""Релей pgwire: прозрачная перекачка клиент↔бэкенд с перехватом DPL.

Клиент аутентифицируется в самом бэкенде: прокси пересылает
auth-сообщения как есть, вырезая лишь механизмы *-PLUS из
AuthenticationSASL (channel binding через посредника не работает).
Дальше два насоса качают сообщения в обе стороны. Вмешательства:

- бэкенд→клиент: стрип *-PLUS; статус транзакции запоминается из
  ReadyForQuery (байт I/T/E);
- клиент→бэкенд: Query, являющийся ровно одним DPL-стейтментом,
  не пересылается — исполняется движком под системной учёткой, клиент
  получает наш ответ; Parse с DPL-текстом — честная ошибка (DPL пока
  только в simple-протоколе), сообщения глотаются до Sync;
- DPL внутри открытой транзакции — ошибка: команда исполняется на
  другом соединении и не может быть атомарна с транзакцией пользователя.

Печать перехваченного python-блока и журнал attach стримятся клиенту
NoticeResponse-ами. BackendKeyData бэкенда запоминается в реестре
сервера: CancelRequest с ключом нашей сессии отменяет активную
перехваченную команду — убивает процесс-ребёнок python-блока либо
отцепляет attach (релейная нога в этот момент idle — Postgres
отменять нечего, форвард безвреден).

Осознанные ограничения MVP: pipelining клиента вокруг перехваченного
сообщения не поддержан (swallow до Sync глотает посланное следом;
статус транзакции при конвейере может отставать) — psql, psycopg и
JDBC в обычном режиме так не делают.
"""

from __future__ import annotations

import asyncio
import logging

import psycopg

from . import commands, dpl, engine as engine_mod, pgwire as pg
from .config import Config
from .dpl import DplError, SqlState

log = logging.getLogger("datapulse.relay")


class RelaySession:
    def __init__(
        self,
        config: Config,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        startup: pg.Startup,
        registry: dict[bytes, "RelaySession"] | None = None,
        engine: engine_mod.BuildEngine | None = None,
    ) -> None:
        self.config = config
        self.client_reader = client_reader
        self.client_writer = client_writer
        self.startup = startup
        self.registry = registry       # ключ бэкенда → сессия (отмена команд)
        self.engine = engine           # движок билдов сервера
        self.user = startup.params.get("user", "")
        self.database = startup.params.get("database") or self.user
        self.tx_status = b"I"          # последний статус ReadyForQuery бэкенда
        self.skip_until_sync = False   # extended: ошибка DPL, глотаем до Sync
        self.backend_key: bytes | None = None    # payload BackendKeyData
        # ручка отмены активной перехваченной команды (python, attach)
        self.active_run: commands.PythonRun | engine_mod.AttachRun | None = None

    async def run(self) -> None:
        try:
            backend = await asyncio.open_connection(
                self.config.pg_host, self.config.pg_port
            )
        except OSError as exc:
            self.client_writer.write(
                pg.error_response(
                    f"бэкенд Postgres недоступен"
                    f" ({self.config.pg_host}:{self.config.pg_port}): {exc}",
                    SqlState.CONNECTION_FAILURE,
                )
            )
            await self.client_writer.drain()
            return
        self.backend_reader, self.backend_writer = backend
        try:
            self.backend_writer.write(self.startup.raw)
            await self.backend_writer.drain()
            pump_client = asyncio.ensure_future(self._pump_client())
            pump_backend = asyncio.ensure_future(self._pump_backend())
            done, pending = await asyncio.wait(
                (pump_client, pump_backend),
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            await asyncio.gather(*done, *pending, return_exceptions=True)
            for task in done:
                if (exc := task.exception()) is not None:
                    raise exc
        finally:
            if self.registry is not None and self.backend_key is not None:
                self.registry.pop(self.backend_key, None)
            self.backend_writer.close()
            try:
                await self.backend_writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    # --- насосы -----------------------------------------------------------

    async def _pump_backend(self) -> None:
        """бэкенд → клиент: стрип *-PLUS, отслеживание статуса транзакции."""
        while True:
            msg = await pg.read_message(self.backend_reader)
            if msg is None:
                return
            msg_type, payload = msg
            if msg_type == b"R":
                payload = pg.strip_sasl_plus(payload)
            elif msg_type == b"Z" and payload:
                self.tx_status = payload[:1]
            elif msg_type == b"K" and len(payload) == 8:
                self.backend_key = bytes(payload)
                if self.registry is not None:
                    self.registry[self.backend_key] = self
            self.client_writer.write(pg.message(msg_type, payload))
            await self.client_writer.drain()

    async def _pump_client(self) -> None:
        """клиент → бэкенд: перехват DPL, остальное как есть."""
        while True:
            msg = await pg.read_message(self.client_reader)
            if msg is None:
                return
            msg_type, payload = msg
            if self.skip_until_sync:
                if msg_type == b"S":
                    self.skip_until_sync = False
                    await self._reply(pg.ready_for_query(self.tx_status))
                elif msg_type == b"X":
                    return
                continue
            if msg_type == b"Q":
                query = pg.PayloadReader(payload).cstring()
                if await self._try_dpl(query):
                    continue
            elif msg_type == b"P":
                reader = pg.PayloadReader(payload)
                reader.cstring()               # имя prepared statement
                query = reader.cstring()
                if dpl.is_dpl_text(query):
                    await self._reply(
                        pg.error_response(
                            "DPL-команды пока поддерживаются только в"
                            " simple-протоколе",
                            SqlState.FEATURE_NOT_SUPPORTED,
                            hint="выполните команду через psql либо клиент"
                            " с simple query protocol",
                        )
                    )
                    self.skip_until_sync = True
                    continue
            self.backend_writer.write(pg.message(msg_type, payload))
            await self.backend_writer.drain()
            if msg_type == b"X":
                return

    # --- перехват DPL -----------------------------------------------------

    async def _try_dpl(self, query: str) -> bool:
        """True — запрос перехвачен и отвечен; False — пересылать бэкенду."""
        try:
            command = dpl.match_command(query)
        except DplError as exc:
            await self._finish(self._error_bytes(exc, query))
            return True
        if command is None:
            return False
        if self.tx_status != b"I":
            await self._finish(
                pg.error_response(
                    "DPL внутри открытой транзакции невозможен: команда"
                    " исполняется движком вне транзакции пользователя",
                    SqlState.ACTIVE_SQL_TRANSACTION,
                    hint="завершите транзакцию (commit/rollback); psycopg —"
                    " режим autocommit",
                )
            )
            return True
        run: commands.PythonRun | engine_mod.AttachRun | None = None
        if isinstance(command, dpl.PythonBlock):
            run = commands.PythonRun()
        elif isinstance(command, (dpl.AttachCall, dpl.FlowAttachCall)):
            run = engine_mod.AttachRun()
        self.active_run = run
        try:
            result = await commands.execute(
                self.config, self.database, self.user, command, query,
                notify=self._notify, run=run, engine=self.engine,
            )
        except DplError as exc:
            await self._finish(self._error_bytes(exc, query))
            return True
        except psycopg.Error as exc:
            # непредусмотренная ошибка Postgres — клиенту как есть
            diag = exc.diag
            await self._finish(
                pg.error_response(
                    diag.message_primary or str(exc),
                    diag.sqlstate or SqlState.INTERNAL_ERROR,
                    hint=diag.message_hint,
                )
            )
            return True
        except (ConnectionError, OSError):
            raise    # клиент оборвался — сессия закрывается штатно
        except Exception:
            log.exception("внутренняя ошибка на DPL-стейтменте")
            await self._finish(
                pg.error_response(
                    "внутренняя ошибка сервера — подробности в журнале"
                    " прокси",
                    SqlState.INTERNAL_ERROR,
                )
            )
            return True
        finally:
            self.active_run = None
        if isinstance(result, commands.TableResult):
            data = pg.row_description(result.columns)
            for row in result.rows:
                data += pg.data_row(row)
            data += pg.command_complete(result.tag)
            tag = result.tag
        else:
            data = pg.command_complete(result)
            tag = result
        log.info(
            "DPL: %s — БД %r, пользователь %r", tag, self.database, self.user
        )
        await self._finish(data)
        return True

    def _error_bytes(self, error: DplError, query: str) -> bytes:
        message = error.message
        position = None
        if error.pos is not None:
            line, col = dpl.line_col(query, error.pos)
            message = f"строка {line}, колонка {col}: {message}"
            position = error.pos + 1
        return pg.error_response(
            message, error.sqlstate, hint=error.hint, position=position
        )

    def cancel_active(self) -> bool:
        """CancelRequest клиента: отменить активную перехваченную команду
        (kill ребёнка python-блока, отцепление attach)."""
        run = self.active_run
        if run is None:
            return False
        run.cancel()
        return True

    async def _notify(self, line: str) -> None:
        """Строка печати перехваченной команды — клиенту NoticeResponse."""
        await self._reply(pg.notice_response(line))

    async def _reply(self, data: bytes) -> None:
        self.client_writer.write(data)
        await self.client_writer.drain()

    async def _finish(self, data: bytes) -> None:
        """Ответ перехваченной команды + ReadyForQuery со статусом бэкенда."""
        await self._reply(data + pg.ready_for_query(self.tx_status))
