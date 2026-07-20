"""Движок билдов: создание, супервизор, SCD2-перелив, stop/fix/attach.

Билд асинхронен: `build(...)` создаёт запись и первую строку журнала
одной транзакцией под каталожным замком и немедленно возвращает
build_id; исполнение — asyncio-задача прокси, жизнь билда не привязана
к соединению клиента. Одновременные билды одной спеки запрещены; более
того, незавершённый билд (включая неразобранный fail) блокирует
следующий запуск той же спеки — fail закрывается командой fix.

Фазы (по донору): load — truncate интерфейсной таблицы и исполнение
тела спеки в процессе-ребёнке; comp — чанковый перенос интерфейсной
таблицы в основную SCD2 (тип переноса — по режиму запуска); финал —
done | fail. Печать тела и статусы идут общим потоком в
datapulse.build_log; attach стримит журнал NoticeResponse-ами.

Тело спеки исполняется под ВРЕМЕННОЙ учёткой билда: роль
dp_build_<id> создаётся в транзакции создания билда (права — только
интерфейсная таблица и usage схемы; системной учётке для этого нужен
CREATEROLE), передаётся ребёнку как warehouse() и дропается по
завершении. Перелив comp работает под системной учёткой в процессе
прокси.

Живость билда — session-замок pg_advisory_lock по build_id на
соединении супервизора: замок жив, пока жив прокси. «Активный» по
журналу билд без замка — сирота упавшего сервера; stop переводит его
в fail (ленивый reconcile), fix закрывает.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
from dataclasses import dataclass

import psycopg

from . import commands
from .config import Config
from .connections import POSTGRES_CONNECTION
from .dpl import AttachCall, BuildCall, DplError, FixCall, SqlState, StopCall

log = logging.getLogger("datapulse.engine")

# финалы билда; неразобранный fail — открытое состояние: он морозит
# дельты потребителей и блокирует следующий билд своей спеки
FINAL_STATUSES = ("done", "fix")

# типы переноса, сравнивающие срез с текущими данными
_COMPARING_TYPES = ("init", "incr", "sect")

_CLAIM_KEY_SQL = "hashtextextended('datapulse:build:' || %s, 0)"

_LAST_STATUS_LATERAL = (
    " join lateral (select status_code from datapulse.build_log l"
    "                where l.build_id = b.build_id"
    "                order by l.build_log_id desc limit 1) ls on true"
)


class _BuildFailed(Exception):
    """Содержательный сбой билда — текст уходит в fail-строку журнала."""


class AttachRun:
    """Ручка attach: CancelRequest клиента отцепляет зрителя, билд живёт."""

    def __init__(self) -> None:
        self.cancelled = False
        self.event = asyncio.Event()

    def cancel(self) -> None:
        self.cancelled = True
        self.event.set()


class BuildRun:
    """Живой билд этого прокси: задача-супервизор и ручка ребёнка."""

    def __init__(self, database: str, build_id: int) -> None:
        self.database = database
        self.build_id = build_id
        self.child = commands.PythonRun()
        self.task: asyncio.Task | None = None
        self.stop_reason: str | None = None

    def stop(self, reason: str) -> None:
        self.stop_reason = reason
        if self.task is not None:
            self.task.cancel()


@dataclass(frozen=True)
class _Job:
    """Снимок всего, что нужно билду, — на момент создания (вотермарка)."""

    database: str
    build_id: int
    version_id: int          # вотермарка версии каталога
    dataset_code: str
    build_spec_num: int
    type_code: str
    body: str
    attrs: list[tuple]       # (attr_code, order_num, type_code, is_primary, descr)
    chunk_attr_code: str
    parallel_cnt: int
    connections: dict        # payload ребёнка: using-коннекты + warehouse
    params: dict             # параметры запуска в globals тела
    role_name: str


class _Plan:
    """Имена и колоночные списки спеки для f-string SQL перелива;
    идентификаторы провалидированы при create (лексика DPL)."""

    def __init__(self, job: _Job) -> None:
        self.pk = [a[0] for a in job.attrs if a[3]]
        self.non_pk = [a[0] for a in job.attrs if not a[3]]
        self.chunk = job.chunk_attr_code
        self.main = commands._spec_table(job.dataset_code, job.build_spec_num)
        self.iface = commands._iface_table(job.dataset_code, job.build_spec_num)
        self.schema, self.table = self.main.split(".", 1)
        self.parallel = max(1, job.parallel_cnt)

    @property
    def pk_csv(self) -> str:
        return ", ".join(self.pk)

    def insert_columns(self) -> str:
        return ", ".join(
            self.pk + ["build_id", "end_build_id", "is_active"] + self.non_pk
        )

    def chunk_of(self, alias: str, rn: int) -> str:
        """Предикат чанка: abs(hashtext(значение)) % n + 1 = rn; hashtext
        возвращает знаковый int4 — каст к bigint переживает INT_MIN."""
        n = self.parallel
        if n <= 1:
            return "true"
        return (
            f"(abs(hashtext({alias}.{self.chunk}::text)::bigint) % {n})::integer"
            f" + 1 = {rn}"
        )


# --- SQL чанков (SCD2-механика донора; end_build_id ИНКЛЮЗИВНЫЙ) -----------


def _sql_bulk_insert(job: _Job, plan: _Plan, rn: int) -> list[str]:
    """Быстрый путь: сравнивать не с чем (пустая основная) либо режим
    appd — активный срез вставляется как есть."""
    select = (
        ", ".join(f"t.{c}" for c in plan.pk)
        + f", {job.build_id}, null::bigint, t.is_active"
        + "".join(f", t.{c}" for c in plan.non_pk)
    )
    return [
        f"insert into {plan.main} ({plan.insert_columns()})\n"
        f"select {select}\n"
        f"  from {plan.iface} t\n"
        f" where {plan.chunk_of('t', rn)}\n"
        f"   and t.is_active"
    ]


def _sql_merge(job: _Job, plan: _Plan, rn: int) -> list[str]:
    """SCD2-мердж одного чанка: собрать изменившиеся строки (result),
    открыть им новые версии, закрыть вытесненные по ctid.

    end_build_id = build_id - 1 — инклюзивно: последний билд, в котором
    старая версия строки ещё актуальна.
    """
    t = job.type_code
    join = "left" if t == "incr" else "full"

    # sect перезаливает целые секции chunk-ключа: цель сужается до
    # секций, присутствующих в срезе, — full join удаляет внутри них,
    # не трогая остального
    rn_col = (
        f"\n         , row_number() over (partition by s.{plan.chunk}"
        f" order by s.is_active desc) as rn$"
        if t == "sect" else ""
    )
    sect_join = (
        f"\n  join source r\n"
        f"    on r.rn$ = 1\n"
        f"   and r.{plan.chunk} = t.{plan.chunk}"
        if t == "sect" else ""
    )

    coalesce_pk = "\n     , ".join(
        f"coalesce(s.{c}, t.{c}) as {c}" for c in plan.pk
    )
    case_non_pk = "".join(
        f"\n     , case when s.is_active then s.{c} else t.{c} end as {c}"
        for c in plan.non_pk
    )
    on_pk = "\n   and ".join(f"t.{c} = s.{c}" for c in plan.pk)
    changed = "".join(
        f"\n    or s.is_active and s.{c} is distinct from t.{c}"
        for c in plan.non_pk
    )
    t_pk = "\n         , ".join(f"t.{c}" for c in plan.pk)
    t_non_pk = "".join(f"\n         , t.{c}" for c in plan.non_pk)

    result = (
        f"create temporary table result on commit drop as\n"
        f"  with source as (\n"
        f"       select distinct on ({plan.pk_csv}) s.*{rn_col}\n"
        f"         from {plan.iface} s\n"
        f"        where {plan.chunk_of('s', rn)}\n"
        f"        order by {plan.pk_csv}, s.is_active desc\n"
        f"       )\n"
        f"     , target as (\n"
        f"       select t.ctid as ctid_\n"
        f"         , {t_pk}\n"
        f"         , t.is_active as is_active{t_non_pk}\n"
        f"         from {plan.main} t{sect_join}\n"
        f"        where t.end_build_id is null\n"
        f"          and {plan.chunk_of('t', rn)}\n"
        f"       )\n"
        f"select t.ctid_ as ctid_\n"
        f"     , case when s.is_active and not coalesce(t.is_active, false)"
        f" then 1 else 0 end as inserted_row_cnt\n"
        f"     , case when s.is_active and t.is_active"
        f" then 1 else 0 end as updated_row_cnt\n"
        f"     , case when not coalesce(s.is_active, false) and t.is_active"
        f" then 1 else 0 end as deleted_row_cnt\n"
        f"     , {coalesce_pk}\n"
        f"     , case when s.is_active then true else false end"
        f" as is_active{case_non_pk}\n"
        f"  from source s\n"
        f"  {join} join target t\n"
        f"    on {on_pk}\n"
        f" where coalesce(s.is_active, false) != coalesce(t.is_active, false)"
        f"{changed}"
    )

    insert = (
        f"insert into {plan.main} ({plan.insert_columns()})\n"
        f"select {plan.pk_csv}, {job.build_id}, null::bigint, is_active"
        + "".join(f", {c}" for c in plan.non_pk)
        + "\n  from result"
    )
    # закрытие — tid-джойн: hash join прочитал бы всю основную таблицу
    close = (
        f"update {plan.main} m\n"
        f"   set end_build_id = {job.build_id - 1}\n"
        f"  from result t\n"
        f" where m.ctid = t.ctid_"
    )
    return [
        result, "analyze result", insert,
        "set local enable_hashjoin = off", close, "reset enable_hashjoin",
    ]


_STATS_SQL = (
    "select coalesce(sum(inserted_row_cnt), 0),"
    " coalesce(sum(updated_row_cnt), 0),"
    " coalesce(sum(deleted_row_cnt), 0) from result"
)


class BuildEngine:
    """Движок билдов сервера: реестр живых билдов и их супервизоры."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.runs: dict[tuple[str, int], BuildRun] = {}

    # --- служебные соединения ----------------------------------------------

    async def _open(self, database: str, *, autocommit: bool) -> psycopg.AsyncConnection:
        try:
            return await psycopg.AsyncConnection.connect(
                host=self.config.pg_host,
                port=self.config.pg_port,
                dbname=database,
                user=self.config.pg_user,
                password=self.config.pg_password,
                autocommit=autocommit,
                connect_timeout=10,
            )
        except psycopg.OperationalError as exc:
            raise DplError(
                f"системное соединение с БД {database!r} не открылось: {exc}",
                sqlstate=SqlState.CONNECTION_FAILURE,
            ) from exc

    async def _journal(
        self,
        conn,
        version_id: int,
        build_id: int,
        status: str,
        *,
        message: str | None = None,
        prepared_row_cnt: int | None = None,
        inserted_row_cnt: int | None = None,
        updated_row_cnt: int | None = None,
        deleted_row_cnt: int | None = None,
    ) -> None:
        await conn.execute(
            "insert into datapulse.build_log"
            " (version_id, build_id, log_time, status_code, message,"
            "  prepared_row_cnt, inserted_row_cnt, updated_row_cnt,"
            "  deleted_row_cnt)"
            " values (%s, %s, now(), %s, %s, %s, %s, %s, %s)",
            (version_id, build_id, status, message, prepared_row_cnt,
             inserted_row_cnt, updated_row_cnt, deleted_row_cnt),
        )

    async def _last_status(self, cur, build_id: int) -> tuple[int, str] | None:
        """(version_id билда, последний статус журнала); None — билда нет."""
        await cur.execute(
            "select b.version_id, ls.status_code from datapulse.build b"
            + _LAST_STATUS_LATERAL
            + " where b.build_id = %s",
            (build_id,),
        )
        return await cur.fetchone()

    # --- создание билда -----------------------------------------------------

    async def start_build(
        self, database: str, user_code: str, command: BuildCall, src: str
    ) -> int:
        """Создаёт билд (валидации, вотермарка, границы дельты, временная
        учётка) одной транзакцией и запускает супервизор; возвращает
        build_id немедленно."""
        super_conn: psycopg.AsyncConnection | None = None
        try:
            async with await commands._connect(self.config, database) as conn:
                cur = conn.cursor()
                last_version, _, _ = await commands._lock_catalog(cur)
                job = await self._prepare(
                    cur, database, last_version, user_code, command
                )
                # claim до коммита: между видимостью билда и замком
                # супервизора не должно быть окна «сироты»
                super_conn = await self._open(database, autocommit=True)
                await super_conn.execute(
                    f"select pg_advisory_lock({_CLAIM_KEY_SQL})",
                    (str(job.build_id),),
                )
        except BaseException:
            if super_conn is not None:
                await super_conn.close()
            raise
        run = BuildRun(database, job.build_id)
        self.runs[(database, job.build_id)] = run
        run.task = asyncio.get_running_loop().create_task(
            self._run_build(run, job, super_conn),
            name=f"build:{database}:{job.build_id}",
        )
        log.info(
            "билд %s: %s.%s режим %r, БД %r, пользователь %r",
            job.build_id, job.dataset_code, job.build_spec_num,
            command.mode_code, database, user_code,
        )
        return job.build_id

    async def _prepare(
        self, cur, database: str, version_id: int, user_code: str,
        command: BuildCall,
    ) -> _Job:
        """Тело транзакции создания: валидации по каталогу, строка build +
        wait, временная учётка."""
        spec = await commands._current_spec(
            cur, command.dataset_code, command.build_spec_num
        )
        if spec is None or spec[1]:
            raise DplError(
                f"спека {command.dataset_code}.{command.build_spec_num}"
                " не существует",
                pos=command.code_pos,
                sqlstate=SqlState.UNDEFINED_OBJECT,
            )
        spec_version, _, _, parallel_cnt, chunk_attr, body = spec
        mode = await self._resolve_mode(cur, command, spec_version)
        await self._require_no_open_build(cur, command)
        await cur.execute(
            "select coalesce(max(build_id), 0) + 1 from datapulse.build"
        )
        build_id = (await cur.fetchone())[0]
        sources = await self._spec_sources(cur, command, spec_version)
        to_build_id = await self._watermark(cur, sources, build_id)
        from_build_id, previous_time = await self._previous_clear(cur, command)
        await cur.execute(
            "insert into datapulse.build"
            " (version_id, build_id, dataset_code, build_spec_num, mode_code,"
            "  is_clear, user_code, source_build_id)"
            " values (%s, %s, %s, %s, %s, %s, %s, %s)",
            (version_id, build_id, command.dataset_code,
             command.build_spec_num, mode[0], mode[2], user_code, to_build_id),
        )
        await self._journal(cur, version_id, build_id, "wait")
        role_name, password = await self._create_build_role(
            cur, command, build_id
        )
        attrs = await commands._dataset_attrs(
            cur, command.dataset_code, spec_version
        )
        connections = await self._child_connections(
            cur, database, command, spec_version, role_name, password
        )
        job = _Job(
            database=database,
            build_id=build_id,
            version_id=version_id,
            dataset_code=command.dataset_code,
            build_spec_num=command.build_spec_num,
            type_code=mode[1],
            body=body,
            attrs=attrs,
            chunk_attr_code=chunk_attr,
            parallel_cnt=parallel_cnt,
            connections=connections,
            params={
                "mode_code": mode[0],
                "from_build_id": from_build_id,
                "to_build_id": to_build_id,
                "previous_time": (
                    previous_time.isoformat() if previous_time else None
                ),
                "parallel_cnt": parallel_cnt,
            },
            role_name=role_name,
        )
        return job

    async def _resolve_mode(
        self, cur, command: BuildCall, spec_version: int
    ) -> tuple[str, str, bool]:
        """Режим запуска версии спеки: (mode_code, type_code, is_clear)."""
        await cur.execute(
            "select mode_code, type_code, is_clear"
            " from datapulse.build_spec_mode"
            " where dataset_code = %s and build_spec_num = %s"
            "  and version_id = %s order by mode_code",
            (command.dataset_code, command.build_spec_num, spec_version),
        )
        modes = await cur.fetchall()
        for mode in modes:
            if mode[0] == command.mode_code:
                return mode
        raise DplError(
            f"у спеки {command.dataset_code}.{command.build_spec_num}"
            f" нет режима {command.mode_code!r}",
            pos=command.mode_pos,
            hint="режимы спеки: " + ", ".join(m[0] for m in modes),
            sqlstate=SqlState.INVALID_PARAMETER_VALUE,
        )

    async def _require_no_open_build(self, cur, command: BuildCall) -> None:
        """Незавершённый билд спеки блокирует следующий: живой — stop,
        сирота — stop (переведёт в fail), fail — fix."""
        await cur.execute(
            "select b.build_id, ls.status_code from datapulse.build b"
            + _LAST_STATUS_LATERAL
            + " where b.dataset_code = %s and b.build_spec_num = %s"
            "   and ls.status_code != all(%s)"
            " order by b.build_id limit 1",
            (command.dataset_code, command.build_spec_num,
             list(FINAL_STATUSES)),
        )
        row = await cur.fetchone()
        if row is None:
            return
        open_id, status = row
        if status == "fail":
            raise DplError(
                f"билд {open_id} этой спеки упал и не разобран",
                pos=command.code_pos,
                hint=f"разобрано — fix({open_id})",
                sqlstate=SqlState.OBJECT_NOT_IN_PREREQUISITE_STATE,
            )
        await cur.execute(
            f"select pg_try_advisory_xact_lock({_CLAIM_KEY_SQL})",
            (str(open_id),),
        )
        orphan = (await cur.fetchone())[0]
        if orphan:
            raise DplError(
                f"билд {open_id} этой спеки осиротел"
                " (сервер останавливался во время исполнения)",
                pos=command.code_pos,
                hint=f"stop({open_id}) переведёт его в fail",
                sqlstate=SqlState.OBJECT_NOT_IN_PREREQUISITE_STATE,
            )
        raise DplError(
            f"билд {open_id} этой спеки уже выполняется",
            pos=command.code_pos,
            hint=f"остановить — stop({open_id})",
            sqlstate=SqlState.OBJECT_NOT_IN_PREREQUISITE_STATE,
        )

    async def _spec_sources(
        self, cur, command: BuildCall, spec_version: int
    ) -> list[str]:
        await cur.execute(
            "select source_dataset_code from datapulse.build_spec_source"
            " where dataset_code = %s and build_spec_num = %s"
            "  and version_id = %s",
            (command.dataset_code, command.build_spec_num, spec_version),
        )
        return [row[0] for row in await cur.fetchall()]

    async def _watermark(self, cur, sources: list[str], my_id: int) -> int:
        """Срез источников (to_build_id), инклюзивно: ниже самого раннего
        незавершённого билда датасетов-источников — его данные могут быть
        дозаписаны (или ждут триажа); без таковых — собственный id."""
        if not sources:
            return my_id
        await cur.execute(
            "select min(b.build_id) from datapulse.build b"
            + _LAST_STATUS_LATERAL
            + " where b.dataset_code = any(%s)"
            "   and ls.status_code != all(%s)",
            (sources, list(FINAL_STATUSES)),
        )
        running = (await cur.fetchone())[0]
        return running - 1 if running is not None else my_id

    async def _previous_clear(self, cur, command: BuildCall):
        """(from_build_id, previous_time) — срез и время финала последнего
        clear-успешного билда спеки; (0, None) — таких не было (0, не NULL:
        маппинги инлайнят границу в where build_id > {from_build_id})."""
        await cur.execute(
            "select b.source_build_id, ls.log_time from datapulse.build b"
            " join lateral (select status_code, log_time"
            "                from datapulse.build_log l"
            "                where l.build_id = b.build_id"
            "                order by l.build_log_id desc limit 1) ls on true"
            " where b.dataset_code = %s and b.build_spec_num = %s"
            "   and b.is_clear and ls.status_code = 'done'"
            " order by b.build_id desc limit 1",
            (command.dataset_code, command.build_spec_num),
        )
        row = await cur.fetchone()
        if row is None:
            return 0, None
        return row[0] or 0, row[1]

    async def _create_build_role(
        self, cur, command: BuildCall, build_id: int
    ) -> tuple[str, str]:
        """Временная учётка билда: права — только интерфейсная таблица
        своей спеки и usage её схемы (чтение датасетов открыто public до
        ролевой модели). Создаётся в транзакции создания билда, дропается
        по завершении; системной учётке нужен CREATEROLE."""
        role_name = f"dp_build_{build_id}"
        password = secrets.token_urlsafe(24)
        schema = command.dataset_code.split(".", 1)[0]
        iface = commands._iface_table(
            command.dataset_code, command.build_spec_num
        )
        # роль — кластерный объект: после жёсткой остановки сервера могла
        # осиротеть (даже пережить пересоздание БД) — дочищаем
        await cur.execute(
            "select 1 from pg_roles where rolname = %s", (role_name,)
        )
        if await cur.fetchone() is not None:
            await cur.execute(f"drop owned by {role_name}")
            await cur.execute(f"drop role {role_name}")
        await cur.execute(
            f"create role {role_name} login password %s", (password,)
        )
        await cur.execute(f"grant usage on schema {schema} to {role_name}")
        await cur.execute(
            f"grant select, insert, update, delete, truncate"
            f" on {iface} to {role_name}"
        )
        return role_name, password

    async def _child_connections(
        self, cur, database: str, command: BuildCall, spec_version: int,
        role_name: str, password: str,
    ) -> dict:
        """Коннекты ребёнка: объявленные using (текущие версии, секреты
        расшифровываются сейчас — битый секрет валит билд до запуска) и
        warehouse под временной учёткой."""
        await cur.execute(
            "select connection_code from datapulse.build_spec_connection"
            " where dataset_code = %s and build_spec_num = %s"
            "  and version_id = %s",
            (command.dataset_code, command.build_spec_num, spec_version),
        )
        connections: dict = {}
        for (code,) in await cur.fetchall():
            current = await commands._current_connection(cur, code)
            if current is None or current[0]:
                raise DplError(
                    f"коннект {code!r} спеки не существует",
                    pos=command.code_pos,
                    sqlstate=SqlState.UNDEFINED_OBJECT,
                )
            _, class_code, params = current
            connections[code] = {
                "class_code": class_code,
                "params": commands._decrypt_params(
                    code, class_code, params, self.config
                ),
            }
        connections["warehouse"] = {
            "class_code": POSTGRES_CONNECTION,
            "params": {
                "host_name": self.config.pg_host,
                "port_num": self.config.pg_port,
                "database_name": database,
                "user_name": role_name,
                "password": password,
            },
        }
        return connections

    # --- супервизор ---------------------------------------------------------

    async def _run_build(
        self, run: BuildRun, job: _Job, conn: psycopg.AsyncConnection
    ) -> None:
        """Ведёт билд до финала: load (ребёнок) → comp (перелив) → done;
        любая беда — fail. conn — соединение супервизора: журнал и
        warehouse-DDL, оно же держит claim-замок билда."""
        plan = _Plan(job)
        try:
            await self._journal(conn, job.version_id, job.build_id, "load")
            await conn.execute(f"truncate table {plan.iface}")
            if job.type_code != "skip":
                await self._run_mapping(run, job, conn)
                await conn.execute(f"analyze {plan.iface}")
            prepared = await self._scalar(
                conn, f"select count(1) from {plan.iface}"
            )
            await self._journal(
                conn, job.version_id, job.build_id, "comp",
                prepared_row_cnt=prepared,
            )
            inserted, updated, deleted = await self._transfer(conn, job, plan)
            if job.type_code == "init":
                # только init чистит интерфейсную за собой: он один удваивает
                # хранение, выхлоп прочих режимов полезен для разбора
                await conn.execute(f"truncate table {plan.iface}")
            await conn.execute(f"analyze {plan.main}")
            await self._journal(
                conn, job.version_id, job.build_id, "done",
                inserted_row_cnt=inserted, updated_row_cnt=updated,
                deleted_row_cnt=deleted,
            )
        except asyncio.CancelledError:
            reason = run.stop_reason or "остановлен"
            await asyncio.shield(self._journal_fail(job, reason))
            raise
        except Exception as exc:
            log.error("билд %s упал: %s", job.build_id, exc)
            await self._journal_fail(job, str(exc))
        finally:
            run.child.cancel()   # ребёнок не должен пережить супервизора
            await asyncio.shield(self._cleanup(run, job, conn))

    async def _run_mapping(
        self, run: BuildRun, job: _Job, conn
    ) -> None:
        """Load-фаза: тело спеки в процессе-ребёнке; печать — в журнал
        со статусом load."""

        async def to_journal(line: str) -> None:
            await self._journal(
                conn, job.version_id, job.build_id, "load", message=line
            )

        payload = json.dumps({
            "body": job.body,
            "connections": job.connections,
            "params": job.params,
        })
        return_code = await commands._run_child(
            payload.encode("utf-8"), to_journal, run.child
        )
        if return_code != 0:
            raise _BuildFailed(
                f"тело спеки завершилось с ошибкой (код {return_code});"
                " traceback — в журнале выше"
            )

    async def _journal_fail(self, job: _Job, reason: str) -> None:
        """Fail-строка на свежем соединении: соединение супервизора после
        отмены задачи может быть в непредсказуемом состоянии."""
        try:
            conn = await self._open(job.database, autocommit=True)
        except Exception:
            log.exception("билд %s: fail-строка журнала не записана",
                          job.build_id)
            return
        try:
            await self._journal(
                conn, job.version_id, job.build_id, "fail", message=reason
            )
        except Exception:
            log.exception("билд %s: fail-строка журнала не записана",
                          job.build_id)
        finally:
            await conn.close()

    async def _cleanup(
        self, run: BuildRun, job: _Job, conn: psycopg.AsyncConnection
    ) -> None:
        """Дроп временной учётки (best effort, свежим соединением) и
        освобождение claim-замка закрытием соединения супервизора."""
        self.runs.pop((run.database, run.build_id), None)
        try:
            cleaner = await self._open(job.database, autocommit=True)
        except Exception:
            log.warning("билд %s: учётка %s не удалена (БД недоступна)",
                        job.build_id, job.role_name)
            cleaner = None
        if cleaner is not None:
            try:
                # добить возможные хвосты сессий ребёнка, снять гранты, роль
                await cleaner.execute(
                    "select pg_terminate_backend(pid) from pg_stat_activity"
                    " where usename = %s", (job.role_name,)
                )
                await cleaner.execute(f"drop owned by {job.role_name}")
                await cleaner.execute(f"drop role {job.role_name}")
            except Exception as exc:
                log.warning("билд %s: учётка %s не удалена: %s",
                            job.build_id, job.role_name, exc)
            finally:
                await cleaner.close()
        await conn.close()

    # --- comp: чанковый перенос ---------------------------------------------

    async def _scalar(self, conn, sql: str):
        cur = await conn.execute(sql)
        return (await cur.fetchone())[0]

    async def _transfer(
        self, conn, job: _Job, plan: _Plan
    ) -> tuple[int, int, int]:
        """Перенос интерфейсной таблицы в основную SCD2 по типу режима."""
        if job.type_code == "skip":
            return 0, 0, 0
        empty = await self._scalar(
            conn, f"select not exists (select 1 from {plan.main})"
        )
        bulk = job.type_code == "appd" or (
            job.type_code in _COMPARING_TYPES and empty
        )
        await self._validate_interface(conn, plan, check_duplicates=bulk)
        if not bulk:
            return await self._run_chunks(job, plan, _sql_merge, stats=True)
        # bulk-загрузка в пустую таблицу роняет индексы и пересоздаёт их
        # после; appd в наполненную индексы не трогает
        indexes = (
            await self._snapshot_indexes(conn, plan)
            if job.type_code != "appd" else []
        )
        for name, _ in indexes:
            await conn.execute(f"drop index {plan.schema}.{name}")
        try:
            counts = await self._run_chunks(
                job, plan, _sql_bulk_insert, stats=False
            )
        except BaseException:
            # ошибка загрузки ценнее ошибки пересоздания — вторую не даём
            # замаскировать первую
            try:
                for _, definition in indexes:
                    await conn.execute(definition)
            except Exception as exc:
                log.error("билд %s: пересоздание индексов после сбоя"
                          " загрузки тоже упало: %s", job.build_id, exc)
            raise
        for _, definition in indexes:
            await conn.execute(definition)
        return counts

    async def _validate_interface(
        self, conn, plan: _Plan, *, check_duplicates: bool
    ) -> None:
        """NULL в логическом ключе — всегда фатален. Дубли ключа фатальны
        только там, где перенос не сравнивает (bulk/appd): мердж дедуплицирует
        их distinct on, а дубль, дошедший до SCD2-таблицы, плодится вечно."""
        nulls = await self._scalar(
            conn,
            f"select count(1) from {plan.iface}"
            f" where {' or '.join(f'{c} is null' for c in plan.pk)}",
        )
        if nulls:
            raise _BuildFailed(
                f"в {plan.iface} {nulls} строк с NULL в атрибутах ключа"
            )
        if not check_duplicates:
            return
        dups = await self._scalar(
            conn,
            f"select count(1) - count(distinct ({plan.pk_csv}))"
            f" from {plan.iface} where is_active",
        )
        if dups:
            raise _BuildFailed(
                f"в {plan.iface} {dups} дублей ключа: этот режим вставляет"
                " без сравнения, дубли остались бы навсегда"
            )

    async def _snapshot_indexes(self, conn, plan: _Plan) -> list[tuple[str, str]]:
        cur = await conn.execute(
            "select indexname, indexdef from pg_indexes"
            " where schemaname = %s and tablename = %s",
            (plan.schema, plan.table),
        )
        return await cur.fetchall()

    async def _run_chunks(
        self, job: _Job, plan: _Plan, make_sql, *, stats: bool
    ) -> tuple[int, int, int]:
        """Чанки параллельно, коммит отложен: транзакции всех чанков
        остаются открытыми и коммитятся подряд только когда каждый чанк
        успешен; любой сбой откатывает все — ничего не приземляется."""
        conns: list[psycopg.AsyncConnection] = []
        counts: list[tuple[int, int, int] | None] = [None] * plan.parallel
        committed = False
        try:
            try:
                async with asyncio.TaskGroup() as group:
                    for rn in range(1, plan.parallel + 1):
                        group.create_task(self._run_chunk(
                            job, plan, rn, make_sql, stats, conns, counts
                        ))
            except ExceptionGroup as eg:
                raise eg.exceptions[0] from eg
            for conn in conns:
                await conn.commit()
            committed = True
        finally:
            for conn in conns:
                if not committed:
                    try:
                        await conn.rollback()
                    except Exception:
                        pass
                await conn.close()
        totals = [0, 0, 0]
        for chunk_counts in counts:
            for i in range(3):
                totals[i] += chunk_counts[i]
        return totals[0], totals[1], totals[2]

    async def _run_chunk(
        self, job: _Job, plan: _Plan, rn: int, make_sql, stats: bool,
        conns: list, counts: list,
    ) -> None:
        conn = await self._open(job.database, autocommit=False)
        conns.append(conn)
        cur = conn.cursor()
        # билд уже параллелен по сессиям чанков — параллельный план сверху
        # умножил бы воркеров
        await cur.execute(
            "select set_config('max_parallel_workers_per_gather', '0', false)"
        )
        inserted = 0
        for stmt in make_sql(job, plan, rn):
            await cur.execute(stmt)
            if stmt.lstrip().startswith("insert"):
                inserted = cur.rowcount
        if stats:
            # sum(bigint) в Postgres — numeric: приводим к int
            await cur.execute(_STATS_SQL)
            counts[rn - 1] = tuple(int(x) for x in await cur.fetchone())
        else:
            counts[rn - 1] = (inserted, 0, 0)
        # транзакция остаётся открытой — коммитит _run_chunks

    # --- stop / fix ---------------------------------------------------------

    async def stop_build(
        self, database: str, user_code: str, command: StopCall
    ) -> str:
        """Запрос остановки: живой билд — отмена супервизора (kill ребёнка,
        откат чанков), сирота — fail-строка (ленивый reconcile). Остановка
        асинхронна: финал виден в журнале."""
        async with await commands._connect(self.config, database) as conn:
            cur = conn.cursor()
            await commands._require_installed(cur)
            row = await self._last_status(cur, command.build_id)
            if row is None:
                raise DplError(
                    f"билд {command.build_id} не существует",
                    pos=command.id_pos,
                    sqlstate=SqlState.UNDEFINED_OBJECT,
                )
            version_id, status = row
            if status in FINAL_STATUSES:
                raise DplError(
                    f"билд {command.build_id} уже завершён ({status})",
                    pos=command.id_pos,
                    sqlstate=SqlState.OBJECT_NOT_IN_PREREQUISITE_STATE,
                )
            if status == "fail":
                raise DplError(
                    f"билд {command.build_id} уже упал",
                    pos=command.id_pos,
                    hint=f"разобрано — fix({command.build_id})",
                    sqlstate=SqlState.OBJECT_NOT_IN_PREREQUISITE_STATE,
                )
            run = self.runs.get((database, command.build_id))
            if run is not None:
                run.stop(f"остановлен пользователем ({user_code})")
                return "STOP"
            await cur.execute(
                f"select pg_try_advisory_xact_lock({_CLAIM_KEY_SQL})",
                (str(command.build_id),),
            )
            orphan = (await cur.fetchone())[0]
            if not orphan:
                raise DplError(
                    f"билд {command.build_id} выполняется другим экземпляром"
                    " DataPulse — остановить его отсюда нельзя",
                    pos=command.id_pos,
                    sqlstate=SqlState.OBJECT_NOT_IN_PREREQUISITE_STATE,
                )
            # сирота упавшего сервера: закрываем журнал честным fail
            await self._journal(
                cur, version_id, command.build_id, "fail",
                message="неожиданная остановка сервера"
                f" (stop от {user_code})",
            )
            return "STOP"

    async def fix_build(
        self, database: str, user_code: str, command: FixCall
    ) -> str:
        """Fail разобран: финальная строка fix — дельты потребителей
        оттаивают, спека снова запускаема."""
        async with await commands._connect(self.config, database) as conn:
            cur = conn.cursor()
            await commands._require_installed(cur)
            row = await self._last_status(cur, command.build_id)
            if row is None:
                raise DplError(
                    f"билд {command.build_id} не существует",
                    pos=command.id_pos,
                    sqlstate=SqlState.UNDEFINED_OBJECT,
                )
            version_id, status = row
            if status in FINAL_STATUSES:
                raise DplError(
                    f"билд {command.build_id} уже завершён ({status})",
                    pos=command.id_pos,
                    sqlstate=SqlState.OBJECT_NOT_IN_PREREQUISITE_STATE,
                )
            if status != "fail":
                raise DplError(
                    f"билд {command.build_id} не завершён ({status}) —"
                    " разбирать нечего",
                    pos=command.id_pos,
                    hint=f"остановить — stop({command.build_id})",
                    sqlstate=SqlState.OBJECT_NOT_IN_PREREQUISITE_STATE,
                )
            await self._journal(
                cur, version_id, command.build_id, "fix",
                message=f"разобрано ({user_code})",
            )
            return "FIX"

    # --- attach -------------------------------------------------------------

    async def attach(
        self, database: str, command: AttachCall, notify, run: AttachRun
    ) -> str:
        """Живой хвост журнала: строки с позиции — NoticeResponse-ами;
        завершается, когда билд перестал быть активным (done | fail | fix).
        CancelRequest клиента отцепляет зрителя, билд продолжает жить."""
        conn = await self._open(database, autocommit=True)
        try:
            cur = conn.cursor()
            await commands._require_installed(cur)
            await cur.execute(
                "select 1 from datapulse.build where build_id = %s",
                (command.build_id,),
            )
            if await cur.fetchone() is None:
                raise DplError(
                    f"билд {command.build_id} не существует",
                    pos=command.id_pos,
                    sqlstate=SqlState.UNDEFINED_OBJECT,
                )
            pos = command.from_log_id
            while True:
                await cur.execute(
                    "select build_log_id, log_time, status_code, message,"
                    "       prepared_row_cnt, inserted_row_cnt,"
                    "       updated_row_cnt, deleted_row_cnt"
                    " from datapulse.build_log"
                    " where build_id = %s and build_log_id > %s"
                    " order by build_log_id",
                    (command.build_id, pos),
                )
                rows = await cur.fetchall()
                last_status = None
                for row in rows:
                    await notify(_format_log_row(row))
                    pos = row[0]
                    last_status = row[2]
                if last_status is None:
                    # новых строк нет — позиция могла быть за финалом
                    current = await self._last_status(cur, command.build_id)
                    last_status = current[1] if current else None
                if last_status in ("done", "fail", "fix"):
                    return "ATTACH"
                if run.cancelled:
                    raise DplError(
                        "attach отменён; билд продолжает выполняться",
                        sqlstate=SqlState.QUERY_CANCELED,
                    )
                try:
                    await asyncio.wait_for(run.event.wait(), timeout=1.0)
                except TimeoutError:
                    pass
        finally:
            await conn.close()


def _format_log_row(row) -> str:
    """Строка журнала для NoticeResponse: позиция, время, статус, детали."""
    (build_log_id, log_time, status, message,
     prepared, inserted, updated, deleted) = row
    text = f"#{build_log_id} {log_time:%Y-%m-%d %H:%M:%S} {status}"
    details = []
    if prepared is not None:
        details.append(f"подготовлено: {prepared}")
    if inserted is not None:
        details.append(
            f"вставлено: {inserted}, обновлено: {updated},"
            f" удалено: {deleted}"
        )
    if message:
        details.append(message)
    if details:
        text += " | " + "; ".join(details)
    return text
