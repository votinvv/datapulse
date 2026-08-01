"""Движок билдов и потоков: создание, супервизор, SCD2-перелив,
дирижёр потока, stop/fix/attach.

Билд асинхронен: `build(...)` создаёт запись и первую строку журнала
одной транзакцией под каталожным замком и немедленно возвращает
build_id; исполнение — asyncio-задача прокси, жизнь билда не привязана
к соединению клиента. Одновременные билды одной спеки запрещены; более
того, незавершённый билд (включая неразобранный fail) блокирует
следующий запуск той же спеки — fail закрывается командой fix.
«Замки» билда — журнальные, под каталожным замком создания: exclusive
на свою спеку (открытый билд блокирует следующий), shared на источники
(store-билд не стартует при занятом источнике и сам держит источники
от пересборки, пока читает); витринный билд замков на источники не
берёт — он читает по границе последнего успешного потока.

Окно дельты: from — build_id последнего успешного билда своей спеки в
окно-двигающем режиме (initial/increment/skip), to — собственный
build_id (у ручного витринного — граница последнего успешного потока);
границы инъецируются в тело, в каталоге не хранятся.

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

Поток (`flow(...)`) — волна по всему графу: дирижёр строит план
(живые store-спеки в топологическом порядке + витрины по крану
отгрузки), исполняет его последовательно билдами и ждёт своей очереди
(одновременно исполняется один поток; второй ждёт в статусе wait).
На время потока создание межстримовых билдов store-спек заблокировано
(витринные свободны). Упавший билд держит поток на своей спеке до fix,
после fix спека перезапускается новым билдом.

Живость билда и потока — session-замок pg_advisory_lock на соединении
супервизора/дирижёра: замок жив, пока жив прокси. «Активный» по
журналу билд (поток) без замка — сирота упавшего сервера; stop
закрывает его честным fail (билд) либо stop (поток) — ленивый
reconcile.
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
from .dpl import (
    AttachCall,
    BuildCall,
    DplError,
    FixCall,
    FlowAttachCall,
    FlowCall,
    FlowPauseCall,
    FlowResumeCall,
    FlowStopCall,
    SqlState,
    StopCall,
    WINDOW_MODES,
)

log = logging.getLogger("datapulse.engine")

# финалы билда; неразобранный fail — открытое состояние: он морозит
# дельты потребителей и блокирует следующий билд своей спеки
FINAL_STATUSES = ("done", "fix")

# статусы потока: wait → exec ⇄ hold → done | stop
FLOW_FINAL_STATUSES = ("done", "stop")
FLOW_OPEN_STATUSES = ("wait", "exec", "hold")

# типы переноса, сравнивающие срез с текущими данными
_COMPARING_TYPES = ("init", "incr", "sect")

_CLAIM_KEY_SQL = "hashtextextended('datapulse:build:' || %s, 0)"
_FLOW_CLAIM_KEY_SQL = "hashtextextended('datapulse:flow:' || %s, 0)"

_LAST_STATUS_LATERAL = (
    " join lateral (select status_code from datapulse.build_log l"
    "                where l.build_id = b.build_id"
    "                order by l.build_log_id desc limit 1) ls on true"
)

_FLOW_LAST_STATUS_LATERAL = (
    " join lateral (select status_code from datapulse.flow_log l"
    "                where l.flow_id = f.flow_id"
    "                order by l.flow_log_id desc limit 1) ls on true"
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


class FlowRun:
    """Живой поток этого прокси: задача-дирижёр и управление."""

    def __init__(self, database: str, flow_id: int) -> None:
        self.database = database
        self.flow_id = flow_id
        self.task: asyncio.Task | None = None
        self.stop_reason: str | None = None
        self.started = False           # дирижёр дошёл до исполнения
        self.active_build_id: int | None = None
        self._go = asyncio.Event()     # set — работаем; clear — пауза
        self._go.set()

    @property
    def paused(self) -> bool:
        return not self._go.is_set()

    def pause(self) -> None:
        self._go.clear()

    def resume(self) -> None:
        self._go.set()

    async def gate(self) -> None:
        """Точка паузы дирижёра: между шагами и в очереди."""
        await self._go.wait()

    def stop(self, reason: str) -> None:
        self.stop_reason = reason
        if self.task is not None:
            self.task.cancel()


@dataclass(frozen=True)
class _FlowStep:
    """Шаг плана потока: один билд спеки."""

    dataset_code: str
    build_spec_num: int
    mode_code: str


@dataclass(frozen=True)
class _Job:
    """Снимок всего, что нужно билду, — на момент создания (вотермарка)."""

    database: str
    build_id: int
    flow_id: int | None      # NULL — межстримовый (ручной) билд
    version_id: int          # вотермарка версии каталога
    dataset_code: str
    dataset_type: str        # store | mart
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


def _sql_mart_init(job: _Job, plan: _Plan, rn: int) -> list[str]:
    """Витринный init — «переотдать всё»: закрыть все открытые строки
    своего чанка и вставить активный срез интерфейсной целиком новой
    порцией. Сравнение здесь сломало бы семантику переотдачи: порция
    потребителя — полный срез одним build_id, а не дифф."""
    close = (
        f"update {plan.main} m\n"
        f"   set end_build_id = {job.build_id - 1}\n"
        f" where m.end_build_id is null\n"
        f"   and {plan.chunk_of('m', rn)}"
    )
    return [close, *_sql_bulk_insert(job, plan, rn)]


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
        self.flows: dict[tuple[str, int], FlowRun] = {}

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
        self,
        database: str,
        user_code: str,
        command: BuildCall,
        src: str,
        *,
        flow_id: int | None = None,
    ) -> int:
        """Создаёт билд (валидации-«замки», окно дельты, временная
        учётка) одной транзакцией и запускает супервизор; возвращает
        build_id немедленно. flow_id — билд запущен дирижёром потока."""
        super_conn: psycopg.AsyncConnection | None = None
        try:
            async with await commands._connect(self.config, database) as conn:
                cur = conn.cursor()
                last_version, _, _ = await commands._lock_catalog(cur)
                job = await self._prepare(
                    cur, database, last_version, user_code, command, flow_id
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
        command: BuildCall, flow_id: int | None,
    ) -> _Job:
        """Тело транзакции создания: валидации-«замки» по каталогу и
        журналу, окно дельты, строка build + wait, временная учётка."""
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
        dataset = await commands._current_dataset(cur, command.dataset_code)
        dataset_type = dataset[3]
        mode = await self._resolve_mode(cur, command, spec_version)
        # exclusive на свою спеку: открытый билд (включая неразобранный
        # fail) блокирует следующий
        await self._require_no_open_build(cur, command)
        sources = await self._spec_sources(cur, command, spec_version)
        if dataset_type == "store":
            if flow_id is None:
                await self._require_no_open_flow(cur, command)
            # shared на источники: занятый (включая открытый fail) источник
            # не отдаёт консистентного чтения
            await self._require_free_sources(cur, command, sources)
            # и зеркало shared: активные store-читатели держат мой датасет
            await self._require_no_active_readers(cur, command)
        await cur.execute(
            "select coalesce(max(build_id), 0) + 1 from datapulse.build"
        )
        build_id = (await cur.fetchone())[0]
        from_build_id, previous_time = await self._window_from(cur, command)
        to_build_id = await self._window_to(
            cur, build_id, dataset_type, flow_id
        )
        await cur.execute(
            "insert into datapulse.build"
            " (version_id, build_id, flow_id, dataset_code, build_spec_num,"
            "  mode_code, user_code)"
            " values (%s, %s, %s, %s, %s, %s, %s)",
            (version_id, build_id, flow_id, command.dataset_code,
             command.build_spec_num, mode[0], user_code),
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
            flow_id=flow_id,
            version_id=version_id,
            dataset_code=command.dataset_code,
            dataset_type=dataset_type,
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
    ) -> tuple[str, str]:
        """Режим запуска версии спеки: (mode_code, type_code)."""
        await cur.execute(
            "select mode_code, type_code"
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

    async def _require_no_open_flow(self, cur, command: BuildCall) -> None:
        """На время потока создание межстримовых билдов store-спек
        заблокировано: во время волны сторы пишет только сам поток."""
        await cur.execute(
            "select f.flow_id, ls.status_code from datapulse.flow f"
            + _FLOW_LAST_STATUS_LATERAL
            + " where ls.status_code = any(%s)"
            " order by f.flow_id limit 1",
            (list(FLOW_OPEN_STATUSES),),
        )
        row = await cur.fetchone()
        if row is not None:
            raise DplError(
                f"идёт поток {row[0]} ({row[1]}): межстримовые билды"
                " store-спек заблокированы до его завершения",
                pos=command.code_pos,
                hint=f"дождитесь потока (attach flow({row[0]})) либо"
                f" остановите его (stop flow({row[0]}))",
                sqlstate=SqlState.OBJECT_NOT_IN_PREREQUISITE_STATE,
            )

    async def _require_free_sources(
        self, cur, command: BuildCall, sources: list[str]
    ) -> None:
        """Shared-«замок» на источники: у спек source-датасетов нет
        незавершённых билдов — бегущий дописал бы срез под чтением, а
        открытый fail оставил частично применённые строки."""
        if not sources:
            return
        await cur.execute(
            "select b.build_id, b.dataset_code, ls.status_code"
            " from datapulse.build b"
            + _LAST_STATUS_LATERAL
            + " where b.dataset_code = any(%s)"
            "   and ls.status_code != all(%s)"
            " order by b.build_id limit 1",
            (sources, list(FINAL_STATUSES)),
        )
        row = await cur.fetchone()
        if row is not None:
            build_id, source, status = row
            hint = (
                f"fix({build_id}) после разбора"
                if status == "fail"
                else f"дождитесь билда (attach({build_id}))"
            )
            raise DplError(
                f"источник {source!r} занят: билд {build_id} ({status})",
                pos=command.code_pos,
                hint=hint,
                sqlstate=SqlState.OBJECT_NOT_IN_PREREQUISITE_STATE,
            )

    async def _require_no_active_readers(
        self, cur, command: BuildCall
    ) -> None:
        """Зеркало shared-«замка»: активный билд store-читателя держит мой
        датасет от пересборки, пока читает. Витринные читатели не держат
        (они читают по границе последнего успешного потока), открытый
        fail читателя — тоже (он не читает; его окно доберёт дельту
        после fix)."""
        await cur.execute(
            commands._CURRENT_SPECS_CTE
            + "select b.build_id, b.dataset_code, b.build_spec_num"
            "  from current_spec s"
            "  join datapulse.build_spec_source src"
            "    on src.dataset_code = s.dataset_code"
            "   and src.build_spec_num = s.build_spec_num"
            "   and src.version_id = s.version_id"
            "  join lateral ("
            "       select d.type_code from datapulse.dataset d"
            "        where d.dataset_code = s.dataset_code"
            "        order by d.version_id desc limit 1) dt on true"
            "  join datapulse.build b"
            "    on b.dataset_code = s.dataset_code"
            "   and b.build_spec_num = s.build_spec_num"
            "  join lateral (select status_code from datapulse.build_log l"
            "                 where l.build_id = b.build_id"
            "                 order by l.build_log_id desc limit 1) ls on true"
            " where not s.is_deleted and src.source_dataset_code = %s"
            "   and dt.type_code = 'store'"
            "   and ls.status_code in ('wait', 'load', 'comp')"
            " order by b.build_id limit 1",
            (command.dataset_code,),
        )
        row = await cur.fetchone()
        if row is not None:
            build_id, reader, num = row
            raise DplError(
                f"датасет читает билд {build_id} спеки {reader}.{num} —"
                " пересборка источника под чтением запрещена",
                pos=command.code_pos,
                hint=f"дождитесь билда (attach({build_id}))",
                sqlstate=SqlState.OBJECT_NOT_IN_PREREQUISITE_STATE,
            )

    async def _window_from(self, cur, command: BuildCall):
        """(from_build_id, previous_time) — нижняя граница окна дельты:
        build_id и время финала последнего успешного билда своей спеки в
        окно-двигающем режиме (initial/increment/skip); (0, None) — таких
        не было (0, не NULL: маппинги инлайнят границу в
        where build_id > {from_build_id})."""
        await cur.execute(
            "select b.build_id, ls.log_time from datapulse.build b"
            " join lateral (select status_code, log_time"
            "                from datapulse.build_log l"
            "                where l.build_id = b.build_id"
            "                order by l.build_log_id desc limit 1) ls on true"
            " where b.dataset_code = %s and b.build_spec_num = %s"
            "   and b.mode_code = any(%s) and ls.status_code = 'done'"
            " order by b.build_id desc limit 1",
            (command.dataset_code, command.build_spec_num,
             list(WINDOW_MODES)),
        )
        row = await cur.fetchone()
        if row is None:
            return 0, None
        return row[0], row[1]

    async def _window_to(
        self, cur, build_id: int, dataset_type: str, flow_id: int | None
    ) -> int:
        """Верхняя граница окна дельты, инклюзивно. Под «замками» билда
        собственный build_id накрывает всё закоммиченное: строк источников
        старше него появиться не может. Ручной витринный билд границ не
        держит — он строится только на данных последнего успешного потока,
        всё свежее для него грязь."""
        if dataset_type == "mart" and flow_id is None:
            await cur.execute(
                "select coalesce(max(b.build_id), 0) from datapulse.build b"
                " where b.flow_id in ("
                "   select f.flow_id from datapulse.flow f"
                + _FLOW_LAST_STATUS_LATERAL
                + "   where ls.status_code = 'done')"
            )
            return (await cur.fetchone())[0]
        return build_id

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
        if job.dataset_type == "mart" and job.type_code == "init":
            # полная переотдача: закрытие прежних порций + вставка среза;
            # индексы не роняются (таблица наполнена, как у appd)
            await self._validate_interface(conn, plan, check_duplicates=True)
            return await self._run_chunks(
                job, plan, _sql_mart_init, stats=False
            )
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

    # --- поток: запуск, очередь, дирижёр ------------------------------------

    async def _flow_journal(
        self, conn, version_id: int, flow_id: int, status: str,
        *, message: str | None = None,
    ) -> None:
        await conn.execute(
            "insert into datapulse.flow_log"
            " (version_id, flow_id, log_time, status_code, message)"
            " values (%s, %s, now(), %s, %s)",
            (version_id, flow_id, status, message),
        )

    async def _flow_last_status(self, cur, flow_id: int) -> tuple | None:
        """(version_id потока, последний статус); None — потока нет."""
        await cur.execute(
            "select f.version_id, ls.status_code from datapulse.flow f"
            + _FLOW_LAST_STATUS_LATERAL
            + " where f.flow_id = %s",
            (flow_id,),
        )
        return await cur.fetchone()

    async def start_flow(
        self, database: str, user_code: str, command: FlowCall
    ) -> int:
        """Создаёт поток (строка flow + wait) и немедленно возвращает
        flow_id; дирижёр — asyncio-задача, поток ждёт своей очереди
        (одновременно исполняется один), stop/pause/attach доступны с
        момента создания."""
        flow_conn: psycopg.AsyncConnection | None = None
        try:
            async with await commands._connect(self.config, database) as conn:
                cur = conn.cursor()
                last_version, _, _ = await commands._lock_catalog(cur)
                preset_body: str | None = None
                if command.flow_spec is not None:
                    preset = await commands._current_flow_spec(
                        cur, command.flow_spec
                    )
                    if preset is None or preset[0]:
                        raise DplError(
                            f"пресет {command.flow_spec!r} не существует",
                            pos=command.spec_pos,
                            sqlstate=SqlState.UNDEFINED_OBJECT,
                        )
                    preset_body = preset[2]
                await cur.execute(
                    "select coalesce(max(flow_id), 0) + 1 from datapulse.flow"
                )
                flow_id = (await cur.fetchone())[0]
                await cur.execute(
                    "insert into datapulse.flow"
                    " (version_id, flow_id, flow_spec_code, user_code,"
                    "  intake_code, export_code)"
                    " values (%s, %s, %s, %s, %s, %s)",
                    (last_version, flow_id, command.flow_spec, user_code,
                     command.intake_code, command.export_code),
                )
                await self._flow_journal(
                    cur, last_version, flow_id, "wait",
                    message="поток создан и ждёт очереди",
                )
                # claim до коммита: окна «сироты» нет (как у билда)
                flow_conn = await self._open(database, autocommit=True)
                await flow_conn.execute(
                    f"select pg_advisory_lock({_FLOW_CLAIM_KEY_SQL})",
                    (str(flow_id),),
                )
        except BaseException:
            if flow_conn is not None:
                await flow_conn.close()
            raise
        run = FlowRun(database, flow_id)
        self.flows[(database, flow_id)] = run
        run.task = asyncio.get_running_loop().create_task(
            self._run_flow(
                run, last_version, user_code, command, preset_body, flow_conn
            ),
            name=f"flow:{database}:{flow_id}",
        )
        log.info(
            "поток %s: пресет %r, краны intake=%s export=%s, БД %r,"
            " пользователь %r",
            flow_id, command.flow_spec, command.intake_code,
            command.export_code, database, user_code,
        )
        return flow_id

    async def _run_flow(
        self,
        run: FlowRun,
        version_id: int,
        user_code: str,
        command: FlowCall,
        preset_body: str | None,
        conn: psycopg.AsyncConnection,
    ) -> None:
        """Дирижёр: очередь → план → последовательные билды → done.
        conn — соединение дирижёра: журнал потока, оно же держит
        claim-замок."""
        flow_id = run.flow_id
        try:
            await self._flow_wait_turn(run, conn)
            run.started = True
            await self._flow_journal(
                conn, version_id, flow_id, "exec",
                message="поток начал исполнение",
            )
            plan = await self._flow_plan(conn, command, preset_body)
            await self._flow_journal(
                conn, version_id, flow_id, "exec",
                message="план: " + (
                    ", ".join(
                        f"{s.dataset_code}.{s.build_spec_num} ({s.mode_code})"
                        for s in plan
                    ) if plan else "пусто"
                ),
            )
            done_cnt = 0
            for step in plan:
                done_cnt += await self._flow_step(
                    run, conn, version_id, user_code, step
                )
            await self._flow_journal(
                conn, version_id, flow_id, "done",
                message=f"поток завершён: билдов {done_cnt}",
            )
        except asyncio.CancelledError:
            reason = run.stop_reason or "остановлен"
            await asyncio.shield(
                self._flow_finish_stop(run, version_id, reason)
            )
            raise
        except Exception as exc:
            log.error("поток %s остановлен ошибкой: %s", flow_id, exc)
            await asyncio.shield(
                self._flow_finish_stop(run, version_id, f"ошибка: {exc}")
            )
        finally:
            self.flows.pop((run.database, flow_id), None)
            await conn.close()

    async def _flow_wait_turn(self, run: FlowRun, conn) -> None:
        """Очередь потоков (FIFO по flow_id) + ожидание бегущих
        межстримовых store-билдов на старте. Открытый по журналу, но
        осиротевший поток (сервер падал) закрывается честным stop —
        иначе он заклинил бы очередь навсегда."""
        while True:
            await run.gate()
            cur = await conn.execute(
                "select f.flow_id, f.version_id from datapulse.flow f"
                + _FLOW_LAST_STATUS_LATERAL
                + " where f.flow_id < %s and ls.status_code = any(%s)"
                " order by f.flow_id limit 1",
                (run.flow_id, list(FLOW_OPEN_STATUSES)),
            )
            row = await cur.fetchone()
            if row is None:
                break
            ahead_id, ahead_version = row
            if self.flows.get((run.database, ahead_id)) is None:
                cur = await conn.execute(
                    f"select pg_try_advisory_lock({_FLOW_CLAIM_KEY_SQL})",
                    (str(ahead_id),),
                )
                orphan = (await cur.fetchone())[0]
                if orphan:
                    await self._flow_journal(
                        conn, ahead_version, ahead_id, "stop",
                        message="неожиданная остановка сервера (reconcile"
                        f" потоком {run.flow_id})",
                    )
                    await conn.execute(
                        f"select pg_advisory_unlock({_FLOW_CLAIM_KEY_SQL})",
                        (str(ahead_id),),
                    )
                    continue
            await asyncio.sleep(2.0)
        while True:
            await run.gate()
            cur = await conn.execute(
                "select b.build_id from datapulse.build b"
                + _LAST_STATUS_LATERAL
                + " join lateral (select d.type_code from datapulse.dataset d"
                "                 where d.dataset_code = b.dataset_code"
                "                 order by d.version_id desc limit 1) dt"
                "   on true"
                " where ls.status_code in ('wait', 'load', 'comp')"
                "   and dt.type_code = 'store'"
                " limit 1"
            )
            if (await cur.fetchone()) is None:
                return
            await asyncio.sleep(2.0)

    async def _flow_plan(
        self, conn, command: FlowCall, preset_body: str | None
    ) -> list[_FlowStep]:
        """План потока: все живые спеки в топологическом порядке
        датасетов; store — чистым режимом (increment, при отсутствии или
        первом запуске — initial), витрины — по крану отгрузки;
        индивидуальные запуски пресета — перед штатным толчком."""
        cur = conn.cursor()
        await cur.execute(
            commands._CURRENT_SPECS_CTE
            + "select s.dataset_code, s.build_spec_num, dt.type_code"
            "  from current_spec s"
            "  join lateral (select d.type_code from datapulse.dataset d"
            "                 where d.dataset_code = s.dataset_code"
            "                 order by d.version_id desc limit 1) dt on true"
            " where not s.is_deleted"
            " order by s.dataset_code, s.build_spec_num"
        )
        specs = await cur.fetchall()       # (dataset, num, type)
        await cur.execute(
            commands._CURRENT_SPECS_CTE
            + "select s.dataset_code, s.build_spec_num, m.mode_code"
            "  from current_spec s"
            "  join datapulse.build_spec_mode m"
            "    using (dataset_code, build_spec_num, version_id)"
            " where not s.is_deleted"
        )
        modes: dict[tuple[str, int], set[str]] = {}
        for ds, num, mode in await cur.fetchall():
            modes.setdefault((ds, num), set()).add(mode)
        edges = await commands._live_spec_sources(cur)
        await cur.execute(
            "select distinct b.dataset_code, b.build_spec_num"
            " from datapulse.build b"
            + _LAST_STATUS_LATERAL
            + " where b.mode_code = any(%s) and ls.status_code = 'done'",
            (list(WINDOW_MODES),),
        )
        has_window = set(await cur.fetchall())
        preset = await self._flow_preset(
            cur, preset_body, {(ds, num): t for ds, num, t in specs}
        )
        order = _topo_datasets(
            [ds for ds, _, _ in specs], [(ds, src) for ds, _, src in edges]
        )
        sources_of: dict[tuple[str, int], bool] = {}
        for ds, num, src in edges:
            sources_of[(ds, num)] = True
        plan: list[_FlowStep] = []
        by_dataset: dict[str, list[tuple[int, str]]] = {}
        for ds, num, type_code in specs:
            by_dataset.setdefault(ds, []).append((num, type_code))
        for ds in order:
            for num, type_code in sorted(by_dataset.get(ds, [])):
                key = (ds, num)
                declared = modes.get(key, set())
                if type_code == "mart":
                    if command.export_code == "pass":
                        continue
                    mode = (
                        "skip" if command.export_code == "skip"
                        else "increment"
                    )
                    if mode in declared:
                        plan.append(_FlowStep(ds, num, mode))
                    continue
                incoming = key not in sources_of      # загрузчик/генератор
                manual = preset.get(key)
                if incoming and command.intake_code == "pass":
                    # кран приёма закрыт: только индивидуальный запуск
                    # из пресета, без штатного толчка
                    if manual is not None:
                        plan.append(_FlowStep(ds, num, manual))
                    continue
                if manual is not None:
                    plan.append(_FlowStep(ds, num, manual))
                    if manual in WINDOW_MODES:
                        continue      # чистый индивидуальный — толчок не нужен
                if key in has_window and "increment" in declared:
                    clean = "increment"
                elif "initial" in declared:
                    clean = "initial"
                else:
                    clean = "increment"
                plan.append(_FlowStep(ds, num, clean))
        return plan

    async def _flow_preset(
        self, cur, preset_body: str | None,
        spec_types: dict[tuple[str, int], str],
    ) -> dict[tuple[str, int], str]:
        """Исполнение SQL пресета (read-only транзакция) и валидация
        all-or-nothing: строки (код датасета, номер спеки, режим)."""
        if preset_body is None:
            return {}
        await cur.execute("begin transaction read only")
        try:
            await cur.execute(preset_body)
            rows = await cur.fetchall()
        except psycopg.Error as exc:
            raise _BuildFailed(
                "SQL пресета упал: "
                + (exc.diag.message_primary or str(exc))
            ) from exc
        finally:
            try:
                await cur.execute("rollback")
            except psycopg.Error:
                pass
        preset: dict[tuple[str, int], str] = {}
        for row in rows:
            if len(row) < 3:
                raise _BuildFailed(
                    "пресет обязан отдавать три колонки: код датасета,"
                    " номер спеки, режим"
                )
            ds = str(row[0]).strip().lower()
            try:
                num = int(row[1])
            except (TypeError, ValueError):
                raise _BuildFailed(
                    f"пресет: номер спеки {row[1]!r} — не целое"
                ) from None
            mode = str(row[2]).strip().lower()
            key = (ds, num)
            if key not in spec_types:
                raise _BuildFailed(f"пресет: спеки {ds}.{num} не существует")
            if spec_types[key] == "mart":
                raise _BuildFailed(
                    f"пресет: {ds}.{num} — витринная спека; витрины"
                    " управляются краном отгрузки и ручным build"
                )
            if key in preset:
                raise _BuildFailed(f"пресет: спека {ds}.{num} указана дважды")
            preset[key] = mode
        return preset

    async def _flow_step(
        self, run: FlowRun, conn, version_id: int, user_code: str,
        step: _FlowStep,
    ) -> int:
        """Один шаг плана: создать билд (ожидая занятость спеки и
        источников), дождаться финала; fail — ждать fix и перезапустить
        спеку новым билдом. Возвращает число успешных билдов шага."""
        flow_id = run.flow_id
        call = BuildCall(
            dataset_code=step.dataset_code,
            code_pos=0,
            build_spec_num=step.build_spec_num,
            num_pos=0,
            mode_code=step.mode_code,
            mode_pos=0,
        )
        waiting_logged = False
        while True:
            await run.gate()
            try:
                build_id = await self.start_build(
                    run.database, user_code, call, "flow", flow_id=flow_id
                )
            except DplError as exc:
                if exc.sqlstate != SqlState.OBJECT_NOT_IN_PREREQUISITE_STATE:
                    # сдвиг каталога под планом (спека исчезла) или
                    # авария — поток останавливается с ошибкой
                    raise _BuildFailed(
                        f"спека {step.dataset_code}.{step.build_spec_num}:"
                        f" {exc.message}"
                    ) from exc
                # спека или источник заняты (доезжает межстримовый,
                # открытый fail ждёт fix) — дирижёр ждёт
                if not waiting_logged:
                    await self._flow_journal(
                        conn, version_id, flow_id, "exec",
                        message=f"спека {step.dataset_code}"
                        f".{step.build_spec_num}: ожидание —"
                        f" {exc.message}",
                    )
                    waiting_logged = True
                await asyncio.sleep(2.0)
                continue
            waiting_logged = False
            run.active_build_id = build_id
            await self._flow_journal(
                conn, version_id, flow_id, "exec",
                message=f"спека {step.dataset_code}.{step.build_spec_num}:"
                f" билд {build_id} ({step.mode_code})",
            )
            final = await self._wait_build_final(conn, build_id)
            run.active_build_id = None
            if final == "done":
                return 1
            # fail: поток держится на спеке до fix, затем перезапуск
            await self._flow_journal(
                conn, version_id, flow_id, "exec",
                message=f"билд {build_id} упал — поток ждёт fix({build_id})",
            )
            await self._wait_build_fixed(conn, build_id)

    async def _wait_build_final(self, conn, build_id: int) -> str:
        while True:
            cur = await conn.execute(
                "select ls.status_code from datapulse.build b"
                + _LAST_STATUS_LATERAL
                + " where b.build_id = %s",
                (build_id,),
            )
            status = (await cur.fetchone())[0]
            if status in ("done", "fail", "fix"):
                return status
            await asyncio.sleep(0.3)

    async def _wait_build_fixed(self, conn, build_id: int) -> None:
        while True:
            cur = await conn.execute(
                "select ls.status_code from datapulse.build b"
                + _LAST_STATUS_LATERAL
                + " where b.build_id = %s",
                (build_id,),
            )
            if (await cur.fetchone())[0] == "fix":
                return
            await asyncio.sleep(2.0)

    async def _flow_finish_stop(
        self, run: FlowRun, version_id: int, reason: str
    ) -> None:
        """Финал stop: убить активный билд потока (с автоматическим
        system-fix — в триаже только реальные поломки), дописать stop
        свежим соединением."""
        try:
            conn = await self._open(run.database, autocommit=True)
        except Exception:
            log.exception("поток %s: stop-строка журнала не записана",
                          run.flow_id)
            return
        try:
            build_id = run.active_build_id
            if build_id is not None:
                build_run = self.runs.get((run.database, build_id))
                if build_run is not None:
                    build_run.stop(f"поток {run.flow_id}: {reason}")
                    await self._system_fix(conn, build_id)
            await self._flow_journal(
                conn, version_id, run.flow_id, "stop",
                message=f"остановлен вручную: {reason}",
            )
        except Exception:
            log.exception("поток %s: stop-строка журнала не записана",
                          run.flow_id)
        finally:
            await conn.close()

    async def _system_fix(self, conn, build_id: int) -> None:
        """Автоматический fix билда, убитого вместе с потоком: остановка
        административная, в триаже только реальные поломки."""
        try:
            async with asyncio.timeout(30):
                while True:
                    cur = await conn.execute(
                        "select b.version_id, ls.status_code"
                        " from datapulse.build b"
                        + _LAST_STATUS_LATERAL
                        + " where b.build_id = %s",
                        (build_id,),
                    )
                    row = await cur.fetchone()
                    if row is None or row[1] in FINAL_STATUSES:
                        return
                    if row[1] == "fail":
                        await self._journal(
                            conn, row[0], build_id, "fix",
                            message="остановлен вместе с потоком"
                            " (system-fix)",
                        )
                        return
                    await asyncio.sleep(0.5)
        except TimeoutError:
            log.warning("билд %s: system-fix не дождался финала", build_id)

    # --- поток: stop / pause / resume / attach ------------------------------

    async def stop_flow(
        self, database: str, user_code: str, command: FlowStopCall
    ) -> str:
        """Остановка потока: живой — отмена дирижёра (kill активного
        билда с system-fix); сирота упавшего сервера — честный stop
        (ленивый reconcile)."""
        async with await commands._connect(self.config, database) as conn:
            cur = conn.cursor()
            await commands._require_installed(cur)
            row = await self._flow_last_status(cur, command.flow_id)
            if row is None:
                raise DplError(
                    f"поток {command.flow_id} не существует",
                    pos=command.id_pos,
                    sqlstate=SqlState.UNDEFINED_OBJECT,
                )
            version_id, status = row
            if status in FLOW_FINAL_STATUSES:
                raise DplError(
                    f"поток {command.flow_id} уже завершён ({status})",
                    pos=command.id_pos,
                    sqlstate=SqlState.OBJECT_NOT_IN_PREREQUISITE_STATE,
                )
            run = self.flows.get((database, command.flow_id))
            if run is not None:
                run.stop(f"остановлен пользователем ({user_code})")
                return "STOP"
            await cur.execute(
                f"select pg_try_advisory_xact_lock({_FLOW_CLAIM_KEY_SQL})",
                (str(command.flow_id),),
            )
            orphan = (await cur.fetchone())[0]
            if not orphan:
                raise DplError(
                    f"поток {command.flow_id} выполняется другим экземпляром"
                    " DataPulse — остановить его отсюда нельзя",
                    pos=command.id_pos,
                    sqlstate=SqlState.OBJECT_NOT_IN_PREREQUISITE_STATE,
                )
            await self._flow_journal(
                cur, version_id, command.flow_id, "stop",
                message="неожиданная остановка сервера"
                f" (stop от {user_code})",
            )
            return "STOP"

    def _live_flow(self, database: str, flow_id: int, pos: int) -> FlowRun:
        run = self.flows.get((database, flow_id))
        if run is None:
            raise DplError(
                f"поток {flow_id} не исполняется этим экземпляром DataPulse"
                " (завершён, осиротел или чужой)",
                pos=pos,
                hint="журнал потока — select из datapulse.flow_log",
                sqlstate=SqlState.OBJECT_NOT_IN_PREREQUISITE_STATE,
            )
        return run

    async def pause_flow(
        self, database: str, user_code: str, command: FlowPauseCall
    ) -> str:
        """Пауза: новые билды не запускаются, бегущий доезжает."""
        run = self._live_flow(database, command.flow_id, command.id_pos)
        if run.paused:
            raise DplError(
                f"поток {command.flow_id} уже на паузе",
                pos=command.id_pos,
                sqlstate=SqlState.OBJECT_NOT_IN_PREREQUISITE_STATE,
            )
        run.pause()
        async with await commands._connect(self.config, database) as conn:
            row = await self._flow_last_status(
                conn.cursor(), command.flow_id
            )
            await self._flow_journal(
                conn, row[0], command.flow_id, "hold",
                message=f"пауза ({user_code})",
            )
        return "PAUSE"

    async def resume_flow(
        self, database: str, user_code: str, command: FlowResumeCall
    ) -> str:
        run = self._live_flow(database, command.flow_id, command.id_pos)
        if not run.paused:
            raise DplError(
                f"поток {command.flow_id} не на паузе",
                pos=command.id_pos,
                sqlstate=SqlState.OBJECT_NOT_IN_PREREQUISITE_STATE,
            )
        run.resume()
        async with await commands._connect(self.config, database) as conn:
            row = await self._flow_last_status(
                conn.cursor(), command.flow_id
            )
            await self._flow_journal(
                conn, row[0], command.flow_id,
                "exec" if run.started else "wait",
                message=f"пауза снята ({user_code})",
            )
        return "RESUME"

    async def attach_flow(
        self, database: str, command: FlowAttachCall, notify, run: AttachRun
    ) -> str:
        """Живой хвост журнала потока: строки с позиции —
        NoticeResponse-ами; завершается на финале (done | stop)."""
        conn = await self._open(database, autocommit=True)
        try:
            cur = conn.cursor()
            await commands._require_installed(cur)
            await cur.execute(
                "select 1 from datapulse.flow where flow_id = %s",
                (command.flow_id,),
            )
            if await cur.fetchone() is None:
                raise DplError(
                    f"поток {command.flow_id} не существует",
                    pos=command.id_pos,
                    sqlstate=SqlState.UNDEFINED_OBJECT,
                )
            pos = command.from_log_id
            while True:
                await cur.execute(
                    "select flow_log_id, log_time, status_code, message"
                    " from datapulse.flow_log"
                    " where flow_id = %s and flow_log_id > %s"
                    " order by flow_log_id",
                    (command.flow_id, pos),
                )
                rows = await cur.fetchall()
                last_status = None
                for row in rows:
                    await notify(_format_flow_log_row(row))
                    pos = row[0]
                    last_status = row[2]
                if last_status is None:
                    current = await self._flow_last_status(
                        cur, command.flow_id
                    )
                    last_status = current[1] if current else None
                if last_status in FLOW_FINAL_STATUSES:
                    return "ATTACH"
                if run.cancelled:
                    raise DplError(
                        "attach отменён; поток продолжает выполняться",
                        sqlstate=SqlState.QUERY_CANCELED,
                    )
                try:
                    await asyncio.wait_for(run.event.wait(), timeout=1.0)
                except TimeoutError:
                    pass
        finally:
            await conn.close()


def _topo_datasets(
    datasets: list[str], edges: list[tuple[str, str]]
) -> list[str]:
    """Топологический порядок датасетов (Кан): источники раньше
    читателей; при равенстве — лексикографически (стабильный план).
    Ацикличность гарантирована валидацией create build_spec."""
    nodes = sorted(set(datasets))
    depends: dict[str, set[str]] = {ds: set() for ds in nodes}
    for ds, src in edges:
        if ds in depends and src in depends:
            depends[ds].add(src)
    order: list[str] = []
    ready = sorted(ds for ds, deps in depends.items() if not deps)
    while ready:
        node = ready.pop(0)
        order.append(node)
        for ds in nodes:
            deps = depends.get(ds)
            if deps is not None and node in deps:
                deps.discard(node)
                if not deps and ds not in order and ds not in ready:
                    ready.append(ds)
        ready.sort()
    return order


def _format_flow_log_row(row) -> str:
    """Строка журнала потока для NoticeResponse."""
    flow_log_id, log_time, status, message = row
    text = f"#{flow_log_id} {log_time:%Y-%m-%d %H:%M:%S} {status}"
    if message:
        text += " | " + message
    return text


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
