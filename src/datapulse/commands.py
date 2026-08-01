"""Исполнение перехваченных DPL-команд.

Команда исполняется на отдельном соединении под системной учёткой
(PG_USER) к той же БД, к которой подключён клиент; одна команда — одна
транзакция: метаданные и warehouse-объекты атомарны. Курсоры —
клиентские (simple-протокол): schema.sql исполняется одним куском.

Имена схем, датасетов и атрибутов интерполируются в DDL без кавычек —
они провалидированы парсером ([a-z_][a-z0-9_]*, лимиты длины), типы
атрибутов — из белого списка; список из datapulse.version.usage
перепроверяется тем же правилом.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import subprocess
import sys
import textwrap
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

import psycopg

from .config import Config
from .connections import (
    POSTGRES_CONNECTION,
    RESERVED_CONNECTION_CODE,
    secret_fields,
    validate_params,
)
from .dpl import (
    AlterDatapulseAdd,
    AttachCall,
    BuildCall,
    Command,
    CommentOnAttr,
    CommentOnDatapulse,
    CommentOnDataset,
    CreateBuildSpec,
    CreateConnection,
    CreateDatapulse,
    CreateDataset,
    CreateFlowSpec,
    DatasetAttr,
    DplError,
    DropBuildSpec,
    DropDataset,
    DropFlowSpec,
    FixCall,
    FlowAttachCall,
    FlowCall,
    FlowPauseCall,
    FlowResumeCall,
    FlowStopCall,
    MART_TRANSFER_TYPES,
    PythonBlock,
    STORE_TRANSFER_TYPES,
    SqlState,
    StopCall,
    TestConnection,
)
from .pgwire import INT8_OID
from .secrets import SecretError, decrypt_value, encrypt_value

log = logging.getLogger("datapulse.commands")

DATAPULSE_SCHEMA = "datapulse"

_IDENT_RE = re.compile(r"[a-z_][a-z0-9_]{0,62}\Z")

_SCHEMA_SQL = Path(__file__).with_name("schema.sql").read_text(encoding="utf-8")

# стриминг наружу (NoticeResponse): печать python-блоков и журналы билдов
NotifyFn = Callable[[str], Awaitable[None]]


@dataclass(frozen=True)
class TableResult:
    """Собственный табличный ответ перехваченной команды (build)."""

    tag: str
    columns: list[tuple[str, int]]     # (имя, OID типа)
    rows: list[list[str | None]]       # значения текстового формата


class PythonRun:
    """Ручка живого python-блока: релей отменяет его по CancelRequest
    клиента (kill процесса-ребёнка); сокеты коннектов рвутся вместе с
    процессом, незакоммиченные транзакции откатывают сами СУБД."""

    def __init__(self) -> None:
        self.proc: subprocess.Popen | None = None
        self.cancelled = False

    def cancel(self) -> None:
        self.cancelled = True
        if self.proc is not None and self.proc.poll() is None:
            self.proc.kill()


async def execute(
    config: Config,
    database: str,
    user_code: str,
    command: Command,
    src: str,
    *,
    notify: NotifyFn | None = None,
    run=None,
    engine=None,
) -> str | TableResult:
    """Исполняет команду, возвращает command tag для клиента (build —
    табличный TableResult).

    src — текст запроса как пришёл: команды, бампающие версию каталога,
    кладут его в datapulse.version.src. notify — стрим печати/журнала
    перехваченной команды клиенту, run — ручка отмены (python-блок,
    attach), engine — движок билдов сервера. Ошибки платформы —
    DplError; непредусмотренная ошибка Postgres пробрасывается клиенту
    с оригинальным SQLSTATE и текстом.
    """
    try:
        if isinstance(command, PythonBlock):
            return await _run_python(config, database, command, notify, run)
        if isinstance(command, BuildCall):
            build_id = await engine.start_build(
                database, user_code, command, src
            )
            return TableResult(
                tag="BUILD",
                columns=[("build_id", INT8_OID)],
                rows=[[str(build_id)]],
            )
        if isinstance(command, AttachCall):
            return await engine.attach(database, command, notify, run)
        if isinstance(command, StopCall):
            return await engine.stop_build(database, user_code, command)
        if isinstance(command, FixCall):
            return await engine.fix_build(database, user_code, command)
        if isinstance(command, FlowCall):
            flow_id = await engine.start_flow(database, user_code, command)
            return TableResult(
                tag="FLOW",
                columns=[("flow_id", INT8_OID)],
                rows=[[str(flow_id)]],
            )
        if isinstance(command, FlowAttachCall):
            return await engine.attach_flow(database, command, notify, run)
        if isinstance(command, FlowStopCall):
            return await engine.stop_flow(database, user_code, command)
        if isinstance(command, FlowPauseCall):
            return await engine.pause_flow(database, user_code, command)
        if isinstance(command, FlowResumeCall):
            return await engine.resume_flow(database, user_code, command)
        async with await _connect(config, database) as conn:
            cur = conn.cursor()
            if isinstance(command, CreateDatapulse):
                return await _create(cur, command.schemas, user_code, src)
            if isinstance(command, CreateDataset):
                return await _create_dataset(cur, command, user_code, src)
            if isinstance(command, DropDataset):
                return await _drop_dataset(cur, command, user_code, src)
            if isinstance(command, CreateBuildSpec):
                return await _create_build_spec(cur, command, user_code, src)
            if isinstance(command, DropBuildSpec):
                return await _drop_build_spec(cur, command, user_code, src)
            if isinstance(command, CommentOnDatapulse):
                return await _comment_datapulse(cur, command, user_code, src)
            if isinstance(command, CommentOnDataset):
                return await _comment_dataset(cur, command, user_code, src)
            if isinstance(command, CommentOnAttr):
                return await _comment_attr(cur, command, user_code, src)
            if isinstance(command, CreateConnection):
                return await _create_connection(
                    cur, command, user_code, src, config
                )
            if isinstance(command, TestConnection):
                return await _test_connection(cur, command, config)
            if isinstance(command, AlterDatapulseAdd):
                return await _alter_datapulse_add(cur, command, user_code, src)
            if isinstance(command, CreateFlowSpec):
                return await _create_flow_spec(cur, command, user_code, src)
            if isinstance(command, DropFlowSpec):
                return await _drop_flow_spec(cur, command, user_code, src)
            return await _drop(cur)
    except (DplError, psycopg.Error):
        raise
    except Exception:
        log.exception("внутренняя ошибка исполнения DPL")
        raise


async def _connect(config: Config, database: str) -> psycopg.AsyncConnection:
    try:
        return await psycopg.AsyncConnection.connect(
            host=config.pg_host,
            port=config.pg_port,
            dbname=database,
            user=config.pg_user,
            password=config.pg_password,
            cursor_factory=psycopg.AsyncClientCursor,
            connect_timeout=10,
        )
    except psycopg.OperationalError as exc:
        raise DplError(
            f"системное соединение с БД {database!r} не открылось: {exc}",
            sqlstate=SqlState.CONNECTION_FAILURE,
        ) from exc


# --- create / drop datapulse ------------------------------------------------


async def _create(cur, schemas: list[str], user_code: str, src: str) -> str:
    names = ", ".join(f"'{s}'" for s in [DATAPULSE_SCHEMA, *schemas])
    await cur.execute(
        f"select nspname from pg_namespace where nspname in ({names})"
        " order by nspname"
    )
    busy = [row[0] for row in await cur.fetchall()]
    if DATAPULSE_SCHEMA in busy:
        raise DplError(
            f"DataPulse уже установлен: схема {DATAPULSE_SCHEMA!r} существует",
            sqlstate=SqlState.DUPLICATE_SCHEMA,
            hint="снять установку — drop datapulse",
        )
    if busy:
        raise DplError(
            "схемы уже существуют в БД: " + ", ".join(busy),
            sqlstate=SqlState.DUPLICATE_SCHEMA,
            hint="выберите свободные имена схем данных",
        )
    await cur.execute(_SCHEMA_SQL)
    for schema in schemas:
        await _create_data_schema(cur, schema)
    await _insert_version(
        cur, 1,
        user_code=user_code,
        command="create datapulse",
        src=src,
        usage=",".join(schemas),
        descr=None,
    )
    return "CREATE DATAPULSE"


async def _create_data_schema(cur, schema: str) -> None:
    await cur.execute(f"create schema {schema}")
    await cur.execute(f"grant usage on schema {schema} to public")


async def _drop(cur) -> str:
    # advisory-замок: снос не должен гнаться с каталожной командой
    _, usage, _ = await _lock_catalog(cur)
    schemas = [s for s in usage.split(",") if s]
    for schema in schemas:
        if not _IDENT_RE.fullmatch(schema):
            raise DplError(
                f"повреждён список схем данных в datapulse.version.usage:"
                f" {schema!r}",
                sqlstate=SqlState.INTERNAL_ERROR,
            )
    for schema in schemas:
        await cur.execute(f"drop schema if exists {schema} cascade")
    await cur.execute(f"drop schema {DATAPULSE_SCHEMA} cascade")
    return "DROP DATAPULSE"


async def _alter_datapulse_add(
    cur, command: AlterDatapulseAdd, user_code: str, src: str
) -> str:
    """Новая схема данных: создаётся в БД и дополняет usage."""
    last_version, usage, dp_descr = await _lock_catalog(cur)
    declared = usage.split(",")
    if command.schema in declared:
        raise DplError(
            f"схема {command.schema!r} уже объявлена схемой данных",
            pos=command.schema_pos,
            sqlstate=SqlState.DUPLICATE_SCHEMA,
        )
    await cur.execute(
        "select 1 from pg_namespace where nspname = %s", (command.schema,)
    )
    if await cur.fetchone() is not None:
        raise DplError(
            f"схема {command.schema!r} уже существует в БД",
            pos=command.schema_pos,
            sqlstate=SqlState.DUPLICATE_SCHEMA,
            hint="выберите свободное имя схемы данных",
        )
    await _create_data_schema(cur, command.schema)
    await _insert_version(
        cur, last_version + 1,
        user_code=user_code,
        command="alter datapulse add",
        src=src,
        usage=",".join([*declared, command.schema]),
        descr=dp_descr,
    )
    return "ALTER DATAPULSE"


# --- общий каркас каталожных команд ----------------------------------------


async def _require_installed(cur) -> None:
    await cur.execute(
        "select 1 from pg_namespace where nspname = %s", (DATAPULSE_SCHEMA,)
    )
    if await cur.fetchone() is None:
        raise DplError(
            f"DataPulse не установлен: схемы {DATAPULSE_SCHEMA!r} нет",
            sqlstate=SqlState.INVALID_SCHEMA_NAME,
            hint="установка — create datapulse (схема_1, …)",
        )


async def _lock_catalog(cur) -> tuple[int, str, str | None]:
    """Пролог каталожной команды: установка на месте, advisory-замок БД
    на время транзакции (иначе гонка за max(version_id) между сессиями);
    возвращает последнюю версию каталога (version_id, usage, descr)."""
    await _require_installed(cur)
    await cur.execute(
        "select pg_advisory_xact_lock("
        "hashtextextended('datapulse:' || current_database(), 0))"
    )
    await cur.execute(
        "select version_id, usage, descr from datapulse.version"
        " order by version_id desc limit 1"
    )
    row = await cur.fetchone()
    if row is None:
        raise DplError(
            "повреждены метаданные: datapulse.version пуст",
            sqlstate=SqlState.INTERNAL_ERROR,
        )
    return row


async def _insert_version(
    cur,
    version_id: int,
    *,
    user_code: str,
    command: str,
    src: str,
    usage: str,
    descr: str | None,
) -> None:
    """Новая строка журнала версий; descr — описание установки,
    версионируется вместе с каталогом (как usage)."""
    await cur.execute(
        "insert into datapulse.version"
        " (version_id, create_time, user_code, command, src, descr, usage)"
        " values (%s, now(), %s, %s, %s, %s, %s)",
        (version_id, user_code, command, src, descr, usage),
    )


# --- датасеты ---------------------------------------------------------------


async def _current_dataset(
    cur, dataset_code: str
) -> tuple[int, bool, str | None, str] | None:
    """Последняя версия датасета (version_id, is_deleted, descr,
    type_code); None — версий не было."""
    await cur.execute(
        "select version_id, is_deleted, descr, type_code"
        " from datapulse.dataset"
        " where dataset_code = %s order by version_id desc limit 1",
        (dataset_code,),
    )
    return await cur.fetchone()


async def _require_live_dataset(
    cur, dataset_code: str, pos: int
) -> tuple[int, bool, str | None, str]:
    """Живой датасет обязателен: (version_id, is_deleted=False, descr,
    type_code)."""
    current = await _current_dataset(cur, dataset_code)
    if current is None or current[1]:
        raise DplError(
            f"датасет {dataset_code!r} не существует",
            pos=pos,
            sqlstate=SqlState.UNDEFINED_OBJECT,
        )
    return current


async def _insert_dataset(
    cur,
    version_id: int,
    dataset_code: str,
    *,
    type_code: str,
    is_deleted: bool,
    descr: str | None,
) -> None:
    await cur.execute(
        "insert into datapulse.dataset"
        " (version_id, dataset_code, type_code, is_deleted, descr)"
        " values (%s, %s, %s, %s, %s)",
        (version_id, dataset_code, type_code, is_deleted, descr),
    )


async def _dataset_attrs(cur, dataset_code: str, version_id: int) -> list[tuple]:
    """Атрибуты версии датасета: (attr_code, order_num, type_code,
    is_primary, descr)."""
    await cur.execute(
        "select attr_code, order_num, type_code, is_primary, descr"
        " from datapulse.dataset_attr"
        " where dataset_code = %s and version_id = %s order by order_num",
        (dataset_code, version_id),
    )
    return await cur.fetchall()


async def _insert_dataset_attrs(
    cur, version_id: int, dataset_code: str, attrs: list[tuple]
) -> None:
    """Комплект атрибутов под version_id; attrs — кортежи (attr_code,
    order_num, type_code, is_primary, descr)."""
    await cur.executemany(
        "insert into datapulse.dataset_attr"
        " (version_id, dataset_code, attr_code, order_num, type_code,"
        "  is_primary, descr)"
        " values (%s, %s, %s, %s, %s, %s, %s)",
        [(version_id, dataset_code, *attr) for attr in attrs],
    )


async def _create_dataset(cur, command: CreateDataset, user_code: str, src: str) -> str:
    last_version, usage, dp_descr = await _lock_catalog(cur)
    schema = command.dataset_code.split(".", 1)[0]
    declared = usage.split(",")
    if schema not in declared:
        raise DplError(
            f"схема {schema!r} не объявлена схемой данных установки",
            pos=command.code_pos,
            sqlstate=SqlState.INVALID_SCHEMA_NAME,
            hint="объявленные схемы: " + ", ".join(declared),
        )
    current = await _current_dataset(cur, command.dataset_code)
    alive = current is not None and not current[1]
    if alive and not command.or_replace:
        raise DplError(
            f"датасет {command.dataset_code!r} уже существует",
            pos=command.code_pos,
            sqlstate=SqlState.DUPLICATE_OBJECT,
            hint=f"заменить — create or replace {command.type_code} dataset",
        )
    if alive and current[3] != command.type_code:
        raise DplError(
            f"датасет {command.dataset_code!r} — {current[3]}: смена"
            " подкласса через or replace запрещена",
            pos=command.code_pos,
            hint="смена рода — drop dataset, затем create",
            sqlstate=SqlState.FEATURE_NOT_SUPPORTED,
        )
    # комментарии датасета и атрибутов переживают or replace (семантика
    # Postgres); сопоставление атрибутов — по имени
    ds_descr = current[2] if alive else None
    attr_descr: dict[str, str | None] = {}
    live_specs: list[int] = []
    if alive:
        old = await _dataset_attrs(cur, command.dataset_code, current[0])
        attr_descr = {attr[0]: attr[4] for attr in old}
        live_specs = await _live_spec_nums(cur, command.dataset_code)
        if live_specs:
            _check_live_specs_diff(command, old)
    version_id = last_version + 1
    await _insert_version(
        cur, version_id,
        user_code=user_code,
        command=(
            f"create or replace {command.type_code} dataset"
            if command.or_replace else f"create {command.type_code} dataset"
        ),
        src=src,
        usage=usage,
        descr=dp_descr,
    )
    await _insert_dataset(
        cur, version_id, command.dataset_code,
        type_code=command.type_code, is_deleted=False, descr=ds_descr,
    )
    await _insert_dataset_attrs(
        cur, version_id, command.dataset_code,
        [
            (attr.name, order_num, attr.type_code, attr.is_primary,
             attr_descr.get(attr.name))
            for order_num, attr in enumerate(command.attrs, start=1)
        ],
    )
    await _create_dataset_view(
        cur, command.dataset_code, command.attrs, live_specs, ds_descr,
        {attr.name: attr_descr.get(attr.name) for attr in command.attrs},
    )
    return "CREATE DATASET"


def _check_live_specs_diff(command: CreateDataset, old: list[tuple]) -> None:
    """При живых спеках менять можно только набор неключевых атрибутов —
    но физика ALTER пары таблиц пока не разъезжается (честная заглушка)."""
    old_types = {attr[0]: attr[2] for attr in old}
    old_pk = {attr[0] for attr in old if attr[3]}
    new_types = {attr.name: attr.type_code for attr in command.attrs}
    new_pk = {attr.name for attr in command.attrs if attr.is_primary}
    if old_pk != new_pk:
        raise DplError(
            "при живых спеках PRIMARY KEY неизменен"
            f" (был: {', '.join(sorted(old_pk))})",
            pos=command.code_pos,
            sqlstate=SqlState.FEATURE_NOT_SUPPORTED,
        )
    for name in sorted(old_types.keys() & new_types.keys()):
        if old_types[name] != new_types[name]:
            raise DplError(
                f"при живых спеках тип атрибута {name!r} неизменен"
                f" ({old_types[name]} → {new_types[name]})",
                pos=command.code_pos,
                sqlstate=SqlState.FEATURE_NOT_SUPPORTED,
            )
    if old_types.keys() != new_types.keys():
        # TODO(mvp): ALTER пары таблиц каждой живой спеки (add/drop
        # неключевых колонок); каталожно правка разрешена (req 21)
        raise DplError(
            "изменение набора атрибутов при живых спеках ещё не"
            " реализовано",
            pos=command.code_pos,
            sqlstate=SqlState.FEATURE_NOT_SUPPORTED,
        )


def _view_columns(attrs) -> list[tuple[str, str]]:
    """Колонки вьюхи датасета — порядок спековой таблицы донора:
    ключевые атрибуты, служебные SCD2, неключевые атрибуты."""
    pk = [a for a in attrs if a.is_primary]
    non_pk = [a for a in attrs if not a.is_primary]
    return (
        [(a.name, a.type_code) for a in pk]
        + [("build_id", "bigint"),
           ("end_build_id", "bigint"),
           ("is_active", "boolean")]
        + [(a.name, a.type_code) for a in non_pk]
    )


async def _create_dataset_view(
    cur,
    dataset_code: str,
    attrs,
    spec_nums: list[int],
    descr: str | None,
    attr_descrs: dict[str, str | None] | None = None,
) -> None:
    """Вьюха датасета `схема.имя` — union all по основным таблицам живых
    спек, без параметров и фильтров.

    Вьюха отдаёт сырую историю «как есть» (включая недоехавшие билды):
    консистентные срезы обеспечиваются окнами дельт билдов, а
    потребительский as-of выражается по колонкам build_id/end_build_id;
    защитные вьюхи и права — следующие итерации. Без спек тело пустое
    (нуль строк правильных типов). Состав колонок при or replace
    датасета меняется, а create or replace view сузить или переставить
    колонки не умеет — поэтому drop + create; комментарии датасета и
    атрибутов накатываются заново.
    """
    columns = _view_columns(attrs)
    if spec_nums:
        names = "\n     , ".join(name for name, _ in columns)
        body = "\nunion all\n".join(
            f"select {names}\n  from {dataset_code}_{num}"
            for num in sorted(spec_nums)
        )
    else:
        nulls = "\n     , ".join(
            f"null::{type_code} as {name}" for name, type_code in columns
        )
        body = f"select {nulls}\n where false"
    await _drop_dataset_view(cur, dataset_code)
    await cur.execute(f"create view {dataset_code} as\n{body}")
    # чтение открыто временно, до ролевой модели (как таблицы спек)
    await cur.execute(f"grant select on {dataset_code} to public")
    if descr is not None:
        await _comment_dataset_view(cur, dataset_code, descr)
    for column, comment in _SYS_COLUMN_COMMENTS.items():
        await cur.execute(
            f"comment on column {dataset_code}.{column} is %s", (comment,)
        )
    for name, comment in (attr_descrs or {}).items():
        if comment is not None:
            await cur.execute(
                f"comment on column {dataset_code}.{name} is %s", (comment,)
            )


async def _drop_dataset_view(cur, dataset_code: str) -> None:
    await cur.execute(f"drop view if exists {dataset_code}")


async def _comment_dataset_view(
    cur, dataset_code: str, descr: str | None
) -> None:
    """Комментарий датасета дублируется на его вьюху (comment on view);
    комментарии атрибутов ложатся на её колонки."""
    await cur.execute(f"comment on view {dataset_code} is %s", (descr,))


async def _drop_dataset(cur, command: DropDataset, user_code: str, src: str) -> str:
    last_version, usage, dp_descr = await _lock_catalog(cur)
    current = await _require_live_dataset(
        cur, command.dataset_code, command.code_pos
    )
    own = await _live_spec_nums(cur, command.dataset_code)
    if own:
        raise DplError(
            "у датасета есть живые спеки: "
            + ", ".join(str(num) for num in own),
            pos=command.code_pos,
            hint="сначала drop build_spec",
            sqlstate=SqlState.DEPENDENT_OBJECTS,
        )
    readers = await _live_reader_specs(cur, command.dataset_code)
    if readers:
        specs = ", ".join(f"{ds}.{num}" for ds, num in readers)
        raise DplError(
            f"датасет читают живые спеки: {specs}",
            pos=command.code_pos,
            hint="сначала удалите или переведите спеки-читатели",
            sqlstate=SqlState.DEPENDENT_OBJECTS,
        )
    # tombstone-версия: копирует поля предыдущей версии (descr,
    # type_code), детей (атрибутов) не имеет
    version_id = last_version + 1
    await _insert_version(
        cur, version_id,
        user_code=user_code,
        command="drop dataset",
        src=src,
        usage=usage,
        descr=dp_descr,
    )
    await _insert_dataset(
        cur, version_id, command.dataset_code,
        type_code=current[3], is_deleted=True, descr=current[2],
    )
    await _drop_dataset_view(cur, command.dataset_code)
    return "DROP DATASET"


# --- спеки ------------------------------------------------------------------

_SPEC_OPTIONS = ("parallel", "chunk_attr")

# служебные колонки SCD2 основной таблицы спеки (по донору);
# end_build_id ИНКЛЮЗИВНЫЙ: последний билд, в котором версия строки
# ещё актуальна; NULL — версия открыта
_SYS_COLUMN_COMMENTS = {
    "build_id": "Билд, создавший эту версию строки",
    "end_build_id": (
        "Последний билд, в котором версия строки ещё актуальна —"
        " инклюзивно (NULL — версия открыта; SCD2)"
    ),
    "is_active": "Признак жизни строки (false — строка логически удалена)",
}


def _spec_table(dataset_code: str, num: int) -> str:
    return f"{dataset_code}_{num}"


def _iface_table(dataset_code: str, num: int) -> str:
    return f"{dataset_code}_{num}_$"


async def _current_spec(
    cur, dataset_code: str, num: int
) -> tuple[int, bool, str | None, int, str, str] | None:
    """Последняя версия спеки (version_id, is_deleted, descr,
    parallel_cnt, chunk_attr_code, body); None — версий не было."""
    await cur.execute(
        "select version_id, is_deleted, descr, parallel_cnt,"
        "       chunk_attr_code, body"
        " from datapulse.build_spec"
        " where dataset_code = %s and build_spec_num = %s"
        " order by version_id desc limit 1",
        (dataset_code, num),
    )
    return await cur.fetchone()


async def _live_spec_nums(cur, dataset_code: str) -> list[int]:
    """Номера живых спек датасета."""
    await cur.execute(
        "select distinct on (build_spec_num) build_spec_num, is_deleted"
        " from datapulse.build_spec where dataset_code = %s"
        " order by build_spec_num, version_id desc",
        (dataset_code,),
    )
    return [num for num, deleted in await cur.fetchall() if not deleted]


_CURRENT_SPECS_CTE = """
with current_spec as (
    select distinct on (dataset_code, build_spec_num) *
    from datapulse.build_spec
    order by dataset_code, build_spec_num, version_id desc
)
"""


async def _live_reader_specs(cur, dataset_code: str) -> list[tuple[str, int]]:
    """Живые чужие спеки-читатели датасета (RESTRICT в drop dataset)."""
    await cur.execute(
        _CURRENT_SPECS_CTE
        + "select s.dataset_code, s.build_spec_num"
        "  from current_spec s"
        "  join datapulse.build_spec_source src"
        "    on src.dataset_code = s.dataset_code"
        "   and src.build_spec_num = s.build_spec_num"
        "   and src.version_id = s.version_id"
        " where not s.is_deleted and src.source_dataset_code = %s"
        " order by s.dataset_code, s.build_spec_num",
        (dataset_code,),
    )
    return await cur.fetchall()


async def _live_spec_sources(cur) -> list[tuple[str, int, str]]:
    """Рёбра «датасет читает датасет» живых спек всего каталога:
    (dataset_code, build_spec_num, source_dataset_code)."""
    await cur.execute(
        _CURRENT_SPECS_CTE
        + "select s.dataset_code, s.build_spec_num, src.source_dataset_code"
        "  from current_spec s"
        "  join datapulse.build_spec_source src"
        "    on src.dataset_code = s.dataset_code"
        "   and src.build_spec_num = s.build_spec_num"
        "   and src.version_id = s.version_id"
        " where not s.is_deleted",
    )
    return await cur.fetchall()


async def _require_no_open_builds(
    cur, dataset_code: str, num: int, pos: int
) -> None:
    """DDL спеки при незавершённом билде запрещён: живой билд работает с
    её таблицами, неразобранный fail ждёт триажа (финалы — done и fix)."""
    await cur.execute(
        "select b.build_id, ls.status_code from datapulse.build b"
        " join lateral (select status_code from datapulse.build_log l"
        "                where l.build_id = b.build_id"
        "                order by l.build_log_id desc limit 1) ls on true"
        " where b.dataset_code = %s and b.build_spec_num = %s"
        "   and ls.status_code not in ('done', 'fix')"
        " order by b.build_id limit 1",
        (dataset_code, num),
    )
    row = await cur.fetchone()
    if row is not None:
        raise DplError(
            f"у спеки незавершённый билд {row[0]} ({row[1]})",
            pos=pos,
            hint=f"stop({row[0]}) остановит, fix({row[0]}) пометит"
            " разобранным",
            sqlstate=SqlState.OBJECT_NOT_IN_PREREQUISITE_STATE,
        )


async def _create_spec_tables(cur, dataset_code: str, num: int, attrs) -> None:
    """Пара таблиц спеки: основная SCD2 и интерфейсная `_$` (по донору).

    Основная: ключевые атрибуты NOT NULL, служебные
    build_id/end_build_id/is_active, неключевые NOT NULL; PK на таблице
    нет — уникальность версий строк обеспечивает движок. Интерфейсная:
    все колонки nullable — кривой выхлоп маппинга должен долететь и
    упасть позже, на переливе. Занятое имя — ошибка Postgres как есть.
    """
    main = _spec_table(dataset_code, num)
    iface = _iface_table(dataset_code, num)
    pk = [attr for attr in attrs if attr[3]]
    non_pk = [attr for attr in attrs if not attr[3]]
    main_cols = (
        [f"{attr[0]} {attr[2]} not null" for attr in pk]
        + ["build_id bigint not null",
           "end_build_id bigint",
           "is_active boolean not null"]
        + [f"{attr[0]} {attr[2]} not null" for attr in non_pk]
    )
    iface_cols = (
        [f"{attr[0]} {attr[2]}" for attr in pk]
        + ["is_active boolean"]
        + [f"{attr[0]} {attr[2]}" for attr in non_pk]
    )
    await cur.execute(f"create table {main} ({', '.join(main_cols)})")
    await cur.execute(f"create table {iface} ({', '.join(iface_cols)})")
    # чтение открыто временно, до ролевой модели (как у метаданных)
    await cur.execute(f"grant select on {main}, {iface} to public")
    for column, comment in _SYS_COLUMN_COMMENTS.items():
        await cur.execute(
            f"comment on column {main}.{column} is %s", (comment,)
        )
    await cur.execute(
        f"comment on column {iface}.is_active is %s",
        ("Признак жизни строки (false — логическое удаление);"
         " проставляет маппинг",),
    )
    for attr_code, _, _, _, descr in attrs:
        if descr is not None:
            await cur.execute(
                f"comment on column {main}.{attr_code} is %s", (descr,)
            )
            await cur.execute(
                f"comment on column {iface}.{attr_code} is %s", (descr,)
            )


async def _drop_spec_tables(cur, dataset_code: str, num: int) -> None:
    """Данные держатся актуальными: drop build_spec удаляет таблицы
    спеки физически (глубокий откат — только у метаданных)."""
    await cur.execute(
        f"drop table if exists {_spec_table(dataset_code, num)},"
        f" {_iface_table(dataset_code, num)}"
    )


async def _create_build_spec(
    cur, command: CreateBuildSpec, user_code: str, src: str
) -> str:
    parallel_cnt, chunk_attr = _check_spec_head(command)
    last_version, usage, dp_descr = await _lock_catalog(cur)
    dataset = await _require_live_dataset(
        cur, command.dataset_code, command.code_pos
    )
    dataset_type = dataset[3]
    _check_spec_modes(command, dataset_type)
    if dataset_type == "store" and command.using and command.sources:
        raise DplError(
            "USING и FROM взаимоисключающи у store-спеки: она — загрузчик"
            " либо трансформер",
            pos=command.code_pos,
            hint="оба сразу — только у витринной спеки (from — сторы,"
            " using — коннекты отгрузки)",
            sqlstate=SqlState.INVALID_PARAMETER_VALUE,
        )
    attrs = await _dataset_attrs(cur, command.dataset_code, dataset[0])
    pk = {attr[0] for attr in attrs if attr[3]}
    if chunk_attr.value.text not in pk:
        raise DplError(
            f"chunk_attr {chunk_attr.value.text!r} должен быть атрибутом"
            f" PRIMARY KEY датасета (ключ: {', '.join(sorted(pk))})",
            pos=chunk_attr.value.pos,
            sqlstate=SqlState.INVALID_PARAMETER_VALUE,
        )
    for named in command.using:
        connection = await _current_connection(cur, named.name)
        if connection is None or connection[0]:
            raise DplError(
                f"коннект {named.name!r} не существует",
                pos=named.pos,
                sqlstate=SqlState.UNDEFINED_OBJECT,
            )
    for named in command.sources:
        source = await _current_dataset(cur, named.name)
        if source is None or source[1]:
            raise DplError(
                f"датасет-источник {named.name!r} не существует",
                pos=named.pos,
                sqlstate=SqlState.UNDEFINED_OBJECT,
            )
        if source[3] == "mart":
            raise DplError(
                f"витрина {named.name!r} не может быть источником:"
                " у витрин нет зависимых спек",
                pos=named.pos,
                sqlstate=SqlState.INVALID_PARAMETER_VALUE,
            )
    await _check_source_cycle(cur, command)
    current = await _current_spec(
        cur, command.dataset_code, command.build_spec_num
    )
    alive = current is not None and not current[1]
    if alive and not command.or_replace:
        raise DplError(
            f"спека {command.dataset_code}.{command.build_spec_num}"
            " уже существует",
            pos=command.code_pos,
            hint="заменить — create or replace build_spec",
            sqlstate=SqlState.DUPLICATE_OBJECT,
        )
    if alive:
        await _require_no_open_builds(
            cur, command.dataset_code, command.build_spec_num,
            command.code_pos,
        )
    version_id = last_version + 1
    await _insert_version(
        cur, version_id,
        user_code=user_code,
        command="create or replace build_spec" if command.or_replace
        else "create build_spec",
        src=src,
        usage=usage,
        descr=dp_descr,
    )
    # бамп датасета той же версией: копия dataset + dataset_attr
    await _bump_dataset(cur, version_id, command.dataset_code, dataset, attrs)
    await cur.execute(
        "insert into datapulse.build_spec"
        " (version_id, dataset_code, build_spec_num, is_deleted, descr,"
        "  parallel_cnt, chunk_attr_code, body)"
        " values (%s, %s, %s, false, %s, %s, %s, %s)",
        (version_id, command.dataset_code, command.build_spec_num,
         current[2] if alive else None, parallel_cnt,
         chunk_attr.value.text, command.body),
    )
    await cur.executemany(
        "insert into datapulse.build_spec_mode"
        " (version_id, dataset_code, build_spec_num, mode_code, type_code)"
        " values (%s, %s, %s, %s, %s)",
        [
            (version_id, command.dataset_code, command.build_spec_num,
             mode.mode_code, mode.type_code)
            for mode in command.modes
        ],
    )
    if command.using:
        await cur.executemany(
            "insert into datapulse.build_spec_connection"
            " (version_id, dataset_code, build_spec_num, connection_code)"
            " values (%s, %s, %s, %s)",
            [
                (version_id, command.dataset_code, command.build_spec_num,
                 named.name)
                for named in command.using
            ],
        )
    if command.sources:
        await cur.executemany(
            "insert into datapulse.build_spec_source"
            " (version_id, dataset_code, build_spec_num,"
            "  source_dataset_code)"
            " values (%s, %s, %s, %s)",
            [
                (version_id, command.dataset_code, command.build_spec_num,
                 named.name)
                for named in command.sources
            ],
        )
    live = await _live_spec_nums(cur, command.dataset_code)
    if not alive:
        # новая спека (или поверх tombstone: её таблицы удалил drop)
        await _create_spec_tables(
            cur, command.dataset_code, command.build_spec_num, attrs
        )
    await _create_dataset_view(
        cur, command.dataset_code, _attrs_as_dataset(attrs), live,
        dataset[2], {attr[0]: attr[4] for attr in attrs},
    )
    return "CREATE BUILD_SPEC"


async def _drop_build_spec(
    cur, command: DropBuildSpec, user_code: str, src: str
) -> str:
    last_version, usage, dp_descr = await _lock_catalog(cur)
    current = await _current_spec(
        cur, command.dataset_code, command.build_spec_num
    )
    if current is None or current[1]:
        raise DplError(
            f"спека {command.dataset_code}.{command.build_spec_num}"
            " не существует",
            pos=command.code_pos,
            sqlstate=SqlState.UNDEFINED_OBJECT,
        )
    await _require_no_open_builds(
        cur, command.dataset_code, command.build_spec_num, command.code_pos
    )
    dataset = await _current_dataset(cur, command.dataset_code)
    attrs = await _dataset_attrs(cur, command.dataset_code, dataset[0])
    version_id = last_version + 1
    await _insert_version(
        cur, version_id,
        user_code=user_code,
        command="drop build_spec",
        src=src,
        usage=usage,
        descr=dp_descr,
    )
    # бамп датасета: набор его спек изменился (функция пересобирается)
    await _bump_dataset(cur, version_id, command.dataset_code, dataset, attrs)
    # tombstone спеки: копия полей без детей
    await cur.execute(
        "insert into datapulse.build_spec"
        " (version_id, dataset_code, build_spec_num, is_deleted, descr,"
        "  parallel_cnt, chunk_attr_code, body)"
        " values (%s, %s, %s, true, %s, %s, %s, %s)",
        (version_id, command.dataset_code, command.build_spec_num,
         current[2], current[3], current[4], current[5]),
    )
    # сначала вьюха без умирающей спеки (иначе drop таблиц упёрся бы в
    # зависимость), потом физика; последняя спека умерла — заглушка
    live = await _live_spec_nums(cur, command.dataset_code)
    await _create_dataset_view(
        cur, command.dataset_code, _attrs_as_dataset(attrs), live,
        dataset[2], {attr[0]: attr[4] for attr in attrs},
    )
    await _drop_spec_tables(
        cur, command.dataset_code, command.build_spec_num
    )
    return "DROP BUILD_SPEC"


def _attrs_as_dataset(attrs) -> list[DatasetAttr]:
    """Кортежи dataset_attr → DatasetAttr (для генераторов колонок)."""
    return [
        DatasetAttr(attr_code, type_code, is_primary)
        for attr_code, _, type_code, is_primary, _ in attrs
    ]


async def _bump_dataset(
    cur, version_id: int, dataset_code: str, dataset, attrs
) -> None:
    """Версия датасета бампится той же version_id, что и команда его
    спеки: копия dataset + dataset_attr (каждая версия самодостаточна)."""
    await _insert_dataset(
        cur, version_id, dataset_code,
        type_code=dataset[3], is_deleted=False, descr=dataset[2],
    )
    await _insert_dataset_attrs(cur, version_id, dataset_code, attrs)


def _check_spec_head(command: CreateBuildSpec):
    """Статика спеки: номер, длина физических имён, опции, режимы,
    using/from, тело. Возвращает (parallel_cnt, chunk_attr)."""
    if command.build_spec_num < 1:
        raise DplError(
            "номер спеки должен быть ≥ 1",
            pos=command.code_pos,
            sqlstate=SqlState.INVALID_PARAMETER_VALUE,
        )
    name = command.dataset_code.split(".", 1)[1]
    iface = f"{name}_{command.build_spec_num}_$"
    if len(iface) > 63:
        raise DplError(
            f"полное имя интерфейсной таблицы {iface} длиннее 63 символов"
            f" ({len(iface)})",
            pos=command.code_pos,
            sqlstate=SqlState.INVALID_PARAMETER_VALUE,
        )
    parallel_cnt = 1
    chunk_attr = None
    seen: set[str] = set()
    for option in command.options:
        if option.name not in _SPEC_OPTIONS:
            raise DplError(
                f"неизвестная опция {option.name!r}",
                pos=option.name_pos,
                hint="опции спеки: " + ", ".join(_SPEC_OPTIONS),
                sqlstate=SqlState.INVALID_PARAMETER_VALUE,
            )
        if option.name in seen:
            raise DplError(
                f"опция {option.name!r} задана дважды",
                pos=option.name_pos,
                sqlstate=SqlState.INVALID_PARAMETER_VALUE,
            )
        seen.add(option.name)
        if option.name == "parallel":
            if option.value.kind != "number" or int(option.value.text) < 1:
                raise DplError(
                    "parallel — целое число ≥ 1",
                    pos=option.value.pos,
                    sqlstate=SqlState.INVALID_PARAMETER_VALUE,
                )
            parallel_cnt = int(option.value.text)
        else:
            if option.value.kind != "ident":
                raise DplError(
                    "chunk_attr — имя атрибута без кавычек",
                    pos=option.value.pos,
                    sqlstate=SqlState.INVALID_PARAMETER_VALUE,
                )
            chunk_attr = option
    if chunk_attr is None:
        raise DplError(
            "опция chunk_attr обязательна: атрибут чанкования параллельного"
            " переноса, дефолта нет",
            pos=command.code_pos,
            hint="chunk_attr = <атрибут PRIMARY KEY>",
            sqlstate=SqlState.INVALID_PARAMETER_VALUE,
        )
    seen = set()
    for mode in command.modes:
        if mode.mode_code in seen:
            raise DplError(
                f"режим {mode.mode_code!r} объявлен дважды",
                pos=mode.mode_pos,
                sqlstate=SqlState.DUPLICATE_OBJECT,
            )
        seen.add(mode.mode_code)
    seen = set()
    for named in command.using:
        if named.name in seen:
            raise DplError(
                f"коннект {named.name!r} в using дважды",
                pos=named.pos,
                sqlstate=SqlState.DUPLICATE_OBJECT,
            )
        seen.add(named.name)
        if named.name == RESERVED_CONNECTION_CODE:
            raise DplError(
                "warehouse в using не объявляется — он неявный у каждой"
                " спеки",
                pos=named.pos,
                sqlstate=SqlState.INVALID_PARAMETER_VALUE,
            )
    seen = set()
    for named in command.sources:
        if named.name in seen:
            raise DplError(
                f"источник {named.name!r} в from дважды",
                pos=named.pos,
                sqlstate=SqlState.DUPLICATE_OBJECT,
            )
        seen.add(named.name)
        if named.name == command.dataset_code:
            raise DplError(
                "спека не может читать собственный датасет",
                pos=named.pos,
                sqlstate=SqlState.INVALID_PARAMETER_VALUE,
            )
    if not command.body.strip():
        raise DplError(
            "тело спеки пустое",
            pos=command.body_pos,
            sqlstate=SqlState.INVALID_PARAMETER_VALUE,
        )
    return parallel_cnt, chunk_attr


def _check_spec_modes(command: CreateBuildSpec, dataset_type: str) -> None:
    """Режимная дисциплина по подклассу датасета.

    Матрица типов переноса: store — init/incr/sect, mart — appd/init/skip.
    Зарезервированные имена (их запускает поток, и только они двигают
    окно дельты): initial — тип init; increment — incr|sect у store,
    appd у mart; skip — только витрины. Прочие имена — ручные режимы.
    Обязательность: store-спека несёт initial или increment (иначе
    потоку нечего запускать); витринная — skip (иначе кран «скипаем»
    не работает); витрина без initial/increment легальна — поток её
    не считает, запуски только ручные.
    """
    allowed = (
        STORE_TRANSFER_TYPES if dataset_type == "store"
        else MART_TRANSFER_TYPES
    )
    increment_types = ("incr", "sect") if dataset_type == "store" else ("appd",)
    names = {mode.mode_code for mode in command.modes}
    for mode in command.modes:
        if mode.type_code not in allowed:
            raise DplError(
                f"тип переноса {mode.type_code!r} недоступен"
                f" {dataset_type}-спеке",
                pos=mode.mode_pos,
                hint=f"типы {dataset_type}: {', '.join(allowed)}",
                sqlstate=SqlState.INVALID_PARAMETER_VALUE,
            )
        if mode.mode_code == "initial" and mode.type_code != "init":
            raise DplError(
                "режим initial обязан иметь тип init (полный пересчёт)",
                pos=mode.mode_pos,
                sqlstate=SqlState.INVALID_PARAMETER_VALUE,
            )
        if mode.mode_code == "increment" and mode.type_code not in increment_types:
            raise DplError(
                "режим increment обязан иметь тип "
                + " | ".join(increment_types),
                pos=mode.mode_pos,
                sqlstate=SqlState.INVALID_PARAMETER_VALUE,
            )
        if mode.mode_code == "skip" and mode.type_code != "skip":
            raise DplError(
                "имя skip занято поглотителем дельты (голое SKIP в списке"
                " режимов)",
                pos=mode.mode_pos,
                sqlstate=SqlState.INVALID_PARAMETER_VALUE,
            )
    if dataset_type == "store" and not names & {"initial", "increment"}:
        raise DplError(
            "store-спека обязана нести режим initial или increment —"
            " иначе потоку нечего запускать",
            pos=command.code_pos,
            sqlstate=SqlState.INVALID_PARAMETER_VALUE,
        )
    if dataset_type == "mart" and "skip" not in names:
        raise DplError(
            "витринная спека обязана нести режим skip: без него кран"
            " отгрузки «скипаем» не сможет сбросить накопленную дельту",
            pos=command.code_pos,
            hint="добавьте голое SKIP в список режимов",
            sqlstate=SqlState.INVALID_PARAMETER_VALUE,
        )


async def _check_source_cycle(cur, command: CreateBuildSpec) -> None:
    """Ацикличность графа «датасет читает датасет» (по донору): рёбра
    живых спек каталога, спека команды — с новыми источниками."""
    edges: dict[str, set[str]] = {}
    for ds, num, source in await _live_spec_sources(cur):
        if (ds, num) == (command.dataset_code, command.build_spec_num):
            continue
        edges.setdefault(ds, set()).add(source)
    for named in command.sources:
        edges.setdefault(command.dataset_code, set()).add(named.name)
    cycle = _find_cycle(edges)
    if cycle is not None:
        raise DplError(
            f"граф зависимостей датасетов зацикливается (через {cycle!r})",
            pos=command.code_pos,
            sqlstate=SqlState.INVALID_PARAMETER_VALUE,
        )


def _find_cycle(edges: dict[str, set[str]]) -> str | None:
    white, grey, black = 0, 1, 2
    color = {node: white for node in edges}

    def visit(node: str) -> str | None:
        color[node] = grey
        for peer in edges.get(node, ()):
            if peer not in color:
                continue
            if color[peer] == grey:
                return peer
            if color[peer] == white:
                found = visit(peer)
                if found:
                    return found
        color[node] = black
        return None

    for node in edges:
        if color[node] == white:
            found = visit(node)
            if found:
                return found
    return None


# --- comment on -------------------------------------------------------------


async def _comment_datapulse(
    cur, command: CommentOnDatapulse, user_code: str, src: str
) -> str:
    """Описание установки: новая версия каталога с новым descr
    (строки версий иммутабельны, правок на месте нет)."""
    last_version, usage, _ = await _lock_catalog(cur)
    await _insert_version(
        cur, last_version + 1,
        user_code=user_code,
        command="comment on datapulse",
        src=src,
        usage=usage,
        descr=command.comment,
    )
    return "COMMENT"


async def _comment_dataset(
    cur, command: CommentOnDataset, user_code: str, src: str
) -> str:
    """Комментарий датасета: новая версия датасета с копией атрибутов
    (включая их комментарии) и новым descr; функция не меняется."""
    last_version, usage, dp_descr = await _lock_catalog(cur)
    current = await _require_live_dataset(
        cur, command.dataset_code, command.code_pos
    )
    attrs = await _dataset_attrs(cur, command.dataset_code, current[0])
    version_id = last_version + 1
    await _insert_version(
        cur, version_id,
        user_code=user_code,
        command="comment on dataset",
        src=src,
        usage=usage,
        descr=dp_descr,
    )
    await _insert_dataset(
        cur, version_id, command.dataset_code,
        type_code=current[3], is_deleted=False, descr=command.comment,
    )
    await _insert_dataset_attrs(cur, version_id, command.dataset_code, attrs)
    await _comment_dataset_view(cur, command.dataset_code, command.comment)
    return "COMMENT"


async def _comment_attr(cur, command: CommentOnAttr, user_code: str, src: str) -> str:
    """Комментарий атрибута: новая версия датасета, descr целевого
    атрибута меняется, всё прочее копируется."""
    last_version, usage, dp_descr = await _lock_catalog(cur)
    current = await _require_live_dataset(
        cur, command.dataset_code, command.code_pos
    )
    attrs = await _dataset_attrs(cur, command.dataset_code, current[0])
    if command.attr_name not in {attr[0] for attr in attrs}:
        raise DplError(
            f"у датасета {command.dataset_code!r} нет атрибута"
            f" {command.attr_name!r}",
            pos=command.attr_pos,
            sqlstate=SqlState.UNDEFINED_OBJECT,
        )
    version_id = last_version + 1
    await _insert_version(
        cur, version_id,
        user_code=user_code,
        command="comment on attr",
        src=src,
        usage=usage,
        descr=dp_descr,
    )
    await _insert_dataset(
        cur, version_id, command.dataset_code,
        type_code=current[3], is_deleted=False, descr=current[2],
    )
    await _insert_dataset_attrs(
        cur, version_id, command.dataset_code,
        [
            (attr_code, order_num, type_code, is_primary,
             command.comment if attr_code == command.attr_name else descr)
            for attr_code, order_num, type_code, is_primary, descr in attrs
        ],
    )
    # комментарий дублируется на колонку вьюхи датасета и на колонки
    # таблиц живых спек
    await cur.execute(
        f"comment on column {command.dataset_code}.{command.attr_name} is %s",
        (command.comment,),
    )
    for num in await _live_spec_nums(cur, command.dataset_code):
        for table in (
            _spec_table(command.dataset_code, num),
            _iface_table(command.dataset_code, num),
        ):
            await cur.execute(
                f"comment on column {table}.{command.attr_name} is %s",
                (command.comment,),
            )
    return "COMMENT"


# --- коннекты ---------------------------------------------------------------


async def _current_connection(cur, name: str) -> tuple[bool, str, dict] | None:
    """Последняя версия коннекта (is_deleted, class_code, param_json);
    None — версий не было."""
    await cur.execute(
        "select is_deleted, class_code, param_json from datapulse.connection"
        " where connection_code = %s order by version_id desc limit 1",
        (name,),
    )
    return await cur.fetchone()


async def _live_connections(cur) -> list[tuple[str, str, dict]]:
    """Живые коннекты каталога: (connection_code, class_code, param_json)."""
    await cur.execute(
        "select distinct on (connection_code)"
        "       connection_code, is_deleted, class_code, param_json"
        " from datapulse.connection"
        " order by connection_code, version_id desc"
    )
    return [
        (code, class_code, params)
        for code, deleted, class_code, params in await cur.fetchall()
        if not deleted
    ]


def _decrypt_params(name: str, class_code: str, params: dict, config: Config) -> dict:
    """Открытые параметры коннекта: секретные поля расшифровываются."""
    plain = dict(params)
    for field in secret_fields(class_code):
        if field in plain:
            try:
                plain[field] = decrypt_value(plain[field], config.encryption_key)
            except SecretError as exc:
                raise DplError(
                    f"секрет поля {field!r} коннекта {name!r}: {exc}",
                    sqlstate=SqlState.OBJECT_NOT_IN_PREREQUISITE_STATE,
                ) from exc
    return plain


async def _create_connection(
    cur, command: CreateConnection, user_code: str, src: str, config: Config
) -> str:
    if command.name == RESERVED_CONNECTION_CODE:
        raise DplError(
            f"имя {RESERVED_CONNECTION_CODE!r} занято зарезервированным"
            " коннектом установки",
            pos=command.name_pos,
            sqlstate=SqlState.DUPLICATE_OBJECT,
            hint="warehouse — коннект на БД самой установки, его"
            " предоставляет платформа",
        )
    params = validate_params(command.class_code, command.fields)
    last_version, usage, dp_descr = await _lock_catalog(cur)
    current = await _current_connection(cur, command.name)
    alive = current is not None and not current[0]
    if alive and not command.or_replace:
        raise DplError(
            f"коннект {command.name!r} уже существует",
            pos=command.name_pos,
            sqlstate=SqlState.DUPLICATE_OBJECT,
            hint=f"заменить — create or replace {command.class_code}"
            " connection",
        )
    if alive and current[1] != command.class_code:
        raise DplError(
            f"коннект {command.name!r} — {current[1]}: смена класса через"
            " or replace запрещена",
            pos=command.name_pos,
            hint="миграция источника на другой класс — новый коннект под"
            " новым именем",
            sqlstate=SqlState.FEATURE_NOT_SUPPORTED,
        )
    encrypted = dict(params)
    for name in secret_fields(command.class_code):
        if name in encrypted:
            encrypted[name] = encrypt_value(
                str(encrypted[name]), config.encryption_key
            )
    version_id = last_version + 1
    await _insert_version(
        cur, version_id,
        user_code=user_code,
        command=(
            f"create or replace {command.class_code} connection"
            if command.or_replace
            else f"create {command.class_code} connection"
        ),
        src=src,
        usage=usage,
        descr=dp_descr,
    )
    await cur.execute(
        "insert into datapulse.connection"
        " (version_id, connection_code, is_deleted, class_code, param_json)"
        " values (%s, %s, false, %s, %s)",
        (version_id, command.name, command.class_code, json.dumps(encrypted)),
    )
    return "CREATE CONNECTION"


async def _test_connection(cur, command: TestConnection, config: Config) -> str:
    """Проверка коннекта: реальное подключение к целевой базе."""
    await _require_installed(cur)
    current = await _current_connection(cur, command.name)
    if current is None or current[0]:
        raise DplError(
            f"коннект {command.name!r} не существует",
            pos=command.name_pos,
            sqlstate=SqlState.UNDEFINED_OBJECT,
        )
    _, class_code, params = current
    plain = _decrypt_params(command.name, class_code, params, config)
    probe = (
        _probe_postgres if class_code == POSTGRES_CONNECTION else _probe_oracle
    )
    try:
        # общий таймаут: зависшая проба не должна держать сессию —
        # перехваченную команду CancelRequest клиента не отменяет
        async with asyncio.timeout(_PROBE_TIMEOUT):
            await probe(plain)
    except TimeoutError as exc:
        raise DplError(
            f"коннект {command.name!r} не прошёл проверку: нет ответа"
            f" за {_PROBE_TIMEOUT} с",
            pos=command.name_pos,
            sqlstate=SqlState.CONNECTION_FAILURE,
        ) from exc
    except Exception as exc:
        raise DplError(
            f"коннект {command.name!r} не прошёл проверку: {exc}",
            pos=command.name_pos,
            sqlstate=SqlState.CONNECTION_FAILURE,
        ) from exc
    return "TEST"


_PROBE_TIMEOUT = 30    # секунды на всю пробу test (коннект + select 1)


async def _probe_postgres(params: dict) -> None:
    conn = await psycopg.AsyncConnection.connect(
        host=params["host_name"],
        port=params["port_num"],
        dbname=params["database_name"],
        user=params["user_name"],
        password=params["password"],
        connect_timeout=10,
    )
    try:
        await conn.execute("select 1")
    finally:
        await conn.close()


async def _probe_oracle(params: dict) -> None:
    import oracledb  # ленивый импорт: нужен только команде test

    conn = await oracledb.connect_async(
        user=params["user_name"],
        password=params["password"],
        dsn=f"{params['host_name']}:{params['port_num']}"
        f"/{params['service_name']}",
        tcp_connect_timeout=10,
    )
    try:
        cur = conn.cursor()
        await cur.execute("select 1 from dual")
        await cur.fetchone()
    finally:
        await conn.close()


# --- flow_spec --------------------------------------------------------------


async def _current_flow_spec(
    cur, name: str
) -> tuple[bool, str | None, str] | None:
    """Последняя версия пресета (is_deleted, descr, body); None — версий
    не было."""
    await cur.execute(
        "select is_deleted, descr, body from datapulse.flow_spec"
        " where flow_spec_code = %s order by version_id desc limit 1",
        (name,),
    )
    return await cur.fetchone()


async def _create_flow_spec(
    cur, command: CreateFlowSpec, user_code: str, src: str
) -> str:
    """Пресет потока: тело — read-only SQL списка индивидуальных
    запусков; исполняется и валидируется при запуске потока."""
    if not command.body.strip():
        raise DplError(
            "тело пресета пустое",
            pos=command.body_pos,
            sqlstate=SqlState.INVALID_PARAMETER_VALUE,
        )
    last_version, usage, dp_descr = await _lock_catalog(cur)
    current = await _current_flow_spec(cur, command.name)
    alive = current is not None and not current[0]
    if alive and not command.or_replace:
        raise DplError(
            f"пресет {command.name!r} уже существует",
            pos=command.name_pos,
            sqlstate=SqlState.DUPLICATE_OBJECT,
            hint="заменить — create or replace flow_spec",
        )
    version_id = last_version + 1
    await _insert_version(
        cur, version_id,
        user_code=user_code,
        command="create or replace flow_spec" if command.or_replace
        else "create flow_spec",
        src=src,
        usage=usage,
        descr=dp_descr,
    )
    await cur.execute(
        "insert into datapulse.flow_spec"
        " (version_id, flow_spec_code, is_deleted, descr, body)"
        " values (%s, %s, false, %s, %s)",
        (version_id, command.name,
         current[1] if alive else None, command.body),
    )
    return "CREATE FLOW_SPEC"


async def _drop_flow_spec(
    cur, command: DropFlowSpec, user_code: str, src: str
) -> str:
    last_version, usage, dp_descr = await _lock_catalog(cur)
    current = await _current_flow_spec(cur, command.name)
    if current is None or current[0]:
        raise DplError(
            f"пресет {command.name!r} не существует",
            pos=command.name_pos,
            sqlstate=SqlState.UNDEFINED_OBJECT,
        )
    version_id = last_version + 1
    await _insert_version(
        cur, version_id,
        user_code=user_code,
        command="drop flow_spec",
        src=src,
        usage=usage,
        descr=dp_descr,
    )
    # tombstone: копия полей предыдущей версии
    await cur.execute(
        "insert into datapulse.flow_spec"
        " (version_id, flow_spec_code, is_deleted, descr, body)"
        " values (%s, %s, true, %s, %s)",
        (version_id, command.name, current[1], current[2]),
    )
    return "DROP FLOW_SPEC"


# --- python -----------------------------------------------------------------


async def _run_python(
    config: Config,
    database: str,
    command: PythonBlock,
    notify: NotifyFn | None,
    run: PythonRun | None,
) -> str:
    """Отладочный прогон инженерного кода в процессе-ребёнке.

    В globals тела — фабрики всех живых коннектов каталога и warehouse
    (коннект на БД установки под системной учёткой). Версию каталога не
    бампает, каталожный замок не берёт (долгий блок не должен запирать
    DDL). Печать стримится notify по мере выполнения; CancelRequest
    клиента убивает ребёнка (run.cancel)."""
    _check_python_syntax(command)
    async with await _connect(config, database) as conn:
        cur = conn.cursor()
        await _require_installed(cur)
        live = await _live_connections(cur)
    connections = {
        name: {
            "class_code": class_code,
            "params": _decrypt_params(name, class_code, params, config),
        }
        for name, class_code, params in live
    }
    connections[RESERVED_CONNECTION_CODE] = {
        "class_code": POSTGRES_CONNECTION,
        "params": {
            "host_name": config.pg_host,
            "port_num": config.pg_port,
            "database_name": database,
            "user_name": config.pg_user,
            "password": config.pg_password,
        },
    }
    payload = json.dumps({"body": command.body, "connections": connections})
    return_code = await _run_child(payload.encode("utf-8"), notify, run)
    if run is not None and run.cancelled:
        raise DplError(
            "python-блок отменён по требованию пользователя",
            sqlstate=SqlState.QUERY_CANCELED,
        )
    if return_code != 0:
        raise DplError(
            f"python-блок завершился с ошибкой (код {return_code});"
            " traceback — в печати выше",
            sqlstate=SqlState.EXTERNAL_ERROR,
        )
    return "PYTHON"


async def _run_child(
    payload: bytes, notify: NotifyFn | None, run: PythonRun | None
) -> int:
    """Процесс-ребёнок через Popen + поток-помпу: работает и на
    selector-цикле Windows (asyncio-сабпроцессы требуют Proactor,
    несовместимый с psycopg-async). Любая авария потребителя (разрыв
    клиента, снос сессии) убивает ребёнка."""
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[str | None] = asyncio.Queue()
    src_dir = str(Path(__file__).resolve().parent.parent)
    env = dict(os.environ)
    env["PYTHONPATH"] = (
        src_dir + os.pathsep + env["PYTHONPATH"]
        if env.get("PYTHONPATH")
        else src_dir
    )
    proc = subprocess.Popen(
        [sys.executable, "-m", "datapulse.runner"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
    )
    if run is not None:
        run.proc = proc
        if run.cancelled:   # CancelRequest успел раньше старта ребёнка
            proc.kill()

    def pump() -> int:
        try:
            proc.stdin.write(payload)
            proc.stdin.close()
            for raw in proc.stdout:
                line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                loop.call_soon_threadsafe(queue.put_nowait, line)
            return proc.wait()
        finally:
            loop.call_soon_threadsafe(queue.put_nowait, None)

    pump_future = loop.run_in_executor(None, pump)
    try:
        while (line := await queue.get()) is not None:
            if notify is not None:
                await notify(line)
        return await pump_future
    except BaseException:
        proc.kill()
        raise


def _check_python_syntax(command: PythonBlock) -> None:
    """Синтаксис Python проверяется на сервере до запуска (compile без
    исполнения); dedent — как в раннере. Позиция ошибки — глобальная в
    тексте запроса: body_pos + смещение строки/колонки внутри тела."""
    source = textwrap.dedent(command.body)
    try:
        compile(source, "<python>", "exec")
    except SyntaxError as exc:
        lineno = max(1, exc.lineno or 1)
        raw_lines = command.body.split("\n")
        pos = command.body_pos + sum(
            len(line) + 1 for line in raw_lines[: lineno - 1]
        )
        dedented_lines = source.split("\n")
        if lineno <= min(len(raw_lines), len(dedented_lines)):
            # dedent срезал общий отступ — вернуть его в колонку
            margin = len(raw_lines[lineno - 1]) - len(dedented_lines[lineno - 1])
            pos += max(0, margin) + max(0, (exc.offset or 1) - 1)
        raise DplError(
            f"синтаксическая ошибка Python: {exc.msg}",
            pos=pos,
            sqlstate=SqlState.SYNTAX_ERROR,
        ) from exc
