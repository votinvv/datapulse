"""E2E: прокси против живого Postgres.

Бэкенд берётся из PG_HOST / PG_PORT / PG_USER / PG_PASSWORD (без них
модуль скипается). Прокси поднимается в фоновом потоке на свободном
порту; служебная БД прогона создаётся и сносится мимо прокси.

Клиенты: psycopg с обычным курсором — extended-протокол,
с ClientCursor — simple-протокол (путь DPL). Тесты в файле
упорядочены: установка → ошибки → датасеты → снос.
"""

import asyncio
import os
import socket
import threading
import time

import pytest

psycopg = pytest.importorskip("psycopg")

from datapulse.config import Config
from datapulse.server import DataPulseServer

_REQUIRED = ("PG_HOST", "PG_USER", "PG_PASSWORD")
pytestmark = pytest.mark.skipif(
    not all(os.environ.get(name) for name in _REQUIRED),
    reason="нужен живой Postgres: PG_HOST, PG_USER, PG_PASSWORD (+PG_PORT)",
)

E2E_DB = "datapulse_e2e"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture(scope="module")
def config() -> Config:
    return Config(
        pg_host=os.environ["PG_HOST"],
        pg_port=int(os.environ.get("PG_PORT") or 5432),
        pg_user=os.environ["PG_USER"],
        pg_password=os.environ["PG_PASSWORD"],
        dp_port=_free_port(),
        encryption_key=os.urandom(32),
    )


@pytest.fixture(scope="module")
def database(config):
    """Служебная БД прогона — соединением мимо прокси."""

    def admin():
        return psycopg.connect(
            host=config.pg_host,
            port=config.pg_port,
            dbname="postgres",
            user=config.pg_user,
            password=config.pg_password,
            autocommit=True,
        )

    with admin() as conn:
        conn.execute(f"drop database if exists {E2E_DB} with (force)")
        conn.execute(f"create database {E2E_DB}")
    yield E2E_DB
    with admin() as conn:
        conn.execute(f"drop database if exists {E2E_DB} with (force)")


@pytest.fixture(scope="module")
def proxy(config):
    """Прокси в фоновом потоке со своим selector-циклом."""
    loop = asyncio.SelectorEventLoop()
    server = DataPulseServer(config)
    started = threading.Event()

    def run() -> None:
        asyncio.set_event_loop(loop)
        loop.run_until_complete(server.start())
        started.set()
        loop.run_forever()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    assert started.wait(10), "прокси не поднялся"
    yield config.dp_port
    asyncio.run_coroutine_threadsafe(server.stop(), loop).result(10)
    loop.call_soon_threadsafe(loop.stop)
    thread.join(10)


def _dataset_function(conn, schema, name):
    """(аргументы, результат) функции датасета либо None — функции нет."""
    row = conn.execute(
        "select pg_get_function_arguments(p.oid),"
        "       pg_get_function_result(p.oid)"
        "  from pg_proc p join pg_namespace n on n.oid = p.pronamespace"
        " where n.nspname = %s and p.proname = %s",
        (schema, name),
    ).fetchone()
    return row


def _connect(port, database, *, autocommit=True, simple=False, **kwargs):
    return psycopg.connect(
        host="127.0.0.1",
        port=port,
        dbname=database,
        user=os.environ["PG_USER"],
        password=os.environ["PG_PASSWORD"],
        autocommit=autocommit,
        cursor_factory=psycopg.ClientCursor if simple else None,
        **kwargs,
    )


# --- голый релей -----------------------------------------------------------


def test_relay_select(proxy, database):
    with _connect(proxy, database) as conn:
        assert conn.execute("select 1 + 1").fetchone() == (2,)
        row = conn.execute("select current_database(), current_user").fetchone()
        assert row == (database, os.environ["PG_USER"])


def test_relay_transaction_rollback(proxy, database):
    with _connect(proxy, database, autocommit=False) as conn:
        conn.execute("create table relay_t (n int)")
        conn.execute("insert into relay_t values (1)")
        conn.rollback()
        assert conn.execute("select to_regclass('relay_t')").fetchone() == (None,)


def test_relay_error_passthrough(proxy, database):
    with _connect(proxy, database) as conn:
        with pytest.raises(psycopg.errors.SyntaxError):
            conn.execute("селект 1")


def test_relay_copy_out(proxy, database):
    with _connect(proxy, database) as conn, conn.cursor() as cur:
        with cur.copy("copy (select generate_series(1, 5)) to stdout") as copy:
            rows = b"".join(copy)
    assert rows == b"1\n2\n3\n4\n5\n"


def test_relay_wrong_password(proxy, database):
    with pytest.raises(psycopg.OperationalError):
        psycopg.connect(
            host="127.0.0.1",
            port=proxy,
            dbname=database,
            user=os.environ["PG_USER"],
            password="заведомо-неверный",
            connect_timeout=10,
        )


# --- create datapulse ------------------------------------------------------


def test_dpl_syntax_error(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(psycopg.errors.SyntaxError, match="хотя бы одну"):
            conn.execute("create datapulse ()")


def test_create_collision_with_existing_schema(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        conn.execute("create schema busy_schema")
        with pytest.raises(
            psycopg.errors.DuplicateSchema, match="busy_schema"
        ):
            conn.execute("create datapulse (busy_schema)")
        conn.execute("drop schema busy_schema")


def test_create_datapulse(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        cur = conn.cursor()
        cur.execute("create datapulse (stg, ods)")
        assert cur.statusmessage == "CREATE DATAPULSE"
        names = conn.execute(
            "select nspname from pg_namespace"
            " where nspname in ('datapulse', 'stg', 'ods') order by nspname"
        ).fetchall()
        assert names == [("datapulse",), ("ods",), ("stg",)]
        version = conn.execute(
            "select version_id, user_code, usage from datapulse.version"
        ).fetchall()
        assert version == [(1, os.environ["PG_USER"], "stg,ods")]
        row = conn.execute(
            "select command, src from datapulse.version"
        ).fetchone()
        assert row == ("create datapulse", "create datapulse (stg, ods)")


def test_create_again_fails(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(
            psycopg.errors.DuplicateSchema, match="уже установлен"
        ):
            conn.execute("create datapulse (dm)")


def test_dpl_extended_rejected(proxy, database):
    # psycopg без параметров шлёт simple query; extended (Parse) —
    # только под prepare=True. JDBC/DataGrip шлют Parse всегда.
    with _connect(proxy, database) as conn:
        with pytest.raises(
            psycopg.errors.FeatureNotSupported, match="simple"
        ):
            conn.execute("drop datapulse", prepare=True)
        # сессия жива после ошибки
        assert conn.execute("select 1").fetchone() == (1,)


def test_dpl_in_transaction_rejected(proxy, database):
    with _connect(proxy, database, simple=True, autocommit=False) as conn:
        conn.execute("select 1")  # открывает транзакцию (psycopg шлёт begin)
        with pytest.raises(psycopg.errors.ActiveSqlTransaction):
            conn.execute("drop datapulse")
        conn.rollback()


# --- create [or replace] dataset -------------------------------------------


def test_create_dataset(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        cur = conn.cursor()
        cur.execute(
            "create dataset stg.dog ("
            " agreement_number text, open_date timestamp,"
            " amount numeric(18,2), primary key (agreement_number))"
        )
        assert cur.statusmessage == "CREATE DATASET"
        version = conn.execute(
            "select version_id, user_code, usage from datapulse.version"
            " order by version_id desc limit 1"
        ).fetchone()
        assert version == (2, os.environ["PG_USER"], "stg,ods")
        dataset = conn.execute(
            "select version_id, dataset_code, is_deleted, descr"
            " from datapulse.dataset"
        ).fetchall()
        assert dataset == [(2, "stg.dog", False, None)]
        attrs = conn.execute(
            "select attr_code, order_num, type_code, is_primary"
            " from datapulse.dataset_attr order by order_num"
        ).fetchall()
        assert attrs == [
            ("agreement_number", 1, "text", True),
            ("open_date", 2, "timestamp", False),
            ("amount", 3, "numeric(18,2)", False),
        ]
        # табличная функция датасета: пустая, но с полным составом колонок
        assert conn.execute("select * from stg.dog()").fetchall() == []
        assert conn.execute(
            "select * from stg.dog(build_id => 42)"
        ).fetchall() == []
        args, result = _dataset_function(conn, "stg", "dog")
        assert args == "build_id bigint DEFAULT NULL::bigint"
        # numeric(18,2) в returns table Postgres хранит как numeric —
        # модификаторы типов результата отбрасываются; точный тип в метаданных
        assert result == (
            "TABLE(agreement_number text, build_id bigint,"
            " end_build_id bigint, is_active boolean,"
            " open_date timestamp without time zone, amount numeric)"
        )


def test_create_dataset_duplicate(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(
            psycopg.errors.DuplicateObject, match="уже существует"
        ):
            conn.execute(
                "create dataset stg.dog (x text, primary key (x))"
            )


def test_create_or_replace_dataset(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        cur = conn.cursor()
        cur.execute(
            "create or replace dataset stg.dog ("
            " agreement_number text, descr text,"
            " primary key (agreement_number))"
        )
        assert cur.statusmessage == "CREATE DATASET"
        # новая версия датасета; прежняя остаётся в журнале
        versions = conn.execute(
            "select version_id from datapulse.dataset"
            " where dataset_code = 'stg.dog' order by version_id"
        ).fetchall()
        assert versions == [(2,), (3,)]
        attrs = conn.execute(
            "select attr_code, is_primary from datapulse.dataset_attr"
            " where version_id = 3 order by order_num"
        ).fetchall()
        assert attrs == [("agreement_number", True), ("descr", False)]
        # функция пересоздана под новый состав колонок
        _, result = _dataset_function(conn, "stg", "dog")
        assert "descr text" in result and "open_date" not in result
        command = conn.execute(
            "select command from datapulse.version"
            " order by version_id desc limit 1"
        ).fetchone()
        assert command == ("create or replace dataset",)


def test_create_dataset_undeclared_schema(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(
            psycopg.errors.InvalidSchemaName, match="не объявлена"
        ):
            conn.execute("create dataset dm.dog (x text, primary key (x))")


def test_create_dataset_syntax_error(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(
            psycopg.errors.SyntaxError, match="PRIMARY KEY обязателен"
        ):
            conn.execute("create dataset stg.cat (x text)")


# --- drop dataset ----------------------------------------------------------


def test_drop_dataset(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        cur = conn.cursor()
        cur.execute("drop dataset stg.dog")
        assert cur.statusmessage == "DROP DATASET"
        last = conn.execute(
            "select version_id, is_deleted from datapulse.dataset"
            " where dataset_code = 'stg.dog'"
            " order by version_id desc limit 1"
        ).fetchone()
        assert last == (4, True)
        # tombstone без атрибутов; функция датасета дропнута
        attrs = conn.execute(
            "select count(*) from datapulse.dataset_attr where version_id = 4"
        ).fetchone()
        assert attrs == (0,)
        assert _dataset_function(conn, "stg", "dog") is None


def test_drop_dataset_not_exists(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(
            psycopg.errors.UndefinedObject, match="не существует"
        ):
            conn.execute("drop dataset stg.nothing")
        # повторный drop только что удалённого — тоже «не существует»
        with pytest.raises(
            psycopg.errors.UndefinedObject, match="не существует"
        ):
            conn.execute("drop dataset stg.dog")


def test_recreate_dataset_after_drop(proxy, database):
    # поверх tombstone создание идёт без or replace
    with _connect(proxy, database, simple=True) as conn:
        cur = conn.cursor()
        cur.execute("create dataset stg.dog (x text, primary key (x))")
        assert cur.statusmessage == "CREATE DATASET"
        last = conn.execute(
            "select version_id, is_deleted from datapulse.dataset"
            " where dataset_code = 'stg.dog'"
            " order by version_id desc limit 1"
        ).fetchone()
        assert last == (5, False)
        assert _dataset_function(conn, "stg", "dog") is not None


# --- comment on ------------------------------------------------------------


def test_comment_on_datapulse(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        cur = conn.cursor()
        cur.execute("comment on datapulse is 'описание установки'")
        assert cur.statusmessage == "COMMENT"
        descr = conn.execute(
            "select descr from datapulse.version"
            " order by version_id desc limit 1"
        ).fetchone()
        assert descr == ("описание установки",)
        # описание версионируется вместе с каталогом: следующая
        # каталожная команда копирует его в свою версию
        cur.execute(
            "create or replace dataset stg.dog"
            " (x text, y integer, primary key (x))"
        )
        descr = conn.execute(
            "select descr from datapulse.version"
            " order by version_id desc limit 1"
        ).fetchone()
        assert descr == ("описание установки",)


def test_comment_on_attr(proxy, database):
    # состояние после test_comment_on_datapulse: stg.dog (x text pk, y integer)
    with _connect(proxy, database, simple=True) as conn:
        cur = conn.cursor()
        cur.execute("comment on attr stg.dog.y is 'счётчик'")
        assert cur.statusmessage == "COMMENT"
        row = conn.execute(
            "select command, src from datapulse.version"
            " order by version_id desc limit 1"
        ).fetchone()
        assert row == (
            "comment on attr", "comment on attr stg.dog.y is 'счётчик'"
        )
        assert _attr_descrs(conn) == [("x", None), ("y", "счётчик")]
        # комментарий атрибута переживает or replace: сопоставление по имени
        cur.execute(
            "create or replace dataset stg.dog"
            " (x text, y integer, primary key (x))"
        )
        assert _attr_descrs(conn) == [("x", None), ("y", "счётчик")]
        with pytest.raises(
            psycopg.errors.UndefinedObject, match="нет атрибута"
        ):
            conn.execute("comment on attr stg.dog.zzz is 'нет такого'")


def _attr_descrs(conn):
    """(attr_code, descr) атрибутов текущей версии stg.dog."""
    return conn.execute(
        "select attr_code, descr from datapulse.dataset_attr"
        " where dataset_code = 'stg.dog'"
        "   and version_id = (select max(version_id)"
        "                       from datapulse.dataset"
        "                      where dataset_code = 'stg.dog')"
        " order by order_num"
    ).fetchall()


def test_comment_on_dataset(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        cur = conn.cursor()
        cur.execute("comment on dataset stg.dog is 'основной датасет'")
        assert cur.statusmessage == "COMMENT"
        last = conn.execute(
            "select is_deleted, descr from datapulse.dataset"
            " where dataset_code = 'stg.dog'"
            " order by version_id desc limit 1"
        ).fetchone()
        assert last == (False, "основной датасет")
        # атрибуты скопированы в новую версию (с их комментариями),
        # функция жива
        attrs = conn.execute(
            "select attr_code, type_code, is_primary, descr"
            "  from datapulse.dataset_attr a"
            " where dataset_code = 'stg.dog'"
            "   and version_id = (select max(version_id)"
            "                       from datapulse.dataset"
            "                      where dataset_code = 'stg.dog')"
            " order by order_num"
        ).fetchall()
        assert attrs == [
            ("x", "text", True, None),
            ("y", "integer", False, "счётчик"),
        ]
        # комментарий продублирован на функцию датасета
        assert conn.execute(
            "select obj_description('stg.dog(bigint)'::regprocedure)"
        ).fetchone() == ("основной датасет",)
        assert conn.execute("select * from stg.dog()").fetchall() == []
        # комментарий переживает or replace (семантика Postgres) —
        # и в метаданных, и на пересозданной функции
        cur.execute("create or replace dataset stg.dog (x text, primary key (x))")
        last = conn.execute(
            "select descr from datapulse.dataset"
            " where dataset_code = 'stg.dog'"
            " order by version_id desc limit 1"
        ).fetchone()
        assert last == ("основной датасет",)
        assert conn.execute(
            "select obj_description('stg.dog(bigint)'::regprocedure)"
        ).fetchone() == ("основной датасет",)
        # tombstone копирует descr; is null снимает комментарий
        cur.execute("drop dataset stg.dog")
        last = conn.execute(
            "select is_deleted, descr from datapulse.dataset"
            " where dataset_code = 'stg.dog'"
            " order by version_id desc limit 1"
        ).fetchone()
        assert last == (True, "основной датасет")


def test_comment_on_dataset_not_exists(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(
            psycopg.errors.UndefinedObject, match="не существует"
        ):
            conn.execute("comment on dataset stg.dog is 'мёртв'")


def test_comment_on_table_relayed(proxy, database):
    # comment on table — не DPL, уходит релеем в Postgres
    with _connect(proxy, database) as conn:
        conn.execute("create table cmt (n int)")
        conn.execute("comment on table cmt is 'обычная таблица'")
        descr = conn.execute(
            "select obj_description('cmt'::regclass)"
        ).fetchone()
        assert descr == ("обычная таблица",)
        conn.execute("drop table cmt")


# --- create *_connection / test --------------------------------------------


def test_create_postgres_connection(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        cur = conn.cursor()
        cur.execute(
            "create postgres_connection wh with ("
            f" host_name = '{os.environ['PG_HOST']}',"
            f" port_num = {int(os.environ.get('PG_PORT') or 5432)},"
            f" database_name = '{database}',"
            f" user_name = '{os.environ['PG_USER']}',"
            f" password = '{os.environ['PG_PASSWORD']}')"
        )
        assert cur.statusmessage == "CREATE POSTGRES_CONNECTION"
        row = conn.execute(
            "select is_deleted, class_code, param_json"
            " from datapulse.connection order by version_id desc limit 1"
        ).fetchone()
        assert (row[0], row[1]) == (False, "postgres_connection")
        params = row[2]
        assert params["host_name"] == os.environ["PG_HOST"]
        assert set(params["password"].keys()) == {"enc"}  # секрет зашифрован
        command = conn.execute(
            "select command from datapulse.version"
            " order by version_id desc limit 1"
        ).fetchone()
        assert command == ("create postgres_connection",)


def test_test_postgres_connection(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        cur = conn.cursor()
        cur.execute("test wh")
        assert cur.statusmessage == "TEST"


def test_create_connection_duplicate(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(
            psycopg.errors.DuplicateObject, match="уже существует"
        ):
            conn.execute(
                "create postgres_connection wh with (host_name = 'h',"
                " port_num = 5432, database_name = 'd', user_name = 'u',"
                " password = 'p')"
            )


def test_test_connection_wrong_password(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        conn.execute(
            "create postgres_connection bad with ("
            f" host_name = '{os.environ['PG_HOST']}',"
            f" port_num = {int(os.environ.get('PG_PORT') or 5432)},"
            f" database_name = '{database}',"
            f" user_name = '{os.environ['PG_USER']}',"
            " password = 'заведомо-неверный')"
        )
        with pytest.raises(
            psycopg.errors.SqlclientUnableToEstablishSqlconnection,
            match="не прошёл проверку",
        ):
            conn.execute("test bad")


def test_oracle_connection_probe_fails(proxy, database):
    # оракла в прогоне нет: коннект пишется, проверка честно падает
    with _connect(proxy, database, simple=True) as conn:
        cur = conn.cursor()
        cur.execute(
            "create oracle_connection ora with (host_name = '127.0.0.1',"
            " port_num = 1, service_name = 'X', user_name = 'u',"
            " password = 'p')"
        )
        assert cur.statusmessage == "CREATE ORACLE_CONNECTION"
        with pytest.raises(
            psycopg.errors.SqlclientUnableToEstablishSqlconnection,
            match="не прошёл проверку",
        ):
            conn.execute("test ora")


def test_test_connection_not_exists(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(
            psycopg.errors.UndefinedObject, match="не существует"
        ):
            conn.execute("test nothing")


def test_connection_field_validation(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(
            psycopg.errors.InvalidParameterValue, match="обязательное поле"
        ):
            conn.execute(
                "create postgres_connection bad2 with (host_name = 'h')"
            )


def test_connection_warehouse_reserved(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(
            psycopg.errors.DuplicateObject, match="зарезервированным"
        ):
            conn.execute(
                "create postgres_connection warehouse with ("
                " host_name = 'h', port_num = 5432, database_name = 'd',"
                " user_name = 'u', password = 'p')"
            )


# --- python ----------------------------------------------------------------


def _collect_notices(conn):
    """Хендлер печати python-блока: NoticeResponse → список строк."""
    notices = []
    conn.add_notice_handler(lambda diag: notices.append(diag.message_primary))
    return notices


def test_python_print_streams_notices(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        notices = _collect_notices(conn)
        cur = conn.cursor()
        cur.execute("python $$\nprint('привет')\nprint(1 + 1)\n$$")
        assert cur.statusmessage == "PYTHON"
        assert notices == ["привет", "2"]


def test_python_single_line_body(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        notices = _collect_notices(conn)
        conn.execute("python $$ print('ok') $$")
        assert notices == ["ok"]


def test_python_warehouse_connection(proxy, database):
    # warehouse() — коннект на БД установки под системной учёткой
    body = (
        "python $$\n"
        "with warehouse() as w:\n"
        "    print(w.execute('select current_database()').fetchone()[0])\n"
        "$$"
    )
    with _connect(proxy, database, simple=True) as conn:
        notices = _collect_notices(conn)
        conn.execute(body)
        assert notices == [database]


def test_python_named_connection(proxy, database):
    # именованный коннект каталога (wh создан выше) — с расшифровкой секрета
    body = (
        "python $$\n"
        "with wh() as c:\n"
        "    print(c.execute('select 17').fetchone()[0])\n"
        "$$"
    )
    with _connect(proxy, database, simple=True) as conn:
        notices = _collect_notices(conn)
        conn.execute(body)
        assert notices == ["17"]


def test_python_runtime_error(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        notices = _collect_notices(conn)
        with pytest.raises(
            psycopg.errors.ExternalRoutineException,
            match="traceback — в печати выше",
        ):
            conn.execute("python $$\nprint('до')\nraise RuntimeError('бум')\n$$")
        assert "до" in notices
        assert any("бум" in line for line in notices)
        # сессия жива после ошибки
        assert conn.execute("select 1").fetchone() == (1,)


def test_python_syntax_error_with_position(proxy, database):
    query = "python $$\nx = 1\ny = )\n$$"
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(
            psycopg.errors.SyntaxError, match="синтаксическая ошибка Python"
        ) as exc_info:
            conn.execute(query)
        position = int(exc_info.value.diag.statement_position)
        assert query[position - 1] == ")"   # позиция 1-based


def test_python_cancel_kills_child(proxy, database):
    import threading as _threading

    with _connect(proxy, database, simple=True) as conn:
        started = _threading.Event()
        conn.add_notice_handler(lambda diag: started.set())
        result = {}

        def run():
            try:
                conn.execute(
                    "python $$\nimport time\nprint('старт')\ntime.sleep(60)\n$$"
                )
            except psycopg.Error as exc:
                result["sqlstate"] = exc.sqlstate

        thread = _threading.Thread(target=run)
        thread.start()
        assert started.wait(30), "python-блок не стартовал"
        # именно cancel_safe: классический conn.cancel() (PQcancel) в
        # psycopg-binary не отпускает GIL — а прокси в тестах живёт в том
        # же интерпретаторе и не смог бы ответить (дедлок только теста)
        conn.cancel_safe()
        thread.join(30)
        assert not thread.is_alive(), "отмена не сработала — блок висит"
        assert result["sqlstate"] == "57014"
        assert conn.execute("select 1").fetchone() == (1,)


def test_python_in_transaction_rejected(proxy, database):
    with _connect(proxy, database, simple=True, autocommit=False) as conn:
        conn.execute("select 1")
        with pytest.raises(psycopg.errors.ActiveSqlTransaction):
            conn.execute("python $$ print(1) $$")
        conn.rollback()


def test_do_block_relayed(proxy, database):
    # анонимный блок Postgres не затеняется командой python
    with _connect(proxy, database, simple=True) as conn:
        cur = conn.cursor()
        cur.execute("do $$ begin null; end $$")
        assert cur.statusmessage == "DO"


# --- alter datapulse -------------------------------------------------------


def test_alter_datapulse_add(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        cur = conn.cursor()
        cur.execute("alter datapulse add mart")
        assert cur.statusmessage == "ALTER DATAPULSE"
        row = conn.execute(
            "select command, usage from datapulse.version"
            " order by version_id desc limit 1"
        ).fetchone()
        assert row == ("alter datapulse add", "stg,ods,mart")
        assert conn.execute(
            "select 1 from pg_namespace where nspname = 'mart'"
        ).fetchone() == (1,)
        # новая схема сразу пригодна для датасетов
        cur.execute("create dataset mart.cat (x text, primary key (x))")
        assert cur.statusmessage == "CREATE DATASET"


def test_alter_datapulse_add_declared(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(
            psycopg.errors.DuplicateSchema, match="уже объявлена"
        ):
            conn.execute("alter datapulse add stg")


def test_alter_datapulse_add_busy(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        conn.execute("create schema busy_alter")
        with pytest.raises(
            psycopg.errors.DuplicateSchema, match="уже существует в БД"
        ):
            conn.execute("alter datapulse add busy_alter")
        conn.execute("drop schema busy_alter")


# --- create [or replace] / drop build_spec ----------------------------------
# состояние: mart.cat жив (x text pk), stg.dog — tombstone, коннект wh жив


def _column_comment(conn, table, column):
    return conn.execute(
        "select col_description(%s::regclass,"
        " (select attnum from pg_attribute"
        "   where attrelid = %s::regclass and attname = %s))",
        (table, table, column),
    ).fetchone()[0]


def test_create_build_spec(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        cur = conn.cursor()
        cur.execute(
            "create build_spec mart.cat.1 ("
            "  clear init mode initial"
            ", dirty incr mode manual"
            ") with (parallel = 4, chunk_attr = x)"
            "  using wh"
            "  as python $$ print('привет') $$"
        )
        assert cur.statusmessage == "CREATE BUILD_SPEC"
        spec = conn.execute(
            "select is_deleted, parallel_cnt, chunk_attr_code, body"
            " from datapulse.build_spec"
            " where dataset_code = 'mart.cat' and build_spec_num = 1"
            " order by version_id desc limit 1"
        ).fetchone()
        assert spec == (False, 4, "x", " print('привет') ")
        modes = conn.execute(
            "select mode_code, type_code, is_clear"
            " from datapulse.build_spec_mode"
            " where dataset_code = 'mart.cat'"
            "   and version_id = (select max(version_id)"
            "                       from datapulse.build_spec)"
            " order by mode_code"
        ).fetchall()
        assert modes == [("initial", "init", True), ("manual", "incr", False)]
        used = conn.execute(
            "select connection_code from datapulse.build_spec_connection"
            " order by version_id desc limit 1"
        ).fetchone()
        assert used == ("wh",)
        # версия датасета бампнута той же version_id, что и спека
        bump = conn.execute(
            "select (select max(version_id) from datapulse.dataset"
            "         where dataset_code = 'mart.cat')"
            "     = (select max(version_id) from datapulse.build_spec)"
        ).fetchone()
        assert bump == (True,)
        # пара таблиц спеки: основная строгая, интерфейсная вся nullable
        main = conn.execute(
            "select column_name, is_nullable from information_schema.columns"
            " where table_schema = 'mart' and table_name = 'cat_1'"
            " order by ordinal_position"
        ).fetchall()
        assert main == [
            ("x", "NO"), ("build_id", "NO"), ("end_build_id", "YES"),
            ("is_active", "NO"),
        ]
        iface = conn.execute(
            "select column_name, is_nullable from information_schema.columns"
            " where table_schema = 'mart' and table_name = 'cat_1_$'"
            " order by ordinal_position"
        ).fetchall()
        assert iface == [("x", "YES"), ("is_active", "YES")]
        assert "Билд, создавший" in _column_comment(
            conn, "mart.cat_1", "build_id"
        )


def test_dataset_function_over_spec(proxy, database):
    with _connect(proxy, database) as conn:
        # строки напрямую в основную таблицу (мимо движка, он ещё не жив):
        # открытая версия с билда 5 и версия, закрытая билдом 4
        conn.execute(
            "insert into mart.cat_1 (x, build_id, end_build_id, is_active)"
            " values ('a', 5, null, true), ('b', 3, 4, true)"
        )
        assert conn.execute(
            "select x from mart.cat() order by x"
        ).fetchall() == [("a",), ("b",)]
        # срез на билд 5: открытая версия видна, закрытая билдом 4 — нет
        assert conn.execute(
            "select x from mart.cat(build_id => 5)"
        ).fetchall() == [("a",)]
        # срез на билд 3: наоборот
        assert conn.execute(
            "select x from mart.cat(build_id => 3)"
        ).fetchall() == [("b",)]


def test_create_build_spec_duplicate(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(
            psycopg.errors.DuplicateObject, match="уже существует"
        ):
            conn.execute(
                "create build_spec mart.cat.1 (clear init mode m)"
                " with (chunk_attr = x) as python $$x$$"
            )


def test_create_or_replace_build_spec(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        cur = conn.cursor()
        cur.execute(
            "create or replace build_spec mart.cat.1 (clear init mode m)"
            " with (parallel = 8, chunk_attr = x) using wh as python $$новое тело$$"
        )
        assert cur.statusmessage == "CREATE BUILD_SPEC"
        spec = conn.execute(
            "select parallel_cnt, body from datapulse.build_spec"
            " where dataset_code = 'mart.cat' and build_spec_num = 1"
            " order by version_id desc limit 1"
        ).fetchone()
        assert spec == (8, "новое тело")
        # or replace живой спеки не трогает таблицы — данные живут
        rows = conn.execute("select count(*) from mart.cat_1").fetchone()
        assert rows == (2,)


@pytest.mark.parametrize(
    "query, error, fragment",
    [
        ("create build_spec mart.cat.2 (clear init mode m)"
         " with (chunk_attr = zzz) as python $$x$$",
         "InvalidParameterValue", "PRIMARY KEY датасета"),
        ("create build_spec mart.cat.2 (clear init mode m)"
         " with (chunk_attr = x) using nothing as python $$x$$",
         "UndefinedObject", "не существует"),
        ("create build_spec mart.cat.2 (clear init mode m)"
         " with (chunk_attr = x) using warehouse as python $$x$$",
         "InvalidParameterValue", "неявный"),
        ("create build_spec stg.dog.1 (clear init mode m)"
         " with (chunk_attr = x) as python $$x$$",
         "UndefinedObject", "не существует"),
        ("create build_spec mart.cat.2 (clear init mode m)"
         " with (parallel = 0, chunk_attr = x) as python $$x$$",
         "InvalidParameterValue", "≥ 1"),
        ("create build_spec mart.cat.2 (clear init mode m)"
         " with (parallel = 4) as python $$x$$",
         "InvalidParameterValue", "chunk_attr обязательна"),
        ("create build_spec mart.cat.2 (clear init mode m)"
         " with (chunk_attr = x) as python $$   $$",
         "InvalidParameterValue", "тело спеки пустое"),
        ("create build_spec mart.cat.2 (clear init mode m)"
         " with (chunk_attr = x) from mart.cat as python $$x$$",
         "InvalidParameterValue", "собственный датасет"),
    ],
)
def test_build_spec_validation(proxy, database, query, error, fragment):
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(getattr(psycopg.errors, error), match=fragment):
            conn.execute(query)


def test_build_spec_from_and_cycle(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        conn.execute("create dataset mart.pup (y text, primary key (y))")
        conn.execute(
            "create build_spec mart.pup.1 (dirty incr mode m)"
            " with (chunk_attr = y) from mart.cat as python $$transform$$"
        )
        source = conn.execute(
            "select source_dataset_code from datapulse.build_spec_source"
            " order by version_id desc limit 1"
        ).fetchone()
        assert source == ("mart.cat",)
        # цикл: cat читал бы pup, pup читает cat
        with pytest.raises(
            psycopg.errors.InvalidParameterValue, match="зацикливается"
        ):
            conn.execute(
                "create or replace build_spec mart.cat.1"
                " (clear init mode m) with (chunk_attr = x)"
                " from mart.pup as python $$x$$"
            )


def test_comment_on_attr_spec_columns(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        conn.execute("comment on attr mart.cat.x is 'ключик'")
        assert _column_comment(conn, "mart.cat_1", "x") == "ключик"
        assert _column_comment(conn, "mart.cat_1_$", "x") == "ключик"


def test_drop_dataset_restrict_own_specs(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(
            psycopg.errors.DependentObjectsStillExist, match="живые спеки: 1"
        ):
            conn.execute("drop dataset mart.cat")


def test_drop_build_spec(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        cur = conn.cursor()
        cur.execute("drop build_spec mart.cat.1")
        assert cur.statusmessage == "DROP BUILD_SPEC"
        spec = conn.execute(
            "select is_deleted, parallel_cnt, body from datapulse.build_spec"
            " where dataset_code = 'mart.cat' and build_spec_num = 1"
            " order by version_id desc limit 1"
        ).fetchone()
        assert spec == (True, 8, "новое тело")   # tombstone копирует поля
        # данные держатся актуальными: таблицы спеки удалены физически
        gone = conn.execute(
            "select to_regclass('mart.cat_1'), to_regclass('mart.cat_1_$')"
        ).fetchone()
        assert gone == (None, None)
        # последняя спека умерла — функция откатилась на заглушку
        assert conn.execute("select * from mart.cat()").fetchall() == []


def test_drop_dataset_restrict_readers(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(
            psycopg.errors.DependentObjectsStillExist,
            match="читают живые спеки: mart.pup.1",
        ):
            conn.execute("drop dataset mart.cat")


def test_recreate_build_spec_after_drop(proxy, database):
    # поверх tombstone создание идёт без or replace; таблицы — заново
    with _connect(proxy, database, simple=True) as conn:
        cur = conn.cursor()
        cur.execute(
            "create build_spec mart.cat.1 (clear init mode m)"
            " with (chunk_attr = x) using wh as python $$заново$$"
        )
        assert cur.statusmessage == "CREATE BUILD_SPEC"
        rows = conn.execute("select count(*) from mart.cat_1").fetchone()
        assert rows == (0,)
        assert conn.execute("select * from mart.cat()").fetchall() == []


def test_dataset_structure_frozen_with_live_specs(proxy, database):
    # у mart.cat живая спека 1: PK и типы неизменны, набор — 0A000
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(
            psycopg.errors.FeatureNotSupported, match="PRIMARY KEY неизменен"
        ):
            conn.execute(
                "create or replace dataset mart.cat"
                " (x text, z text, primary key (x, z))"
            )
        with pytest.raises(
            psycopg.errors.FeatureNotSupported, match="тип атрибута 'x'"
        ):
            conn.execute(
                "create or replace dataset mart.cat"
                " (x integer, primary key (x))"
            )
        with pytest.raises(
            psycopg.errors.FeatureNotSupported, match="ещё не реализовано"
        ):
            conn.execute(
                "create or replace dataset mart.cat"
                " (x text, y integer, primary key (x))"
            )
        # без изменений структуры or replace разрешён — просто новая версия
        cur = conn.cursor()
        cur.execute("create or replace dataset mart.cat (x text, primary key (x))")
        assert cur.statusmessage == "CREATE DATASET"
        assert conn.execute("select * from mart.cat()").fetchall() == []


# --- билды ------------------------------------------------------------------


def _last_build_status(conn, build_id):
    row = conn.execute(
        "select status_code from datapulse.build_log where build_id = %s"
        " order by build_log_id desc limit 1",
        (build_id,),
    ).fetchone()
    return row[0] if row else None


def _wait_status(conn, build_id, statuses, timeout=90):
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = _last_build_status(conn, build_id)
        if status in statuses:
            return status
        time.sleep(0.2)
    raise AssertionError(
        f"билд {build_id} не дошёл до {statuses} за {timeout} с;"
        f" журнал: {_journal_rows(conn, build_id)}"
    )


def _wait_final(conn, build_id, timeout=90):
    return _wait_status(conn, build_id, ("done", "fail", "fix"), timeout)


def _journal_rows(conn, build_id):
    return conn.execute(
        "select status_code, message, prepared_row_cnt, inserted_row_cnt,"
        "       updated_row_cnt, deleted_row_cnt"
        " from datapulse.build_log where build_id = %s order by build_log_id",
        (build_id,),
    ).fetchall()


def _launch(conn, statement):
    """build(...) через прокси: (build_id, command tag)."""
    cur = conn.cursor()
    cur.execute(statement)
    row = cur.fetchone()
    return row[0], cur.statusmessage


def _wait_role_gone(conn, build_id, timeout=30):
    """Дочистка временной учётки — в finally супервизора, ПОСЛЕ финальной
    строки журнала: мгновенной гарантии нет, опрашиваем."""
    role = f"dp_build_{build_id}"
    deadline = time.time() + timeout
    while time.time() < deadline:
        row = conn.execute(
            "select count(*) from pg_roles where rolname = %s", (role,)
        ).fetchone()
        if row == (0,):
            return
        time.sleep(0.2)
    raise AssertionError(f"учётка {role} не удалена за {timeout} с")


def test_build_dataset_and_spec(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        conn.execute(
            "create table public.deal_src"
            " (num text, val integer, is_active boolean)"
        )
        conn.execute("grant select on public.deal_src to public")
        conn.execute(
            "create dataset mart.deal (num text, val integer,"
            " primary key (num))"
        )
        conn.execute(
            "create build_spec mart.deal.1 ("
            "  clear init mode ini"
            ", dirty incr mode inc"
            ", dirty appd mode app"
            ", clear skip mode skp"
            ") with (parallel = 2, chunk_attr = num) as python $$\n"
            "print('режим', mode_code, from_build_id, to_build_id)\n"
            "with warehouse() as c:\n"
            "    c.cursor().execute("
            "\"insert into mart.deal_1_$ (num, val, is_active)"
            " select num, val, is_active from public.deal_src\")\n"
            "$$"
        )


def test_build_init(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        conn.execute(
            "insert into public.deal_src values"
            " ('n1', 1, true), ('n2', 2, true), ('n3', 3, true)"
        )
        build_id, tag = _launch(conn, "build('mart.deal', 1, 'ini')")
        assert tag == "BUILD"
        assert _wait_final(conn, build_id) == "done"
        journal = _journal_rows(conn, build_id)
        statuses = [row[0] for row in journal]
        assert statuses[0] == "wait" and statuses[-1] == "done"
        assert "load" in statuses and "comp" in statuses
        # печать тела — в журнале со статусом load; параметры инъецированы
        prints = [row[1] for row in journal if row[0] == "load" and row[1]]
        assert any(f"режим ini 0 {build_id}" in p for p in prints)
        comp = next(row for row in journal if row[0] == "comp")
        assert comp[2] == 3    # prepared_row_cnt
        assert journal[-1][3:6] == (3, 0, 0)
        build = conn.execute(
            "select mode_code, is_clear, user_code, source_build_id"
            " from datapulse.build where build_id = %s",
            (build_id,),
        ).fetchone()
        # генератор: срез источников — собственный id
        assert build == ("ini", True, os.environ["PG_USER"], build_id)
        rows = conn.execute(
            "select num, val, build_id, end_build_id, is_active"
            " from mart.deal_1 order by num"
        ).fetchall()
        assert rows == [
            ("n1", 1, build_id, None, True),
            ("n2", 2, build_id, None, True),
            ("n3", 3, build_id, None, True),
        ]
        # init чистит интерфейсную за собой
        assert conn.execute(
            "select count(*) from mart.deal_1_$"
        ).fetchone() == (0,)
        # временная учётка билда удалена
        _wait_role_gone(conn, build_id)


def test_build_second_init_merges(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        conn.execute("update public.deal_src set val = 22 where num = 'n2'")
        conn.execute(
            "update public.deal_src set is_active = false where num = 'n3'"
        )
        conn.execute("insert into public.deal_src values ('n4', 4, true)")
        b1 = conn.execute(
            "select min(build_id) from datapulse.build"
            " where dataset_code = 'mart.deal'"
        ).fetchone()[0]
        b2, _ = _launch(conn, "build('mart.deal', 1, 'ini')")
        assert _wait_final(conn, b2) == "done"
        journal = _journal_rows(conn, b2)
        # нижняя граница дельты — срез прошлого clear-успеха
        prints = [row[1] for row in journal if row[0] == "load" and row[1]]
        assert any(f"режим ini {b1} {b2}" in p for p in prints)
        assert next(r for r in journal if r[0] == "comp")[2] == 4
        assert journal[-1][3:6] == (1, 1, 1)   # n4; n2; n3
        # SCD2: старые версии закрыты ИНКЛЮЗИВНО билдом b2 - 1
        n2 = conn.execute(
            "select build_id, end_build_id, is_active, val from mart.deal_1"
            " where num = 'n2' order by build_id"
        ).fetchall()
        assert n2 == [(b1, b2 - 1, True, 2), (b2, None, True, 22)]
        n3 = conn.execute(
            "select build_id, end_build_id, is_active, val from mart.deal_1"
            " where num = 'n3' order by build_id"
        ).fetchall()
        assert n3 == [(b1, b2 - 1, True, 3), (b2, None, False, 3)]
        # срезы функции датасета: на b1 — старый мир, на b2 — новый
        old = conn.execute(
            "select num, val, is_active from mart.deal(%s) order by num",
            (b1,),
        ).fetchall()
        assert old == [("n1", 1, True), ("n2", 2, True), ("n3", 3, True)]
        new = conn.execute(
            "select num, val, is_active from mart.deal(%s) order by num",
            (b2,),
        ).fetchall()
        assert new == [
            ("n1", 1, True), ("n2", 22, True), ("n3", 3, False),
            ("n4", 4, True),
        ]


def test_build_incr(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        conn.execute("truncate public.deal_src")
        conn.execute("insert into public.deal_src values ('n5', 5, true)")
        build_id, _ = _launch(conn, "build('mart.deal', 1, 'inc')")
        assert _wait_final(conn, build_id) == "done"
        assert _journal_rows(conn, build_id)[-1][3:6] == (1, 0, 0)
        # left join: строки вне среза не тронуты
        untouched = conn.execute(
            "select count(*) from mart.deal_1 where end_build_id is null"
        ).fetchone()
        assert untouched == (5,)   # n1, n2, n3(tombstone), n4, n5
        # incr не чистит интерфейсную — выхлоп остаётся для разбора
        assert conn.execute(
            "select count(*) from mart.deal_1_$"
        ).fetchone() == (1,)


def test_build_appd_and_skip(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        conn.execute("truncate public.deal_src")
        conn.execute("insert into public.deal_src values ('n6', 6, true)")
        build_id, _ = _launch(conn, "build('mart.deal', 1, 'app')")
        assert _wait_final(conn, build_id) == "done"
        assert _journal_rows(conn, build_id)[-1][3:6] == (1, 0, 0)
        # skip: только журнал и вотермарка, переноса нет
        skip_id, _ = _launch(conn, "build('mart.deal', 1, 'skp')")
        assert _wait_final(conn, skip_id) == "done"
        journal = _journal_rows(conn, skip_id)
        assert next(r for r in journal if r[0] == "comp")[2] == 0
        assert journal[-1][3:6] == (0, 0, 0)
        assert conn.execute(
            "select count(*) from mart.deal_1 where end_build_id is null"
        ).fetchone() == (6,)


@pytest.mark.parametrize(
    "query, error, fragment",
    [
        ("build('mart.deal', 9, 'ini')", "UndefinedObject", "не существует"),
        ("build('mart.nope', 1, 'ini')", "UndefinedObject", "не существует"),
        ("build('mart.deal', 1, 'nope')", "InvalidParameterValue",
         "нет режима"),
    ],
)
def test_build_validation(proxy, database, query, error, fragment):
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(getattr(psycopg.errors, error), match=fragment):
            conn.execute(query)


def test_build_fail_and_fix(proxy, database):
    # тело mart.pup.1 — 'transform': NameError → fail, traceback в журнале
    with _connect(proxy, database, simple=True) as conn:
        build_id, _ = _launch(conn, "build('mart.pup', 1, 'm')")
        assert _wait_final(conn, build_id) == "fail"
        journal = _journal_rows(conn, build_id)
        prints = [row[1] for row in journal if row[0] == "load" and row[1]]
        assert any("NameError" in p for p in prints)
        assert "завершилось с ошибкой" in journal[-1][1]
        # трансформер без незавершённых билдов источника: срез — свой id
        assert conn.execute(
            "select source_build_id from datapulse.build where build_id = %s",
            (build_id,),
        ).fetchone() == (build_id,)
        # неразобранный fail блокирует следующий билд спеки
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState,
            match="упал и не разобран",
        ):
            conn.execute("build('mart.pup', 1, 'm')")
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState, match="уже упал"
        ):
            conn.execute(f"stop({build_id})")
        cur = conn.cursor()
        cur.execute(f"fix({build_id})")
        assert cur.statusmessage == "FIX"
        journal = _journal_rows(conn, build_id)
        assert journal[-1][0] == "fix"
        assert os.environ["PG_USER"] in journal[-1][1]
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState, match="уже завершён"
        ):
            conn.execute(f"fix({build_id})")
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState, match="уже завершён"
        ):
            conn.execute(f"stop({build_id})")
        with pytest.raises(psycopg.errors.UndefinedObject, match="не существует"):
            conn.execute("stop(999999)")
        with pytest.raises(psycopg.errors.UndefinedObject, match="не существует"):
            conn.execute("fix(999999)")


def test_build_stop_concurrency_and_watermark(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        conn.execute("create dataset mart.slow (k text, primary key (k))")
        conn.execute(
            "create build_spec mart.slow.1 (dirty init mode long)"
            " with (chunk_attr = k) as python"
            " $$\nimport time\ntime.sleep(120)\n$$"
        )
        b_long, _ = _launch(conn, "build('mart.slow', 1, 'long')")
        assert _wait_status(conn, b_long, ("load",)) == "load"
        # одновременный билд той же спеки запрещён
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState,
            match="уже выполняется",
        ):
            conn.execute("build('mart.slow', 1, 'long')")
        # DDL спеки при незавершённом билде запрещён
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState,
            match="незавершённый билд",
        ):
            conn.execute(
                "create or replace build_spec mart.slow.1"
                " (dirty init mode long) with (chunk_attr = k)"
                " as python $$pass$$"
            )
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState,
            match="незавершённый билд",
        ):
            conn.execute("drop build_spec mart.slow.1")
        # вотермарка читателя: незавершённый билд источника держит срез ниже
        conn.execute("create dataset mart.rep (r text, primary key (r))")
        conn.execute(
            "create build_spec mart.rep.1 (dirty skip mode m)"
            " with (chunk_attr = r) from mart.slow as python $$pass$$"
        )
        b_rep, _ = _launch(conn, "build('mart.rep', 1, 'm')")
        assert _wait_final(conn, b_rep) == "done"
        assert conn.execute(
            "select source_build_id from datapulse.build where build_id = %s",
            (b_rep,),
        ).fetchone() == (b_long - 1,)
        # остановка живого билда: kill ребёнка, финал fail в журнале
        cur = conn.cursor()
        cur.execute(f"stop({b_long})")
        assert cur.statusmessage == "STOP"
        assert _wait_final(conn, b_long) == "fail"
        journal = _journal_rows(conn, b_long)
        assert "остановлен пользователем" in journal[-1][1]
        cur.execute(f"fix({b_long})")
        assert cur.statusmessage == "FIX"
        # временная учётка убитого билда удалена
        _wait_role_gone(conn, b_long)


def test_build_orphan_reconcile(proxy, database, config):
    # сирота: активная запись журнала без claim-замка — рукотворно, мимо
    # прокси, как оставила бы жёсткая остановка сервера
    with psycopg.connect(
        host=config.pg_host, port=config.pg_port, dbname=database,
        user=config.pg_user, password=config.pg_password, autocommit=True,
    ) as admin:
        version_id = admin.execute(
            "select max(version_id) from datapulse.version"
        ).fetchone()[0]
        orphan = admin.execute(
            "select max(build_id) + 1 from datapulse.build"
        ).fetchone()[0]
        admin.execute(
            "insert into datapulse.build (version_id, build_id, dataset_code,"
            " build_spec_num, mode_code, is_clear, user_code, source_build_id)"
            " values (%s, %s, 'mart.slow', 1, 'long', false, 'x', %s)",
            (version_id, orphan, orphan),
        )
        admin.execute(
            "insert into datapulse.build_log (version_id, build_id, log_time,"
            " status_code) values (%s, %s, now(), 'wait'),"
            " (%s, %s, now(), 'load')",
            (version_id, orphan, version_id, orphan),
        )
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState, match="осиротел"
        ):
            conn.execute("build('mart.slow', 1, 'long')")
        cur = conn.cursor()
        cur.execute(f"stop({orphan})")
        assert cur.statusmessage == "STOP"
        journal = _journal_rows(conn, orphan)
        assert journal[-1][0] == "fail"
        assert "неожиданная остановка сервера" in journal[-1][1]
        cur.execute(f"fix({orphan})")
        assert cur.statusmessage == "FIX"


def test_attach_finished_build(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        b1 = conn.execute(
            "select min(build_id) from datapulse.build"
            " where dataset_code = 'mart.deal'"
        ).fetchone()[0]
        notices = []
        conn.add_notice_handler(lambda d: notices.append(d.message_primary))
        cur = conn.cursor()
        cur.execute(f"attach({b1})")
        assert cur.statusmessage == "ATTACH"
        assert notices and " wait" in notices[0]
        assert any(" done" in n for n in notices)
        assert any("подготовлено: 3" in n for n in notices)
        # позиция за финалом — attach завершается без строк
        notices.clear()
        cur.execute(f"attach({b1}, 999999999)")
        assert cur.statusmessage == "ATTACH"
        assert notices == []
        with pytest.raises(
            psycopg.errors.UndefinedObject, match="не существует"
        ):
            conn.execute("attach(999999)")


def test_attach_live_build(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        conn.execute(
            "create or replace build_spec mart.slow.1 (dirty init mode nap)"
            " with (chunk_attr = k) as python"
            " $$\nimport time\ntime.sleep(3)\n$$"
        )
        build_id, _ = _launch(conn, "build('mart.slow', 1, 'nap')")
        notices = []
        conn.add_notice_handler(lambda d: notices.append(d.message_primary))
        cur = conn.cursor()
        cur.execute(f"attach({build_id})")   # живой хвост — до финала билда
        assert cur.statusmessage == "ATTACH"
        assert any(" done" in n for n in notices)
        assert _last_build_status(conn, build_id) == "done"


# --- drop datapulse --------------------------------------------------------


def test_drop_datapulse(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        cur = conn.cursor()
        cur.execute("drop datapulse")
        assert cur.statusmessage == "DROP DATAPULSE"
        names = conn.execute(
            "select nspname from pg_namespace"
            " where nspname in ('datapulse', 'stg', 'ods', 'mart')"
        ).fetchall()
        assert names == []


def test_drop_not_installed(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(
            psycopg.errors.InvalidSchemaName, match="не установлен"
        ):
            conn.execute("drop datapulse")


def test_create_dataset_not_installed(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(
            psycopg.errors.InvalidSchemaName, match="не установлен"
        ):
            conn.execute("create dataset stg.dog (x text, primary key (x))")


def test_python_not_installed(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(
            psycopg.errors.InvalidSchemaName, match="не установлен"
        ):
            conn.execute("python $$ print(1) $$")


def test_build_not_installed(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(
            psycopg.errors.InvalidSchemaName, match="не установлен"
        ):
            conn.execute("build('mart.deal', 1, 'ini')")
        with pytest.raises(
            psycopg.errors.InvalidSchemaName, match="не установлен"
        ):
            conn.execute("stop(1)")
