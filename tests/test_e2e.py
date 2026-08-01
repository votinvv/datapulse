"""E2E: прокси против живого Postgres.

Бэкенд берётся из PG_HOST / PG_PORT / PG_USER / PG_PASSWORD (без них
модуль скипается). Прокси поднимается в фоновом потоке на свободном
порту; служебная БД прогона создаётся и сносится мимо прокси.

Клиенты: psycopg с обычным курсором — extended-протокол,
с ClientCursor — simple-протокол (путь DPL). Тесты в файле
упорядочены: установка → ошибки → датасеты → спеки → билды →
потоки → снос.
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


def _view_columns(conn, schema, name):
    """Колонки вьюхи датасета по порядку либо None — вьюхи нет."""
    rows = conn.execute(
        "select column_name from information_schema.columns"
        " where table_schema = %s and table_name = %s"
        " order by ordinal_position",
        (schema, name),
    ).fetchall()
    if not rows:
        return None
    return [row[0] for row in rows]


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
        row = conn.execute(
            "select current_database(), current_user"
        ).fetchone()
        assert row == (database, os.environ["PG_USER"])


def test_relay_transaction_rollback(proxy, database):
    with _connect(proxy, database, autocommit=False) as conn:
        conn.execute("create table relay_t (n int)")
        conn.execute("insert into relay_t values (1)")
        conn.rollback()
        assert conn.execute(
            "select to_regclass('relay_t')"
        ).fetchone() == (None,)


def test_relay_error_passthrough(proxy, database):
    with _connect(proxy, database) as conn:
        with pytest.raises(psycopg.errors.SyntaxError):
            conn.execute("селект 1")


def test_relay_copy_out(proxy, database):
    with _connect(proxy, database) as conn, conn.cursor() as cur:
        with cur.copy(
            "copy (select generate_series(1, 5)) to stdout"
        ) as copy:
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


# --- create [or replace] store|mart dataset --------------------------------


def test_create_store_dataset(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        cur = conn.cursor()
        cur.execute(
            "create store dataset stg.dog ("
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
            "select version_id, dataset_code, type_code, is_deleted, descr"
            " from datapulse.dataset"
        ).fetchall()
        assert dataset == [(2, "stg.dog", "store", False, None)]
        attrs = conn.execute(
            "select attr_code, order_num, type_code, is_primary"
            " from datapulse.dataset_attr order by order_num"
        ).fetchall()
        assert attrs == [
            ("agreement_number", 1, "text", True),
            ("open_date", 2, "timestamp", False),
            ("amount", 3, "numeric(18,2)", False),
        ]
        # вьюха датасета: пустая, но с полным составом колонок
        # (PK, служебные SCD2, неключевые — порядок спековой таблицы)
        assert conn.execute("select * from stg.dog").fetchall() == []
        assert _view_columns(conn, "stg", "dog") == [
            "agreement_number", "build_id", "end_build_id", "is_active",
            "open_date", "amount",
        ]


def test_create_dataset_duplicate(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(
            psycopg.errors.DuplicateObject, match="уже существует"
        ):
            conn.execute(
                "create store dataset stg.dog (x text, primary key (x))"
            )


def test_dataset_type_change_rejected(proxy, database):
    # смена подкласса через or replace запрещена — только drop + create
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(
            psycopg.errors.FeatureNotSupported, match="смена подкласса"
        ):
            conn.execute(
                "create or replace mart dataset stg.dog"
                " (x text, primary key (x))"
            )


def test_create_or_replace_dataset(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        cur = conn.cursor()
        cur.execute(
            "create or replace store dataset stg.dog ("
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
        # вьюха пересоздана под новый состав колонок
        assert _view_columns(conn, "stg", "dog") == [
            "agreement_number", "build_id", "end_build_id", "is_active",
            "descr",
        ]
        command = conn.execute(
            "select command from datapulse.version"
            " order by version_id desc limit 1"
        ).fetchone()
        assert command == ("create or replace store dataset",)


def test_create_dataset_undeclared_schema(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(
            psycopg.errors.InvalidSchemaName, match="не объявлена"
        ):
            conn.execute(
                "create store dataset dm.dog (x text, primary key (x))"
            )


def test_create_dataset_syntax_error(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(
            psycopg.errors.SyntaxError, match="PRIMARY KEY обязателен"
        ):
            conn.execute("create store dataset stg.cat (x text)")


# --- drop dataset ----------------------------------------------------------


def test_drop_dataset(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        cur = conn.cursor()
        cur.execute("drop dataset stg.dog")
        assert cur.statusmessage == "DROP DATASET"
        last = conn.execute(
            "select version_id, type_code, is_deleted from datapulse.dataset"
            " where dataset_code = 'stg.dog'"
            " order by version_id desc limit 1"
        ).fetchone()
        assert last == (4, "store", True)   # tombstone копирует подкласс
        # tombstone без атрибутов; вьюха датасета дропнута
        attrs = conn.execute(
            "select count(*) from datapulse.dataset_attr where version_id = 4"
        ).fetchone()
        assert attrs == (0,)
        assert conn.execute(
            "select to_regclass('stg.dog')"
        ).fetchone() == (None,)


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
    # поверх tombstone создание идёт без or replace; подкласс можно сменить
    with _connect(proxy, database, simple=True) as conn:
        cur = conn.cursor()
        cur.execute("create mart dataset stg.dog (x text, primary key (x))")
        assert cur.statusmessage == "CREATE DATASET"
        last = conn.execute(
            "select version_id, type_code, is_deleted from datapulse.dataset"
            " where dataset_code = 'stg.dog'"
            " order by version_id desc limit 1"
        ).fetchone()
        assert last == (5, "mart", False)
        assert _view_columns(conn, "stg", "dog") is not None
        # вернём подкласс store через drop + create (дальше тесты ждут store)
        cur.execute("drop dataset stg.dog")
        cur.execute("create store dataset stg.dog (x text, primary key (x))")


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
            "create or replace store dataset stg.dog"
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
        # комментарий атрибута лёг на колонку вьюхи датасета
        assert _column_comment(conn, "stg.dog", "y") == "счётчик"
        # комментарий атрибута переживает or replace: сопоставление по имени
        cur.execute(
            "create or replace store dataset stg.dog"
            " (x text, y integer, primary key (x))"
        )
        assert _attr_descrs(conn) == [("x", None), ("y", "счётчик")]
        assert _column_comment(conn, "stg.dog", "y") == "счётчик"
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


def _column_comment(conn, table, column):
    return conn.execute(
        "select col_description(%s::regclass,"
        " (select attnum from pg_attribute"
        "   where attrelid = %s::regclass and attname = %s))",
        (table, table, column),
    ).fetchone()[0]


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
        # атрибуты скопированы в новую версию (с их комментариями)
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
        # комментарий продублирован на вьюху датасета
        assert conn.execute(
            "select obj_description('stg.dog'::regclass)"
        ).fetchone() == ("основной датасет",)
        assert conn.execute("select * from stg.dog").fetchall() == []
        # комментарий переживает or replace (семантика Postgres) —
        # и в метаданных, и на пересозданной вьюхе
        cur.execute(
            "create or replace store dataset stg.dog"
            " (x text, primary key (x))"
        )
        last = conn.execute(
            "select descr from datapulse.dataset"
            " where dataset_code = 'stg.dog'"
            " order by version_id desc limit 1"
        ).fetchone()
        assert last == ("основной датасет",)
        assert conn.execute(
            "select obj_description('stg.dog'::regclass)"
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


# --- create oracle|postgres connection / test -------------------------------


def test_create_postgres_connection(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        cur = conn.cursor()
        cur.execute(
            "create postgres connection wh with ("
            f" host_name = '{os.environ['PG_HOST']}',"
            f" port_num = {int(os.environ.get('PG_PORT') or 5432)},"
            f" database_name = '{database}',"
            f" user_name = '{os.environ['PG_USER']}',"
            f" password = '{os.environ['PG_PASSWORD']}')"
        )
        assert cur.statusmessage == "CREATE CONNECTION"
        row = conn.execute(
            "select is_deleted, class_code, param_json"
            " from datapulse.connection order by version_id desc limit 1"
        ).fetchone()
        assert (row[0], row[1]) == (False, "postgres")
        params = row[2]
        assert params["host_name"] == os.environ["PG_HOST"]
        assert set(params["password"].keys()) == {"enc"}  # секрет зашифрован
        command = conn.execute(
            "select command from datapulse.version"
            " order by version_id desc limit 1"
        ).fetchone()
        assert command == ("create postgres connection",)


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
                "create postgres connection wh with (host_name = 'h',"
                " port_num = 5432, database_name = 'd', user_name = 'u',"
                " password = 'p')"
            )


def test_connection_class_change_rejected(proxy, database):
    # смена класса коннекта через or replace запрещена
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(
            psycopg.errors.FeatureNotSupported, match="смена класса"
        ):
            conn.execute(
                "create or replace oracle connection wh with ("
                " host_name = 'h', port_num = 1521, service_name = 's',"
                " user_name = 'u', password = 'p')"
            )


def test_test_connection_wrong_password(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        conn.execute(
            "create postgres connection bad with ("
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
            "create oracle connection ora with (host_name = '127.0.0.1',"
            " port_num = 1, service_name = 'X', user_name = 'u',"
            " password = 'p')"
        )
        assert cur.statusmessage == "CREATE CONNECTION"
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
                "create postgres connection bad2 with (host_name = 'h')"
            )


def test_connection_warehouse_reserved(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(
            psycopg.errors.DuplicateObject, match="зарезервированным"
        ):
            conn.execute(
                "create postgres connection warehouse with ("
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
            conn.execute(
                "python $$\nprint('до')\nraise RuntimeError('бум')\n$$"
            )
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
                    "python $$\nimport time\nprint('старт')\n"
                    "time.sleep(60)\n$$"
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
        cur.execute("alter datapulse add dm")
        assert cur.statusmessage == "ALTER DATAPULSE"
        row = conn.execute(
            "select command, usage from datapulse.version"
            " order by version_id desc limit 1"
        ).fetchone()
        assert row == ("alter datapulse add", "stg,ods,dm")
        assert conn.execute(
            "select 1 from pg_namespace where nspname = 'dm'"
        ).fetchone() == (1,)
        # новая схема сразу пригодна для датасетов
        cur.execute("create store dataset dm.cat (x text, primary key (x))")
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
# состояние: dm.cat жив (x text pk), stg.dog — tombstone, коннект wh жив


def test_create_build_spec(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        cur = conn.cursor()
        cur.execute(
            "create build_spec dm.cat.1 ("
            "  init mode initial"
            ", incr mode manual"
            ") with (parallel = 4, chunk_attr = x)"
            "  using wh"
            "  as python $$ print('привет') $$"
        )
        assert cur.statusmessage == "CREATE BUILD_SPEC"
        spec = conn.execute(
            "select is_deleted, parallel_cnt, chunk_attr_code, body"
            " from datapulse.build_spec"
            " where dataset_code = 'dm.cat' and build_spec_num = 1"
            " order by version_id desc limit 1"
        ).fetchone()
        assert spec == (False, 4, "x", " print('привет') ")
        modes = conn.execute(
            "select mode_code, type_code"
            " from datapulse.build_spec_mode"
            " where dataset_code = 'dm.cat'"
            "   and version_id = (select max(version_id)"
            "                       from datapulse.build_spec)"
            " order by mode_code"
        ).fetchall()
        assert modes == [("initial", "init"), ("manual", "incr")]
        used = conn.execute(
            "select connection_code from datapulse.build_spec_connection"
            " order by version_id desc limit 1"
        ).fetchone()
        assert used == ("wh",)
        # версия датасета бампнута той же version_id, что и спека
        bump = conn.execute(
            "select (select max(version_id) from datapulse.dataset"
            "         where dataset_code = 'dm.cat')"
            "     = (select max(version_id) from datapulse.build_spec)"
        ).fetchone()
        assert bump == (True,)
        # пара таблиц спеки: основная строгая, интерфейсная вся nullable
        main = conn.execute(
            "select column_name, is_nullable from information_schema.columns"
            " where table_schema = 'dm' and table_name = 'cat_1'"
            " order by ordinal_position"
        ).fetchall()
        assert main == [
            ("x", "NO"), ("build_id", "NO"), ("end_build_id", "YES"),
            ("is_active", "NO"),
        ]
        iface = conn.execute(
            "select column_name, is_nullable from information_schema.columns"
            " where table_schema = 'dm' and table_name = 'cat_1_$'"
            " order by ordinal_position"
        ).fetchall()
        assert iface == [("x", "YES"), ("is_active", "YES")]
        assert "Билд, создавший" in _column_comment(
            conn, "dm.cat_1", "build_id"
        )


def test_dataset_view_over_spec(proxy, database):
    with _connect(proxy, database) as conn:
        # строки напрямую в основную таблицу (мимо движка): открытая
        # версия с билда 5 и версия, закрытая билдом 4 (end инклюзивный)
        conn.execute(
            "insert into dm.cat_1 (x, build_id, end_build_id, is_active)"
            " values ('a', 5, null, true), ('b', 3, 4, true)"
        )
        # вьюха отдаёт историю как есть — обе версии
        assert conn.execute(
            "select x from dm.cat order by x"
        ).fetchall() == [("a",), ("b",)]
        # потребительский as-of по колонкам: срез на билд 5 и на билд 3
        as_of = (
            "select x from dm.cat where build_id <= %s"
            " and (end_build_id is null or end_build_id >= %s)"
        )
        assert conn.execute(as_of, (5, 5)).fetchall() == [("a",)]
        assert conn.execute(as_of, (3, 3)).fetchall() == [("b",)]
        conn.execute("truncate dm.cat_1")


def test_create_build_spec_duplicate(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(
            psycopg.errors.DuplicateObject, match="уже существует"
        ):
            conn.execute(
                "create build_spec dm.cat.1 (init mode initial)"
                " with (chunk_attr = x) as python $$x$$"
            )


def test_create_or_replace_build_spec(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        conn.execute(
            "insert into dm.cat_1 (x, build_id, is_active)"
            " values ('строка', 1, true)"
        )
        cur = conn.cursor()
        cur.execute(
            "create or replace build_spec dm.cat.1 (init mode initial)"
            " with (parallel = 8, chunk_attr = x) using wh"
            " as python $$новое тело$$"
        )
        assert cur.statusmessage == "CREATE BUILD_SPEC"
        spec = conn.execute(
            "select parallel_cnt, body from datapulse.build_spec"
            " where dataset_code = 'dm.cat' and build_spec_num = 1"
            " order by version_id desc limit 1"
        ).fetchone()
        assert spec == (8, "новое тело")
        # or replace живой спеки не трогает таблицы — данные живут
        rows = conn.execute("select count(*) from dm.cat_1").fetchone()
        assert rows == (1,)
        conn.execute("truncate dm.cat_1")


@pytest.mark.parametrize(
    "query, error, fragment",
    [
        ("create build_spec dm.cat.2 (init mode initial)"
         " with (chunk_attr = zzz) as python $$x$$",
         "InvalidParameterValue", "PRIMARY KEY датасета"),
        ("create build_spec dm.cat.2 (init mode initial)"
         " with (chunk_attr = x) using nothing as python $$x$$",
         "UndefinedObject", "не существует"),
        ("create build_spec dm.cat.2 (init mode initial)"
         " with (chunk_attr = x) using warehouse as python $$x$$",
         "InvalidParameterValue", "неявный"),
        ("create build_spec stg.dog2.1 (init mode initial)"
         " with (chunk_attr = x) as python $$x$$",
         "UndefinedObject", "не существует"),
        ("create build_spec dm.cat.2 (init mode initial)"
         " with (parallel = 0, chunk_attr = x) as python $$x$$",
         "InvalidParameterValue", "≥ 1"),
        ("create build_spec dm.cat.2 (init mode initial)"
         " with (parallel = 4) as python $$x$$",
         "InvalidParameterValue", "chunk_attr обязательна"),
        ("create build_spec dm.cat.2 (init mode initial)"
         " with (chunk_attr = x) as python $$   $$",
         "InvalidParameterValue", "тело спеки пустое"),
        ("create build_spec dm.cat.2 (init mode initial)"
         " with (chunk_attr = x) from dm.cat as python $$x$$",
         "InvalidParameterValue", "собственный датасет"),
        # режимная дисциплина store-спеки
        ("create build_spec dm.cat.2 (sect mode allegro)"
         " with (chunk_attr = x) as python $$x$$",
         "InvalidParameterValue", "initial или increment"),
        ("create build_spec dm.cat.2 (appd mode increment)"
         " with (chunk_attr = x) as python $$x$$",
         "InvalidParameterValue", "недоступен store"),
        ("create build_spec dm.cat.2 (skip, init mode initial)"
         " with (chunk_attr = x) as python $$x$$",
         "InvalidParameterValue", "недоступен store"),
        ("create build_spec dm.cat.2 (incr mode initial)"
         " with (chunk_attr = x) as python $$x$$",
         "InvalidParameterValue", "тип init"),
        # store: using и from взаимоисключающи
        ("create build_spec dm.cat.2 (init mode initial)"
         " with (chunk_attr = x) using wh from stg.dog as python $$x$$",
         "InvalidParameterValue", "взаимоисключающи"),
    ],
)
def test_build_spec_validation(proxy, database, query, error, fragment):
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(getattr(psycopg.errors, error), match=fragment):
            conn.execute(query)


def test_build_spec_from_and_cycle(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        conn.execute(
            "create store dataset dm.pup (y text, primary key (y))"
        )
        conn.execute(
            "create build_spec dm.pup.1 (incr mode increment)"
            " with (chunk_attr = y) from dm.cat as python $$transform$$"
        )
        source = conn.execute(
            "select source_dataset_code from datapulse.build_spec_source"
            " order by version_id desc limit 1"
        ).fetchone()
        assert source == ("dm.cat",)
        # цикл: cat читал бы pup, pup читает cat
        with pytest.raises(
            psycopg.errors.InvalidParameterValue, match="зацикливается"
        ):
            conn.execute(
                "create or replace build_spec dm.cat.1"
                " (init mode initial) with (chunk_attr = x)"
                " from dm.pup as python $$x$$"
            )


def test_mart_spec_rules(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        cur = conn.cursor()
        cur.execute(
            "create mart dataset dm.feed (num text, val integer,"
            " primary key (num))"
        )
        # витринная спека: skip обязателен
        with pytest.raises(
            psycopg.errors.InvalidParameterValue, match="режим skip"
        ):
            conn.execute(
                "create build_spec dm.feed.1 (appd mode increment)"
                " with (chunk_attr = num) from dm.cat as python $$x$$"
            )
        # у витрины increment — только тип appd
        with pytest.raises(
            psycopg.errors.InvalidParameterValue, match="appd"
        ):
            conn.execute(
                "create build_spec dm.feed.1 (init mode increment, skip)"
                " with (chunk_attr = num) as python $$x$$"
            )
        # витрине можно и from (сторы), и using (коннект отгрузки) сразу
        cur.execute(
            "create build_spec dm.feed.1"
            " (appd mode increment, init mode initial, skip,"
            "  appd mode resend)"
            " with (chunk_attr = num) using wh from dm.cat"
            " as python $$pass$$"
        )
        assert cur.statusmessage == "CREATE BUILD_SPEC"
        # витрина не может быть источником
        with pytest.raises(
            psycopg.errors.InvalidParameterValue, match="не может быть"
        ):
            conn.execute(
                "create build_spec dm.pup.2 (incr mode increment)"
                " with (chunk_attr = y) from dm.feed as python $$x$$"
            )
        # прибираем: витрина этого теста дальше не нужна
        cur.execute("drop build_spec dm.feed.1")
        cur.execute("drop dataset dm.feed")


def test_comment_on_attr_spec_columns(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        conn.execute("comment on attr dm.cat.x is 'ключик'")
        assert _column_comment(conn, "dm.cat_1", "x") == "ключик"
        assert _column_comment(conn, "dm.cat_1_$", "x") == "ключик"
        assert _column_comment(conn, "dm.cat", "x") == "ключик"


def test_drop_dataset_restrict_own_specs(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(
            psycopg.errors.DependentObjectsStillExist, match="живые спеки: 1"
        ):
            conn.execute("drop dataset dm.cat")


def test_drop_build_spec(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        cur = conn.cursor()
        cur.execute("drop build_spec dm.cat.1")
        assert cur.statusmessage == "DROP BUILD_SPEC"
        spec = conn.execute(
            "select is_deleted, parallel_cnt, body from datapulse.build_spec"
            " where dataset_code = 'dm.cat' and build_spec_num = 1"
            " order by version_id desc limit 1"
        ).fetchone()
        assert spec == (True, 8, "новое тело")   # tombstone копирует поля
        # данные держатся актуальными: таблицы спеки удалены физически
        gone = conn.execute(
            "select to_regclass('dm.cat_1'), to_regclass('dm.cat_1_$')"
        ).fetchone()
        assert gone == (None, None)
        # последняя спека умерла — вьюха откатилась на заглушку
        assert conn.execute("select * from dm.cat").fetchall() == []


def test_drop_dataset_restrict_readers(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(
            psycopg.errors.DependentObjectsStillExist,
            match="читают живые спеки: dm.pup.1",
        ):
            conn.execute("drop dataset dm.cat")


def test_recreate_build_spec_after_drop(proxy, database):
    # поверх tombstone создание идёт без or replace; таблицы — заново
    with _connect(proxy, database, simple=True) as conn:
        cur = conn.cursor()
        cur.execute(
            "create build_spec dm.cat.1 (init mode initial)"
            " with (chunk_attr = x) using wh as python $$заново$$"
        )
        assert cur.statusmessage == "CREATE BUILD_SPEC"
        rows = conn.execute("select count(*) from dm.cat_1").fetchone()
        assert rows == (0,)
        assert conn.execute("select * from dm.cat").fetchall() == []


def test_dataset_structure_frozen_with_live_specs(proxy, database):
    # у dm.cat живая спека 1: PK и типы неизменны, набор — 0A000
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(
            psycopg.errors.FeatureNotSupported, match="PRIMARY KEY неизменен"
        ):
            conn.execute(
                "create or replace store dataset dm.cat"
                " (x text, z text, primary key (x, z))"
            )
        with pytest.raises(
            psycopg.errors.FeatureNotSupported, match="тип атрибута 'x'"
        ):
            conn.execute(
                "create or replace store dataset dm.cat"
                " (x integer, primary key (x))"
            )
        with pytest.raises(
            psycopg.errors.FeatureNotSupported, match="ещё не реализовано"
        ):
            conn.execute(
                "create or replace store dataset dm.cat"
                " (x text, y integer, primary key (x))"
            )
        # без изменений структуры or replace разрешён — просто новая версия
        cur = conn.cursor()
        cur.execute(
            "create or replace store dataset dm.cat"
            " (x text, primary key (x))"
        )
        assert cur.statusmessage == "CREATE DATASET"
        assert conn.execute("select * from dm.cat").fetchall() == []


# --- flow_spec ---------------------------------------------------------------


def test_create_flow_spec(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        cur = conn.cursor()
        cur.execute(
            "create flow_spec night as $$ select 'dm.deal', 1, 'allegro' $$"
        )
        assert cur.statusmessage == "CREATE FLOW_SPEC"
        row = conn.execute(
            "select is_deleted, body from datapulse.flow_spec"
            " where flow_spec_code = 'night'"
            " order by version_id desc limit 1"
        ).fetchone()
        assert row == (False, " select 'dm.deal', 1, 'allegro' ")
        with pytest.raises(
            psycopg.errors.DuplicateObject, match="уже существует"
        ):
            conn.execute("create flow_spec night as $$ select 1 $$")
        cur.execute(
            "create or replace flow_spec night as"
            " $$ select dataset_code, num, mode from public.night_plan $$"
        )
        assert cur.statusmessage == "CREATE FLOW_SPEC"


def test_drop_flow_spec(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        cur = conn.cursor()
        cur.execute("create flow_spec doomed as $$ select 1 $$")
        cur.execute("drop flow_spec doomed")
        assert cur.statusmessage == "DROP FLOW_SPEC"
        row = conn.execute(
            "select is_deleted, body from datapulse.flow_spec"
            " where flow_spec_code = 'doomed'"
            " order by version_id desc limit 1"
        ).fetchone()
        assert row == (True, " select 1 ")   # tombstone копирует тело
        with pytest.raises(
            psycopg.errors.UndefinedObject, match="не существует"
        ):
            conn.execute("drop flow_spec doomed")


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
    """build(...) / flow(...) через прокси: (id, command tag)."""
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
            "create store dataset dm.deal (num text, val integer,"
            " primary key (num))"
        )
        conn.execute(
            "create build_spec dm.deal.1 ("
            "  init mode initial"
            ", incr mode increment"
            ", sect mode allegro"
            ") with (parallel = 2, chunk_attr = num) as python $$\n"
            "print('режим', mode_code, from_build_id, to_build_id)\n"
            "with warehouse() as c:\n"
            "    c.cursor().execute("
            "\"insert into dm.deal_1_$ (num, val, is_active)"
            " select num, val, is_active from public.deal_src\")\n"
            "$$"
        )


def test_build_initial(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        conn.execute(
            "insert into public.deal_src values"
            " ('n1', 1, true), ('n2', 2, true), ('n3', 3, true)"
        )
        build_id, tag = _launch(conn, "build('dm.deal', 1, 'initial')")
        assert tag == "BUILD"
        assert _wait_final(conn, build_id) == "done"
        journal = _journal_rows(conn, build_id)
        statuses = [row[0] for row in journal]
        assert statuses[0] == "wait" and statuses[-1] == "done"
        assert "load" in statuses and "comp" in statuses
        # печать тела — в журнале со статусом load; окно инъецировано:
        # from = 0 (чистых билдов не было), to = собственный build_id
        prints = [row[1] for row in journal if row[0] == "load" and row[1]]
        assert any(f"режим initial 0 {build_id}" in p for p in prints)
        comp = next(row for row in journal if row[0] == "comp")
        assert comp[2] == 3    # prepared_row_cnt
        assert journal[-1][3:6] == (3, 0, 0)
        build = conn.execute(
            "select mode_code, flow_id, user_code"
            " from datapulse.build where build_id = %s",
            (build_id,),
        ).fetchone()
        # межстримовый билд: flow_id пуст
        assert build == ("initial", None, os.environ["PG_USER"])
        rows = conn.execute(
            "select num, val, build_id, end_build_id, is_active"
            " from dm.deal_1 order by num"
        ).fetchall()
        assert rows == [
            ("n1", 1, build_id, None, True),
            ("n2", 2, build_id, None, True),
            ("n3", 3, build_id, None, True),
        ]
        # init чистит интерфейсную за собой
        assert conn.execute(
            "select count(*) from dm.deal_1_$"
        ).fetchone() == (0,)
        # временная учётка билда удалена
        _wait_role_gone(conn, build_id)


def test_build_second_initial_merges(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        conn.execute("update public.deal_src set val = 22 where num = 'n2'")
        conn.execute(
            "update public.deal_src set is_active = false where num = 'n3'"
        )
        conn.execute("insert into public.deal_src values ('n4', 4, true)")
        b1 = conn.execute(
            "select min(build_id) from datapulse.build"
            " where dataset_code = 'dm.deal'"
        ).fetchone()[0]
        b2, _ = _launch(conn, "build('dm.deal', 1, 'initial')")
        assert _wait_final(conn, b2) == "done"
        journal = _journal_rows(conn, b2)
        # нижняя граница окна — build_id последнего чистого успеха
        prints = [row[1] for row in journal if row[0] == "load" and row[1]]
        assert any(f"режим initial {b1} {b2}" in p for p in prints)
        assert next(r for r in journal if r[0] == "comp")[2] == 4
        assert journal[-1][3:6] == (1, 1, 1)   # n4; n2; n3
        # SCD2: старые версии закрыты ИНКЛЮЗИВНО билдом b2 - 1
        n2 = conn.execute(
            "select build_id, end_build_id, is_active, val from dm.deal_1"
            " where num = 'n2' order by build_id"
        ).fetchall()
        assert n2 == [(b1, b2 - 1, True, 2), (b2, None, True, 22)]
        n3 = conn.execute(
            "select build_id, end_build_id, is_active, val from dm.deal_1"
            " where num = 'n3' order by build_id"
        ).fetchall()
        assert n3 == [(b1, b2 - 1, True, 3), (b2, None, False, 3)]
        # as-of по колонкам вьюхи: на b1 — старый мир, на b2 — новый
        as_of = (
            "select num, val, is_active from dm.deal"
            " where build_id <= %s"
            " and (end_build_id is null or end_build_id >= %s)"
            " order by num"
        )
        old = conn.execute(as_of, (b1, b1)).fetchall()
        assert old == [("n1", 1, True), ("n2", 2, True), ("n3", 3, True)]
        new = conn.execute(as_of, (b2, b2)).fetchall()
        assert new == [
            ("n1", 1, True), ("n2", 22, True), ("n3", 3, False),
            ("n4", 4, True),
        ]


def test_build_increment(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        conn.execute("truncate public.deal_src")
        conn.execute("insert into public.deal_src values ('n5', 5, true)")
        build_id, _ = _launch(conn, "build('dm.deal', 1, 'increment')")
        assert _wait_final(conn, build_id) == "done"
        assert _journal_rows(conn, build_id)[-1][3:6] == (1, 0, 0)
        # left join: строки вне среза не тронуты
        untouched = conn.execute(
            "select count(*) from dm.deal_1 where end_build_id is null"
        ).fetchone()
        assert untouched == (5,)   # n1, n2, n3(tombstone), n4, n5
        # increment не чистит интерфейсную — выхлоп остаётся для разбора
        assert conn.execute(
            "select count(*) from dm.deal_1_$"
        ).fetchone() == (1,)


@pytest.mark.parametrize(
    "query, error, fragment",
    [
        ("build('dm.deal', 9, 'initial')", "UndefinedObject",
         "не существует"),
        ("build('dm.nope', 1, 'initial')", "UndefinedObject",
         "не существует"),
        ("build('dm.deal', 1, 'nope')", "InvalidParameterValue",
         "нет режима"),
    ],
)
def test_build_validation(proxy, database, query, error, fragment):
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(getattr(psycopg.errors, error), match=fragment):
            conn.execute(query)


def test_build_fail_and_fix(proxy, database):
    # тело dm.pup.1 — 'transform': NameError → fail, traceback в журнале
    with _connect(proxy, database, simple=True) as conn:
        build_id, _ = _launch(conn, "build('dm.pup', 1, 'increment')")
        assert _wait_final(conn, build_id) == "fail"
        journal = _journal_rows(conn, build_id)
        prints = [row[1] for row in journal if row[0] == "load" and row[1]]
        assert any("NameError" in p for p in prints)
        assert "завершилось с ошибкой" in journal[-1][1]
        # неразобранный fail блокирует следующий билд спеки
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState,
            match="упал и не разобран",
        ):
            conn.execute("build('dm.pup', 1, 'increment')")
        # открытый fail держит и exclusive: пересборка источника читателем
        # не блокируется (fail не читает), но сам pup заблокирован до fix
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
        with pytest.raises(
            psycopg.errors.UndefinedObject, match="не существует"
        ):
            conn.execute("stop(999999)")
        with pytest.raises(
            psycopg.errors.UndefinedObject, match="не существует"
        ):
            conn.execute("fix(999999)")


def test_build_locks_and_stop(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        conn.execute(
            "create store dataset dm.slow (k text, primary key (k))"
        )
        conn.execute(
            "create build_spec dm.slow.1 (init mode initial)"
            " with (chunk_attr = k) as python"
            " $$\nimport time\ntime.sleep(120)\n$$"
        )
        b_long, _ = _launch(conn, "build('dm.slow', 1, 'initial')")
        assert _wait_status(conn, b_long, ("load",)) == "load"
        # одновременный билд той же спеки запрещён (exclusive)
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState,
            match="уже выполняется",
        ):
            conn.execute("build('dm.slow', 1, 'initial')")
        # DDL спеки при незавершённом билде запрещён
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState,
            match="незавершённый билд",
        ):
            conn.execute(
                "create or replace build_spec dm.slow.1"
                " (init mode initial) with (chunk_attr = k)"
                " as python $$pass$$"
            )
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState,
            match="незавершённый билд",
        ):
            conn.execute("drop build_spec dm.slow.1")
        # shared-«замок» читателя: бегущий билд источника не отдаёт
        # консистентного чтения — билд читателя не стартует
        conn.execute(
            "create store dataset dm.rep (r text, primary key (r))"
        )
        conn.execute(
            "create build_spec dm.rep.1 (incr mode increment)"
            " with (chunk_attr = r) from dm.slow as python $$pass$$"
        )
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState,
            match="источник 'dm.slow' занят",
        ):
            conn.execute("build('dm.rep', 1, 'increment')")
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


def test_build_reader_holds_source(proxy, database):
    # зеркало shared: активный store-читатель держит источник от пересборки
    with _connect(proxy, database, simple=True) as conn:
        conn.execute(
            "create or replace build_spec dm.rep.1 (incr mode increment)"
            " with (chunk_attr = r) from dm.slow as python"
            " $$\nimport time\ntime.sleep(6)\n$$"
        )
        b_rep, _ = _launch(conn, "build('dm.rep', 1, 'increment')")
        assert _wait_status(conn, b_rep, ("load",)) == "load"
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState,
            match="датасет читает билд",
        ):
            conn.execute("build('dm.slow', 1, 'initial')")
        assert _wait_final(conn, b_rep) == "done"


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
            "insert into datapulse.build (version_id, build_id, flow_id,"
            " dataset_code, build_spec_num, mode_code, user_code)"
            " values (%s, %s, null, 'dm.slow', 1, 'initial', 'x')",
            (version_id, orphan),
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
            conn.execute("build('dm.slow', 1, 'initial')")
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
            " where dataset_code = 'dm.deal'"
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
            "create or replace build_spec dm.slow.1 (init mode initial)"
            " with (chunk_attr = k) as python"
            " $$\nimport time\ntime.sleep(3)\n$$"
        )
        build_id, _ = _launch(conn, "build('dm.slow', 1, 'initial')")
        notices = []
        conn.add_notice_handler(lambda d: notices.append(d.message_primary))
        cur = conn.cursor()
        cur.execute(f"attach({build_id})")   # живой хвост — до финала билда
        assert cur.statusmessage == "ATTACH"
        assert any(" done" in n for n in notices)
        assert _last_build_status(conn, build_id) == "done"


# --- потоки -----------------------------------------------------------------
# состояние: store-спеки dm.cat.1 (генератор, печать), dm.deal.1 (загрузчик
# deal_src), dm.pup.1 (тело с NameError!), dm.rep.1 (from dm.slow),
# dm.slow.1 (sleep 3)


def _last_flow_status(conn, flow_id):
    row = conn.execute(
        "select status_code from datapulse.flow_log where flow_id = %s"
        " order by flow_log_id desc limit 1",
        (flow_id,),
    ).fetchone()
    return row[0] if row else None


def _flow_journal(conn, flow_id):
    return conn.execute(
        "select status_code, message from datapulse.flow_log"
        " where flow_id = %s order by flow_log_id",
        (flow_id,),
    ).fetchall()


def _flow_builds(conn, flow_id):
    """(dataset_code, build_spec_num, mode_code, финал) билдов потока."""
    return conn.execute(
        "select b.dataset_code, b.build_spec_num, b.mode_code,"
        " (select status_code from datapulse.build_log l"
        "   where l.build_id = b.build_id"
        "   order by build_log_id desc limit 1)"
        " from datapulse.build b where b.flow_id = %s order by b.build_id",
        (flow_id,),
    ).fetchall()


def test_flow_prepare_graph(proxy, database):
    """Чинит хвосты прежних тестов и строит витрину: поток погонит все
    живые store-спеки — тела должны быть исполнимы."""
    with _connect(proxy, database, simple=True) as conn:
        # cat: тело «заново» (NameError) → генератор-пустышка
        conn.execute(
            "create or replace build_spec dm.cat.1 (init mode initial)"
            " with (chunk_attr = x) as python $$pass$$"
        )
        # pup: NameError-тело → нормальный трансформер
        conn.execute(
            "create or replace build_spec dm.pup.1 (incr mode increment)"
            " with (chunk_attr = y) from dm.cat as python $$pass$$"
        )
        # rep: сон из теста замков → пустышка
        conn.execute(
            "create or replace build_spec dm.rep.1 (incr mode increment)"
            " with (chunk_attr = r) from dm.slow as python $$pass$$"
        )
        # slow: короткий сон (нужен живой поток для pause/stop-тестов)
        conn.execute(
            "create or replace build_spec dm.slow.1 (init mode initial)"
            " with (chunk_attr = k) as python"
            " $$\nimport time\ntime.sleep(2)\n$$"
        )
        # витрина: порции активного среза окна дельты dm.deal;
        # тело ветвится по режиму — initial переотдаёт всё до границы
        conn.execute(
            "create mart dataset dm.feed (num text, val integer,"
            " primary key (num))"
        )
        conn.execute(
            "create build_spec dm.feed.1"
            " (appd mode increment, init mode initial, skip,"
            "  appd mode resend)"
            " with (chunk_attr = num) from dm.deal as python $$\n"
            "print('витрина', mode_code, from_build_id, to_build_id)\n"
            "low = 0 if mode_code == 'initial' else from_build_id\n"
            "with warehouse() as c:\n"
            "    c.cursor().execute("
            "f\"insert into dm.feed_1_$ (num, val, is_active)"
            " select num, val, true from dm.deal"
            " where build_id > {low}"
            " and build_id <= {to_build_id}"
            " and end_build_id is null and is_active\")\n"
            "$$"
        )
        # таблица плана для пресета night
        conn.execute(
            "create table public.night_plan"
            " (dataset_code text, num int, mode text)"
        )
        conn.execute(
            "insert into public.night_plan values ('dm.deal', 1, 'allegro')"
        )


def test_flow_full_pulse(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        conn.execute("truncate public.deal_src")
        conn.execute(
            "insert into public.deal_src values ('p1', 10, true)"
        )
        flow_id, tag = _launch(conn, "flow()")
        assert tag == "FLOW"
        row = conn.execute(
            "select flow_spec_code, user_code, intake_code, export_code"
            " from datapulse.flow where flow_id = %s",
            (flow_id,),
        ).fetchone()
        assert row == (None, os.environ["PG_USER"], "calc", "calc")
        # attach flow ждёт финала потока, стримя журнал
        notices = []
        conn.add_notice_handler(lambda d: notices.append(d.message_primary))
        cur = conn.cursor()
        cur.execute(f"attach flow({flow_id})")
        assert cur.statusmessage == "ATTACH"
        assert _last_flow_status(conn, flow_id) == "done"
        assert any("поток завершён" in n for n in notices)
        builds = _flow_builds(conn, flow_id)
        # все store-спеки пробежали чистым режимом (increment при
        # наличии чистой истории и самого режима, иначе initial),
        # витрина — increment; порядок топологический: источники
        # раньше читателей, датасеты без зависимостей — по алфавиту
        assert [(b[0], b[2]) for b in builds] == [
            ("dm.cat", "initial"),
            ("dm.deal", "increment"),
            ("dm.feed", "increment"),
            ("dm.pup", "increment"),
            ("dm.slow", "initial"),
            ("dm.rep", "increment"),
        ]
        assert all(b[3] == "done" for b in builds)
        # витринная порция: дельта dm.deal доехала до dm.feed
        feed = conn.execute(
            "select num, val from dm.feed order by num"
        ).fetchall()
        assert ("p1", 10) in feed


def test_flow_preset_dirty_then_clean(proxy, database):
    # пресет night: dm.deal бежит allegro (грязный), затем толчок
    # increment — дубль спеки в плане штатен
    with _connect(proxy, database, simple=True) as conn:
        conn.execute("truncate public.deal_src")
        conn.execute("insert into public.deal_src values ('p2', 20, true)")
        flow_id, _ = _launch(conn, "flow('night')")
        cur = conn.cursor()
        cur.execute(f"attach flow({flow_id})")
        assert _last_flow_status(conn, flow_id) == "done"
        deal = [
            b for b in _flow_builds(conn, flow_id) if b[0] == "dm.deal"
        ]
        assert [(b[2], b[3]) for b in deal] == [
            ("allegro", "done"), ("increment", "done"),
        ]


def test_flow_intake_pass(proxy, database):
    # кран приёма закрыт: входящие (генераторы/загрузчики) не бегут,
    # трансформеры и витрина — бегут
    with _connect(proxy, database, simple=True) as conn:
        flow_id, _ = _launch(conn, "flow(intake = pass)")
        cur = conn.cursor()
        cur.execute(f"attach flow({flow_id})")
        assert _last_flow_status(conn, flow_id) == "done"
        datasets = [b[0] for b in _flow_builds(conn, flow_id)]
        assert "dm.deal" not in datasets and "dm.cat" not in datasets
        assert "dm.pup" in datasets and "dm.feed" in datasets


def test_flow_export_skip_and_pass(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        # накопим дельту и скипнем отгрузку: витрина бежит skip-режимом
        conn.execute("truncate public.deal_src")
        conn.execute("insert into public.deal_src values ('p3', 30, true)")
        flow_id, _ = _launch(conn, "flow(export = skip)")
        cur = conn.cursor()
        cur.execute(f"attach flow({flow_id})")
        feed = [
            b for b in _flow_builds(conn, flow_id) if b[0] == "dm.feed"
        ]
        assert [(b[2], b[3]) for b in feed] == [("skip", "done")]
        # дельта p3 поглощена: в витрину она уже не приедет
        assert ("p3", 30) not in conn.execute(
            "select num, val from dm.feed"
        ).fetchall()
        # экспорт pass: витрина вовсе не бежит
        flow_id, _ = _launch(conn, "flow(export = pass)")
        cur.execute(f"attach flow({flow_id})")
        assert all(
            b[0] != "dm.feed" for b in _flow_builds(conn, flow_id)
        )


def test_flow_blocks_interflow_builds(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        flow_id, _ = _launch(conn, "flow()")
        # поток открыт (очередь/исполнение): межстримовый store-билд
        # заблокирован
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState, match="идёт поток"
        ):
            conn.execute("build('dm.deal', 1, 'increment')")
        cur = conn.cursor()
        cur.execute(f"attach flow({flow_id})")
        assert _last_flow_status(conn, flow_id) == "done"


def test_flow_pause_resume(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        flow_id, _ = _launch(conn, "flow()")
        cur = conn.cursor()
        cur.execute(f"pause flow({flow_id})")
        assert cur.statusmessage == "PAUSE"
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState, match="уже на паузе"
        ):
            conn.execute(f"pause flow({flow_id})")
        # пауза держит очередь шагов: бегущий билд доезжает, новые не
        # стартуют — поток не финиширует, пока стоит hold
        time.sleep(5)
        status = _last_flow_status(conn, flow_id)
        assert status not in ("done", "stop")
        # витринный ручной билд свободен даже при открытом потоке
        b_feed, _ = _launch(conn, "build('dm.feed', 1, 'resend')")
        assert _wait_final(conn, b_feed) == "done"
        cur.execute(f"resume flow({flow_id})")
        assert cur.statusmessage == "RESUME"
        cur.execute(f"attach flow({flow_id})")
        assert _last_flow_status(conn, flow_id) == "done"


def test_flow_queue_fifo(proxy, database):
    # второй поток ждёт первого в очереди, затем едет сам
    with _connect(proxy, database, simple=True) as conn:
        first, _ = _launch(conn, "flow(intake = pass, export = pass)")
        second, _ = _launch(conn, "flow(intake = pass, export = pass)")
        assert second == first + 1
        cur = conn.cursor()
        cur.execute(f"attach flow({second})")
        assert _last_flow_status(conn, first) == "done"
        assert _last_flow_status(conn, second) == "done"
        # порядок: все билды первого раньше билдов второго
        b_first = conn.execute(
            "select coalesce(max(build_id), 0) from datapulse.build"
            " where flow_id = %s", (first,),
        ).fetchone()[0]
        b_second = conn.execute(
            "select coalesce(min(build_id), %s) from datapulse.build"
            " where flow_id = %s", (b_first + 1, second),
        ).fetchone()[0]
        assert b_first < b_second


def test_flow_stop(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        flow_id, _ = _launch(conn, "flow()")
        # дождаться живого билда потока и остановить весь поток
        deadline = time.time() + 30
        while time.time() < deadline:
            if _last_flow_status(conn, flow_id) == "exec":
                break
            time.sleep(0.2)
        cur = conn.cursor()
        cur.execute(f"stop flow({flow_id})")
        assert cur.statusmessage == "STOP"
        deadline = time.time() + 30
        while time.time() < deadline:
            if _last_flow_status(conn, flow_id) == "stop":
                break
            time.sleep(0.2)
        assert _last_flow_status(conn, flow_id) == "stop"
        journal = _flow_journal(conn, flow_id)
        assert any(
            row[1] and "остановлен вручную" in row[1] for row in journal
        )
        # билды остановленного потока закрыты (fail получил system-fix);
        # открытых билдов не осталось — следующий поток пройдёт
        deadline = time.time() + 30
        while time.time() < deadline:
            open_builds = conn.execute(
                "select count(*) from datapulse.build b"
                " where (select status_code from datapulse.build_log l"
                "         where l.build_id = b.build_id"
                "         order by build_log_id desc limit 1)"
                "       not in ('done', 'fix')"
            ).fetchone()[0]
            if open_builds == 0:
                break
            time.sleep(0.2)
        assert open_builds == 0
        next_flow, _ = _launch(conn, "flow(intake = pass, export = pass)")
        cur.execute(f"attach flow({next_flow})")
        assert _last_flow_status(conn, next_flow) == "done"


def test_flow_control_errors(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        with pytest.raises(
            psycopg.errors.UndefinedObject, match="не существует"
        ):
            conn.execute("stop flow(999999)")
        with pytest.raises(
            psycopg.errors.UndefinedObject, match="не существует"
        ):
            conn.execute("attach flow(999999)")
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState,
            match="не исполняется",
        ):
            conn.execute("pause flow(999999)")
        done_flow = conn.execute(
            "select max(flow_id) from datapulse.flow"
        ).fetchone()[0]
        with pytest.raises(
            psycopg.errors.ObjectNotInPrerequisiteState, match="уже завершён"
        ):
            conn.execute(f"stop flow({done_flow})")
        with pytest.raises(
            psycopg.errors.UndefinedObject, match="не существует"
        ):
            conn.execute("flow('no_such_preset')")


def test_mart_manual_sees_only_successful_flow(proxy, database):
    # ручной витринный билд строится только на данных последнего
    # успешного потока: межстримовая свежатина для него — грязь
    with _connect(proxy, database, simple=True) as conn:
        border = conn.execute(
            "select max(b.build_id) from datapulse.build b"
            " where b.flow_id in ("
            "   select f.flow_id from datapulse.flow f"
            "   where (select status_code from datapulse.flow_log l"
            "           where l.flow_id = f.flow_id"
            "           order by flow_log_id desc limit 1) = 'done')"
        ).fetchone()[0]
        # межстримовый билд стора — данные свежее границы потока
        conn.execute("truncate public.deal_src")
        conn.execute("insert into public.deal_src values ('x9', 99, true)")
        b_new, _ = _launch(conn, "build('dm.deal', 1, 'increment')")
        assert _wait_final(conn, b_new) == "done"
        assert b_new > border
        # ручная переотправка: to = граница успешного потока — x9 невидим
        b_feed, _ = _launch(conn, "build('dm.feed', 1, 'resend')")
        assert _wait_final(conn, b_feed) == "done"
        journal = _journal_rows(conn, b_feed)
        prints = [r[1] for r in journal if r[0] == "load" and r[1]]
        assert any(f"витрина resend" in p and str(border) in p
                   for p in prints)
        rows = conn.execute(
            "select num from dm.feed_1 where build_id = %s", (b_feed,)
        ).fetchall()
        assert ("x9",) not in rows


def test_mart_initial_recloses_everything(proxy, database):
    # витринный init — «переотдать всё»: закрывает прежние порции и
    # вставляет полный срез одной порцией
    with _connect(proxy, database, simple=True) as conn:
        before = conn.execute(
            "select count(*) from dm.feed_1 where end_build_id is null"
        ).fetchone()[0]
        assert before > 0
        b_init, _ = _launch(conn, "build('dm.feed', 1, 'initial')")
        assert _wait_final(conn, b_init) == "done"
        # все прежние порции закрыты инклюзивно границей b_init - 1
        leftovers = conn.execute(
            "select count(*) from dm.feed_1"
            " where end_build_id is null and build_id != %s",
            (b_init,),
        ).fetchone()[0]
        assert leftovers == 0
        closed = conn.execute(
            "select distinct end_build_id from dm.feed_1"
            " where end_build_id is not null"
        ).fetchall()
        assert (b_init - 1,) in closed


# --- drop datapulse --------------------------------------------------------


def test_drop_datapulse(proxy, database):
    with _connect(proxy, database, simple=True) as conn:
        cur = conn.cursor()
        cur.execute("drop datapulse")
        assert cur.statusmessage == "DROP DATAPULSE"
        names = conn.execute(
            "select nspname from pg_namespace"
            " where nspname in ('datapulse', 'stg', 'ods', 'dm')"
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
            conn.execute(
                "create store dataset stg.dog (x text, primary key (x))"
            )


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
            conn.execute("build('dm.deal', 1, 'initial')")
        with pytest.raises(
            psycopg.errors.InvalidSchemaName, match="не установлен"
        ):
            conn.execute("stop(1)")
        with pytest.raises(
            psycopg.errors.InvalidSchemaName, match="не установлен"
        ):
            conn.execute("flow()")
