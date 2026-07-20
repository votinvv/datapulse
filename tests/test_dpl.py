"""Юниты распознавания и разбора DPL."""

import pytest

from datapulse.dpl import (
    AlterDatapulseAdd,
    AttachCall,
    BuildCall,
    CommentOnAttr,
    CommentOnDatapulse,
    CommentOnDataset,
    CreateBuildSpec,
    CreateConnection,
    CreateDatapulse,
    CreateDataset,
    DatasetAttr,
    DplError,
    DropBuildSpec,
    DropDatapulse,
    DropDataset,
    FixCall,
    PythonBlock,
    SqlState,
    StopCall,
    TestConnection,
    is_dpl_text,
    match_command,
    split_statements,
)

# --- распознавание: что DPL, а что релей ----------------------------------


@pytest.mark.parametrize(
    "query",
    [
        "select 1",
        "create table t (n int)",
        "drop schema stg cascade",
        "create datapulse (stg); select 1",   # мульти-стейтмент — релей
        "begin; create datapulse (stg); commit",
        "",
        "-- комментарий",
        "create or replace view v as select 1",
        "create or replace function f() returns int language sql"
        " as 'select 1'",
        "drop table dm.dog",
        "comment on table t is 'x'",
        "comment on column t.c is 'x'",
        "alter table t add column n int",
        "alter system set work_mem = '64MB'",
    ],
)
def test_not_dpl(query):
    assert match_command(query) is None


def test_create():
    command = match_command("create datapulse (stg)")
    assert command == CreateDatapulse(schemas=["stg"])


def test_create_many_with_noise():
    command = match_command(
        "/* x */ CREATE  Datapulse ( stg ,\n ods , dm );  -- хвост"
    )
    assert command == CreateDatapulse(schemas=["stg", "ods", "dm"])


def test_drop():
    assert match_command("  drop datapulse ;") == DropDatapulse()


# --- create [or replace] dataset -------------------------------------------


def test_create_dataset():
    command = match_command(
        "create dataset dm.dog (agreement_number text, open_date timestamp,"
        " amount numeric(18,2), primary key (agreement_number))"
    )
    assert isinstance(command, CreateDataset)
    assert command.dataset_code == "dm.dog"
    assert command.or_replace is False
    assert command.attrs == [
        DatasetAttr("agreement_number", "text", True),
        DatasetAttr("open_date", "timestamp", False),
        DatasetAttr("amount", "numeric(18,2)", False),
    ]


def test_create_or_replace_dataset():
    command = match_command(
        "CREATE OR REPLACE DATASET stg.cat (x integer, primary key (x))"
    )
    assert isinstance(command, CreateDataset)
    assert command.or_replace is True
    assert command.attrs == [DatasetAttr("x", "integer", True)]


def test_create_dataset_composite_key_and_numeric_forms():
    command = match_command(
        "create dataset dm.acct (a text, b numeric, c numeric(10),"
        " d numeric(10,0), primary key (a, b))"
    )
    assert command.attrs == [
        DatasetAttr("a", "text", True),
        DatasetAttr("b", "numeric", True),
        DatasetAttr("c", "numeric(10)", False),
        DatasetAttr("d", "numeric(10,0)", False),
    ]


def test_create_dataset_code_pos_is_global():
    query = "/* x */ create dataset dm.dog (a text, primary key (a))"
    command = match_command(query)
    assert query[command.code_pos :].startswith("dm.dog")


@pytest.mark.parametrize(
    "query, fragment",
    [
        ("create dataset dog (x text, primary key (x))", "'.'"),
        ("create dataset dm.dog2 (x text, primary key (x))", "цифрой"),
        ("create dataset dm." + "a" * 51 + " (x text, primary key (x))",
         "длиннее 50"),
        ("create dataset dm.dog (x text)", "PRIMARY KEY обязателен"),
        ("create dataset dm.dog (primary key (x), y text)", "последним"),
        ("create dataset dm.dog (x text, primary key (x), primary key (x))",
         "дважды"),
        ("create dataset dm.dog (x text, y text, primary key (z))",
         "не объявлен"),
        ("create dataset dm.dog (x text, primary key (x, x))",
         "в ключе дважды"),
        ("create dataset dm.dog (x text, x integer, primary key (x))",
         "объявлен дважды"),
        ("create dataset dm.dog (build_id text, primary key (build_id))",
         "служебной колонкой"),
        ("create dataset dm.dog (select text, primary key (select))",
         "ключевое слово"),
        ("create dataset dm.dog (" + "a" * 64 + " text, primary key (x))",
         "длиннее 63"),
        ("create dataset dm.dog (x blob, primary key (x))", "неизвестный тип"),
        ("create dataset dm.dog (x, primary key (x))", "тип атрибута"),
        ("create dataset dm.dog (x numeric(0), primary key (x))", "точность"),
        ("create dataset dm.dog (x numeric(5,6), primary key (x))", "масштаб"),
        ("create dataset dm.dog (x text, primary key (x)) hvost",
         "лишний текст"),
        ("create or replace datapulse (stg)", "неприменим"),
    ],
)
def test_dataset_syntax_errors(query, fragment):
    with pytest.raises(DplError) as exc_info:
        match_command(query)
    assert fragment in exc_info.value.message
    assert exc_info.value.sqlstate == SqlState.SYNTAX_ERROR


def test_dataset_error_position_is_global():
    query = "  /* привет */  create dataset dm.dog (x text)"
    with pytest.raises(DplError) as exc_info:
        match_command(query)
    assert query[exc_info.value.pos :].startswith("dm.dog")


# --- drop dataset ----------------------------------------------------------


def test_drop_dataset():
    command = match_command("/* x */ DROP DATASET dm.Dog ;")
    assert isinstance(command, DropDataset)
    assert command.dataset_code == "dm.dog"


def test_drop_dataset_code_pos_is_global():
    query = "-- к\ndrop dataset dm.dog"
    command = match_command(query)
    assert query[command.code_pos :].startswith("dm.dog")


@pytest.mark.parametrize(
    "query, fragment",
    [
        ("drop dataset", "код датасета"),
        ("drop dataset dog", "'.'"),
        ("drop dataset dm.", "имя датасета после точки"),
        ("drop dataset dm.dog cascade", "лишний текст"),
    ],
)
def test_drop_dataset_syntax_errors(query, fragment):
    with pytest.raises(DplError) as exc_info:
        match_command(query)
    assert fragment in exc_info.value.message
    assert exc_info.value.sqlstate == SqlState.SYNTAX_ERROR


# --- comment on ------------------------------------------------------------


def test_comment_on_datapulse():
    command = match_command("COMMENT ON DATAPULSE IS 'описание установки'")
    assert command == CommentOnDatapulse(comment="описание установки")


def test_comment_on_datapulse_null():
    assert match_command("comment on datapulse is null") == CommentOnDatapulse(
        comment=None
    )


def test_comment_on_dataset():
    command = match_command("comment on dataset dm.dog is 'о''кей'")
    assert isinstance(command, CommentOnDataset)
    assert command.dataset_code == "dm.dog"
    assert command.comment == "о'кей"


def test_comment_on_dataset_null():
    command = match_command("comment on dataset dm.dog is null")
    assert command.comment is None


def test_comment_on_attr():
    command = match_command("comment on attr rbs.maina.uno is 'первый'")
    assert isinstance(command, CommentOnAttr)
    assert command.dataset_code == "rbs.maina"
    assert command.attr_name == "uno"
    assert command.comment == "первый"


def test_comment_on_attr_null():
    command = match_command("COMMENT ON ATTR rbs.maina.uno IS NULL")
    assert command == CommentOnAttr(
        dataset_code="rbs.maina",
        attr_name="uno",
        code_pos=16,
        attr_pos=26,
        comment=None,
    )


@pytest.mark.parametrize(
    "query, fragment",
    [
        ("comment on datapulse 'x'", "IS"),
        ("comment on datapulse is", "кавычках либо NULL"),
        ("comment on datapulse is 42", "кавычках либо NULL"),
        ("comment on dataset dog is 'x'", "'.'"),
        ("comment on datapulse is 'x' y", "лишний текст"),
        ("comment on datapulse is 'незакрытая", "не закрыт"),
        ("comment on attr rbs.maina is 'x'", "'.'"),
        ("comment on attr rbs.maina.", "имя атрибута после точки"),
    ],
)
def test_comment_syntax_errors(query, fragment):
    with pytest.raises(DplError) as exc_info:
        match_command(query)
    assert fragment in exc_info.value.message
    assert exc_info.value.sqlstate == SqlState.SYNTAX_ERROR


# --- create [or replace] / drop build_spec ----------------------------------


def test_create_build_spec():
    command = match_command(
        "create or replace build_spec dm.dog.1 ("
        "  clear init mode initial"
        ", dirty incr mode manual"
        ") with (parallel = 16, chunk_attr = agreement_number)"
        "  using rbs, cft"
        "  as python $$ with rbs() as v_rbs: ... $$"
    )
    assert isinstance(command, CreateBuildSpec)
    assert command.dataset_code == "dm.dog"
    assert command.build_spec_num == 1
    assert command.or_replace is True
    assert [(m.mode_code, m.type_code, m.is_clear) for m in command.modes] == [
        ("initial", "init", True),
        ("manual", "incr", False),
    ]
    assert {o.name: (o.value.kind, o.value.text) for o in command.options} == {
        "parallel": ("number", "16"),
        "chunk_attr": ("ident", "agreement_number"),
    }
    assert [n.name for n in command.using] == ["rbs", "cft"]
    assert command.sources == []
    assert command.body == " with rbs() as v_rbs: ... "


def test_create_build_spec_from():
    command = match_command(
        "create build_spec dm.dog.2 (dirty sect mode s)"
        " with (chunk_attr = x) from stg.a, ods.b as python $$x$$"
    )
    assert command.or_replace is False
    assert command.using == []
    assert [n.name for n in command.sources] == ["stg.a", "ods.b"]


def test_create_build_spec_generator():
    command = match_command(
        "create build_spec dm.dog.3 (clear appd mode a)"
        " with (chunk_attr = x) as python $$gen$$"
    )
    assert command.using == [] and command.sources == []


def test_drop_build_spec():
    command = match_command("drop build_spec dm.dog.1;")
    assert command == DropBuildSpec(
        dataset_code="dm.dog", build_spec_num=1, code_pos=16
    )


@pytest.mark.parametrize(
    "query, fragment",
    [
        ("create build_spec dm.dog (clear init mode m)"
         " with (chunk_attr = x) as python $$x$$", "'.'"),
        ("create build_spec dm.dog.1 (clear init mode m) as python $$x$$", "WITH"),
        ("create build_spec dm.dog.1 (clear init mode m)"
         " with (chunk_attr = x) using a from b.c as python $$x$$",
         "взаимоисключающи"),
        ("create build_spec dm.dog.1 (clear init mode m)"
         " with (chunk_attr = x)", "AS"),
        ("create build_spec dm.dog.1 (clear init mode m)"
         " with (chunk_attr = x) as $$x$$", "PYTHON"),
        ("create build_spec dm.dog.1 (clear init mode m)"
         " with (chunk_attr = x) as python 'тело'", "тело $$…$$"),
        ("create build_spec dm.dog.1 (clear init mode m)"
         " with (chunk_attr = x) as python $$незакрыто", "завершающего"),
        ("create build_spec dm.dog.1 (clear foo mode m)"
         " with (chunk_attr = x) as python $$x$$", "INCR"),
        ("create build_spec dm.dog.1 (clear init m)"
         " with (chunk_attr = x) as python $$x$$", "MODE"),
        ("create build_spec dm.dog.1 (init mode m)"
         " with (chunk_attr = x) as python $$x$$", "CLEAR | DIRTY"),
        ("drop build_spec dm.dog", "'.'"),
        ("drop build_spec dm.dog.1 cascade", "лишний текст"),
    ],
)
def test_build_spec_syntax_errors(query, fragment):
    with pytest.raises(DplError) as exc_info:
        match_command(query)
    assert fragment in exc_info.value.message
    assert exc_info.value.sqlstate == SqlState.SYNTAX_ERROR


# --- alter datapulse --------------------------------------------------------


def test_alter_datapulse_add():
    command = match_command("ALTER DATAPULSE ADD mart ;")
    assert isinstance(command, AlterDatapulseAdd)
    assert command.schema == "mart"


@pytest.mark.parametrize(
    "query, fragment",
    [
        ("alter datapulse", "ADD"),
        ("alter datapulse drop stg", "ADD"),
        ("alter datapulse add", "имя схемы данных"),
        ("alter datapulse add public", "зарезервировано"),
        ("alter datapulse add " + "a" * 64, "длиннее 63"),
        ("alter datapulse add mart, ods", "лишний текст"),
    ],
)
def test_alter_syntax_errors(query, fragment):
    with pytest.raises(DplError) as exc_info:
        match_command(query)
    assert fragment in exc_info.value.message
    assert exc_info.value.sqlstate == SqlState.SYNTAX_ERROR


# --- create [or replace] *_connection / test --------------------------------


def test_create_oracle_connection():
    command = match_command(
        "create oracle_connection rbs with (host_name = 'db.rbs.ru',"
        " service_name = 'RBS', user_name = 'ext', password = 'p''w')"
    )
    assert isinstance(command, CreateConnection)
    assert command.class_code == "oracle_connection"
    assert command.name == "rbs"
    assert command.or_replace is False
    fields = {f.name: (f.value.kind, f.value.text) for f in command.fields}
    assert fields == {
        "host_name": ("string", "db.rbs.ru"),
        "service_name": ("string", "RBS"),
        "user_name": ("string", "ext"),
        "password": ("string", "p'w"),
    }


def test_create_or_replace_postgres_connection():
    command = match_command(
        "CREATE OR REPLACE postgres_connection wh WITH"
        " (host_name = 'h', port_num = 5433, database_name = 'd',"
        "  user_name = 'u', password = 'p')"
    )
    assert isinstance(command, CreateConnection)
    assert command.class_code == "postgres_connection"
    assert command.or_replace is True
    port = next(f for f in command.fields if f.name == "port_num")
    assert (port.value.kind, port.value.text) == ("number", "5433")


def test_test_connection():
    command = match_command("test rbs")
    assert isinstance(command, TestConnection)
    assert command.name == "rbs"


@pytest.mark.parametrize(
    "query, fragment",
    [
        ("create oracle_connection rbs (host_name = 'h')", "WITH"),
        ("create oracle_connection rbs with ()", "поле коннекта"),
        ("create oracle_connection rbs with (host_name 'h')", "'='"),
        ("create oracle_connection rbs with (host_name = )", "значение"),
        ("test", "имя коннекта"),
        ("test rbs x", "лишний текст"),
    ],
)
def test_connection_syntax_errors(query, fragment):
    with pytest.raises(DplError) as exc_info:
        match_command(query)
    assert fragment in exc_info.value.message
    assert exc_info.value.sqlstate == SqlState.SYNTAX_ERROR


# --- python -----------------------------------------------------------------


def test_python_block():
    query = "PYTHON $$\nprint('привет')\n$$"
    command = match_command(query)
    assert isinstance(command, PythonBlock)
    assert command.body == "\nprint('привет')\n"
    assert query[command.body_pos :].startswith("\nprint")


def test_python_block_tagged_body():
    command = match_command("python $py$ print(1) $$ (2) $py$")
    assert isinstance(command, PythonBlock)
    assert command.body == " print(1) $$ (2) "


def test_python_is_routed():
    assert is_dpl_text("python $$ 1 $$")


def test_do_is_relayed():
    # do затенил бы анонимный блок Postgres — команда названа python
    assert match_command("do $$ begin null; end $$") is None
    assert match_command("DO LANGUAGE plpgsql $$ begin null; end $$") is None


@pytest.mark.parametrize(
    "query, fragment",
    [
        ("python", "тело $$…$$"),
        ("python 'print(1)'", "тело $$…$$"),
        ("python $$ x = 1 $$ hvost", "лишний текст"),
        ("python $$ x = 1", "не закрыто"),
    ],
)
def test_python_syntax_errors(query, fragment):
    with pytest.raises(DplError) as exc_info:
        match_command(query)
    assert fragment in exc_info.value.message
    assert exc_info.value.sqlstate == SqlState.SYNTAX_ERROR


def test_python_keyword_forbidden_as_attr():
    with pytest.raises(DplError, match="ключевое слово"):
        match_command(
            "create dataset dm.dog (python text, primary key (python))"
        )


# --- build / attach / stop / fix -------------------------------------------


def test_build_call():
    query = "build('dm.dog', 1, 'initial');"
    command = match_command(query)
    assert command == BuildCall(
        dataset_code="dm.dog",
        code_pos=query.index("'dm.dog'"),
        build_spec_num=1,
        num_pos=query.index("1"),
        mode_code="initial",
        mode_pos=query.index("'initial'"),
    )


def test_build_call_lowers_literals():
    command = match_command("BUILD ( 'DM.Dog' , 7 , 'Manual' )")
    assert command.dataset_code == "dm.dog"
    assert command.mode_code == "manual"
    assert command.build_spec_num == 7


def test_attach_call():
    assert match_command("attach(42)") == AttachCall(
        build_id=42, id_pos=7, from_log_id=0
    )
    command = match_command("attach(42, 1000)")
    assert (command.build_id, command.from_log_id) == (42, 1000)


def test_stop_and_fix_calls():
    assert match_command("stop(42)") == StopCall(build_id=42, id_pos=5)
    assert match_command("fix(42)") == FixCall(build_id=42, id_pos=4)


@pytest.mark.parametrize(
    "query, fragment",
    [
        ("build", "'('"),
        ("build(dm.dog, 1, 'm')", "строкой"),
        ("build('dog', 1, 'm')", "не 'схема.имя'"),
        ("build('dm.dog', 'x', 'm')", "номер спеки"),
        ("build('dm.dog', 1, m)", "строкой"),
        ("build('dm.dog', 1, '1x')", "не идентификатор"),
        ("build('dm.dog', 1, 'm') x", "лишний текст"),
        ("attach()", "номер билда"),
        ("attach(42, x)", "позиция журнала"),
        ("stop()", "номер билда"),
        ("stop(42, 1)", "')'"),
        ("fix('42')", "номер билда"),
    ],
)
def test_build_call_syntax_errors(query, fragment):
    with pytest.raises(DplError) as exc_info:
        match_command(query)
    assert fragment in exc_info.value.message
    assert exc_info.value.sqlstate == SqlState.SYNTAX_ERROR


def test_build_commands_are_routed():
    for query in ("build('dm.dog', 1, 'm')", "attach(1)", "stop(1)", "fix(1)"):
        assert is_dpl_text(query)


# --- синтаксические ошибки -------------------------------------------------


@pytest.mark.parametrize(
    "query, fragment",
    [
        ("create datapulse", "список схем"),
        ("create datapulse ()", "хотя бы одну"),
        ("create datapulse (stg,)", "идентификатор схемы"),
        ("create datapulse (stg ods)", "','"),
        ("create datapulse (stg)(", "лишний текст"),
        ("drop datapulse now", "лишний текст"),
        ("create datapulse (stg, stg)", "дважды"),
        ("create datapulse (public)", "зарезервировано"),
        ("create datapulse (datapulse)", "зарезервировано"),
        ("create datapulse (pg_temp)", "зарезервировано"),
        ("create datapulse (" + "a" * 64 + ")", "длиннее 63"),
    ],
)
def test_syntax_errors(query, fragment):
    with pytest.raises(DplError) as exc_info:
        match_command(query)
    assert fragment in exc_info.value.message
    assert exc_info.value.sqlstate == SqlState.SYNTAX_ERROR


def test_error_position_is_global():
    query = "  /* привет */  create datapulse (stg,)"
    with pytest.raises(DplError) as exc_info:
        match_command(query)
    assert query[exc_info.value.pos] == ")"


# --- is_dpl_text (перехват в extended) -------------------------------------


@pytest.mark.parametrize(
    "query, expected",
    [
        ("create datapulse (x)", True),
        ("DROP DATAPULSE", True),
        ("create dataset dm.dog (x text, primary key (x))", True),
        ("create or replace dataset dm.dog (x text, primary key (x))", True),
        ("drop dataset dm.dog", True),
        ("create build_spec dm.dog.1 (clear init mode m)"
         " with (chunk_attr = x) as python $$x$$", True),
        ("drop build_spec dm.dog.1", True),
        ("comment on datapulse is 'x'", True),
        ("comment on dataset dm.dog is null", True),
        ("comment on attr dm.dog.x is 'x'", True),
        ("create oracle_connection rbs with (host_name = 'h')", True),
        ("test rbs", True),
        ("alter datapulse add mart", True),
        ("testing = off", False),
        ("alter table datapulse add column n int", False),
        ("create table t (n int)", False),
        ("create or replace view v as select 1", False),
        ("drop table datapulse", False),
        ("comment on table t is 'x'", False),
        ("select 1", False),
    ],
)
def test_is_dpl_text(query, expected):
    assert is_dpl_text(query) is expected


# --- сплиттер --------------------------------------------------------------


def test_split_respects_quotes_and_comments():
    query = (
        "select ';' as a; -- x;\n"
        "select $tag$ ; $tag$; select e'\\';' /* ; /* ; */ ; */; select 2"
    )
    statements = split_statements(query)
    assert len(statements) == 4
    assert statements[3].text.strip() == "select 2"
    assert query[statements[3].offset :].lstrip().startswith("select 2")
