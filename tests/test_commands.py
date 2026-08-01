"""Юниты чистых проверок commands.py и engine.py (без БД): статика
спеки, режимная матрица, циклы, топология, синтаксис python-блока,
раннер (процесс-ребёнок), SQL-генерация перелива."""

import datetime
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from datapulse.commands import (
    _check_python_syntax,
    _check_spec_head,
    _check_spec_modes,
    _find_cycle,
)
from datapulse.dpl import DplError, SqlState, match_command
from datapulse.engine import (
    _format_flow_log_row,
    _format_log_row,
    _Job,
    _Plan,
    _sql_bulk_insert,
    _sql_mart_init,
    _sql_merge,
    _topo_datasets,
)


def _spec(query):
    return match_command(query)


def test_check_spec_head_ok():
    command = _spec(
        "create build_spec dm.dog.1 (init mode m)"
        " with (parallel = 4, chunk_attr = x) as python $$x$$"
    )
    parallel_cnt, chunk_attr = _check_spec_head(command)
    assert parallel_cnt == 4
    assert chunk_attr.value.text == "x"


def test_check_spec_head_parallel_default():
    command = _spec(
        "create build_spec dm.dog.1 (init mode m)"
        " with (chunk_attr = x) as python $$x$$"
    )
    parallel_cnt, _ = _check_spec_head(command)
    assert parallel_cnt == 1   # дефолт материализуется


@pytest.mark.parametrize(
    "query, fragment",
    [
        ("create build_spec dm.dog.0 (init mode m)"
         " with (chunk_attr = x) as python $$x$$", "≥ 1"),
        ("create build_spec dm." + "a" * 50 + ".123456789012"
         " (init mode m) with (chunk_attr = x) as python $$x$$",
         "длиннее 63"),
        ("create build_spec dm.dog.1 (init mode m)"
         " with (zzz = 1, chunk_attr = x) as python $$x$$",
         "неизвестная опция"),
        ("create build_spec dm.dog.1 (init mode m)"
         " with (chunk_attr = x, chunk_attr = y) as python $$x$$", "дважды"),
        ("create build_spec dm.dog.1 (init mode m)"
         " with (parallel = 'много', chunk_attr = x) as python $$x$$",
         "целое число"),
        ("create build_spec dm.dog.1 (init mode m)"
         " with (chunk_attr = 'x') as python $$x$$", "без кавычек"),
        ("create build_spec dm.dog.1 (init mode m, incr mode m)"
         " with (chunk_attr = x) as python $$x$$",
         "режим 'm' объявлен дважды"),
        ("create build_spec dm.dog.1 (init mode m)"
         " with (chunk_attr = x) using a, a as python $$x$$",
         "в using дважды"),
        ("create build_spec dm.dog.1 (init mode m)"
         " with (chunk_attr = x) from stg.a, stg.a as python $$x$$",
         "в from дважды"),
    ],
)
def test_check_spec_head_errors(query, fragment):
    with pytest.raises(DplError, match=fragment):
        _check_spec_head(_spec(query))


# --- режимная матрица по подклассу датасета ---------------------------------


@pytest.mark.parametrize(
    "modes, dataset_type",
    [
        ("init mode initial", "store"),
        ("incr mode increment", "store"),
        ("init mode initial, incr mode increment, sect mode allegro",
         "store"),
        ("sect mode increment", "store"),      # increment может быть sect
        ("appd mode increment, skip", "mart"),
        ("appd mode increment, init mode initial, skip, appd mode resend",
         "mart"),
        ("skip", "mart"),                      # витрина «только руками»
    ],
)
def test_check_spec_modes_ok(modes, dataset_type):
    command = _spec(
        f"create build_spec dm.dog.1 ({modes})"
        " with (chunk_attr = x) as python $$x$$"
    )
    _check_spec_modes(command, dataset_type)


@pytest.mark.parametrize(
    "modes, dataset_type, fragment",
    [
        ("appd mode a, init mode initial", "store", "недоступен store"),
        ("skip, init mode initial", "store", "недоступен store"),
        ("incr mode a, skip", "mart", "недоступен mart"),
        ("sect mode a, skip", "mart", "недоступен mart"),
        ("incr mode initial", "store", "тип init"),
        ("init mode increment", "store", "incr | sect"),
        ("init mode increment, skip", "mart", "appd"),
        ("init mode skip, incr mode increment", "store", "имя skip занято"),
        ("sect mode allegro", "store", "initial или increment"),
        ("appd mode increment", "mart", "режим skip"),
        ("appd mode resend, skip", "mart", None),   # без initial/increment — ок
    ],
)
def test_check_spec_modes_errors(modes, dataset_type, fragment):
    command = _spec(
        f"create build_spec dm.dog.1 ({modes})"
        " with (chunk_attr = x) as python $$x$$"
    )
    if fragment is None:
        _check_spec_modes(command, dataset_type)
        return
    with pytest.raises(DplError) as exc_info:
        _check_spec_modes(command, dataset_type)
    assert fragment in exc_info.value.message
    assert exc_info.value.sqlstate == SqlState.INVALID_PARAMETER_VALUE


def test_find_cycle():
    assert _find_cycle({"a": {"b"}, "b": {"c"}}) is None
    assert _find_cycle({"a": {"a"}}) == "a"
    assert _find_cycle({"a": {"b"}, "b": {"c"}, "c": {"a"}}) is not None
    # ребро в узел вне графа (датасет без спек) — не цикл
    assert _find_cycle({"a": {"external"}}) is None


def test_topo_datasets():
    # b читает a, c читает b — порядок a, b, c; d независим (по алфавиту)
    order = _topo_datasets(
        ["dm.c", "dm.a", "dm.b", "dm.d"],
        [("dm.b", "dm.a"), ("dm.c", "dm.b")],
    )
    assert order.index("dm.a") < order.index("dm.b") < order.index("dm.c")
    assert order[0] == "dm.a"   # независимые — лексикографически
    assert set(order) == {"dm.a", "dm.b", "dm.c", "dm.d"}


# --- python: серверная проверка синтаксиса ----------------------------------


def test_python_syntax_ok():
    _check_python_syntax(match_command("python $$\nx = 1\nprint(x)\n$$"))


def test_python_syntax_dedented_like_runner():
    # однострочное тело с ведущим пробелом — dedent спасает, как в раннере
    _check_python_syntax(match_command("python $$ print(1) $$"))


def test_python_syntax_error_position_is_global():
    query = "python $$\nx = 1\ny = )\n$$"
    with pytest.raises(DplError) as exc_info:
        _check_python_syntax(match_command(query))
    assert "синтаксическая ошибка Python" in exc_info.value.message
    assert exc_info.value.sqlstate == SqlState.SYNTAX_ERROR
    # позиция указывает в третью строку тела (y = ))
    assert query[exc_info.value.pos :].startswith(")")


def test_python_syntax_error_indented_body():
    query = "python $$\n    x = 1\n    y = (\n$$"
    with pytest.raises(DplError) as exc_info:
        _check_python_syntax(match_command(query))
    # dedent срезал отступ — позиция всё равно в границах запроса
    assert 0 <= exc_info.value.pos <= len(query)


# --- python: раннер ---------------------------------------------------------


def _run_runner(payload: dict) -> subprocess.CompletedProcess:
    src_dir = str(Path(__file__).resolve().parent.parent / "src")
    env = dict(os.environ)
    env["PYTHONPATH"] = (
        src_dir + os.pathsep + env["PYTHONPATH"]
        if env.get("PYTHONPATH")
        else src_dir
    )
    return subprocess.run(
        [sys.executable, "-m", "datapulse.runner"],
        input=json.dumps(payload).encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,   # как у сервера: единый поток печати
        env=env,
        timeout=60,
    )


def test_runner_prints():
    result = _run_runner(
        {"body": "\nprint('привет')\nprint(1 + 1)\n", "connections": {}}
    )
    assert result.returncode == 0
    assert result.stdout.decode("utf-8").splitlines() == ["привет", "2"]


def test_runner_dedents_single_line_body():
    result = _run_runner({"body": " print('ok') ", "connections": {}})
    assert result.returncode == 0


def test_runner_injects_factories_only():
    body = (
        "\nprint(callable(wh), callable(warehouse))"
        "\nprint(sorted(k for k in globals() if not k.startswith('__')))\n"
    )
    payload = {
        "body": body,
        "connections": {
            "wh": {"class_code": "postgres", "params": {}},
            "warehouse": {"class_code": "postgres", "params": {}},
        },
    }
    result = _run_runner(payload)
    assert result.returncode == 0
    lines = result.stdout.decode("utf-8").splitlines()
    assert lines[0] == "True True"
    # неймспейс голый: кроме фабрик коннектов — ничего
    assert lines[1] == "['warehouse', 'wh']"


def test_runner_exception_traceback_to_stdout():
    result = _run_runner(
        {"body": "\nprint('до')\nraise RuntimeError('бум')\n",
         "connections": {}}
    )
    assert result.returncode != 0
    out = result.stdout.decode("utf-8")
    assert "до" in out
    assert "RuntimeError" in out and "бум" in out


def test_runner_injects_build_params():
    result = _run_runner({
        "body": "\nprint(mode_code, from_build_id, to_build_id,"
                " parallel_cnt)\nprint(previous_time.isoformat())\n",
        "connections": {},
        "params": {
            "mode_code": "increment",
            "from_build_id": 0,
            "to_build_id": 7,
            "previous_time": "2026-07-20T12:00:00+03:00",
            "parallel_cnt": 2,
        },
    })
    assert result.returncode == 0
    lines = result.stdout.decode("utf-8").splitlines()
    assert lines == ["increment 0 7 2", "2026-07-20T12:00:00+03:00"]


# --- engine: SQL перелива ----------------------------------------------------


def _job(type_code="init", parallel=2, dataset_type="store"):
    return _Job(
        database="db",
        build_id=10,
        flow_id=None,
        version_id=5,
        dataset_code="dm.deal",
        dataset_type=dataset_type,
        build_spec_num=1,
        type_code=type_code,
        body="",
        attrs=[
            ("num", 1, "text", True, None),
            ("val", 2, "integer", False, None),
        ],
        chunk_attr_code="num",
        parallel_cnt=parallel,
        connections={},
        params={},
        role_name="dp_build_10",
    )


def test_plan_names_and_columns():
    plan = _Plan(_job())
    assert plan.main == "dm.deal_1"
    assert plan.iface == "dm.deal_1_$"
    assert (plan.schema, plan.table) == ("dm", "deal_1")
    assert plan.insert_columns() == (
        "num, build_id, end_build_id, is_active, val"
    )
    assert plan.chunk_of("t", 1).startswith("(abs(hashtext(t.num::text)")


def test_plan_single_chunk_takes_all():
    plan = _Plan(_job(parallel=1))
    assert plan.chunk_of("t", 1) == "true"


def test_sql_bulk_insert():
    job = _job(type_code="appd", dataset_type="mart")
    [sql] = _sql_bulk_insert(job, _Plan(job), 1)
    assert "insert into dm.deal_1" in sql
    assert "10, null::bigint, t.is_active" in sql
    assert "and t.is_active" in sql


def test_sql_mart_init_closes_then_inserts():
    # витринный init — «переотдать всё»: закрытие прежних порций
    # инклюзивной границей + вставка полного среза (без сравнения)
    job = _job(type_code="init", dataset_type="mart")
    stmts = _sql_mart_init(job, _Plan(job), 1)
    assert stmts[0].startswith("update dm.deal_1 m")
    assert "set end_build_id = 9" in stmts[0]
    assert "m.end_build_id is null" in stmts[0]
    assert "insert into dm.deal_1" in stmts[1]


def test_sql_merge_init_full_join_and_inclusive_close():
    job = _job(type_code="init")
    stmts = _sql_merge(job, _Plan(job), 1)
    assert stmts[0].startswith("create temporary table result")
    assert "full join target" in stmts[0]
    assert "rn$" not in stmts[0]
    # end_build_id ИНКЛЮЗИВНЫЙ: закрытие — build_id - 1
    close = stmts[4]
    assert "set end_build_id = 9" in close
    assert "m.ctid = t.ctid_" in close


def test_sql_merge_incr_left_join():
    job = _job(type_code="incr")
    assert "left join target" in _sql_merge(job, _Plan(job), 1)[0]


def test_sql_merge_sect_narrows_to_sections():
    job = _job(type_code="sect")
    result = _sql_merge(job, _Plan(job), 1)[0]
    assert "rn$" in result
    assert "r.num = t.num" in result


def test_format_log_row():
    when = datetime.datetime(2026, 7, 20, 18, 30, 5)
    assert _format_log_row(
        (1, when, "wait", None, None, None, None, None)
    ) == "#1 2026-07-20 18:30:05 wait"
    assert _format_log_row(
        (3, when, "comp", None, 1000, None, None, None)
    ) == "#3 2026-07-20 18:30:05 comp | подготовлено: 1000"
    assert _format_log_row(
        (4, when, "done", None, None, 900, 50, 10)
    ) == ("#4 2026-07-20 18:30:05 done | вставлено: 900, обновлено: 50,"
          " удалено: 10")
    assert _format_log_row(
        (2, when, "load", "печать тела", None, None, None, None)
    ) == "#2 2026-07-20 18:30:05 load | печать тела"


def test_format_flow_log_row():
    when = datetime.datetime(2026, 7, 20, 18, 30, 5)
    assert _format_flow_log_row(
        (1, when, "wait", "поток создан и ждёт очереди")
    ) == "#1 2026-07-20 18:30:05 wait | поток создан и ждёт очереди"
    assert _format_flow_log_row((2, when, "done", None)) == (
        "#2 2026-07-20 18:30:05 done"
    )
