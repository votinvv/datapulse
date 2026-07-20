"""DPL: распознавание, лексика и разбор команд платформы.

Перехватываются только команды закрытого списка — create/drop/comment
on над объектами платформы (datapulse, dataset, attr, коннекты), test
и python — и только когда
запрос — ровно один стейтмент; весь прочий трафик прокси пробрасывает в
Postgres как есть. Сплиттер режет по `;` лексикой-надмножеством
Postgres (кавычки, E-строки, dollar-quoting, вложенные блочные
комментарии): резать пробрасываемый SQL надо по правилам Postgres.
Строгая лексика DPL (tokenize) применяется уже к перехваченному
стейтменту.

Позиция ошибки (`DplError.pos`) — смещение в символах (0-based) в
тексте запроса целиком; релей пересчитывает её в поле position
ErrorResponse и строку/колонку в сообщении.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class SqlState:
    """SQLSTATE-коды, используемые прокси (словарь Postgres)."""

    SYNTAX_ERROR = "42601"
    DUPLICATE_SCHEMA = "42P06"
    DUPLICATE_OBJECT = "42710"
    UNDEFINED_OBJECT = "42704"
    INVALID_SCHEMA_NAME = "3F000"
    INVALID_PARAMETER_VALUE = "22023"
    OBJECT_NOT_IN_PREREQUISITE_STATE = "55000"
    DEPENDENT_OBJECTS = "2BP01"
    FEATURE_NOT_SUPPORTED = "0A000"
    ACTIVE_SQL_TRANSACTION = "25001"
    CONNECTION_FAILURE = "08001"
    EXTERNAL_ERROR = "38000"
    QUERY_CANCELED = "57014"
    INTERNAL_ERROR = "XX000"


class DplError(Exception):
    """Одна ошибка платформы с позицией в тексте запроса."""

    def __init__(
        self,
        message: str,
        *,
        pos: int | None = None,
        hint: str | None = None,
        sqlstate: str = SqlState.SYNTAX_ERROR,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.pos = pos
        self.hint = hint
        self.sqlstate = sqlstate


def line_col(text: str, pos: int) -> tuple[int, int]:
    """Строка и колонка (1-based) для смещения pos в тексте."""
    line = text.count("\n", 0, pos) + 1
    last_nl = text.rfind("\n", 0, pos)
    col = pos - last_nl if last_nl >= 0 else pos + 1
    return line, col


# --- разрезание на стейтменты (лексика-надмножество Postgres) ------------


@dataclass(frozen=True)
class RawStatement:
    text: str      # текст стейтмента без завершающего ';'
    offset: int    # смещение (в символах) начала в исходной строке запроса


_DOLLAR_TAG_RE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)?\$")


def split_statements(query: str) -> list[RawStatement]:
    """Режет строку запроса на стейтменты по `;` вне кавычек и комментариев.

    Пустые сегменты (пробелы/комментарии) опускаются. Ошибок не бросает:
    незакрытая кавычка дотягивает сегмент до конца строки — строгую
    диагностику даёт парсер конкретной команды либо Postgres.
    """
    statements: list[RawStatement] = []
    start = 0
    i = 0
    n = len(query)
    while i < n:
        ch = query[i]
        if ch == ";":
            _append_segment(statements, query, start, i)
            i += 1
            start = i
        elif ch == "'" or (ch in "eEbBxX" and i + 1 < n and query[i + 1] == "'"):
            # обычная либо E/B/X-строка; в E-строке действует backslash
            escaped = ch in "eE"
            if ch != "'":
                i += 1
            i = _skip_quoted(query, i + 1, "'", backslash=escaped)
        elif ch == '"':
            i = _skip_quoted(query, i + 1, '"', backslash=False)
        elif ch == "$":
            match = _DOLLAR_TAG_RE.match(query, i)
            if match:
                closing = match.group(0)
                end = query.find(closing, match.end())
                i = n if end < 0 else end + len(closing)
            else:
                i += 1
        elif ch == "-" and query.startswith("--", i):
            end = query.find("\n", i)
            i = n if end < 0 else end + 1
        elif ch == "/" and query.startswith("/*", i):
            i = _skip_block_comment(query, i)
        else:
            i += 1
    _append_segment(statements, query, start, n)
    return statements


def _append_segment(out: list[RawStatement], query: str, start: int, end: int) -> None:
    segment = query[start:end]
    if _has_content(segment):
        out.append(RawStatement(text=segment, offset=start))


def _has_content(segment: str) -> bool:
    """Есть ли в сегменте что-то кроме пробелов и комментариев."""
    return _skip_blank(segment, 0) < len(segment)


def _skip_blank(text: str, i: int) -> int:
    """Пропускает пробелы и комментарии начиная с позиции i."""
    n = len(text)
    while i < n:
        ch = text[i]
        if ch.isspace():
            i += 1
        elif text.startswith("--", i):
            end = text.find("\n", i)
            i = n if end < 0 else end + 1
        elif text.startswith("/*", i):
            i = _skip_block_comment(text, i)
        else:
            break
    return i


def _skip_quoted(text: str, i: int, quote: str, *, backslash: bool) -> int:
    n = len(text)
    while i < n:
        ch = text[i]
        if backslash and ch == "\\":
            i += 2
        elif ch == quote:
            if i + 1 < n and text[i + 1] == quote:  # удвоение кавычки
                i += 2
            else:
                return i + 1
        else:
            i += 1
    return n


def _skip_block_comment(text: str, i: int) -> int:
    """Вложенные блочные комментарии — как в Postgres; незакрытый
    дотягивается до конца текста."""
    n = len(text)
    depth = 0
    while i < n:
        if text.startswith("/*", i):
            depth += 1
            i += 2
        elif text.startswith("*/", i):
            depth -= 1
            i += 2
            if depth == 0:
                return i
        else:
            i += 1
    return n


# --- строгая токенизация DPL ----------------------------------------------


class TokKind(Enum):
    IDENT = "идентификатор"
    NUMBER = "число"
    STRING = "строка"
    BODY = "тело $$…$$"
    PUNCT = "знак"
    END = "конец стейтмента"


@dataclass(frozen=True)
class Token:
    kind: TokKind
    value: str     # идентификаторы — в нижнем регистре; строки — без кавычек
    pos: int       # смещение в тексте стейтмента


_WORD_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_NUMBER_RE = re.compile(r"[0-9]+")

# ключевые слова DPL (включая будущие команды) — запрещены как имена
# атрибутов датасета: имя, легальное сегодня, не должно сломаться завтра
KEYWORDS = frozenset(
    """
    create or replace drop clear comment on is null attr test alter add
    datapulse dataset build_spec
    oracle_connection postgres_connection
    primary key with using from as mode
    dirty init incr sect appd skip
    text integer bigint numeric boolean date timestamp timestamptz
    select do python build attach stop fix
    set reset show begin commit rollback
    """.split()
)


def tokenize(text: str, base: int = 0) -> list[Token]:
    """Токены строгой лексики DPL; ошибки — DplError с позицией.

    base — смещение стейтмента в тексте запроса: все позиции (токенов
    и ошибок) сразу глобальные, отдельного пересчёта нет.
    """
    tokens: list[Token] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch.isspace():
            i += 1
        elif text.startswith("--", i):
            end = text.find("\n", i)
            i = n if end < 0 else end + 1
        elif text.startswith("/*", i):
            i = _skip_block_comment(text, i)
        elif match := _WORD_RE.match(text, i):
            tokens.append(Token(TokKind.IDENT, match.group(0).lower(), base + i))
            i = match.end()
        elif match := _NUMBER_RE.match(text, i):
            tokens.append(Token(TokKind.NUMBER, match.group(0), base + i))
            i = match.end()
        elif ch == "'":
            value, end = _read_string(text, i, base)
            tokens.append(Token(TokKind.STRING, value, base + i))
            i = end
        elif ch == "$":
            match = _DOLLAR_TAG_RE.match(text, i)
            if not match:
                raise DplError(
                    "ожидался тег dollar-quoting ($$ или $тег$)", pos=base + i
                )
            closing = match.group(0)
            end = text.find(closing, match.end())
            if end < 0:
                raise DplError(
                    f"тело не закрыто: нет завершающего {closing}", pos=base + i
                )
            tokens.append(
                Token(TokKind.BODY, text[match.end() : end], base + match.end())
            )
            i = end + len(closing)
        elif ch in "(),.=;":
            tokens.append(Token(TokKind.PUNCT, ch, base + i))
            i += 1
        else:
            raise DplError(f"неожиданный символ {ch!r}", pos=base + i)
    tokens.append(Token(TokKind.END, "", base + n))
    return tokens


def _read_string(text: str, i: int, base: int = 0) -> tuple[str, int]:
    """Строковый литерал '...'; кавычка внутри удваивается."""
    start = i
    i += 1
    parts: list[str] = []
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "'":
            if i + 1 < n and text[i + 1] == "'":
                parts.append("'")
                i += 2
            else:
                return "".join(parts), i + 1
        else:
            parts.append(ch)
            i += 1
    raise DplError("строковый литерал не закрыт", pos=base + start)


# --- команды (AST) ---------------------------------------------------------


@dataclass(frozen=True)
class CreateDatapulse:
    schemas: list[str]     # объявленные схемы данных, в порядке команды


@dataclass(frozen=True)
class DropDatapulse:
    pass


@dataclass(frozen=True)
class DatasetAttr:
    name: str
    type_code: str         # канонический: 'text', 'numeric(18,2)', …
    is_primary: bool


@dataclass(frozen=True)
class CreateDataset:
    dataset_code: str      # 'схема.имя'
    code_pos: int          # позиция кода датасета в тексте запроса
    or_replace: bool
    attrs: list[DatasetAttr]   # в порядке объявления (order_num = индекс+1)


@dataclass(frozen=True)
class DropDataset:
    dataset_code: str
    code_pos: int


@dataclass(frozen=True)
class CommentOnDatapulse:
    comment: str | None    # None — снять описание (is null)


@dataclass(frozen=True)
class CommentOnDataset:
    dataset_code: str
    code_pos: int
    comment: str | None


@dataclass(frozen=True)
class CommentOnAttr:
    dataset_code: str
    attr_name: str
    code_pos: int          # позиция кода датасета (схема)
    attr_pos: int          # позиция имени атрибута
    comment: str | None


@dataclass(frozen=True)
class Value:
    """Значение в присваивании: строка, число или голый идентификатор."""

    kind: str      # 'string' | 'number' | 'ident'
    text: str
    pos: int


@dataclass(frozen=True)
class FieldAssign:
    """`имя = значение` в with-секциях."""

    name: str
    name_pos: int
    value: Value


@dataclass(frozen=True)
class CreateConnection:
    class_code: str        # oracle_connection | postgres_connection
    name: str
    name_pos: int
    or_replace: bool
    fields: list[FieldAssign]


@dataclass(frozen=True)
class TestConnection:
    __test__ = False   # pytest: не коллекционировать как тест-класс

    name: str
    name_pos: int


@dataclass(frozen=True)
class AlterDatapulseAdd:
    schema: str        # новая схема данных
    schema_pos: int


@dataclass(frozen=True)
class PythonBlock:
    """python $$…$$ — отладочный прогон инженерного кода.

    Имя команды — python, не do: грамматика `do $$…$$` байт в байт
    совпадает с анонимным блоком Postgres (DO $$…$$), а прозрачный
    прокси не должен затенять живые стейтменты бэкенда.
    """

    body: str
    body_pos: int      # позиция начала тела в тексте запроса


@dataclass(frozen=True)
class Named:
    """Имя с позицией (коннект в using, датасет в from)."""

    name: str
    pos: int


@dataclass(frozen=True)
class ModeDecl:
    mode_code: str
    mode_pos: int
    type_code: str     # init | incr | sect | appd | skip
    is_clear: bool


@dataclass(frozen=True)
class CreateBuildSpec:
    dataset_code: str
    build_spec_num: int
    code_pos: int
    or_replace: bool
    modes: list[ModeDecl]
    options: list[FieldAssign]     # with-опции: parallel, chunk_attr
    using: list[Named]             # коннекты (загрузчик)
    sources: list[Named]           # датасеты-источники (трансформер)
    body: str
    body_pos: int


@dataclass(frozen=True)
class DropBuildSpec:
    dataset_code: str
    build_spec_num: int
    code_pos: int


@dataclass(frozen=True)
class BuildCall:
    """build('схема.имя', номер, 'режим') — асинхронный запуск билда."""

    dataset_code: str
    code_pos: int
    build_spec_num: int
    num_pos: int
    mode_code: str
    mode_pos: int


@dataclass(frozen=True)
class AttachCall:
    """attach(build_id [, позиция]) — живой хвост журнала билда."""

    build_id: int
    id_pos: int
    from_log_id: int    # 0 — с начала журнала


@dataclass(frozen=True)
class StopCall:
    """stop(build_id) — запрос остановки билда."""

    build_id: int
    id_pos: int


@dataclass(frozen=True)
class FixCall:
    """fix(build_id) — упавший билд разобран, финал вручную."""

    build_id: int
    id_pos: int


Command = (
    CreateDatapulse
    | DropDatapulse
    | CreateDataset
    | DropDataset
    | CreateBuildSpec
    | DropBuildSpec
    | CommentOnDatapulse
    | CommentOnDataset
    | CommentOnAttr
    | CreateConnection
    | TestConnection
    | AlterDatapulseAdd
    | PythonBlock
    | BuildCall
    | AttachCall
    | StopCall
    | FixCall
)

IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# имена, запрещённые как схемы данных
RESERVED_SCHEMAS = frozenset({"datapulse", "public", "information_schema"})

# служебные колонки SCD2 таблиц данных и функции датасета — заняты движком
RESERVED_ATTRS = frozenset({"build_id", "end_build_id", "is_active"})

# имя датасета короче физического лимита Postgres (63): запас под
# суффиксы служебных таблиц спек (_<номер>, _<номер>_$)
MAX_DATASET_NAME = 50

_SIMPLE_TYPES = (
    "text",
    "integer",
    "bigint",
    "boolean",
    "date",
    "timestamp",
    "timestamptz",
)


# --- распознавание (лёгкий пик слов, до строгой лексики) -------------------


def _next_word(text: str, i: int) -> tuple[str | None, int]:
    """Следующее слово начиная с позиции i (нижним регистром) и его позиция."""
    i = _skip_blank(text, i)
    match = IDENT_RE.match(text, i)
    if not match:
        return None, i
    return match.group(0).lower(), i


_CREATE_OBJECTS = frozenset(
    {"datapulse", "dataset", "build_spec",
     "oracle_connection", "postgres_connection"}
)
_DROP_OBJECTS = frozenset({"datapulse", "dataset", "build_spec"})
_COMMENT_OBJECTS = frozenset({"datapulse", "dataset", "attr"})


def _routed(text: str) -> bool:
    """Перехватывать ли стейтмент: create [or replace] | drop | comment on
    над объектами платформы, а также test, python и команды билдов; всё
    прочее (включая create or replace view/function, drop table,
    comment on table … и анонимные блоки DO) уходит релеем."""
    word, pos = _next_word(text, 0)
    if word in ("test", "python", "build", "attach", "stop", "fix"):
        return True    # в словаре Postgres таких стейтментов нет
    if word == "alter":
        word2, _ = _next_word(text, pos + len(word))
        return word2 == "datapulse"
    if word == "drop":
        word2, _ = _next_word(text, pos + len(word))
        return word2 in _DROP_OBJECTS
    if word == "comment":
        word2, pos2 = _next_word(text, pos + len(word))
        if word2 != "on":
            return False
        word3, _ = _next_word(text, pos2 + len(word2))
        return word3 in _COMMENT_OBJECTS
    if word != "create":
        return False
    word2, pos2 = _next_word(text, pos + len(word))
    if word2 == "or":
        word3, pos3 = _next_word(text, pos2 + len(word2))
        if word3 != "replace":
            return False
        word2, _ = _next_word(text, pos3 + len(word3))
    return word2 in _CREATE_OBJECTS


def is_dpl_text(query: str) -> bool:
    """Похож ли текст на DPL (для честной ошибки в extended-протоколе)."""
    return _routed(query)


def match_command(query: str) -> Command | None:
    """DPL — только когда запрос является ровно одним DPL-стейтментом.

    None — запрос не DPL, уходит релеем (в том числе мульти-стейтмент:
    транзакционных пакетов у DataPulse нет). Синтаксически неверный
    DPL — DplError с позицией в тексте запроса.
    """
    statements = split_statements(query)
    if len(statements) != 1:
        return None
    stmt = statements[0]
    if not _routed(stmt.text):
        return None
    # токенизация со смещением стейтмента: позиции токенов, узлов команд
    # и ошибок — сразу глобальные в тексте запроса
    return _Parser(stmt.text, stmt.offset).parse()


# --- парсер ----------------------------------------------------------------


class _Parser:
    """Рекурсивный спуск по токенам одного перехваченного стейтмента."""

    def __init__(self, text: str, base: int = 0) -> None:
        self.tokens = tokenize(text, base)
        self.i = 0

    # --- инфраструктура ---------------------------------------------------

    def peek(self) -> Token:
        return self.tokens[self.i]

    def advance(self) -> Token:
        token = self.tokens[self.i]
        if token.kind is not TokKind.END:
            self.i += 1
        return token

    def error(self, expected: str) -> DplError:
        token = self.peek()
        found = (
            "конец стейтмента"
            if token.kind is TokKind.END
            else f"{token.kind.value} {token.value!r}"
        )
        return DplError(f"ожидалось {expected}, найдено {found}", pos=token.pos)

    def keyword(self, *words: str) -> Token:
        token = self.peek()
        if token.kind is not TokKind.IDENT or token.value not in words:
            raise self.error(" | ".join(w.upper() for w in words))
        return self.advance()

    def try_keyword(self, *words: str) -> Token | None:
        token = self.peek()
        if token.kind is TokKind.IDENT and token.value in words:
            return self.advance()
        return None

    def ident(self, what: str) -> Token:
        token = self.peek()
        if token.kind is not TokKind.IDENT:
            raise self.error(what)
        return self.advance()

    def number(self, what: str) -> Token:
        token = self.peek()
        if token.kind is not TokKind.NUMBER:
            raise self.error(what)
        return self.advance()

    def string(self, what: str) -> Token:
        token = self.peek()
        if token.kind is not TokKind.STRING:
            raise self.error(what)
        return self.advance()

    def punct(self, ch: str) -> Token:
        token = self.peek()
        if token.kind is not TokKind.PUNCT or token.value != ch:
            raise self.error(f"{ch!r}")
        return self.advance()

    def try_punct(self, ch: str) -> Token | None:
        token = self.peek()
        if token.kind is TokKind.PUNCT and token.value == ch:
            return self.advance()
        return None

    def at_punct(self, ch: str) -> bool:
        token = self.peek()
        return token.kind is TokKind.PUNCT and token.value == ch

    def finish(self) -> None:
        """Конец стейтмента (';' срезан сплиттером)."""
        if self.peek().kind is not TokKind.END:
            raise DplError("лишний текст после команды", pos=self.peek().pos)

    # --- вход -------------------------------------------------------------

    def parse(self) -> Command:
        """Стейтмент уже прошёл маршрутизацию — глагол и объект известны."""
        if self.try_keyword("drop"):
            obj = self.keyword("datapulse", "dataset", "build_spec")
            if obj.value == "dataset":
                schema, name = self.dataset_code()
                self.finish()
                return DropDataset(
                    dataset_code=f"{schema.value}.{name.value}",
                    code_pos=schema.pos,
                )
            if obj.value == "build_spec":
                code, num, pos = self.build_spec_ref()
                self.finish()
                return DropBuildSpec(
                    dataset_code=code, build_spec_num=num, code_pos=pos
                )
            self.finish()
            return DropDatapulse()
        if self.try_keyword("comment"):
            return self.comment_on()
        if self.try_keyword("test"):
            name = self.ident("имя коннекта")
            self.finish()
            return TestConnection(name=name.value, name_pos=name.pos)
        if self.try_keyword("python"):
            body = self.peek()
            if body.kind is not TokKind.BODY:
                raise self.error("тело $$…$$")
            self.advance()
            self.finish()
            return PythonBlock(body=body.value, body_pos=body.pos)
        if self.try_keyword("build"):
            return self.build_call()
        if self.try_keyword("attach"):
            return self.attach_call()
        if self.try_keyword("stop"):
            return StopCall(*self.single_build_id())
        if self.try_keyword("fix"):
            return FixCall(*self.single_build_id())
        if self.try_keyword("alter"):
            self.keyword("datapulse")
            self.keyword("add")
            schema = self.ident("имя схемы данных")
            _check_schema_name(schema.value, schema.pos)
            self.finish()
            return AlterDatapulseAdd(schema=schema.value, schema_pos=schema.pos)
        self.keyword("create")
        or_token = self.try_keyword("or")
        if or_token:
            self.keyword("replace")
        obj = self.keyword(
            "datapulse", "dataset", "build_spec",
            "oracle_connection", "postgres_connection",
        )
        if obj.value == "dataset":
            return self.create_dataset(or_replace=or_token is not None)
        if obj.value == "build_spec":
            return self.create_build_spec(or_replace=or_token is not None)
        if obj.value in ("oracle_connection", "postgres_connection"):
            return self.create_connection(
                class_code=obj.value, or_replace=or_token is not None
            )
        if or_token:
            raise DplError(
                "OR REPLACE неприменим к datapulse",
                pos=or_token.pos,
                hint="переустановка — drop datapulse, затем create datapulse",
            )
        return self.create_datapulse()

    # --- create datapulse -------------------------------------------------

    def create_datapulse(self) -> CreateDatapulse:
        """create datapulse ( схема [, схема …] )"""
        token = self.peek()
        if not self.at_punct("("):
            raise DplError(
                "ожидался список схем данных в скобках",
                pos=token.pos,
                hint="create datapulse (схема_1, схема_2, …)",
            )
        self.advance()
        schemas: list[str] = []
        while True:
            token = self.peek()
            if self.at_punct(")") and not schemas:
                raise DplError(
                    "укажите хотя бы одну схему данных",
                    pos=token.pos,
                    hint="create datapulse (схема_1, схема_2, …)",
                )
            if token.kind is not TokKind.IDENT:
                raise DplError("ожидался идентификатор схемы", pos=token.pos)
            self.advance()
            _check_schema_name(token.value, token.pos)
            if token.value in schemas:
                raise DplError(f"схема {token.value!r} указана дважды", pos=token.pos)
            schemas.append(token.value)
            if self.try_punct(","):
                continue
            if self.try_punct(")"):
                break
            raise DplError("ожидалась ',' или ')'", pos=self.peek().pos)
        self.finish()
        return CreateDatapulse(schemas=schemas)

    # --- comment on ---------------------------------------------------------

    def comment_on(self) -> Command:
        """comment on datapulse | dataset схема.имя | attr схема.имя.атрибут
        is 'текст'|null"""
        self.keyword("on")
        obj = self.keyword("datapulse", "dataset", "attr")
        code = attr = None
        if obj.value in ("dataset", "attr"):
            code = self.dataset_code()
            if obj.value == "attr":
                self.punct(".")
                attr = self.ident("имя атрибута после точки")
        self.keyword("is")
        if self.try_keyword("null"):
            comment = None
        else:
            comment = self.string("текст комментария в кавычках либо NULL").value
        self.finish()
        if code is None:
            return CommentOnDatapulse(comment=comment)
        schema, name = code
        if attr is not None:
            return CommentOnAttr(
                dataset_code=f"{schema.value}.{name.value}",
                attr_name=attr.value,
                code_pos=schema.pos,
                attr_pos=attr.pos,
                comment=comment,
            )
        return CommentOnDataset(
            dataset_code=f"{schema.value}.{name.value}",
            code_pos=schema.pos,
            comment=comment,
        )

    # --- create [or replace] *_connection -----------------------------------

    def create_connection(self, class_code: str, or_replace: bool) -> CreateConnection:
        """create [or replace] класс имя with ( поле = значение, … )"""
        name = self.ident("имя коннекта")
        self.keyword("with")
        fields = self.assign_list("поле коннекта")
        self.finish()
        return CreateConnection(
            class_code=class_code,
            name=name.value,
            name_pos=name.pos,
            or_replace=or_replace,
            fields=fields,
        )

    def assign_list(self, what: str) -> list[FieldAssign]:
        """`( имя = значение , … )`"""
        self.punct("(")
        fields: list[FieldAssign] = []
        while True:
            name = self.ident(what)
            self.punct("=")
            token = self.peek()
            if token.kind is TokKind.STRING:
                value = Value("string", token.value, token.pos)
            elif token.kind is TokKind.NUMBER:
                value = Value("number", token.value, token.pos)
            elif token.kind is TokKind.IDENT:
                value = Value("ident", token.value, token.pos)
            else:
                raise self.error("значение (строка, число или идентификатор)")
            self.advance()
            fields.append(
                FieldAssign(name=name.value, name_pos=name.pos, value=value)
            )
            if not self.try_punct(","):
                break
        self.punct(")")
        return fields

    # --- create [or replace] build_spec -------------------------------------

    def create_build_spec(self, or_replace: bool) -> CreateBuildSpec:
        """create [or replace] build_spec схема.имя.номер
        ( режим [, …] ) with ( опция = значение [, …] )
        [ using имя [, …] | from код_датасета [, …] ]
        as python $$тело$$"""
        code, num, pos = self.build_spec_ref()
        self.punct("(")
        modes = [self.mode_decl()]
        while self.try_punct(","):
            modes.append(self.mode_decl())
        self.punct(")")
        self.keyword("with")
        options = self.assign_list("опция спеки")
        using: list[Named] = []
        sources: list[Named] = []
        if self.try_keyword("using"):
            using = self.named_list("имя коннекта")
        if from_token := self.try_keyword("from"):
            if using:
                raise DplError(
                    "USING и FROM взаимоисключающи: спека — загрузчик либо"
                    " трансформер",
                    pos=from_token.pos,
                )
            sources = self.code_list()
        # обе секции отсутствуют — допустимо (спека-генератор)
        self.keyword("as")
        self.keyword("python")   # язык тела; других языков пока нет
        body = self.peek()
        if body.kind is not TokKind.BODY:
            raise self.error("тело $$…$$")
        self.advance()
        self.finish()
        return CreateBuildSpec(
            dataset_code=code,
            build_spec_num=num,
            code_pos=pos,
            or_replace=or_replace,
            modes=modes,
            options=options,
            using=using,
            sources=sources,
            body=body.value,
            body_pos=body.pos,
        )

    def mode_decl(self) -> ModeDecl:
        """`( clear | dirty ) тип_переноса mode имя`"""
        clear_token = self.keyword("clear", "dirty")
        transfer = self.keyword("init", "incr", "sect", "appd", "skip")
        self.keyword("mode")
        name = self.ident("имя режима")
        return ModeDecl(
            mode_code=name.value,
            mode_pos=name.pos,
            type_code=transfer.value,
            is_clear=clear_token.value == "clear",
        )

    def named_list(self, what: str) -> list[Named]:
        names = [self.ident(what)]
        while self.try_punct(","):
            names.append(self.ident(what))
        return [Named(name=t.value, pos=t.pos) for t in names]

    def code_list(self) -> list[Named]:
        """Коды датасетов через запятую (from)."""
        codes: list[Named] = []
        while True:
            schema, name = self.dataset_code()
            codes.append(
                Named(name=f"{schema.value}.{name.value}", pos=schema.pos)
            )
            if not self.try_punct(","):
                break
        return codes

    # --- build / attach / stop / fix ----------------------------------------

    def build_call(self) -> BuildCall:
        """build('схема.имя', номер, 'режим') — код датасета и режим строковыми
        литералами, номер спеки — числом."""
        self.punct("(")
        code = self.string("код датасета строкой: 'схема.имя'")
        dataset_code = _check_dataset_literal(code.value, code.pos)
        self.punct(",")
        num = self.number("номер спеки")
        self.punct(",")
        mode = self.string("имя режима строкой: 'режим'")
        mode_code = mode.value.strip().lower()
        if not IDENT_RE.fullmatch(mode_code):
            raise DplError(
                f"имя режима {mode.value!r} — не идентификатор", pos=mode.pos
            )
        self.punct(")")
        self.finish()
        return BuildCall(
            dataset_code=dataset_code,
            code_pos=code.pos,
            build_spec_num=int(num.value),
            num_pos=num.pos,
            mode_code=mode_code,
            mode_pos=mode.pos,
        )

    def attach_call(self) -> AttachCall:
        """attach(build_id [, позиция build_log_id])"""
        self.punct("(")
        build_id = self.number("номер билда (build_id)")
        from_log_id = 0
        if self.try_punct(","):
            from_log_id = int(self.number("позиция журнала (build_log_id)").value)
        self.punct(")")
        self.finish()
        return AttachCall(
            build_id=int(build_id.value),
            id_pos=build_id.pos,
            from_log_id=from_log_id,
        )

    def single_build_id(self) -> tuple[int, int]:
        """`( build_id )` — общий хвост stop и fix."""
        self.punct("(")
        build_id = self.number("номер билда (build_id)")
        self.punct(")")
        self.finish()
        return int(build_id.value), build_id.pos

    # --- dataset ------------------------------------------------------------

    def dataset_code(self) -> tuple[Token, Token]:
        """`схема.имя` — два идентификатора через точку."""
        schema = self.ident("код датасета (схема.имя)")
        self.punct(".")
        name = self.ident("имя датасета после точки")
        return schema, name

    def build_spec_ref(self) -> tuple[str, int, int]:
        """`схема.имя.номер` — ссылка на спеку."""
        schema = self.ident("ссылка на спеку (схема.имя.номер)")
        self.punct(".")
        name = self.ident("имя датасета после точки")
        self.punct(".")
        num = self.number("номер спеки")
        return f"{schema.value}.{name.value}", int(num.value), schema.pos

    def create_dataset(self, or_replace: bool) -> CreateDataset:
        """create [or replace] dataset схема.имя
        ( атрибут тип [, …], primary key ( имя [, …] ) )"""
        schema, name = self.dataset_code()
        _check_dataset_name(name.value, name.pos)
        self.punct("(")
        attrs: list[tuple[Token, str]] = []      # (имя, канонический тип)
        primary_key: list[Token] | None = None
        while True:
            if pk_token := self.try_keyword("primary"):
                if primary_key is not None:
                    raise DplError("PRIMARY KEY объявлен дважды", pos=pk_token.pos)
                self.keyword("key")
                self.punct("(")
                primary_key = [self.ident("атрибут ключа")]
                while self.try_punct(","):
                    primary_key.append(self.ident("атрибут ключа"))
                self.punct(")")
            else:
                if primary_key is not None:
                    raise DplError(
                        "PRIMARY KEY должен идти последним в списке",
                        pos=self.peek().pos,
                    )
                attrs.append(self.attr_decl())
            if not self.try_punct(","):
                break
        self.punct(")")
        self.finish()
        if primary_key is None:
            raise DplError(
                "PRIMARY KEY обязателен: датасет без ключа не имеет"
                " SCD2-семантики",
                pos=schema.pos,
            )
        return _build_create_dataset(schema, name, or_replace, attrs, primary_key)

    def attr_decl(self) -> tuple[Token, str]:
        """`имя тип`; проверки имени и параметров numeric — сразу."""
        name = self.ident("имя атрибута")
        if name.value in RESERVED_ATTRS:
            raise DplError(
                f"имя {name.value!r} занято служебной колонкой SCD2",
                pos=name.pos,
            )
        if name.value in KEYWORDS:
            raise DplError(f"имя {name.value!r} — ключевое слово DPL", pos=name.pos)
        if len(name.value) > 63:
            raise DplError("имя атрибута длиннее 63 символов", pos=name.pos)
        type_token = self.peek()
        if type_token.kind is not TokKind.IDENT:
            raise self.error("тип атрибута")
        if type_token.value in _SIMPLE_TYPES:
            self.advance()
            return name, type_token.value
        if type_token.value == "numeric":
            self.advance()
            return name, self.numeric_type()
        raise DplError(
            f"неизвестный тип {type_token.value!r}",
            pos=type_token.pos,
            hint="типы: " + ", ".join(_SIMPLE_TYPES)
            + ", numeric[(точность[,масштаб])]",
        )

    def numeric_type(self) -> str:
        """numeric [ '(' точность [ ',' масштаб ] ')' ] → канонический тип."""
        if not self.try_punct("("):
            return "numeric"
        precision_token = self.number("точность numeric")
        precision = int(precision_token.value)
        if precision < 1:
            raise DplError(
                "точность numeric должна быть ≥ 1", pos=precision_token.pos
            )
        scale = None
        if self.try_punct(","):
            scale_token = self.number("масштаб numeric")
            scale = int(scale_token.value)
            if scale > precision:
                raise DplError(
                    "масштаб numeric не может превышать точность",
                    pos=scale_token.pos,
                )
        self.punct(")")
        if scale is None:
            return f"numeric({precision})"
        return f"numeric({precision},{scale})"


def _build_create_dataset(
    schema: Token,
    name: Token,
    or_replace: bool,
    attrs: list[tuple[Token, str]],
    primary_key: list[Token],
) -> CreateDataset:
    """Сквозные проверки списков + сборка узла команды."""
    declared: set[str] = set()
    for token, _ in attrs:
        if token.value in declared:
            raise DplError(f"атрибут {token.value!r} объявлен дважды", pos=token.pos)
        declared.add(token.value)
    pk_names: set[str] = set()
    for token in primary_key:
        if token.value not in declared:
            raise DplError(
                f"атрибут ключа {token.value!r} не объявлен в списке атрибутов",
                pos=token.pos,
            )
        if token.value in pk_names:
            raise DplError(f"атрибут {token.value!r} в ключе дважды", pos=token.pos)
        pk_names.add(token.value)
    return CreateDataset(
        dataset_code=f"{schema.value}.{name.value}",
        code_pos=schema.pos,
        or_replace=or_replace,
        attrs=[
            DatasetAttr(token.value, type_code, token.value in pk_names)
            for token, type_code in attrs
        ],
    )


def _check_dataset_literal(value: str, pos: int) -> str:
    """Код датасета из строкового литерала build(...): 'схема.имя';
    приводится к нижнему регистру, как идентификаторы DPL."""
    code = value.strip().lower()
    schema, dot, name = code.partition(".")
    if not dot or not IDENT_RE.fullmatch(schema) or not IDENT_RE.fullmatch(name):
        raise DplError(
            f"код датасета {value!r} — не 'схема.имя'",
            pos=pos,
            hint="пример: build('dm.dog', 1, 'initial')",
        )
    return code


def _check_schema_name(name: str, pos: int) -> None:
    if len(name) > 63:
        raise DplError("имя схемы длиннее 63 символов", pos=pos)
    if name in RESERVED_SCHEMAS or name.startswith("pg_"):
        raise DplError(f"имя схемы {name!r} зарезервировано", pos=pos)


def _check_dataset_name(name: str, pos: int) -> None:
    if len(name) > MAX_DATASET_NAME:
        raise DplError(
            f"имя датасета длиннее {MAX_DATASET_NAME} символов",
            pos=pos,
            hint="запас до лимита Postgres (63) — под суффиксы таблиц спек"
            " (_<номер>, _<номер>_$)",
        )
    if name[-1].isdigit():
        raise DplError(
            "имя датасета не может заканчиваться цифрой",
            pos=pos,
            hint="хвост _<номер> полного имени спеки должен отщепляться"
            " однозначно",
        )
