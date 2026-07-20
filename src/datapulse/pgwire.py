"""Кодек протокола Postgres v3.0 — ровно то, что нужно релею.

Читает сообщения из asyncio-стрима с обеих сторон (рамка «тип + длина +
payload»), собирает немногие собственные сообщения прокси (ошибки, ответы
перехваченных команд) и переписывает единственное чужое —
AuthenticationSASL (стрип механизмов *-PLUS). Кодировка строк — UTF-8.
"""

from __future__ import annotations

import struct
from asyncio import IncompleteReadError, StreamReader
from dataclasses import dataclass

PROTOCOL_3_0 = 196608          # 3.0
SSL_REQUEST_CODE = 80877103
GSSENC_REQUEST_CODE = 80877104
CANCEL_REQUEST_CODE = 80877102

# лимит длины одного сообщения; у Postgres рамка ~1 ГБ
MAX_MESSAGE_LEN = 1 << 30


class ProtocolViolation(Exception):
    """Сторона нарушила рамки протокола — соединение закрывается."""


# --- первый пакет соединения ----------------------------------------------


@dataclass(frozen=True)
class Startup:
    """Startup-пакет: raw — байты для форварда бэкенду как есть."""

    raw: bytes
    params: dict[str, str]     # user, database, application_name, ...


@dataclass(frozen=True)
class CancelCall:
    """CancelRequest: raw форвардится бэкенду как есть."""

    raw: bytes


async def read_startup(reader: StreamReader) -> Startup | CancelCall | str:
    """Читает первый пакет соединения.

    Возвращает Startup, CancelCall либо строку 'ssl'/'gssenc' — запрос
    шифрования, на который вызывающий отвечает отказом и читает снова.
    """
    try:
        head = await reader.readexactly(4)
    except IncompleteReadError as exc:
        raise ProtocolViolation("соединение закрыто до startup-пакета") from exc
    (length,) = struct.unpack("!i", head)
    if length < 8 or length > MAX_MESSAGE_LEN:
        raise ProtocolViolation(f"некорректная длина startup-пакета: {length}")
    try:
        payload = await reader.readexactly(length - 4)
    except IncompleteReadError as exc:
        raise ProtocolViolation("соединение оборвано в startup-пакете") from exc
    (code,) = struct.unpack("!i", payload[:4])
    if code == SSL_REQUEST_CODE:
        return "ssl"
    if code == GSSENC_REQUEST_CODE:
        return "gssenc"
    if code == CANCEL_REQUEST_CODE:
        return CancelCall(raw=head + payload)
    if code != PROTOCOL_3_0:
        raise ProtocolViolation(f"неподдерживаемая версия протокола: {code}")
    params: dict[str, str] = {}
    rest = payload[4:]
    while rest and rest != b"\x00":
        key, _, rest = rest.partition(b"\x00")
        value, _, rest = rest.partition(b"\x00")
        params[key.decode("utf-8")] = value.decode("utf-8")
    return Startup(raw=head + payload, params=params)


async def read_message(reader: StreamReader) -> tuple[bytes, bytes] | None:
    """Читает одно типизированное сообщение: (тип, payload); None — конец стрима."""
    try:
        head = await reader.readexactly(5)
    except IncompleteReadError:
        return None
    msg_type = head[:1]
    (length,) = struct.unpack_from("!i", head, 1)
    if length < 4 or length > MAX_MESSAGE_LEN:
        raise ProtocolViolation(
            f"некорректная длина сообщения {msg_type!r}: {length}"
        )
    try:
        payload = await reader.readexactly(length - 4)
    except IncompleteReadError:
        return None
    return msg_type, payload


class PayloadReader:
    """Последовательное чтение полей из payload сообщения."""

    def __init__(self, payload: bytes) -> None:
        self._data = payload
        self._pos = 0

    def cstring(self) -> str:
        end = self._data.index(b"\x00", self._pos)
        value = self._data[self._pos : end].decode("utf-8")
        self._pos = end + 1
        return value


# --- сборка сообщений ------------------------------------------------------


def message(msg_type: bytes, payload: bytes) -> bytes:
    """Собирает рамку сообщения (тип + длина + payload)."""
    return msg_type + struct.pack("!i", len(payload) + 4) + payload


def _cstr(value: str) -> bytes:
    return value.encode("utf-8") + b"\x00"


def ready_for_query(status: bytes = b"I") -> bytes:
    return message(b"Z", status)


def command_complete(tag: str) -> bytes:
    return message(b"C", _cstr(tag))


def notice_response(text: str) -> bytes:
    """NoticeResponse: печать python-блоков и стрим журналов билдов."""
    fields = {"S": "NOTICE", "V": "NOTICE", "C": "00000", "M": text}
    parts = [code.encode("ascii") + _cstr(value) for code, value in fields.items()]
    parts.append(b"\x00")
    return message(b"N", b"".join(parts))


INT8_OID = 20    # bigint — тип колонки build_id табличного ответа build


def row_description(columns: list[tuple[str, int]]) -> bytes:
    """RowDescription собственного табличного ответа прокси:
    (имя колонки, OID типа), текстовый формат."""
    parts = [struct.pack("!h", len(columns))]
    for name, type_oid in columns:
        parts.append(_cstr(name))
        # таблица/атрибут 0 (не колонка таблицы), typlen -2 не нужен:
        # длина по словарю не проверяется клиентами — ставим -1 (varlena)
        parts.append(struct.pack("!ihihih", 0, 0, type_oid, -1, -1, 0))
    return message(b"T", b"".join(parts))


def data_row(values: list[str | None]) -> bytes:
    """DataRow текстового формата; None — SQL NULL."""
    parts = [struct.pack("!h", len(values))]
    for value in values:
        if value is None:
            parts.append(struct.pack("!i", -1))
        else:
            raw = value.encode("utf-8")
            parts.append(struct.pack("!i", len(raw)) + raw)
    return message(b"D", b"".join(parts))


def error_response(
    text: str,
    sqlstate: str = "XX000",
    *,
    hint: str | None = None,
    position: int | None = None,
) -> bytes:
    """ErrorResponse; position — 1-based индекс символа в тексте запроса."""
    fields = {"S": "ERROR", "V": "ERROR", "C": sqlstate, "M": text}
    if hint:
        fields["H"] = hint
    if position:
        fields["P"] = str(position)
    parts = [code.encode("ascii") + _cstr(value) for code, value in fields.items()]
    parts.append(b"\x00")
    return message(b"E", b"".join(parts))


# --- переписывание AuthenticationSASL --------------------------------------


def strip_sasl_plus(payload: bytes) -> bytes:
    """AuthenticationSASL: вырезает механизмы *-PLUS из списка бэкенда.

    Channel binding через посредника не работает в принципе: клиент
    подмешивает в SCRAM отпечаток TLS-сертификата стороны, с которой
    физически соединён. Прочие R-сообщения возвращаются как есть.
    """
    if len(payload) < 4:
        return payload
    (code,) = struct.unpack_from("!i", payload, 0)
    if code != 10:  # AuthenticationSASL
        return payload
    mechanisms: list[bytes] = []
    rest = payload[4:]
    while rest and rest[:1] != b"\x00":
        name, _, rest = rest.partition(b"\x00")
        mechanisms.append(name)
    kept = [m for m in mechanisms if not m.endswith(b"-PLUS")]
    if kept == mechanisms or not kept:
        return payload
    return struct.pack("!i", 10) + b"".join(m + b"\x00" for m in kept) + b"\x00"
