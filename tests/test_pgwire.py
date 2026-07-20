"""Юниты кодека pgwire."""

import asyncio
import struct

import pytest

from datapulse import pgwire as pg

# --- стрип *-PLUS ----------------------------------------------------------


def _sasl_payload(mechanisms: list[bytes]) -> bytes:
    return (
        struct.pack("!i", 10)
        + b"".join(m + b"\x00" for m in mechanisms)
        + b"\x00"
    )


def test_strip_sasl_plus():
    payload = _sasl_payload([b"SCRAM-SHA-256-PLUS", b"SCRAM-SHA-256"])
    assert pg.strip_sasl_plus(payload) == _sasl_payload([b"SCRAM-SHA-256"])


def test_strip_sasl_plus_untouched_without_plus():
    payload = _sasl_payload([b"SCRAM-SHA-256"])
    assert pg.strip_sasl_plus(payload) == payload


def test_strip_sasl_plus_keeps_other_auth_codes():
    payload = struct.pack("!i", 0)  # AuthenticationOk
    assert pg.strip_sasl_plus(payload) == payload


def test_strip_sasl_plus_all_plus_falls_back():
    payload = _sasl_payload([b"SCRAM-SHA-256-PLUS"])
    assert pg.strip_sasl_plus(payload) == payload


# --- рамки сообщений -------------------------------------------------------


def test_message_frame():
    framed = pg.message(b"Q", b"select 1\x00")
    assert framed[:1] == b"Q"
    (length,) = struct.unpack("!i", framed[1:5])
    assert length == 4 + 9
    assert framed[5:] == b"select 1\x00"


def _feed(data: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return reader


def test_read_startup_params_and_raw():
    body = struct.pack("!i", pg.PROTOCOL_3_0)
    body += b"user\x00alice\x00database\x00appdb\x00\x00"
    packet = struct.pack("!i", len(body) + 4) + body

    async def scenario():
        return await pg.read_startup(_feed(packet))

    startup = asyncio.run(scenario())
    assert isinstance(startup, pg.Startup)
    assert startup.params == {"user": "alice", "database": "appdb"}
    assert startup.raw == packet


def test_read_startup_cancel_raw():
    body = struct.pack("!iii", pg.CANCEL_REQUEST_CODE, 42, 777)
    packet = struct.pack("!i", len(body) + 4) + body

    async def scenario():
        return await pg.read_startup(_feed(packet))

    cancel = asyncio.run(scenario())
    assert isinstance(cancel, pg.CancelCall)
    assert cancel.raw == packet


def test_read_message_roundtrip():
    async def scenario():
        reader = _feed(pg.message(b"Q", b"select 1\x00") + pg.message(b"X", b""))
        first = await pg.read_message(reader)
        second = await pg.read_message(reader)
        third = await pg.read_message(reader)
        return first, second, third

    first, second, third = asyncio.run(scenario())
    assert first == (b"Q", b"select 1\x00")
    assert second == (b"X", b"")
    assert third is None


def test_read_message_truncated_frame():
    # обрыв посреди рамки — конец стрима, не исключение
    async def scenario():
        return await pg.read_message(_feed(b"Q\x00\x00\x00\x10sel"))

    assert asyncio.run(scenario()) is None


def test_read_message_bad_length():
    async def scenario():
        return await pg.read_message(_feed(b"Q" + struct.pack("!i", 2)))

    with pytest.raises(pg.ProtocolViolation, match="некорректная длина"):
        asyncio.run(scenario())


def test_read_startup_bad_length():
    async def scenario():
        return await pg.read_startup(_feed(struct.pack("!i", 4)))

    with pytest.raises(pg.ProtocolViolation, match="длина startup"):
        asyncio.run(scenario())


def test_read_startup_unknown_protocol():
    body = struct.pack("!i", 123456)
    packet = struct.pack("!i", len(body) + 4) + body

    async def scenario():
        return await pg.read_startup(_feed(packet))

    with pytest.raises(pg.ProtocolViolation, match="версия протокола"):
        asyncio.run(scenario())
