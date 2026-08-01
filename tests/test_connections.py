"""Юниты реестра классов коннектов и шифрования секретов."""

import os

import pytest

from datapulse.connections import secret_fields, validate_params
from datapulse.dpl import DplError, SqlState, match_command
from datapulse.secrets import (
    SecretError,
    decrypt_value,
    encrypt_value,
    is_encrypted,
)


def _fields(query):
    """Поля из разобранной команды create *_connection."""
    return match_command(query).fields


def test_validate_params():
    fields = _fields(
        "create oracle connection c with (host_name = 'h', port_num = 1521,"
        " service_name = 's', user_name = 'u', password = 'p')"
    )
    params = validate_params("oracle", fields)
    assert params == {
        "host_name": "h",
        "port_num": 1521,
        "service_name": "s",
        "user_name": "u",
        "password": "p",
    }


def test_validate_params_port_required():
    # дефолтов у портов нет — обязательное поле (решение: явные порты)
    fields = _fields(
        "create oracle connection c with (host_name = 'h',"
        " service_name = 's', user_name = 'u', password = 'p')"
    )
    with pytest.raises(DplError, match="port_num"):
        validate_params("oracle", fields)


@pytest.mark.parametrize(
    "with_clause, fragment",
    [
        ("(host_name = 'h', color = 'red')", "неизвестное поле"),
        ("(host_name = 'h', host_name = 'h2')", "задано дважды"),
        ("(host_name = 42)", "строка"),
        ("(port_num = 'пять')", "целое число"),
        ("(host_name = yes)", "строка"),           # ident — не значение
        ("(host_name = 'h')", "обязательное поле"),
    ],
)
def test_validate_params_errors(with_clause, fragment):
    fields = _fields(f"create postgres connection c with {with_clause}")
    with pytest.raises(DplError) as exc_info:
        validate_params("postgres", fields)
    assert fragment in exc_info.value.message
    assert exc_info.value.sqlstate == SqlState.INVALID_PARAMETER_VALUE


def test_secret_fields():
    assert secret_fields("oracle") == {"password"}
    assert secret_fields("postgres") == {"password"}


def test_secret_roundtrip():
    key = os.urandom(32)
    token = encrypt_value("p@ss'слово", key)
    assert is_encrypted(token)
    assert decrypt_value(token, key) == "p@ss'слово"


def test_secret_wrong_key():
    token = encrypt_value("секрет", os.urandom(32))
    with pytest.raises(SecretError, match="не расшифровался"):
        decrypt_value(token, os.urandom(32))


def test_secret_not_encrypted_value():
    with pytest.raises(SecretError, match="не является шифртекстом"):
        decrypt_value({"плейн": "x"}, os.urandom(32))
