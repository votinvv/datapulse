"""Юниты конфигурации из переменных среды."""

import base64

import pytest

from datapulse.config import Config, ConfigError, load_config

FULL_ENV = {
    "PG_HOST": "db.local",
    "PG_PORT": "5433",
    "PG_USER": "datapulse",
    "PG_PASSWORD": "secret",
    "DP_PORT": "6432",
}


def test_full_env():
    config = load_config(FULL_ENV)
    assert config == Config(
        pg_host="db.local",
        pg_port=5433,
        pg_user="datapulse",
        pg_password="secret",
        dp_port=6432,
        encryption_key=config.encryption_key,
    )
    # ключ не задан — сгенерирован случайный (дев-режим)
    assert len(config.encryption_key) == 32
    assert load_config(FULL_ENV).encryption_key != config.encryption_key


def test_pg_port_default():
    env = dict(FULL_ENV)
    del env["PG_PORT"]
    assert load_config(env).pg_port == 5432


def test_missing_required_lists_all():
    with pytest.raises(ConfigError) as exc_info:
        load_config({"PG_PORT": "5432"})
    text = str(exc_info.value)
    for name in ("PG_HOST", "PG_USER", "PG_PASSWORD", "DP_PORT"):
        assert name in text


def test_bad_port():
    env = dict(FULL_ENV, DP_PORT="батарея")
    with pytest.raises(ConfigError, match="DP_PORT"):
        load_config(env)


def test_encryption_key_roundtrip():
    key = bytes(range(32))
    env = dict(FULL_ENV, DP_ENCRYPTION_KEY=base64.b64encode(key).decode())
    assert load_config(env).encryption_key == key


def test_encryption_key_wrong_length():
    env = dict(FULL_ENV, DP_ENCRYPTION_KEY=base64.b64encode(b"short").decode())
    with pytest.raises(ConfigError, match="32 байта"):
        load_config(env)


def test_encryption_key_not_base64():
    env = dict(FULL_ENV, DP_ENCRYPTION_KEY="ключ")
    with pytest.raises(ConfigError, match="base64"):
        load_config(env)
