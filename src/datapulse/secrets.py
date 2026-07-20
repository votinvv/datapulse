"""Шифрование секретных полей коннектов.

Секрет шифруется «на месте» в param_json: значение поля заменяется
само-опознаваемым объектом {"enc": "<base64(nonce + шифртекст)>"}.
Алгоритм — AES-256-GCM; ключ — вне БД (env установки,
DP_ENCRYPTION_KEY).
"""

from __future__ import annotations

import base64
import secrets as _secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_NONCE_LEN = 12

MASK = "********"


class SecretError(Exception):
    """Ошибка шифрования/расшифровки секрета."""


def encrypt_value(plain: str, key: bytes) -> dict:
    nonce = _secrets.token_bytes(_NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, plain.encode("utf-8"), None)
    return {"enc": base64.b64encode(nonce + ciphertext).decode("ascii")}


def decrypt_value(value: dict, key: bytes) -> str:
    if not is_encrypted(value):
        raise SecretError("значение не является шифртекстом {'enc': …}")
    try:
        blob = base64.b64decode(value["enc"], validate=True)
        plain = AESGCM(key).decrypt(blob[:_NONCE_LEN], blob[_NONCE_LEN:], None)
    except (InvalidTag, ValueError) as exc:
        raise SecretError(
            "секрет не расшифровался: ключ не от этой установки либо"
            " данные повреждены"
        ) from exc
    return plain.decode("utf-8")


def is_encrypted(value) -> bool:
    """Шифртекст — объект ровно с одним полем 'enc' (строка base64)."""
    return (
        isinstance(value, dict)
        and set(value.keys()) == {"enc"}
        and isinstance(value["enc"], str)
    )
