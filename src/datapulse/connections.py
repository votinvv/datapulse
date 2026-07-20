"""Реестр классов коннектов.

Класс задаёт схему полей param_json: типы и секретность; все поля
обязательны, дефолтов нет. Поля DDL — буквально ключи param_json
(нулевой маппинг). Валидация create *_connection идёт отсюда;
ошибка — первая найденная (DplError с позицией).
"""

from __future__ import annotations

from dataclasses import dataclass

from .dpl import DplError, FieldAssign, SqlState


@dataclass(frozen=True)
class FieldSpec:
    name: str
    kind: str                  # 'string' | 'integer'
    secret: bool = False


ORACLE_CONNECTION = "oracle_connection"
POSTGRES_CONNECTION = "postgres_connection"

# имя занято коннектом на БД самой установки: его предоставляет
# платформа инженерному коду (warehouse()), в каталоге он не хранится
RESERVED_CONNECTION_CODE = "warehouse"

CONNECTION_CLASSES: dict[str, tuple[FieldSpec, ...]] = {
    ORACLE_CONNECTION: (
        FieldSpec("host_name", "string"),
        FieldSpec("port_num", "integer"),
        FieldSpec("service_name", "string"),
        FieldSpec("user_name", "string"),
        FieldSpec("password", "string", secret=True),
    ),
    POSTGRES_CONNECTION: (
        FieldSpec("host_name", "string"),
        FieldSpec("port_num", "integer"),
        FieldSpec("database_name", "string"),
        FieldSpec("user_name", "string"),
        FieldSpec("password", "string", secret=True),
    ),
}


def validate_params(class_code: str, assigns: list[FieldAssign]) -> dict:
    """Проверка полей по классу; возвращает param_json с открытыми
    значениями и материализованными дефолтами (шифрование секретов —
    при записи)."""
    specs = {f.name: f for f in CONNECTION_CLASSES[class_code]}
    params: dict = {}
    for assign in assigns:
        spec = specs.get(assign.name)
        if spec is None:
            raise DplError(
                f"неизвестное поле {assign.name!r} класса {class_code}",
                pos=assign.name_pos,
                hint="поля класса: " + ", ".join(specs),
                sqlstate=SqlState.INVALID_PARAMETER_VALUE,
            )
        if assign.name in params:
            raise DplError(
                f"поле {assign.name!r} задано дважды",
                pos=assign.name_pos,
                sqlstate=SqlState.INVALID_PARAMETER_VALUE,
            )
        value = assign.value
        if spec.kind == "string":
            if value.kind != "string":
                raise DplError(
                    f"поле {assign.name!r} — строка: значение в одинарных"
                    " кавычках",
                    pos=value.pos,
                    sqlstate=SqlState.INVALID_PARAMETER_VALUE,
                )
            params[assign.name] = value.text
        else:
            if value.kind != "number":
                raise DplError(
                    f"поле {assign.name!r} — целое число",
                    pos=value.pos,
                    sqlstate=SqlState.INVALID_PARAMETER_VALUE,
                )
            params[assign.name] = int(value.text)
    for spec in CONNECTION_CLASSES[class_code]:
        if spec.name not in params:
            # все поля классов обязательны, дефолтов нет
            raise DplError(
                f"не задано обязательное поле {spec.name!r} класса"
                f" {class_code}",
                sqlstate=SqlState.INVALID_PARAMETER_VALUE,
            )
    return params


def secret_fields(class_code: str) -> frozenset[str]:
    return frozenset(f.name for f in CONNECTION_CLASSES[class_code] if f.secret)
