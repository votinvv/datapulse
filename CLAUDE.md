# DataPulse — инструкции для ассистента

## Язык

Всё, кроме кода, — **по-русски**: доки, комментарии, сообщения об
ошибках, интерфейс, коммиты. Идентификаторы — английские.

## Что это

Прозрачный pgwire-прокси над кластером Postgres: пользовательский
трафик пробрасывается как есть под учёткой пользователя (сквозной
SCRAM), команды DPL перехватываются и исполняются под системной
учёткой. Установка per-DB (`create datapulse`), своей БД у продукта
нет. Читай [README](README.md) и [docs/](docs/) — это снимки
текущего состояния и целевой модели.

## Референсы (сверяться, не гадать)

- `C:\Project\datapulse_legacy` — донор (исходный продукт):
  `backend/app/schema/core.*.sql`, `sdk/datapulse/rules.py`,
  `backend/app/datatable.py` — истина по правилам валидации,
  SCD2-механике и физике таблиц спек.
- `C:\Project\datapulse_legacy_2` — прошлая (допивотная) итерация:
  парсер DPL, крипто, DDL-семантика, движковые куски — источник
  для переноса build_spec / do / build.
- История принятых решений живёт во внешней памяти ассистента, не
  в репо. Доки — снимки без истории; не реинкарнировать
  отвергнутое без нового довода.

## Структура

- `src/datapulse/` — код (src-layout — общее правило Python;
  пакет не устанавливается: docker — единственный заявленный
  способ запуска, зависимости объявлены в Dockerfile);
- `tests/` — pytest (`tests/conftest.py` добавляет `src` в path);
- `docs/` — requirements, architecture, protocol, model.

## Правила работы

- Не коммитить без явной просьбы; разрешение на один коммит не
  распространяется на следующие.
- Всегда перепроверять юниты и e2e перед завершением задачи;
  после правок кода пересобирать контейнер `datapulse`.
- Ошибки платформы — DplError с позицией (позиции в узлах команд —
  глобальные в тексте запроса); тексты ошибок — по-русски и
  закреплены тестами.

## Дев-окружение

- Тестовый Postgres — докер-контейнер `hdbki`
  (postgres:latest, порт 5432, postgres/postgres). E2E:
  `PG_HOST=127.0.0.1 PG_USER=postgres PG_PASSWORD=postgres
  python -m pytest tests -q`; служебная БД `datapulse_e2e`
  создаётся и сносится прогоном.
- Тестовый Oracle — докер-контейнер `rbsreps`
  (container-registry.oracle.com/database/enterprise:19.3.0.0,
  порт 1521, SYS: Oracle123, PDB `RBSREPS`, пользователь
  hdbki/hdbki). Первый старт создаёт базу ~15 минут.
- Дев-контейнер продукта: `docker build -t datapulse:dev .`,
  запуск на 8000 → бэкенд `host.docker.internal:5432`; БД `demo`
  на hdbki — песочница для ручных проверок через
  `psql "host=... port=8000 dbname=demo user=postgres
  password=postgres"` (изнутри контейнера hdbki —
  host=host.docker.internal).
- Windows: psycopg-async требует SelectorEventLoop
  (`loop_factory`), см. `__main__.py`.
