-- Схема метаданных DataPulse; разворачивается командой create datapulse
-- в БД текущего подключения. Листинг чистый (нейминг-правила — docs/meta.md
-- прежнего репозитория, актуализация под per-DB модель — при переписи
-- доков); все ограничения — здесь. Строку datapulse.version с
-- объявленными схемами данных (usage) вставляет код команды.

create schema datapulse;

-- журнал версий пайплайна: строка — версия, не пайплайн; текущее
-- состояние — последняя строка; command — имя бампившей команды DPL,
-- src — её текст как пришёл; usage — объявленные схемы данных через
-- запятую, descr — описание установки (comment on datapulse) —
-- версионируются вместе с каталогом
create table datapulse.version (
    version_id   bigint       not null,
    create_time  timestamptz  not null,
    user_code    text         not null,
    command      text         not null,
    src          text         not null,
    descr        text,
    usage        text         not null,
    constraint pk_version primary key (version_id)
);

create table datapulse.dataset (
    version_id    bigint   not null,
    dataset_code  text     not null,
    is_deleted    boolean  not null,
    descr         text,
    constraint pk_dataset primary key (dataset_code, version_id),
    constraint uq_dataset__version_id unique (version_id),
    constraint fk_dataset__version_id
        foreign key (version_id)
        references datapulse.version (version_id)
        on delete cascade
);

create table datapulse.dataset_attr (
    version_id    bigint   not null,
    dataset_code  text     not null,
    attr_code     text     not null,
    order_num     integer  not null,
    type_code     text     not null,
    is_primary    boolean  not null,
    descr         text,
    constraint pk_dataset_attr
        primary key (dataset_code, version_id, attr_code),
    constraint fk_dataset_attr__version_id
        foreign key (version_id)
        references datapulse.version (version_id)
        on delete cascade,
    constraint fk_dataset_attr__dataset_code_version_id
        foreign key (dataset_code, version_id)
        references datapulse.dataset (dataset_code, version_id)
        on delete cascade,
    constraint ck_dataset_attr__order_num check (order_num >= 1)
);

create table datapulse.build_spec (
    version_id       bigint   not null,
    dataset_code     text     not null,
    build_spec_num   integer  not null,
    is_deleted       boolean  not null,
    descr            text,
    parallel_cnt     integer  not null default 1,
    chunk_attr_code  text     not null,
    body             text     not null,
    constraint pk_build_spec
        primary key (dataset_code, build_spec_num, version_id),
    constraint uq_build_spec__version_id unique (version_id),
    constraint fk_build_spec__version_id
        foreign key (version_id)
        references datapulse.version (version_id)
        on delete cascade,
    -- версия датасета бампится той же version_id — inner join без поиска
    -- «максимальной версии ≤»
    constraint fk_build_spec__dataset_code_version_id
        foreign key (dataset_code, version_id)
        references datapulse.dataset (dataset_code, version_id)
        on delete cascade,
    constraint ck_build_spec__build_spec_num check (build_spec_num >= 1),
    constraint ck_build_spec__parallel_cnt check (parallel_cnt >= 1)
);

create table datapulse.build_spec_mode (
    version_id      bigint   not null,
    dataset_code    text     not null,
    build_spec_num  integer  not null,
    mode_code       text     not null,
    type_code       text     not null,
    is_clear        boolean  not null,
    constraint pk_build_spec_mode
        primary key (dataset_code, build_spec_num, version_id, mode_code),
    constraint fk_build_spec_mode__version_id
        foreign key (version_id)
        references datapulse.version (version_id)
        on delete cascade,
    constraint fk_build_spec_mode__build_spec
        foreign key (dataset_code, build_spec_num, version_id)
        references datapulse.build_spec
            (dataset_code, build_spec_num, version_id)
        on delete cascade,
    constraint ck_build_spec_mode__type_code
        check (type_code in ('init', 'incr', 'sect', 'appd', 'skip'))
);

create table datapulse.build_spec_connection (
    version_id       bigint   not null,
    dataset_code     text     not null,
    build_spec_num   integer  not null,
    connection_code  text     not null,
    constraint pk_build_spec_connection
        primary key (dataset_code, build_spec_num, version_id,
                     connection_code),
    constraint fk_build_spec_connection__version_id
        foreign key (version_id)
        references datapulse.version (version_id)
        on delete cascade,
    constraint fk_build_spec_connection__build_spec
        foreign key (dataset_code, build_spec_num, version_id)
        references datapulse.build_spec
            (dataset_code, build_spec_num, version_id)
        on delete cascade
);

create table datapulse.build_spec_source (
    version_id           bigint   not null,
    dataset_code         text     not null,
    build_spec_num       integer  not null,
    source_dataset_code  text     not null,
    constraint pk_build_spec_source
        primary key (dataset_code, build_spec_num, version_id,
                     source_dataset_code),
    constraint fk_build_spec_source__version_id
        foreign key (version_id)
        references datapulse.version (version_id)
        on delete cascade,
    constraint fk_build_spec_source__build_spec
        foreign key (dataset_code, build_spec_num, version_id)
        references datapulse.build_spec
            (dataset_code, build_spec_num, version_id)
        on delete cascade
);

create table datapulse.connection (
    version_id       bigint   not null,
    connection_code  text     not null,
    is_deleted       boolean  not null,
    class_code       text     not null,
    param_json       jsonb    not null,
    constraint pk_connection primary key (connection_code, version_id),
    constraint uq_connection__version_id unique (version_id),
    constraint fk_connection__version_id
        foreign key (version_id)
        references datapulse.version (version_id)
        on delete cascade,
    constraint ck_connection__class_code
        check (class_code in ('oracle_connection', 'postgres_connection'))
);

-- билд: статика запуска; version_id — вотермарка версии метаданных;
-- ссылки на спеку — по значению, журнал переживает версии каталога
create table datapulse.build (
    version_id       bigint   not null,
    build_id         bigint   not null,
    dataset_code     text     not null,
    build_spec_num   integer  not null,
    mode_code        text     not null,
    is_clear         boolean  not null,
    user_code        text     not null,
    source_build_id  bigint,
    constraint pk_build primary key (build_id),
    constraint fk_build__version_id
        foreign key (version_id)
        references datapulse.version (version_id)
        on delete cascade
);

create index ix_build__dataset_code_build_spec_num
    on datapulse.build (dataset_code, build_spec_num, build_id);

-- единый журнал билда: статусы и печать общим потоком;
-- текущее состояние билда — status_code последней строки;
-- позиция build_log_id — из счётчика identity: журнал пишут
-- параллельные билды, каталожный замок им не нужен
create table datapulse.build_log (
    version_id        bigint       not null,
    build_log_id      bigint       generated always as identity,
    build_id          bigint       not null,
    log_time          timestamptz  not null,
    status_code       text         not null,
    message           text,
    prepared_row_cnt  bigint,
    inserted_row_cnt  bigint,
    updated_row_cnt   bigint,
    deleted_row_cnt   bigint,
    constraint pk_build_log primary key (build_log_id),
    constraint fk_build_log__version_id
        foreign key (version_id)
        references datapulse.version (version_id)
        on delete cascade,
    constraint fk_build_log__build_id
        foreign key (build_id)
        references datapulse.build (build_id)
        on delete cascade,
    constraint ck_build_log__status_code
        check (status_code in ('wait', 'load', 'comp', 'done', 'fail', 'fix'))
);

create index ix_build_log__build_id
    on datapulse.build_log (build_id, build_log_id);

-- целостность метаданных держится грантами: запись — только системной
-- роли (владельцу схемы), чтение — открыто; уточнение прав — вместе
-- с ролевой моделью DataPulse
grant usage on schema datapulse to public;
grant select on all tables in schema datapulse to public;
