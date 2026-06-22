//! zorm — a high-performance, comptime-generated ORM + messaging layer for
//! Zig (a "Hibernate + Spring Messaging for Zig"). You declare an entity
//! struct ONCE using zorm field types; zorm generates — at compile time,
//! with no runtime reflection — its table DDL, CRUD SQL, change tracking,
//! relations, a wire codec, and a schema descriptor. Tiger Style: bounded
//! field types, per-session arenas, no per-row heap allocation.
//!
//! zorm is standalone and dependency-free: it knows nothing about any host
//! application. A host bridges its concrete storage / stream / queue
//! backends to zorm's contract via thin zero-cost adapters.
//!
//! Module map (built up across stages):
//!   contract.zig  — Backend / BindValue / Row / ColumnValue / Dialect / Error  (S0)
//!   fields.zig    — Text(N) / Bytes(N) / Pk(N) / AutoPk / Timestamp            (S1)
//!   reflect.zig   — comptime entity reflection (columnSpec, TableInfo)         (S1)
//!   ddl.zig       — createTable(T) + migration(T,id)                           (S1)
//!   sql.zig + bind.zig — comptime statement gen + field↔value marshaling       (S2)
//!   session.zig + repository.zig — identity map / unit-of-work / CRUD          (S3)
//!   query.zig     — typed query builder                                        (S4)
//!   relations.zig — BelongsTo / HasMany / HasOne                               (S5)
//!   codec.zig + schema_desc.zig — wire codec + schema for messaging            (S7)
//!   messaging.zig — typed publish/consume/enqueue over Sink/Queue              (S8)

const contract = @import("contract.zig");
const fields = @import("fields.zig");
const reflect = @import("reflect.zig");
const ddl = @import("ddl.zig");
const sql = @import("sql.zig");
const bind = @import("bind.zig");
const crud = @import("crud.zig");
const codec = @import("codec.zig");
const schema_desc = @import("schema_desc.zig");
const session = @import("session.zig");
const repository = @import("repository.zig");
const query = @import("query.zig");
const relations = @import("relations.zig");
const migrate = @import("migrate.zig");
const messaging = @import("messaging.zig");
pub const testing = @import("testing.zig");

// ── Storage contract (S0) ──────────────────────────────────────────────
pub const Backend = contract.Backend;
pub const BindValue = contract.BindValue;
pub const Row = contract.Row;
pub const ColumnValue = contract.ColumnValue;
pub const RowCallback = contract.RowCallback;
pub const Dialect = contract.Dialect;
pub const Error = contract.Error;
pub const max_columns = contract.max_columns;
pub const max_inline_bytes = contract.max_inline_bytes;

// ── Field types (S1) ───────────────────────────────────────────────────
pub const Text = fields.Text;
pub const Bytes = fields.Bytes;
pub const Pk = fields.Pk;
pub const AutoPk = fields.AutoPk;
pub const Timestamp = fields.Timestamp;

// ── Reflection + DDL (S1) ──────────────────────────────────────────────
pub const TableInfo = reflect.TableInfo;
pub const ColumnSpec = reflect.ColumnSpec;
pub const createTable = ddl.createTable;
pub const dropTable = ddl.dropTable;
pub const createIndex = ddl.createIndex;
pub const dropIndex = ddl.dropIndex;
pub const addColumn = ddl.addColumn;
pub const dropColumn = ddl.dropColumn;
pub const foreignKeyIndexes = ddl.foreignKeyIndexes;
pub const foreignKeys = reflect.foreignKeys;
pub const FkSpec = reflect.FkSpec;

// ── Migrations (M3) ────────────────────────────────────────────────────
pub const Migration = migrate.Migration;
pub const Migrator = migrate.Migrator;
pub const initialMigration = migrate.initialMigration;

// ── Marshaling + CRUD (S2) ─────────────────────────────────────────────
pub const PkValue = bind.PkValue;
pub const insert = crud.insert;
pub const upsert = crud.upsert;
pub const findByPk = crud.findByPk;
pub const update = crud.update;
pub const delete = crud.delete;
pub const deleteByPk = crud.deleteByPk;
pub const sql_gen = sql;
pub const marshal = bind;

// ── Wire codec + schema descriptor (S7) ────────────────────────────────
pub const serialize = codec.serialize;
pub const deserialize = codec.deserialize;
pub const Schema = schema_desc.Schema;
pub const schemaToJson = schema_desc.toJson;
pub const WireType = schema_desc.WireType;

// ── Session / identity map / unit-of-work + Repository (S3) ────────────
pub const Session = session.Session;
pub const Repository = repository.Repository;
pub const entityEql = session.entityEql;

// ── Query builder (S4) ─────────────────────────────────────────────────
pub const Query = query.Query;
pub const Dir = query.Dir;

// ── Relations (S5) ─────────────────────────────────────────────────────
pub const BelongsTo = relations.BelongsTo;
pub const HasMany = relations.HasMany;
pub const HasOne = relations.HasOne;
pub const Action = relations.Action;
pub const FkOpts = relations.FkOpts;

// ── Typed messaging over Sink / Queue (S8) ─────────────────────────────
pub const Sink = messaging.Sink;
pub const Queue = messaging.Queue;
pub const QueueItem = messaging.QueueItem;
pub const publish = messaging.publish;
pub const publishSchema = messaging.publishSchema;
pub const consume = messaging.consume;
pub const enqueue = messaging.enqueue;
pub const claim = messaging.claim;
pub const keyFor = messaging.keyFor;

test {
    _ = contract;
    _ = fields;
    _ = reflect;
    _ = ddl;
    _ = sql;
    _ = bind;
    _ = crud;
    _ = codec;
    _ = schema_desc;
    _ = session;
    _ = repository;
    _ = query;
    _ = relations;
    _ = migrate;
    _ = messaging;
    _ = testing;
}
