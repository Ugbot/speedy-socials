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

test {
    _ = contract;
    _ = fields;
    _ = reflect;
    _ = ddl;
}
