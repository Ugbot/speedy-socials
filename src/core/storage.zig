//! Storage subsystem re-exports.

pub const sqlite = @import("storage/sqlite.zig");
pub const stmts = @import("storage/stmts.zig");
pub const channel = @import("storage/channel.zig");
pub const schema = @import("storage/schema.zig");
pub const handle = @import("storage/handle.zig");
pub const backend = @import("storage/backend.zig");
pub const Backend = backend.Backend;
pub const SqliteBackend = backend.SqliteBackend;

/// Pluggable per-tenant database provider (DbProvider + SqliteProvider) and
/// the thread-local current-tenant routing seam. See `storage/provider.zig`.
pub const provider = @import("storage/provider.zig");
pub const DbProvider = provider.DbProvider;
pub const SqliteProvider = provider.SqliteProvider;
/// Pure-Zig Postgres DbProvider (over pg.zig). See `storage/postgres_provider.zig`.
pub const PostgresProvider = @import("storage/postgres_provider.zig").PostgresProvider;
/// Pure-Zig MySQL/MariaDB DbProvider (in-tree wire driver). See `storage/mysql_provider.zig`.
pub const MysqlProvider = @import("storage/mysql_provider.zig").MysqlProvider;
pub const MysqlBackend = @import("storage/mysql_backend.zig").MysqlBackend;
/// Pure-Zig MS SQL Server (TDS) DbProvider. Codec unit-tested; live validation
/// pending a runnable SQL Server. See `storage/mssql/`.
pub const MssqlProvider = @import("storage/mssql/mssql_provider.zig").MssqlProvider;
pub const MssqlBackend = @import("storage/mssql/mssql_backend.zig").MssqlBackend;

/// Zero-cost bridge from `Backend` to the standalone `zorm` library's
/// storage contract. See `storage/zorm_adapter.zig`.
pub const zorm_adapter = @import("storage/zorm_adapter.zig");
pub const setProvider = provider.setProvider;
pub const dbProvider = provider.provider;
pub const setCurrentTenant = provider.setCurrentTenant;
pub const currentHandle = provider.currentHandle;
pub const currentBackend = provider.currentBackend;
pub const clearCurrentTenant = provider.clearCurrent;

pub const StmtKey = stmts.StmtKey;
pub const StmtTable = stmts.StmtTable;
pub const Channel = channel.Channel;
pub const Query = channel.Query;
pub const Value = channel.Value;
pub const BindArgs = channel.BindArgs;
pub const Row = channel.Row;
pub const ResultValue = channel.ResultValue;
pub const QueryStatus = channel.QueryStatus;
pub const Schema = schema.Schema;
pub const Migration = schema.Migration;
pub const Handle = handle.Handle;
pub const Writer = sqlite.Writer;

pub const bootstrap_migration = @import("storage/migrations/0001_core.zig").migration;

test {
    _ = sqlite;
    _ = stmts;
    _ = channel;
    _ = schema;
    _ = handle;
    _ = backend;
    _ = provider;
    _ = PostgresProvider;
    _ = MysqlProvider;
    _ = MysqlBackend;
    _ = @import("storage/mysql/mysql.zig");
    _ = MssqlProvider;
    _ = MssqlBackend;
    _ = @import("storage/mssql/tds_test.zig");
    _ = zorm_adapter;
}
