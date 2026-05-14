//! Storage subsystem re-exports.

pub const sqlite = @import("storage/sqlite.zig");
pub const stmts = @import("storage/stmts.zig");
pub const channel = @import("storage/channel.zig");
pub const schema = @import("storage/schema.zig");
pub const handle = @import("storage/handle.zig");

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
}
