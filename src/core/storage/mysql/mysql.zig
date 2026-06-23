//! Pure-Zig MySQL/MariaDB driver — module root.
//!
//! A minimal in-tree, dependency-free MySQL wire-protocol client (protocol
//! 41, mysql_native_password auth) sufficient to run the SQL zorm's `.mysql`
//! dialect emits. Chosen over vendoring an external driver as a submodule
//! because (a) the wire subset we need is small and (b) it keeps the codec
//! unit-testable without a server and avoids a 0.16 port of someone else's
//! std.net-based code. See `protocol.zig` for the pure codec, `conn.zig` for
//! the blocking-socket connection, `pool.zig` for the bounded pool.
//!
//! Parameter binding uses MySQL prepared-statement *binary* protocol
//! (COM_STMT_PREPARE/EXECUTE/CLOSE); the dialect's `?` placeholders map 1:1
//! onto positional binary params.

pub const protocol = @import("protocol.zig");
pub const Conn = @import("conn.zig").Conn;
pub const Options = @import("conn.zig").Options;
pub const Value = @import("conn.zig").Value;
pub const Row = @import("conn.zig").Row;
pub const RowCallback = @import("conn.zig").RowCallback;
pub const ConnError = @import("conn.zig").Error;
pub const Pool = @import("pool.zig").Pool;
pub const PoolError = @import("pool.zig").Error;
pub const Param = protocol.Param;

test {
    // Pull every submodule's tests into the driver test binary.
    _ = @import("protocol.zig");
    _ = @import("conn.zig");
    _ = @import("pool.zig");
}
