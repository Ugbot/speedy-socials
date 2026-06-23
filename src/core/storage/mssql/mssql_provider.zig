//! D2: Microsoft SQL Server `DbProvider` over the pure-Zig TDS connection
//! (`conn.zig`) + `MssqlBackend`. Backs a future `STORAGE_BACKEND=mssql`
//! option, mirroring `postgres_provider.zig`.
//!
//! This first cut owns a single TDS connection (one `Conn`) shared by all
//! tenants — adequate for the dialect-neutral, migrated query sites that
//! reach storage through `backendFor`. A bounded connection pool is a
//! follow-on (the seam already supports per-tenant routing).
//!
//! `migrate` is a documented **no-op**: the registered migrations are
//! SQLite-flavored, and zorm emits T-SQL DDL through its own Migrator
//! (`zorm/src/migrate.zig`, mssql dialect) rather than the host
//! `Schema.applyAll` path. Operators provision the SQL Server schema via
//! zorm's standalone Migrator or out-of-band, exactly as the Postgres
//! provider documents.
//!
//! ⚠️ LIVE VALIDATION PENDING A RUNNABLE SQL SERVER — see `conn.zig`. The
//! TDS codec is unit-tested in `tds_test.zig`; the network path is gated on
//! `MSSQL_TEST_URL` and skips when unset/unreachable, because this arm64
//! host cannot run SQL Server.
//!
//! Tiger Style: one owned `Conn` (fixed send/recv buffers); `handleFor`
//! returns null (no `*sqlite3`); `backendFor` hands back a pointer-stable
//! `Backend` over the embedded `MssqlBackend`.

const std = @import("std");
const c = @import("sqlite").c;
const conn_mod = @import("conn.zig");
const mssql_backend = @import("mssql_backend.zig");
const provider = @import("../provider.zig");
const backend_mod = @import("../backend.zig");
const schema_mod = @import("../schema.zig");

const DbProvider = provider.DbProvider;
const Error = provider.Error;
const Backend = backend_mod.Backend;
const Schema = schema_mod.Schema;
const Conn = conn_mod.Conn;
const MssqlBackend = mssql_backend.MssqlBackend;

pub const MssqlProvider = struct {
    conn: Conn,
    mssql_backend: MssqlBackend,

    /// Connect via a SQL-Server-style URI
    /// (`mssql://user:pass@host:port/db`). The single connection performs
    /// Pre-Login + LOGIN7 (SQL auth) during `init`.
    /// `MssqlProvider` is returned by value, so the embedded `conn`'s address
    /// is not stable until the caller stores the result. The backend's
    /// `conn` pointer is therefore (re)bound to the final, stable address in
    /// `dbProvider` — callers must reach the vtable through `dbProvider()`
    /// (which is the only way to obtain the `DbProvider`), so the backend is
    /// never dereferenced before its pointer is corrected.
    pub fn init(uri_str: []const u8) Error!MssqlProvider {
        const cfg = parseUri(uri_str) orelse return error.OpenFailed;
        var self: MssqlProvider = .{ .conn = .{}, .mssql_backend = .{ .conn = undefined } };
        self.conn.connect(cfg) catch return error.OpenFailed;
        return self;
    }

    pub fn deinit(self: *MssqlProvider) void {
        self.conn.close();
    }

    pub fn dbProvider(self: *MssqlProvider) DbProvider {
        // Bind the backend to our (now stable) owned conn address.
        self.mssql_backend.conn = &self.conn;
        return .{ .ctx = self, .vtable = &vtable };
    }

    const vtable: DbProvider.VTable = .{
        .migrate = doMigrate,
        .ensureTenant = doEnsureTenant,
        .handleFor = doHandleFor,
        .backendFor = doBackendFor,
        .deinit = doDeinit,
    };

    fn doMigrate(ctx: *anyopaque, schema: *Schema) Error!void {
        _ = ctx;
        _ = schema;
        // T-SQL migrations are owned by zorm's Migrator (mssql dialect), not
        // the SQLite-flavored host `Schema.applyAll`. Documented no-op:
        // operators provision the SQL Server schema via zorm out-of-band.
    }

    fn doEnsureTenant(ctx: *anyopaque, tenant_id: []const u8) Error!void {
        _ = ctx;
        _ = tenant_id;
        // Single shared connection in this cut; per-tenant databases are a
        // follow-on. No-op (default + every tenant resolve to the one conn).
    }

    fn doHandleFor(ctx: *anyopaque, tenant_id: []const u8) ?*c.sqlite3 {
        _ = ctx;
        _ = tenant_id;
        return null; // SQL Server has no sqlite handle.
    }

    fn doBackendFor(ctx: *anyopaque, tenant_id: []const u8) ?Backend {
        const self: *MssqlProvider = @ptrCast(@alignCast(ctx));
        _ = tenant_id;
        return self.mssql_backend.backend();
    }

    fn doDeinit(ctx: *anyopaque) void {
        const self: *MssqlProvider = @ptrCast(@alignCast(ctx));
        self.deinit();
    }
};

/// Parse `mssql://user:pass@host:port/db` into a connection config. Returns
/// null on any missing required component (host/user/password).
fn parseUri(uri_str: []const u8) ?conn_mod.Config {
    const uri = std.Uri.parse(uri_str) catch return null;
    const host = switch (uri.host orelse return null) {
        .raw => |h| h,
        .percent_encoded => |h| h,
    };
    const user = switch (uri.user orelse return null) {
        .raw => |u| u,
        .percent_encoded => |u| u,
    };
    const pass = switch (uri.password orelse return null) {
        .raw => |p| p,
        .percent_encoded => |p| p,
    };
    var db: []const u8 = "";
    const path = switch (uri.path) {
        .raw => |x| x,
        .percent_encoded => |x| x,
    };
    if (path.len > 1) db = path[1..];
    return .{
        .host = host,
        .port = uri.port orelse 1433,
        .username = user,
        .password = pass,
        .database = db,
    };
}

const testing = std.testing;

test "MssqlProvider: vtable shape" {
    try testing.expectEqual(DbProvider.VTable, @TypeOf(MssqlProvider.vtable));
}

test "MssqlProvider: parseUri extracts host/port/user/db" {
    const cfg = parseUri("mssql://sa:Secret123@db.example.com:14330/appdb") orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("db.example.com", cfg.host);
    try testing.expectEqual(@as(u16, 14330), cfg.port);
    try testing.expectEqualStrings("sa", cfg.username);
    try testing.expectEqualStrings("Secret123", cfg.password);
    try testing.expectEqualStrings("appdb", cfg.database);
}

test "MssqlProvider: parseUri defaults port 1433 + empty db" {
    const cfg = parseUri("mssql://u:p@host") orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u16, 1433), cfg.port);
    try testing.expectEqualStrings("", cfg.database);
}

test "MssqlProvider: parseUri rejects missing credentials" {
    try testing.expect(parseUri("mssql://host:1433/db") == null);
}

test {
    _ = @import("mssql_backend.zig");
}
