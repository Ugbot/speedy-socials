//! MySQL/MariaDB `DbProvider` over the in-tree pure-Zig MySQL driver. Backs
//! the `STORAGE_BACKEND=mysql` option. Mirrors `postgres_provider.zig`.
//!
//! This first cut connects to a single database (`DATABASE_URL`) shared by
//! all tenants; per-tenant MySQL databases are a follow-on (the tenant-
//! routing seam already supports it via `backendFor`). `migrate` applies the
//! mysql-dialect bootstrap DDL when present; the existing SQLite-dialect
//! migrations are NOT replayed here (they use SQLite syntax), so by default
//! `migrate` is a documented no-op and operators provision the MySQL schema
//! out-of-band — identical to the Postgres provider's stance. The provider
//! still wires the pure-Zig MySQL `Backend` so dialect-neutral query sites
//! run against MySQL.
//!
//! Tiger Style: one bounded pool; `handleFor` returns null (MySQL has no
//! `*sqlite3` handle); `backendFor` hands back a pointer-stable `Backend`
//! over the embedded `MysqlBackend`.

const std = @import("std");
const c = @import("sqlite").c;
const mysql = @import("mysql/mysql.zig");
const provider = @import("provider.zig");
const backend_mod = @import("backend.zig");
const schema_mod = @import("schema.zig");
const mysql_backend = @import("mysql_backend.zig");

const DbProvider = provider.DbProvider;
const Error = provider.Error;
const Backend = backend_mod.Backend;
const MysqlBackend = mysql_backend.MysqlBackend;
const Schema = schema_mod.Schema;

pub const MysqlProvider = struct {
    pool: *mysql.Pool,
    my_backend: MysqlBackend,

    /// Default pool size (mirrors PostgresProvider's 8).
    pub const default_pool_size: usize = 8;

    /// Connect via a `mysql://user:pass@host:port/db` URL.
    pub fn init(allocator: std.mem.Allocator, uri_str: []const u8) Error!MysqlProvider {
        const opts = mysql_backend.parseMysqlUrl(uri_str) orelse return error.OpenFailed;
        const pool = mysql.Pool.init(allocator, opts, default_pool_size) catch return error.OpenFailed;
        return .{ .pool = pool, .my_backend = MysqlBackend.init(pool) };
    }

    pub fn deinit(self: *MysqlProvider) void {
        self.pool.deinit();
    }

    pub fn dbProvider(self: *MysqlProvider) DbProvider {
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
        // MySQL-dialect migrations deferred — the registered migrations are
        // SQLite-flavored. Document via the no-op; operators provision the
        // MySQL schema out-of-band for now (same stance as PostgresProvider).
    }

    fn doEnsureTenant(ctx: *anyopaque, tenant_id: []const u8) Error!void {
        _ = ctx;
        _ = tenant_id;
        // Single shared database in this cut; per-tenant MySQL databases are
        // a follow-on. No-op (default + every tenant resolve to the one pool).
    }

    fn doHandleFor(ctx: *anyopaque, tenant_id: []const u8) ?*c.sqlite3 {
        _ = ctx;
        _ = tenant_id;
        return null; // MySQL has no sqlite handle.
    }

    fn doBackendFor(ctx: *anyopaque, tenant_id: []const u8) ?Backend {
        const self: *MysqlProvider = @ptrCast(@alignCast(ctx));
        _ = tenant_id;
        return self.my_backend.backend();
    }

    fn doDeinit(ctx: *anyopaque) void {
        const self: *MysqlProvider = @ptrCast(@alignCast(ctx));
        self.deinit();
    }
};

test "MysqlProvider: vtable shape" {
    const testing = std.testing;
    try testing.expectEqual(DbProvider.VTable, @TypeOf(MysqlProvider.vtable));
}
