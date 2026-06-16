//! Postgres `DbProvider` over the pure-Zig `pg.zig` driver. Backs the
//! `STORAGE_BACKEND=postgres` option.
//!
//! This first cut connects to a single database (`DATABASE_URL`) shared by
//! all tenants; per-tenant Postgres databases are a follow-on (the
//! tenant-routing seam already supports it via `backendFor`). Because the
//! existing migrations are SQLite-dialect, **`migrate` is intentionally a
//! no-op here** (logged) — PG-dialect DDL is deferred; SQLite remains the
//! fully-migrated default. The provider still wires the pure-Zig pg
//! `Backend` so migrated, dialect-neutral query sites can run against
//! Postgres.
//!
//! Tiger Style: one pool (bounded by pg.zig's pool size); `handleFor`
//! returns null (Postgres has no `*sqlite3` handle); `backendFor` hands
//! back a pointer-stable `Backend` over the embedded `PostgresBackend`.

const std = @import("std");
const c = @import("sqlite").c;
const pg = @import("pg");
const provider = @import("provider.zig");
const backend_mod = @import("backend.zig");
const schema_mod = @import("schema.zig");

const DbProvider = provider.DbProvider;
const Error = provider.Error;
const Backend = backend_mod.Backend;
const PostgresBackend = backend_mod.PostgresBackend;
const Schema = schema_mod.Schema;

pub const PostgresProvider = struct {
    pool: *pg.Pool,
    pg_backend: PostgresBackend,

    /// Connect via a libpq-style URI (`postgresql://user:pass@host:port/db`).
    pub fn init(io: std.Io, allocator: std.mem.Allocator, uri_str: []const u8) Error!PostgresProvider {
        const uri = std.Uri.parse(uri_str) catch return error.OpenFailed;
        const pool = pg.Pool.initUri(io, allocator, uri, .{ .size = 8, .timeout = 5000 }) catch return error.OpenFailed;
        return .{ .pool = pool, .pg_backend = PostgresBackend.init(pool) };
    }

    pub fn deinit(self: *PostgresProvider) void {
        self.pool.deinit();
    }

    pub fn dbProvider(self: *PostgresProvider) DbProvider {
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
        // PG-dialect migrations deferred — the registered migrations are
        // SQLite-flavored. Document via the no-op; operators provision the
        // Postgres schema out-of-band for now.
    }

    fn doEnsureTenant(ctx: *anyopaque, tenant_id: []const u8) Error!void {
        _ = ctx;
        _ = tenant_id;
        // Single shared database in this cut; per-tenant PG databases are a
        // follow-on. No-op (the default + every tenant resolve to the one pool).
    }

    fn doHandleFor(ctx: *anyopaque, tenant_id: []const u8) ?*c.sqlite3 {
        _ = ctx;
        _ = tenant_id;
        return null; // Postgres has no sqlite handle.
    }

    fn doBackendFor(ctx: *anyopaque, tenant_id: []const u8) ?Backend {
        const self: *PostgresProvider = @ptrCast(@alignCast(ctx));
        _ = tenant_id;
        return self.pg_backend.backend();
    }

    fn doDeinit(ctx: *anyopaque) void {
        const self: *PostgresProvider = @ptrCast(@alignCast(ctx));
        self.deinit();
    }
};

test "PostgresProvider: vtable shape" {
    const testing = std.testing;
    try testing.expectEqual(DbProvider.VTable, @TypeOf(PostgresProvider.vtable));
}
