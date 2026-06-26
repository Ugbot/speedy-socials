//! Postgres `DbProvider` over the pure-Zig `pg.zig` driver. Backs the
//! `STORAGE_BACKEND=postgres` option.
//!
//! F7: this provider now OWNS Postgres-dialect migrations and per-tenant
//! Postgres databases.
//!
//!   * `migrate` applies every registered migration's `up_pg` (the
//!     Postgres-dialect DDL) to the connected database, recording applied
//!     ids in a `migrations` bookkeeping table — the same idempotent,
//!     transaction-per-migration contract as the SQLite `Schema.applyAll`,
//!     but issued over `pg.zig`'s simple-query protocol (multi-statement
//!     DDL in one round-trip). A migration with a null `up_pg` is a hard
//!     error: every migration must carry a PG variant for PG to be a
//!     complete backend.
//!   * `ensureTenant` provisions a per-tenant database (`CREATE DATABASE
//!     tenant_<id>`), opens a dedicated pool, and migrates it. `backendFor`
//!     then routes that tenant's requests to its own database; unknown
//!     tenants fall back to the shared default database.
//!
//! Validation note: the in-process pg.zig path currently stalls against
//! some servers (a known std.Io interaction), so the generated `up_pg` DDL
//! is validated out-of-process via `psql`; the pure URI/identifier helpers
//! below are unit-tested directly. The apply loop mirrors the proven
//! SQLite `applyAll`.
//!
//! Tiger Style: bounded per-tenant registry (`max_tenants`); `handleFor`
//! returns null (Postgres has no `*sqlite3` handle); `backendFor` hands
//! back a pointer-stable `Backend`; the only allocation is opening a pool.

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

const max_tenants = provider.max_tenants;
const max_id_bytes = provider.max_id_bytes;

pub const PostgresProvider = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    pool: *pg.Pool,
    pg_backend: PostgresBackend,
    /// Owned copy of the base connection URI, used to derive per-tenant
    /// URIs (same server, different database name).
    base_uri_buf: [512]u8 = undefined,
    base_uri_len: usize = 0,
    /// Schema captured at `migrate`, reused to migrate per-tenant DBs.
    schema: ?*Schema = null,
    tenants: [max_tenants]Tenant = undefined,
    count: usize = 0,

    const Tenant = struct {
        id_buf: [max_id_bytes]u8 = undefined,
        id_len: usize = 0,
        pool: *pg.Pool,
        pg_backend: PostgresBackend,

        fn id(self: *const Tenant) []const u8 {
            return self.id_buf[0..self.id_len];
        }
    };

    /// Connect via a libpq-style URI (`postgresql://user:pass@host:port/db`).
    pub fn init(io: std.Io, allocator: std.mem.Allocator, uri_str: []const u8) Error!PostgresProvider {
        if (uri_str.len > 512) return error.PathTooLong;
        const uri = std.Uri.parse(uri_str) catch return error.OpenFailed;
        const pool = pg.Pool.initUri(io, allocator, uri, .{ .size = 8, .timeout = 5000 }) catch return error.OpenFailed;
        var self: PostgresProvider = .{
            .io = io,
            .allocator = allocator,
            .pool = pool,
            .pg_backend = PostgresBackend.init(pool),
        };
        @memcpy(self.base_uri_buf[0..uri_str.len], uri_str);
        self.base_uri_len = uri_str.len;
        return self;
    }

    pub fn deinit(self: *PostgresProvider) void {
        var i: usize = 0;
        while (i < self.count) : (i += 1) self.tenants[i].pool.deinit();
        self.pool.deinit();
    }

    pub fn dbProvider(self: *PostgresProvider) DbProvider {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn baseUri(self: *const PostgresProvider) []const u8 {
        return self.base_uri_buf[0..self.base_uri_len];
    }

    fn lookup(self: *PostgresProvider, tenant_id: []const u8) ?*Tenant {
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            if (std.mem.eql(u8, self.tenants[i].id(), tenant_id)) return &self.tenants[i];
        }
        return null;
    }

    const vtable: DbProvider.VTable = .{
        .migrate = doMigrate,
        .ensureTenant = doEnsureTenant,
        .handleFor = doHandleFor,
        .backendFor = doBackendFor,
        .deinit = doDeinit,
    };

    fn doMigrate(ctx: *anyopaque, schema: *Schema) Error!void {
        const self: *PostgresProvider = @ptrCast(@alignCast(ctx));
        self.schema = schema;
        try pgApplyAll(self.pool, schema);
    }

    fn doEnsureTenant(ctx: *anyopaque, tenant_id: []const u8) Error!void {
        const self: *PostgresProvider = @ptrCast(@alignCast(ctx));
        if (tenant_id.len == 0 or tenant_id.len > max_id_bytes) return; // default / invalid
        if (self.lookup(tenant_id) != null) return; // idempotent
        if (self.count >= max_tenants) return error.ProviderFull;

        var name_buf: [64]u8 = undefined;
        const dbname = buildTenantDbName(tenant_id, &name_buf) orelse return error.OpenFailed;

        // CREATE DATABASE runs in autocommit (it cannot be transactional).
        // An "already exists" failure is benign — recover the connection
        // and proceed to migrate the existing database.
        {
            const conn = self.pool.acquire() catch return error.OpenFailed;
            defer self.pool.release(conn);
            var sql_buf: [128]u8 = undefined;
            const create_sql = std.fmt.bufPrint(&sql_buf, "CREATE DATABASE \"{s}\"", .{dbname}) catch return error.PathTooLong;
            _ = conn.exec(create_sql, .{}) catch {
                conn.readyForQuery() catch {};
            };
        }

        // Open a dedicated pool to the tenant database and migrate it.
        var uri_buf: [640]u8 = undefined;
        const turi = buildTenantUri(self.baseUri(), dbname, &uri_buf) orelse return error.PathTooLong;
        const parsed = std.Uri.parse(turi) catch return error.OpenFailed;
        const tpool = pg.Pool.initUri(self.io, self.allocator, parsed, .{ .size = 4, .timeout = 5000 }) catch return error.OpenFailed;
        errdefer tpool.deinit();
        if (self.schema) |s| try pgApplyAll(tpool, s);

        var t: Tenant = .{ .pool = tpool, .pg_backend = PostgresBackend.init(tpool) };
        @memcpy(t.id_buf[0..tenant_id.len], tenant_id);
        t.id_len = tenant_id.len;
        self.tenants[self.count] = t;
        self.count += 1;
    }

    fn doHandleFor(ctx: *anyopaque, tenant_id: []const u8) ?*c.sqlite3 {
        _ = ctx;
        _ = tenant_id;
        return null; // Postgres has no sqlite handle.
    }

    fn doBackendFor(ctx: *anyopaque, tenant_id: []const u8) ?Backend {
        const self: *PostgresProvider = @ptrCast(@alignCast(ctx));
        if (tenant_id.len > 0) {
            if (self.lookup(tenant_id)) |t| return t.pg_backend.backend();
        }
        return self.pg_backend.backend();
    }

    fn doDeinit(ctx: *anyopaque) void {
        const self: *PostgresProvider = @ptrCast(@alignCast(ctx));
        self.deinit();
    }
};

/// Apply every not-yet-recorded migration's `up_pg` to `pool`'s database,
/// each in its own transaction, recording the id in `migrations`. Mirrors
/// `Schema.applyAll` over the pg.zig simple-query protocol.
fn pgApplyAll(pool: *pg.Pool, schema: *Schema) Error!void {
    schema.sort();
    const conn = pool.acquire() catch return error.MigrateFailed;
    defer pool.release(conn);

    // Guarantee the bookkeeping table exists so the per-migration
    // `isApplied` probe never trips on a missing relation. Migration #1
    // also creates it (IF NOT EXISTS), so this is a harmless pre-step.
    _ = conn.exec(
        \\CREATE TABLE IF NOT EXISTS migrations (
        \\    id BIGINT PRIMARY KEY,
        \\    name TEXT NOT NULL,
        \\    applied_at BIGINT NOT NULL
        \\)
    , .{}) catch return error.MigrateFailed;

    var i: u32 = 0;
    while (i < schema.count) : (i += 1) {
        const m = schema.migrations[i];
        if (pgIsApplied(conn, m.id)) continue;
        const ddl = m.up_pg orelse return error.MigrateFailed;

        conn.begin() catch return error.MigrateFailed;
        _ = conn.exec(ddl, .{}) catch {
            conn.rollback() catch {};
            return error.MigrateFailed;
        };
        _ = conn.exec(
            "INSERT INTO migrations (id, name, applied_at) VALUES ($1, $2, EXTRACT(EPOCH FROM now())::bigint)",
            .{ m.id, m.name },
        ) catch {
            conn.rollback() catch {};
            return error.MigrateFailed;
        };
        conn.commit() catch return error.MigrateFailed;
    }
}

fn pgIsApplied(conn: *pg.Conn, id: u32) bool {
    var maybe = conn.row("SELECT 1 FROM migrations WHERE id = $1", .{id}) catch return false;
    if (maybe) |*r| {
        r.deinit() catch {};
        return true;
    }
    return false;
}

/// Map a tenant id to a safe Postgres database identifier `tenant_<id>`.
/// Only `[a-z0-9_]` (case-folded) is allowed in the id — anything else is
/// rejected (`null`) rather than risk an injection into `CREATE DATABASE`,
/// which cannot use a bound parameter for the name.
fn buildTenantDbName(tenant_id: []const u8, out: []u8) ?[]const u8 {
    const prefix = "tenant_";
    if (tenant_id.len == 0 or tenant_id.len > max_id_bytes) return null;
    if (prefix.len + tenant_id.len > out.len) return null;
    @memcpy(out[0..prefix.len], prefix);
    var w: usize = prefix.len;
    for (tenant_id) |ch| {
        const lc = std.ascii.toLower(ch);
        const ok = (lc >= 'a' and lc <= 'z') or (lc >= '0' and lc <= '9') or lc == '_';
        if (!ok) return null;
        out[w] = lc;
        w += 1;
    }
    return out[0..w];
}

/// Derive a per-tenant connection URI from `base` by swapping the database
/// segment of the path for `tenant_db`, preserving scheme/authority and any
/// query string. Returns null on a malformed base URI / overflow.
fn buildTenantUri(base: []const u8, tenant_db: []const u8, out: []u8) ?[]const u8 {
    const sep = std.mem.indexOf(u8, base, "://") orelse return null;
    const auth_start = sep + 3;
    const path_slash = std.mem.indexOfScalarPos(u8, base, auth_start, '/') orelse return null;
    const path_end = std.mem.indexOfScalarPos(u8, base, path_slash, '?') orelse base.len;
    const head = base[0 .. path_slash + 1];
    const tail = base[path_end..];
    if (head.len + tenant_db.len + tail.len > out.len) return null;
    var w: usize = 0;
    @memcpy(out[w..][0..head.len], head);
    w += head.len;
    @memcpy(out[w..][0..tenant_db.len], tenant_db);
    w += tenant_db.len;
    @memcpy(out[w..][0..tail.len], tail);
    w += tail.len;
    return out[0..w];
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

test "PostgresProvider: vtable shape" {
    try testing.expectEqual(DbProvider.VTable, @TypeOf(PostgresProvider.vtable));
}

test "buildTenantDbName: prefixes + case-folds + rejects unsafe ids" {
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("tenant_acme", buildTenantDbName("ACME", &buf).?);
    try testing.expectEqualStrings("tenant_org_42", buildTenantDbName("org_42", &buf).?);
    // Injection / unsafe characters rejected.
    try testing.expect(buildTenantDbName("a\"; DROP DATABASE x; --", &buf) == null);
    try testing.expect(buildTenantDbName("a b", &buf) == null);
    try testing.expect(buildTenantDbName("a-b", &buf) == null);
    try testing.expect(buildTenantDbName("", &buf) == null);
}

test "buildTenantUri: swaps db segment, preserves authority + query" {
    var buf: [256]u8 = undefined;
    try testing.expectEqualStrings(
        "postgresql://u:p@host:5432/tenant_acme",
        buildTenantUri("postgresql://u:p@host:5432/speedy", "tenant_acme", &buf).?,
    );
    try testing.expectEqualStrings(
        "postgresql://u:p@host:5432/tenant_acme?sslmode=require",
        buildTenantUri("postgresql://u:p@host:5432/speedy?sslmode=require", "tenant_acme", &buf).?,
    );
    // Malformed bases.
    try testing.expect(buildTenantUri("not-a-uri", "tenant_x", &buf) == null);
    try testing.expect(buildTenantUri("postgresql://host-no-path", "tenant_x", &buf) == null);
}

test "buildTenantUri: randomized round-trip keeps host + tenant db" {
    var prng = std.Random.DefaultPrng.init(testing.random_seed);
    const rand = prng.random();
    var buf: [256]u8 = undefined;
    var iter: usize = 0;
    while (iter < 64) : (iter += 1) {
        const port = rand.intRangeAtMost(u16, 1, 65535);
        var base_buf: [128]u8 = undefined;
        const base = std.fmt.bufPrint(&base_buf, "postgresql://user:pw@db{d}.example:{d}/origdb", .{ rand.int(u16), port }) catch unreachable;
        const got = buildTenantUri(base, "tenant_z", &buf).?;
        try testing.expect(std.mem.endsWith(u8, got, "/tenant_z"));
        try testing.expect(std.mem.indexOf(u8, got, "origdb") == null);
        try testing.expect(std.mem.startsWith(u8, got, "postgresql://user:pw@"));
    }
}
