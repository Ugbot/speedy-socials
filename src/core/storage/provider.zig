//! Pluggable database provider (per-tenant routing + migration ownership).
//!
//! A `DbProvider` is the seam that lets storage backends coexist as
//! runtime-selectable OPTIONS (embedded SQLite by default; Postgres via
//! pg.zig under `STORAGE_BACKEND=postgres`) AND routes each request to its
//! tenant's database. The provider OWNS migrations — the composition root
//! hands it the assembled `Schema` and the provider applies it to the
//! default tenant and to each per-tenant database it opens.
//!
//! Per-request routing uses a thread-local "current handle" set by the
//! server after it resolves the Host→tenant mapping. Request handlers read
//! it via `core.storage.currentHandle()`, falling back to their attached
//! global handle when no per-tenant database is active — so the default
//! (single-tenant) deployment is byte-for-byte unchanged.
//!
//! Tiger Style: the tenant registry is a fixed-capacity array (no map, no
//! hot-path allocation); `handleFor`/`backendFor` are bounded linear scans;
//! the only allocation is opening a tenant DB at boot via `ensureTenant`.
//! Lookups after boot touch immutable state, so no lock is needed on the
//! hot path.

const std = @import("std");
const c = @import("sqlite").c;
const sqlite = @import("sqlite.zig");
const schema_mod = @import("schema.zig");
const backend_mod = @import("backend.zig");

const Schema = schema_mod.Schema;
const Backend = backend_mod.Backend;
const SqliteBackend = backend_mod.SqliteBackend;

pub const Error = error{
    ProviderFull,
    OpenFailed,
    MigrateFailed,
    PathTooLong,
};

/// Maximum distinct tenants a provider hosts (mirrors `core.tenancy`).
pub const max_tenants: usize = 16;
pub const max_id_bytes: usize = 32;

// ── DbProvider vtable ────────────────────────────────────────────────────

pub const DbProvider = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Apply the assembled migration set. The provider owns this:
        /// SQLite runs `Schema.applyAll` against the default + every tenant
        /// DB; Postgres applies its own (dialect) bootstrap. Boot-only.
        migrate: *const fn (ctx: *anyopaque, schema: *Schema) Error!void,
        /// Open + migrate a tenant's database and register it. Boot-only
        /// (may allocate). Idempotent.
        ensureTenant: *const fn (ctx: *anyopaque, tenant_id: []const u8) Error!void,
        /// Per-tenant raw SQLite handle, or null for backends without one
        /// (e.g. Postgres). Hot-path, alloc-free. Unknown id → default.
        handleFor: *const fn (ctx: *anyopaque, tenant_id: []const u8) ?*c.sqlite3,
        /// Per-tenant dialect-neutral `Backend`, or null. Hot-path, alloc-free.
        backendFor: *const fn (ctx: *anyopaque, tenant_id: []const u8) ?Backend,
        /// Release resources (close owned handles). Shutdown-only.
        deinit: *const fn (ctx: *anyopaque) void,
    };

    pub fn migrate(self: DbProvider, schema: *Schema) Error!void {
        return self.vtable.migrate(self.ctx, schema);
    }
    pub fn ensureTenant(self: DbProvider, tenant_id: []const u8) Error!void {
        return self.vtable.ensureTenant(self.ctx, tenant_id);
    }
    pub fn handleFor(self: DbProvider, tenant_id: []const u8) ?*c.sqlite3 {
        return self.vtable.handleFor(self.ctx, tenant_id);
    }
    pub fn backendFor(self: DbProvider, tenant_id: []const u8) ?Backend {
        return self.vtable.backendFor(self.ctx, tenant_id);
    }
    pub fn deinit(self: DbProvider) void {
        self.vtable.deinit(self.ctx);
    }
};

// ── Global provider + thread-local current-tenant seam ───────────────────

var global_provider: ?DbProvider = null;

pub fn setProvider(p: ?DbProvider) void {
    global_provider = p;
}
pub fn provider() ?DbProvider {
    return global_provider;
}

/// Per-request resolved tenant storage. Set by the server after Host→tenant
/// resolution; read by plugin handlers via `currentHandle`/`currentBackend`.
/// Null means "no specific tenant" → callers fall back to their global
/// handle, preserving single-tenant behaviour exactly.
threadlocal var current_db: ?*c.sqlite3 = null;
threadlocal var current_backend: ?Backend = null;

/// Resolve + cache the current request's tenant storage. A `""`/unknown
/// tenant (or no provider) clears the thread-local so the default global
/// handle is used. Bounded, alloc-free.
pub fn setCurrentTenant(tenant_id: []const u8) void {
    if (tenant_id.len == 0) {
        clearCurrent();
        return;
    }
    const p = global_provider orelse {
        clearCurrent();
        return;
    };
    current_db = p.handleFor(tenant_id);
    current_backend = p.backendFor(tenant_id);
}

pub fn currentHandle() ?*c.sqlite3 {
    return current_db;
}
pub fn currentBackend() ?Backend {
    return current_backend;
}
pub fn clearCurrent() void {
    current_db = null;
    current_backend = null;
}

// ──────────────────────────────────────────────────────────────────────
// SqliteProvider — the single embedded-SQLite DbProvider implementation.
// ──────────────────────────────────────────────────────────────────────

pub const SqliteProvider = struct {
    const Tenant = struct {
        id_buf: [max_id_bytes]u8 = undefined,
        id_len: u8 = 0,
        db: *c.sqlite3,
        owns: bool, // false for the default tenant (shares the global handle)
        sqlite_backend: SqliteBackend,

        fn id(self: *const Tenant) []const u8 {
            return self.id_buf[0..self.id_len];
        }
    };

    default_db: *c.sqlite3,
    default_backend: SqliteBackend,
    /// Stored at `migrate` so `ensureTenant` can apply the same schema to a
    /// freshly-opened tenant DB.
    schema: ?*Schema = null,
    /// `TENANT_DB_ROOT` (a directory); tenant DBs are `<root>/<id>.db`.
    root_buf: [256]u8 = undefined,
    root_len: u16 = 0,
    allocator: std.mem.Allocator,
    tenants: [max_tenants]Tenant = undefined,
    count: u8 = 0,

    pub fn init(allocator: std.mem.Allocator, default_db: *c.sqlite3, tenant_root: []const u8) SqliteProvider {
        var self: SqliteProvider = .{
            .default_db = default_db,
            .default_backend = SqliteBackend.init(default_db),
            .allocator = allocator,
        };
        const n = @min(tenant_root.len, self.root_buf.len);
        @memcpy(self.root_buf[0..n], tenant_root[0..n]);
        self.root_len = @intCast(n);
        return self;
    }

    fn root(self: *const SqliteProvider) []const u8 {
        return self.root_buf[0..self.root_len];
    }

    pub fn deinit(self: *SqliteProvider) void {
        var i: u8 = 0;
        while (i < self.count) : (i += 1) {
            if (self.tenants[i].owns) sqlite.closeDb(self.tenants[i].db);
        }
        self.count = 0;
    }

    pub fn dbProvider(self: *SqliteProvider) DbProvider {
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
        const self: *SqliteProvider = @ptrCast(@alignCast(ctx));
        self.schema = schema;
        schema.applyAll(self.default_db) catch return error.MigrateFailed;
        // Apply to any tenants already opened before migrate (normally none —
        // ensureTenant runs after migrate — but keep it order-independent).
        var i: u8 = 0;
        while (i < self.count) : (i += 1) {
            schema.applyAll(self.tenants[i].db) catch return error.MigrateFailed;
        }
    }

    fn doEnsureTenant(ctx: *anyopaque, tenant_id: []const u8) Error!void {
        const self: *SqliteProvider = @ptrCast(@alignCast(ctx));
        if (tenant_id.len == 0 or tenant_id.len > max_id_bytes) return; // default / invalid
        if (self.lookup(tenant_id) != null) return; // idempotent
        if (self.count >= max_tenants) return error.ProviderFull;

        // Build the per-tenant path `<root>/<id>.db` as a NUL-terminated
        // string for sqlite.openWriter.
        var path_buf: [512]u8 = undefined;
        const path = std.fmt.bufPrintZ(&path_buf, "{s}/{s}.db", .{ self.root(), tenant_id }) catch return error.PathTooLong;

        const db = sqlite.openWriter(path) catch return error.OpenFailed;
        errdefer sqlite.closeDb(db);
        if (self.schema) |s| s.applyAll(db) catch return error.MigrateFailed;

        var t: Tenant = .{ .db = db, .owns = true, .sqlite_backend = SqliteBackend.init(db) };
        @memcpy(t.id_buf[0..tenant_id.len], tenant_id);
        t.id_len = @intCast(tenant_id.len);
        self.tenants[self.count] = t;
        self.count += 1;
    }

    fn lookup(self: *SqliteProvider, tenant_id: []const u8) ?*Tenant {
        var i: u8 = 0;
        while (i < self.count) : (i += 1) {
            if (std.mem.eql(u8, self.tenants[i].id(), tenant_id)) return &self.tenants[i];
        }
        return null;
    }

    fn doHandleFor(ctx: *anyopaque, tenant_id: []const u8) ?*c.sqlite3 {
        const self: *SqliteProvider = @ptrCast(@alignCast(ctx));
        if (self.lookup(tenant_id)) |t| return t.db;
        return self.default_db;
    }

    fn doBackendFor(ctx: *anyopaque, tenant_id: []const u8) ?Backend {
        const self: *SqliteProvider = @ptrCast(@alignCast(ctx));
        if (self.lookup(tenant_id)) |t| return t.sqlite_backend.backend();
        return self.default_backend.backend();
    }

    fn doDeinit(ctx: *anyopaque) void {
        const self: *SqliteProvider = @ptrCast(@alignCast(ctx));
        self.deinit();
    }
};

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "SqliteProvider: default-only routing + thread-local seam is inert without tenants" {
    const db = try sqlite.openWriter(":memory:");
    defer sqlite.closeDb(db);
    var prov = SqliteProvider.init(testing.allocator, db, "/tmp/sps-tenants-test");
    defer prov.deinit();
    const p = prov.dbProvider();
    setProvider(p);
    defer setProvider(null);

    // No tenant set → currentHandle is null (callers use their global handle).
    clearCurrent();
    try testing.expect(currentHandle() == null);
    setCurrentTenant(""); // default tenant
    try testing.expect(currentHandle() == null);

    // handleFor falls back to the default db for any id.
    try testing.expect(p.handleFor("") == db);
    try testing.expect(p.handleFor("nope") == db);
}

test "SqliteProvider: per-tenant databases are isolated; migrate owns schema" {
    // Two tenants get two separate on-disk DBs; a row in one is absent in
    // the other. Uses unique /tmp paths; cleans up.
    const root = "/tmp/sps-prov-iso";
    _ = std.c.mkdir(root, 0o755);
    const db = try sqlite.openWriter(":memory:");
    defer sqlite.closeDb(db);

    var prov = SqliteProvider.init(testing.allocator, db, root);
    defer prov.deinit();
    const p = prov.dbProvider();

    // A tiny schema owned + applied by the provider. The first migration
    // creates the `migrations` bookkeeping table (applyAll's contract).
    var schema = Schema.init();
    try schema.register(.{ .id = 1, .name = "bookkeeping", .up = "CREATE TABLE migrations(id INTEGER PRIMARY KEY, name TEXT, applied_at INTEGER)", .down = null });
    try schema.register(.{ .id = 2, .name = "t", .up = "CREATE TABLE t (a INTEGER)", .down = null });
    try p.migrate(&schema);
    try p.ensureTenant("alpha");
    try p.ensureTenant("beta");

    const da = p.handleFor("alpha").?;
    const dbq = p.handleFor("beta").?;
    try testing.expect(da != dbq);
    try testing.expect(da != db and dbq != db);

    // Insert into alpha only.
    var em: [*c]u8 = null;
    _ = c.sqlite3_exec(da, "INSERT INTO t (a) VALUES (7)", null, null, &em);
    if (em != null) c.sqlite3_free(em);

    // Count via the per-tenant Backends (proves backendFor routing too).
    const ba = p.backendFor("alpha").?;
    const bb = p.backendFor("beta").?;
    var row: backend_mod.Row = .{};
    _ = try ba.queryOne("SELECT COUNT(*) FROM t", &.{}, &row);
    try testing.expectEqual(@as(i64, 1), row.columns[0].int_val);
    _ = try bb.queryOne("SELECT COUNT(*) FROM t", &.{}, &row);
    try testing.expectEqual(@as(i64, 0), row.columns[0].int_val);

    // Best-effort cleanup of the two tenant files.
    _ = std.c.unlink("/tmp/sps-prov-iso/alpha.db");
    _ = std.c.unlink("/tmp/sps-prov-iso/beta.db");
}

test "SqliteProvider: setCurrentTenant routes the thread-local to the tenant handle" {
    const root = "/tmp/sps-prov-tls";
    _ = std.c.mkdir(root, 0o755);
    const db = try sqlite.openWriter(":memory:");
    defer sqlite.closeDb(db);
    var prov = SqliteProvider.init(testing.allocator, db, root);
    defer prov.deinit();
    setProvider(prov.dbProvider());
    defer setProvider(null);

    var schema = Schema.init();
    try schema.register(.{ .id = 1, .name = "bookkeeping", .up = "CREATE TABLE migrations(id INTEGER PRIMARY KEY, name TEXT, applied_at INTEGER)", .down = null });
    try schema.register(.{ .id = 2, .name = "t", .up = "CREATE TABLE t (a INTEGER)", .down = null });
    try prov.dbProvider().migrate(&schema);
    try prov.dbProvider().ensureTenant("gamma");

    setCurrentTenant("gamma");
    try testing.expect(currentHandle() == prov.dbProvider().handleFor("gamma"));
    try testing.expect(currentHandle() != db);
    clearCurrent();
    try testing.expect(currentHandle() == null);
    _ = std.c.unlink("/tmp/sps-prov-tls/gamma.db");
}
