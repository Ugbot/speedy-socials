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
    /// Saved connection config; the actual Pre-Login/TLS/LOGIN7 handshake is
    /// deferred to the first `dbProvider()` call so it runs at the provider's
    /// final, stable address (see below).
    cfg: conn_mod.Config,
    connected: bool = false,
    connect_err: ?Error = null,

    /// Parse a SQL-Server-style URI (`mssql://user:pass@host:port/db`,
    /// optional `?tls=require|off`) and stage the connection.
    ///
    /// ⚠️ The handshake is NOT performed here. `MssqlProvider` is returned by
    /// value, so the embedded `conn`'s address is not stable until the caller
    /// stores the result. When TLS is negotiated the std TLS client retains
    /// pointers into `conn`'s embedded transport, which a post-return move
    /// would dangle. We therefore defer the whole connect to `dbProvider()`,
    /// which runs once at the stable address. `init` only fails on an
    /// unparseable URI; connection failures surface from the first
    /// `dbProvider()`/`backendFor` use (and are logged by the boot path).
    pub fn init(uri_str: []const u8) Error!MssqlProvider {
        const cfg = parseUri(uri_str) orelse return error.OpenFailed;
        return .{ .conn = .{}, .mssql_backend = .{ .conn = undefined }, .cfg = cfg };
    }

    pub fn deinit(self: *MssqlProvider) void {
        if (self.connected) self.conn.close();
    }

    /// True once the deferred handshake has succeeded. Callers (e.g. the boot
    /// path) use this after `dbProvider()` to decide whether to fall back to
    /// SQLite when the server is unreachable.
    pub fn isConnected(self: *const MssqlProvider) bool {
        return self.connected;
    }

    /// Perform the deferred connect exactly once, at the stable `self`
    /// address. Idempotent; a prior failure is sticky (re-reported).
    fn ensureConnected(self: *MssqlProvider) Error!void {
        if (self.connected) return;
        if (self.connect_err) |e| return e;
        self.conn.connect(self.cfg) catch {
            self.connect_err = error.OpenFailed;
            return error.OpenFailed;
        };
        self.connected = true;
    }

    pub fn dbProvider(self: *MssqlProvider) DbProvider {
        // Bind the backend to our (now stable) owned conn address and run the
        // deferred handshake. A connect failure is swallowed here (the vtable
        // returns it on use); the provider object is still valid to hold.
        self.mssql_backend.conn = &self.conn;
        self.ensureConnected() catch {};
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

    // Optional `?tls=require|off` flag. Default off (plaintext fallback).
    var tls_mode: conn_mod.TlsMode = .off;
    if (uri.query) |q| {
        const qs = switch (q) {
            .raw => |x| x,
            .percent_encoded => |x| x,
        };
        tls_mode = parseTlsQuery(qs) orelse .off;
    }
    return .{
        .host = host,
        .port = uri.port orelse 1433,
        .username = user,
        .password = pass,
        .database = db,
        .tls = tls_mode,
    };
}

/// Scan a URI query string for a `tls=` key and map its value to a `TlsMode`.
/// Recognized values:
///   * `require`/`on`/`1`        → require WITH CA + hostname verification
///                                 (the secure default; MITM-resistant).
///   * `require-noverify`        → TLS WITHOUT verification (encrypt only).
///                                 Opt-in escape hatch for self-signed/dev.
///   * `off`/`disable`/`0`       → plaintext.
/// An unrecognized or absent value yields null (caller defaults to off).
/// Verification is never silently disabled: skipping it requires the explicit
/// `require-noverify` value.
fn parseTlsQuery(query: []const u8) ?conn_mod.TlsMode {
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const key = pair[0..eq];
        const val = pair[eq + 1 ..];
        if (!std.mem.eql(u8, key, "tls")) continue;
        // Check the noverify variant before the plain `require` prefix.
        if (std.mem.eql(u8, val, "require-noverify"))
            return .require_noverify;
        if (std.mem.eql(u8, val, "require") or std.mem.eql(u8, val, "on") or std.mem.eql(u8, val, "1"))
            return .require;
        if (std.mem.eql(u8, val, "off") or std.mem.eql(u8, val, "disable") or std.mem.eql(u8, val, "0"))
            return .off;
        return null;
    }
    return null;
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

test "MssqlProvider: parseUri tls flag defaults off and honors require/on/1" {
    const off_default = parseUri("mssql://u:p@h:1433/db") orelse return error.TestUnexpectedResult;
    try testing.expectEqual(conn_mod.TlsMode.off, off_default.tls);

    const req = parseUri("mssql://u:p@h:1433/db?tls=require") orelse return error.TestUnexpectedResult;
    try testing.expectEqual(conn_mod.TlsMode.require, req.tls);

    const on = parseUri("mssql://u:p@h:1433/db?tls=on") orelse return error.TestUnexpectedResult;
    try testing.expectEqual(conn_mod.TlsMode.require, on.tls);

    const one = parseUri("mssql://u:p@h:1433/db?tls=1") orelse return error.TestUnexpectedResult;
    try testing.expectEqual(conn_mod.TlsMode.require, one.tls);

    const explicit_off = parseUri("mssql://u:p@h:1433/db?tls=off") orelse return error.TestUnexpectedResult;
    try testing.expectEqual(conn_mod.TlsMode.off, explicit_off.tls);

    // Unknown value falls back to off (the safe plaintext default).
    const unknown = parseUri("mssql://u:p@h:1433/db?tls=banana") orelse return error.TestUnexpectedResult;
    try testing.expectEqual(conn_mod.TlsMode.off, unknown.tls);

    // tls flag mixed with other query keys.
    const mixed = parseUri("mssql://u:p@h:1433/db?foo=bar&tls=require&x=y") orelse return error.TestUnexpectedResult;
    try testing.expectEqual(conn_mod.TlsMode.require, mixed.tls);
}

test "MssqlProvider: tls=require verifies; only require-noverify opts out" {
    // Plain `require` selects the verifying mode — verification is never the
    // implicit default that gets skipped.
    const req = parseUri("mssql://u:p@h:1433/db?tls=require") orelse return error.TestUnexpectedResult;
    try testing.expectEqual(conn_mod.TlsMode.require, req.tls);

    // The explicit escape hatch selects the unverified mode.
    const nv = parseUri("mssql://u:p@h:1433/db?tls=require-noverify") orelse return error.TestUnexpectedResult;
    try testing.expectEqual(conn_mod.TlsMode.require_noverify, nv.tls);

    // require-noverify mixed with other query keys still resolves.
    const nv_mixed = parseUri("mssql://u:p@h:1433/db?foo=bar&tls=require-noverify&x=y") orelse return error.TestUnexpectedResult;
    try testing.expectEqual(conn_mod.TlsMode.require_noverify, nv_mixed.tls);
}

test "parseTlsQuery: recognized + unrecognized values" {
    try testing.expectEqual(conn_mod.TlsMode.require, parseTlsQuery("tls=require").?);
    try testing.expectEqual(conn_mod.TlsMode.require_noverify, parseTlsQuery("tls=require-noverify").?);
    try testing.expectEqual(conn_mod.TlsMode.off, parseTlsQuery("tls=off").?);
    try testing.expect(parseTlsQuery("tls=maybe") == null);
    try testing.expect(parseTlsQuery("other=1") == null);
    try testing.expect(parseTlsQuery("") == null);
}

test {
    _ = @import("mssql_backend.zig");
}
