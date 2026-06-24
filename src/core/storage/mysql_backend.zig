//! MySQL/MariaDB `storage.Backend` over the in-tree pure-Zig MySQL driver
//! (`storage/mysql/`). Backs the `STORAGE_BACKEND=mysql` option. Mirrors
//! `postgres_backend.zig`: the runtime `BindValue` union maps onto the
//! driver's binary prepared-statement params; result columns come back as
//! the driver's typed `Value`s and are copied into the bounded `Row`.
//!
//! SQL uses `?` placeholders (the zorm `.mysql` dialect). Every statement is
//! run as a prepared statement (PREPARE → EXECUTE → CLOSE) so binds use the
//! binary protocol uniformly and `lastInsertId`/`changes` come from the OK
//! packet — matching the dialect's auto-PK-via-lastInsertId design.
//!
//! Constraint errors are classified from the MySQL server error code stashed
//! on the connection after a `ServerError`:
//!   1062 ER_DUP_ENTRY        → UniqueViolation
//!   1451/1452 ER_ROW_IS_REFERENCED_2 / ER_NO_REFERENCED_ROW_2 → ForeignKeyViolation
//!   1048 ER_BAD_NULL_ERROR   → NotNullViolation
//!
//! Transactions pin one pooled connection for the body's duration via a
//! thread-local (BEGIN/work/COMMIT on the same conn), exactly like the PG
//! backend; ordinary exec/query acquire-and-release per call.
//!
//! Tiger Style: bounded `Row` inline buffers; no per-call heap beyond the
//! driver's pool. Each statement closes its prepared handle on the way out.

const std = @import("std");
const mysql = @import("mysql/mysql.zig");
const backend_mod = @import("backend.zig");

const Error = backend_mod.Error;
const BindValue = backend_mod.BindValue;
const Row = backend_mod.Row;
const ColumnValue = backend_mod.ColumnValue;
const RowCallback = backend_mod.RowCallback;
const Backend = backend_mod.Backend;

const Conn = mysql.Conn;
const Pool = mysql.Pool;
const Param = mysql.Param;

// MySQL server error codes (subset mapped to typed constraint errors).
const ER_DUP_ENTRY: u16 = 1062;
const ER_BAD_NULL_ERROR: u16 = 1048;
const ER_NO_REFERENCED_ROW_2: u16 = 1452;
const ER_ROW_IS_REFERENCED_2: u16 = 1451;

pub const MysqlBackend = struct {
    pool: *Pool,
    last_changes: i64 = 0,
    last_insert_id: i64 = 0,

    /// Connection pinned for the current thread's open transaction.
    threadlocal var tx_conn: ?*Conn = null;

    pub fn init(pool: *Pool) MysqlBackend {
        return .{ .pool = pool };
    }

    pub fn backend(self: *MysqlBackend) Backend {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Backend.VTable = .{
        .exec = doExec,
        .query = doQuery,
        .queryOne = doQueryOne,
        .lastInsertId = doLastInsertId,
        .changes = doChanges,
        .transaction = doTransaction,
    };

    fn acquire(self: *MysqlBackend) Error!*Conn {
        if (tx_conn) |c| return c;
        return self.pool.acquire() catch return error.BackendFailed;
    }
    fn releaseIfNotTx(self: *MysqlBackend, conn: *Conn) void {
        if (tx_conn != conn) self.pool.release(conn);
    }

    /// Refine a driver `ServerError` into a typed constraint error using the
    /// MySQL error code captured on the connection. Non-constraint errors
    /// (and non-ServerError failures) fall back to `fallback`.
    fn classify(conn: *Conn, err: mysql.ConnError, fallback: Error) Error {
        if (err != error.ServerError) return mapDriverError(err, fallback);
        return switch (conn.last_err.code) {
            ER_DUP_ENTRY => error.UniqueViolation,
            ER_NO_REFERENCED_ROW_2, ER_ROW_IS_REFERENCED_2 => error.ForeignKeyViolation,
            ER_BAD_NULL_ERROR => error.NotNullViolation,
            else => fallback,
        };
    }

    fn mapDriverError(err: mysql.ConnError, fallback: Error) Error {
        return switch (err) {
            error.WriteFailed, error.ReadFailed, error.ConnectFailed, error.SocketError, error.DnsFailed, error.TlsFailed => error.BackendFailed,
            error.ProtocolError, error.UnsupportedAuth, error.PacketTooLarge, error.Truncated, error.Unsupported => error.StepFailed,
            else => fallback,
        };
    }

    /// Translate the runtime BindValue union onto the driver's binary params.
    /// Bounded to `max_params` (the ORM's CRUD never exceeds the column count
    /// of any one table).
    const max_params = 32;
    fn toParams(args: []const BindValue, out: *[max_params]Param) Error![]const Param {
        if (args.len > max_params) return error.BadBinding;
        for (args, 0..) |a, i| {
            out[i] = switch (a) {
                .null_ => .null_,
                .int => |v| .{ .int = v },
                .real => |v| .{ .real = v },
                .text => |s| .{ .text = s },
                .blob => |s| .{ .blob = s },
            };
        }
        return out[0..args.len];
    }

    fn doExec(ptr: *anyopaque, sql: []const u8, args: []const BindValue) Error!void {
        const self: *MysqlBackend = @ptrCast(@alignCast(ptr));
        const conn = try self.acquire();
        defer self.releaseIfNotTx(conn);

        var pbuf: [max_params]Param = undefined;
        const params = try toParams(args, &pbuf);

        const stmt = conn.prepare(sql) catch |e| return classify(conn, e, error.BadStatement);
        defer conn.closeStmt(stmt);
        conn.execPrepared(stmt, params) catch |e| return classify(conn, e, error.StepFailed);
        self.last_changes = @intCast(conn.last_affected);
        self.last_insert_id = @bitCast(conn.last_insert_id);
    }

    fn doQuery(ptr: *anyopaque, sql: []const u8, args: []const BindValue, ctx: *anyopaque, cb: RowCallback) Error!void {
        const self: *MysqlBackend = @ptrCast(@alignCast(ptr));
        const conn = try self.acquire();
        defer self.releaseIfNotTx(conn);

        var pbuf: [max_params]Param = undefined;
        const params = try toParams(args, &pbuf);

        const stmt = conn.prepare(sql) catch |e| return classify(conn, e, error.BadStatement);
        defer conn.closeStmt(stmt);

        var fwd = Forward{ .ctx = ctx, .cb = cb };
        conn.queryPrepared(stmt, params, &fwd, Forward.onRow) catch |e| return classify(conn, e, error.StepFailed);
    }

    fn doQueryOne(ptr: *anyopaque, sql: []const u8, args: []const BindValue, out: *Row) Error!bool {
        const self: *MysqlBackend = @ptrCast(@alignCast(ptr));
        const conn = try self.acquire();
        defer self.releaseIfNotTx(conn);

        var pbuf: [max_params]Param = undefined;
        const params = try toParams(args, &pbuf);

        const stmt = conn.prepare(sql) catch |e| return classify(conn, e, error.BadStatement);
        defer conn.closeStmt(stmt);

        var first = First{};
        conn.queryPrepared(stmt, params, &first, First.onRow) catch |e| return classify(conn, e, error.StepFailed);
        if (first.have) {
            out.* = first.row;
            return true;
        }
        out.column_count = 0;
        return false;
    }

    fn doLastInsertId(ptr: *anyopaque) i64 {
        const self: *MysqlBackend = @ptrCast(@alignCast(ptr));
        return self.last_insert_id;
    }

    fn doChanges(ptr: *anyopaque) i64 {
        const self: *MysqlBackend = @ptrCast(@alignCast(ptr));
        return self.last_changes;
    }

    fn doTransaction(ptr: *anyopaque, ctx: *anyopaque, body: *const fn (ctx: *anyopaque) Error!void) Error!void {
        const self: *MysqlBackend = @ptrCast(@alignCast(ptr));
        const conn = self.pool.acquire() catch return error.BackendFailed;
        defer self.pool.release(conn);
        conn.exec("BEGIN") catch return error.BackendFailed;
        tx_conn = conn;
        defer tx_conn = null;
        body(ctx) catch |err| {
            conn.exec("ROLLBACK") catch {};
            return err;
        };
        conn.exec("COMMIT") catch return error.BackendFailed;
    }

    /// Streaming-callback adapter: converts the driver `Row` into a backend
    /// `Row` (copying text/blob bytes inline) and forwards to the caller.
    const Forward = struct {
        ctx: *anyopaque,
        cb: RowCallback,
        fn onRow(p: *anyopaque, drow: *const mysql.Row) bool {
            const self: *Forward = @ptrCast(@alignCast(p));
            var out: Row = .{};
            fillRow(drow, &out);
            return self.cb(self.ctx, &out);
        }
    };

    /// Single-row sink for `queryOne`: captures the first row, then signals
    /// stop so the driver stops streaming.
    const First = struct {
        have: bool = false,
        row: Row = .{},
        fn onRow(p: *anyopaque, drow: *const mysql.Row) bool {
            const self: *First = @ptrCast(@alignCast(p));
            if (!self.have) {
                fillRow(drow, &self.row);
                self.have = true;
            }
            return false; // stop after the first row
        }
    };

    fn fillRow(drow: *const mysql.Row, out: *Row) void {
        const n: usize = @min(drow.count, backend_mod.max_columns);
        out.column_count = @intCast(n);
        var i: usize = 0;
        while (i < n) : (i += 1) {
            var cv: ColumnValue = .{};
            switch (drow.values[i]) {
                .null_ => cv.kind = .null_,
                .int => |v| {
                    cv.kind = .int;
                    cv.int_val = v;
                },
                .real => |v| {
                    cv.kind = .real;
                    cv.real_val = v;
                },
                .str => |s| {
                    cv.kind = .text;
                    copyInline(&cv, s);
                },
            }
            out.columns[i] = cv;
        }
    }

    fn copyInline(cv: *ColumnValue, s: []const u8) void {
        const cap = @min(s.len, backend_mod.max_inline_bytes);
        if (cap > 0) @memcpy(cv.bytes_buf[0..cap], s[0..cap]);
        cv.bytes_len = @intCast(cap);
    }
};

// ── Tests ──────────────────────────────────────────────────────────────
//
// Live round-trip against a MySQL/MariaDB server, gated on MYSQL_TEST_URL so
// the default suite never attempts a connect (a failed connect would fail
// the runner). Set MYSQL_TEST_URL=mysql://user:pass@host:port/db to exercise.
// Compiled always (pure-Zig); skips cleanly without a server.

const testing = std.testing;

fn parseTestUrl() ?mysql.Options {
    const url_c = std.c.getenv("MYSQL_TEST_URL") orelse return null;
    const uri_str = std.mem.sliceTo(url_c, 0);
    return parseMysqlUrl(uri_str);
}

/// Parse `mysql://user:pass@host:port/db`. Returns null on a malformed URL.
/// Shared with the provider; kept here so the backend test is self-contained.
pub fn parseMysqlUrl(uri_str: []const u8) ?mysql.Options {
    const uri = std.Uri.parse(uri_str) catch return null;
    var opts: mysql.Options = .{};
    if (uri.host) |h| opts.host = switch (h) {
        .raw => |r| r,
        .percent_encoded => |p| p,
    };
    if (uri.port) |p| opts.port = p;
    if (uri.user) |u| opts.username = switch (u) {
        .raw => |r| r,
        .percent_encoded => |p| p,
    };
    if (uri.password) |pw| opts.password = switch (pw) {
        .raw => |r| r,
        .percent_encoded => |p| p,
    };
    // Path is "/dbname".
    const path = switch (uri.path) {
        .raw => |r| r,
        .percent_encoded => |p| p,
    };
    if (path.len > 1) opts.database = path[1..];

    // Query: `?tls=require` (or `tls=disable`/absent) selects transport
    // security. We scan the raw query for a `tls=` token rather than a
    // full key/value parse — the only knob the driver honours today.
    if (uri.query) |q| {
        const qs = switch (q) {
            .raw => |r| r,
            .percent_encoded => |p| p,
        };
        if (tlsModeFromQuery(qs)) |m| opts.tls = m;
    }
    return opts;
}

/// Extract the `tls=` value from a URL query string. Recognises:
///   * `require`           — TLS with full CA + hostname verification (the
///                           secure default; a MITM cannot intercept).
///   * `require-noverify`  — TLS WITHOUT verification (encrypt only). Opt-in
///                           escape hatch for self-signed/dev servers.
///   * `disable`/`disabled`— plain TCP.
/// Returns null when no `tls=` token is present so the caller keeps its
/// default. Verification is never silently disabled: skipping it requires
/// the explicit `require-noverify` value.
fn tlsModeFromQuery(query: []const u8) ?mysql.TlsMode {
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const key = pair[0..eq];
        const val = pair[eq + 1 ..];
        if (!std.mem.eql(u8, key, "tls")) continue;
        if (std.mem.eql(u8, val, "require")) return .require;
        if (std.mem.eql(u8, val, "require-noverify")) return .require_noverify;
        if (std.mem.eql(u8, val, "disable") or std.mem.eql(u8, val, "disabled")) return .disabled;
    }
    return null;
}

test "parseMysqlUrl: extracts host/port/user/pass/db" {
    const o = parseMysqlUrl("mysql://app:s3cret@db.example:3307/speedy").?;
    try testing.expectEqualStrings("db.example", o.host);
    try testing.expectEqual(@as(u16, 3307), o.port);
    try testing.expectEqualStrings("app", o.username);
    try testing.expectEqualStrings("s3cret", o.password);
    try testing.expectEqualStrings("speedy", o.database);
}

test "parseMysqlUrl: defaults port + empty db" {
    const o = parseMysqlUrl("mysql://root@127.0.0.1/").?;
    try testing.expectEqual(@as(u16, 3306), o.port);
    try testing.expectEqualStrings("", o.database);
    // No query → TLS disabled by default (plain TCP, RSA full-auth path).
    try testing.expectEqual(mysql.TlsMode.disabled, o.tls);
}

test "parseMysqlUrl: tls=require selects TLS; tls=disable / absent stays plain" {
    const req = parseMysqlUrl("mysql://app:pw@db.example:3306/speedy?tls=require").?;
    try testing.expectEqual(mysql.TlsMode.require, req.tls);
    try testing.expectEqualStrings("speedy", req.database);

    const dis = parseMysqlUrl("mysql://app:pw@db.example/speedy?tls=disable").?;
    try testing.expectEqual(mysql.TlsMode.disabled, dis.tls);

    // Other params alongside tls= are ignored; tls= is still found.
    const mixed = parseMysqlUrl("mysql://app@h/db?charset=utf8&tls=require").?;
    try testing.expectEqual(mysql.TlsMode.require, mixed.tls);

    // Absent tls= leaves the default.
    const none = parseMysqlUrl("mysql://app@h/db?charset=utf8").?;
    try testing.expectEqual(mysql.TlsMode.disabled, none.tls);
}

test "parseMysqlUrl: tls=require verifies; only require-noverify opts out" {
    // The plain `require` token must select the verifying mode — skipping
    // certificate/hostname verification must never be the default.
    const req = parseMysqlUrl("mysql://app:pw@db.example/speedy?tls=require").?;
    try testing.expectEqual(mysql.TlsMode.require, req.tls);

    // The explicit escape hatch selects the unverified mode.
    const nv = parseMysqlUrl("mysql://app:pw@db.example/speedy?tls=require-noverify").?;
    try testing.expectEqual(mysql.TlsMode.require_noverify, nv.tls);

    // require-noverify alongside other params is still recognised.
    const nv_mixed = parseMysqlUrl("mysql://app@h/db?charset=utf8&tls=require-noverify").?;
    try testing.expectEqual(mysql.TlsMode.require_noverify, nv_mixed.tls);

    // A bare `require` (not the noverify variant) is the verifying mode even
    // when other tls-shaped values appear — guards against prefix confusion.
    const req2 = parseMysqlUrl("mysql://app@h/db?tls=require&extra=1").?;
    try testing.expectEqual(mysql.TlsMode.require, req2.tls);
}

test "MysqlBackend: live exec + queryOne + transaction (skips if no server)" {
    const opts = parseTestUrl() orelse return error.SkipZigTest;
    // size=1 so the per-connection TEMPORARY table is visible to every call.
    const pool = Pool.init(testing.allocator, opts, 1) catch return error.SkipZigTest;
    defer pool.deinit();
    var be_state = MysqlBackend.init(pool);
    const b = be_state.backend();

    b.exec("CREATE TEMPORARY TABLE sps_my_be (a BIGINT, t TEXT, d BLOB)", &.{}) catch return error.SkipZigTest;

    var prng = std.Random.DefaultPrng.init(testing.random_seed);
    const rand = prng.random();
    const a_val: i64 = rand.int(i32);
    var blob: [12]u8 = undefined;
    rand.bytes(&blob);

    try b.exec("INSERT INTO sps_my_be (a, t, d) VALUES (?, ?, ?)", &.{
        .{ .int = a_val }, .{ .text = "hello-my-zig" }, .{ .blob = &blob },
    });

    var row: Row = .{};
    try testing.expect(try b.queryOne("SELECT a, t, d FROM sps_my_be WHERE a = ?", &.{.{ .int = a_val }}, &row));
    try testing.expectEqual(a_val, row.columns[0].int_val);
    try testing.expectEqualStrings("hello-my-zig", row.columns[1].bytes());
    try testing.expectEqualSlices(u8, &blob, row.columns[2].bytes());
}
