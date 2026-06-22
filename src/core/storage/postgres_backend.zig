//! Postgres `storage.Backend` over the vendored PURE-ZIG `pg.zig` driver
//! (no libpq). Backs the `STORAGE_BACKEND=postgres` option.
//!
//! Param binding maps the runtime `BindValue` union onto pg.zig's dynamic
//! statement API (`conn.prepare` → `stmt.prepareForBind(n)` →
//! `stmt.bind(value)` per arg → `stmt.execute`). Result columns are read
//! generically by switching on each column's PostgreSQL type oid
//! (`row.oids[col]`, a public field) and calling the matching
//! `row.get(T, col)`. SQL uses `$N` placeholders (Postgres dialect).
//!
//! Transactions pin one pooled connection for the body's duration via a
//! thread-local, so the BEGIN/work/COMMIT all run on the same connection;
//! ordinary exec/query acquire-and-release per call.
//!
//! Tiger Style: bounded result rows (`Row` inline buffers via `Row.set`);
//! no per-call heap beyond what pg.zig's pool manages internally.

const std = @import("std");
const pg = @import("pg");
const backend_mod = @import("backend.zig");

const Error = backend_mod.Error;
const BindValue = backend_mod.BindValue;
const Row = backend_mod.Row;
const ColumnValue = backend_mod.ColumnValue;
const RowCallback = backend_mod.RowCallback;
const Backend = backend_mod.Backend;

// Standard PostgreSQL built-in type oids (pg_type).
const OID_BOOL: i32 = 16;
const OID_BYTEA: i32 = 17;
const OID_INT8: i32 = 20;
const OID_INT2: i32 = 21;
const OID_INT4: i32 = 23;
const OID_FLOAT4: i32 = 700;
const OID_FLOAT8: i32 = 701;

pub const PostgresBackend = struct {
    pool: *pg.Pool,
    last_changes: i64 = 0,

    /// Connection pinned for the current thread's open transaction (if any),
    /// so exec/query inside `transaction` run on the same connection.
    threadlocal var tx_conn: ?*pg.Conn = null;

    pub fn init(pool: *pg.Pool) PostgresBackend {
        return .{ .pool = pool };
    }

    pub fn backend(self: *PostgresBackend) Backend {
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

    fn acquire(self: *PostgresBackend) Error!*pg.Conn {
        if (tx_conn) |c| return c;
        return self.pool.acquire() catch return error.BackendFailed;
    }
    fn releaseIfNotTx(self: *PostgresBackend, conn: *pg.Conn) void {
        if (tx_conn != conn) self.pool.release(conn);
    }

    /// Refine a pg.zig failure into a typed constraint error by inspecting
    /// the connection's last server error (SQLSTATE). pg.zig surfaces server
    /// errors as `error.PG` and stashes the parsed `proto.Error` (with its
    /// 5-char SQLSTATE `code`) on `conn.err`. The PostgreSQL class 23
    /// integrity-constraint codes map as: `23505` unique_violation,
    /// `23503` foreign_key_violation, `23502` not_null_violation. Anything
    /// else (including a null/absent error) falls back to `fallback`.
    fn classify(conn: *pg.Conn, fallback: Error) Error {
        const pg_err = conn.err orelse return fallback;
        const code = pg_err.code;
        if (std.mem.eql(u8, code, "23505")) return error.UniqueViolation;
        if (std.mem.eql(u8, code, "23503")) return error.ForeignKeyViolation;
        if (std.mem.eql(u8, code, "23502")) return error.NotNullViolation;
        return fallback;
    }

    fn bindAll(stmt: *pg.Stmt, args: []const BindValue) Error!void {
        stmt.prepareForBind(@intCast(args.len)) catch return error.BadStatement;
        for (args) |a| {
            (switch (a) {
                .null_ => stmt.bind(@as(?[]const u8, null)),
                .int => |v| stmt.bind(v),
                .real => |v| stmt.bind(v),
                .text => |s| stmt.bind(s),
                .blob => |s| stmt.bind(s),
            }) catch return error.BadBinding;
        }
    }

    fn doExec(ptr: *anyopaque, sql: []const u8, args: []const BindValue) Error!void {
        const self: *PostgresBackend = @ptrCast(@alignCast(ptr));
        const conn = try self.acquire();
        defer self.releaseIfNotTx(conn);
        var stmt = conn.prepare(sql) catch return error.BadStatement;
        defer stmt.deinit();
        try bindAll(&stmt, args);
        var result = stmt.execute() catch return classify(conn, error.StepFailed);
        defer result.deinit();
        result.drain() catch return classify(conn, error.StepFailed);
    }

    fn doQuery(ptr: *anyopaque, sql: []const u8, args: []const BindValue, ctx: *anyopaque, cb: RowCallback) Error!void {
        const self: *PostgresBackend = @ptrCast(@alignCast(ptr));
        const conn = try self.acquire();
        defer self.releaseIfNotTx(conn);
        var stmt = conn.prepare(sql) catch return error.BadStatement;
        defer stmt.deinit();
        try bindAll(&stmt, args);
        var result = stmt.execute() catch return classify(conn, error.StepFailed);
        defer result.deinit();
        while (result.next() catch return classify(conn, error.StepFailed)) |row| {
            var out: Row = .{};
            readRow(&row, &out);
            if (!cb(ctx, &out)) return;
        }
    }

    fn doQueryOne(ptr: *anyopaque, sql: []const u8, args: []const BindValue, out: *Row) Error!bool {
        const self: *PostgresBackend = @ptrCast(@alignCast(ptr));
        const conn = try self.acquire();
        defer self.releaseIfNotTx(conn);
        var stmt = conn.prepare(sql) catch return error.BadStatement;
        defer stmt.deinit();
        try bindAll(&stmt, args);
        var result = stmt.execute() catch return classify(conn, error.StepFailed);
        defer result.deinit();
        if (result.next() catch return classify(conn, error.StepFailed)) |row| {
            readRow(&row, out);
            result.drain() catch {};
            return true;
        }
        out.column_count = 0;
        return false;
    }

    fn doLastInsertId(_: *anyopaque) i64 {
        // Postgres has no implicit rowid; callers needing the new id use
        // `INSERT ... RETURNING id` and read it as a normal column.
        return 0;
    }

    fn doChanges(ptr: *anyopaque) i64 {
        const self: *PostgresBackend = @ptrCast(@alignCast(ptr));
        return self.last_changes;
    }

    fn doTransaction(ptr: *anyopaque, ctx: *anyopaque, body: *const fn (ctx: *anyopaque) Error!void) Error!void {
        const self: *PostgresBackend = @ptrCast(@alignCast(ptr));
        const conn = self.pool.acquire() catch return error.BackendFailed;
        defer self.pool.release(conn);
        conn.begin() catch return error.BackendFailed;
        tx_conn = conn;
        defer tx_conn = null;
        body(ctx) catch |err| {
            conn.rollback() catch {};
            return err;
        };
        conn.commit() catch return error.BackendFailed;
    }

    fn readRow(row: *const pg.Row, out: *Row) void {
        const n: usize = @min(row.oids.len, backend_mod.max_columns);
        out.column_count = @intCast(n);
        var i: usize = 0;
        while (i < n) : (i += 1) {
            var cv: ColumnValue = .{};
            const oid = row.oids[i];
            switch (oid) {
                OID_BOOL => {
                    cv.kind = .int;
                    cv.int_val = if (row.get(?bool, i) catch null) |b| (if (b) @as(i64, 1) else 0) else blk: {
                        cv.kind = .null_;
                        break :blk 0;
                    };
                },
                OID_INT2, OID_INT4, OID_INT8 => {
                    if (row.get(?i64, i) catch null) |v| {
                        cv.kind = .int;
                        cv.int_val = v;
                    } else cv.kind = .null_;
                },
                OID_FLOAT4, OID_FLOAT8 => {
                    if (row.get(?f64, i) catch null) |v| {
                        cv.kind = .real;
                        cv.real_val = v;
                    } else cv.kind = .null_;
                },
                OID_BYTEA => {
                    if (row.get(?[]const u8, i) catch null) |s| {
                        cv.kind = .blob;
                        copyInline(&cv, s);
                    } else cv.kind = .null_;
                },
                else => {
                    // text / varchar / numeric / everything else → text bytes.
                    if (row.get(?[]const u8, i) catch null) |s| {
                        cv.kind = .text;
                        copyInline(&cv, s);
                    } else cv.kind = .null_;
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
// Live round-trip against a Postgres server (skips when unreachable). A
// pg16 is expected on localhost:5433 (or PG_TEST_URL). Compiled always
// (pure-Zig); the test simply skips without a server.

const testing = std.testing;

fn testPool() ?*pg.Pool {
    // Gated on PG_TEST_URL so the default suite never attempts a connect
    // (a failed connect logs at err level, which fails the test runner).
    // Set PG_TEST_URL=postgresql://user:pass@host:port/db to exercise it.
    const url_c = std.c.getenv("PG_TEST_URL") orelse return null;
    const uri_str = std.mem.sliceTo(url_c, 0);
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    const io = threaded.io();
    const uri = std.Uri.parse(uri_str) catch return null;
    const pool = pg.Pool.initUri(io, testing.allocator, uri, .{ .size = 1, .timeout = 2000 }) catch return null;
    return pool;
}

test "PostgresBackend: live exec + queryOne + transaction (skips if no server)" {
    const pool = testPool() orelse return error.SkipZigTest;
    defer pool.deinit();
    var be_state = PostgresBackend.init(pool);
    const b = be_state.backend();

    b.exec("CREATE TEMP TABLE sps_pg_be (a BIGINT, t TEXT, d BYTEA)", &.{}) catch return error.SkipZigTest;

    var prng = std.Random.DefaultPrng.init(0x9_6_5_4);
    const rand = prng.random();
    const a_val: i64 = rand.int(i32);
    var blob: [12]u8 = undefined;
    rand.bytes(&blob);

    try b.exec("INSERT INTO sps_pg_be (a, t, d) VALUES ($1, $2, $3)", &.{
        .{ .int = a_val }, .{ .text = "hello-pg-zig" }, .{ .blob = &blob },
    });

    var row: Row = .{};
    try testing.expect(try b.queryOne("SELECT a, t, d FROM sps_pg_be WHERE a = $1", &.{.{ .int = a_val }}, &row));
    try testing.expectEqual(a_val, row.columns[0].int_val);
    try testing.expectEqualStrings("hello-pg-zig", row.columns[1].bytes());
    try testing.expectEqualSlices(u8, &blob, row.columns[2].bytes());

    // Transaction rollback leaves no extra row.
    const Ctx = struct {
        var bp: Backend = undefined;
        fn body(_: *anyopaque) Error!void {
            try bp.exec("INSERT INTO sps_pg_be (a, t, d) VALUES (1, 'x', '\\x00')", &.{});
            return error.BackendFailed;
        }
    };
    Ctx.bp = b;
    var dummy: u8 = 0;
    try testing.expectError(error.BackendFailed, b.transaction(&dummy, Ctx.body));
    var cnt: Row = .{};
    _ = try b.queryOne("SELECT COUNT(*) FROM sps_pg_be", &.{}, &cnt);
    try testing.expectEqual(@as(i64, 1), cnt.columns[0].int_val);
}
