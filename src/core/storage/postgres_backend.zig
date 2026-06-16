//! Phase G: Postgres storage backend implementing `core.storage.Backend`
//! via libpq.
//!
//! Compiled only under `-Dpostgres` (see `build.zig`); `backend.zig` gates
//! the import behind the same flag so the default build needs no libpq
//! headers. Selected at boot with `STORAGE_BACKEND=postgres` +
//! `DATABASE_URL` (a libpq conninfo string / URI).
//!
//! Parameter binding: SQL uses `$1,$2,…` placeholders (the caller's
//! `?`-style SQL must be written for Postgres, or translated — the
//! migrated query sites use `$N` for this backend). Scalars are bound in
//! libpq *text* format (Postgres parses them); blobs are bound in *binary*
//! format against `bytea` columns. Results are read in text format and
//! typed by their column OID so the `ColumnValue` kind matches what the
//! SQLite backend would return for the analogous column.
//!
//! Tiger Style: one connection per backend instance; no allocation on the
//! query path — bind values are formatted into a fixed stack scratch
//! buffer, capped at `max_params` / `scratch_bytes`.

const std = @import("std");
const backend_mod = @import("backend.zig");

const Error = backend_mod.Error;
const BindValue = backend_mod.BindValue;
const Row = backend_mod.Row;
const ColumnValue = backend_mod.ColumnValue;
const RowCallback = backend_mod.RowCallback;
const Backend = backend_mod.Backend;

pub const c = @cImport({
    @cInclude("libpq-fe.h");
});

// Postgres built-in type OIDs (from pg_type). libpq-fe.h doesn't expose
// these, so we name the ones we map. Stable across versions.
const OID_BOOL: c_uint = 16;
const OID_BYTEA: c_uint = 17;
const OID_INT8: c_uint = 20;
const OID_INT2: c_uint = 21;
const OID_INT4: c_uint = 23;
const OID_FLOAT4: c_uint = 700;
const OID_FLOAT8: c_uint = 701;
const OID_NUMERIC: c_uint = 1700;

pub const max_params: usize = 32;
pub const scratch_bytes: usize = 16 * 1024;

/// Per-call parameter marshalling buffer. Built fresh on the stack for
/// each exec/query so there is no shared mutable state.
const Params = struct {
    values: [max_params][*c]const u8 = undefined,
    lengths: [max_params]c_int = undefined,
    formats: [max_params]c_int = undefined,
    scratch: [scratch_bytes]u8 = undefined,
    scratch_used: usize = 0,
    n: c_int = 0,

    fn allocZ(self: *Params, bytes: []const u8) Error![*c]const u8 {
        // Copy `bytes` + a NUL into scratch, return a C pointer to it.
        if (self.scratch_used + bytes.len + 1 > self.scratch.len) return error.BufferTooSmall;
        const start = self.scratch_used;
        @memcpy(self.scratch[start .. start + bytes.len], bytes);
        self.scratch[start + bytes.len] = 0;
        self.scratch_used += bytes.len + 1;
        return @ptrCast(&self.scratch[start]);
    }

    fn bind(self: *Params, args: []const BindValue) Error!void {
        if (args.len > max_params) return error.BadBinding;
        self.n = @intCast(args.len);
        for (args, 0..) |a, i| {
            switch (a) {
                .null_ => {
                    self.values[i] = null;
                    self.lengths[i] = 0;
                    self.formats[i] = 0;
                },
                .int => |v| {
                    var buf: [24]u8 = undefined;
                    const s = std.fmt.bufPrint(&buf, "{d}", .{v}) catch return error.BadBinding;
                    self.values[i] = try self.allocZ(s);
                    self.lengths[i] = 0;
                    self.formats[i] = 0;
                },
                .real => |v| {
                    var buf: [64]u8 = undefined;
                    const s = std.fmt.bufPrint(&buf, "{d}", .{v}) catch return error.BadBinding;
                    self.values[i] = try self.allocZ(s);
                    self.lengths[i] = 0;
                    self.formats[i] = 0;
                },
                .text => |s| {
                    self.values[i] = try self.allocZ(s);
                    self.lengths[i] = 0;
                    self.formats[i] = 0;
                },
                .blob => |s| {
                    // Binary format against a bytea column. Point straight
                    // at the caller's bytes (valid for the call duration).
                    self.values[i] = if (s.len > 0) @ptrCast(s.ptr) else @ptrCast(&self.scratch[0]);
                    self.lengths[i] = @intCast(s.len);
                    self.formats[i] = 1;
                },
            }
        }
    }
};

pub const PostgresBackend = struct {
    conn: *c.PGconn,
    last_changes: i64 = 0,

    pub fn init(conninfo: []const u8) Error!PostgresBackend {
        var z: [2048]u8 = undefined;
        if (conninfo.len >= z.len) return error.BackendFailed;
        @memcpy(z[0..conninfo.len], conninfo);
        z[conninfo.len] = 0;
        const conn = c.PQconnectdb(@ptrCast(&z)) orelse return error.BackendFailed;
        if (c.PQstatus(conn) != c.CONNECTION_OK) {
            c.PQfinish(conn);
            return error.BackendFailed;
        }
        return .{ .conn = conn };
    }

    pub fn deinit(self: *PostgresBackend) void {
        c.PQfinish(self.conn);
        self.* = undefined;
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

    /// Run a parameterised statement, returning the libpq result. Caller
    /// must `PQclear` it. `want_rows` distinguishes the acceptable status.
    fn execParams(self: *PostgresBackend, sql: []const u8, args: []const BindValue) Error!*c.PGresult {
        var sqlz: [8192]u8 = undefined;
        if (sql.len >= sqlz.len) return error.BadStatement;
        @memcpy(sqlz[0..sql.len], sql);
        sqlz[sql.len] = 0;

        var params: Params = .{};
        try params.bind(args);

        const res = c.PQexecParams(
            self.conn,
            @ptrCast(&sqlz),
            params.n,
            null, // let the server infer param types
            if (args.len > 0) @ptrCast(&params.values) else null,
            if (args.len > 0) @ptrCast(&params.lengths) else null,
            if (args.len > 0) @ptrCast(&params.formats) else null,
            0, // text result format
        ) orelse return error.BackendFailed;
        return res;
    }

    fn doExec(ptr: *anyopaque, sql: []const u8, args: []const BindValue) Error!void {
        const self: *PostgresBackend = @ptrCast(@alignCast(ptr));
        const res = try self.execParams(sql, args);
        defer c.PQclear(res);
        const st = c.PQresultStatus(res);
        if (st != c.PGRES_COMMAND_OK and st != c.PGRES_TUPLES_OK) return error.StepFailed;
        // PQcmdTuples returns the affected-row count as a decimal string.
        const tuples = std.mem.sliceTo(c.PQcmdTuples(res), 0);
        self.last_changes = std.fmt.parseInt(i64, tuples, 10) catch 0;
    }

    fn doQuery(ptr: *anyopaque, sql: []const u8, args: []const BindValue, ctx: *anyopaque, cb: RowCallback) Error!void {
        const self: *PostgresBackend = @ptrCast(@alignCast(ptr));
        const res = try self.execParams(sql, args);
        defer c.PQclear(res);
        if (c.PQresultStatus(res) != c.PGRES_TUPLES_OK) return error.StepFailed;
        const ntuples = c.PQntuples(res);
        var t: c_int = 0;
        while (t < ntuples) : (t += 1) {
            var row: Row = .{};
            readRow(res, t, &row);
            if (!cb(ctx, &row)) return;
        }
    }

    fn doQueryOne(ptr: *anyopaque, sql: []const u8, args: []const BindValue, out: *Row) Error!bool {
        const self: *PostgresBackend = @ptrCast(@alignCast(ptr));
        const res = try self.execParams(sql, args);
        defer c.PQclear(res);
        if (c.PQresultStatus(res) != c.PGRES_TUPLES_OK) return error.StepFailed;
        if (c.PQntuples(res) == 0) {
            out.column_count = 0;
            return false;
        }
        readRow(res, 0, out);
        return true;
    }

    /// Postgres has no implicit rowid; inserts that need the new id use
    /// `RETURNING id` and read it as a normal column. We surface 0 here
    /// and document the RETURNING convention for migrated call sites.
    fn doLastInsertId(_: *anyopaque) i64 {
        return 0;
    }

    fn doChanges(ptr: *anyopaque) i64 {
        const self: *PostgresBackend = @ptrCast(@alignCast(ptr));
        return self.last_changes;
    }

    fn doTransaction(ptr: *anyopaque, ctx: *anyopaque, body: *const fn (ctx: *anyopaque) Error!void) Error!void {
        const self: *PostgresBackend = @ptrCast(@alignCast(ptr));
        try self.simple("BEGIN");
        body(ctx) catch |err| {
            self.simple("ROLLBACK") catch {};
            return err;
        };
        try self.simple("COMMIT");
    }

    fn simple(self: *PostgresBackend, sql: [*c]const u8) Error!void {
        const res = c.PQexec(self.conn, sql) orelse return error.BackendFailed;
        defer c.PQclear(res);
        const st = c.PQresultStatus(res);
        if (st != c.PGRES_COMMAND_OK and st != c.PGRES_TUPLES_OK) return error.BackendFailed;
    }

    fn readRow(res: *c.PGresult, t: c_int, out: *Row) void {
        const nf = c.PQnfields(res);
        const count: u8 = @intCast(@min(nf, @as(c_int, backend_mod.max_columns)));
        out.column_count = count;
        var col: c_int = 0;
        while (col < count) : (col += 1) {
            var cv: ColumnValue = .{};
            if (c.PQgetisnull(res, t, col) == 1) {
                cv.kind = .null_;
                out.columns[@intCast(col)] = cv;
                continue;
            }
            const oid = c.PQftype(res, col);
            const raw = c.PQgetvalue(res, t, col);
            const len: usize = @intCast(c.PQgetlength(res, t, col));
            const text = raw[0..len];
            switch (oid) {
                OID_INT2, OID_INT4, OID_INT8, OID_BOOL => {
                    cv.kind = .int;
                    cv.int_val = if (oid == OID_BOOL)
                        (if (len > 0 and (text[0] == 't' or text[0] == '1')) @as(i64, 1) else 0)
                    else
                        std.fmt.parseInt(i64, text, 10) catch 0;
                },
                OID_FLOAT4, OID_FLOAT8, OID_NUMERIC => {
                    cv.kind = .real;
                    cv.real_val = std.fmt.parseFloat(f64, text) catch 0;
                },
                OID_BYTEA => {
                    cv.kind = .blob;
                    copyBytea(text, &cv);
                },
                else => {
                    cv.kind = .text;
                    const cap = @min(len, backend_mod.max_inline_bytes);
                    if (cap > 0) @memcpy(cv.bytes_buf[0..cap], text[0..cap]);
                    cv.bytes_len = @intCast(cap);
                },
            }
            out.columns[@intCast(col)] = cv;
        }
    }

    /// Decode Postgres text-format bytea (`\x<hex>`) into the column's
    /// inline buffer. Non-hex / legacy-escape output falls back to a raw
    /// copy so we never crash on unexpected encodings.
    fn copyBytea(text: []const u8, cv: *ColumnValue) void {
        if (text.len >= 2 and text[0] == '\\' and text[1] == 'x') {
            const hex = text[2..];
            const out_len = @min(hex.len / 2, backend_mod.max_inline_bytes);
            var i: usize = 0;
            while (i < out_len) : (i += 1) {
                const hi = hexNibble(hex[i * 2]) orelse break;
                const lo = hexNibble(hex[i * 2 + 1]) orelse break;
                cv.bytes_buf[i] = (hi << 4) | lo;
            }
            cv.bytes_len = @intCast(i);
        } else {
            const cap = @min(text.len, backend_mod.max_inline_bytes);
            if (cap > 0) @memcpy(cv.bytes_buf[0..cap], text[0..cap]);
            cv.bytes_len = @intCast(cap);
        }
    }

    fn hexNibble(ch: u8) ?u8 {
        return switch (ch) {
            '0'...'9' => ch - '0',
            'a'...'f' => ch - 'a' + 10,
            'A'...'F' => ch - 'A' + 10,
            else => null,
        };
    }
};

// ── Tests ────────────────────────────────────────────────────────────────
//
// A full round-trip needs a live Postgres. The test connects to
// `PG_TEST_CONN` (or the libpq defaults) and SkipZigTests when no server
// is reachable, so it runs in CI with a Postgres service and is skipped
// locally. Compiled only under -Dpostgres.

const testing = std.testing;

fn testConn() ?[]const u8 {
    // std.posix.getenv is absent in this std; use the C env directly.
    const v = std.c.getenv("PG_TEST_CONN") orelse return "host=localhost user=postgres dbname=postgres";
    return std.mem.sliceTo(v, 0);
}

test "PostgresBackend: exec + queryOne round-trip against a live server" {
    const conninfo = testConn() orelse return error.SkipZigTest;
    var pg = PostgresBackend.init(conninfo) catch return error.SkipZigTest;
    defer pg.deinit();
    const b = pg.backend();

    // Unique temp table so concurrent CI runs don't collide.
    b.exec("CREATE TEMP TABLE sps_g_test (a BIGINT, b TEXT, d BYTEA)", &.{}) catch return error.SkipZigTest;

    var prng = std.Random.DefaultPrng.init(0x6_05_C_01);
    const rand = prng.random();
    const a_val = rand.int(i32);
    var blob: [16]u8 = undefined;
    rand.bytes(&blob);

    try b.exec("INSERT INTO sps_g_test (a, b, d) VALUES ($1, $2, $3)", &.{
        .{ .int = a_val },
        .{ .text = "hello-pg" },
        .{ .blob = &blob },
    });
    try testing.expectEqual(@as(i64, 1), b.changes());

    var row: Row = .{};
    const found = try b.queryOne("SELECT a, b, d FROM sps_g_test WHERE a = $1", &.{.{ .int = a_val }}, &row);
    try testing.expect(found);
    try testing.expectEqual(@as(i64, a_val), row.columns[0].int_val);
    try testing.expectEqualStrings("hello-pg", row.columns[1].bytes());
    try testing.expectEqualSlices(u8, &blob, row.columns[2].bytes());
}

test "PostgresBackend: transaction rolls back on error" {
    const conninfo = testConn() orelse return error.SkipZigTest;
    var pg = PostgresBackend.init(conninfo) catch return error.SkipZigTest;
    defer pg.deinit();
    const b = pg.backend();
    b.exec("CREATE TEMP TABLE sps_g_tx (a BIGINT)", &.{}) catch return error.SkipZigTest;

    const Ctx = struct {
        var bp: Backend = undefined;
        fn body(_: *anyopaque) Error!void {
            try bp.exec("INSERT INTO sps_g_tx (a) VALUES (1)", &.{});
            return error.BackendFailed;
        }
    };
    Ctx.bp = b;
    var dummy: u8 = 0;
    try testing.expectError(error.BackendFailed, b.transaction(&dummy, Ctx.body));

    var row: Row = .{};
    _ = try b.queryOne("SELECT COUNT(*) FROM sps_g_tx", &.{}, &row);
    try testing.expectEqual(@as(i64, 0), row.columns[0].int_val);
}
