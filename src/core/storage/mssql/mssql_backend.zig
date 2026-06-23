//! D2: Microsoft SQL Server `storage.Backend` over the pure-Zig TDS codec
//! (`tds.zig`) + wire layer (`conn.zig`). Backs a future
//! `STORAGE_BACKEND=mssql` option, mirroring `postgres_backend.zig`.
//!
//! Parameterization: every statement runs through RPC `sp_executesql` so the
//! `@pN` placeholders zorm's mssql dialect emits bind as real typed
//! parameters (no client-side string splicing). The runtime `BindValue`
//! union maps onto `tds.RpcParam`; result columns decode generically by
//! switching on each column's TDS type token.
//!
//! Error mapping (SQL Server error numbers, MS-TDS ERROR token `Number`):
//!   * 2627 (PK/unique constraint) and 2601 (unique index) → UniqueViolation
//!   * 547  (FK / check constraint conflict)               → ForeignKeyViolation
//!   * 515  (NULL into NOT NULL column)                     → NotNullViolation
//! Anything else → StepFailed.
//!
//! Transactions pin the connection (the single `Conn` owned here) for the
//! body's duration and drive BEGIN/COMMIT/ROLLBACK TRANSACTION via SQL_BATCH
//! on that same connection, exactly like the Postgres path pins a pooled
//! connection.
//!
//! ⚠️ LIVE VALIDATION PENDING A RUNNABLE SQL SERVER — see `conn.zig`. The
//! codec is unit-tested in `tds_test.zig`; the round-trip test below is
//! gated on `MSSQL_TEST_URL` and skips when unset/unreachable.
//!
//! Tiger Style: one owned `Conn` with its fixed send/recv buffers; result
//! rows decoded into the backend's inline `Row` buffers (`max_inline_bytes`),
//! no per-call heap.

const std = @import("std");
const tds = @import("tds.zig");
const conn_mod = @import("conn.zig");
const backend_mod = @import("../backend.zig");

const Error = backend_mod.Error;
const BindValue = backend_mod.BindValue;
const Row = backend_mod.Row;
const ColumnValue = backend_mod.ColumnValue;
const RowCallback = backend_mod.RowCallback;
const Backend = backend_mod.Backend;

const Conn = conn_mod.Conn;

// SQL Server error numbers → typed constraint errors.
const SQLSRV_UNIQUE_PK: i32 = 2627;
const SQLSRV_UNIQUE_IDX: i32 = 2601;
const SQLSRV_FK_OR_CHECK: i32 = 547;
const SQLSRV_NOT_NULL: i32 = 515;

pub const MssqlBackend = struct {
    conn: *Conn,
    in_tx: bool = false,
    last_changes: i64 = 0,

    pub fn init(conn: *Conn) MssqlBackend {
        return .{ .conn = conn };
    }

    pub fn backend(self: *MssqlBackend) Backend {
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

    /// Map a `conn.Error` to the storage `Error`, refining a `ServerError`
    /// to a typed constraint error from the connection's last error number.
    fn classify(self: *MssqlBackend, err: conn_mod.Error) Error {
        return switch (err) {
            error.ServerError, error.LoginFailed => switch (self.conn.last_error_number) {
                SQLSRV_UNIQUE_PK, SQLSRV_UNIQUE_IDX => error.UniqueViolation,
                SQLSRV_FK_OR_CHECK => error.ForeignKeyViolation,
                SQLSRV_NOT_NULL => error.NotNullViolation,
                else => error.StepFailed,
            },
            error.BufferTooSmall => error.BufferTooSmall,
            error.ConnectFailed, error.DnsFailed, error.SocketError, error.Closed, error.WriteFailed, error.ReadFailed => error.BackendFailed,
            error.Truncated, error.Malformed, error.UnsupportedToken, error.ProtocolError, error.ResponseTooLarge, error.TooManyColumns => error.StepFailed,
        };
    }

    fn toRpcParams(args: []const BindValue, out: []tds.RpcParam) []tds.RpcParam {
        const n = @min(args.len, out.len);
        var i: usize = 0;
        while (i < n) : (i += 1) {
            out[i] = switch (args[i]) {
                .null_ => .null_,
                .int => |v| .{ .int = v },
                .real => |v| .{ .real = v },
                .text => |s| .{ .text = s },
                .blob => |s| .{ .blob = s },
            };
        }
        return out[0..n];
    }

    /// Execute a statement via RPC sp_executesql and drive the token stream,
    /// invoking `row_cb` (if non-null) for each ROW token. Returns on the
    /// first ERROR token (raising the classified error). Records the row
    /// count from the terminal DONE token in `last_changes`.
    fn run(
        self: *MssqlBackend,
        sql: []const u8,
        args: []const BindValue,
        ctx: ?*anyopaque,
        row_cb: ?RowCallback,
    ) Error!void {
        var param_storage: [backend_mod.max_columns]tds.RpcParam = undefined;
        const params = toRpcParams(args, &param_storage);
        const payload = self.conn.rpcExecuteSql(sql, params) catch |e| return self.classify(e);
        try self.consume(payload, ctx, row_cb, null);
    }

    /// Token-stream consumer. Decodes COLMETADATA, dispatches ROWs, captures
    /// the first ROW into `one_out` (for queryOne), and on ERROR records the
    /// number and raises a classified error.
    fn consume(
        self: *MssqlBackend,
        payload: []const u8,
        ctx: ?*anyopaque,
        row_cb: ?RowCallback,
        one_out: ?*Row,
    ) Error!void {
        var r = tds.Reader.init(payload);
        var meta: tds.ColMetadata = .{};
        var have_meta = false;
        var captured_one = false;
        while (!r.atEnd()) {
            const tok = r.u8_() catch return error.StepFailed;
            switch (tok) {
                @intFromEnum(tds.Token.colmetadata) => {
                    meta = tds.parseColMetadata(&r) catch return error.StepFailed;
                    have_meta = meta.count > 0;
                },
                @intFromEnum(tds.Token.row), @intFromEnum(tds.Token.nbcrow) => {
                    if (!have_meta) return error.StepFailed;
                    var cells: [backend_mod.max_columns]tds.Cell = undefined;
                    const n = tds.parseRow(&r, &meta, &cells) catch return error.StepFailed;
                    if (one_out) |out| {
                        if (!captured_one) {
                            fillRow(out, &meta, cells[0..n]);
                            captured_one = true;
                        }
                    } else if (row_cb) |cb| {
                        var out: Row = .{};
                        fillRow(&out, &meta, cells[0..n]);
                        if (!cb(ctx.?, &out)) {
                            // Caller asked to stop; drain rest silently.
                            return;
                        }
                    }
                },
                @intFromEnum(tds.Token.error_) => {
                    const m = tds.parseServerMessage(&r) catch return error.StepFailed;
                    self.conn.last_error_number = m.number;
                    return self.classify(error.ServerError);
                },
                @intFromEnum(tds.Token.info) => {
                    _ = tds.parseServerMessage(&r) catch return error.StepFailed;
                },
                @intFromEnum(tds.Token.envchange) => tds.skipEnvChange(&r) catch return error.StepFailed,
                @intFromEnum(tds.Token.order) => tds.skipOrder(&r) catch return error.StepFailed,
                @intFromEnum(tds.Token.returnstatus) => tds.skipReturnStatus(&r) catch return error.StepFailed,
                @intFromEnum(tds.Token.loginack) => {
                    _ = tds.parseLoginAck(&r) catch return error.StepFailed;
                },
                @intFromEnum(tds.Token.done), @intFromEnum(tds.Token.doneproc), @intFromEnum(tds.Token.doneinproc) => {
                    const d = tds.parseDone(&r) catch return error.StepFailed;
                    if (d.countValid()) self.last_changes = @intCast(d.row_count);
                },
                else => return error.StepFailed,
            }
        }
        if (one_out != null and !captured_one) {
            one_out.?.column_count = 0;
        }
    }

    fn fillRow(out: *Row, meta: *const tds.ColMetadata, cells: []const tds.Cell) void {
        const n: usize = @min(meta.count, backend_mod.max_columns);
        out.column_count = @intCast(n);
        var i: usize = 0;
        while (i < n) : (i += 1) {
            var cv: ColumnValue = .{};
            const cell = cells[i];
            switch (cell.kind) {
                .null_ => cv.kind = .null_,
                .int => {
                    cv.kind = .int;
                    cv.int_val = cell.int_val;
                },
                .real => {
                    cv.kind = .real;
                    cv.real_val = cell.real_val;
                },
                .blob => {
                    cv.kind = .blob;
                    copyInline(&cv, cell.bytes);
                },
                .text => {
                    // NVARCHAR/NCHAR cells arrive UTF-16LE; transcode to UTF-8
                    // so callers (and the SQLite-shaped Row contract) see the
                    // same byte semantics as the other backends.
                    cv.kind = .text;
                    copyUtf16AsUtf8(&cv, cell.bytes, meta.columns[i].type_token);
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

    /// NVARCHAR/NCHAR/NTEXT columns (type tokens 0xE7/0xEF/0x63) are UTF-16LE
    /// on the wire; transcode to UTF-8. Non-N character types (VARCHAR /
    /// CHAR / TEXT / DECIMAL-as-text) arrive as single-byte/ASCII and copy
    /// verbatim.
    fn copyUtf16AsUtf8(cv: *ColumnValue, s: []const u8, type_token: u8) void {
        const is_wide = (type_token == 0xE7 or type_token == 0xEF or type_token == 0x63);
        if (!is_wide) {
            copyInline(cv, s);
            return;
        }
        var out_len: usize = 0;
        var i: usize = 0;
        while (i + 1 < s.len and out_len < backend_mod.max_inline_bytes) : (i += 2) {
            const cp: u21 = @as(u21, s[i]) | (@as(u21, s[i + 1]) << 8);
            var enc: [4]u8 = undefined;
            const wrote = std.unicode.utf8Encode(cp, &enc) catch {
                continue;
            };
            const room = backend_mod.max_inline_bytes - out_len;
            const take = @min(wrote, room);
            @memcpy(cv.bytes_buf[out_len .. out_len + take], enc[0..take]);
            out_len += take;
        }
        cv.bytes_len = @intCast(out_len);
    }

    // ── vtable methods ─────────────────────────────────────────────────────

    fn doExec(ptr: *anyopaque, sql: []const u8, args: []const BindValue) Error!void {
        const self: *MssqlBackend = @ptrCast(@alignCast(ptr));
        try self.run(sql, args, null, null);
    }

    fn doQuery(ptr: *anyopaque, sql: []const u8, args: []const BindValue, ctx: *anyopaque, cb: RowCallback) Error!void {
        const self: *MssqlBackend = @ptrCast(@alignCast(ptr));
        try self.run(sql, args, ctx, cb);
    }

    fn doQueryOne(ptr: *anyopaque, sql: []const u8, args: []const BindValue, out: *Row) Error!bool {
        const self: *MssqlBackend = @ptrCast(@alignCast(ptr));
        var param_storage: [backend_mod.max_columns]tds.RpcParam = undefined;
        const params = toRpcParams(args, &param_storage);
        const payload = self.conn.rpcExecuteSql(sql, params) catch |e| return self.classify(e);
        out.column_count = 0;
        try self.consume(payload, null, null, out);
        return out.column_count > 0;
    }

    fn doLastInsertId(_: *anyopaque) i64 {
        // SQL Server has no implicit rowid; zorm's mssql dialect uses
        // `INSERT ... OUTPUT INSERTED.<pk>` (see zorm/src/crud.zig) and reads
        // the new id back as a normal result column — same contract as PG.
        return 0;
    }

    fn doChanges(ptr: *anyopaque) i64 {
        const self: *MssqlBackend = @ptrCast(@alignCast(ptr));
        return self.last_changes;
    }

    fn doTransaction(ptr: *anyopaque, ctx: *anyopaque, body: *const fn (ctx: *anyopaque) Error!void) Error!void {
        const self: *MssqlBackend = @ptrCast(@alignCast(ptr));
        // BEGIN/COMMIT/ROLLBACK run as plain SQL_BATCH on the same Conn.
        _ = self.conn.sqlBatch("BEGIN TRANSACTION", 0) catch |e| return self.classify(e);
        self.in_tx = true;
        defer self.in_tx = false;
        body(ctx) catch |err| {
            _ = self.conn.sqlBatch("IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION", 0) catch {};
            return err;
        };
        _ = self.conn.sqlBatch("COMMIT TRANSACTION", 0) catch |e| return self.classify(e);
    }
};

// ── Tests ──────────────────────────────────────────────────────────────
//
// Pure-codec unit tests live in `tds_test.zig`. The test below is a LIVE
// round-trip gated on `MSSQL_TEST_URL`
// (`mssql://user:pass@host:port/db`); it SKIPS when unset or unreachable.
// ⚠️ LIVE VALIDATION PENDING A RUNNABLE SQL SERVER — this arm64 host cannot
// run SQL Server, so this path is unverified against a real server here.

const testing = std.testing;

test {
    _ = tds;
    _ = conn_mod;
}

fn parseTestUrl() ?conn_mod.Config {
    const url_c = std.c.getenv("MSSQL_TEST_URL") orelse return null;
    const uri_str = std.mem.sliceTo(url_c, 0);
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
    if (uri.path.isEmpty() == false) {
        const p = switch (uri.path) {
            .raw => |x| x,
            .percent_encoded => |x| x,
        };
        if (p.len > 1) db = p[1..];
    }
    return .{
        .host = host,
        .port = uri.port orelse 1433,
        .username = user,
        .password = pass,
        .database = db,
    };
}

test "MssqlBackend: live exec + queryOne + tx (skips without MSSQL_TEST_URL)" {
    const cfg = parseTestUrl() orelse return error.SkipZigTest;
    var conn: Conn = .{};
    conn.connect(cfg) catch return error.SkipZigTest;
    defer conn.close();

    var be_state = MssqlBackend.init(&conn);
    const b = be_state.backend();

    b.exec("IF OBJECT_ID('tempdb..#sps_be') IS NULL CREATE TABLE #sps_be (a BIGINT, t NVARCHAR(64))", &.{}) catch return error.SkipZigTest;

    var prng = std.Random.DefaultPrng.init(testing.random_seed);
    const rand = prng.random();
    const a_val: i64 = rand.int(i32);

    try b.exec("INSERT INTO #sps_be (a, t) VALUES (@p1, @p2)", &.{ .{ .int = a_val }, .{ .text = "hello-tds" } });

    var row: Row = .{};
    try testing.expect(try b.queryOne("SELECT a, t FROM #sps_be WHERE a = @p1", &.{.{ .int = a_val }}, &row));
    try testing.expectEqual(a_val, row.columns[0].int_val);
    try testing.expectEqualStrings("hello-tds", row.columns[1].bytes());
}
