//! In-memory `contract.Backend` for zorm's own tests. zorm depends on
//! nothing, so it cannot test against the host's SQLite/Postgres backends;
//! instead this mock interprets the exact statement shapes `sql.zig` emits
//! (INSERT / SELECT-by-pk / UPDATE / DELETE-by-pk). It is a TEST DOUBLE —
//! not a SQL engine — sufficient to prove the marshaling + CRUD logic.
//! Full-engine round-trips run in the host's integration suite (S6).
//!
//! Tiger Style: fixed-capacity table/row/cell storage, no heap. Rows are
//! stored generically (column name → value), so any entity shape works.
//! `transaction` takes a value snapshot and restores it on error (real
//! rollback), which the Session unit-of-work tests (S3) rely on.

const std = @import("std");
const contract = @import("contract.zig");

const BindValue = contract.BindValue;
const Error = contract.Error;

const max_tables = 4;
const max_rows = 16;
const max_cols = contract.max_columns;
const cell_bytes = 256;

const Cell = struct {
    name: [64]u8 = undefined,
    name_len: u8 = 0,
    kind: enum { null_, int, real, text, blob } = .null_,
    bytes_buf: [cell_bytes]u8 = undefined,
    bytes_len: u16 = 0,
    int_val: i64 = 0,
    real_val: f64 = 0,

    fn nameSlice(self: *const Cell) []const u8 {
        return self.name[0..self.name_len];
    }
    fn setName(self: *Cell, s: []const u8) void {
        const n = @min(self.name.len, s.len);
        @memcpy(self.name[0..n], s[0..n]);
        self.name_len = @intCast(n);
    }
    fn setFromBind(self: *Cell, b: BindValue) void {
        switch (b) {
            .null_ => self.kind = .null_,
            .int => |v| {
                self.kind = .int;
                self.int_val = v;
            },
            .real => |v| {
                self.kind = .real;
                self.real_val = v;
            },
            .text => |s| {
                self.kind = .text;
                const n = @min(cell_bytes, s.len);
                @memcpy(self.bytes_buf[0..n], s[0..n]);
                self.bytes_len = @intCast(n);
            },
            .blob => |s| {
                self.kind = .blob;
                const n = @min(cell_bytes, s.len);
                @memcpy(self.bytes_buf[0..n], s[0..n]);
                self.bytes_len = @intCast(n);
            },
        }
    }
    fn matchesBind(self: *const Cell, b: BindValue) bool {
        return switch (b) {
            .null_ => self.kind == .null_,
            .int => |v| self.kind == .int and self.int_val == v,
            .real => |v| self.kind == .real and self.real_val == v,
            .text => |s| self.kind == .text and std.mem.eql(u8, self.bytes_buf[0..self.bytes_len], s),
            .blob => |s| self.kind == .blob and std.mem.eql(u8, self.bytes_buf[0..self.bytes_len], s),
        };
    }
};

const Row = struct {
    cells: [max_cols]Cell = undefined,
    cell_count: u8 = 0,
    rowid: i64 = 0,
    present: bool = false,

    fn findCell(self: *Row, name: []const u8) ?*Cell {
        var i: usize = 0;
        while (i < self.cell_count) : (i += 1) {
            if (std.mem.eql(u8, self.cells[i].nameSlice(), name)) return &self.cells[i];
        }
        return null;
    }
};

const Table = struct {
    name: [64]u8 = undefined,
    name_len: u8 = 0,
    rows: [max_rows]Row = undefined,
    row_count: u8 = 0,

    fn nameSlice(self: *const Table) []const u8 {
        return self.name[0..self.name_len];
    }
};

pub const MockBackend = struct {
    tables: [max_tables]Table = undefined,
    table_count: u8 = 0,
    next_rowid: i64 = 0,
    last_insert: i64 = 0,
    change_count: i64 = 0,

    pub fn init() MockBackend {
        return .{};
    }

    pub fn backend(self: *MockBackend, dialect: contract.Dialect) contract.Backend {
        return .{ .ptr = self, .vtable = &vtable, .dialect = dialect };
    }

    fn table(self: *MockBackend, name: []const u8) *Table {
        var i: usize = 0;
        while (i < self.table_count) : (i += 1) {
            if (std.mem.eql(u8, self.tables[i].nameSlice(), name)) return &self.tables[i];
        }
        std.debug.assert(self.table_count < max_tables);
        const t = &self.tables[self.table_count];
        t.* = .{};
        const n = @min(t.name.len, name.len);
        @memcpy(t.name[0..n], name[0..n]);
        t.name_len = @intCast(n);
        self.table_count += 1;
        return t;
    }

    // ── vtable impls ────────────────────────────────────────────────────

    fn execImpl(ptr: *anyopaque, sql: []const u8, args: []const BindValue) Error!void {
        const self: *MockBackend = @ptrCast(@alignCast(ptr));
        if (std.mem.startsWith(u8, sql, "INSERT INTO ")) {
            _ = try self.doInsert(sql, args);
        } else if (std.mem.startsWith(u8, sql, "UPDATE ")) {
            try self.doUpdate(sql, args);
        } else if (std.mem.startsWith(u8, sql, "DELETE FROM ")) {
            try self.doDelete(sql, args);
        } else if (std.mem.startsWith(u8, sql, "CREATE TABLE") or std.mem.startsWith(u8, sql, "DROP TABLE")) {
            // DDL is a no-op for the mock (schema is implicit).
        } else return Error.BadStatement;
    }

    fn queryOneImpl(ptr: *anyopaque, sql: []const u8, args: []const BindValue, out: *contract.Row) Error!bool {
        const self: *MockBackend = @ptrCast(@alignCast(ptr));
        if (std.mem.startsWith(u8, sql, "INSERT INTO ")) {
            // Postgres auto-PK path: `… RETURNING <pk>`.
            const rowid = try self.doInsert(sql, args);
            out.column_count = 1;
            out.columns[0] = .{};
            out.columns[0].kind = .int;
            out.columns[0].int_val = rowid;
            return true;
        }
        if (!std.mem.startsWith(u8, sql, "SELECT ")) return Error.BadStatement;
        return self.doSelect(sql, args, out);
    }

    fn queryImpl(ptr: *anyopaque, sql: []const u8, args: []const BindValue, ctx: *anyopaque, cb: contract.RowCallback) Error!void {
        const self: *MockBackend = @ptrCast(@alignCast(ptr));
        if (!std.mem.startsWith(u8, sql, "SELECT ")) return Error.BadStatement;
        try self.doSelectAll(sql, args, ctx, cb);
    }

    fn lastInsertIdImpl(ptr: *anyopaque) i64 {
        const self: *MockBackend = @ptrCast(@alignCast(ptr));
        return self.last_insert;
    }

    fn changesImpl(ptr: *anyopaque) i64 {
        const self: *MockBackend = @ptrCast(@alignCast(ptr));
        return self.change_count;
    }

    fn transactionImpl(ptr: *anyopaque, ctx: *anyopaque, body: *const fn (ctx: *anyopaque) Error!void) Error!void {
        const self: *MockBackend = @ptrCast(@alignCast(ptr));
        const snapshot = self.*; // value copy → real rollback on error
        body(ctx) catch |e| {
            self.* = snapshot;
            return e;
        };
    }

    const vtable = contract.Backend.VTable{
        .exec = execImpl,
        .query = queryImpl,
        .queryOne = queryOneImpl,
        .lastInsertId = lastInsertIdImpl,
        .changes = changesImpl,
        .transaction = transactionImpl,
    };

    // ── statement handlers ──────────────────────────────────────────────

    fn doInsert(self: *MockBackend, sql: []const u8, args: []const BindValue) Error!i64 {
        const tname = between(sql, "INSERT INTO ", " (") orelse return Error.BadStatement;
        const cols_str = between(sql, " (", ")") orelse return Error.BadStatement;
        const t = self.table(tname);
        std.debug.assert(t.row_count < max_rows);

        self.next_rowid += 1;
        const rowid = self.next_rowid;
        self.last_insert = rowid;

        var row = &t.rows[t.row_count];
        row.* = .{ .rowid = rowid, .present = true };

        var it = std.mem.splitSequence(u8, cols_str, ", ");
        var i: usize = 0;
        while (it.next()) |col_name| : (i += 1) {
            if (i >= args.len) return Error.BadBinding;
            var cell = &row.cells[row.cell_count];
            cell.* = .{};
            cell.setName(col_name);
            cell.setFromBind(args[i]);
            row.cell_count += 1;
        }
        t.row_count += 1;
        self.change_count = 1;
        return rowid;
    }

    fn doSelect(self: *MockBackend, sql: []const u8, args: []const BindValue, out: *contract.Row) Error!bool {
        const proj = between(sql, "SELECT ", " FROM ") orelse return Error.BadStatement;
        const tname = tableName(sql) orelse return Error.BadStatement;
        const where = whereClause(sql);

        const t = self.table(tname);
        var i: usize = 0;
        while (i < t.row_count) : (i += 1) {
            if (!t.rows[i].present) continue;
            if (rowMatches(&t.rows[i], where, args)) {
                projectRow(&t.rows[i], proj, out);
                return true;
            }
        }
        return false;
    }

    /// Stream every matching row to `cb` (respecting LIMIT and cb's stop
    /// signal). The query() path — multiple rows, unlike queryOne.
    fn doSelectAll(self: *MockBackend, sql: []const u8, args: []const BindValue, ctx: *anyopaque, cb: contract.RowCallback) Error!void {
        const proj = between(sql, "SELECT ", " FROM ") orelse return Error.BadStatement;
        const tname = tableName(sql) orelse return Error.BadStatement;
        const where = whereClause(sql);
        const lim = limitOf(sql);

        const t = self.table(tname);
        var emitted: usize = 0;
        var i: usize = 0;
        while (i < t.row_count) : (i += 1) {
            if (!t.rows[i].present) continue;
            if (!rowMatches(&t.rows[i], where, args)) continue;
            if (lim) |l| if (emitted >= l) break;
            var out: contract.Row = .{};
            projectRow(&t.rows[i], proj, &out);
            emitted += 1;
            if (!cb(ctx, &out)) break;
        }
    }

    fn doUpdate(self: *MockBackend, sql: []const u8, args: []const BindValue) Error!void {
        const tname = between(sql, "UPDATE ", " SET ") orelse return Error.BadStatement;
        const set_str = between(sql, " SET ", " WHERE ") orelse return Error.BadStatement;
        const where_col = between(sql, " WHERE ", " = ") orelse return Error.BadStatement;

        const t = self.table(tname);
        // The WHERE pk value is the final bind arg.
        if (args.len < 1) return Error.BadBinding;
        const pk_arg = args[args.len - 1];
        const match = self.findRow(t, where_col, pk_arg) orelse {
            self.change_count = 0;
            return;
        };

        var it = std.mem.splitSequence(u8, set_str, ", ");
        var i: usize = 0;
        while (it.next()) |assign| : (i += 1) {
            // "<col> = ?" / "<col> = $N"
            const col = between(assign, "", " = ") orelse return Error.BadStatement;
            if (i >= args.len - 1) return Error.BadBinding;
            if (match.findCell(col)) |cell| {
                cell.setFromBind(args[i]);
            } else {
                var cell = &match.cells[match.cell_count];
                cell.* = .{};
                cell.setName(col);
                cell.setFromBind(args[i]);
                match.cell_count += 1;
            }
        }
        self.change_count = 1;
    }

    fn doDelete(self: *MockBackend, sql: []const u8, args: []const BindValue) Error!void {
        const tname = between(sql, "DELETE FROM ", " WHERE ") orelse return Error.BadStatement;
        const where_col = between(sql, " WHERE ", " = ") orelse return Error.BadStatement;
        if (args.len < 1) return Error.BadBinding;
        const t = self.table(tname);

        var idx: usize = 0;
        while (idx < t.row_count) : (idx += 1) {
            if (!t.rows[idx].present) continue;
            if (cellForKey(&t.rows[idx], where_col).matchesBind(args[0])) {
                // Compact: shift the tail down.
                var j = idx;
                while (j + 1 < t.row_count) : (j += 1) t.rows[j] = t.rows[j + 1];
                t.row_count -= 1;
                self.change_count = 1;
                return;
            }
        }
        self.change_count = 0;
    }

    fn findRow(self: *MockBackend, t: *Table, key_col: []const u8, key: BindValue) ?*Row {
        _ = self;
        var i: usize = 0;
        while (i < t.row_count) : (i += 1) {
            if (!t.rows[i].present) continue;
            if (cellForKey(&t.rows[i], key_col).matchesBind(key)) return &t.rows[i];
        }
        return null;
    }
};

/// Value of `row`'s key column. If the column wasn't stored (an auto PK
/// omitted at INSERT), the row's synthetic rowid stands in.
fn cellForKey(row: *Row, col: []const u8) Cell {
    if (row.findCell(col)) |c| return c.*;
    var c: Cell = .{};
    c.setName(col);
    c.kind = .int;
    c.int_val = row.rowid;
    return c;
}

/// Project `row` into a contract.Row following the comma-separated column
/// list `proj` (the SELECT projection). A projected column not physically
/// stored (the auto PK) resolves to the rowid.
fn projectRow(row: *Row, proj: []const u8, out: *contract.Row) void {
    var it = std.mem.splitSequence(u8, proj, ", ");
    var i: usize = 0;
    while (it.next()) |col| : (i += 1) {
        var dst = &out.columns[i];
        dst.* = .{};
        if (row.findCell(col)) |c| {
            switch (c.kind) {
                .null_ => dst.kind = .null_,
                .int => {
                    dst.kind = .int;
                    dst.int_val = c.int_val;
                },
                .real => {
                    dst.kind = .real;
                    dst.real_val = c.real_val;
                },
                .text => {
                    dst.kind = .text;
                    @memcpy(dst.bytes_buf[0..c.bytes_len], c.bytes_buf[0..c.bytes_len]);
                    dst.bytes_len = c.bytes_len;
                },
                .blob => {
                    dst.kind = .blob;
                    @memcpy(dst.bytes_buf[0..c.bytes_len], c.bytes_buf[0..c.bytes_len]);
                    dst.bytes_len = c.bytes_len;
                },
            }
        } else {
            // Auto PK: not stored, equals the rowid.
            dst.kind = .int;
            dst.int_val = row.rowid;
        }
    }
    out.column_count = @intCast(i);
}

// ── tiny string helpers (the SQL is generated, so shapes are fixed) ─────

/// The substring strictly between the first `a` and the first `b` after it.
/// An empty `a` anchors at the start.
fn between(s: []const u8, a: []const u8, b: []const u8) ?[]const u8 {
    const start = if (a.len == 0) 0 else (std.mem.indexOf(u8, s, a) orelse return null) + a.len;
    const end_rel = std.mem.indexOf(u8, s[start..], b) orelse return null;
    return s[start .. start + end_rel];
}

fn sliceAfter(s: []const u8, a: []const u8) ?[]const u8 {
    const idx = std.mem.indexOf(u8, s, a) orelse return null;
    return s[idx + a.len ..];
}

/// Table name following `FROM` (first token up to a space or end).
fn tableName(sql: []const u8) ?[]const u8 {
    const rest = sliceAfter(sql, " FROM ") orelse return null;
    const end = std.mem.indexOfScalar(u8, rest, ' ') orelse rest.len;
    return rest[0..end];
}

/// The WHERE predicate text (between `WHERE` and ORDER BY / LIMIT / end),
/// or null if the statement has no WHERE.
fn whereClause(sql: []const u8) ?[]const u8 {
    const start_idx = std.mem.indexOf(u8, sql, " WHERE ") orelse return null;
    const start = start_idx + " WHERE ".len;
    var end = sql.len;
    if (std.mem.indexOf(u8, sql[start..], " ORDER BY ")) |o| end = @min(end, start + o);
    if (std.mem.indexOf(u8, sql[start..], " LIMIT ")) |l| end = @min(end, start + l);
    return sql[start..end];
}

fn limitOf(sql: []const u8) ?usize {
    const rest = sliceAfter(sql, " LIMIT ") orelse return null;
    var end: usize = 0;
    while (end < rest.len and rest[end] >= '0' and rest[end] <= '9') : (end += 1) {}
    return std.fmt.parseInt(usize, rest[0..end], 10) catch null;
}

/// Does `row` satisfy every `col = ?` predicate in `where`? Predicates are
/// AND-joined and bind args positionally (predicate i → args[i]).
fn rowMatches(row: *Row, where: ?[]const u8, args: []const BindValue) bool {
    const clause = where orelse return true;
    var it = std.mem.splitSequence(u8, clause, " AND ");
    var i: usize = 0;
    while (it.next()) |pred| : (i += 1) {
        const col = between(pred, "", " = ") orelse return false;
        if (i >= args.len) return false;
        if (!cellForKey(row, col).matchesBind(args[i])) return false;
    }
    return true;
}

// ── Tests (exercise the mock directly; CRUD-level tests live in crud.zig) ─

const testing = std.testing;

test "MockBackend stores and matches a text-keyed row" {
    var db = MockBackend.init();
    const b = db.backend(.sqlite);

    try b.exec("INSERT INTO users (id, name) VALUES (?, ?)", &.{ .{ .text = "u1" }, .{ .text = "Ann" } });
    var row: contract.Row = .{};
    try testing.expect(try b.queryOne("SELECT id, name FROM users WHERE id = ?", &.{.{ .text = "u1" }}, &row));
    try testing.expectEqual(@as(u8, 2), row.column_count);
    try testing.expectEqualStrings("u1", row.columns[0].bytes());
    try testing.expectEqualStrings("Ann", row.columns[1].bytes());
}

test "MockBackend transaction rolls back on error" {
    var db = MockBackend.init();
    const b = db.backend(.sqlite);
    try b.exec("INSERT INTO t (id, v) VALUES (?, ?)", &.{ .{ .text = "a" }, .{ .int = 1 } });

    const Body = struct {
        fn run(ctx: *anyopaque) Error!void {
            const be: *contract.Backend = @ptrCast(@alignCast(ctx));
            try be.exec("INSERT INTO t (id, v) VALUES (?, ?)", &.{ .{ .text = "b" }, .{ .int = 2 } });
            return Error.StepFailed; // force rollback
        }
    };
    var be_copy = b;
    try testing.expectError(Error.StepFailed, b.transaction(&be_copy, Body.run));

    // "b" must be gone; "a" remains.
    var row: contract.Row = .{};
    try testing.expect(!try b.queryOne("SELECT id, v FROM t WHERE id = ?", &.{.{ .text = "b" }}, &row));
    try testing.expect(try b.queryOne("SELECT id, v FROM t WHERE id = ?", &.{.{ .text = "a" }}, &row));
}

test "between/sliceAfter parse generated SQL shapes" {
    const ins = "INSERT INTO atp_accounts (id, handle) VALUES (?, ?)";
    try testing.expectEqualStrings("atp_accounts", between(ins, "INSERT INTO ", " (").?);
    try testing.expectEqualStrings("id, handle", between(ins, " (", ")").?);

    const sel = "SELECT id, handle FROM atp_accounts WHERE id = ?";
    try testing.expectEqualStrings("id, handle", between(sel, "SELECT ", " FROM ").?);
    const rest = sliceAfter(sel, " FROM ").?;
    try testing.expectEqualStrings("atp_accounts", between(rest, "", " WHERE ").?);
    try testing.expectEqualStrings("id", between(sel, " WHERE ", " = ").?);
}
