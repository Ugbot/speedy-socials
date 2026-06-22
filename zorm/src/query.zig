//! Typed query builder. `Query(T)` assembles a SELECT with equality
//! predicates, ordering, and a limit, then runs it filling a caller-owned
//! bounded slice. Column names are validated at comptime against the
//! entity; values bind as parameters (never interpolated → injection-safe).
//! Dialect-correct placeholders (`?` vs `$N`) are emitted as the builder
//! grows. Tiger Style: the SQL text builds into a fixed in-struct buffer
//! and bind args into a fixed array — no allocation; results fill a bounded
//! `out` slice.

const std = @import("std");
const contract = @import("contract.zig");
const reflect = @import("reflect.zig");
const fields = @import("fields.zig");
const bind = @import("bind.zig");
const sql = @import("sql.zig");
const session = @import("session.zig");

const Backend = contract.Backend;
const BindValue = contract.BindValue;
const Error = contract.Error;
const Dialect = contract.Dialect;
const max_columns = contract.max_columns;

const sql_buf_len = 1024;

pub const Dir = enum { asc, desc };

/// Comparison operators usable with `whereOp`.
pub const Op = enum {
    eq,
    ne,
    lt,
    lte,
    gt,
    gte,

    fn sql(self: Op) []const u8 {
        return switch (self) {
            .eq => "=",
            .ne => "<>",
            .lt => "<",
            .lte => "<=",
            .gt => ">",
            .gte => ">=",
        };
    }
};

/// Assert at comptime that `name` is a real column of `T`, returning it.
fn checkColumn(comptime T: type, comptime name: []const u8) []const u8 {
    comptime {
        var found = false;
        for (reflect.TableInfo(T).columns) |col| {
            if (std.mem.eql(u8, col.name, name)) found = true;
        }
        if (!found) @compileError("zorm: '" ++ name ++ "' is not a column of " ++ @typeName(T));
    }
    return name;
}

pub fn Query(comptime T: type) type {
    return struct {
        const Self = @This();

        dialect: Dialect,
        buf: [sql_buf_len]u8 = undefined,
        len: usize = 0,
        args: [max_columns]BindValue = undefined,
        arg_count: usize = 0,
        has_where: bool = false,
        has_order: bool = false,
        offset_n: ?usize = null,

        pub fn init(dialect: Dialect) Self {
            var q = Self{ .dialect = dialect };
            q.append(sql.selectAll(T, dialect));
            return q;
        }

        fn append(self: *Self, s: []const u8) void {
            std.debug.assert(self.len + s.len <= sql_buf_len);
            @memcpy(self.buf[self.len .. self.len + s.len], s);
            self.len += s.len;
        }

        fn appendPlaceholder(self: *Self) void {
            switch (self.dialect) {
                .sqlite, .mysql => self.append("?"),
                .postgres => {
                    var tmp: [16]u8 = undefined;
                    const s = std.fmt.bufPrint(&tmp, "${d}", .{self.arg_count + 1}) catch unreachable;
                    self.append(s);
                },
                .mssql => {
                    var tmp: [16]u8 = undefined;
                    const s = std.fmt.bufPrint(&tmp, "@p{d}", .{self.arg_count + 1}) catch unreachable;
                    self.append(s);
                },
            }
        }

        /// Append a column identifier, quoted for the runtime dialect so it
        /// stays consistent with the (quoted) projection/table emitted by
        /// `sql.selectAll`. Quoting is comptime per dialect (no runtime cost).
        fn appendIdent(self: *Self, comptime name: []const u8) void {
            switch (self.dialect) {
                inline else => |d| self.append(comptime sql.quoteIdent(name, d)),
            }
        }

        /// Emit the ` WHERE `/` AND ` join + quoted column name, leaving the
        /// caller to append the operator and (optional) placeholder.
        fn whereColumn(self: *Self, comptime name: []const u8) void {
            self.append(if (self.has_where) " AND " else " WHERE ");
            self.has_where = true;
            self.appendIdent(name);
        }

        /// Record a single bound parameter into the args array.
        fn bindArg(self: *Self, value: BindValue) void {
            std.debug.assert(self.arg_count < max_columns);
            self.args[self.arg_count] = value;
            self.arg_count += 1;
        }

        // ── predicates (chainable) ──────────────────────────────────────

        /// `WHERE <field> = <value>` with an explicit bind value.
        pub fn where(self: *Self, comptime field: []const u8, value: BindValue) *Self {
            return self.whereOp(field, .eq, value);
        }

        /// `WHERE <field> <op> <value>` — comparison against a bound value.
        pub fn whereOp(self: *Self, comptime field: []const u8, op: Op, value: BindValue) *Self {
            self.whereColumn(checkColumn(T, field));
            self.append(" ");
            self.append(op.sql());
            self.append(" ");
            self.appendPlaceholder();
            self.bindArg(value);
            return self;
        }

        /// `WHERE <field> LIKE <pattern>` — pattern bound as a parameter.
        pub fn whereLike(self: *Self, comptime field: []const u8, pattern: []const u8) *Self {
            self.whereColumn(checkColumn(T, field));
            self.append(" LIKE ");
            self.appendPlaceholder();
            self.bindArg(.{ .text = pattern });
            return self;
        }

        /// `WHERE <field> IN (<ph>,…)` — each value bound as a parameter.
        /// An empty `values` list emits the always-false `1 = 0` (no binds),
        /// so the query is well-formed and returns no rows.
        pub fn whereIn(self: *Self, comptime field: []const u8, values: []const BindValue) *Self {
            if (values.len == 0) {
                self.append(if (self.has_where) " AND " else " WHERE ");
                self.has_where = true;
                self.append("1 = 0");
                return self;
            }
            self.whereColumn(checkColumn(T, field));
            self.append(" IN (");
            for (values, 0..) |v, i| {
                if (i != 0) self.append(", ");
                self.appendPlaceholder();
                self.bindArg(v);
            }
            self.append(")");
            return self;
        }

        /// `WHERE <field> IS NULL` — no bound value.
        pub fn whereNull(self: *Self, comptime field: []const u8) *Self {
            self.whereColumn(checkColumn(T, field));
            self.append(" IS NULL");
            return self;
        }

        /// `WHERE <field> IS NOT NULL` — no bound value.
        pub fn whereNotNull(self: *Self, comptime field: []const u8) *Self {
            self.whereColumn(checkColumn(T, field));
            self.append(" IS NOT NULL");
            return self;
        }

        pub fn whereText(self: *Self, comptime field: []const u8, value: []const u8) *Self {
            return self.where(field, .{ .text = value });
        }
        pub fn whereInt(self: *Self, comptime field: []const u8, value: i64) *Self {
            return self.where(field, .{ .int = value });
        }
        pub fn whereBool(self: *Self, comptime field: []const u8, value: bool) *Self {
            return self.where(field, .{ .int = if (value) @as(i64, 1) else 0 });
        }
        /// Match an enum field by its stored text name.
        pub fn whereEnum(self: *Self, comptime field: []const u8, value: anytype) *Self {
            return self.where(field, .{ .text = @tagName(value) });
        }

        pub fn orderBy(self: *Self, comptime field: []const u8, dir: Dir) *Self {
            self.append(" ORDER BY ");
            self.appendIdent(checkColumn(T, field));
            self.append(if (dir == .desc) " DESC" else " ASC");
            self.has_order = true;
            return self;
        }

        /// Skip the first `n` rows. **Call-order contract: `offset()` must be
        /// invoked BEFORE `limit()`** — `offset()` only records the value, and
        /// `limit()` emits the single dialect-correct pagination clause that
        /// folds the offset in. `offset()` with no following `limit()` emits a
        /// standalone offset clause for every dialect (T-SQL needs an ORDER BY,
        /// which is synthesized when absent).
        pub fn offset(self: *Self, n: usize) *Self {
            self.offset_n = n;
            return self;
        }

        /// Emit the standalone offset clause for an `offset()` that was never
        /// paired with a `limit()`. Called lazily from `statement()`.
        fn flushPendingOffset(self: *Self) void {
            const n = self.offset_n orelse return;
            self.offset_n = null;
            if (self.dialect == .mssql) {
                self.ensureMssqlOrder();
                var tmp: [32]u8 = undefined;
                self.append(std.fmt.bufPrint(&tmp, " OFFSET {d} ROWS", .{n}) catch unreachable);
                return;
            }
            // sqlite/mysql/postgres: a bare OFFSET is invalid without a LIMIT;
            // SQLite/MySQL accept a sentinel "all rows" limit, so emit one.
            var tmp: [48]u8 = undefined;
            const lim: []const u8 = switch (self.dialect) {
                .sqlite, .postgres => " LIMIT -1 OFFSET ",
                .mysql => " LIMIT 18446744073709551615 OFFSET ",
                .mssql => unreachable,
            };
            self.append(lim);
            self.append(std.fmt.bufPrint(&tmp, "{d}", .{n}) catch unreachable);
        }

        /// T-SQL OFFSET/FETCH requires an ORDER BY; synthesize a no-op one when
        /// the caller set none.
        fn ensureMssqlOrder(self: *Self) void {
            if (!self.has_order) {
                self.append(" ORDER BY (SELECT NULL)");
                self.has_order = true;
            }
        }

        pub fn limit(self: *Self, n: usize) *Self {
            const off = self.offset_n orelse 0;
            self.offset_n = null; // consumed — offset() must precede limit()
            // T-SQL has no LIMIT — it uses OFFSET … FETCH, which requires an
            // ORDER BY; synthesize a no-op order when the caller set none.
            if (self.dialect == .mssql) {
                self.ensureMssqlOrder();
                var tmp: [64]u8 = undefined;
                const s = std.fmt.bufPrint(&tmp, " OFFSET {d} ROWS FETCH NEXT {d} ROWS ONLY", .{ off, n }) catch unreachable;
                self.append(s);
                return self;
            }
            var tmp: [48]u8 = undefined;
            const s = if (off == 0)
                std.fmt.bufPrint(&tmp, " LIMIT {d}", .{n}) catch unreachable
            else
                std.fmt.bufPrint(&tmp, " LIMIT {d} OFFSET {d}", .{ n, off }) catch unreachable;
            self.append(s);
            return self;
        }

        /// Finalize and return the SQL text. Flushes any `offset()` that was
        /// recorded without a following `limit()`.
        fn statement(self: *Self) []const u8 {
            self.flushPendingOffset();
            return self.buf[0..self.len];
        }

        // ── terminals ───────────────────────────────────────────────────

        const Collector = struct {
            out: []T,
            n: usize = 0,
            fn cb(ctx: *anyopaque, row: *const contract.Row) bool {
                const self: *Collector = @ptrCast(@alignCast(ctx));
                if (self.n >= self.out.len) return false; // bounded: stop
                bind.rowToEntity(T, row, &self.out[self.n]);
                self.n += 1;
                return self.n < self.out.len;
            }
        };

        /// Run the query, filling `out` (bounded by its length). Returns the
        /// number of rows materialized.
        pub fn all(self: *Self, backend: Backend, out: []T) Error!usize {
            var c = Collector{ .out = out };
            try backend.query(self.statement(), self.args[0..self.arg_count], &c, Collector.cb);
            return c.n;
        }

        /// Run the query with an implicit `LIMIT 1`, materializing the first
        /// row into `out`. Returns false if there were no rows.
        pub fn first(self: *Self, backend: Backend, out: *T) Error!bool {
            _ = self.limit(1);
            var row: contract.Row = .{};
            if (!try backend.queryOne(self.statement(), self.args[0..self.arg_count], &row)) return false;
            bind.rowToEntity(T, &row, out);
            return true;
        }

        const ManagedCollector = struct {
            sess: *anyopaque,
            sess_materialize: *const fn (sess: *anyopaque, row: *const contract.Row) Error!?*T,
            out: []*T,
            n: usize = 0,
            err: ?Error = null,
            fn cb(ctx: *anyopaque, row: *const contract.Row) bool {
                const self: *ManagedCollector = @ptrCast(@alignCast(ctx));
                if (self.n >= self.out.len) return false;
                const ptr = self.sess_materialize(self.sess, row) catch |e| {
                    self.err = e;
                    return false;
                };
                self.out[self.n] = ptr.?;
                self.n += 1;
                return self.n < self.out.len;
            }
        };

        /// Run the query routing every row through `sess`'s identity map:
        /// results are deduped against already-managed entities (a row whose
        /// PK is already loaded yields the existing pointer, preserving
        /// in-flight edits). Fills `out` with managed pointers; returns count.
        pub fn allManaged(self: *Self, sess: anytype, out: []*T) Error!usize {
            const S = @typeInfo(@TypeOf(sess)).pointer.child;
            const Trampoline = struct {
                fn materialize(p: *anyopaque, row: *const contract.Row) Error!?*T {
                    const s: *S = @ptrCast(@alignCast(p));
                    var tmp: T = .{};
                    bind.rowToEntity(T, row, &tmp);
                    return try s.materialize(tmp);
                }
            };
            var c = ManagedCollector{
                .sess = sess,
                .sess_materialize = Trampoline.materialize,
                .out = out,
            };
            try sess.backend.query(self.statement(), self.args[0..self.arg_count], &c, ManagedCollector.cb);
            if (c.err) |e| return e;
            return c.n;
        }
    };
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;
const mock = @import("testing.zig");
const crud = @import("crud.zig");

const Role = enum { member, admin };
const Account = struct {
    pub const zorm_table = "atp_accounts";
    id: fields.Pk(64) = .{},
    handle: fields.Text(64) = .{},
    role: Role = .member,
    age: i64 = 0,
};

fn seed(backend: Backend, id: []const u8, handle: []const u8, role: Role, age: i64) !void {
    var a = Account{ .id = fields.Pk(64).from(id), .handle = fields.Text(64).from(handle), .role = role, .age = age };
    try crud.insert(Account, backend, &a);
}

// SELECT projection + table (and WHERE/ORDER BY columns) are identifier-quoted
// per dialect: sqlite/postgres → "..", mysql → `..`, mssql → [..].
const sel_sqlite = "SELECT \"id\", \"handle\", \"role\", \"age\" FROM \"atp_accounts\"";
const sel_pg = sel_sqlite; // postgres shares double-quote quoting
const sel_mysql = "SELECT `id`, `handle`, `role`, `age` FROM `atp_accounts`";
const sel_mssql = "SELECT [id], [handle], [role], [age] FROM [atp_accounts]";

test "where builds dialect placeholders + binds values" {
    var q = Query(Account).init(.postgres);
    _ = q.whereText("handle", "alice").whereInt("age", 30);
    try testing.expectEqualStrings(
        sel_pg ++ " WHERE \"handle\" = $1 AND \"age\" = $2",
        q.buf[0..q.len],
    );
    try testing.expectEqual(@as(usize, 2), q.arg_count);

    var q2 = Query(Account).init(.sqlite);
    _ = q2.whereText("handle", "bob");
    try testing.expectEqualStrings(
        sel_sqlite ++ " WHERE \"handle\" = ?",
        q2.buf[0..q2.len],
    );
}

test "orderBy + limit append correctly" {
    var q = Query(Account).init(.sqlite);
    _ = q.whereEnum("role", Role.admin).orderBy("age", .desc).limit(5);
    try testing.expectEqualStrings(
        sel_sqlite ++ " WHERE \"role\" = ? ORDER BY \"age\" DESC LIMIT 5",
        q.buf[0..q.len],
    );
    try testing.expectEqualStrings("admin", q.args[0].text);
}

test "MS SQL: @pN placeholders + OFFSET/FETCH for limit" {
    // limit with an explicit order → OFFSET/FETCH after the ORDER BY.
    var q = Query(Account).init(.mssql);
    _ = q.whereText("handle", "a").whereInt("age", 9).orderBy("age", .desc).limit(5);
    try testing.expectEqualStrings(
        sel_mssql ++ " WHERE [handle] = @p1 AND [age] = @p2 ORDER BY [age] DESC OFFSET 0 ROWS FETCH NEXT 5 ROWS ONLY",
        q.buf[0..q.len],
    );
    // limit WITHOUT an order → a synthesized no-op ORDER BY (T-SQL requires one).
    var q2 = Query(Account).init(.mssql);
    _ = q2.whereText("id", "x").limit(1);
    try testing.expectEqualStrings(
        sel_mssql ++ " WHERE [id] = @p1 ORDER BY (SELECT NULL) OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY",
        q2.buf[0..q2.len],
    );
}

test "whereOp emits each comparison operator (sqlite/postgres/mssql)" {
    const cases = [_]struct { op: Op, sym: []const u8 }{
        .{ .op = .eq, .sym = "=" },
        .{ .op = .ne, .sym = "<>" },
        .{ .op = .lt, .sym = "<" },
        .{ .op = .lte, .sym = "<=" },
        .{ .op = .gt, .sym = ">" },
        .{ .op = .gte, .sym = ">=" },
    };
    inline for (cases) |c| {
        var qs = Query(Account).init(.sqlite);
        _ = qs.whereOp("age", c.op, .{ .int = 18 });
        var buf: [256]u8 = undefined;
        const want_s = std.fmt.bufPrint(&buf, sel_sqlite ++ " WHERE \"age\" {s} ?", .{c.sym}) catch unreachable;
        try testing.expectEqualStrings(want_s, qs.buf[0..qs.len]);

        var qp = Query(Account).init(.postgres);
        _ = qp.whereOp("age", c.op, .{ .int = 18 });
        var buf2: [256]u8 = undefined;
        const want_p = std.fmt.bufPrint(&buf2, sel_pg ++ " WHERE \"age\" {s} $1", .{c.sym}) catch unreachable;
        try testing.expectEqualStrings(want_p, qp.buf[0..qp.len]);

        var qm = Query(Account).init(.mssql);
        _ = qm.whereOp("age", c.op, .{ .int = 18 });
        var buf3: [256]u8 = undefined;
        const want_m = std.fmt.bufPrint(&buf3, sel_mssql ++ " WHERE [age] {s} @p1", .{c.sym}) catch unreachable;
        try testing.expectEqualStrings(want_m, qm.buf[0..qm.len]);
        try testing.expectEqual(@as(i64, 18), qm.args[0].int);
    }
}

test "whereOp chains with AND and binds in order" {
    var q = Query(Account).init(.postgres);
    _ = q.whereOp("age", .gte, .{ .int = 18 }).whereOp("age", .lt, .{ .int = 65 });
    try testing.expectEqualStrings(
        sel_pg ++ " WHERE \"age\" >= $1 AND \"age\" < $2",
        q.buf[0..q.len],
    );
    try testing.expectEqual(@as(usize, 2), q.arg_count);
    try testing.expectEqual(@as(i64, 18), q.args[0].int);
    try testing.expectEqual(@as(i64, 65), q.args[1].int);
}

test "whereLike emits LIKE with a bound pattern (all placeholder styles)" {
    var qs = Query(Account).init(.sqlite);
    _ = qs.whereLike("handle", "a%");
    try testing.expectEqualStrings(
        sel_sqlite ++ " WHERE \"handle\" LIKE ?",
        qs.buf[0..qs.len],
    );
    try testing.expectEqualStrings("a%", qs.args[0].text);

    var qp = Query(Account).init(.postgres);
    _ = qp.whereLike("handle", "%bob%");
    try testing.expectEqualStrings(
        sel_pg ++ " WHERE \"handle\" LIKE $1",
        qp.buf[0..qp.len],
    );

    var qm = Query(Account).init(.mssql);
    _ = qm.whereLike("handle", "z_");
    try testing.expectEqualStrings(
        sel_mssql ++ " WHERE [handle] LIKE @p1",
        qm.buf[0..qm.len],
    );
}

test "whereIn with three values binds each as a placeholder" {
    var qs = Query(Account).init(.sqlite);
    const vals = [_]BindValue{ .{ .text = "1" }, .{ .text = "2" }, .{ .text = "3" } };
    _ = qs.whereIn("id", &vals);
    try testing.expectEqualStrings(
        sel_sqlite ++ " WHERE \"id\" IN (?, ?, ?)",
        qs.buf[0..qs.len],
    );
    try testing.expectEqual(@as(usize, 3), qs.arg_count);

    var qp = Query(Account).init(.postgres);
    _ = qp.whereIn("id", &vals);
    try testing.expectEqualStrings(
        sel_pg ++ " WHERE \"id\" IN ($1, $2, $3)",
        qp.buf[0..qp.len],
    );

    var qm = Query(Account).init(.mssql);
    _ = qm.whereIn("id", &vals);
    try testing.expectEqualStrings(
        sel_mssql ++ " WHERE [id] IN (@p1, @p2, @p3)",
        qm.buf[0..qm.len],
    );
}

test "whereIn empty list emits the always-false 1 = 0 with no binds" {
    var q = Query(Account).init(.postgres);
    const empty = [_]BindValue{};
    _ = q.whereIn("id", &empty);
    try testing.expectEqualStrings(
        sel_pg ++ " WHERE 1 = 0",
        q.buf[0..q.len],
    );
    try testing.expectEqual(@as(usize, 0), q.arg_count);

    // Chains correctly with a following predicate (joined via AND).
    var q2 = Query(Account).init(.sqlite);
    _ = q2.whereIn("id", &empty).whereText("handle", "x");
    try testing.expectEqualStrings(
        sel_sqlite ++ " WHERE 1 = 0 AND \"handle\" = ?",
        q2.buf[0..q2.len],
    );
}

test "whereNull / whereNotNull emit IS NULL / IS NOT NULL with no binds" {
    var q = Query(Account).init(.sqlite);
    _ = q.whereNull("handle").whereNotNull("age");
    try testing.expectEqualStrings(
        sel_sqlite ++ " WHERE \"handle\" IS NULL AND \"age\" IS NOT NULL",
        q.buf[0..q.len],
    );
    try testing.expectEqual(@as(usize, 0), q.arg_count);

    var qp = Query(Account).init(.postgres);
    _ = qp.whereNotNull("handle");
    try testing.expectEqualStrings(
        sel_pg ++ " WHERE \"handle\" IS NOT NULL",
        qp.buf[0..qp.len],
    );
}

test "offset + limit combined is dialect-correct on all four dialects" {
    // sqlite: LIMIT k OFFSET n
    var qs = Query(Account).init(.sqlite);
    _ = qs.orderBy("age", .asc).offset(20).limit(10);
    try testing.expectEqualStrings(
        sel_sqlite ++ " ORDER BY \"age\" ASC LIMIT 10 OFFSET 20",
        qs.buf[0..qs.len],
    );

    // postgres: identical LIMIT/OFFSET tail
    var qp = Query(Account).init(.postgres);
    _ = qp.orderBy("age", .asc).offset(20).limit(10);
    try testing.expectEqualStrings(
        sel_pg ++ " ORDER BY \"age\" ASC LIMIT 10 OFFSET 20",
        qp.buf[0..qp.len],
    );

    // mysql: identical LIMIT/OFFSET tail
    var qy = Query(Account).init(.mysql);
    _ = qy.orderBy("age", .asc).offset(20).limit(10);
    try testing.expectEqualStrings(
        sel_mysql ++ " ORDER BY `age` ASC LIMIT 10 OFFSET 20",
        qy.buf[0..qy.len],
    );

    // mssql: single OFFSET n ROWS FETCH NEXT k ROWS ONLY clause
    var qm = Query(Account).init(.mssql);
    _ = qm.orderBy("age", .asc).offset(20).limit(10);
    try testing.expectEqualStrings(
        sel_mssql ++ " ORDER BY [age] ASC OFFSET 20 ROWS FETCH NEXT 10 ROWS ONLY",
        qm.buf[0..qm.len],
    );
}

test "limit without offset is unchanged across dialects" {
    var qs = Query(Account).init(.sqlite);
    _ = qs.limit(5);
    try testing.expectEqualStrings(
        sel_sqlite ++ " LIMIT 5",
        qs.buf[0..qs.len],
    );

    // mssql with no order still synthesizes ORDER BY (SELECT NULL), OFFSET 0.
    var qm = Query(Account).init(.mssql);
    _ = qm.limit(5);
    try testing.expectEqualStrings(
        sel_mssql ++ " ORDER BY (SELECT NULL) OFFSET 0 ROWS FETCH NEXT 5 ROWS ONLY",
        qm.buf[0..qm.len],
    );
}

test "offset without limit flushes a standalone clause at statement()" {
    var db = mock.MockBackend.init();

    // sqlite: LIMIT -1 OFFSET n
    var qs = Query(Account).init(.sqlite);
    _ = qs.orderBy("age", .asc).offset(7);
    var out: [4]Account = undefined;
    _ = try qs.all(db.backend(.sqlite), &out);
    try testing.expectEqualStrings(
        sel_sqlite ++ " ORDER BY \"age\" ASC LIMIT -1 OFFSET 7",
        qs.buf[0..qs.len],
    );

    // postgres: LIMIT -1 OFFSET n
    var qp = Query(Account).init(.postgres);
    _ = qp.offset(7);
    var out2: [4]Account = undefined;
    _ = try qp.all(db.backend(.postgres), &out2);
    try testing.expectEqualStrings(
        sel_pg ++ " LIMIT -1 OFFSET 7",
        qp.buf[0..qp.len],
    );

    // mysql: sentinel max-LIMIT idiom
    var qy = Query(Account).init(.mysql);
    _ = qy.offset(7);
    var out3: [4]Account = undefined;
    _ = try qy.all(db.backend(.mysql), &out3);
    try testing.expectEqualStrings(
        sel_mysql ++ " LIMIT 18446744073709551615 OFFSET 7",
        qy.buf[0..qy.len],
    );

    // mssql: OFFSET n ROWS with a synthesized order
    var qm = Query(Account).init(.mssql);
    _ = qm.offset(7);
    var out4: [4]Account = undefined;
    _ = try qm.all(db.backend(.mssql), &out4);
    try testing.expectEqualStrings(
        sel_mssql ++ " ORDER BY (SELECT NULL) OFFSET 7 ROWS",
        qm.buf[0..qm.len],
    );
}

test "all() fills a bounded slice and matches the predicate" {
    var db = mock.MockBackend.init();
    const backend = db.backend(.sqlite);
    try seed(backend, "1", "a", .admin, 20);
    try seed(backend, "2", "b", .member, 30);

    var out: [8]Account = undefined;
    var q = Query(Account).init(.sqlite);
    const n = try q.whereText("id", "2").all(backend, &out);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqualStrings("b", out[0].handle.slice());
    try testing.expectEqual(@as(i64, 30), out[0].age);
}

test "first() returns false when no row matches" {
    var db = mock.MockBackend.init();
    const backend = db.backend(.sqlite);
    try seed(backend, "1", "a", .admin, 20);

    var got: Account = .{};
    var q = Query(Account).init(.sqlite);
    try testing.expect(!try q.whereText("id", "nope").first(backend, &got));

    var got2: Account = .{};
    var q2 = Query(Account).init(.sqlite);
    try testing.expect(try q2.whereText("id", "1").first(backend, &got2));
    try testing.expectEqualStrings("a", got2.handle.slice());
}

test "allManaged dedups against already-loaded entities" {
    var db = mock.MockBackend.init();
    const backend = db.backend(.sqlite);
    try seed(backend, "x", "orig", .member, 1);

    var s = session.Session(Account, 8).init(backend);
    // Load x and edit it in-flight (not yet flushed).
    const loaded = (try s.get("x")).?;
    loaded.handle = fields.Text(64).from("edited");

    var out: [8]*Account = undefined;
    var q = Query(Account).init(.sqlite);
    const n = try q.whereText("id", "x").allManaged(&s, &out);
    try testing.expectEqual(@as(usize, 1), n);
    // Same managed pointer — the in-flight edit is preserved, DB copy discarded.
    try testing.expectEqual(loaded, out[0]);
    try testing.expectEqualStrings("edited", out[0].handle.slice());
}
