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

        pub fn init(dialect: Dialect) Self {
            var q = Self{ .dialect = dialect };
            q.append(sql.selectAll(T));
            return q;
        }

        fn append(self: *Self, s: []const u8) void {
            std.debug.assert(self.len + s.len <= sql_buf_len);
            @memcpy(self.buf[self.len .. self.len + s.len], s);
            self.len += s.len;
        }

        fn appendPlaceholder(self: *Self) void {
            switch (self.dialect) {
                .sqlite => self.append("?"),
                .postgres => {
                    var tmp: [16]u8 = undefined;
                    const s = std.fmt.bufPrint(&tmp, "${d}", .{self.arg_count + 1}) catch unreachable;
                    self.append(s);
                },
            }
        }

        fn whereColumn(self: *Self, comptime name: []const u8) void {
            self.append(if (self.has_where) " AND " else " WHERE ");
            self.has_where = true;
            self.append(name);
            self.append(" = ");
            self.appendPlaceholder();
        }

        // ── predicates (chainable) ──────────────────────────────────────

        /// `WHERE <field> = <value>` with an explicit bind value.
        pub fn where(self: *Self, comptime field: []const u8, value: BindValue) *Self {
            self.whereColumn(checkColumn(T, field));
            self.args[self.arg_count] = value;
            self.arg_count += 1;
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
            self.append(checkColumn(T, field));
            self.append(if (dir == .desc) " DESC" else " ASC");
            return self;
        }

        pub fn limit(self: *Self, n: usize) *Self {
            var tmp: [24]u8 = undefined;
            const s = std.fmt.bufPrint(&tmp, " LIMIT {d}", .{n}) catch unreachable;
            self.append(s);
            return self;
        }

        fn statement(self: *const Self) []const u8 {
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

test "where builds dialect placeholders + binds values" {
    var q = Query(Account).init(.postgres);
    _ = q.whereText("handle", "alice").whereInt("age", 30);
    try testing.expectEqualStrings(
        "SELECT id, handle, role, age FROM atp_accounts WHERE handle = $1 AND age = $2",
        q.buf[0..q.len],
    );
    try testing.expectEqual(@as(usize, 2), q.arg_count);

    var q2 = Query(Account).init(.sqlite);
    _ = q2.whereText("handle", "bob");
    try testing.expectEqualStrings(
        "SELECT id, handle, role, age FROM atp_accounts WHERE handle = ?",
        q2.buf[0..q2.len],
    );
}

test "orderBy + limit append correctly" {
    var q = Query(Account).init(.sqlite);
    _ = q.whereEnum("role", Role.admin).orderBy("age", .desc).limit(5);
    try testing.expectEqualStrings(
        "SELECT id, handle, role, age FROM atp_accounts WHERE role = ? ORDER BY age DESC LIMIT 5",
        q.buf[0..q.len],
    );
    try testing.expectEqualStrings("admin", q.args[0].text);
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
