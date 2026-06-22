//! Stateless CRUD over a `contract.Backend`: the comptime-generated SQL
//! (`sql.zig`) bound with the comptime marshaler (`bind.zig`). No session,
//! no identity map — those live in `session.zig` (S3) and build on this.
//! Bind argument buffers are fixed-size (`max_columns`), stack-allocated;
//! no heap allocation on any path.

const std = @import("std");
const contract = @import("contract.zig");
const reflect = @import("reflect.zig");
const fields = @import("fields.zig");
const bind = @import("bind.zig");
const sql = @import("sql.zig");

const Backend = contract.Backend;
const BindValue = contract.BindValue;
const Error = contract.Error;
const max_columns = contract.max_columns;

/// Record `value` as a new row. For an auto-PK entity the DB-assigned id is
/// written back into `value`'s PK field (Postgres via `RETURNING`, SQLite
/// via `lastInsertId()`); for a text-PK entity the caller-set PK is used
/// as-is.
pub fn insert(comptime T: type, backend: Backend, value: *T) Error!void {
    const info = reflect.TableInfo(T);
    var args: [max_columns]BindValue = undefined;
    const n = bind.bindInsert(T, value, &args);
    const stmt = sql.insert(T, backend.dialect);

    if (info.pk_auto) {
        switch (backend.dialect) {
            // Postgres `… RETURNING <pk>` and SQL Server `… OUTPUT INSERTED.<pk>`
            // both yield one row, one integer column.
            .postgres, .mssql => {
                var row: contract.Row = .{};
                if (!try backend.queryOne(stmt, args[0..n], &row)) return Error.StepFailed;
                setAutoPk(T, value, row.columns[0].int_val);
            },
            // MySQL 8 has no RETURNING; like SQLite it reads the assigned id
            // from the connection (LAST_INSERT_ID()).
            .sqlite, .mysql => {
                try backend.exec(stmt, args[0..n]);
                setAutoPk(T, value, backend.lastInsertId());
            },
        }
    } else {
        try backend.exec(stmt, args[0..n]);
    }
}

/// Load the row with primary key `pk` into `out`. Returns false if absent
/// (`out` is left untouched).
pub fn findByPk(comptime T: type, backend: Backend, pk: bind.PkValue(T), out: *T) Error!bool {
    const stmt = sql.selectByPk(T, backend.dialect);
    const arg = bind.bindPkValue(T, pk);
    var row: contract.Row = .{};
    if (!try backend.queryOne(stmt, &.{arg}, &row)) return false;
    bind.rowToEntity(T, &row, out);
    return true;
}

/// Insert `value`, or — on a primary-key collision — update its non-PK
/// columns to the supplied values (an upsert). Binds the full row exactly
/// like `insert` (every non-auto-PK column, in `TableInfo` order) and execs
/// the dialect's conflict-resolution statement.
///
/// No RETURNING / id write-back: an upsert may either insert (a new id) or
/// update (an existing id), and the dialects disagree on what they can return
/// (MySQL ON DUPLICATE KEY / SQL Server MERGE do not yield the row uniformly),
/// so the auto-PK field is NOT populated here. Callers that need the assigned
/// id for a fresh row should `insert` instead; `upsert` targets text/explicit
/// PKs where the key is caller-supplied and already known.
pub fn upsert(comptime T: type, backend: Backend, value: *T) Error!void {
    var args: [max_columns]BindValue = undefined;
    const n = bind.bindInsert(T, value, &args);
    try backend.exec(sql.upsert(T, backend.dialect), args[0..n]);
}

/// Persist all non-PK columns of `value`, matched by its PK.
pub fn update(comptime T: type, backend: Backend, value: *const T) Error!void {
    var args: [max_columns]BindValue = undefined;
    const n = bind.bindUpdate(T, value, &args);
    try backend.exec(sql.update(T, backend.dialect), args[0..n]);
}

/// Delete the row with primary key `pk`.
pub fn deleteByPk(comptime T: type, backend: Backend, pk: bind.PkValue(T)) Error!void {
    const arg = bind.bindPkValue(T, pk);
    try backend.exec(sql.deleteByPk(T, backend.dialect), &.{arg});
}

/// Delete the row identified by `value`'s PK.
pub fn delete(comptime T: type, backend: Backend, value: *const T) Error!void {
    var args: [max_columns]BindValue = undefined;
    const arg = bind.bindPk(T, value);
    args[0] = arg;
    try backend.exec(sql.deleteByPk(T, backend.dialect), args[0..1]);
}

/// Write a DB-assigned id into the entity's auto-PK field.
fn setAutoPk(comptime T: type, value: *T, id: i64) void {
    const info = reflect.TableInfo(T);
    @field(value.*, info.pk_column.name).value = id;
}

// ── Tests ──────────────────────────────────────────────────────────────
//
// CRUD exercises a live backend. zorm depends on nothing, so these tests
// run against a self-contained in-memory mock backend that interprets the
// exact statement shapes `sql.zig` emits (INSERT / SELECT-by-pk / UPDATE /
// DELETE-by-pk). Full-engine round-trips against a real SqliteBackend +
// live Postgres live in the host's integration suite (S6).

const testing = std.testing;
const mock = @import("testing.zig");

const Role = enum { member, admin };
const Account = struct {
    pub const zorm_table = "atp_accounts";
    id: fields.Pk(64) = .{},
    handle: fields.Text(64) = .{},
    email: ?fields.Text(64) = null,
    role: Role = .member,
    score: f64 = 0,
};

test "insert + findByPk round-trips a text-PK entity" {
    var db = mock.MockBackend.init();
    const backend = db.backend(.sqlite);

    var a = Account{
        .id = fields.Pk(64).from("did:plc:xyz"),
        .handle = fields.Text(64).from("alice"),
        .email = fields.Text(64).from("a@x.test"),
        .role = .admin,
        .score = 3.5,
    };
    try insert(Account, backend, &a);

    var got: Account = .{};
    try testing.expect(try findByPk(Account, backend, "did:plc:xyz", &got));
    try testing.expectEqualStrings("alice", got.handle.slice());
    try testing.expect(got.email != null);
    try testing.expectEqualStrings("a@x.test", got.email.?.slice());
    try testing.expectEqual(Role.admin, got.role);
    try testing.expectEqual(@as(f64, 3.5), got.score);
}

test "findByPk returns false for a missing row" {
    var db = mock.MockBackend.init();
    const backend = db.backend(.sqlite);
    var got: Account = .{};
    try testing.expect(!try findByPk(Account, backend, "nope", &got));
}

test "update changes non-PK columns, keyed by PK" {
    var db = mock.MockBackend.init();
    const backend = db.backend(.sqlite);

    var a = Account{ .id = fields.Pk(64).from("k"), .handle = fields.Text(64).from("old"), .role = .member };
    try insert(Account, backend, &a);

    a.handle = fields.Text(64).from("new");
    a.role = .admin;
    a.email = fields.Text(64).from("e@x.test");
    try update(Account, backend, &a);

    var got: Account = .{};
    try testing.expect(try findByPk(Account, backend, "k", &got));
    try testing.expectEqualStrings("new", got.handle.slice());
    try testing.expectEqual(Role.admin, got.role);
    try testing.expectEqualStrings("e@x.test", got.email.?.slice());
}

test "deleteByPk removes the row" {
    var db = mock.MockBackend.init();
    const backend = db.backend(.sqlite);

    var a = Account{ .id = fields.Pk(64).from("d"), .handle = fields.Text(64).from("x") };
    try insert(Account, backend, &a);
    try deleteByPk(Account, backend, "d");

    var got: Account = .{};
    try testing.expect(!try findByPk(Account, backend, "d", &got));
}

const Thing = struct {
    pub const zorm_table = "things";
    id: fields.AutoPk = .{},
    name: fields.Text(32) = .{},
};

test "insert assigns an auto PK via lastInsertId (SQLite path)" {
    var db = mock.MockBackend.init();
    const backend = db.backend(.sqlite);

    var t1 = Thing{ .name = fields.Text(32).from("first") };
    try insert(Thing, backend, &t1);
    try testing.expect(t1.id.value > 0);

    var t2 = Thing{ .name = fields.Text(32).from("second") };
    try insert(Thing, backend, &t2);
    try testing.expect(t2.id.value > t1.id.value);

    var got: Thing = .{};
    try testing.expect(try findByPk(Thing, backend, t1.id.value, &got));
    try testing.expectEqualStrings("first", got.name.slice());
}

test "upsert: same PK twice updates the row instead of duplicating it" {
    var db = mock.MockBackend.init();
    const backend = db.backend(.sqlite);

    // First upsert behaves as an insert.
    var a = Account{
        .id = fields.Pk(64).from("did:plc:up"),
        .handle = fields.Text(64).from("first"),
        .role = .member,
        .score = 1.0,
    };
    try upsert(Account, backend, &a);

    // Second upsert with the SAME PK but changed columns must UPDATE, not
    // append a second row.
    var a2 = Account{
        .id = fields.Pk(64).from("did:plc:up"),
        .handle = fields.Text(64).from("second"),
        .email = fields.Text(64).from("up@x.test"),
        .role = .admin,
        .score = 9.0,
    };
    try upsert(Account, backend, &a2);

    // The row reflects the latest values …
    var got: Account = .{};
    try testing.expect(try findByPk(Account, backend, "did:plc:up", &got));
    try testing.expectEqualStrings("second", got.handle.slice());
    try testing.expect(got.email != null);
    try testing.expectEqualStrings("up@x.test", got.email.?.slice());
    try testing.expectEqual(Role.admin, got.role);
    try testing.expectEqual(@as(f64, 9.0), got.score);

    // … and there is exactly ONE row for that PK (no duplicate).
    try testing.expectEqual(@as(usize, 1), db.rowCount("atp_accounts"));
}

test "upsert: a brand-new PK simply inserts" {
    var db = mock.MockBackend.init();
    const backend = db.backend(.sqlite);

    var a = Account{ .id = fields.Pk(64).from("fresh"), .handle = fields.Text(64).from("h") };
    try upsert(Account, backend, &a);

    var got: Account = .{};
    try testing.expect(try findByPk(Account, backend, "fresh", &got));
    try testing.expectEqualStrings("h", got.handle.slice());
    try testing.expectEqual(@as(usize, 1), db.rowCount("atp_accounts"));
}

test "values with SQL metacharacters survive as data (parameterized binds)" {
    var db = mock.MockBackend.init();
    const backend = db.backend(.sqlite);

    const nasty = "rob'; DROP TABLE accounts;--";
    var a = Account{ .id = fields.Pk(64).from("inj"), .handle = fields.Text(64).from(nasty) };
    try insert(Account, backend, &a);

    var got: Account = .{};
    try testing.expect(try findByPk(Account, backend, "inj", &got));
    try testing.expectEqualStrings(nasty, got.handle.slice());
}
