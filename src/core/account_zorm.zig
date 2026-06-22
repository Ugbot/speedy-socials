//! S6 — zorm proof: the canonical account row, persisted and fetched
//! through the full zorm stack (comptime DDL, CRUD, Session/unit-of-work,
//! query builder) against the REAL storage engines via the zero-cost
//! `zorm_adapter` — SQLite always, and live Postgres when `PG_TEST_URL` is
//! set. This proves the ORM end-to-end on actual engines (not just the
//! in-library mock) AND that the dialect divergence is handled correctly:
//! `?` + `lastInsertId()` on SQLite vs `$N` + `RETURNING` on Postgres.
//!
//! Scope (per plan): the cross-protocol account *row* (id/handle/email/
//! state/email_confirmed/created_at). The auth surface (password hashing,
//! email tokens, app-passwords — composite keys / upserts) remains on the
//! hand-written `account_sqlite.SqliteBackend`; those are explicit v1
//! non-goals for zorm and are NOT faked here.

const std = @import("std");
const zorm = @import("zorm");
const storage = @import("storage.zig");
const account = @import("account.zig");
const pg = @import("pg");
const postgres = @import("storage/postgres_backend.zig");

/// The account row as a zorm entity — the struct fields ARE the schema.
/// Reuses `account.State` directly: zorm stores an enum as its `@tagName`
/// ("active"/"suspended"/…), which matches the existing column strings.
const ZAccount = struct {
    pub const zorm_table = "zorm_accounts";
    id: zorm.Pk(account.max_id_bytes) = .{},
    handle: zorm.Text(account.max_handle_bytes) = .{},
    email: zorm.Text(account.max_email_bytes) = .{},
    state: account.State = .active,
    email_confirmed: bool = false,
    created_at: zorm.Timestamp = .{},
};

/// A second entity with an auto-increment PK, to prove the DB-assigned-id
/// path on both engines (RETURNING on PG, lastInsertId on SQLite).
const ZEvent = struct {
    pub const zorm_table = "zorm_events";
    id: zorm.AutoPk = .{},
    name: zorm.Text(64) = .{},
};

fn randAccount(rand: std.Random, i: usize) ZAccount {
    var a: ZAccount = .{};
    var idb: [account.max_id_bytes]u8 = undefined;
    a.id.set(std.fmt.bufPrint(&idb, "did:plc:{x}{d}", .{ rand.int(u48), i }) catch unreachable);
    var hb: [account.max_handle_bytes]u8 = undefined;
    a.handle.set(std.fmt.bufPrint(&hb, "user{x}.test", .{rand.int(u32)}) catch unreachable);
    var eb: [account.max_email_bytes]u8 = undefined;
    a.email.set(std.fmt.bufPrint(&eb, "u{x}@mail.test", .{rand.int(u32)}) catch unreachable);
    const states = [_]account.State{ .active, .deactivated, .suspended, .takendown };
    a.state = states[rand.uintLessThan(usize, states.len)];
    a.email_confirmed = rand.boolean();
    a.created_at = .{ .unix = rand.int(i32) };
    return a;
}

fn expectSameAccount(want: *const ZAccount, got: *const ZAccount) !void {
    const t = std.testing;
    try t.expectEqualStrings(want.id.slice(), got.id.slice());
    try t.expectEqualStrings(want.handle.slice(), got.handle.slice());
    try t.expectEqualStrings(want.email.slice(), got.email.slice());
    try t.expectEqual(want.state, got.state);
    try t.expectEqual(want.email_confirmed, got.email_confirmed);
    try t.expectEqual(want.created_at.unix, got.created_at.unix);
}

// ── SQLite (always runs) ─────────────────────────────────────────────────

const sqlite = storage.sqlite;

/// Open an in-memory SQLite, wrap it as a zorm backend, create the table.
fn sqliteZorm(comptime T: type, db: *@import("sqlite").c.sqlite3, be: *storage.SqliteBackend, adapter: *storage.zorm_adapter.Adapter) !zorm.Backend {
    be.* = storage.SqliteBackend.init(db);
    adapter.* = storage.zorm_adapter.Adapter.init(be.backend());
    const zb = adapter.backend(.sqlite);
    try zb.exec(zorm.createTable(T, .sqlite), &.{});
    return zb;
}

test "zorm/SQLite: CRUD round-trip of the account row (randomized)" {
    const db = try sqlite.openWriter(":memory:");
    defer sqlite.closeDb(db);
    var be: storage.SqliteBackend = undefined;
    var adapter: storage.zorm_adapter.Adapter = undefined;
    const zb = try sqliteZorm(ZAccount, db, &be, &adapter);

    var repo = zorm.Repository(ZAccount).init(zb);

    var prng = std.Random.DefaultPrng.init(0xC0FFEE01);
    const rand = prng.random();

    var i: usize = 0;
    while (i < 25) : (i += 1) {
        var a = randAccount(rand, i);
        try repo.insertNow(&a);

        var got: ZAccount = .{};
        try std.testing.expect(try repo.findByPk(a.id.slice(), &got));
        try expectSameAccount(&a, &got);

        // Update a couple of columns and confirm the change persists.
        a.state = .deleted;
        a.email_confirmed = !a.email_confirmed;
        try repo.updateNow(&a);
        var got2: ZAccount = .{};
        try std.testing.expect(try repo.findByPk(a.id.slice(), &got2));
        try expectSameAccount(&a, &got2);
    }

    // A missing key returns false.
    var none: ZAccount = .{};
    try std.testing.expect(!try repo.findByPk("did:plc:absent", &none));
}

test "zorm/SQLite: upsert inserts then updates the same PK without duplicating (real engine)" {
    const db = try sqlite.openWriter(":memory:");
    defer sqlite.closeDb(db);
    var be: storage.SqliteBackend = undefined;
    var adapter: storage.zorm_adapter.Adapter = undefined;
    const zb = try sqliteZorm(ZAccount, db, &be, &adapter);

    var prng = std.Random.DefaultPrng.init(0x0095E4701);
    const rand = prng.random();

    var i: usize = 0;
    while (i < 20) : (i += 1) {
        // First upsert of a brand-new key behaves like an INSERT.
        var a = randAccount(rand, i);
        try zorm.upsert(ZAccount, zb, &a); // INSERT … ON CONFLICT("id") DO UPDATE …

        var got: ZAccount = .{};
        try std.testing.expect(try zorm.findByPk(ZAccount, zb, a.id.slice(), &got));
        try expectSameAccount(&a, &got);

        // Second upsert of the SAME key with changed columns must UPDATE the
        // existing row — not raise a UNIQUE violation, not add a second row.
        var b2 = a; // same id
        b2.handle.set("changed.test");
        b2.email.set("changed@mail.test");
        b2.state = .suspended;
        b2.email_confirmed = !a.email_confirmed;
        b2.created_at = .{ .unix = rand.int(i32) };
        try zorm.upsert(ZAccount, zb, &b2);

        var got2: ZAccount = .{};
        try std.testing.expect(try zorm.findByPk(ZAccount, zb, a.id.slice(), &got2));
        try expectSameAccount(&b2, &got2);
    }

    // Exactly `20` rows exist (one per distinct key) — upsert updated, never
    // duplicated. Count via the query builder over the whole table.
    var out: [64]ZAccount = undefined;
    var q = zorm.Query(ZAccount).init(.sqlite);
    const n = try q.all(zb, &out);
    try std.testing.expectEqual(@as(usize, 20), n);
}

test "zorm/SQLite: Session unit-of-work batches insert+update+delete in one txn" {
    const db = try sqlite.openWriter(":memory:");
    defer sqlite.closeDb(db);
    var be: storage.SqliteBackend = undefined;
    var adapter: storage.zorm_adapter.Adapter = undefined;
    const zb = try sqliteZorm(ZAccount, db, &be, &adapter);

    var s = zorm.Session(ZAccount, 16).init(zb);

    var prng = std.Random.DefaultPrng.init(0x5151);
    const rand = prng.random();

    // Insert three in one flush.
    var ids: [3][account.max_id_bytes]u8 = undefined;
    var id_lens: [3]usize = undefined;
    inline for (0..3) |k| {
        const a = try s.add(randAccount(rand, k));
        id_lens[k] = a.id.slice().len;
        @memcpy(ids[k][0..id_lens[k]], a.id.slice());
    }
    try s.flush();
    s.reset();

    // Reload one, mutate it; add a fresh one; delete another — one flush.
    const keep = (try s.get(ids[0][0..id_lens[0]])).?;
    keep.handle = zorm.Text(account.max_handle_bytes).from("renamed.test");
    const doomed = (try s.get(ids[1][0..id_lens[1]])).?;
    s.remove(doomed);
    var fresh = randAccount(rand, 99);
    _ = try s.add(fresh);
    try s.flush();

    s.reset();
    try std.testing.expectEqualStrings("renamed.test", (try s.get(ids[0][0..id_lens[0]])).?.handle.slice());
    try std.testing.expect((try s.get(ids[1][0..id_lens[1]])) == null);
    try std.testing.expect((try s.get(fresh.id.slice())) != null);
}

test "zorm/SQLite: query builder filters + orders + bounds results" {
    const db = try sqlite.openWriter(":memory:");
    defer sqlite.closeDb(db);
    var be: storage.SqliteBackend = undefined;
    var adapter: storage.zorm_adapter.Adapter = undefined;
    const zb = try sqliteZorm(ZAccount, db, &be, &adapter);
    var repo = zorm.Repository(ZAccount).init(zb);

    // 6 active (varying created_at) + 4 suspended.
    var t: i64 = 0;
    while (t < 6) : (t += 1) {
        var a = ZAccount{ .state = .active, .created_at = .{ .unix = t } };
        var idb: [account.max_id_bytes]u8 = undefined;
        a.id.set(std.fmt.bufPrint(&idb, "act{d}", .{t}) catch unreachable);
        a.handle.set("h.test");
        a.email.set("e@test");
        try repo.insertNow(&a);
    }
    var u: i64 = 0;
    while (u < 4) : (u += 1) {
        var a = ZAccount{ .state = .suspended };
        var idb: [account.max_id_bytes]u8 = undefined;
        a.id.set(std.fmt.bufPrint(&idb, "sus{d}", .{u}) catch unreachable);
        a.handle.set("h.test");
        a.email.set("e@test");
        try repo.insertNow(&a);
    }

    var out: [16]ZAccount = undefined;
    var q = zorm.Query(ZAccount).init(.sqlite);
    const n = try q.whereEnum("state", account.State.active)
        .orderBy("created_at", .desc)
        .limit(3)
        .all(zb, &out);
    try std.testing.expectEqual(@as(usize, 3), n);
    for (out[0..n]) |row| try std.testing.expectEqual(account.State.active, row.state);
    // ORDER BY created_at DESC LIMIT 3 → the three newest (5,4,3).
    try std.testing.expectEqual(@as(i64, 5), out[0].created_at.unix);
    try std.testing.expectEqual(@as(i64, 4), out[1].created_at.unix);
    try std.testing.expectEqual(@as(i64, 3), out[2].created_at.unix);
}

test "zorm/SQLite: auto-PK id assigned via lastInsertId" {
    const db = try sqlite.openWriter(":memory:");
    defer sqlite.closeDb(db);
    var be: storage.SqliteBackend = undefined;
    var adapter: storage.zorm_adapter.Adapter = undefined;
    const zb = try sqliteZorm(ZEvent, db, &be, &adapter);
    var repo = zorm.Repository(ZEvent).init(zb);

    var e1 = ZEvent{ .name = zorm.Text(64).from("created") };
    try repo.insertNow(&e1);
    try std.testing.expect(e1.id.value > 0);
    var e2 = ZEvent{ .name = zorm.Text(64).from("updated") };
    try repo.insertNow(&e2);
    try std.testing.expect(e2.id.value > e1.id.value);

    var got: ZEvent = .{};
    try std.testing.expect(try repo.findByPk(e1.id.value, &got));
    try std.testing.expectEqualStrings("created", got.name.slice());
}

// ── Composite primary key (Z4) — real in-memory SQLite engine ────────────

// A two-column PK entity: (tenant TEXT, seq INTEGER). The pair is the key —
// proving composite findByPk / update / delete / identity-map against the
// REAL SqliteBackend (via the zorm_adapter), not just the in-library mock.
const ZMembership = struct {
    pub const zorm_table = "zorm_memberships";
    tenant: zorm.Pk(32) = .{},
    seq: zorm.PkInt = .{},
    role: zorm.Text(16) = .{},
    note: zorm.Text(64) = .{},
};

test "zorm/SQLite: composite PK CRUD round-trip against the real engine" {
    const db = try sqlite.openWriter(":memory:");
    defer sqlite.closeDb(db);
    var be: storage.SqliteBackend = undefined;
    var adapter: storage.zorm_adapter.Adapter = undefined;
    const zb = try sqliteZorm(ZMembership, db, &be, &adapter);

    var prng = std.Random.DefaultPrng.init(0xC0117B05E);
    const rand = prng.random();

    // Seed a randomized set of (tenant, seq) pairs across a few tenants, all
    // distinct keys. Track them so we can verify each by its full key.
    const n = 24;
    var seeded: [n]ZMembership = undefined;
    const tenants = [_][]const u8{ "acme", "globex", "initech" };
    var i: usize = 0;
    while (i < n) : (i += 1) {
        var m: ZMembership = .{};
        m.tenant.set(tenants[i % tenants.len]);
        // seq is unique within (tenant) by construction: i / tenants.len gives
        // a distinct ordinal per tenant.
        m.seq = .{ .value = @intCast(i / tenants.len) };
        var rb: [16]u8 = undefined;
        m.role.set(std.fmt.bufPrint(&rb, "r{x}", .{rand.int(u16)}) catch unreachable);
        var nb: [64]u8 = undefined;
        m.note.set(std.fmt.bufPrint(&nb, "note-{x}", .{rand.int(u32)}) catch unreachable);
        seeded[i] = m;
        try zorm.insert(ZMembership, zb, &m);
    }

    // findByPk on the FULL composite key matches the right row; a wrong second
    // part (same tenant, different seq) misses.
    for (seeded) |want| {
        var got: ZMembership = .{};
        try std.testing.expect(try zorm.findByPk(
            ZMembership,
            zb,
            .{ want.tenant.slice(), want.seq.value },
            &got,
        ));
        try std.testing.expectEqualStrings(want.role.slice(), got.role.slice());
        try std.testing.expectEqualStrings(want.note.slice(), got.note.slice());
        try std.testing.expectEqual(want.seq.value, got.seq.value);

        var miss: ZMembership = .{};
        try std.testing.expect(!try zorm.findByPk(
            ZMembership,
            zb,
            .{ want.tenant.slice(), want.seq.value + 1000 },
            &miss,
        ));
    }

    // Update keyed on the full composite key; a sibling sharing the tenant is
    // untouched.
    var upd = seeded[0];
    upd.role.set("OWNER");
    try zorm.update(ZMembership, zb, &upd);
    var got0: ZMembership = .{};
    try std.testing.expect(try zorm.findByPk(ZMembership, zb, .{ upd.tenant.slice(), upd.seq.value }, &got0));
    try std.testing.expectEqualStrings("OWNER", got0.role.slice());
    // seeded[tenants.len] shares seeded[0]'s tenant but a different seq.
    const sib = seeded[tenants.len];
    var gotSib: ZMembership = .{};
    try std.testing.expect(try zorm.findByPk(ZMembership, zb, .{ sib.tenant.slice(), sib.seq.value }, &gotSib));
    try std.testing.expectEqualStrings(sib.role.slice(), gotSib.role.slice());

    // Delete keyed on the full composite key removes exactly one row.
    try zorm.deleteByPk(ZMembership, zb, .{ seeded[1].tenant.slice(), seeded[1].seq.value });
    var gone: ZMembership = .{};
    try std.testing.expect(!try zorm.findByPk(ZMembership, zb, .{ seeded[1].tenant.slice(), seeded[1].seq.value }, &gone));

    // The whole table now has n-1 rows.
    var out: [64]ZMembership = undefined;
    var q = zorm.Query(ZMembership).init(.sqlite);
    try std.testing.expectEqual(@as(usize, n - 1), try q.all(zb, &out));
}

test "zorm/SQLite: composite PK identity map returns the same pointer (real engine)" {
    const db = try sqlite.openWriter(":memory:");
    defer sqlite.closeDb(db);
    var be: storage.SqliteBackend = undefined;
    var adapter: storage.zorm_adapter.Adapter = undefined;
    const zb = try sqliteZorm(ZMembership, db, &be, &adapter);

    var s = zorm.Session(ZMembership, 16).init(zb);

    // Two rows under the same tenant with distinct seq parts.
    var a: ZMembership = .{};
    a.tenant.set("acme");
    a.seq = .{ .value = 1 };
    a.role.set("admin");
    _ = try s.add(a);
    var b: ZMembership = .{};
    b.tenant.set("acme");
    b.seq = .{ .value = 2 };
    b.role.set("member");
    _ = try s.add(b);
    try s.flush();
    s.reset();

    // Same composite key → same managed pointer.
    const p1 = (try s.get(.{ "acme", @as(i64, 1) })).?;
    const p2 = (try s.get(.{ "acme", @as(i64, 1) })).?;
    try std.testing.expectEqual(p1, p2);
    try std.testing.expectEqualStrings("admin", p1.role.slice());

    // Different seq part → distinct identity.
    const q = (try s.get(.{ "acme", @as(i64, 2) })).?;
    try std.testing.expect(p1 != q);
    try std.testing.expectEqualStrings("member", q.role.slice());

    // In-flight edit preserved across a repeat get of the same key.
    p1.role = zorm.Text(16).from("OWNER");
    const p3 = (try s.get(.{ "acme", @as(i64, 1) })).?;
    try std.testing.expectEqual(p1, p3);
    try std.testing.expectEqualStrings("OWNER", p3.role.slice());

    // Absent composite key → null.
    try std.testing.expect((try s.get(.{ "acme", @as(i64, 99) })) == null);
}

// ── Postgres (live; skips unless PG_TEST_URL is set) ─────────────────────

fn testPool() ?*pg.Pool {
    const url_c = std.c.getenv("PG_TEST_URL") orelse return null;
    const uri_str = std.mem.sliceTo(url_c, 0);
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    const io = threaded.io();
    const uri = std.Uri.parse(uri_str) catch return null;
    return pg.Pool.initUri(io, std.testing.allocator, uri, .{ .size = 1, .timeout = 2000 }) catch null;
}

test "zorm/Postgres: dialect parity — $N placeholders, text PK round-trip (skips if no server)" {
    const pool = testPool() orelse return error.SkipZigTest;
    defer pool.deinit();
    var be = postgres.PostgresBackend.init(pool);
    var adapter = storage.zorm_adapter.Adapter.init(be.backend());
    const zb = adapter.backend(.postgres);

    // Fresh table each run.
    zb.exec(zorm.dropTable(ZAccount), &.{}) catch return error.SkipZigTest;
    try zb.exec(zorm.createTable(ZAccount, .postgres), &.{});
    defer zb.exec(zorm.dropTable(ZAccount), &.{}) catch {};

    var repo = zorm.Repository(ZAccount).init(zb);
    var prng = std.Random.DefaultPrng.init(0x9E55);
    const rand = prng.random();

    var i: usize = 0;
    while (i < 10) : (i += 1) {
        var a = randAccount(rand, i);
        try repo.insertNow(&a); // INSERT … VALUES ($1,$2,…) — text PK, no RETURNING
        var got: ZAccount = .{};
        try std.testing.expect(try repo.findByPk(a.id.slice(), &got)); // SELECT … WHERE id = $1
        try expectSameAccount(&a, &got);
    }
}

test "zorm/Postgres: auto-PK id assigned via RETURNING (skips if no server)" {
    const pool = testPool() orelse return error.SkipZigTest;
    defer pool.deinit();
    var be = postgres.PostgresBackend.init(pool);
    var adapter = storage.zorm_adapter.Adapter.init(be.backend());
    const zb = adapter.backend(.postgres);

    zb.exec(zorm.dropTable(ZEvent), &.{}) catch return error.SkipZigTest;
    try zb.exec(zorm.createTable(ZEvent, .postgres), &.{});
    defer zb.exec(zorm.dropTable(ZEvent), &.{}) catch {};

    var repo = zorm.Repository(ZEvent).init(zb);
    var e1 = ZEvent{ .name = zorm.Text(64).from("pg-first") };
    try repo.insertNow(&e1); // INSERT … RETURNING id
    try std.testing.expect(e1.id.value > 0);
    var e2 = ZEvent{ .name = zorm.Text(64).from("pg-second") };
    try repo.insertNow(&e2);
    try std.testing.expect(e2.id.value != e1.id.value);

    var got: ZEvent = .{};
    try std.testing.expect(try repo.findByPk(e1.id.value, &got));
    try std.testing.expectEqualStrings("pg-first", got.name.slice());
}
