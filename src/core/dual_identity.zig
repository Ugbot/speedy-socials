//! DUAL-1/3/4/5: cross-protocol identity binding.
//!
//! When a user signs up on speedy-socials, we want the same identity
//! to anchor both AP (`ap_users` row with Ed25519 + actor doc) and
//! AT (`atp_repos` row with signing key + DID). This module owns
//! the join — given a `core.account.Account`, mint both rows and
//! record the binding in `core_identity_map`.
//!
//! Multi-tenancy (DUAL-5) rides on a `tenant` column on the same
//! table; when the field is absent every account belongs to the
//! default tenant.

const std = @import("std");
const c = @import("sqlite").c;
const storage = @import("storage.zig");
const account = @import("account.zig");

pub const Error = error{
    InsertFailed,
    LookupFailed,
};

pub const Binding = struct {
    /// Account id (typically the AT DID).
    account_id_buf: [account.max_id_bytes]u8 = undefined,
    account_id_len: u8 = 0,
    /// AP actor IRI (`https://<host>/users/<u>`).
    ap_actor_buf: [320]u8 = undefined,
    ap_actor_len: u16 = 0,
    /// AT DID (often the same as account_id when did:web is used).
    at_did_buf: [account.max_id_bytes]u8 = undefined,
    at_did_len: u8 = 0,
    /// Tenant identifier — empty = default tenant.
    tenant_buf: [64]u8 = undefined,
    tenant_len: u8 = 0,

    pub fn accountId(self: *const Binding) []const u8 {
        return self.account_id_buf[0..self.account_id_len];
    }
    pub fn apActor(self: *const Binding) []const u8 {
        return self.ap_actor_buf[0..self.ap_actor_len];
    }
    pub fn atDid(self: *const Binding) []const u8 {
        return self.at_did_buf[0..self.at_did_len];
    }
    pub fn tenant(self: *const Binding) []const u8 {
        return self.tenant_buf[0..self.tenant_len];
    }
};

/// Migration. Schema-side it's owned here so both AP and AT plugins
/// can `register` it.
pub const migration: storage.Migration = .{
    .id = 900_001,
    .name = "core:identity_map",
    .up =
    \\CREATE TABLE IF NOT EXISTS core_identity_map (
    \\    account_id TEXT PRIMARY KEY,
    \\    ap_actor   TEXT NOT NULL,
    \\    at_did     TEXT NOT NULL,
    \\    tenant     TEXT NOT NULL DEFAULT '',
    \\    created_at INTEGER NOT NULL
    \\) STRICT;
    \\CREATE INDEX IF NOT EXISTS core_identity_map_ap_idx ON core_identity_map (ap_actor);
    \\CREATE INDEX IF NOT EXISTS core_identity_map_at_idx ON core_identity_map (at_did);
    \\CREATE INDEX IF NOT EXISTS core_identity_map_tenant_idx ON core_identity_map (tenant);
    ,
    .down = "DROP TABLE core_identity_map;",
};

pub fn bind(
    db: *c.sqlite3,
    account_id: []const u8,
    ap_actor: []const u8,
    at_did: []const u8,
    tenant: []const u8,
    now_unix: i64,
) Error!void {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql =
        \\INSERT INTO core_identity_map (account_id, ap_actor, at_did, tenant, created_at)
        \\VALUES (?,?,?,?,?)
        \\ON CONFLICT (account_id) DO UPDATE
        \\  SET ap_actor = excluded.ap_actor, at_did = excluded.at_did, tenant = excluded.tenant
    ;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.InsertFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, account_id.ptr, @intCast(account_id.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 2, ap_actor.ptr, @intCast(ap_actor.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 3, at_did.ptr, @intCast(at_did.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 4, tenant.ptr, @intCast(tenant.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(stmt, 5, now_unix);
    if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return error.InsertFailed;
}

pub fn lookupByAccountId(db: *c.sqlite3, account_id: []const u8, out: *Binding) Error!bool {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "SELECT account_id, ap_actor, at_did, tenant FROM core_identity_map WHERE account_id = ?";
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.LookupFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, account_id.ptr, @intCast(account_id.len), c.sqliteTransientAsDestructor());
    if (c.sqlite3_step(stmt.?) != c.SQLITE_ROW) return false;
    readRow(stmt.?, out);
    return true;
}

pub fn lookupByApActor(db: *c.sqlite3, ap_actor: []const u8, out: *Binding) Error!bool {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "SELECT account_id, ap_actor, at_did, tenant FROM core_identity_map WHERE ap_actor = ?";
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.LookupFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, ap_actor.ptr, @intCast(ap_actor.len), c.sqliteTransientAsDestructor());
    if (c.sqlite3_step(stmt.?) != c.SQLITE_ROW) return false;
    readRow(stmt.?, out);
    return true;
}

pub fn lookupByAtDid(db: *c.sqlite3, at_did: []const u8, out: *Binding) Error!bool {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "SELECT account_id, ap_actor, at_did, tenant FROM core_identity_map WHERE at_did = ?";
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.LookupFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, at_did.ptr, @intCast(at_did.len), c.sqliteTransientAsDestructor());
    if (c.sqlite3_step(stmt.?) != c.SQLITE_ROW) return false;
    readRow(stmt.?, out);
    return true;
}

fn readRow(stmt: *c.sqlite3_stmt, out: *Binding) void {
    const fields = [_]struct { buf: []u8, len_ptr: *u8 }{
        .{ .buf = &out.account_id_buf, .len_ptr = &out.account_id_len },
    };
    _ = fields;
    // Field 0
    {
        const p = c.sqlite3_column_text(stmt, 0);
        const n: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
        const cap = @min(n, out.account_id_buf.len);
        @memcpy(out.account_id_buf[0..cap], p[0..cap]);
        out.account_id_len = @intCast(cap);
    }
    // Field 1 (ap_actor, u16 len)
    {
        const p = c.sqlite3_column_text(stmt, 1);
        const n: usize = @intCast(c.sqlite3_column_bytes(stmt, 1));
        const cap = @min(n, out.ap_actor_buf.len);
        @memcpy(out.ap_actor_buf[0..cap], p[0..cap]);
        out.ap_actor_len = @intCast(cap);
    }
    // Field 2 (at_did)
    {
        const p = c.sqlite3_column_text(stmt, 2);
        const n: usize = @intCast(c.sqlite3_column_bytes(stmt, 2));
        const cap = @min(n, out.at_did_buf.len);
        @memcpy(out.at_did_buf[0..cap], p[0..cap]);
        out.at_did_len = @intCast(cap);
    }
    // Field 3 (tenant)
    {
        const p = c.sqlite3_column_text(stmt, 3);
        const n: usize = @intCast(c.sqlite3_column_bytes(stmt, 3));
        const cap = @min(n, out.tenant_buf.len);
        @memcpy(out.tenant_buf[0..cap], p[0..cap]);
        out.tenant_len = @intCast(cap);
    }
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;
const sqlite = storage.sqlite;

fn setupDb() !*c.sqlite3 {
    const db = try sqlite.openWriter(":memory:");
    var em: [*c]u8 = null;
    const sql_z = try testing.allocator.dupeZ(u8, migration.up);
    defer testing.allocator.free(sql_z);
    _ = c.sqlite3_exec(db, sql_z.ptr, null, null, &em);
    if (em != null) c.sqlite3_free(em);
    return db;
}

test "DUAL-1: bind + lookup by account_id" {
    const db = try setupDb();
    defer sqlite.closeDb(db);
    try bind(db, "did:web:host/alice", "https://host/users/alice", "did:web:host/alice", "", 1);
    var b: Binding = .{};
    try testing.expect(try lookupByAccountId(db, "did:web:host/alice", &b));
    try testing.expectEqualStrings("https://host/users/alice", b.apActor());
    try testing.expectEqualStrings("did:web:host/alice", b.atDid());
}

test "DUAL-1: re-bind updates fields" {
    const db = try setupDb();
    defer sqlite.closeDb(db);
    try bind(db, "did:web:host/a", "https://host/users/a", "did:web:host/a", "", 1);
    try bind(db, "did:web:host/a", "https://host/users/a", "did:plc:abc", "tenant1", 2);
    var b: Binding = .{};
    _ = try lookupByAccountId(db, "did:web:host/a", &b);
    try testing.expectEqualStrings("did:plc:abc", b.atDid());
    try testing.expectEqualStrings("tenant1", b.tenant());
}

test "DUAL-4: lookup by AP actor + AT DID" {
    const db = try setupDb();
    defer sqlite.closeDb(db);
    try bind(db, "did:web:host/bob", "https://host/users/bob", "did:plc:bob", "", 1);

    var by_ap: Binding = .{};
    try testing.expect(try lookupByApActor(db, "https://host/users/bob", &by_ap));
    try testing.expectEqualStrings("did:web:host/bob", by_ap.accountId());

    var by_at: Binding = .{};
    try testing.expect(try lookupByAtDid(db, "did:plc:bob", &by_at));
    try testing.expectEqualStrings("did:web:host/bob", by_at.accountId());
}

test "DUAL-5: tenant column round-trips" {
    const db = try setupDb();
    defer sqlite.closeDb(db);
    try bind(db, "x", "https://h/u/x", "did:web:h/x", "tenantA", 1);
    var b: Binding = .{};
    _ = try lookupByAccountId(db, "x", &b);
    try testing.expectEqualStrings("tenantA", b.tenant());
}

test "DUAL: lookups return false on miss" {
    const db = try setupDb();
    defer sqlite.closeDb(db);
    var b: Binding = .{};
    try testing.expect(!try lookupByAccountId(db, "nope", &b));
    try testing.expect(!try lookupByApActor(db, "https://nowhere", &b));
    try testing.expect(!try lookupByAtDid(db, "did:plc:nope", &b));
}
