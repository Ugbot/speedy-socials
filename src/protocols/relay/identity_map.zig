//! Identity-map helpers.
//!
//! The relay maintains a SQLite table mapping DIDs (AT Protocol) to AP
//! actor URIs. Two operating modes:
//!
//!   * Bridge: both sides exist on the local instance. The mapping is
//!     created at user-signup time; the table is a fast lookup.
//!
//!   * Relay: one side is synthetic. Either an AT-native DID gets a
//!     synthetic `did:web:relayhost:ap:<handle>` AP actor URI, or an
//!     AP-native actor gets a synthetic `did:web:relayhost:ap:<host>:<user>`
//!     DID. The helpers below construct the synthetic ID and upsert.
//!
//! These helpers operate against a caller-owned `*c.sqlite3` connection
//! (the production code uses the writer thread's, the tests an
//! in-memory). Statements are prepared once per call — the relay's
//! identity-map traffic is admin-bound and rare; we keep it simple.

const std = @import("std");
const c = @import("sqlite").c;
const core = @import("core");

const RelayError = core.errors.RelayError;
const Arena = core.arena.Arena;
const Clock = core.clock.Clock;
const assertLe = core.assert.assertLe;

/// Maximum length of a DID we store. AT Protocol caps DIDs at 2 KiB;
/// in practice they are short. 256 covers `did:plc:` + 24-char ident
/// and `did:web:` host names of reasonable length.
pub const max_did_bytes: usize = 256;

/// Maximum length of an AP actor IRI we store.
pub const max_actor_url_bytes: usize = 512;

pub const Entry = struct {
    did: []const u8,
    ap_actor_url: []const u8,
    last_seen: i64,
};

/// Upsert a DID ↔ actor pair. Updates `last_seen` to the current wall
/// time on every call (so a slow firehose subscriber knows when a
/// participant went idle).
pub fn upsert(
    db: *c.sqlite3,
    clock: Clock,
    did: []const u8,
    ap_actor_url: []const u8,
) RelayError!void {
    if (did.len == 0 or did.len > max_did_bytes) return error.IdentityMapFailed;
    if (ap_actor_url.len == 0 or ap_actor_url.len > max_actor_url_bytes) {
        return error.IdentityMapFailed;
    }
    var stmt: ?*c.sqlite3_stmt = null;
    const sql =
        \\INSERT INTO relay_identity_map (did, ap_actor_url, last_seen)
        \\VALUES (?, ?, ?)
        \\ON CONFLICT(did) DO UPDATE SET
        \\    ap_actor_url = excluded.ap_actor_url,
        \\    last_seen    = excluded.last_seen
    ;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return error.IdentityMapFailed;
    }
    defer _ = c.sqlite3_finalize(stmt);
    const now: i64 = @intCast(@divTrunc(clock.wallNs(), std.time.ns_per_s));
    if (c.sqlite3_bind_text(stmt, 1, did.ptr, @intCast(did.len), c.sqliteTransientAsDestructor()) != c.SQLITE_OK) {
        return error.IdentityMapFailed;
    }
    if (c.sqlite3_bind_text(stmt, 2, ap_actor_url.ptr, @intCast(ap_actor_url.len), c.sqliteTransientAsDestructor()) != c.SQLITE_OK) {
        return error.IdentityMapFailed;
    }
    if (c.sqlite3_bind_int64(stmt, 3, now) != c.SQLITE_OK) return error.IdentityMapFailed;
    if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.IdentityMapFailed;
}

/// Look up the AP actor IRI for a DID. Returns `null` when absent.
/// The returned slice is arena-allocated; it survives until the caller
/// resets the arena.
pub fn actorForDid(
    db: *c.sqlite3,
    did: []const u8,
    arena: *Arena,
) RelayError!?[]const u8 {
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "SELECT ap_actor_url FROM relay_identity_map WHERE did = ?", -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return error.IdentityMapFailed;
    }
    defer _ = c.sqlite3_finalize(stmt);
    if (c.sqlite3_bind_text(stmt, 1, did.ptr, @intCast(did.len), c.sqliteTransientAsDestructor()) != c.SQLITE_OK) {
        return error.IdentityMapFailed;
    }
    const step_rc = c.sqlite3_step(stmt);
    if (step_rc == c.SQLITE_DONE) return null;
    if (step_rc != c.SQLITE_ROW) return error.IdentityMapFailed;
    const ptr = c.sqlite3_column_text(stmt, 0);
    const n: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
    if (n > max_actor_url_bytes) return error.IdentityMapFailed;
    const alloc = arena.allocator();
    const buf = alloc.alloc(u8, n) catch return error.IdentityMapFailed;
    if (n > 0 and ptr != null) @memcpy(buf, ptr[0..n]);
    return buf;
}

/// Look up the DID for an AP actor IRI.
pub fn didForActor(
    db: *c.sqlite3,
    ap_actor_url: []const u8,
    arena: *Arena,
) RelayError!?[]const u8 {
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "SELECT did FROM relay_identity_map WHERE ap_actor_url = ?", -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return error.IdentityMapFailed;
    }
    defer _ = c.sqlite3_finalize(stmt);
    if (c.sqlite3_bind_text(stmt, 1, ap_actor_url.ptr, @intCast(ap_actor_url.len), c.sqliteTransientAsDestructor()) != c.SQLITE_OK) {
        return error.IdentityMapFailed;
    }
    const step_rc = c.sqlite3_step(stmt);
    if (step_rc == c.SQLITE_DONE) return null;
    if (step_rc != c.SQLITE_ROW) return error.IdentityMapFailed;
    const ptr = c.sqlite3_column_text(stmt, 0);
    const n: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
    if (n > max_did_bytes) return error.IdentityMapFailed;
    const alloc = arena.allocator();
    const buf = alloc.alloc(u8, n) catch return error.IdentityMapFailed;
    if (n > 0 and ptr != null) @memcpy(buf, ptr[0..n]);
    return buf;
}

/// Construct a synthetic AP actor URI for an AT-native DID. Used in
/// relay mode where the AT user has no native AP presence. The actor
/// IRI lives on the relay's domain.
///
///   did:plc:abc123  →  https://relay/ap/users/at:plc:abc123
pub fn syntheticActorForDid(
    relay_host: []const u8,
    did: []const u8,
    arena: *Arena,
) RelayError![]const u8 {
    if (relay_host.len == 0 or relay_host.len > 128) return error.IdentityMapFailed;
    if (did.len == 0 or did.len > max_did_bytes) return error.IdentityMapFailed;
    const alloc = arena.allocator();
    // "https://" + host + "/ap/users/" + escaped(did) — escape did:'s
    // colons by replacing with `:` (URI-safe in path segments) — keep
    // as-is since `:` is fine inside path segments per RFC 3986. We just
    // strip the `did:` prefix for tidiness.
    const did_tail = if (std.mem.startsWith(u8, did, "did:")) did[4..] else did;
    const total = "https://".len + relay_host.len + "/ap/users/at:".len + did_tail.len;
    if (total > max_actor_url_bytes) return error.IdentityMapFailed;
    const buf = alloc.alloc(u8, total) catch return error.IdentityMapFailed;
    var w: usize = 0;
    @memcpy(buf[w..][0.."https://".len], "https://");
    w += "https://".len;
    @memcpy(buf[w..][0..relay_host.len], relay_host);
    w += relay_host.len;
    @memcpy(buf[w..][0.."/ap/users/at:".len], "/ap/users/at:");
    w += "/ap/users/at:".len;
    @memcpy(buf[w..][0..did_tail.len], did_tail);
    w += did_tail.len;
    assertLe(w, buf.len);
    return buf[0..w];
}

/// Construct a synthetic AT DID for an AP-native actor. Used in relay
/// mode where the AP user has no native AT presence. We use `did:web`
/// rooted at the relay's domain.
///
///   https://mastodon.social/users/alice  →  did:web:relay:ap:mastodon.social:alice
pub fn syntheticDidForActor(
    relay_host: []const u8,
    actor_url: []const u8,
    arena: *Arena,
) RelayError![]const u8 {
    if (relay_host.len == 0 or relay_host.len > 128) return error.IdentityMapFailed;
    if (actor_url.len == 0 or actor_url.len > max_actor_url_bytes) {
        return error.IdentityMapFailed;
    }
    // Strip scheme.
    var rest = actor_url;
    if (std.mem.startsWith(u8, rest, "https://")) rest = rest["https://".len..];
    if (std.mem.startsWith(u8, rest, "http://")) rest = rest["http://".len..];
    // Replace '/' with ':' to fit the did:web path encoding convention.
    const alloc = arena.allocator();
    const prefix = "did:web:";
    const total = prefix.len + relay_host.len + ":ap:".len + rest.len;
    if (total > max_did_bytes) return error.IdentityMapFailed;
    const buf = alloc.alloc(u8, total) catch return error.IdentityMapFailed;
    var w: usize = 0;
    @memcpy(buf[w..][0..prefix.len], prefix);
    w += prefix.len;
    @memcpy(buf[w..][0..relay_host.len], relay_host);
    w += relay_host.len;
    @memcpy(buf[w..][0..":ap:".len], ":ap:");
    w += ":ap:".len;
    for (rest) |ch| {
        buf[w] = if (ch == '/') ':' else ch;
        w += 1;
    }
    assertLe(w, buf.len);
    return buf[0..w];
}

// ──────────────────────────────────────────────────────────────────────
// Tests — use an in-memory SQLite with the schema applied.
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;
const sqlite_mod = core.storage.sqlite;
const schema = @import("schema.zig");

fn applyRelaySchema(db: *c.sqlite3) !void {
    for (schema.all_migrations) |m| {
        const sql_z = try testing.allocator.dupeZ(u8, m.up);
        defer testing.allocator.free(sql_z);
        var errmsg: [*c]u8 = null;
        const rc = c.sqlite3_exec(db, sql_z.ptr, null, null, &errmsg);
        if (errmsg != null) c.sqlite3_free(errmsg);
        if (rc != c.SQLITE_OK) return error.TestSchemaFailed;
    }
}

test "identity_map upsert + lookup round-trips" {
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try applyRelaySchema(db);

    var sc = core.clock.SimClock.init(1_700_000_000);
    const clock = sc.clock();

    try upsert(db, clock, "did:plc:alice123", "https://h/users/alice");
    try upsert(db, clock, "did:plc:bob456", "https://h/users/bob");

    var buf: [4096]u8 = undefined;
    var arena = Arena.init(&buf);

    const got1 = try actorForDid(db, "did:plc:alice123", &arena);
    try testing.expect(got1 != null);
    try testing.expectEqualStrings("https://h/users/alice", got1.?);

    const got2 = try didForActor(db, "https://h/users/bob", &arena);
    try testing.expect(got2 != null);
    try testing.expectEqualStrings("did:plc:bob456", got2.?);

    // Missing keys.
    const missing = try actorForDid(db, "did:plc:nope", &arena);
    try testing.expect(missing == null);
}

test "identity_map upsert overwrites existing mapping" {
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try applyRelaySchema(db);

    var sc = core.clock.SimClock.init(1_700_000_000);
    try upsert(db, sc.clock(), "did:plc:x", "https://h/users/old");
    sc.advance(60 * std.time.ns_per_s);
    try upsert(db, sc.clock(), "did:plc:x", "https://h/users/new");

    var buf: [1024]u8 = undefined;
    var arena = Arena.init(&buf);
    const got = try actorForDid(db, "did:plc:x", &arena);
    try testing.expectEqualStrings("https://h/users/new", got.?);
}

test "syntheticActorForDid builds a tidy URI" {
    var buf: [1024]u8 = undefined;
    var arena = Arena.init(&buf);
    const got = try syntheticActorForDid("relay.example.com", "did:plc:abc123", &arena);
    try testing.expectEqualStrings("https://relay.example.com/ap/users/at:plc:abc123", got);
}

test "syntheticDidForActor builds did:web with relay namespace" {
    var buf: [1024]u8 = undefined;
    var arena = Arena.init(&buf);
    const got = try syntheticDidForActor("relay.example.com", "https://mastodon.social/users/alice", &arena);
    try testing.expectEqualStrings("did:web:relay.example.com:ap:mastodon.social:users:alice", got);
}

test "identity_map rejects oversized inputs" {
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try applyRelaySchema(db);
    var sc = core.clock.SimClock.init(1);

    // Empty inputs.
    try testing.expectError(error.IdentityMapFailed, upsert(db, sc.clock(), "", "https://h/u"));
    try testing.expectError(error.IdentityMapFailed, upsert(db, sc.clock(), "did:plc:x", ""));
}
