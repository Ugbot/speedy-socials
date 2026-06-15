//! DUAL-1: provision a local ActivityPub actor.
//!
//! A unified signup (driven by the AT Protocol `createAccount` handler)
//! calls `provisionLocalUser` so the same identity exists on both
//! networks: this creates the `ap_users` row + an Ed25519 keypair stored
//! in `ap_actor_keys`, so the AP actor IRI the identity map binds to
//! actually resolves and can sign/verify federation traffic.
//!
//! Wired into the AT plugin via a hook set in the composition root
//! (`main.zig`) — the plugins don't import each other directly.

const std = @import("std");
const c = @import("sqlite").c;
const core = @import("core");
const ed25519 = core.crypto.ed25519;
const keys = @import("keys.zig");

pub const Error = error{ Provision, Encode };

/// RFC 8410 PKCS#8 PrivateKeyInfo prefix for an Ed25519 key. The 32-byte
/// seed follows at offset 16 — exactly what `http_delivery.extractEd25519Seed`
/// expects on the signing path.
const pkcs8_ed25519_prefix = [16]u8{
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
    0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
};

var seed_counter: u64 = 0;

/// Non-deterministic 32-byte seed (clock + pid + counter → Xoshiro),
/// matching the entropy approach used elsewhere in-tree. The derived
/// private key is *stored*, never re-derived, so this only needs to be
/// unpredictable at generation time for a self-hosted node.
fn genSeed() [32]u8 {
    seed_counter +%= 1;
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(@enumFromInt(@intFromEnum(std.c.CLOCK.REALTIME)), &ts);
    const wall_ns: i128 = @as(i128, ts.sec) * std.time.ns_per_s + @as(i128, ts.nsec);
    const pid: u64 = @intCast(std.c.getpid());
    const s: u64 = @as(u64, @bitCast(@as(i64, @truncate(wall_ns)))) ^ (pid << 32) ^ seed_counter;
    var prng = std.Random.DefaultPrng.init(s);
    var seed: [32]u8 = undefined;
    prng.random().bytes(&seed);
    return seed;
}

fn userExists(db: *c.sqlite3, username: []const u8) bool {
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "SELECT 1 FROM ap_users WHERE username = ?", -1, &stmt, null) != c.SQLITE_OK) return false;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, username.ptr, @intCast(username.len), c.sqliteTransientAsDestructor());
    return c.sqlite3_step(stmt.?) == c.SQLITE_ROW;
}

/// Provision a local AP user + Ed25519 actor key. Idempotent: a no-op
/// if `username` already has an `ap_users` row.
pub fn provisionLocalUser(db: *c.sqlite3, username: []const u8, now: i64) anyerror!void {
    if (userExists(db, username)) return;

    // 1. Insert the user row.
    {
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db, "INSERT INTO ap_users(username, display_name, bio, is_locked, discoverable, indexable, created_at) VALUES (?,?,'',0,1,1,?)", -1, &stmt, null) != c.SQLITE_OK) return error.Provision;
        defer _ = c.sqlite3_finalize(stmt);
        _ = c.sqlite3_bind_text(stmt, 1, username.ptr, @intCast(username.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_text(stmt, 2, username.ptr, @intCast(username.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_int64(stmt, 3, now);
        if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return error.Provision;
    }
    const actor_id = c.sqlite3_last_insert_rowid(db);

    // 2. Generate the keypair.
    const seed = genSeed();
    const kp = ed25519.fromSeed(seed) catch return error.Encode;

    var pub_pem_buf: [256]u8 = undefined;
    const pub_pem_len = keys.writeEd25519PublicPem(kp.public_key, &pub_pem_buf) catch return error.Encode;
    const pub_pem = pub_pem_buf[0..pub_pem_len];

    // 3. Build the PKCS#8 private PEM (prefix || seed → DER → base64 → PEM).
    var der: [48]u8 = undefined;
    @memcpy(der[0..16], &pkcs8_ed25519_prefix);
    @memcpy(der[16..48], &seed);
    var b64_buf: [80]u8 = undefined;
    const b64 = std.base64.standard.Encoder.encode(&b64_buf, &der);
    var priv_pem_buf: [256]u8 = undefined;
    const priv_pem = std.fmt.bufPrint(&priv_pem_buf, "-----BEGIN PRIVATE KEY-----\n{s}\n-----END PRIVATE KEY-----", .{b64}) catch return error.Encode;

    // 4. Store the key.
    {
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db, "INSERT INTO ap_actor_keys(actor_id, key_type, public_pem, private_pem, created_at) VALUES (?, 'ed25519', ?, ?, ?)", -1, &stmt, null) != c.SQLITE_OK) return error.Provision;
        defer _ = c.sqlite3_finalize(stmt);
        _ = c.sqlite3_bind_int64(stmt, 1, actor_id);
        _ = c.sqlite3_bind_text(stmt, 2, pub_pem.ptr, @intCast(pub_pem.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_blob(stmt, 3, priv_pem.ptr, @intCast(priv_pem.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_int64(stmt, 4, now);
        if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return error.Provision;
    }
}

// ── Tests ──────────────────────────────────────────────────────────

const testing = std.testing;
const http_delivery = @import("http_delivery.zig");

test "DUAL-1: provisionLocalUser creates a resolvable, signable AP actor" {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try @import("schema.zig").applyAllForTests(db);

    try provisionLocalUser(db, "alice", 1000);

    // The signing path can load + parse the stored private key (proves
    // the PKCS#8 PEM round-trips with extractEd25519Seed).
    var loaded: http_delivery.LoadedPrivateKey = .{ .algo = .ed25519 };
    try http_delivery.loadActorPrivateKey(db, "alice", &loaded);
    const seed = try http_delivery.extractEd25519Seed(loaded.bytes[0..loaded.len]);
    const kp = try ed25519.fromSeed(seed);

    // The recovered public key signs + verifies a message.
    const msg = "federation-test";
    const sig = ed25519.sign(kp.secret_key, msg);
    try testing.expect(ed25519.verify(kp.public_key, msg, sig));

    // Idempotent: a second call is a no-op (no duplicate-key error).
    try provisionLocalUser(db, "alice", 1001);
}
