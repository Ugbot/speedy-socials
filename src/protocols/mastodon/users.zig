//! Mastodon-local user store with Argon2id-hashed passwords.
//!
//! Why a dedicated table?
//! ====================
//! `ap_users` is owned by the ActivityPub plugin and addresses the
//! protocol-public identity (the actor row that other AP servers see).
//! Password material has no business living there — it's a Mastodon-
//! specific concept (clients log in over the Mastodon REST surface),
//! and mixing the two would force every plugin schema to know about
//! every other plugin's secrets.
//!
//! So `createUser` writes to `mastodon_users` (this module) AND
//! `ap_users` (the AP plugin's table), keeping handle parity but
//! isolating the credential. `verifyPassword` only ever reads from
//! `mastodon_users`.
//!
//! Tiger Style: caller-provided buffers; no allocator past Argon2id's
//! internal scratch. The argon2 working memory is owned by the
//! process-wide allocator captured by `core.crypto.argon2id.configure`
//! at boot — login is intentionally off the hot path so the brief
//! ~64 MiB lease is acceptable.

const std = @import("std");
const c = @import("sqlite").c;
const core = @import("core");

const argon2id = core.crypto.argon2id;

const Transient = c.sqliteTransientAsDestructor;

pub const Error = error{
    PrepareFailed,
    StepFailed,
    HandleTooLong,
    HashFailed,
    DuplicateHandle,
};

pub const max_handle_bytes: usize = 64;
pub const UserId = i64;

/// Create a Mastodon user account. Hashes `password` with Argon2id,
/// stores the PHC string in `mastodon_users`, and inserts a matching
/// `ap_users` row so the actor side of the world sees the same handle.
///
/// The matching `ap_users` insert is best-effort — if a row already
/// exists with this handle we leave it alone (idempotent across
/// re-runs of test fixtures that pre-seed AP rows).
pub fn createUser(
    db: *c.sqlite3,
    rng: *core.rng.Rng,
    clock: core.clock.Clock,
    handle: []const u8,
    password: []const u8,
) Error!UserId {
    if (handle.len == 0 or handle.len > max_handle_bytes) return error.HandleTooLong;

    var salt: [argon2id.salt_length]u8 = undefined;
    rng.random().bytes(&salt);

    var phc_buf: [argon2id.max_phc_bytes]u8 = undefined;
    const phc = argon2id.hashDefault(password, salt, &phc_buf) catch return error.HashFailed;

    const now = clock.wallUnix();

    // ap_users: keep handle parity with the AP plugin. If the row
    // already exists, we silently skip — the test fixtures sometimes
    // pre-seed it.
    {
        const sql =
            \\INSERT OR IGNORE INTO ap_users(username, display_name, bio, is_locked, discoverable, indexable, created_at)
            \\VALUES (?, ?, '', 0, 1, 1, ?)
        ;
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);
        _ = c.sqlite3_bind_text(stmt, 1, handle.ptr, @intCast(handle.len), Transient());
        _ = c.sqlite3_bind_text(stmt, 2, handle.ptr, @intCast(handle.len), Transient());
        _ = c.sqlite3_bind_int64(stmt, 3, now);
        if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return error.StepFailed;
    }

    const sql =
        \\INSERT INTO mastodon_users(handle, password_hash, created_at)
        \\VALUES (?, ?, ?)
    ;
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, handle.ptr, @intCast(handle.len), Transient());
    _ = c.sqlite3_bind_blob(stmt, 2, phc.ptr, @intCast(phc.len), Transient());
    _ = c.sqlite3_bind_int64(stmt, 3, now);
    const rc = c.sqlite3_step(stmt.?);
    if (rc != c.SQLITE_DONE) {
        // UNIQUE violation surfaces as SQLITE_CONSTRAINT (19).
        if (rc == c.SQLITE_CONSTRAINT) return error.DuplicateHandle;
        return error.StepFailed;
    }
    return c.sqlite3_last_insert_rowid(db);
}

/// Look up `handle` in `mastodon_users` and verify `password` against
/// the stored Argon2id PHC string. Returns false when the user does not
/// exist OR the password is wrong (both paths constant-time-ish via
/// Argon2id's verify; the lookup short-circuit leaks existence).
pub fn verifyPassword(
    db: *c.sqlite3,
    handle: []const u8,
    password: []const u8,
) bool {
    if (handle.len == 0 or handle.len > max_handle_bytes) return false;
    const sql = "SELECT password_hash FROM mastodon_users WHERE handle = ? LIMIT 1";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return false;
    }
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, handle.ptr, @intCast(handle.len), Transient());
    if (c.sqlite3_step(stmt.?) != c.SQLITE_ROW) return false;

    const ptr = c.sqlite3_column_blob(stmt.?, 0);
    const n: usize = @intCast(c.sqlite3_column_bytes(stmt.?, 0));
    if (n == 0 or n > argon2id.max_phc_bytes or ptr == null) return false;

    // Copy out of the prepared-stmt buffer so we don't depend on the
    // statement staying live past `finalize`.
    var hash_buf: [argon2id.max_phc_bytes]u8 = undefined;
    const p: [*]const u8 = @ptrCast(ptr);
    @memcpy(hash_buf[0..n], p[0..n]);
    return argon2id.verifyDefault(password, hash_buf[0..n]) catch false;
}

// ── tests ──────────────────────────────────────────────────────────

const testing = std.testing;
const schema_mod = @import("schema.zig");

fn setupDb() !*c.sqlite3 {
    const db = try core.storage.sqlite.openWriter(":memory:");
    try schema_mod.applyAllForTests(db);
    return db;
}

fn configureArgon() void {
    argon2id.resetForTests();
    const T = struct {
        var threaded: ?std.Io.Threaded = null;
    };
    if (T.threaded == null) T.threaded = std.Io.Threaded.init(testing.allocator, .{});
    argon2id.configure(testing.allocator, T.threaded.?.io());
}

test "users: createUser + verifyPassword round-trip" {
    configureArgon();
    defer argon2id.resetForTests();
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);

    var rng = core.rng.Rng.init(0xDEAD_BEEF);
    var sc = core.clock.SimClock.init(1_700_000_000);
    const id = try createUser(db, &rng, sc.clock(), "alice", "correct horse battery staple");
    try testing.expect(id > 0);

    try testing.expect(verifyPassword(db, "alice", "correct horse battery staple"));
    try testing.expect(!verifyPassword(db, "alice", "wrong"));
    try testing.expect(!verifyPassword(db, "nobody", "anything"));
}

test "users: duplicate handle returns DuplicateHandle" {
    configureArgon();
    defer argon2id.resetForTests();
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    var rng = core.rng.Rng.init(0xCAFE);
    var sc = core.clock.SimClock.init(1);
    _ = try createUser(db, &rng, sc.clock(), "bob", "pw1");
    try testing.expectError(error.DuplicateHandle, createUser(db, &rng, sc.clock(), "bob", "pw2"));
}

test "users: createUser propagates handle into ap_users" {
    configureArgon();
    defer argon2id.resetForTests();
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    var rng = core.rng.Rng.init(0x1234);
    var sc = core.clock.SimClock.init(2);
    _ = try createUser(db, &rng, sc.clock(), "carol", "hunter2");

    var stmt: ?*c.sqlite3_stmt = null;
    _ = c.sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM ap_users WHERE username = ?", -1, &stmt, null);
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, "carol", 5, Transient());
    try testing.expectEqual(@as(c_int, c.SQLITE_ROW), c.sqlite3_step(stmt.?));
    try testing.expectEqual(@as(i64, 1), c.sqlite3_column_int64(stmt.?, 0));
}

test "users: rejects oversized handle" {
    configureArgon();
    defer argon2id.resetForTests();
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    var rng = core.rng.Rng.init(1);
    var sc = core.clock.SimClock.init(0);
    var big: [max_handle_bytes + 1]u8 = undefined;
    @memset(&big, 'x');
    try testing.expectError(error.HandleTooLong, createUser(db, &rng, sc.clock(), &big, "x"));
    try testing.expect(!verifyPassword(db, &big, "x"));
}
