//! SqliteBackend — durable account store (AT-8/9/10/11). The production
//! default backing `core.account.Backend`.
//!
//! Split out of `account.zig` (which owns the vtable, the `Account`
//! projection, and the in-memory `MemoryBackend`) to keep each file
//! readable. Re-exported as `core.account.SqliteBackend` /
//! `core.account.sqlite_migration`.
//!
//! Wraps a single `*sqlite3` writer connection. The server handles each
//! accepted request to completion on one thread before the next starts
//! on the same handle (see `core/server.zig` D1/D2), so account
//! operations — all on request threads — never race the writer. Account
//! passwords are hashed with Argon2id (`core.crypto.argon2id`, configured
//! at boot); email / reset tokens and app passwords are high-entropy
//! random strings stored as SHA-256 hashes (same scheme as MemoryBackend).

const std = @import("std");
const sqlite_c = @import("sqlite").c;
const storage = @import("storage.zig");
const argon2id = @import("crypto/argon2id.zig");
const account = @import("account.zig");

const Account = account.Account;
const CreateArgs = account.CreateArgs;
const TokenIssued = account.TokenIssued;
const TokenKind = account.TokenKind;
const State = account.State;
const Error = account.Error;
const Backend = account.Backend;

/// Per-call salt counter so tight loops still get distinct salts even
/// when the wall clock hasn't advanced. Single-threaded request model
/// (one handler at a time on the writer connection) means no atomics.
var salt_counter: u64 = 0;

/// Fill `out` with a fresh 16-byte salt. Seeded from the realtime clock
/// XOR pid XOR a monotonic counter — same approach as
/// `account.MemoryBackend`'s salt path. The salt only needs to be
/// unique/unpredictable per hash; Argon2id provides the work factor.
fn genSalt(out: *[argon2id.salt_length]u8) void {
    salt_counter +%= 1;
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(@enumFromInt(@intFromEnum(std.c.CLOCK.REALTIME)), &ts);
    const wall_ns: i128 = @as(i128, ts.sec) * std.time.ns_per_s + @as(i128, ts.nsec);
    const pid: u64 = @intCast(std.c.getpid());
    const seed: u64 = @as(u64, @bitCast(@as(i64, @truncate(wall_ns)))) ^ (pid << 32) ^ salt_counter;
    var prng = std.Random.DefaultPrng.init(seed);
    prng.random().bytes(out);
}

/// Schema for the durable account tables. Register at boot alongside the
/// other core migrations (id namespace 9xxxxx, like `dual_identity`).
pub const sqlite_migration: storage.Migration = .{
    .id = 900_010,
    .name = "core:accounts",
    .up =
    \\CREATE TABLE IF NOT EXISTS atp_accounts (
    \\    id              TEXT PRIMARY KEY,
    \\    handle          TEXT NOT NULL UNIQUE,
    \\    email           TEXT NOT NULL DEFAULT '',
    \\    password_hash   TEXT NOT NULL,
    \\    state           TEXT NOT NULL DEFAULT 'active',
    \\    email_confirmed INTEGER NOT NULL DEFAULT 0,
    \\    created_at      INTEGER NOT NULL,
    \\    updated_at      INTEGER NOT NULL
    \\) STRICT;
    \\CREATE INDEX IF NOT EXISTS atp_accounts_email_idx ON atp_accounts (email);
    \\CREATE TABLE IF NOT EXISTS atp_email_tokens (
    \\    token_hash TEXT PRIMARY KEY,
    \\    account_id TEXT NOT NULL,
    \\    kind       TEXT NOT NULL,
    \\    expires_at INTEGER NOT NULL,
    \\    consumed   INTEGER NOT NULL DEFAULT 0
    \\) STRICT;
    \\CREATE INDEX IF NOT EXISTS atp_email_tokens_acct_idx ON atp_email_tokens (account_id);
    \\CREATE TABLE IF NOT EXISTS atp_app_passwords (
    \\    account_id    TEXT NOT NULL,
    \\    label         TEXT NOT NULL,
    \\    password_hash TEXT NOT NULL,
    \\    created_at    INTEGER NOT NULL,
    \\    PRIMARY KEY (account_id, label)
    \\) STRICT;
    \\CREATE TABLE IF NOT EXISTS atp_invites (
    \\    code       TEXT PRIMARY KEY,
    \\    created_by TEXT NOT NULL DEFAULT '',
    \\    max_uses   INTEGER NOT NULL DEFAULT 1,
    \\    uses       INTEGER NOT NULL DEFAULT 0,
    \\    disabled   INTEGER NOT NULL DEFAULT 0,
    \\    created_at INTEGER NOT NULL
    \\) STRICT;
    ,
    .down = "DROP TABLE atp_accounts; DROP TABLE atp_email_tokens; DROP TABLE atp_app_passwords; DROP TABLE atp_invites;",
};

pub const SqliteBackend = struct {
    db: *sqlite_c.sqlite3,

    pub fn init(db: *sqlite_c.sqlite3) SqliteBackend {
        return .{ .db = db };
    }

    // ── statement helpers ──────────────────────────────────────────
    fn bindText(stmt: ?*sqlite_c.sqlite3_stmt, idx: c_int, s: []const u8) void {
        _ = sqlite_c.sqlite3_bind_text(stmt, idx, s.ptr, @intCast(s.len), sqlite_c.sqliteTransientAsDestructor());
    }

    fn readText(stmt: ?*sqlite_c.sqlite3_stmt, col: c_int, buf: []u8) usize {
        const p = sqlite_c.sqlite3_column_text(stmt, col);
        const n: usize = @intCast(sqlite_c.sqlite3_column_bytes(stmt, col));
        const cap = @min(n, buf.len);
        if (cap > 0 and p != null) @memcpy(buf[0..cap], p[0..cap]);
        return cap;
    }

    fn rowExists(self: *SqliteBackend, sql: [:0]const u8, key: []const u8) Error!bool {
        var stmt: ?*sqlite_c.sqlite3_stmt = null;
        if (sqlite_c.sqlite3_prepare_v2(self.db, sql.ptr, -1, &stmt, null) != sqlite_c.SQLITE_OK) return error.BackendFailed;
        defer _ = sqlite_c.sqlite3_finalize(stmt);
        bindText(stmt, 1, key);
        return sqlite_c.sqlite3_step(stmt.?) == sqlite_c.SQLITE_ROW;
    }

    fn projectFromStmt(stmt: ?*sqlite_c.sqlite3_stmt, out: *Account) void {
        out.id_len = @intCast(readText(stmt, 0, &out.id_buf));
        out.handle_len = @intCast(readText(stmt, 1, &out.handle_buf));
        out.email_len = @intCast(readText(stmt, 2, &out.email_buf));
        var sbuf: [16]u8 = undefined;
        const sl = readText(stmt, 3, &sbuf);
        out.state = State.fromColumn(sbuf[0..sl]);
        out.email_confirmed = sqlite_c.sqlite3_column_int(stmt, 4) != 0;
        out.created_at_unix = sqlite_c.sqlite3_column_int64(stmt, 5);
    }

    fn lookupBy(self: *SqliteBackend, sql: [:0]const u8, key: []const u8, out: *Account) Error!bool {
        var stmt: ?*sqlite_c.sqlite3_stmt = null;
        if (sqlite_c.sqlite3_prepare_v2(self.db, sql.ptr, -1, &stmt, null) != sqlite_c.SQLITE_OK) return error.BackendFailed;
        defer _ = sqlite_c.sqlite3_finalize(stmt);
        bindText(stmt, 1, key);
        if (sqlite_c.sqlite3_step(stmt.?) != sqlite_c.SQLITE_ROW) return false;
        projectFromStmt(stmt, out);
        return true;
    }

    const select_cols = "SELECT id, handle, email, state, email_confirmed, created_at FROM atp_accounts WHERE ";

    // ── account lifecycle ──────────────────────────────────────────
    fn doCreate(ptr: *anyopaque, args: *const CreateArgs, now: i64) Error!void {
        const self: *SqliteBackend = @ptrCast(@alignCast(ptr));
        if (args.id.len == 0 or args.id.len > account.max_id_bytes) return error.InvalidArg;
        if (args.handle.len == 0 or args.handle.len > account.max_handle_bytes) return error.InvalidArg;
        if (args.email.len > account.max_email_bytes) return error.InvalidArg;
        if (args.password.len == 0 or args.password.len > account.max_password_bytes) return error.InvalidArg;

        if (try self.rowExists("SELECT 1 FROM atp_accounts WHERE id = ?", args.id)) return error.AlreadyExists;
        if (try self.rowExists("SELECT 1 FROM atp_accounts WHERE handle = ?", args.handle)) return error.AlreadyExists;

        var salt: [argon2id.salt_length]u8 = undefined;
        genSalt(&salt);
        var phc: [argon2id.max_phc_bytes]u8 = undefined;
        const encoded = argon2id.hashDefault(args.password, salt, &phc) catch return error.BackendFailed;

        var stmt: ?*sqlite_c.sqlite3_stmt = null;
        const sql =
            \\INSERT INTO atp_accounts (id, handle, email, password_hash, state, email_confirmed, created_at, updated_at)
            \\VALUES (?,?,?,?,'active',0,?,?)
        ;
        if (sqlite_c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null) != sqlite_c.SQLITE_OK) return error.BackendFailed;
        defer _ = sqlite_c.sqlite3_finalize(stmt);
        bindText(stmt, 1, args.id);
        bindText(stmt, 2, args.handle);
        bindText(stmt, 3, args.email);
        bindText(stmt, 4, encoded);
        _ = sqlite_c.sqlite3_bind_int64(stmt, 5, now);
        _ = sqlite_c.sqlite3_bind_int64(stmt, 6, now);
        if (sqlite_c.sqlite3_step(stmt.?) != sqlite_c.SQLITE_DONE) return error.AlreadyExists;
    }

    fn doLookupById(ptr: *anyopaque, id: []const u8, out: *Account) Error!bool {
        const self: *SqliteBackend = @ptrCast(@alignCast(ptr));
        return self.lookupBy(select_cols ++ "id = ?", id, out);
    }
    fn doLookupByHandle(ptr: *anyopaque, handle: []const u8, out: *Account) Error!bool {
        const self: *SqliteBackend = @ptrCast(@alignCast(ptr));
        return self.lookupBy(select_cols ++ "handle = ?", handle, out);
    }
    fn doLookupByEmail(ptr: *anyopaque, email: []const u8, out: *Account) Error!bool {
        const self: *SqliteBackend = @ptrCast(@alignCast(ptr));
        return self.lookupBy(select_cols ++ "email = ?", email, out);
    }

    fn doSetState(ptr: *anyopaque, id: []const u8, state: State, now: i64) Error!void {
        const self: *SqliteBackend = @ptrCast(@alignCast(ptr));
        var stmt: ?*sqlite_c.sqlite3_stmt = null;
        if (sqlite_c.sqlite3_prepare_v2(self.db, "UPDATE atp_accounts SET state = ?, updated_at = ? WHERE id = ?", -1, &stmt, null) != sqlite_c.SQLITE_OK) return error.BackendFailed;
        defer _ = sqlite_c.sqlite3_finalize(stmt);
        bindText(stmt, 1, state.columnString());
        _ = sqlite_c.sqlite3_bind_int64(stmt, 2, now);
        bindText(stmt, 3, id);
        if (sqlite_c.sqlite3_step(stmt.?) != sqlite_c.SQLITE_DONE) return error.BackendFailed;
        if (sqlite_c.sqlite3_changes(self.db) == 0) return error.NotFound;
    }

    fn doSetHandle(ptr: *anyopaque, id: []const u8, handle: []const u8, now: i64) Error!void {
        const self: *SqliteBackend = @ptrCast(@alignCast(ptr));
        if (handle.len == 0 or handle.len > account.max_handle_bytes) return error.InvalidArg;
        {
            var cstmt: ?*sqlite_c.sqlite3_stmt = null;
            if (sqlite_c.sqlite3_prepare_v2(self.db, "SELECT 1 FROM atp_accounts WHERE handle = ? AND id <> ?", -1, &cstmt, null) != sqlite_c.SQLITE_OK) return error.BackendFailed;
            defer _ = sqlite_c.sqlite3_finalize(cstmt);
            bindText(cstmt, 1, handle);
            bindText(cstmt, 2, id);
            if (sqlite_c.sqlite3_step(cstmt.?) == sqlite_c.SQLITE_ROW) return error.AlreadyExists;
        }
        var stmt: ?*sqlite_c.sqlite3_stmt = null;
        if (sqlite_c.sqlite3_prepare_v2(self.db, "UPDATE atp_accounts SET handle = ?, updated_at = ? WHERE id = ?", -1, &stmt, null) != sqlite_c.SQLITE_OK) return error.BackendFailed;
        defer _ = sqlite_c.sqlite3_finalize(stmt);
        bindText(stmt, 1, handle);
        _ = sqlite_c.sqlite3_bind_int64(stmt, 2, now);
        bindText(stmt, 3, id);
        if (sqlite_c.sqlite3_step(stmt.?) != sqlite_c.SQLITE_DONE) return error.BackendFailed;
        if (sqlite_c.sqlite3_changes(self.db) == 0) return error.NotFound;
    }

    fn doSetEmail(ptr: *anyopaque, id: []const u8, email: []const u8, now: i64) Error!void {
        const self: *SqliteBackend = @ptrCast(@alignCast(ptr));
        if (email.len > account.max_email_bytes) return error.InvalidArg;
        var stmt: ?*sqlite_c.sqlite3_stmt = null;
        if (sqlite_c.sqlite3_prepare_v2(self.db, "UPDATE atp_accounts SET email = ?, email_confirmed = 0, updated_at = ? WHERE id = ?", -1, &stmt, null) != sqlite_c.SQLITE_OK) return error.BackendFailed;
        defer _ = sqlite_c.sqlite3_finalize(stmt);
        bindText(stmt, 1, email);
        _ = sqlite_c.sqlite3_bind_int64(stmt, 2, now);
        bindText(stmt, 3, id);
        if (sqlite_c.sqlite3_step(stmt.?) != sqlite_c.SQLITE_DONE) return error.BackendFailed;
        if (sqlite_c.sqlite3_changes(self.db) == 0) return error.NotFound;
    }

    fn doMarkEmailConfirmed(ptr: *anyopaque, id: []const u8, now: i64) Error!void {
        const self: *SqliteBackend = @ptrCast(@alignCast(ptr));
        var stmt: ?*sqlite_c.sqlite3_stmt = null;
        if (sqlite_c.sqlite3_prepare_v2(self.db, "UPDATE atp_accounts SET email_confirmed = 1, updated_at = ? WHERE id = ?", -1, &stmt, null) != sqlite_c.SQLITE_OK) return error.BackendFailed;
        defer _ = sqlite_c.sqlite3_finalize(stmt);
        _ = sqlite_c.sqlite3_bind_int64(stmt, 1, now);
        bindText(stmt, 2, id);
        if (sqlite_c.sqlite3_step(stmt.?) != sqlite_c.SQLITE_DONE) return error.BackendFailed;
        if (sqlite_c.sqlite3_changes(self.db) == 0) return error.NotFound;
    }

    fn doVerifyPassword(ptr: *anyopaque, id: []const u8, password: []const u8) Error!bool {
        const self: *SqliteBackend = @ptrCast(@alignCast(ptr));
        var stmt: ?*sqlite_c.sqlite3_stmt = null;
        if (sqlite_c.sqlite3_prepare_v2(self.db, "SELECT password_hash FROM atp_accounts WHERE id = ?", -1, &stmt, null) != sqlite_c.SQLITE_OK) return error.BackendFailed;
        defer _ = sqlite_c.sqlite3_finalize(stmt);
        bindText(stmt, 1, id);
        if (sqlite_c.sqlite3_step(stmt.?) != sqlite_c.SQLITE_ROW) return error.NotFound;
        var hbuf: [argon2id.max_phc_bytes]u8 = undefined;
        const hlen = readText(stmt, 0, &hbuf);
        return argon2id.verifyDefault(password, hbuf[0..hlen]) catch |e| switch (e) {
            error.NotConfigured => error.BackendFailed,
            else => false,
        };
    }

    fn doUpdatePassword(ptr: *anyopaque, id: []const u8, new_password: []const u8, now: i64) Error!void {
        const self: *SqliteBackend = @ptrCast(@alignCast(ptr));
        if (new_password.len == 0 or new_password.len > account.max_password_bytes) return error.InvalidArg;
        var salt: [argon2id.salt_length]u8 = undefined;
        genSalt(&salt);
        var phc: [argon2id.max_phc_bytes]u8 = undefined;
        const encoded = argon2id.hashDefault(new_password, salt, &phc) catch return error.BackendFailed;
        var stmt: ?*sqlite_c.sqlite3_stmt = null;
        if (sqlite_c.sqlite3_prepare_v2(self.db, "UPDATE atp_accounts SET password_hash = ?, updated_at = ? WHERE id = ?", -1, &stmt, null) != sqlite_c.SQLITE_OK) return error.BackendFailed;
        defer _ = sqlite_c.sqlite3_finalize(stmt);
        bindText(stmt, 1, encoded);
        _ = sqlite_c.sqlite3_bind_int64(stmt, 2, now);
        bindText(stmt, 3, id);
        if (sqlite_c.sqlite3_step(stmt.?) != sqlite_c.SQLITE_DONE) return error.BackendFailed;
        if (sqlite_c.sqlite3_changes(self.db) == 0) return error.NotFound;
    }

    // ── tokens (email confirm + password reset) ────────────────────
    fn doIssueToken(
        ptr: *anyopaque,
        id: []const u8,
        kind: TokenKind,
        ttl_seconds: i64,
        now: i64,
        rng_seed: u64,
        out: *TokenIssued,
    ) Error!void {
        const self: *SqliteBackend = @ptrCast(@alignCast(ptr));
        account.mintToken(rng_seed, out);
        var hash: [64]u8 = undefined;
        account.hashTokenHex(out.token(), &hash);
        var stmt: ?*sqlite_c.sqlite3_stmt = null;
        if (sqlite_c.sqlite3_prepare_v2(self.db, "INSERT INTO atp_email_tokens (token_hash, account_id, kind, expires_at, consumed) VALUES (?,?,?,?,0)", -1, &stmt, null) != sqlite_c.SQLITE_OK) return error.BackendFailed;
        defer _ = sqlite_c.sqlite3_finalize(stmt);
        bindText(stmt, 1, hash[0..]);
        bindText(stmt, 2, id);
        bindText(stmt, 3, kind.columnString());
        _ = sqlite_c.sqlite3_bind_int64(stmt, 4, now + ttl_seconds);
        if (sqlite_c.sqlite3_step(stmt.?) != sqlite_c.SQLITE_DONE) return error.BackendFailed;
    }

    fn doRedeemToken(
        ptr: *anyopaque,
        kind: TokenKind,
        token: []const u8,
        now: i64,
        out_id: []u8,
    ) Error![]const u8 {
        const self: *SqliteBackend = @ptrCast(@alignCast(ptr));
        var hash: [64]u8 = undefined;
        account.hashTokenHex(token, &hash);

        var aid_len: usize = 0;
        {
            var stmt: ?*sqlite_c.sqlite3_stmt = null;
            if (sqlite_c.sqlite3_prepare_v2(self.db, "SELECT account_id, expires_at, consumed FROM atp_email_tokens WHERE token_hash = ? AND kind = ?", -1, &stmt, null) != sqlite_c.SQLITE_OK) return error.BackendFailed;
            defer _ = sqlite_c.sqlite3_finalize(stmt);
            bindText(stmt, 1, hash[0..]);
            bindText(stmt, 2, kind.columnString());
            if (sqlite_c.sqlite3_step(stmt.?) != sqlite_c.SQLITE_ROW) return error.NotFound;
            const aid_n: usize = @intCast(sqlite_c.sqlite3_column_bytes(stmt, 0));
            aid_len = readText(stmt, 0, out_id);
            if (aid_len < aid_n) return error.BackendFailed; // out_id too small
            const expires = sqlite_c.sqlite3_column_int64(stmt, 1);
            const consumed = sqlite_c.sqlite3_column_int(stmt, 2) != 0;
            if (consumed) return error.NotFound;
            if (expires < now) return error.Expired;
        }
        // Single-use: mark consumed so a replay misses.
        var ustmt: ?*sqlite_c.sqlite3_stmt = null;
        if (sqlite_c.sqlite3_prepare_v2(self.db, "UPDATE atp_email_tokens SET consumed = 1 WHERE token_hash = ?", -1, &ustmt, null) != sqlite_c.SQLITE_OK) return error.BackendFailed;
        defer _ = sqlite_c.sqlite3_finalize(ustmt);
        bindText(ustmt, 1, hash[0..]);
        if (sqlite_c.sqlite3_step(ustmt.?) != sqlite_c.SQLITE_DONE) return error.BackendFailed;
        return out_id[0..aid_len];
    }

    // ── app passwords ──────────────────────────────────────────────
    fn doCreateAppPassword(
        ptr: *anyopaque,
        id: []const u8,
        label: []const u8,
        now: i64,
        rng_seed: u64,
        out: *TokenIssued,
    ) Error!void {
        const self: *SqliteBackend = @ptrCast(@alignCast(ptr));
        if (label.len == 0 or label.len > 64) return error.InvalidArg;
        account.mintToken(rng_seed, out);
        var hash: [64]u8 = undefined;
        account.hashTokenHex(out.token(), &hash);
        var stmt: ?*sqlite_c.sqlite3_stmt = null;
        if (sqlite_c.sqlite3_prepare_v2(self.db, "INSERT INTO atp_app_passwords (account_id, label, password_hash, created_at) VALUES (?,?,?,?)", -1, &stmt, null) != sqlite_c.SQLITE_OK) return error.BackendFailed;
        defer _ = sqlite_c.sqlite3_finalize(stmt);
        bindText(stmt, 1, id);
        bindText(stmt, 2, label);
        bindText(stmt, 3, hash[0..]);
        _ = sqlite_c.sqlite3_bind_int64(stmt, 4, now);
        if (sqlite_c.sqlite3_step(stmt.?) != sqlite_c.SQLITE_DONE) return error.AlreadyExists;
    }

    fn doVerifyAppPassword(ptr: *anyopaque, id: []const u8, password: []const u8) Error!bool {
        const self: *SqliteBackend = @ptrCast(@alignCast(ptr));
        var hash: [64]u8 = undefined;
        account.hashTokenHex(password, &hash);
        var stmt: ?*sqlite_c.sqlite3_stmt = null;
        if (sqlite_c.sqlite3_prepare_v2(self.db, "SELECT 1 FROM atp_app_passwords WHERE account_id = ? AND password_hash = ?", -1, &stmt, null) != sqlite_c.SQLITE_OK) return error.BackendFailed;
        defer _ = sqlite_c.sqlite3_finalize(stmt);
        bindText(stmt, 1, id);
        bindText(stmt, 2, hash[0..]);
        return sqlite_c.sqlite3_step(stmt.?) == sqlite_c.SQLITE_ROW;
    }

    fn doRevokeAppPassword(ptr: *anyopaque, id: []const u8, label: []const u8) Error!void {
        const self: *SqliteBackend = @ptrCast(@alignCast(ptr));
        var stmt: ?*sqlite_c.sqlite3_stmt = null;
        if (sqlite_c.sqlite3_prepare_v2(self.db, "DELETE FROM atp_app_passwords WHERE account_id = ? AND label = ?", -1, &stmt, null) != sqlite_c.SQLITE_OK) return error.BackendFailed;
        defer _ = sqlite_c.sqlite3_finalize(stmt);
        bindText(stmt, 1, id);
        bindText(stmt, 2, label);
        if (sqlite_c.sqlite3_step(stmt.?) != sqlite_c.SQLITE_DONE) return error.BackendFailed;
        if (sqlite_c.sqlite3_changes(self.db) == 0) return error.NotFound;
    }

    // ── invites ────────────────────────────────────────────────────
    fn doIssueInvite(
        ptr: *anyopaque,
        code: []const u8,
        created_by: []const u8,
        max_uses: u32,
        now: i64,
    ) Error!void {
        const self: *SqliteBackend = @ptrCast(@alignCast(ptr));
        if (code.len == 0 or code.len > account.max_invite_bytes) return error.InvalidArg;
        if (try self.rowExists("SELECT 1 FROM atp_invites WHERE code = ?", code)) return error.AlreadyExists;
        var stmt: ?*sqlite_c.sqlite3_stmt = null;
        if (sqlite_c.sqlite3_prepare_v2(self.db, "INSERT INTO atp_invites (code, created_by, max_uses, uses, disabled, created_at) VALUES (?,?,?,0,0,?)", -1, &stmt, null) != sqlite_c.SQLITE_OK) return error.BackendFailed;
        defer _ = sqlite_c.sqlite3_finalize(stmt);
        bindText(stmt, 1, code);
        bindText(stmt, 2, created_by);
        _ = sqlite_c.sqlite3_bind_int64(stmt, 3, @intCast(max_uses));
        _ = sqlite_c.sqlite3_bind_int64(stmt, 4, now);
        if (sqlite_c.sqlite3_step(stmt.?) != sqlite_c.SQLITE_DONE) return error.AlreadyExists;
    }

    fn doConsumeInvite(ptr: *anyopaque, code: []const u8, _: i64) Error!bool {
        const self: *SqliteBackend = @ptrCast(@alignCast(ptr));
        {
            var stmt: ?*sqlite_c.sqlite3_stmt = null;
            if (sqlite_c.sqlite3_prepare_v2(self.db, "SELECT max_uses, uses, disabled FROM atp_invites WHERE code = ?", -1, &stmt, null) != sqlite_c.SQLITE_OK) return error.BackendFailed;
            defer _ = sqlite_c.sqlite3_finalize(stmt);
            bindText(stmt, 1, code);
            if (sqlite_c.sqlite3_step(stmt.?) != sqlite_c.SQLITE_ROW) return false;
            const max_uses = sqlite_c.sqlite3_column_int64(stmt, 0);
            const uses = sqlite_c.sqlite3_column_int64(stmt, 1);
            const disabled = sqlite_c.sqlite3_column_int(stmt, 2) != 0;
            if (disabled or uses >= max_uses) return false;
        }
        var ustmt: ?*sqlite_c.sqlite3_stmt = null;
        if (sqlite_c.sqlite3_prepare_v2(self.db, "UPDATE atp_invites SET uses = uses + 1 WHERE code = ?", -1, &ustmt, null) != sqlite_c.SQLITE_OK) return error.BackendFailed;
        defer _ = sqlite_c.sqlite3_finalize(ustmt);
        bindText(ustmt, 1, code);
        if (sqlite_c.sqlite3_step(ustmt.?) != sqlite_c.SQLITE_DONE) return error.BackendFailed;
        return true;
    }

    fn doDisableInvite(ptr: *anyopaque, code: []const u8) Error!void {
        const self: *SqliteBackend = @ptrCast(@alignCast(ptr));
        var stmt: ?*sqlite_c.sqlite3_stmt = null;
        if (sqlite_c.sqlite3_prepare_v2(self.db, "UPDATE atp_invites SET disabled = 1 WHERE code = ?", -1, &stmt, null) != sqlite_c.SQLITE_OK) return error.BackendFailed;
        defer _ = sqlite_c.sqlite3_finalize(stmt);
        bindText(stmt, 1, code);
        if (sqlite_c.sqlite3_step(stmt.?) != sqlite_c.SQLITE_DONE) return error.BackendFailed;
        if (sqlite_c.sqlite3_changes(self.db) == 0) return error.NotFound;
    }

    pub fn backend(self: *SqliteBackend) Backend {
        return .{
            .ptr = self,
            .vtable = &.{
                .create = doCreate,
                .lookupById = doLookupById,
                .lookupByHandle = doLookupByHandle,
                .lookupByEmail = doLookupByEmail,
                .setState = doSetState,
                .setHandle = doSetHandle,
                .setEmail = doSetEmail,
                .markEmailConfirmed = doMarkEmailConfirmed,
                .verifyPassword = doVerifyPassword,
                .updatePassword = doUpdatePassword,
                .issueToken = doIssueToken,
                .redeemToken = doRedeemToken,
                .createAppPassword = doCreateAppPassword,
                .verifyAppPassword = doVerifyAppPassword,
                .revokeAppPassword = doRevokeAppPassword,
                .issueInvite = doIssueInvite,
                .consumeInvite = doConsumeInvite,
                .disableInvite = doDisableInvite,
            },
        };
    }
};

// ──────────────────────────────────────────────────────────────────────
// Tests — durable, randomized, persistence-across-reopen.
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;
const sqlite = storage.sqlite;

/// Real `std.Io` for argon2id in tests (mirrors argon2id.zig's testIo).
fn acctTestIo() std.Io {
    const T = struct {
        var threaded: ?std.Io.Threaded = null;
    };
    if (T.threaded == null) T.threaded = std.Io.Threaded.init(testing.allocator, .{});
    return T.threaded.?.io();
}

fn applyAccountSchema(db: *sqlite_c.sqlite3) !void {
    const sql_z = try testing.allocator.dupeZ(u8, sqlite_migration.up);
    defer testing.allocator.free(sql_z);
    var em: [*c]u8 = null;
    _ = sqlite_c.sqlite3_exec(db, sql_z.ptr, null, null, &em);
    if (em != null) sqlite_c.sqlite3_free(em);
}

/// Remove a file DB and its WAL sidecars (best-effort). Uses libc
/// `unlink` directly — this Zig's `std.fs.cwd()` moved under the new
/// `Io` API and the repo's convention is to reach for `std.c` for
/// these one-off filesystem touches (see the media plugin).
fn cleanupDb(path: [:0]const u8) void {
    _ = std.c.unlink(path.ptr);
    var buf: [320]u8 = undefined;
    inline for (.{ "-wal", "-shm", "-journal" }) |suf| {
        const p = std.fmt.bufPrintZ(&buf, "{s}{s}", .{ path, suf }) catch return;
        _ = std.c.unlink(p.ptr);
    }
}

fn randHandle(rng: std.Random, buf: []u8) []const u8 {
    const n = 6 + rng.uintLessThan(usize, 8);
    var i: usize = 0;
    while (i < n) : (i += 1) buf[i] = 'a' + rng.uintLessThan(u8, 26);
    return buf[0..n];
}

test "SqliteBackend: create + lookup persists across reopen" {
    argon2id.configure(testing.allocator, acctTestIo());
    defer argon2id.resetForTests();

    // Unique per process: `zig build test` runs test binaries concurrently
    // and this file is compiled into more than one, so a shared path would
    // race (another process's `create` resets the row mid-test).
    var path_buf: [64]u8 = undefined;
    const db_path = std.fmt.bufPrintZ(&path_buf, "./.acct_persist_test.{d}.db", .{std.c.getpid()}) catch unreachable;
    cleanupDb(db_path);
    defer cleanupDb(db_path);

    var rng_state = std.Random.DefaultPrng.init(0xACC0_5EED_1234_BEEF);
    const rng = rng_state.random();
    var hbuf: [16]u8 = undefined;
    const handle = randHandle(rng, &hbuf);
    var idbuf: [64]u8 = undefined;
    const id = try std.fmt.bufPrint(&idbuf, "did:web:host/{s}", .{handle});
    var ebuf: [64]u8 = undefined;
    const email = try std.fmt.bufPrint(&ebuf, "{s}@example.test", .{handle});

    // First boot: create.
    {
        const db = try sqlite.openWriter(db_path);
        defer sqlite.closeDb(db);
        try applyAccountSchema(db);
        var be_state = SqliteBackend.init(db);
        const be = be_state.backend();
        try be.create(&.{ .id = id, .handle = handle, .email = email, .password = "correct horse" }, 1000);
        try testing.expect(try be.verifyPassword(id, "correct horse"));
        try testing.expect(!try be.verifyPassword(id, "wrong"));
    }

    // Second boot: the account is still there.
    {
        const db = try sqlite.openWriter(db_path);
        defer sqlite.closeDb(db);
        var be_state = SqliteBackend.init(db);
        const be = be_state.backend();
        var acc: Account = .{};
        try testing.expect(try be.lookupById(id, &acc));
        try testing.expectEqualStrings(handle, acc.handle());
        try testing.expectEqualStrings(email, acc.email());
        try testing.expectEqual(State.active, acc.state);
        try testing.expect(!acc.email_confirmed);
        try testing.expect(try be.verifyPassword(id, "correct horse"));

        var by_h: Account = .{};
        try testing.expect(try be.lookupByHandle(handle, &by_h));
        try testing.expectEqualStrings(id, by_h.id());
        var by_e: Account = .{};
        try testing.expect(try be.lookupByEmail(email, &by_e));
        try testing.expectEqualStrings(id, by_e.id());
    }
}

test "SqliteBackend: duplicate id + handle rejected" {
    argon2id.configure(testing.allocator, acctTestIo());
    defer argon2id.resetForTests();
    const db = try sqlite.openWriter(":memory:");
    defer sqlite.closeDb(db);
    try applyAccountSchema(db);
    var be_state = SqliteBackend.init(db);
    const be = be_state.backend();
    try be.create(&.{ .id = "a", .handle = "h1", .email = "e1@x", .password = "p" }, 1);
    try testing.expectError(error.AlreadyExists, be.create(&.{ .id = "a", .handle = "h2", .email = "e2@x", .password = "p" }, 1));
    try testing.expectError(error.AlreadyExists, be.create(&.{ .id = "b", .handle = "h1", .email = "e3@x", .password = "p" }, 1));
}

test "SqliteBackend: state transition persists across reopen" {
    argon2id.configure(testing.allocator, acctTestIo());
    defer argon2id.resetForTests();
    var path_buf: [64]u8 = undefined;
    const db_path = std.fmt.bufPrintZ(&path_buf, "./.acct_state_test.{d}.db", .{std.c.getpid()}) catch unreachable;
    cleanupDb(db_path);
    defer cleanupDb(db_path);

    {
        const db = try sqlite.openWriter(db_path);
        defer sqlite.closeDb(db);
        try applyAccountSchema(db);
        var be_state = SqliteBackend.init(db);
        const be = be_state.backend();
        try be.create(&.{ .id = "did:x", .handle = "user", .email = "u@x", .password = "p" }, 1);
        try be.setState("did:x", .deactivated, 2);
        try testing.expectError(error.NotFound, be.setState("did:missing", .takendown, 3));
    }
    {
        const db = try sqlite.openWriter(db_path);
        defer sqlite.closeDb(db);
        var be_state = SqliteBackend.init(db);
        const be = be_state.backend();
        var acc: Account = .{};
        _ = try be.lookupById("did:x", &acc);
        try testing.expectEqual(State.deactivated, acc.state);
    }
}

test "SqliteBackend: token issue + redeem (single-use, expiry, kind)" {
    argon2id.configure(testing.allocator, acctTestIo());
    defer argon2id.resetForTests();
    const db = try sqlite.openWriter(":memory:");
    defer sqlite.closeDb(db);
    try applyAccountSchema(db);
    var be_state = SqliteBackend.init(db);
    const be = be_state.backend();
    try be.create(&.{ .id = "acct1", .handle = "h", .email = "e@x", .password = "p" }, 1000);

    var tok: TokenIssued = .{};
    try be.issueToken("acct1", .email_confirm, 3600, 1000, 0xDEADBEEF, &tok);
    try testing.expectEqual(@as(u8, 64), tok.token_len);

    var out_id: [account.max_id_bytes]u8 = undefined;
    try testing.expectError(error.NotFound, be.redeemToken(.password_reset, tok.token(), 1500, &out_id));
    const redeemed = try be.redeemToken(.email_confirm, tok.token(), 1500, &out_id);
    try testing.expectEqualStrings("acct1", redeemed);
    try testing.expectError(error.NotFound, be.redeemToken(.email_confirm, tok.token(), 1500, &out_id));

    var tok2: TokenIssued = .{};
    try be.issueToken("acct1", .password_reset, 10, 1000, 0xC0FFEE, &tok2);
    try testing.expectError(error.Expired, be.redeemToken(.password_reset, tok2.token(), 9999, &out_id));
}

test "SqliteBackend: app password + invite flows" {
    argon2id.configure(testing.allocator, acctTestIo());
    defer argon2id.resetForTests();
    const db = try sqlite.openWriter(":memory:");
    defer sqlite.closeDb(db);
    try applyAccountSchema(db);
    var be_state = SqliteBackend.init(db);
    const be = be_state.backend();
    try be.create(&.{ .id = "acct1", .handle = "h", .email = "e@x", .password = "p" }, 1);

    var ap: TokenIssued = .{};
    try be.createAppPassword("acct1", "phone", 2, 0x1234, &ap);
    try testing.expect(try be.verifyAppPassword("acct1", ap.token()));
    try testing.expect(!try be.verifyAppPassword("acct1", "wrong"));
    try testing.expectError(error.AlreadyExists, be.createAppPassword("acct1", "phone", 3, 0x5678, &ap));
    try be.revokeAppPassword("acct1", "phone");
    try testing.expect(!try be.verifyAppPassword("acct1", ap.token()));

    try be.issueInvite("INVITE-1", "admin", 2, 100);
    try testing.expect(try be.consumeInvite("INVITE-1", 200));
    try testing.expect(try be.consumeInvite("INVITE-1", 300));
    try testing.expect(!try be.consumeInvite("INVITE-1", 400)); // exhausted
    try be.disableInvite("INVITE-1");
    try testing.expectError(error.AlreadyExists, be.issueInvite("INVITE-1", "admin", 1, 100));
    try testing.expect(!try be.consumeInvite("nonexistent", 500));
}
