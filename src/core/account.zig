//! Account lifecycle — pluggable backend for the cross-protocol
//! user/account identity that both AP and AT need.
//!
//! Why core (not protocol-local): AT-8/9/10/11 + Mastodon's user
//! signup all need the same primitives — create, lookup, state
//! transitions, password verify, email verify-token issue/redeem,
//! app-password issue/revoke. Sharing the store via a `Backend`
//! vtable means a single signup mints one account that both
//! protocols anchor onto (eventually DUAL-1).
//!
//! Two impls land here:
//!   * `SqliteBackend` — wraps the existing `core.storage` channel +
//!                       per-thread readers. Default.
//!   * `MemoryBackend` — in-process; tests + future ephemeral mode.
//!
//! Postgres / FoundationDB drop in by implementing the same vtable.

const std = @import("std");
const sqlite_c = @import("sqlite").c;
const storage = @import("storage.zig");
const argon2id = @import("crypto/argon2id.zig");
const rng_mod = @import("rng.zig");
const clock_mod = @import("clock.zig");

pub const max_handle_bytes: usize = 253; // RFC 1035 hostname max
pub const max_email_bytes: usize = 320; // RFC 5321 max
pub const max_id_bytes: usize = 64;
pub const max_password_bytes: usize = 256;
pub const max_token_bytes: usize = 128;
pub const max_invite_bytes: usize = 64;
pub const max_app_pw_bytes: usize = 64;

pub const State = enum(u8) {
    active,
    deactivated,
    suspended,
    takendown,
    deleted,

    pub fn fromColumn(s: []const u8) State {
        if (std.mem.eql(u8, s, "deactivated")) return .deactivated;
        if (std.mem.eql(u8, s, "suspended")) return .suspended;
        if (std.mem.eql(u8, s, "takendown")) return .takendown;
        if (std.mem.eql(u8, s, "deleted")) return .deleted;
        return .active;
    }

    pub fn columnString(self: State) []const u8 {
        return switch (self) {
            .active => "active",
            .deactivated => "deactivated",
            .suspended => "suspended",
            .takendown => "takendown",
            .deleted => "deleted",
        };
    }
};

pub const Error = error{
    NotFound,
    AlreadyExists,
    InvalidArg,
    BackendFailed,
    PasswordMismatch,
    StateMismatch,
    Expired,
    OutOfMemory,
};

pub const TokenKind = enum(u8) {
    /// Email confirmation on signup or email update.
    email_confirm,
    /// Password reset.
    password_reset,

    pub fn columnString(self: TokenKind) []const u8 {
        return switch (self) {
            .email_confirm => "email_confirm",
            .password_reset => "password_reset",
        };
    }

    pub fn fromColumn(s: []const u8) ?TokenKind {
        if (std.mem.eql(u8, s, "email_confirm")) return .email_confirm;
        if (std.mem.eql(u8, s, "password_reset")) return .password_reset;
        return null;
    }
};

/// Public projection of one account row. Fixed-size — no allocator
/// on the lookup hot path.
pub const Account = struct {
    id_buf: [max_id_bytes]u8 = undefined,
    id_len: u8 = 0,
    handle_buf: [max_handle_bytes]u8 = undefined,
    handle_len: u8 = 0,
    email_buf: [max_email_bytes]u8 = undefined,
    email_len: u16 = 0,
    state: State = .active,
    email_confirmed: bool = false,
    created_at_unix: i64 = 0,

    pub fn id(self: *const Account) []const u8 {
        return self.id_buf[0..self.id_len];
    }
    pub fn handle(self: *const Account) []const u8 {
        return self.handle_buf[0..self.handle_len];
    }
    pub fn email(self: *const Account) []const u8 {
        return self.email_buf[0..self.email_len];
    }
};

pub const CreateArgs = struct {
    /// Stable identifier — typically the atproto DID (`did:plc:…`)
    /// or the AP actor URL. Caller supplies; this layer doesn't mint
    /// it (different protocols have different ID conventions).
    id: []const u8,
    handle: []const u8,
    email: []const u8,
    password: []const u8,
    invite_code: ?[]const u8 = null,
};

pub const TokenIssued = struct {
    /// The opaque random token string the caller should email to the
    /// user. NOT stored — only its hash is stored. Maximum
    /// `max_token_bytes` bytes.
    token_buf: [max_token_bytes]u8 = undefined,
    token_len: u8 = 0,

    pub fn token(self: *const TokenIssued) []const u8 {
        return self.token_buf[0..self.token_len];
    }
};

// ──────────────────────────────────────────────────────────────────────
// Backend vtable
// ──────────────────────────────────────────────────────────────────────

pub const Backend = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        // Account lifecycle
        create: *const fn (ptr: *anyopaque, args: *const CreateArgs, now: i64) Error!void,
        lookupById: *const fn (ptr: *anyopaque, id: []const u8, out: *Account) Error!bool,
        lookupByHandle: *const fn (ptr: *anyopaque, handle: []const u8, out: *Account) Error!bool,
        lookupByEmail: *const fn (ptr: *anyopaque, email: []const u8, out: *Account) Error!bool,
        setState: *const fn (ptr: *anyopaque, id: []const u8, state: State, now: i64) Error!void,
        setHandle: *const fn (ptr: *anyopaque, id: []const u8, handle: []const u8, now: i64) Error!void,
        setEmail: *const fn (ptr: *anyopaque, id: []const u8, email: []const u8, now: i64) Error!void,
        markEmailConfirmed: *const fn (ptr: *anyopaque, id: []const u8, now: i64) Error!void,
        verifyPassword: *const fn (ptr: *anyopaque, id: []const u8, password: []const u8) Error!bool,
        updatePassword: *const fn (ptr: *anyopaque, id: []const u8, new_password: []const u8, now: i64) Error!void,

        // Token issue / redeem (email confirm + password reset)
        issueToken: *const fn (
            ptr: *anyopaque,
            id: []const u8,
            kind: TokenKind,
            ttl_seconds: i64,
            now: i64,
            rng_seed: u64,
            out: *TokenIssued,
        ) Error!void,
        redeemToken: *const fn (
            ptr: *anyopaque,
            kind: TokenKind,
            token: []const u8,
            now: i64,
            out_id: []u8,
        ) Error![]const u8,

        // App passwords
        createAppPassword: *const fn (ptr: *anyopaque, id: []const u8, label: []const u8, now: i64, rng_seed: u64, out: *TokenIssued) Error!void,
        verifyAppPassword: *const fn (ptr: *anyopaque, id: []const u8, password: []const u8) Error!bool,
        revokeAppPassword: *const fn (ptr: *anyopaque, id: []const u8, label: []const u8) Error!void,

        // Invite codes
        issueInvite: *const fn (ptr: *anyopaque, code: []const u8, created_by: []const u8, max_uses: u32, now: i64) Error!void,
        consumeInvite: *const fn (ptr: *anyopaque, code: []const u8, now: i64) Error!bool,
        disableInvite: *const fn (ptr: *anyopaque, code: []const u8) Error!void,
    };

    // Thin pass-throughs.
    pub fn create(self: Backend, args: *const CreateArgs, now: i64) Error!void {
        return self.vtable.create(self.ptr, args, now);
    }
    pub fn lookupById(self: Backend, id: []const u8, out: *Account) Error!bool {
        return self.vtable.lookupById(self.ptr, id, out);
    }
    pub fn lookupByHandle(self: Backend, handle: []const u8, out: *Account) Error!bool {
        return self.vtable.lookupByHandle(self.ptr, handle, out);
    }
    pub fn lookupByEmail(self: Backend, email: []const u8, out: *Account) Error!bool {
        return self.vtable.lookupByEmail(self.ptr, email, out);
    }
    pub fn setState(self: Backend, id: []const u8, state: State, now: i64) Error!void {
        return self.vtable.setState(self.ptr, id, state, now);
    }
    pub fn setHandle(self: Backend, id: []const u8, handle: []const u8, now: i64) Error!void {
        return self.vtable.setHandle(self.ptr, id, handle, now);
    }
    pub fn setEmail(self: Backend, id: []const u8, email: []const u8, now: i64) Error!void {
        return self.vtable.setEmail(self.ptr, id, email, now);
    }
    pub fn markEmailConfirmed(self: Backend, id: []const u8, now: i64) Error!void {
        return self.vtable.markEmailConfirmed(self.ptr, id, now);
    }
    pub fn verifyPassword(self: Backend, id: []const u8, password: []const u8) Error!bool {
        return self.vtable.verifyPassword(self.ptr, id, password);
    }
    pub fn updatePassword(self: Backend, id: []const u8, new_password: []const u8, now: i64) Error!void {
        return self.vtable.updatePassword(self.ptr, id, new_password, now);
    }
    pub fn issueToken(
        self: Backend,
        id: []const u8,
        kind: TokenKind,
        ttl_seconds: i64,
        now: i64,
        rng_seed: u64,
        out: *TokenIssued,
    ) Error!void {
        return self.vtable.issueToken(self.ptr, id, kind, ttl_seconds, now, rng_seed, out);
    }
    pub fn redeemToken(
        self: Backend,
        kind: TokenKind,
        token: []const u8,
        now: i64,
        out_id: []u8,
    ) Error![]const u8 {
        return self.vtable.redeemToken(self.ptr, kind, token, now, out_id);
    }
    pub fn createAppPassword(
        self: Backend,
        id: []const u8,
        label: []const u8,
        now: i64,
        rng_seed: u64,
        out: *TokenIssued,
    ) Error!void {
        return self.vtable.createAppPassword(self.ptr, id, label, now, rng_seed, out);
    }
    pub fn verifyAppPassword(self: Backend, id: []const u8, password: []const u8) Error!bool {
        return self.vtable.verifyAppPassword(self.ptr, id, password);
    }
    pub fn revokeAppPassword(self: Backend, id: []const u8, label: []const u8) Error!void {
        return self.vtable.revokeAppPassword(self.ptr, id, label);
    }
    pub fn issueInvite(
        self: Backend,
        code: []const u8,
        created_by: []const u8,
        max_uses: u32,
        now: i64,
    ) Error!void {
        return self.vtable.issueInvite(self.ptr, code, created_by, max_uses, now);
    }
    pub fn consumeInvite(self: Backend, code: []const u8, now: i64) Error!bool {
        return self.vtable.consumeInvite(self.ptr, code, now);
    }
    pub fn disableInvite(self: Backend, code: []const u8) Error!void {
        return self.vtable.disableInvite(self.ptr, code);
    }
};

// ──────────────────────────────────────────────────────────────────────
// Module-level singleton.
// ──────────────────────────────────────────────────────────────────────

var global_backend: ?Backend = null;

pub fn setGlobal(b: Backend) void {
    global_backend = b;
}

pub fn global() ?Backend {
    return global_backend;
}

pub fn resetGlobal() void {
    global_backend = null;
}

// ──────────────────────────────────────────────────────────────────────
// Token helpers — shared between backends.
// ──────────────────────────────────────────────────────────────────────

/// 32-byte random token rendered as 64 lowercase hex chars.
pub fn mintToken(seed: u64, out: *TokenIssued) void {
    var prng = std.Random.DefaultPrng.init(seed);
    var bytes: [32]u8 = undefined;
    prng.random().bytes(&bytes);
    const hex = "0123456789abcdef";
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        out.token_buf[i * 2] = hex[bytes[i] >> 4];
        out.token_buf[i * 2 + 1] = hex[bytes[i] & 0xF];
    }
    out.token_len = 64;
}

/// SHA-256 hash of the token, hex-encoded (64 chars). Stored instead
/// of the plaintext so a DB compromise doesn't yield active tokens.
pub fn hashTokenHex(token: []const u8, out: *[64]u8) void {
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(token, &h, .{});
    const hex = "0123456789abcdef";
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        out[i * 2] = hex[h[i] >> 4];
        out[i * 2 + 1] = hex[h[i] & 0xF];
    }
}

// ──────────────────────────────────────────────────────────────────────
// MemoryBackend — bounded in-process maps for tests.
// ──────────────────────────────────────────────────────────────────────

pub const MemoryBackend = struct {
    pub const max_accounts: usize = 256;
    pub const max_tokens: usize = 256;
    pub const max_app_passwords: usize = 256;
    pub const max_invites: usize = 64;

    const Row = struct {
        id_buf: [max_id_bytes]u8 = undefined,
        id_len: u8 = 0,
        handle_buf: [max_handle_bytes]u8 = undefined,
        handle_len: u8 = 0,
        email_buf: [max_email_bytes]u8 = undefined,
        email_len: u16 = 0,
        password_hash_buf: [256]u8 = undefined,
        password_hash_len: u16 = 0,
        state: State = .active,
        email_confirmed: bool = false,
        created_at_unix: i64 = 0,
        updated_at_unix: i64 = 0,

        fn id(self: *const Row) []const u8 {
            return self.id_buf[0..self.id_len];
        }
        fn handle(self: *const Row) []const u8 {
            return self.handle_buf[0..self.handle_len];
        }
        fn email(self: *const Row) []const u8 {
            return self.email_buf[0..self.email_len];
        }
    };

    const TokenRow = struct {
        account_id_buf: [max_id_bytes]u8 = undefined,
        account_id_len: u8 = 0,
        token_hash: [64]u8 = undefined,
        kind: TokenKind = .email_confirm,
        expires_at_unix: i64 = 0,
        consumed: bool = false,

        fn accountId(self: *const TokenRow) []const u8 {
            return self.account_id_buf[0..self.account_id_len];
        }
    };

    const AppPasswordRow = struct {
        account_id_buf: [max_id_bytes]u8 = undefined,
        account_id_len: u8 = 0,
        label_buf: [64]u8 = undefined,
        label_len: u8 = 0,
        password_hash: [64]u8 = undefined,

        fn accountId(self: *const AppPasswordRow) []const u8 {
            return self.account_id_buf[0..self.account_id_len];
        }
        fn label(self: *const AppPasswordRow) []const u8 {
            return self.label_buf[0..self.label_len];
        }
    };

    const InviteRow = struct {
        code_buf: [max_invite_bytes]u8 = undefined,
        code_len: u8 = 0,
        max_uses: u32 = 1,
        uses: u32 = 0,
        disabled: bool = false,
        created_by_buf: [max_id_bytes]u8 = undefined,
        created_by_len: u8 = 0,

        fn code(self: *const InviteRow) []const u8 {
            return self.code_buf[0..self.code_len];
        }
    };

    rows: [max_accounts]Row = undefined,
    row_count: u16 = 0,
    tokens: [max_tokens]TokenRow = undefined,
    token_count: u16 = 0,
    app_passwords: [max_app_passwords]AppPasswordRow = undefined,
    app_password_count: u16 = 0,
    invites: [max_invites]InviteRow = undefined,
    invite_count: u16 = 0,

    pub fn init() MemoryBackend {
        return .{};
    }

    fn findRowById(self: *MemoryBackend, id: []const u8) ?*Row {
        var i: usize = 0;
        while (i < self.row_count) : (i += 1) {
            if (std.mem.eql(u8, self.rows[i].id(), id)) return &self.rows[i];
        }
        return null;
    }

    fn projectAccount(row: *const Row, out: *Account) void {
        @memcpy(out.id_buf[0..row.id_len], row.id_buf[0..row.id_len]);
        out.id_len = row.id_len;
        @memcpy(out.handle_buf[0..row.handle_len], row.handle_buf[0..row.handle_len]);
        out.handle_len = row.handle_len;
        @memcpy(out.email_buf[0..row.email_len], row.email_buf[0..row.email_len]);
        out.email_len = row.email_len;
        out.state = row.state;
        out.email_confirmed = row.email_confirmed;
        out.created_at_unix = row.created_at_unix;
    }

    fn doCreate(ptr: *anyopaque, args: *const CreateArgs, now: i64) Error!void {
        const self: *MemoryBackend = @ptrCast(@alignCast(ptr));
        if (args.id.len == 0 or args.id.len > max_id_bytes) return error.InvalidArg;
        if (args.handle.len == 0 or args.handle.len > max_handle_bytes) return error.InvalidArg;
        if (args.email.len > max_email_bytes) return error.InvalidArg;
        if (args.password.len == 0 or args.password.len > max_password_bytes) return error.InvalidArg;
        if (self.findRowById(args.id)) |_| return error.AlreadyExists;
        if (self.row_count >= max_accounts) return error.BackendFailed;
        // Also reject duplicate handle.
        var i: usize = 0;
        while (i < self.row_count) : (i += 1) {
            if (std.mem.eql(u8, self.rows[i].handle(), args.handle)) return error.AlreadyExists;
        }

        var row: Row = .{
            .state = .active,
            .email_confirmed = false,
            .created_at_unix = now,
            .updated_at_unix = now,
        };
        @memcpy(row.id_buf[0..args.id.len], args.id);
        row.id_len = @intCast(args.id.len);
        @memcpy(row.handle_buf[0..args.handle.len], args.handle);
        row.handle_len = @intCast(args.handle.len);
        @memcpy(row.email_buf[0..args.email.len], args.email);
        row.email_len = @intCast(args.email.len);
        const hash = hashPassword(args.password, &row.password_hash_buf) catch return error.BackendFailed;
        row.password_hash_len = @intCast(hash.len);

        self.rows[self.row_count] = row;
        self.row_count += 1;
    }

    fn doLookupById(ptr: *anyopaque, id: []const u8, out: *Account) Error!bool {
        const self: *MemoryBackend = @ptrCast(@alignCast(ptr));
        const row = self.findRowById(id) orelse return false;
        projectAccount(row, out);
        return true;
    }

    fn doLookupByHandle(ptr: *anyopaque, handle: []const u8, out: *Account) Error!bool {
        const self: *MemoryBackend = @ptrCast(@alignCast(ptr));
        var i: usize = 0;
        while (i < self.row_count) : (i += 1) {
            if (std.mem.eql(u8, self.rows[i].handle(), handle)) {
                projectAccount(&self.rows[i], out);
                return true;
            }
        }
        return false;
    }

    fn doLookupByEmail(ptr: *anyopaque, email: []const u8, out: *Account) Error!bool {
        const self: *MemoryBackend = @ptrCast(@alignCast(ptr));
        var i: usize = 0;
        while (i < self.row_count) : (i += 1) {
            if (std.mem.eql(u8, self.rows[i].email(), email)) {
                projectAccount(&self.rows[i], out);
                return true;
            }
        }
        return false;
    }

    fn doSetState(ptr: *anyopaque, id: []const u8, state: State, now: i64) Error!void {
        const self: *MemoryBackend = @ptrCast(@alignCast(ptr));
        const row = self.findRowById(id) orelse return error.NotFound;
        row.state = state;
        row.updated_at_unix = now;
    }

    fn doSetHandle(ptr: *anyopaque, id: []const u8, handle: []const u8, now: i64) Error!void {
        const self: *MemoryBackend = @ptrCast(@alignCast(ptr));
        if (handle.len == 0 or handle.len > max_handle_bytes) return error.InvalidArg;
        // Reject if another account already has this handle.
        var i: usize = 0;
        while (i < self.row_count) : (i += 1) {
            if (std.mem.eql(u8, self.rows[i].handle(), handle) and !std.mem.eql(u8, self.rows[i].id(), id)) {
                return error.AlreadyExists;
            }
        }
        const row = self.findRowById(id) orelse return error.NotFound;
        @memcpy(row.handle_buf[0..handle.len], handle);
        row.handle_len = @intCast(handle.len);
        row.updated_at_unix = now;
    }

    fn doSetEmail(ptr: *anyopaque, id: []const u8, email: []const u8, now: i64) Error!void {
        const self: *MemoryBackend = @ptrCast(@alignCast(ptr));
        if (email.len > max_email_bytes) return error.InvalidArg;
        const row = self.findRowById(id) orelse return error.NotFound;
        @memcpy(row.email_buf[0..email.len], email);
        row.email_len = @intCast(email.len);
        // Changing email un-confirms it.
        row.email_confirmed = false;
        row.updated_at_unix = now;
    }

    fn doMarkEmailConfirmed(ptr: *anyopaque, id: []const u8, now: i64) Error!void {
        const self: *MemoryBackend = @ptrCast(@alignCast(ptr));
        const row = self.findRowById(id) orelse return error.NotFound;
        row.email_confirmed = true;
        row.updated_at_unix = now;
    }

    fn doVerifyPassword(ptr: *anyopaque, id: []const u8, password: []const u8) Error!bool {
        const self: *MemoryBackend = @ptrCast(@alignCast(ptr));
        const row = self.findRowById(id) orelse return error.NotFound;
        return verifyPasswordHash(row.password_hash_buf[0..row.password_hash_len], password);
    }

    fn doUpdatePassword(ptr: *anyopaque, id: []const u8, new_password: []const u8, now: i64) Error!void {
        const self: *MemoryBackend = @ptrCast(@alignCast(ptr));
        if (new_password.len == 0 or new_password.len > max_password_bytes) return error.InvalidArg;
        const row = self.findRowById(id) orelse return error.NotFound;
        const hash = hashPassword(new_password, &row.password_hash_buf) catch return error.BackendFailed;
        row.password_hash_len = @intCast(hash.len);
        row.updated_at_unix = now;
    }

    fn doIssueToken(
        ptr: *anyopaque,
        id: []const u8,
        kind: TokenKind,
        ttl_seconds: i64,
        now: i64,
        rng_seed: u64,
        out: *TokenIssued,
    ) Error!void {
        const self: *MemoryBackend = @ptrCast(@alignCast(ptr));
        if (self.token_count >= max_tokens) {
            // Evict the oldest token.
            self.tokens[0] = self.tokens[self.token_count - 1];
            self.token_count -= 1;
        }
        mintToken(rng_seed, out);
        var hash: [64]u8 = undefined;
        hashTokenHex(out.token(), &hash);

        var row: TokenRow = .{
            .kind = kind,
            .expires_at_unix = now + ttl_seconds,
        };
        @memcpy(row.account_id_buf[0..id.len], id);
        row.account_id_len = @intCast(id.len);
        @memcpy(&row.token_hash, &hash);

        self.tokens[self.token_count] = row;
        self.token_count += 1;
    }

    fn doRedeemToken(
        ptr: *anyopaque,
        kind: TokenKind,
        token: []const u8,
        now: i64,
        out_id: []u8,
    ) Error![]const u8 {
        const self: *MemoryBackend = @ptrCast(@alignCast(ptr));
        var hash: [64]u8 = undefined;
        hashTokenHex(token, &hash);
        var i: usize = 0;
        while (i < self.token_count) : (i += 1) {
            const t = &self.tokens[i];
            if (t.consumed) continue;
            if (t.kind != kind) continue;
            if (!std.mem.eql(u8, &t.token_hash, &hash)) continue;
            if (t.expires_at_unix < now) return error.Expired;
            t.consumed = true;
            const aid = t.accountId();
            if (out_id.len < aid.len) return error.BackendFailed;
            @memcpy(out_id[0..aid.len], aid);
            return out_id[0..aid.len];
        }
        return error.NotFound;
    }

    fn doCreateAppPassword(
        ptr: *anyopaque,
        id: []const u8,
        label: []const u8,
        _: i64,
        rng_seed: u64,
        out: *TokenIssued,
    ) Error!void {
        const self: *MemoryBackend = @ptrCast(@alignCast(ptr));
        if (label.len == 0 or label.len > 64) return error.InvalidArg;
        if (self.app_password_count >= max_app_passwords) return error.BackendFailed;
        // Reject same (id, label) pair.
        var i: usize = 0;
        while (i < self.app_password_count) : (i += 1) {
            if (std.mem.eql(u8, self.app_passwords[i].accountId(), id) and
                std.mem.eql(u8, self.app_passwords[i].label(), label))
            {
                return error.AlreadyExists;
            }
        }
        mintToken(rng_seed, out);
        var row: AppPasswordRow = .{};
        @memcpy(row.account_id_buf[0..id.len], id);
        row.account_id_len = @intCast(id.len);
        @memcpy(row.label_buf[0..label.len], label);
        row.label_len = @intCast(label.len);
        hashTokenHex(out.token(), &row.password_hash);
        self.app_passwords[self.app_password_count] = row;
        self.app_password_count += 1;
    }

    fn doVerifyAppPassword(ptr: *anyopaque, id: []const u8, password: []const u8) Error!bool {
        const self: *MemoryBackend = @ptrCast(@alignCast(ptr));
        var hash: [64]u8 = undefined;
        hashTokenHex(password, &hash);
        var i: usize = 0;
        while (i < self.app_password_count) : (i += 1) {
            if (std.mem.eql(u8, self.app_passwords[i].accountId(), id) and
                std.mem.eql(u8, &self.app_passwords[i].password_hash, &hash))
            {
                return true;
            }
        }
        return false;
    }

    fn doRevokeAppPassword(ptr: *anyopaque, id: []const u8, label: []const u8) Error!void {
        const self: *MemoryBackend = @ptrCast(@alignCast(ptr));
        var i: usize = 0;
        while (i < self.app_password_count) : (i += 1) {
            if (std.mem.eql(u8, self.app_passwords[i].accountId(), id) and
                std.mem.eql(u8, self.app_passwords[i].label(), label))
            {
                const last = self.app_password_count - 1;
                if (i != last) self.app_passwords[i] = self.app_passwords[last];
                self.app_password_count = last;
                return;
            }
        }
        return error.NotFound;
    }

    fn findInvite(self: *MemoryBackend, code: []const u8) ?*InviteRow {
        var i: usize = 0;
        while (i < self.invite_count) : (i += 1) {
            if (std.mem.eql(u8, self.invites[i].code(), code)) return &self.invites[i];
        }
        return null;
    }

    fn doIssueInvite(
        ptr: *anyopaque,
        code: []const u8,
        created_by: []const u8,
        max_uses: u32,
        _: i64,
    ) Error!void {
        const self: *MemoryBackend = @ptrCast(@alignCast(ptr));
        if (code.len == 0 or code.len > max_invite_bytes) return error.InvalidArg;
        if (self.findInvite(code)) |_| return error.AlreadyExists;
        if (self.invite_count >= max_invites) return error.BackendFailed;
        var row: InviteRow = .{ .max_uses = max_uses };
        @memcpy(row.code_buf[0..code.len], code);
        row.code_len = @intCast(code.len);
        @memcpy(row.created_by_buf[0..created_by.len], created_by);
        row.created_by_len = @intCast(created_by.len);
        self.invites[self.invite_count] = row;
        self.invite_count += 1;
    }

    fn doConsumeInvite(ptr: *anyopaque, code: []const u8, _: i64) Error!bool {
        const self: *MemoryBackend = @ptrCast(@alignCast(ptr));
        const inv = self.findInvite(code) orelse return false;
        if (inv.disabled) return false;
        if (inv.uses >= inv.max_uses) return false;
        inv.uses += 1;
        return true;
    }

    fn doDisableInvite(ptr: *anyopaque, code: []const u8) Error!void {
        const self: *MemoryBackend = @ptrCast(@alignCast(ptr));
        const inv = self.findInvite(code) orelse return error.NotFound;
        inv.disabled = true;
    }

    pub fn backend(self: *MemoryBackend) Backend {
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
// Password hashing — MemoryBackend uses a fast placeholder
// (salted-sha256 hex). Production SqliteBackend (sibling file) uses
// real Argon2id via `core.crypto.argon2id`. The placeholder is
// deliberately weak — it's only for in-memory tests and an "ephemeral
// node" mode where there is no DB to compromise; it MUST NOT be used
// for any user-facing password storage in production.
// ──────────────────────────────────────────────────────────────────────

const placeholder_prefix = "sha256-test:";
var salt_counter: u64 = 0;

fn hashPassword(password: []const u8, out: []u8) ![]const u8 {
    // MemoryBackend is test-only; we don't need a CSPRNG for salt
    // generation. Seed a Xoshiro256 from the monotonic clock + a
    // call counter so even tight loops get fresh salts. The real
    // production backend (SqliteBackend, follow-up) hashes via
    // `core.crypto.argon2id` and salts via `core.crypto.openssl`.
    salt_counter += 1;
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(@enumFromInt(@intFromEnum(std.c.CLOCK.REALTIME)), &ts);
    const wall_ns: i128 = @as(i128, ts.sec) * std.time.ns_per_s + @as(i128, ts.nsec);
    const seed: u64 = @bitCast(@as(i64, @truncate(wall_ns)) ^ @as(i64, @intCast(salt_counter)));
    var prng = std.Random.DefaultPrng.init(seed);
    var salt: [16]u8 = undefined;
    prng.random().bytes(&salt);
    var h: [32]u8 = undefined;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(&salt);
    hasher.update(password);
    hasher.final(&h);

    const hex = "0123456789abcdef";
    const total = placeholder_prefix.len + 32 + 64;
    if (out.len < total) return error.BufferTooSmall;
    @memcpy(out[0..placeholder_prefix.len], placeholder_prefix);
    var pos: usize = placeholder_prefix.len;
    // 16-byte salt → 32 hex chars
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        out[pos] = hex[salt[i] >> 4];
        out[pos + 1] = hex[salt[i] & 0xF];
        pos += 2;
    }
    // 32-byte hash → 64 hex chars
    i = 0;
    while (i < 32) : (i += 1) {
        out[pos] = hex[h[i] >> 4];
        out[pos + 1] = hex[h[i] & 0xF];
        pos += 2;
    }
    return out[0..pos];
}

fn verifyPasswordHash(stored: []const u8, password: []const u8) bool {
    if (!std.mem.startsWith(u8, stored, placeholder_prefix)) return false;
    const rest = stored[placeholder_prefix.len..];
    if (rest.len != 32 + 64) return false;
    var salt: [16]u8 = undefined;
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        const hi = hexNybble(rest[i * 2]) orelse return false;
        const lo = hexNybble(rest[i * 2 + 1]) orelse return false;
        salt[i] = (hi << 4) | lo;
    }
    var h: [32]u8 = undefined;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(&salt);
    hasher.update(password);
    hasher.final(&h);

    var diff: u8 = 0;
    i = 0;
    while (i < 32) : (i += 1) {
        const hi = hexNybble(rest[32 + i * 2]) orelse return false;
        const lo = hexNybble(rest[32 + i * 2 + 1]) orelse return false;
        const got = (hi << 4) | lo;
        diff |= got ^ h[i];
    }
    return diff == 0;
}

fn hexNybble(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "MemoryBackend: create + lookup by id/handle/email" {
    var m = MemoryBackend.init();
    const be = m.backend();
    try be.create(&.{
        .id = "did:plc:alice",
        .handle = "alice.example",
        .email = "alice@example.com",
        .password = "hunter2",
    }, 1000);

    var acc: Account = .{};
    try testing.expect(try be.lookupById("did:plc:alice", &acc));
    try testing.expectEqualStrings("alice.example", acc.handle());
    try testing.expectEqualStrings("alice@example.com", acc.email());
    try testing.expectEqual(State.active, acc.state);
    try testing.expect(!acc.email_confirmed);

    var acc2: Account = .{};
    try testing.expect(try be.lookupByHandle("alice.example", &acc2));
    try testing.expectEqualStrings("did:plc:alice", acc2.id());

    var acc3: Account = .{};
    try testing.expect(try be.lookupByEmail("alice@example.com", &acc3));
    try testing.expectEqualStrings("did:plc:alice", acc3.id());

    var miss: Account = .{};
    try testing.expect(!(try be.lookupById("did:plc:nobody", &miss)));
}

test "MemoryBackend: duplicate id rejected" {
    var m = MemoryBackend.init();
    const be = m.backend();
    try be.create(&.{ .id = "a", .handle = "h1", .email = "e1", .password = "p" }, 1);
    try testing.expectError(error.AlreadyExists, be.create(&.{ .id = "a", .handle = "h2", .email = "e2", .password = "p" }, 1));
}

test "MemoryBackend: duplicate handle rejected" {
    var m = MemoryBackend.init();
    const be = m.backend();
    try be.create(&.{ .id = "a", .handle = "h", .email = "e1", .password = "p" }, 1);
    try testing.expectError(error.AlreadyExists, be.create(&.{ .id = "b", .handle = "h", .email = "e2", .password = "p" }, 1));
}

test "MemoryBackend: verifyPassword returns true on correct password" {
    var m = MemoryBackend.init();
    const be = m.backend();
    try be.create(&.{ .id = "a", .handle = "h", .email = "e", .password = "correct" }, 1);
    try testing.expect(try be.verifyPassword("a", "correct"));
    try testing.expect(!try be.verifyPassword("a", "wrong"));
}

test "MemoryBackend: updatePassword changes verification" {
    var m = MemoryBackend.init();
    const be = m.backend();
    try be.create(&.{ .id = "a", .handle = "h", .email = "e", .password = "old" }, 1);
    try be.updatePassword("a", "new", 2);
    try testing.expect(!try be.verifyPassword("a", "old"));
    try testing.expect(try be.verifyPassword("a", "new"));
}

test "MemoryBackend: setState transitions" {
    var m = MemoryBackend.init();
    const be = m.backend();
    try be.create(&.{ .id = "a", .handle = "h", .email = "e", .password = "p" }, 1);
    try be.setState("a", .deactivated, 2);
    var acc: Account = .{};
    _ = try be.lookupById("a", &acc);
    try testing.expectEqual(State.deactivated, acc.state);
    try be.setState("a", .takendown, 3);
    _ = try be.lookupById("a", &acc);
    try testing.expectEqual(State.takendown, acc.state);
}

test "MemoryBackend: setHandle rejects collision" {
    var m = MemoryBackend.init();
    const be = m.backend();
    try be.create(&.{ .id = "a", .handle = "h1", .email = "e1", .password = "p" }, 1);
    try be.create(&.{ .id = "b", .handle = "h2", .email = "e2", .password = "p" }, 1);
    try testing.expectError(error.AlreadyExists, be.setHandle("a", "h2", 2));
    try be.setHandle("a", "h3", 2);
    var acc: Account = .{};
    _ = try be.lookupById("a", &acc);
    try testing.expectEqualStrings("h3", acc.handle());
}

test "MemoryBackend: setEmail clears email_confirmed" {
    var m = MemoryBackend.init();
    const be = m.backend();
    try be.create(&.{ .id = "a", .handle = "h", .email = "old@e", .password = "p" }, 1);
    try be.markEmailConfirmed("a", 2);
    var acc: Account = .{};
    _ = try be.lookupById("a", &acc);
    try testing.expect(acc.email_confirmed);
    try be.setEmail("a", "new@e", 3);
    _ = try be.lookupById("a", &acc);
    try testing.expect(!acc.email_confirmed);
}

test "MemoryBackend: token issue + redeem" {
    var m = MemoryBackend.init();
    const be = m.backend();
    try be.create(&.{ .id = "a", .handle = "h", .email = "e", .password = "p" }, 1000);
    var tok: TokenIssued = .{};
    try be.issueToken("a", .email_confirm, 3600, 1000, 0xDEADBEEF, &tok);
    try testing.expectEqual(@as(u8, 64), tok.token_len);

    var out_id: [max_id_bytes]u8 = undefined;
    const redeemed = try be.redeemToken(.email_confirm, tok.token(), 2000, &out_id);
    try testing.expectEqualStrings("a", redeemed);
}

test "MemoryBackend: token redeem fails after expiry" {
    var m = MemoryBackend.init();
    const be = m.backend();
    try be.create(&.{ .id = "a", .handle = "h", .email = "e", .password = "p" }, 1000);
    var tok: TokenIssued = .{};
    try be.issueToken("a", .password_reset, 10, 1000, 0xC0FFEE, &tok);
    var out_id: [max_id_bytes]u8 = undefined;
    try testing.expectError(error.Expired, be.redeemToken(.password_reset, tok.token(), 9999, &out_id));
}

test "MemoryBackend: token redeem fails on wrong kind" {
    var m = MemoryBackend.init();
    const be = m.backend();
    try be.create(&.{ .id = "a", .handle = "h", .email = "e", .password = "p" }, 1000);
    var tok: TokenIssued = .{};
    try be.issueToken("a", .email_confirm, 3600, 1000, 0xFEED, &tok);
    var out_id: [max_id_bytes]u8 = undefined;
    try testing.expectError(error.NotFound, be.redeemToken(.password_reset, tok.token(), 1500, &out_id));
}

test "MemoryBackend: token can only be redeemed once" {
    var m = MemoryBackend.init();
    const be = m.backend();
    try be.create(&.{ .id = "a", .handle = "h", .email = "e", .password = "p" }, 1000);
    var tok: TokenIssued = .{};
    try be.issueToken("a", .email_confirm, 3600, 1000, 0x42, &tok);
    var out_id: [max_id_bytes]u8 = undefined;
    _ = try be.redeemToken(.email_confirm, tok.token(), 1500, &out_id);
    try testing.expectError(error.NotFound, be.redeemToken(.email_confirm, tok.token(), 1500, &out_id));
}

test "MemoryBackend: app password create + verify + revoke" {
    var m = MemoryBackend.init();
    const be = m.backend();
    try be.create(&.{ .id = "a", .handle = "h", .email = "e", .password = "p" }, 1);
    var tok: TokenIssued = .{};
    try be.createAppPassword("a", "phone-app", 2, 0x1234, &tok);
    try testing.expect(try be.verifyAppPassword("a", tok.token()));
    try testing.expect(!try be.verifyAppPassword("a", "wrong"));
    try be.revokeAppPassword("a", "phone-app");
    try testing.expect(!try be.verifyAppPassword("a", tok.token()));
}

test "MemoryBackend: invite issue + consume + disable" {
    var m = MemoryBackend.init();
    const be = m.backend();
    try be.issueInvite("INVITE-XYZ", "admin", 2, 100);
    try testing.expect(try be.consumeInvite("INVITE-XYZ", 200));
    try testing.expect(try be.consumeInvite("INVITE-XYZ", 300));
    try testing.expect(!try be.consumeInvite("INVITE-XYZ", 400));
    try be.disableInvite("INVITE-XYZ");
    try be.issueInvite("ANOTHER", "admin", 5, 100);
    try be.disableInvite("ANOTHER");
    try testing.expect(!try be.consumeInvite("ANOTHER", 200));
}

test "mintToken produces 64-char hex" {
    var t: TokenIssued = .{};
    mintToken(0x12345678, &t);
    try testing.expectEqual(@as(u8, 64), t.token_len);
    for (t.token()) |b| {
        try testing.expect((b >= '0' and b <= '9') or (b >= 'a' and b <= 'f'));
    }
}

test "mintToken deterministic from same seed" {
    var t1: TokenIssued = .{};
    var t2: TokenIssued = .{};
    mintToken(0xDEADBEEF, &t1);
    mintToken(0xDEADBEEF, &t2);
    try testing.expectEqualStrings(t1.token(), t2.token());
}

test "global backend set/get/reset" {
    resetGlobal();
    try testing.expect(global() == null);
    var m = MemoryBackend.init();
    setGlobal(m.backend());
    try testing.expect(global() != null);
    resetGlobal();
}

// Imports kept reachable for the SqliteBackend sibling file that lands
// in a follow-up; reference them via `comptime` so they don't trip
// the unused-import check.
comptime {
    _ = sqlite_c;
    _ = storage;
    _ = argon2id;
    _ = rng_mod;
    _ = clock_mod;
}
