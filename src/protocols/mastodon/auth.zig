//! Bearer-token authentication for the Mastodon API.
//!
//! Tokens are Ed25519 JWTs whose `jti` claim is persisted in
//! `mastodon_tokens`. Verification flow:
//!   1. Parse `Authorization: Bearer <jwt>`.
//!   2. Verify the JWT signature with the module's `jwt_key`.
//!   3. Look up the `jti` in `mastodon_tokens`; reject if revoked.
//!
//! Returns the decoded `Claims` so handlers can apply scope checks.

const std = @import("std");
const core = @import("core");
const c = @import("sqlite").c;
const HandlerContext = core.http.router.HandlerContext;

const state_mod = @import("state.zig");
const jwt = @import("jwt.zig");
const http_util = @import("http_util.zig");

pub const AuthOutcome = union(enum) {
    ok: jwt.Claims,
    missing,
    invalid,
    expired,
    revoked,
};

pub fn authenticate(hc: *const HandlerContext) AuthOutcome {
    const st = state_mod.get();
    const token = http_util.bearerToken(hc) orelse return .missing;
    const now = st.clock.wallUnix();

    var claims: jwt.Claims = .{};
    jwt.verify(token, st.jwt_key.public_key, now, &claims) catch |err| {
        return switch (err) {
            error.Expired => .expired,
            else => .invalid,
        };
    };

    if (st.db) |db| {
        if (isRevoked(db, claims.jti())) return .revoked;
    }
    return .{ .ok = claims };
}

pub fn isRevoked(db: *c.sqlite3, jti: []const u8) bool {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "SELECT revoked FROM mastodon_tokens WHERE jti = ?";
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return true; // fail-closed: missing token row → treat as revoked
    }
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, jti.ptr, @intCast(jti.len), c.sqliteTransientAsDestructor());
    if (c.sqlite3_step(stmt) != c.SQLITE_ROW) return true; // unknown jti → revoked
    return c.sqlite3_column_int(stmt, 0) != 0;
}

/// Helper: bail out with a 401 if the bearer is missing/invalid, with a
/// 403 if the required scope is absent. Returns the verified claims on
/// success.
pub fn requireScope(hc: *HandlerContext, scope: []const u8) !?jwt.Claims {
    switch (authenticate(hc)) {
        .ok => |claims| {
            if (!claims.hasScope(scope)) {
                try http_util.writeError(hc, .forbidden, "insufficient scope");
                return null;
            }
            return claims;
        },
        .missing, .invalid => {
            try http_util.writeError(hc, .unauthorized, "invalid or missing bearer token");
            return null;
        },
        .expired => {
            try http_util.writeError(hc, .unauthorized, "token expired");
            return null;
        },
        .revoked => {
            try http_util.writeError(hc, .unauthorized, "token revoked");
            return null;
        },
    }
}
