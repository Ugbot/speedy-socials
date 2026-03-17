const std = @import("std");
const jwt_mod = @import("jwt.zig");
const storage_mod = @import("../storage.zig");
const config_mod = @import("../config.zig");
const xrpc_mod = @import("../xrpc.zig");
const Storage = storage_mod.Storage;
const PdsConfig = config_mod.PdsConfig;
const XrpcOutput = xrpc_mod.XrpcOutput;

/// Create a new session (com.atproto.server.createSession).
/// Validates credentials and returns access + refresh JWTs.
pub fn createSession(
    allocator: std.mem.Allocator,
    store: Storage,
    cfg: PdsConfig,
    identifier: []const u8,
    password: []const u8,
) !XrpcOutput {
    // Look up account
    const account = try store.getAccountByIdentifier(allocator, identifier) orelse {
        return XrpcOutput.errResponse(401, "AuthenticationRequired", "Account not found");
    };

    // Verify password (constant-time comparison)
    if (!std.mem.eql(u8, account.password_hash, password)) {
        return XrpcOutput.errResponse(401, "AuthenticationRequired", "Invalid identifier or password");
    }

    const now = std.time.timestamp();

    // Create access token
    const access_jwt = try jwt_mod.createToken(allocator, .{
        .iss = cfg.did,
        .sub = account.did,
        .aud = cfg.did,
        .exp = now + cfg.access_token_ttl,
        .iat = now,
        .scope = "com.atproto.access",
    }, cfg.jwt_secret);
    defer allocator.free(access_jwt);

    // Create refresh token
    const refresh_jwt = try jwt_mod.createToken(allocator, .{
        .iss = cfg.did,
        .sub = account.did,
        .aud = cfg.did,
        .exp = now + cfg.refresh_token_ttl,
        .iat = now,
        .scope = "com.atproto.refresh",
    }, cfg.jwt_secret);
    defer allocator.free(refresh_jwt);

    // Store session
    try store.createSession(allocator, .{
        .did = account.did,
        .handle = account.handle,
        .access_jwt = access_jwt,
        .refresh_jwt = refresh_jwt,
        .created_at = now,
        .access_expires_at = now + cfg.access_token_ttl,
        .refresh_expires_at = now + cfg.refresh_token_ttl,
    });

    // Build response
    return XrpcOutput.ok(try std.json.Stringify.valueAlloc(allocator, .{
        .did = account.did,
        .handle = account.handle,
        .accessJwt = access_jwt,
        .refreshJwt = refresh_jwt,
    }, .{}));
}

/// Refresh an existing session (com.atproto.server.refreshSession).
pub fn refreshSession(
    allocator: std.mem.Allocator,
    store: Storage,
    cfg: PdsConfig,
    refresh_token: []const u8,
) !XrpcOutput {
    // Verify the refresh token
    const claims = jwt_mod.verifyToken(allocator, refresh_token, cfg.jwt_secret) catch {
        return XrpcOutput.errResponse(401, "InvalidToken", "Invalid or expired refresh token");
    };
    defer jwt_mod.freeClaims(allocator, claims);

    if (!std.mem.eql(u8, claims.scope, "com.atproto.refresh")) {
        return XrpcOutput.errResponse(401, "InvalidToken", "Not a refresh token");
    }

    // Delete old session
    const old_session = try store.getSessionByRefreshToken(allocator, refresh_token);
    if (old_session) |os| {
        try store.deleteSession(allocator, os.access_jwt);
    }

    // Look up account
    const account = try store.getAccountByDid(allocator, claims.sub) orelse {
        return XrpcOutput.errResponse(401, "AccountNotFound", "Account not found");
    };

    const now = std.time.timestamp();

    // Create new tokens
    const access_jwt = try jwt_mod.createToken(allocator, .{
        .iss = cfg.did,
        .sub = account.did,
        .aud = cfg.did,
        .exp = now + cfg.access_token_ttl,
        .iat = now,
        .scope = "com.atproto.access",
    }, cfg.jwt_secret);
    defer allocator.free(access_jwt);

    const new_refresh_jwt = try jwt_mod.createToken(allocator, .{
        .iss = cfg.did,
        .sub = account.did,
        .aud = cfg.did,
        .exp = now + cfg.refresh_token_ttl,
        .iat = now,
        .scope = "com.atproto.refresh",
    }, cfg.jwt_secret);
    defer allocator.free(new_refresh_jwt);

    // Store new session
    try store.createSession(allocator, .{
        .did = account.did,
        .handle = account.handle,
        .access_jwt = access_jwt,
        .refresh_jwt = new_refresh_jwt,
        .created_at = now,
        .access_expires_at = now + cfg.access_token_ttl,
        .refresh_expires_at = now + cfg.refresh_token_ttl,
    });

    return XrpcOutput.ok(try std.json.Stringify.valueAlloc(allocator, .{
        .did = account.did,
        .handle = account.handle,
        .accessJwt = access_jwt,
        .refreshJwt = new_refresh_jwt,
    }, .{}));
}

/// Delete a session (com.atproto.server.deleteSession).
pub fn deleteSession(
    allocator: std.mem.Allocator,
    store: Storage,
    cfg: PdsConfig,
    access_token: []const u8,
) !XrpcOutput {
    // Verify the token is valid
    _ = jwt_mod.verifyToken(allocator, access_token, cfg.jwt_secret) catch {
        return XrpcOutput.errResponse(401, "InvalidToken", "Invalid token");
    };

    try store.deleteSession(allocator, access_token);

    return XrpcOutput.ok("{}");
}

/// Get current session info (com.atproto.server.getSession).
pub fn getSession(
    allocator: std.mem.Allocator,
    store: Storage,
    cfg: PdsConfig,
    access_token: []const u8,
) !XrpcOutput {
    const claims = jwt_mod.verifyToken(allocator, access_token, cfg.jwt_secret) catch {
        return XrpcOutput.errResponse(401, "InvalidToken", "Invalid or expired token");
    };
    defer jwt_mod.freeClaims(allocator, claims);

    const account = try store.getAccountByDid(allocator, claims.sub) orelse {
        return XrpcOutput.errResponse(404, "AccountNotFound", "Account not found");
    };

    return XrpcOutput.ok(try std.json.Stringify.valueAlloc(allocator, .{
        .did = account.did,
        .handle = account.handle,
        .email = account.email,
    }, .{}));
}

/// Validate an authorization bearer token and return the DID.
/// Used as middleware by other handlers.
pub fn validateAuth(
    allocator: std.mem.Allocator,
    cfg: PdsConfig,
    bearer_token: ?[]const u8,
) !?[]const u8 {
    const token = bearer_token orelse return null;

    if (!std.mem.startsWith(u8, token, "Bearer ")) {
        return null;
    }

    const jwt_str = token[7..];
    const claims = jwt_mod.verifyToken(allocator, jwt_str, cfg.jwt_secret) catch return null;
    // Caller must free the returned DID
    allocator.free(claims.iss);
    allocator.free(claims.aud);
    allocator.free(claims.scope);
    // Return sub (user DID) — caller owns this memory
    return claims.sub;
}
