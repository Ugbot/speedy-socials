const std = @import("std");
const xrpc_mod = @import("../xrpc.zig");
const storage_mod = @import("../storage.zig");
const config_mod = @import("../config.zig");
const session_mod = @import("../auth/session.zig");
const commit_mod = @import("../commit.zig");
const XrpcInput = xrpc_mod.XrpcInput;
const XrpcOutput = xrpc_mod.XrpcOutput;
const Storage = storage_mod.Storage;
const PdsConfig = config_mod.PdsConfig;

/// com.atproto.server.describeServer
pub fn describeServer(allocator: std.mem.Allocator, cfg: PdsConfig, _: XrpcInput) !XrpcOutput {
    return XrpcOutput.ok(try std.json.Stringify.valueAlloc(allocator, .{
        .did = cfg.did,
        .availableUserDomains = cfg.available_user_domains,
        .inviteCodeRequired = cfg.invite_code_required,
        .phoneVerificationRequired = cfg.phone_verification_required,
        .links = .{},
    }, .{}));
}

/// com.atproto.server.createSession
pub fn createSession(allocator: std.mem.Allocator, store: Storage, cfg: PdsConfig, input: XrpcInput) !XrpcOutput {
    const body = input.body orelse {
        return XrpcOutput.errResponse(400, "InvalidRequest", "Missing request body");
    };

    const parsed = std.json.parseFromSlice(struct {
        identifier: []const u8,
        password: []const u8,
    }, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return XrpcOutput.errResponse(400, "InvalidRequest", "Invalid JSON body");
    };
    defer parsed.deinit();

    return session_mod.createSession(allocator, store, cfg, parsed.value.identifier, parsed.value.password);
}

/// com.atproto.server.refreshSession
pub fn refreshSession(allocator: std.mem.Allocator, store: Storage, cfg: PdsConfig, input: XrpcInput) !XrpcOutput {
    const token = input.auth_token orelse {
        return XrpcOutput.errResponse(401, "AuthenticationRequired", "Missing authorization");
    };

    if (!std.mem.startsWith(u8, token, "Bearer ")) {
        return XrpcOutput.errResponse(401, "AuthenticationRequired", "Invalid authorization format");
    }

    return session_mod.refreshSession(allocator, store, cfg, token[7..]);
}

/// com.atproto.server.deleteSession
pub fn deleteSession(allocator: std.mem.Allocator, store: Storage, cfg: PdsConfig, input: XrpcInput) !XrpcOutput {
    const token = input.auth_token orelse {
        return XrpcOutput.errResponse(401, "AuthenticationRequired", "Missing authorization");
    };

    if (!std.mem.startsWith(u8, token, "Bearer ")) {
        return XrpcOutput.errResponse(401, "AuthenticationRequired", "Invalid authorization format");
    }

    return session_mod.deleteSession(allocator, store, cfg, token[7..]);
}

/// com.atproto.server.getSession
pub fn getSession(allocator: std.mem.Allocator, store: Storage, cfg: PdsConfig, input: XrpcInput) !XrpcOutput {
    const token = input.auth_token orelse {
        return XrpcOutput.errResponse(401, "AuthenticationRequired", "Missing authorization");
    };

    if (!std.mem.startsWith(u8, token, "Bearer ")) {
        return XrpcOutput.errResponse(401, "AuthenticationRequired", "Invalid authorization format");
    }

    return session_mod.getSession(allocator, store, cfg, token[7..]);
}

/// com.atproto.server.createAccount
pub fn createAccount(allocator: std.mem.Allocator, store: Storage, cfg: PdsConfig, input: XrpcInput) !XrpcOutput {
    const body = input.body orelse {
        return XrpcOutput.errResponse(400, "InvalidRequest", "Missing request body");
    };

    const parsed = std.json.parseFromSlice(struct {
        handle: []const u8,
        email: ?[]const u8 = null,
        password: ?[]const u8 = null,
    }, allocator, body, .{ .ignore_unknown_fields = true }) catch {
        return XrpcOutput.errResponse(400, "InvalidRequest", "Invalid JSON body");
    };
    defer parsed.deinit();

    // Generate DID
    const did = try PdsConfig.didFromHostname(cfg.hostname, allocator);
    defer allocator.free(did);
    const user_did = try std.fmt.allocPrint(allocator, "did:web:{s}", .{parsed.value.handle});
    defer allocator.free(user_did);

    // Generate signing key
    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);
    const seed_hex = std.fmt.bytesToHex(&seed, .lower);
    const seed_str: []const u8 = &seed_hex;

    // Create account in storage
    store.createAccount(allocator, .{
        .did = user_did,
        .handle = parsed.value.handle,
        .email = parsed.value.email,
        .password_hash = parsed.value.password orelse "",
        .signing_key_seed = seed_str,
        .created_at = std.time.timestamp(),
    }) catch {
        return XrpcOutput.errResponse(409, "HandleNotAvailable", "Handle already taken");
    };

    // Create initial session
    return session_mod.createSession(
        allocator,
        store,
        cfg,
        parsed.value.handle,
        parsed.value.password orelse "",
    );
}
