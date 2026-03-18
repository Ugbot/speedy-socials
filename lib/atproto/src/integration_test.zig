//! Integration tests for the AT Protocol PDS library.
//! Tests the full flow: create account → authenticate → create records → query → delete.

const std = @import("std");
const root = @import("root.zig");

const Storage = root.Storage;
const MemoryStorage = root.MemoryStorage;
const PdsConfig = root.PdsConfig;
const XrpcInput = root.XrpcInput;
const XrpcOutput = root.XrpcOutput;
const router = root.router;

fn testConfig() PdsConfig {
    return .{
        .did = "did:web:test.local",
        .hostname = "test.local",
        .service_endpoint = "https://test.local",
        .available_user_domains = &.{".local"},
        .jwt_secret = "integration-test-secret-key-32b!",
    };
}

fn expectSuccess(output: XrpcOutput) ![]const u8 {
    switch (output) {
        .success => |s| return s.body,
        .err => |e| {
            std.debug.print("XRPC error: {s} - {s}\n", .{ e.error_name, e.message });
            return error.UnexpectedError;
        },
        .blob => return error.UnexpectedBlob,
    }
}


fn expectError(output: XrpcOutput, expected_status: u16) !void {
    switch (output) {
        .err => |e| try std.testing.expectEqual(expected_status, e.status),
        .success => |s| {
            std.debug.print("Expected error {}, got success: {s}\n", .{ expected_status, s.body });
            return error.ExpectedError;
        },
        .blob => return error.ExpectedError,
    }
}

fn extractJsonString(allocator: std.mem.Allocator, json_body: []const u8, key: []const u8) ![]const u8 {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_body, .{});
    defer parsed.deinit();
    const val = parsed.value.object.get(key) orelse return error.KeyNotFound;
    if (val != .string) return error.NotAString;
    return allocator.dupe(u8, val.string);
}

// ---- Integration Tests ----

test "full flow: create account, authenticate, create record, query, delete" {
    const allocator = std.testing.allocator;
    var mem = MemoryStorage.init(allocator);
    defer mem.deinit();
    const store = mem.storage();
    const cfg = testConfig();

    // 1. Create account
    const create_account_body =
        \\{"handle":"alice.local","email":"alice@test.com","password":"secret123"}
    ;
    const account_result = try router.dispatch(
        "com.atproto.server.createAccount",
        allocator,
        store,
        cfg,
        .{ .body = create_account_body },
    );
    const account_body = try expectSuccess(account_result);
    defer allocator.free(account_body);

    const access_jwt = try extractJsonString(allocator, account_body, "accessJwt");
    defer allocator.free(access_jwt);
    const did = try extractJsonString(allocator, account_body, "did");
    defer allocator.free(did);

    try std.testing.expect(std.mem.startsWith(u8, did, "did:web:"));
    try std.testing.expect(access_jwt.len > 0);

    // 2. Get session with the token
    const bearer = try std.fmt.allocPrint(allocator, "Bearer {s}", .{access_jwt});
    defer allocator.free(bearer);

    const session_result = try router.dispatch(
        "com.atproto.server.getSession",
        allocator,
        store,
        cfg,
        .{ .auth_token = bearer },
    );
    const session_body = try expectSuccess(session_result);
    defer allocator.free(session_body);

    const session_did = try extractJsonString(allocator, session_body, "did");
    defer allocator.free(session_did);
    try std.testing.expectEqualStrings(did, session_did);

    // 3. Create a record
    const record_body = try std.fmt.allocPrint(allocator,
        \\{{"repo":"{s}","collection":"app.bsky.feed.post","record":{{"$type":"app.bsky.feed.post","text":"Hello from integration test!","createdAt":"2024-01-01T00:00:00Z"}}}}
    , .{did});
    defer allocator.free(record_body);

    const create_result = try router.dispatch(
        "com.atproto.repo.createRecord",
        allocator,
        store,
        cfg,
        .{ .body = record_body, .auth_token = bearer },
    );
    const create_body = try expectSuccess(create_result);
    defer allocator.free(create_body);

    const record_uri = try extractJsonString(allocator, create_body, "uri");
    defer allocator.free(record_uri);
    const record_cid = try extractJsonString(allocator, create_body, "cid");
    defer allocator.free(record_cid);

    try std.testing.expect(std.mem.startsWith(u8, record_uri, "at://"));
    try std.testing.expect(record_cid.len > 0);

    // 4. List records
    var list_params: std.StringHashMapUnmanaged([]const u8) = .empty;
    defer list_params.deinit(allocator);
    try list_params.put(allocator, "repo", did);
    try list_params.put(allocator, "collection", "app.bsky.feed.post");

    const list_result = try router.dispatch(
        "com.atproto.repo.listRecords",
        allocator,
        store,
        cfg,
        .{ .params = list_params },
    );
    const list_body = try expectSuccess(list_result);
    defer allocator.free(list_body);

    // Should contain our record
    try std.testing.expect(std.mem.indexOf(u8, list_body, "Hello from integration test!") != null);

    // 5. Delete the record — extract rkey from URI
    const rkey_start = std.mem.lastIndexOf(u8, record_uri, "/").? + 1;
    const rkey = record_uri[rkey_start..];

    const delete_body = try std.fmt.allocPrint(allocator,
        \\{{"repo":"{s}","collection":"app.bsky.feed.post","rkey":"{s}"}}
    , .{ did, rkey });
    defer allocator.free(delete_body);

    const delete_result = try router.dispatch(
        "com.atproto.repo.deleteRecord",
        allocator,
        store,
        cfg,
        .{ .body = delete_body, .auth_token = bearer },
    );
    const del_body = try expectSuccess(delete_result);
    defer allocator.free(del_body);

    // 6. Delete session (logout)
    const logout_result = try router.dispatch(
        "com.atproto.server.deleteSession",
        allocator,
        store,
        cfg,
        .{ .auth_token = bearer },
    );
    const logout_body = try expectSuccess(logout_result);
    defer allocator.free(logout_body);
}

test "describeServer returns correct config" {
    const allocator = std.testing.allocator;
    var mem = MemoryStorage.init(allocator);
    defer mem.deinit();
    const cfg = testConfig();

    const result = try router.dispatch("com.atproto.server.describeServer", allocator, mem.storage(), cfg, .{});
    const body = try expectSuccess(result);
    defer allocator.free(body);

    try std.testing.expect(std.mem.indexOf(u8, body, "did:web:test.local") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, ".local") != null);
}

test "createSession without account returns 401" {
    const allocator = std.testing.allocator;
    var mem = MemoryStorage.init(allocator);
    defer mem.deinit();
    const cfg = testConfig();

    const result = try router.dispatch(
        "com.atproto.server.createSession",
        allocator,
        mem.storage(),
        cfg,
        .{ .body = "{\"identifier\":\"nobody\",\"password\":\"wrong\"}" },
    );
    try expectError(result, 401);
}

test "createRecord without auth returns 401" {
    const allocator = std.testing.allocator;
    var mem = MemoryStorage.init(allocator);
    defer mem.deinit();
    const cfg = testConfig();

    const result = try router.dispatch(
        "com.atproto.repo.createRecord",
        allocator,
        mem.storage(),
        cfg,
        .{ .body = "{\"repo\":\"did:web:x\",\"collection\":\"app.bsky.feed.post\",\"record\":{}}" },
    );
    try expectError(result, 401);
}

test "resolveHandle returns DID for known account" {
    const allocator = std.testing.allocator;
    var mem = MemoryStorage.init(allocator);
    defer mem.deinit();
    const store = mem.storage();
    const cfg = testConfig();

    // Create account first
    const result = try router.dispatch(
        "com.atproto.server.createAccount",
        allocator,
        store,
        cfg,
        .{ .body = "{\"handle\":\"bob.local\",\"password\":\"pass\"}" },
    );
    const body = try expectSuccess(result);
    defer allocator.free(body);

    // Resolve handle
    var params: std.StringHashMapUnmanaged([]const u8) = .empty;
    defer params.deinit(allocator);
    try params.put(allocator, "handle", "bob.local");

    const resolve_result = try router.dispatch(
        "com.atproto.identity.resolveHandle",
        allocator,
        store,
        cfg,
        .{ .params = params },
    );
    const resolve_body = try expectSuccess(resolve_result);
    defer allocator.free(resolve_body);

    try std.testing.expect(std.mem.indexOf(u8, resolve_body, "did:web:bob.local") != null);
}

test "resolveHandle returns 404 for unknown handle" {
    const allocator = std.testing.allocator;
    var mem = MemoryStorage.init(allocator);
    defer mem.deinit();
    const cfg = testConfig();

    var params: std.StringHashMapUnmanaged([]const u8) = .empty;
    defer params.deinit(allocator);
    try params.put(allocator, "handle", "nobody.local");

    const result = try router.dispatch(
        "com.atproto.identity.resolveHandle",
        allocator,
        mem.storage(),
        cfg,
        .{ .params = params },
    );
    try expectError(result, 404);
}

test "unknown XRPC method returns 501" {
    const allocator = std.testing.allocator;
    var mem = MemoryStorage.init(allocator);
    defer mem.deinit();
    const cfg = testConfig();

    const result = try router.dispatch("com.atproto.fake.method", allocator, mem.storage(), cfg, .{});
    try expectError(result, 501);
}

test "DID document generation is spec-compliant" {
    const allocator = std.testing.allocator;
    const doc = try root.did_doc.generateDidWeb(
        allocator,
        "did:web:example.com",
        "alice.example.com",
        "zDnaeVpCqkbjR4Nz6GKkqVnfPkp7fX3LKuqUwMYrVRtBJaJW",
        "https://example.com",
    );
    defer allocator.free(doc);

    // Required fields per AT Protocol spec
    try std.testing.expect(std.mem.indexOf(u8, doc, "#atproto_pds") != null);
    try std.testing.expect(std.mem.indexOf(u8, doc, "AtprotoPersonalDataServer") != null);
    try std.testing.expect(std.mem.indexOf(u8, doc, "#atproto") != null);
    try std.testing.expect(std.mem.indexOf(u8, doc, "Multikey") != null);
    try std.testing.expect(std.mem.indexOf(u8, doc, "at://alice.example.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, doc, "https://example.com") != null);
}

test "well-known atproto-did returns plain DID string" {
    const cfg = testConfig();
    const did = root.well_known.atprotoDid(cfg);
    try std.testing.expectEqualStrings("did:web:test.local", did);
}

test "JWT round-trip create and verify" {
    const allocator = std.testing.allocator;
    const secret = "test-jwt-secret-must-be-long!!!";
    const now = std.time.timestamp();

    const token = try root.jwt.createToken(allocator, .{
        .iss = "did:web:server",
        .sub = "did:web:user",
        .aud = "did:web:server",
        .exp = now + 3600,
        .iat = now,
        .scope = "com.atproto.access",
    }, secret);
    defer allocator.free(token);

    // Verify returns correct claims
    const claims = try root.jwt.verifyToken(allocator, token, secret);
    defer root.jwt.freeClaims(allocator, claims);

    try std.testing.expectEqualStrings("did:web:user", claims.sub);
    try std.testing.expectEqualStrings("com.atproto.access", claims.scope);

    // Wrong secret should fail
    const bad_result = root.jwt.verifyToken(allocator, token, "wrong-secret-wrong-secret-wrong");
    try std.testing.expectError(error.InvalidToken, bad_result);
}

test "multiple records in same collection" {
    const allocator = std.testing.allocator;
    var mem = MemoryStorage.init(allocator);
    defer mem.deinit();

    var repo = root.Repository.init(allocator, "did:web:test", "seedseedseedseedseedseedseedseed", mem.storage());

    // Create 3 records
    const r1 = try repo.createRecord("app.bsky.feed.post", null, "{\"text\":\"post 1\"}");
    defer { allocator.free(r1.uri); allocator.free(r1.cid); allocator.free(r1.rev); }

    const r2 = try repo.createRecord("app.bsky.feed.post", null, "{\"text\":\"post 2\"}");
    defer { allocator.free(r2.uri); allocator.free(r2.cid); allocator.free(r2.rev); }

    const r3 = try repo.createRecord("app.bsky.feed.like", null, "{\"subject\":{\"uri\":\"at://x\"}}");
    defer { allocator.free(r3.uri); allocator.free(r3.cid); allocator.free(r3.rev); }

    // List posts — should get 2
    const posts = try repo.listRecords("app.bsky.feed.post", 50, null);
    defer allocator.free(posts);
    try std.testing.expectEqual(@as(usize, 2), posts.len);

    // List likes — should get 1
    const likes = try repo.listRecords("app.bsky.feed.like", 50, null);
    defer allocator.free(likes);
    try std.testing.expectEqual(@as(usize, 1), likes.len);
}

test "commit is created for each record mutation" {
    const allocator = std.testing.allocator;
    var mem = MemoryStorage.init(allocator);
    defer mem.deinit();

    var repo = root.Repository.init(allocator, "did:web:test", "seedseedseedseedseedseedseedseed", mem.storage());

    // No commits initially
    const no_commit = try repo.getLatestCommit();
    try std.testing.expect(no_commit == null);

    // Create a record — should produce a commit
    const r = try repo.createRecord("app.bsky.feed.post", null, "{\"text\":\"hello\"}");
    defer { allocator.free(r.uri); allocator.free(r.cid); allocator.free(r.rev); }

    const commit_entry = try repo.getLatestCommit();
    try std.testing.expect(commit_entry != null);
    try std.testing.expectEqualStrings("did:web:test", commit_entry.?.did);
    try std.testing.expect(commit_entry.?.rev.len == 13); // TID length
    try std.testing.expect(commit_entry.?.sig.len > 0);
}

test "storage account deduplication" {
    const allocator = std.testing.allocator;
    var mem = MemoryStorage.init(allocator);
    defer mem.deinit();
    const store = mem.storage();

    try store.createAccount(allocator, .{
        .did = "did:web:alice",
        .handle = "alice.test",
        .email = "alice@test.com",
        .password_hash = "hash",
        .signing_key_seed = "seed",
        .created_at = 1000,
    });

    // Same handle should fail
    const result = store.createAccount(allocator, .{
        .did = "did:web:alice2",
        .handle = "alice.test",
        .email = "alice2@test.com",
        .password_hash = "hash",
        .signing_key_seed = "seed",
        .created_at = 1000,
    });
    try std.testing.expectError(root.storage.StorageError.AlreadyExists, result);
}

test "session lifecycle: create, get, delete" {
    const allocator = std.testing.allocator;
    var mem = MemoryStorage.init(allocator);
    defer mem.deinit();
    const store = mem.storage();

    // Create session
    try store.createSession(allocator, .{
        .did = "did:web:user",
        .handle = "user.test",
        .access_jwt = "access-token-123",
        .refresh_jwt = "refresh-token-456",
        .created_at = 1000,
        .access_expires_at = 2000,
        .refresh_expires_at = 9000,
    });

    // Get by token
    const sess = try store.getSessionByToken(allocator, "access-token-123");
    try std.testing.expect(sess != null);
    try std.testing.expectEqualStrings("did:web:user", sess.?.did);

    // Get by refresh token
    const refresh_sess = try store.getSessionByRefreshToken(allocator, "refresh-token-456");
    try std.testing.expect(refresh_sess != null);

    // Delete
    try store.deleteSession(allocator, "access-token-123");
    const deleted = try store.getSessionByToken(allocator, "access-token-123");
    try std.testing.expect(deleted == null);
}

test "blob storage round-trip" {
    const allocator = std.testing.allocator;
    var mem = MemoryStorage.init(allocator);
    defer mem.deinit();
    const store = mem.storage();

    const data = "hello blob data";
    try store.putBlob(allocator, .{
        .cid = "bafytest123",
        .mime_type = "text/plain",
        .size = data.len,
        .data = data,
    });

    const got = try store.getBlob(allocator, "bafytest123");
    try std.testing.expect(got != null);
    try std.testing.expectEqualStrings("text/plain", got.?.mime_type);
    try std.testing.expectEqualStrings(data, got.?.data);
    try std.testing.expectEqual(data.len, got.?.size);

    // Not found
    const missing = try store.getBlob(allocator, "nonexistent");
    try std.testing.expect(missing == null);
}
