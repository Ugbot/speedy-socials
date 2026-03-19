//! Federation test suite.
//! Tests timestamps, database federation functions, and activity handler logic.

const std = @import("std");
const activitypub = @import("activitypub.zig");
const crypto_sig = @import("crypto_sig.zig");
const database = @import("database.zig");

// ---- Timestamp Tests ----

test "unixTimestampToIso8601 epoch zero" {
    const allocator = std.testing.allocator;
    const result = try activitypub.unixTimestampToIso8601(allocator, 0);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("1970-01-01T00:00:00Z", result);
}

test "unixTimestampToIso8601 known date" {
    const allocator = std.testing.allocator;
    // 2024-01-15 10:30:00 UTC = 1705314600
    const result = try activitypub.unixTimestampToIso8601(allocator, 1705314600);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("2024-01-15T10:30:00Z", result);
}

test "unixTimestampToIso8601 year 2038" {
    const allocator = std.testing.allocator;
    // 2038-01-19 03:14:07 UTC = 2147483647 (max i32, but we use i64)
    const result = try activitypub.unixTimestampToIso8601(allocator, 2147483647);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("2038-01-19T03:14:07Z", result);
}

test "unixTimestampToIso8601 recent date" {
    const allocator = std.testing.allocator;
    // 2026-03-19 00:00:00 UTC = 1773878400
    const result = try activitypub.unixTimestampToIso8601(allocator, 1773878400);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("2026-03-19T00:00:00Z", result);
}

test "sqliteDatetimeToIso8601 converts correctly" {
    const allocator = std.testing.allocator;
    const result = try activitypub.sqliteDatetimeToIso8601(allocator, "2024-06-15 14:30:45");
    defer allocator.free(result);
    try std.testing.expectEqualStrings("2024-06-15T14:30:45Z", result);
}

test "formatHttpDate known date" {
    const allocator = std.testing.allocator;
    // 2026-03-19 12:00:00 UTC = 1773921600 (Thursday)
    const result = try activitypub.formatHttpDate(allocator, 1773921600);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Thu, 19 Mar 2026 12:00:00 GMT", result);
}

test "formatHttpDate epoch" {
    const allocator = std.testing.allocator;
    // 1970-01-01 was a Thursday
    const result = try activitypub.formatHttpDate(allocator, 0);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Thu, 01 Jan 1970 00:00:00 GMT", result);
}

// ---- Crypto Round-trip Tests ----

test "crypto sign and verify round-trip" {
    const allocator = std.testing.allocator;
    const kp = crypto_sig.generateKeyPair();

    const key_id = "https://example.com/users/alice#main-key";
    const sig_header = try crypto_sig.signRequest(
        allocator,
        kp.secret_key,
        key_id,
        "post",
        "/inbox",
        "remote.server",
        "Thu, 19 Mar 2026 12:00:00 GMT",
        "SHA-256=abc123",
    );
    defer allocator.free(sig_header);

    const parsed = try crypto_sig.parseSignatureHeader(sig_header);
    try std.testing.expectEqualStrings(key_id, parsed.key_id);
    try std.testing.expectEqualStrings("hs2019", parsed.algorithm);

    const valid = try crypto_sig.verifyRequest(
        allocator,
        kp.public_key,
        parsed,
        "post",
        "/inbox",
        "remote.server",
        "Thu, 19 Mar 2026 12:00:00 GMT",
        "SHA-256=abc123",
    );
    try std.testing.expect(valid);
}

test "crypto verify fails with different digest" {
    const allocator = std.testing.allocator;
    const kp = crypto_sig.generateKeyPair();

    const sig_header = try crypto_sig.signRequest(
        allocator,
        kp.secret_key,
        "https://example.com/users/alice#main-key",
        "post",
        "/inbox",
        "remote.server",
        "Thu, 19 Mar 2026 12:00:00 GMT",
        "SHA-256=original",
    );
    defer allocator.free(sig_header);

    const parsed = try crypto_sig.parseSignatureHeader(sig_header);
    const valid = try crypto_sig.verifyRequest(
        allocator,
        kp.public_key,
        parsed,
        "post",
        "/inbox",
        "remote.server",
        "Thu, 19 Mar 2026 12:00:00 GMT",
        "SHA-256=tampered",
    );
    try std.testing.expect(!valid);
}

test "PEM encoding produces valid format" {
    const allocator = std.testing.allocator;
    const kp = crypto_sig.generateKeyPair();
    const pem = try crypto_sig.publicKeyToPem(allocator, kp.public_key);
    defer allocator.free(pem);

    try std.testing.expect(std.mem.startsWith(u8, pem, "-----BEGIN PUBLIC KEY-----\n"));
    try std.testing.expect(std.mem.endsWith(u8, pem, "\n-----END PUBLIC KEY-----"));

    // Round-trip
    const decoded = try crypto_sig.pemToPublicKey(pem);
    try std.testing.expectEqualSlices(u8, &kp.public_key, &decoded);
}

// ---- Database Federation Tests ----

test "database federation tables migrate" {
    var db = try database.initTestDb();
    defer db.deinit();
    try database.migrate(&db);
    // If we get here without error, all tables created successfully
}

test "database actor key pair lifecycle" {
    const allocator = std.testing.allocator;
    var db = try database.initTestDb();
    defer db.deinit();
    try database.migrate(&db);

    // Create a test user
    _ = try database.createUser(&db, allocator, "testuser", "test@test.com", "hash123");

    // No key pair initially
    const no_key = try database.getActorKeyPair(&db, allocator, 1);
    try std.testing.expect(no_key == null);

    // ensureActorKeyPair generates one
    const key1 = try database.ensureActorKeyPair(&db, allocator, 1);
    defer allocator.free(key1.public_key_pem);
    try std.testing.expect(std.mem.startsWith(u8, key1.public_key_pem, "-----BEGIN PUBLIC KEY-----"));

    // Second call returns same key (idempotent)
    const key2 = try database.ensureActorKeyPair(&db, allocator, 1);
    defer allocator.free(key2.public_key_pem);
    try std.testing.expectEqualStrings(key1.public_key_pem, key2.public_key_pem);
    try std.testing.expectEqualSlices(u8, &key1.private_key_raw, &key2.private_key_raw);
}

test "database remote actor CRUD" {
    const allocator = std.testing.allocator;
    var db = try database.initTestDb();
    defer db.deinit();
    try database.migrate(&db);

    // Create remote actor
    const actor = try database.getOrCreateRemoteActor(
        &db,
        allocator,
        "https://mastodon.social/users/alice",
        "https://mastodon.social/users/alice/inbox",
        "mastodon.social",
    );
    defer actor.deinit(allocator);
    try std.testing.expectEqualStrings("https://mastodon.social/users/alice", actor.actor_uri);

    // Get by URI
    const found = try database.getRemoteActorByUri(&db, allocator, "https://mastodon.social/users/alice");
    try std.testing.expect(found != null);
    defer found.?.deinit(allocator);
    try std.testing.expectEqualStrings("mastodon.social", found.?.domain);

    // Not found
    const missing = try database.getRemoteActorByUri(&db, allocator, "https://nonexistent.social/users/nobody");
    try std.testing.expect(missing == null);

    // Idempotent — same URI returns same actor
    const actor2 = try database.getOrCreateRemoteActor(
        &db,
        allocator,
        "https://mastodon.social/users/alice",
        "https://mastodon.social/users/alice/inbox",
        "mastodon.social",
    );
    defer actor2.deinit(allocator);
    try std.testing.expectEqual(actor.id, actor2.id);
}

test "database federation follow lifecycle" {
    const allocator = std.testing.allocator;
    var db = try database.initTestDb();
    defer db.deinit();
    try database.migrate(&db);

    _ = try database.createUser(&db, allocator, "localuser", "local@test.com", "hash");
    const remote_actor = try database.getOrCreateRemoteActor(
        &db,
        allocator,
        "https://remote.social/users/bob",
        "https://remote.social/users/bob/inbox",
        "remote.social",
    );
    defer remote_actor.deinit(allocator);

    // Create inbound follow
    try database.createFederationFollow(&db, 1, 1, "https://remote.social/activities/follow-1", "inbound");

    // Find by URI
    const follow = try database.getFederationFollowByUri(&db, allocator, "https://remote.social/activities/follow-1");
    try std.testing.expect(follow != null);
    defer follow.?.deinit(allocator);
    try std.testing.expectEqualStrings("inbound", follow.?.direction);
    try std.testing.expectEqualStrings("pending", follow.?.status);

    // Update status
    try database.updateFederationFollowStatus(&db, "https://remote.social/activities/follow-1", "accepted");
    const updated = try database.getFederationFollowByUri(&db, allocator, "https://remote.social/activities/follow-1");
    try std.testing.expect(updated != null);
    defer updated.?.deinit(allocator);
    try std.testing.expectEqualStrings("accepted", updated.?.status);

    // Delete
    try database.deleteFederationFollow(&db, "https://remote.social/activities/follow-1");
    const deleted = try database.getFederationFollowByUri(&db, allocator, "https://remote.social/activities/follow-1");
    try std.testing.expect(deleted == null);
}

test "database activity deduplication" {
    var db = try database.initTestDb();
    defer db.deinit();
    try database.migrate(&db);

    const uri = "https://remote.social/activities/create-1";

    // Not processed initially
    const before = try database.isActivityProcessed(&db, uri);
    try std.testing.expect(!before);

    // Mark processed
    try database.markActivityProcessed(&db, uri, "Create", "https://remote.social/users/alice", "https://remote.social/posts/1");

    // Now it's processed
    const after = try database.isActivityProcessed(&db, uri);
    try std.testing.expect(after);
}

test "database remote follower inbox resolution" {
    const allocator = std.testing.allocator;
    var db = try database.initTestDb();
    defer db.deinit();
    try database.migrate(&db);

    _ = try database.createUser(&db, allocator, "popular", "popular@test.com", "hash");

    // Create remote actors on two different servers
    const ra1 = try database.getOrCreateRemoteActor(&db, allocator, "https://server1.social/users/a", "https://server1.social/users/a/inbox", "server1.social");
    defer ra1.deinit(allocator);
    const ra2 = try database.getOrCreateRemoteActor(&db, allocator, "https://server2.social/users/b", "https://server2.social/users/b/inbox", "server2.social");
    defer ra2.deinit(allocator);

    // Create accepted inbound follows
    try database.createFederationFollow(&db, 1, 1, "https://server1.social/follow-1", "inbound");
    try database.updateFederationFollowStatus(&db, "https://server1.social/follow-1", "accepted");

    try database.createFederationFollow(&db, 1, 2, "https://server2.social/follow-1", "inbound");
    try database.updateFederationFollowStatus(&db, "https://server2.social/follow-1", "accepted");

    // Query inboxes
    const inboxes = try database.getRemoteFollowerInboxes(&db, allocator, 1);
    defer {
        for (inboxes) |inbox| allocator.free(inbox);
        allocator.free(inboxes);
    }
    try std.testing.expectEqual(@as(usize, 2), inboxes.len);
}

test "database instance blocking" {
    const allocator = std.testing.allocator;
    _ = allocator;
    var db = try database.initTestDb();
    defer db.deinit();
    try database.migrate(&db);

    // Not blocked initially
    const before = try database.isInstanceBlocked(&db, "evil.social");
    try std.testing.expect(!before);

    // Block the domain
    try db.exec("INSERT INTO instance_blocks (domain, severity) VALUES (?, ?)", .{}, .{ "evil.social", "suspend" });

    // Now blocked
    const after = try database.isInstanceBlocked(&db, "evil.social");
    try std.testing.expect(after);
}

test "database user and post counts" {
    const allocator = std.testing.allocator;
    var db = try database.initTestDb();
    defer db.deinit();
    try database.migrate(&db);

    // Initially zero
    const users0 = try database.getUserCount(&db);
    try std.testing.expectEqual(@as(i64, 0), users0);

    // Create users and posts
    _ = try database.createUser(&db, allocator, "user1", "u1@test.com", "hash");
    _ = try database.createUser(&db, allocator, "user2", "u2@test.com", "hash");
    _ = try database.createPost(&db, allocator, 1, "Hello world", "public");
    _ = try database.createPost(&db, allocator, 1, "Second post", "public");
    _ = try database.createPost(&db, allocator, 2, "User 2 post", "public");

    const users = try database.getUserCount(&db);
    try std.testing.expectEqual(@as(i64, 2), users);

    const posts = try database.getPostCount(&db);
    try std.testing.expectEqual(@as(i64, 3), posts);
}

test "database remote post and interaction CRUD" {
    const allocator = std.testing.allocator;
    var db = try database.initTestDb();
    defer db.deinit();
    try database.migrate(&db);

    _ = try database.createUser(&db, allocator, "localuser", "l@test.com", "hash");
    const remote_actor = try database.getOrCreateRemoteActor(&db, allocator, "https://remote.social/users/alice", "https://remote.social/inbox", "remote.social");
    defer remote_actor.deinit(allocator);
    _ = try database.createPost(&db, allocator, 1, "Local post", "public");

    // Create remote post
    try database.createRemotePost(&db, "https://remote.social/posts/1", 1, "<p>Hello from remote!</p>", null, null, "2024-01-01T00:00:00Z");

    // Create interaction (like on local post)
    try database.createRemoteInteraction(&db, "https://remote.social/likes/1", 1, 1, "like");

    // Delete interaction
    try database.deleteRemoteInteraction(&db, "https://remote.social/likes/1");

    // Delete remote post
    try database.deleteRemotePost(&db, "https://remote.social/posts/1");
}
