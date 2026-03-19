const std = @import("std");
const database = @import("../database.zig");

pub const Direction = enum {
    local, // Our own user — has both DID and AP actor URI on this instance
    at_native, // AT Protocol user bridged to AP (synthetic AP actor URI)
    ap_native, // ActivityPub user bridged to AT (synthetic DID)

    pub fn toText(self: Direction) []const u8 {
        return switch (self) {
            .local => "local",
            .at_native => "at_native",
            .ap_native => "ap_native",
        };
    }

    pub fn fromText(text: []const u8) !Direction {
        if (std.mem.eql(u8, text, "local")) return .local;
        if (std.mem.eql(u8, text, "at_native")) return .at_native;
        if (std.mem.eql(u8, text, "ap_native")) return .ap_native;
        return error.InvalidDirection;
    }
};

pub const Mapping = struct {
    id: i64,
    did: []const u8,
    actor_uri: []const u8,
    handle: ?[]const u8,
    domain: []const u8,
    direction: []const u8,

    pub fn getDirection(self: Mapping) !Direction {
        return Direction.fromText(self.direction);
    }

    pub fn deinit(self: Mapping, allocator: std.mem.Allocator) void {
        allocator.free(self.did);
        allocator.free(self.actor_uri);
        if (self.handle) |h| allocator.free(h);
        allocator.free(self.domain);
        allocator.free(self.direction);
    }
};

pub const IdentityMap = struct {
    db: *database.Database,

    pub fn init(db: *database.Database) IdentityMap {
        return .{ .db = db };
    }

    /// Look up the AP actor URI for a given DID.
    pub fn didToActorUri(self: *IdentityMap, allocator: std.mem.Allocator, did: []const u8) !?[]const u8 {
        const Row = struct { actor_uri: []const u8 };
        const row = try self.db.oneAlloc(Row, allocator,
            \\SELECT actor_uri FROM identity_mappings WHERE did = ?
        , .{}, .{did});
        if (row) |r| {
            return r.actor_uri;
        }
        return null;
    }

    /// Look up the DID for a given AP actor URI.
    pub fn actorUriToDid(self: *IdentityMap, allocator: std.mem.Allocator, actor_uri: []const u8) !?[]const u8 {
        const Row = struct { did: []const u8 };
        const row = try self.db.oneAlloc(Row, allocator,
            \\SELECT did FROM identity_mappings WHERE actor_uri = ?
        , .{}, .{actor_uri});
        if (row) |r| {
            return r.did;
        }
        return null;
    }

    /// Ensure a mapping exists. If it already exists, return it. If not, create it.
    pub fn ensureMapping(
        self: *IdentityMap,
        allocator: std.mem.Allocator,
        did: []const u8,
        actor_uri: []const u8,
        handle: ?[]const u8,
        domain: []const u8,
        direction: Direction,
    ) !Mapping {
        // Try to find existing mapping by DID
        if (try self.getMappingByDid(allocator, did)) |existing| {
            return existing;
        }

        // Insert new mapping
        try self.db.exec(
            \\INSERT INTO identity_mappings (did, actor_uri, handle, domain, direction)
            \\VALUES (?, ?, ?, ?, ?)
        , .{}, .{ did, actor_uri, handle, domain, direction.toText() });

        // Fetch and return the newly created mapping
        return (try self.getMappingByDid(allocator, did)).?;
    }

    /// Get mapping by DID.
    pub fn getMappingByDid(self: *IdentityMap, allocator: std.mem.Allocator, did: []const u8) !?Mapping {
        return try self.db.oneAlloc(Mapping, allocator,
            \\SELECT id, did, actor_uri, handle, domain, direction
            \\FROM identity_mappings WHERE did = ?
        , .{}, .{did});
    }

    /// Get mapping by actor URI.
    pub fn getMappingByActorUri(self: *IdentityMap, allocator: std.mem.Allocator, actor_uri: []const u8) !?Mapping {
        return try self.db.oneAlloc(Mapping, allocator,
            \\SELECT id, did, actor_uri, handle, domain, direction
            \\FROM identity_mappings WHERE actor_uri = ?
        , .{}, .{actor_uri});
    }

    /// Generate a synthetic AP actor URI for an AT-native user (relay mode).
    pub fn syntheticActorUri(allocator: std.mem.Allocator, relay_domain: []const u8, handle: []const u8) ![]u8 {
        return std.fmt.allocPrint(allocator, "https://{s}/ap/users/{s}", .{ relay_domain, handle });
    }

    /// Generate a synthetic DID for an AP-native user (relay mode).
    pub fn syntheticDid(allocator: std.mem.Allocator, relay_domain: []const u8, handle: []const u8) ![]u8 {
        return std.fmt.allocPrint(allocator, "did:web:{s}:ap:{s}", .{ relay_domain, handle });
    }
};

// =============================================================================
// Tests
// =============================================================================

fn initTestDb() !database.Database {
    var db = try database.Database.init(.{
        .mode = .{ .Memory = {} },
        .open_flags = .{
            .write = true,
            .create = true,
        },
        .threading_mode = .MultiThread,
    });

    // Create just the identity_mappings table and indexes for tests.
    // We cannot call database.migrate() here because it depends on fts5
    // which is not available in the bundled SQLite used during test builds.
    try db.exec(
        \\CREATE TABLE IF NOT EXISTS identity_mappings (
        \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
        \\    did TEXT UNIQUE NOT NULL,
        \\    actor_uri TEXT UNIQUE NOT NULL,
        \\    handle TEXT,
        \\    domain TEXT NOT NULL,
        \\    direction TEXT NOT NULL,
        \\    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        \\)
    , .{}, .{});
    try db.exec("CREATE INDEX IF NOT EXISTS idx_identity_mappings_did ON identity_mappings(did)", .{}, .{});
    try db.exec("CREATE INDEX IF NOT EXISTS idx_identity_mappings_actor ON identity_mappings(actor_uri)", .{}, .{});

    return db;
}

test "identity map round-trip" {
    const allocator = std.testing.allocator;
    var db = try initTestDb();
    defer db.deinit();
    var id_map = IdentityMap.init(&db);

    const did = "did:plc:abc123xyz";
    const actor_uri = "https://mastodon.social/users/alice";
    const handle = "alice.bsky.social";
    const domain = "bsky.social";

    const mapping = try id_map.ensureMapping(allocator, did, actor_uri, handle, domain, .at_native);
    mapping.deinit(allocator);

    // didToActorUri should return the actor URI
    const resolved_uri = try id_map.didToActorUri(allocator, did);
    try std.testing.expect(resolved_uri != null);
    try std.testing.expectEqualStrings(actor_uri, resolved_uri.?);
    allocator.free(resolved_uri.?);

    // actorUriToDid should return the DID
    const resolved_did = try id_map.actorUriToDid(allocator, actor_uri);
    try std.testing.expect(resolved_did != null);
    try std.testing.expectEqualStrings(did, resolved_did.?);
    allocator.free(resolved_did.?);
}

test "identity map idempotent" {
    const allocator = std.testing.allocator;
    var db = try initTestDb();
    defer db.deinit();
    var id_map = IdentityMap.init(&db);

    const did = "did:plc:idempotent999";
    const actor_uri = "https://example.com/users/bob";
    const handle = "bob.bsky.social";
    const domain = "bsky.social";

    const first = try id_map.ensureMapping(allocator, did, actor_uri, handle, domain, .local);
    defer {
        allocator.free(first.did);
        allocator.free(first.actor_uri);
        if (first.handle) |h| allocator.free(h);
        allocator.free(first.domain);
        allocator.free(first.direction);
    }

    const second = try id_map.ensureMapping(allocator, did, actor_uri, handle, domain, .local);
    defer {
        allocator.free(second.did);
        allocator.free(second.actor_uri);
        if (second.handle) |h| allocator.free(h);
        allocator.free(second.domain);
        allocator.free(second.direction);
    }

    // Both calls should return the same ID
    try std.testing.expectEqual(first.id, second.id);
}

test "synthetic URI generation" {
    const allocator = std.testing.allocator;

    const actor_uri = try IdentityMap.syntheticActorUri(allocator, "relay.example.com", "alice");
    defer allocator.free(actor_uri);
    try std.testing.expectEqualStrings("https://relay.example.com/ap/users/alice", actor_uri);

    const did = try IdentityMap.syntheticDid(allocator, "relay.example.com", "alice");
    defer allocator.free(did);
    try std.testing.expectEqualStrings("did:web:relay.example.com:ap:alice", did);
}

test "missing mapping returns null" {
    const allocator = std.testing.allocator;
    var db = try initTestDb();
    defer db.deinit();
    var id_map = IdentityMap.init(&db);

    const result = try id_map.didToActorUri(allocator, "did:plc:nonexistent");
    try std.testing.expect(result == null);

    const result2 = try id_map.actorUriToDid(allocator, "https://nowhere.example/users/ghost");
    try std.testing.expect(result2 == null);
}
