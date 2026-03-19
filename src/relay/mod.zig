const std = @import("std");
const database = @import("../database.zig");
const identity_map = @import("identity_map.zig");

pub const translate = @import("translate.zig");
pub const IdentityMap = identity_map.IdentityMap;
pub const at_to_ap = @import("at_to_ap.zig");
pub const ap_to_at = @import("ap_to_at.zig");
pub const subscription = @import("subscription.zig");

pub const RelayMode = enum {
    disabled, // No cross-protocol translation
    bridge, // Translate local instance users bidirectionally
    relay, // Standalone relay service for network-level bridging
};

pub const RelayConfig = struct {
    mode: RelayMode = .disabled,
    firehose_url: ?[]const u8 = null, // AT Proto firehose (relay mode)
    relay_domain: ?[]const u8 = null, // Domain for synthetic actors (relay mode)
    bridge_collections: []const []const u8 = &default_collections,

    const default_collections = [_][]const u8{
        "app.bsky.feed.post",
        "app.bsky.feed.like",
        "app.bsky.feed.repost",
        "app.bsky.graph.follow",
        "app.bsky.actor.profile",
    };
};

pub const Relay = struct {
    config: RelayConfig,
    db: *database.Database,
    allocator: std.mem.Allocator,
    id_map: IdentityMap,
    sub_manager: ?subscription.SubscriptionManager,

    pub fn init(allocator: std.mem.Allocator, db: *database.Database, config: RelayConfig) Relay {
        return .{
            .config = config,
            .db = db,
            .allocator = allocator,
            .id_map = IdentityMap.init(db),
            .sub_manager = if (config.mode == .relay)
                subscription.SubscriptionManager.init(allocator, db)
            else
                null,
        };
    }

    /// Check if a collection should be bridged/relayed.
    pub fn shouldTranslate(self: *const Relay, collection: []const u8) bool {
        for (self.config.bridge_collections) |c| {
            if (std.mem.eql(u8, c, collection)) return true;
        }
        return false;
    }

    /// Handle a new AT Protocol record creation (bridge mode hook).
    /// Called after a successful XRPC createRecord.
    pub fn onAtRecordCreated(
        self: *Relay,
        did: []const u8,
        collection: []const u8,
        rkey: []const u8,
        record_json: []const u8,
    ) !void {
        if (self.config.mode == .disabled) return;
        if (!self.shouldTranslate(collection)) return;
        try at_to_ap.handleRecordCreated(self, did, collection, rkey, record_json);
    }

    /// Handle an incoming ActivityPub activity (bridge mode hook).
    /// Called after federation.zig processes the AP side.
    pub fn onApActivityReceived(
        self: *Relay,
        activity_json: []const u8,
    ) !void {
        if (self.config.mode == .disabled) return;
        try ap_to_at.handleActivityReceived(self, activity_json);
    }

    pub fn deinit(self: *Relay) void {
        if (self.sub_manager) |*sm| sm.deinit();
    }
};

test "relay config defaults" {
    const config = RelayConfig{};
    try std.testing.expectEqual(RelayMode.disabled, config.mode);
    try std.testing.expectEqual(@as(?[]const u8, null), config.firehose_url);
    try std.testing.expect(config.bridge_collections.len == 5);
}

test "relay shouldTranslate" {
    var db_val = try database.initTestDb();
    defer db_val.deinit();
    try database.migrate(&db_val);

    var relay = Relay.init(std.testing.allocator, &db_val, .{ .mode = .bridge });
    defer relay.deinit();
    try std.testing.expect(relay.shouldTranslate("app.bsky.feed.post"));
    try std.testing.expect(relay.shouldTranslate("app.bsky.feed.like"));
    try std.testing.expect(!relay.shouldTranslate("app.bsky.feed.threadgate"));
    try std.testing.expect(!relay.shouldTranslate("com.example.unknown"));
}
