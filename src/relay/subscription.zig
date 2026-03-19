const std = @import("std");
const database = @import("../database.zig");

pub const Protocol = enum {
    activitypub,
    atproto,
};

pub const SubscriptionStatus = enum {
    active,
    paused,
    removed,
};

pub const Subscription = struct {
    id: i64,
    subscriber_uri: []const u8,
    protocol: Protocol,
    status: SubscriptionStatus,
};

pub const SubscriptionManager = struct {
    allocator: std.mem.Allocator,
    db: *database.Database,

    pub fn init(allocator: std.mem.Allocator, db: *database.Database) SubscriptionManager {
        return .{ .allocator = allocator, .db = db };
    }

    /// Add a new subscriber (e.g., AP instance following the relay actor).
    pub fn subscribe(self: *SubscriptionManager, subscriber_uri: []const u8, protocol: Protocol) !void {
        const proto_str: []const u8 = switch (protocol) {
            .activitypub => "activitypub",
            .atproto => "atproto",
        };
        self.db.exec(
            \\INSERT OR IGNORE INTO relay_subscriptions (subscriber_uri, protocol, status)
            \\VALUES (?, ?, 'active')
        , .{}, .{ subscriber_uri, proto_str }) catch {};
    }

    /// Remove a subscriber.
    pub fn unsubscribe(self: *SubscriptionManager, subscriber_uri: []const u8) !void {
        try self.db.exec(
            "DELETE FROM relay_subscriptions WHERE subscriber_uri = ?",
            .{},
            .{subscriber_uri},
        );
    }

    /// Get all active subscribers for a given protocol.
    pub fn getActiveSubscribers(self: *SubscriptionManager, allocator: std.mem.Allocator, protocol: Protocol) ![]Subscription {
        const proto_str: []const u8 = switch (protocol) {
            .activitypub => "activitypub",
            .atproto => "atproto",
        };

        const Row = struct {
            id: i64,
            subscriber_uri: []const u8,
        };

        var stmt = try self.db.prepare(
            \\SELECT id, subscriber_uri FROM relay_subscriptions
            \\WHERE protocol = ? AND status = 'active'
        );
        defer stmt.deinit();

        const rows = try stmt.all(Row, allocator, .{}, .{proto_str});
        defer allocator.free(rows);

        var results = try allocator.alloc(Subscription, rows.len);
        for (rows, 0..) |row, i| {
            results[i] = .{
                .id = row.id,
                .subscriber_uri = row.subscriber_uri,
                .protocol = protocol,
                .status = .active,
            };
        }
        return results;
    }

    /// Update the last_delivered_at timestamp for a subscriber.
    pub fn markDelivered(self: *SubscriptionManager, subscriber_uri: []const u8) !void {
        try self.db.exec(
            "UPDATE relay_subscriptions SET last_delivered_at = CURRENT_TIMESTAMP WHERE subscriber_uri = ?",
            .{},
            .{subscriber_uri},
        );
    }

    /// Get subscriber count by protocol.
    pub fn getSubscriberCount(self: *SubscriptionManager, protocol: Protocol) !i64 {
        const proto_str: []const u8 = switch (protocol) {
            .activitypub => "activitypub",
            .atproto => "atproto",
        };
        const Row = struct { count: i64 };
        const result = try self.db.one(
            Row,
            "SELECT COUNT(*) as count FROM relay_subscriptions WHERE protocol = ? AND status = 'active'",
            .{},
            .{proto_str},
        );
        return if (result) |r| r.count else 0;
    }

    pub fn deinit(self: *SubscriptionManager) void {
        _ = self;
    }
};

test "subscription lifecycle" {
    const allocator = std.testing.allocator;
    var db = try database.initTestDb();
    defer db.deinit();
    try database.migrate(&db);

    var sm = SubscriptionManager.init(allocator, &db);

    // Subscribe
    try sm.subscribe("https://mastodon.social/inbox", .activitypub);
    try sm.subscribe("https://pixelfed.social/inbox", .activitypub);
    try sm.subscribe("did:plc:abc123", .atproto);

    // Count
    const ap_count = try sm.getSubscriberCount(.activitypub);
    try std.testing.expectEqual(@as(i64, 2), ap_count);

    const at_count = try sm.getSubscriberCount(.atproto);
    try std.testing.expectEqual(@as(i64, 1), at_count);

    // Get active AP subscribers
    const subs = try sm.getActiveSubscribers(allocator, .activitypub);
    defer {
        for (subs) |sub| allocator.free(sub.subscriber_uri);
        allocator.free(subs);
    }
    try std.testing.expectEqual(@as(usize, 2), subs.len);

    // Unsubscribe
    try sm.unsubscribe("https://mastodon.social/inbox");
    const after = try sm.getSubscriberCount(.activitypub);
    try std.testing.expectEqual(@as(i64, 1), after);
}

test "subscription idempotent" {
    const allocator = std.testing.allocator;
    var db = try database.initTestDb();
    defer db.deinit();
    try database.migrate(&db);

    var sm = SubscriptionManager.init(allocator, &db);

    // Subscribe twice — should not error
    try sm.subscribe("https://example.com/inbox", .activitypub);
    try sm.subscribe("https://example.com/inbox", .activitypub);

    const count = try sm.getSubscriberCount(.activitypub);
    try std.testing.expectEqual(@as(i64, 1), count);
}
