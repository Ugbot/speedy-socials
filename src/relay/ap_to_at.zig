const std = @import("std");
const database = @import("../database.zig");
const translate = @import("translate.zig");
const identity_map = @import("identity_map.zig");
const activitypub = @import("../activitypub.zig");

/// Handle an incoming ActivityPub activity for translation to AT Protocol.
/// Called from Relay.onApActivityReceived.
pub fn handleActivityReceived(
    relay: anytype, // *Relay from mod.zig
    activity_json: []const u8,
) !void {
    const allocator = relay.allocator;

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, activity_json, .{}) catch {
        std.debug.print("relay: failed to parse AP activity JSON\n", .{});
        return;
    };
    defer parsed.deinit();

    const root = parsed.value;
    if (root != .object) return;

    // Extract activity type
    const type_val = root.object.get("type") orelse return;
    const activity_type = if (type_val == .string) type_val.string else return;

    // Extract actor
    const actor_val = root.object.get("actor") orelse return;
    const actor_uri = if (actor_val == .string) actor_val.string else return;

    // Resolve AP actor to DID
    const did = try relay.id_map.actorUriToDid(allocator, actor_uri) orelse {
        std.debug.print("relay: no DID mapping for AP actor {s}, skipping\n", .{actor_uri});
        return;
    };
    defer allocator.free(did);

    if (std.mem.eql(u8, activity_type, "Create")) {
        try handleCreate(allocator, root, did);
    } else if (std.mem.eql(u8, activity_type, "Like")) {
        try handleLike(root, did);
    } else if (std.mem.eql(u8, activity_type, "Announce")) {
        try handleAnnounce(root, did);
    } else if (std.mem.eql(u8, activity_type, "Follow")) {
        try handleFollow(allocator, root, did, &relay.id_map);
    } else if (std.mem.eql(u8, activity_type, "Delete")) {
        std.debug.print("relay: AP->AT Delete translation not yet implemented\n", .{});
    } else if (std.mem.eql(u8, activity_type, "Update")) {
        std.debug.print("relay: AP->AT Update translation not yet implemented\n", .{});
    }
}

fn handleCreate(
    allocator: std.mem.Allocator,
    root: std.json.Value,
    did: []const u8,
) !void {
    // Extract the Note object
    const object_val = root.object.get("object") orelse return;
    if (object_val != .object) return;

    const content_val = object_val.object.get("content") orelse return;
    const content = if (content_val == .string) content_val.string else return;

    const published = blk: {
        const pv = object_val.object.get("published") orelse break :blk "1970-01-01T00:00:00Z";
        break :blk if (pv == .string) pv.string else "1970-01-01T00:00:00Z";
    };

    const object_id = blk: {
        const iv = object_val.object.get("id") orelse break :blk "unknown";
        break :blk if (iv == .string) iv.string else "unknown";
    };

    // Build an ApNote from the parsed fields and translate to AT post
    const in_reply_to: ?[]const u8 = blk: {
        const rv = object_val.object.get("inReplyTo") orelse break :blk null;
        break :blk if (rv == .string) rv.string else null;
    };

    const summary: ?[]const u8 = blk: {
        const sv = object_val.object.get("summary") orelse break :blk null;
        break :blk if (sv == .string) sv.string else null;
    };

    const ap_note = translate.ApNote{
        .id = object_id,
        .attributed_to = did,
        .content = content,
        .published = published,
        .in_reply_to = in_reply_to,
        .summary = summary,
    };

    const at_post = try translate.apNoteToAtPost(allocator, ap_note);
    defer {
        allocator.free(at_post.text);
        allocator.free(at_post.created_at);
        for (at_post.facets) |f| allocator.free(f.value);
        allocator.free(at_post.facets);
        if (at_post.reply_parent_uri) |uri| allocator.free(uri);
        if (at_post.reply_root_uri) |uri| allocator.free(uri);
        if (at_post.content_warning) |cw| allocator.free(cw);
    }

    // In a full implementation, this would write to the AT repo via atproto library:
    // try atproto.repo.createRecord(did, "app.bsky.feed.post", null, at_post_json);
    std.debug.print("relay: translated AP Create to AT post for {s}: {s}\n", .{ did, at_post.text });
}

fn handleLike(
    root: std.json.Value,
    did: []const u8,
) !void {
    const object_val = root.object.get("object") orelse return;
    const object_uri = if (object_val == .string) object_val.string else return;

    // In full implementation: resolve AP object URI to AT-URI, create like record
    std.debug.print("relay: AP->AT like by {s} on {s}\n", .{ did, object_uri });
}

fn handleAnnounce(
    root: std.json.Value,
    did: []const u8,
) !void {
    const object_val = root.object.get("object") orelse return;
    const object_uri = if (object_val == .string) object_val.string else return;

    std.debug.print("relay: AP->AT announce by {s} on {s}\n", .{ did, object_uri });
}

fn handleFollow(
    allocator: std.mem.Allocator,
    root: std.json.Value,
    did: []const u8,
    id_map: *identity_map.IdentityMap,
) !void {
    const object_val = root.object.get("object") orelse return;
    const target_uri = if (object_val == .string) object_val.string else return;

    // Resolve AP target to DID
    const target_did = try id_map.actorUriToDid(allocator, target_uri) orelse {
        std.debug.print("relay: cannot resolve follow target {s}\n", .{target_uri});
        return;
    };
    defer allocator.free(target_did);

    // In full implementation: create app.bsky.graph.follow record in AT repo
    std.debug.print("relay: AP->AT follow by {s} targeting {s}\n", .{ did, target_did });
}
