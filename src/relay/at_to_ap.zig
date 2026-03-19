const std = @import("std");
const database = @import("../database.zig");
const federation = @import("../federation.zig");
const activitypub = @import("../activitypub.zig");
const translate = @import("translate.zig");
const identity_map = @import("identity_map.zig");

/// Handle a new AT Protocol record creation.
/// Called from Relay.onAtRecordCreated in bridge mode.
pub fn handleRecordCreated(
    relay: anytype, // *Relay from mod.zig
    did: []const u8,
    collection: []const u8,
    rkey: []const u8,
    record_json: []const u8,
) !void {
    const allocator = relay.allocator;

    // Resolve DID to AP actor URI
    const actor_uri = try relay.id_map.didToActorUri(allocator, did) orelse {
        // Unknown DID — cannot translate without identity mapping
        std.debug.print("relay: no identity mapping for DID {s}, skipping\n", .{did});
        return;
    };
    defer allocator.free(actor_uri);

    // Generate object URI for this record
    const object_uri = try std.fmt.allocPrint(allocator, "{s}://{s}/ap/objects/{s}/{s}/{s}", .{
        activitypub.instance_scheme,
        activitypub.instance_domain,
        did,
        collection,
        rkey,
    });
    defer allocator.free(object_uri);

    // Translate based on collection type
    if (std.mem.eql(u8, collection, "app.bsky.feed.post")) {
        try handlePostCreated(allocator, relay.db, actor_uri, object_uri, record_json);
    } else if (std.mem.eql(u8, collection, "app.bsky.feed.like")) {
        try handleLikeCreated(allocator, actor_uri, object_uri, record_json);
    } else if (std.mem.eql(u8, collection, "app.bsky.feed.repost")) {
        try handleRepostCreated(allocator, actor_uri, object_uri, record_json);
    } else if (std.mem.eql(u8, collection, "app.bsky.graph.follow")) {
        try handleFollowCreated(allocator, actor_uri, object_uri, record_json, &relay.id_map);
    }
}

fn handlePostCreated(
    allocator: std.mem.Allocator,
    db: *database.Database,
    actor_uri: []const u8,
    object_uri: []const u8,
    record_json: []const u8,
) !void {
    // Parse the AT record
    const record = translate.parseAtPostRecord(allocator, record_json) catch {
        std.debug.print("relay: failed to parse AT post record\n", .{});
        return;
    };
    defer {
        allocator.free(record.text);
        allocator.free(record.created_at);
        for (record.facets) |f| allocator.free(f.value);
        allocator.free(record.facets);
        if (record.reply_parent_uri) |uri| allocator.free(uri);
        if (record.reply_root_uri) |uri| allocator.free(uri);
        for (record.langs) |l| allocator.free(l);
        allocator.free(record.langs);
        if (record.content_warning) |cw| allocator.free(cw);
    }

    // Translate to AP Note
    const note = try translate.atPostToApNote(allocator, record, actor_uri, object_uri);
    defer {
        allocator.free(note.id);
        allocator.free(note.attributed_to);
        allocator.free(note.content);
        allocator.free(note.published);
        if (note.in_reply_to) |irt| allocator.free(irt);
        if (note.summary) |s| allocator.free(s);
    }

    // Serialize as Create activity
    const activity_id = try std.fmt.allocPrint(allocator, "{s}#activity", .{object_uri});
    defer allocator.free(activity_id);

    const activity_json = try translate.createActivityToJson(allocator, activity_id, actor_uri, note);
    defer allocator.free(activity_json);

    // Deliver to followers via federation.
    // In bridge mode with a real user_id, we would resolve the DID to a local user_id.
    // For now, broadcast using the federation layer directly.
    const fed = federation.Federation.init(allocator, db);
    // Attempt delivery — broadcastToFollowers needs a local user_id.
    // In a full implementation the relay would resolve the DID to a local user row.
    // For now we log the translated activity; delivery requires wiring user resolution.
    _ = fed;
    std.debug.print("relay: translated AT post to AP Create: {s}\n", .{activity_id});
}

fn handleLikeCreated(
    allocator: std.mem.Allocator,
    actor_uri: []const u8,
    activity_uri: []const u8,
    record_json: []const u8,
) !void {
    // Parse the like record to get subject URI
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, record_json, .{}) catch return;
    defer parsed.deinit();

    const subject = parsed.value.object.get("subject") orelse return;
    if (subject != .object) return;
    const subject_uri_val = subject.object.get("uri") orelse return;
    const subject_uri = if (subject_uri_val == .string) subject_uri_val.string else return;

    // Create AP Like activity
    const like = try translate.atLikeToApLike(
        allocator,
        subject_uri,
        actor_uri,
        activity_uri,
        subject_uri, // target object URI (would need id_map translation in production)
    );
    defer {
        allocator.free(like.id);
        allocator.free(like.@"type");
        allocator.free(like.actor);
        allocator.free(like.object);
    }

    const json = try translate.apActivityToJson(allocator, like);
    defer allocator.free(json);

    std.debug.print("relay: translated AT like to AP Like: {s}\n", .{activity_uri});
}

fn handleRepostCreated(
    allocator: std.mem.Allocator,
    actor_uri: []const u8,
    activity_uri: []const u8,
    record_json: []const u8,
) !void {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, record_json, .{}) catch return;
    defer parsed.deinit();

    const subject = parsed.value.object.get("subject") orelse return;
    if (subject != .object) return;
    const subject_uri_val = subject.object.get("uri") orelse return;
    const subject_uri = if (subject_uri_val == .string) subject_uri_val.string else return;

    const announce = try translate.atRepostToApAnnounce(
        allocator,
        subject_uri,
        actor_uri,
        activity_uri,
        subject_uri,
    );
    defer {
        allocator.free(announce.id);
        allocator.free(announce.@"type");
        allocator.free(announce.actor);
        allocator.free(announce.object);
    }

    const json = try translate.apActivityToJson(allocator, announce);
    defer allocator.free(json);

    std.debug.print("relay: translated AT repost to AP Announce: {s}\n", .{activity_uri});
}

fn handleFollowCreated(
    allocator: std.mem.Allocator,
    actor_uri: []const u8,
    activity_uri: []const u8,
    record_json: []const u8,
    id_map: *identity_map.IdentityMap,
) !void {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, record_json, .{}) catch return;
    defer parsed.deinit();

    const subject_val = parsed.value.object.get("subject") orelse return;
    const subject_did = if (subject_val == .string) subject_val.string else return;

    // Resolve target DID to AP actor URI
    const target_uri = try id_map.didToActorUri(allocator, subject_did) orelse {
        std.debug.print("relay: cannot resolve follow target DID {s}\n", .{subject_did});
        return;
    };
    defer allocator.free(target_uri);

    const follow = try translate.atFollowToApFollow(
        allocator,
        subject_did,
        actor_uri,
        activity_uri,
        target_uri,
    );
    defer {
        allocator.free(follow.id);
        allocator.free(follow.@"type");
        allocator.free(follow.actor);
        allocator.free(follow.object);
    }

    const json = try translate.apActivityToJson(allocator, follow);
    defer allocator.free(json);

    std.debug.print("relay: translated AT follow to AP Follow: {s}\n", .{activity_uri});
}
