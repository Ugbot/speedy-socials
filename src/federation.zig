const std = @import("std");
const http = std.http;
const compat = @import("compat.zig");
const database = @import("database.zig");
const activitypub = @import("activitypub.zig");
const crypto_sig = @import("crypto_sig.zig");

// Federation delivery system for ActivityPub
pub const Federation = struct {
    allocator: std.mem.Allocator,
    db: *database.Database,

    pub fn init(allocator: std.mem.Allocator, db: *database.Database) Federation {
        return Federation{
            .allocator = allocator,
            .db = db,
        };
    }

    // Deliver activity to remote inbox with real Ed25519 HTTP signature
    pub fn deliverActivity(self: *Federation, activity_json: []const u8, inbox_url: []const u8, secret_key: [64]u8, key_id: []const u8) !void {
        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        const uri = try std.Uri.parse(inbox_url);

        // Generate proper HTTP Date header
        const now = std.time.timestamp();
        const date_str = try activitypub.formatHttpDate(self.allocator, now);
        defer self.allocator.free(date_str);

        // Generate SHA-256 digest of the body
        const digest = try crypto_sig.generateDigest(self.allocator, activity_json);
        defer self.allocator.free(digest);

        var host_buf: [std.Uri.host_name_max]u8 = undefined;
        const host = uri.getHost(&host_buf) catch return error.InvalidUri;

        const path = uri.path.percent_encoded;

        // Generate Ed25519 HTTP signature
        const signature_header = try crypto_sig.signRequest(
            self.allocator,
            secret_key,
            key_id,
            "POST",
            path,
            host,
            date_str,
            digest,
        );
        defer self.allocator.free(signature_header);

        // Use fetch for simplicity
        const result = try client.fetch(.{
            .location = .{ .uri = uri },
            .method = .POST,
            .payload = activity_json,
            .extra_headers = &.{
                .{ .name = "Date", .value = date_str },
                .{ .name = "Digest", .value = digest },
                .{ .name = "Signature", .value = signature_header },
                .{ .name = "User-Agent", .value = "SpeedySocials/1.0" },
            },
            .headers = .{
                .content_type = .{ .override = "application/activity+json" },
            },
            .keep_alive = false,
        });

        if (result.status != .ok and result.status != .created and result.status != .accepted) {
            std.debug.print("Federation delivery failed: {} to {s}\n", .{ result.status, inbox_url });
            return error.DeliveryFailed;
        }

        std.debug.print("Successfully delivered activity to {s}\n", .{inbox_url});
    }

    // Get followers' inboxes from the database (deduplicated, preferring shared inbox)
    pub fn getFollowersInboxes(self: *Federation, user_id: i64) ![]const []const u8 {
        return database.getRemoteFollowerInboxes(self.db, self.allocator, user_id);
    }

    // Broadcast activity to all followers of a local user
    pub fn broadcastToFollowers(self: *Federation, activity_json: []const u8, user_id: i64) !void {
        // Get the user's signing key
        const key_pair = try database.ensureActorKeyPair(self.db, self.allocator, user_id);
        defer self.allocator.free(key_pair.public_key_pem);

        // Build key ID
        const user = (try database.getUserById(self.db, self.allocator, user_id)) orelse return;
        defer {
            self.allocator.free(user.username);
            self.allocator.free(user.email);
            if (user.display_name) |dn| self.allocator.free(dn);
            if (user.bio) |bio| self.allocator.free(bio);
            if (user.avatar_url) |au| self.allocator.free(au);
            if (user.header_url) |hu| self.allocator.free(hu);
            self.allocator.free(user.created_at);
        }

        const actor_id = try activitypub.getUserActivityPubId(self.allocator, user.username);
        defer self.allocator.free(actor_id);
        const key_id = try std.fmt.allocPrint(self.allocator, "{s}#main-key", .{actor_id});
        defer self.allocator.free(key_id);

        const inboxes = try self.getFollowersInboxes(user_id);
        defer {
            for (inboxes) |inbox| self.allocator.free(inbox);
            self.allocator.free(inboxes);
        }

        for (inboxes) |inbox_url| {
            self.deliverActivity(activity_json, inbox_url, key_pair.private_key_raw, key_id) catch |err| {
                std.debug.print("Failed to deliver to {s}: {}\n", .{ inbox_url, err });
            };
        }
    }

    // Handle incoming federation request (ActivityPub inbox)
    pub fn handleInbox(self: *Federation, response: anytype, request: *http.Server.Request) !void {
        var read_buf: [8192]u8 = undefined;
        const reader = request.readerExpectNone(&read_buf);
        const body = reader.allocRemaining(self.allocator, std.io.Limit.limited(1024 * 1024)) catch {
            try response.writer.writeAll("{\"error\": \"Failed to read request body\"}");
            return;
        };
        defer self.allocator.free(body);

        // Parse the incoming ActivityPub activity
        var parsed = std.json.parseFromSlice(std.json.Value, self.allocator, body, .{}) catch {
            try response.writer.writeAll("{\"error\": \"Invalid JSON\"}");
            return;
        };
        defer parsed.deinit();

        // Extract activity ID for dedup
        const activity_id = if (parsed.value.object.get("id")) |id_val| switch (id_val) {
            .string => |str| str,
            else => null,
        } else null;

        // Check for duplicate activity
        if (activity_id) |aid| {
            if (try database.isActivityProcessed(self.db, aid)) {
                try response.writer.writeAll("{\"status\": \"already processed\"}");
                return;
            }
        }

        // Determine activity type and dispatch
        const activity_type = if (parsed.value.object.get("type")) |t| switch (t) {
            .string => |str| str,
            else => {
                try response.writer.writeAll("{\"error\": \"Invalid activity type\"}");
                return;
            },
        } else {
            try response.writer.writeAll("{\"error\": \"Missing activity type\"}");
            return;
        };

        // Extract actor URI for dedup logging
        const actor_uri = if (parsed.value.object.get("actor")) |a| switch (a) {
            .string => |str| str,
            else => "",
        } else "";

        // Dispatch to handlers
        if (std.mem.eql(u8, activity_type, "Follow")) {
            self.handleFollow(&parsed.value) catch |err| {
                std.debug.print("Error handling Follow: {}\n", .{err});
            };
        } else if (std.mem.eql(u8, activity_type, "Create")) {
            self.handleCreate(&parsed.value) catch |err| {
                std.debug.print("Error handling Create: {}\n", .{err});
            };
        } else if (std.mem.eql(u8, activity_type, "Like")) {
            self.handleLike(&parsed.value) catch |err| {
                std.debug.print("Error handling Like: {}\n", .{err});
            };
        } else if (std.mem.eql(u8, activity_type, "Announce")) {
            self.handleAnnounce(&parsed.value) catch |err| {
                std.debug.print("Error handling Announce: {}\n", .{err});
            };
        } else if (std.mem.eql(u8, activity_type, "Accept")) {
            self.handleAccept(&parsed.value) catch |err| {
                std.debug.print("Error handling Accept: {}\n", .{err});
            };
        } else if (std.mem.eql(u8, activity_type, "Reject")) {
            self.handleReject(&parsed.value) catch |err| {
                std.debug.print("Error handling Reject: {}\n", .{err});
            };
        } else if (std.mem.eql(u8, activity_type, "Undo")) {
            self.handleUndo(&parsed.value) catch |err| {
                std.debug.print("Error handling Undo: {}\n", .{err});
            };
        } else if (std.mem.eql(u8, activity_type, "Update")) {
            self.handleUpdate(&parsed.value) catch |err| {
                std.debug.print("Error handling Update: {}\n", .{err});
            };
        } else if (std.mem.eql(u8, activity_type, "Delete")) {
            self.handleDelete(&parsed.value) catch |err| {
                std.debug.print("Error handling Delete: {}\n", .{err});
            };
        } else {
            std.debug.print("Received unhandled activity type: {s}\n", .{activity_type});
        }

        // Mark activity as processed for dedup
        if (activity_id) |aid| {
            database.markActivityProcessed(self.db, aid, activity_type, actor_uri, null) catch {};
        }

        try response.writer.writeAll("{\"status\": \"accepted\"}");
    }

    // =========================================================================
    // Incoming Activity Handlers
    // =========================================================================

    /// Handle incoming Follow activity.
    /// Extracts actor (remote) and object (local user), creates a federation follow,
    /// and auto-accepts if the local user is not locked.
    fn handleFollow(self: *Federation, activity: *std.json.Value) !void {
        const actor_uri = try getJsonString(activity, "actor") orelse return;
        const object_uri = try getJsonStringOrObjectId(self.allocator, activity, "object") orelse return;
        defer if (getJsonStringOrObjectId(self.allocator, activity, "object") catch null) |_| {} else self.allocator.free(object_uri);
        const activity_uri = try getJsonString(activity, "id") orelse return;

        // Parse local username from the object URI
        const users_prefix = try std.fmt.allocPrint(self.allocator, "{s}://{s}/users/", .{ activitypub.instance_scheme, activitypub.instance_domain });
        defer self.allocator.free(users_prefix);

        if (!std.mem.startsWith(u8, object_uri, users_prefix)) {
            std.debug.print("Follow target is not a local user: {s}\n", .{object_uri});
            return;
        }

        const username = object_uri[users_prefix.len..];
        const local_user = (try database.getUserByUsername(self.db, self.allocator, username)) orelse {
            std.debug.print("Follow target user not found: {s}\n", .{username});
            return;
        };
        defer {
            self.allocator.free(local_user.username);
            self.allocator.free(local_user.email);
            if (local_user.display_name) |dn| self.allocator.free(dn);
            if (local_user.bio) |bio| self.allocator.free(bio);
            if (local_user.avatar_url) |au| self.allocator.free(au);
            if (local_user.header_url) |hu| self.allocator.free(hu);
            self.allocator.free(local_user.created_at);
        }

        // Extract domain from actor URI
        const domain = extractDomainFromUri(actor_uri) orelse "unknown";

        // Build inbox URL from actor URI (best guess: actor_uri + /inbox)
        const inbox_url = try std.fmt.allocPrint(self.allocator, "{s}/inbox", .{actor_uri});
        defer self.allocator.free(inbox_url);

        // Get or create remote actor
        const remote_actor = try database.getOrCreateRemoteActor(self.db, self.allocator, actor_uri, inbox_url, domain);
        defer {
            self.allocator.free(remote_actor.actor_uri);
            self.allocator.free(remote_actor.inbox_url);
            self.allocator.free(remote_actor.domain);
        }

        // Create the federation follow record
        database.createFederationFollow(self.db, local_user.id, remote_actor.id, activity_uri, "inbound") catch |err| {
            if (err == error.SQLiteError) {
                std.debug.print("Follow already exists for activity: {s}\n", .{activity_uri});
                return;
            }
            return err;
        };

        // Auto-accept if the local user is not locked
        if (!local_user.is_locked) {
            try database.updateFederationFollowStatus(self.db, activity_uri, "accepted");

            // Queue Accept activity delivery
            const accept_json = try std.fmt.allocPrint(self.allocator,
                \\{{"@context":"https://www.w3.org/ns/activitystreams","id":"{s}://{s}/activities/accept-{s}","type":"Accept","actor":"{s}","object":{{"id":"{s}","type":"Follow","actor":"{s}","object":"{s}"}}}}
            , .{
                activitypub.instance_scheme,
                activitypub.instance_domain,
                activity_uri,
                object_uri,
                activity_uri,
                actor_uri,
                object_uri,
            });
            defer self.allocator.free(accept_json);

            // Deliver accept to the remote actor's inbox
            const key_pair = database.ensureActorKeyPair(self.db, self.allocator, local_user.id) catch return;
            defer self.allocator.free(key_pair.public_key_pem);

            const key_id = try std.fmt.allocPrint(self.allocator, "{s}#main-key", .{object_uri});
            defer self.allocator.free(key_id);

            self.deliverActivity(accept_json, inbox_url, key_pair.private_key_raw, key_id) catch |err| {
                std.debug.print("Failed to deliver Accept to {s}: {}\n", .{ inbox_url, err });
            };
        }

        std.debug.print("Processed Follow from {s} to {s}\n", .{ actor_uri, username });
    }

    /// Handle incoming Create activity (typically a Note).
    fn handleCreate(self: *Federation, activity: *std.json.Value) !void {
        const actor_uri = try getJsonString(activity, "actor") orelse return;

        // Extract the nested object
        const object = activity.object.get("object") orelse return;
        if (object != .object) return;

        // Check it's a Note
        const obj_type_val = object.object.get("type") orelse return;
        if (obj_type_val != .string or !std.mem.eql(u8, obj_type_val.string, "Note")) return;

        const post_uri = if (object.object.get("id")) |id_val| switch (id_val) {
            .string => |str| str,
            else => return,
        } else return;

        const content = if (object.object.get("content")) |c| switch (c) {
            .string => |str| str,
            else => return,
        } else return;

        const content_warning: ?[]const u8 = if (object.object.get("summary")) |s| switch (s) {
            .string => |str| str,
            else => null,
        } else null;

        const in_reply_to: ?[]const u8 = if (object.object.get("inReplyTo")) |r| switch (r) {
            .string => |str| str,
            else => null,
        } else null;

        const published: ?[]const u8 = if (object.object.get("published")) |p| switch (p) {
            .string => |str| str,
            else => null,
        } else null;

        // Get or create remote actor
        const domain = extractDomainFromUri(actor_uri) orelse "unknown";
        const inbox_url = try std.fmt.allocPrint(self.allocator, "{s}/inbox", .{actor_uri});
        defer self.allocator.free(inbox_url);

        const remote_actor = try database.getOrCreateRemoteActor(self.db, self.allocator, actor_uri, inbox_url, domain);
        defer {
            self.allocator.free(remote_actor.actor_uri);
            self.allocator.free(remote_actor.inbox_url);
            self.allocator.free(remote_actor.domain);
        }

        // Store the remote post
        database.createRemotePost(self.db, post_uri, remote_actor.id, content, content_warning, in_reply_to, published) catch |err| {
            if (err == error.SQLiteError) {
                std.debug.print("Remote post already exists: {s}\n", .{post_uri});
                return;
            }
            return err;
        };

        std.debug.print("Stored remote post from {s}: {s}\n", .{ actor_uri, post_uri });
    }

    /// Handle incoming Like activity.
    fn handleLike(self: *Federation, activity: *std.json.Value) !void {
        const actor_uri = try getJsonString(activity, "actor") orelse return;
        const object_uri = try getJsonStringOrObjectId(self.allocator, activity, "object") orelse return;
        const activity_uri = try getJsonString(activity, "id") orelse return;

        // Check if the liked object is a local post
        const posts_prefix = try std.fmt.allocPrint(self.allocator, "{s}://{s}/posts/", .{ activitypub.instance_scheme, activitypub.instance_domain });
        defer self.allocator.free(posts_prefix);

        if (!std.mem.startsWith(u8, object_uri, posts_prefix)) {
            std.debug.print("Liked object is not a local post: {s}\n", .{object_uri});
            return;
        }

        const post_id_str = object_uri[posts_prefix.len..];
        const local_post_id = std.fmt.parseInt(i64, post_id_str, 10) catch return;

        // Get or create remote actor
        const domain = extractDomainFromUri(actor_uri) orelse "unknown";
        const inbox_url = try std.fmt.allocPrint(self.allocator, "{s}/inbox", .{actor_uri});
        defer self.allocator.free(inbox_url);

        const remote_actor = try database.getOrCreateRemoteActor(self.db, self.allocator, actor_uri, inbox_url, domain);
        defer {
            self.allocator.free(remote_actor.actor_uri);
            self.allocator.free(remote_actor.inbox_url);
            self.allocator.free(remote_actor.domain);
        }

        database.createRemoteInteraction(self.db, activity_uri, remote_actor.id, local_post_id, "like") catch |err| {
            if (err == error.SQLiteError) return;
            return err;
        };

        std.debug.print("Recorded like from {s} on post {}\n", .{ actor_uri, local_post_id });
    }

    /// Handle incoming Announce (boost/reblog) activity.
    fn handleAnnounce(self: *Federation, activity: *std.json.Value) !void {
        const actor_uri = try getJsonString(activity, "actor") orelse return;
        const object_uri = try getJsonStringOrObjectId(self.allocator, activity, "object") orelse return;
        const activity_uri = try getJsonString(activity, "id") orelse return;

        // Check if the announced object is a local post
        const posts_prefix = try std.fmt.allocPrint(self.allocator, "{s}://{s}/posts/", .{ activitypub.instance_scheme, activitypub.instance_domain });
        defer self.allocator.free(posts_prefix);

        if (!std.mem.startsWith(u8, object_uri, posts_prefix)) return;

        const post_id_str = object_uri[posts_prefix.len..];
        const local_post_id = std.fmt.parseInt(i64, post_id_str, 10) catch return;

        const domain = extractDomainFromUri(actor_uri) orelse "unknown";
        const inbox_url = try std.fmt.allocPrint(self.allocator, "{s}/inbox", .{actor_uri});
        defer self.allocator.free(inbox_url);

        const remote_actor = try database.getOrCreateRemoteActor(self.db, self.allocator, actor_uri, inbox_url, domain);
        defer {
            self.allocator.free(remote_actor.actor_uri);
            self.allocator.free(remote_actor.inbox_url);
            self.allocator.free(remote_actor.domain);
        }

        database.createRemoteInteraction(self.db, activity_uri, remote_actor.id, local_post_id, "announce") catch |err| {
            if (err == error.SQLiteError) return;
            return err;
        };

        std.debug.print("Recorded announce from {s} on post {}\n", .{ actor_uri, local_post_id });
    }

    /// Handle incoming Accept activity (typically accepting our outbound Follow).
    fn handleAccept(self: *Federation, activity: *std.json.Value) !void {
        // The object should be the Follow activity we sent
        const inner_obj = activity.object.get("object") orelse return;
        const follow_uri = switch (inner_obj) {
            .string => |str| str,
            .object => |obj| if (obj.get("id")) |id_val| switch (id_val) {
                .string => |str| str,
                else => return,
            } else return,
            else => return,
        };

        // Update the outbound follow status to accepted
        database.updateFederationFollowStatus(self.db, follow_uri, "accepted") catch |err| {
            std.debug.print("Failed to update follow status for {s}: {}\n", .{ follow_uri, err });
            return;
        };

        std.debug.print("Follow accepted: {s}\n", .{follow_uri});
    }

    /// Handle incoming Reject activity (rejecting our outbound Follow).
    fn handleReject(self: *Federation, activity: *std.json.Value) !void {
        const inner_obj = activity.object.get("object") orelse return;
        const follow_uri = switch (inner_obj) {
            .string => |str| str,
            .object => |obj| if (obj.get("id")) |id_val| switch (id_val) {
                .string => |str| str,
                else => return,
            } else return,
            else => return,
        };

        database.updateFederationFollowStatus(self.db, follow_uri, "rejected") catch |err| {
            std.debug.print("Failed to update follow status for {s}: {}\n", .{ follow_uri, err });
            return;
        };

        std.debug.print("Follow rejected: {s}\n", .{follow_uri});
    }

    /// Handle incoming Undo activity. Determines inner type and deletes the corresponding record.
    fn handleUndo(self: *Federation, activity: *std.json.Value) !void {
        const inner_obj = activity.object.get("object") orelse return;
        if (inner_obj != .object) return;

        const inner_type = if (inner_obj.object.get("type")) |t| switch (t) {
            .string => |str| str,
            else => return,
        } else return;

        const inner_uri = if (inner_obj.object.get("id")) |id_val| switch (id_val) {
            .string => |str| str,
            else => return,
        } else return;

        if (std.mem.eql(u8, inner_type, "Follow")) {
            // Undo a follow: delete the federation follow record
            database.deleteFederationFollow(self.db, inner_uri) catch {};
            std.debug.print("Undid follow: {s}\n", .{inner_uri});
        } else if (std.mem.eql(u8, inner_type, "Like")) {
            // Undo a like: delete the remote interaction
            database.deleteRemoteInteraction(self.db, inner_uri) catch {};
            std.debug.print("Undid like: {s}\n", .{inner_uri});
        } else if (std.mem.eql(u8, inner_type, "Announce")) {
            // Undo an announce: delete the remote interaction
            database.deleteRemoteInteraction(self.db, inner_uri) catch {};
            std.debug.print("Undid announce: {s}\n", .{inner_uri});
        } else {
            std.debug.print("Unhandled Undo inner type: {s}\n", .{inner_type});
        }
    }

    /// Handle incoming Update activity. Updates remote actor profile or remote post.
    fn handleUpdate(self: *Federation, activity: *std.json.Value) !void {
        const inner_obj = activity.object.get("object") orelse return;
        if (inner_obj != .object) return;

        const inner_type = if (inner_obj.object.get("type")) |t| switch (t) {
            .string => |str| str,
            else => return,
        } else return;

        if (std.mem.eql(u8, inner_type, "Person") or std.mem.eql(u8, inner_type, "Service")) {
            // Update remote actor
            const actor_uri = if (inner_obj.object.get("id")) |id_val| switch (id_val) {
                .string => |str| str,
                else => return,
            } else return;

            const existing = (try database.getRemoteActorByUri(self.db, self.allocator, actor_uri)) orelse return;
            defer {
                self.allocator.free(existing.actor_uri);
                self.allocator.free(existing.inbox_url);
                self.allocator.free(existing.domain);
            }

            // Update public key if present
            if (inner_obj.object.get("publicKey")) |pk_obj| {
                if (pk_obj == .object) {
                    const pem = if (pk_obj.object.get("publicKeyPem")) |p| switch (p) {
                        .string => |str| str,
                        else => null,
                    } else null;
                    const pk_id = if (pk_obj.object.get("id")) |p| switch (p) {
                        .string => |str| str,
                        else => null,
                    } else null;

                    if (pem != null and pk_id != null) {
                        try database.updateRemoteActorKey(self.db, existing.id, pem.?, pk_id.?);
                    }
                }
            }

            std.debug.print("Updated remote actor: {s}\n", .{actor_uri});
        } else if (std.mem.eql(u8, inner_type, "Note")) {
            // For Note updates, delete the old and re-create
            const post_uri = if (inner_obj.object.get("id")) |id_val| switch (id_val) {
                .string => |str| str,
                else => return,
            } else return;

            // Delete old version
            database.deleteRemotePost(self.db, post_uri) catch {};

            // Re-create with updated content
            const actor_uri = try getJsonString(activity, "actor") orelse return;
            const content = if (inner_obj.object.get("content")) |c| switch (c) {
                .string => |str| str,
                else => return,
            } else return;

            const domain = extractDomainFromUri(actor_uri) orelse "unknown";
            const inbox_url = try std.fmt.allocPrint(self.allocator, "{s}/inbox", .{actor_uri});
            defer self.allocator.free(inbox_url);

            const remote_actor = try database.getOrCreateRemoteActor(self.db, self.allocator, actor_uri, inbox_url, domain);
            defer {
                self.allocator.free(remote_actor.actor_uri);
                self.allocator.free(remote_actor.inbox_url);
                self.allocator.free(remote_actor.domain);
            }

            database.createRemotePost(self.db, post_uri, remote_actor.id, content, null, null, null) catch {};
            std.debug.print("Updated remote post: {s}\n", .{post_uri});
        }
    }

    /// Handle incoming Delete activity. Deletes remote posts or marks actors as tombstoned.
    fn handleDelete(self: *Federation, activity: *std.json.Value) !void {
        const object_val = activity.object.get("object") orelse return;

        const object_uri = switch (object_val) {
            .string => |str| str,
            .object => |obj| if (obj.get("id")) |id_val| switch (id_val) {
                .string => |str| str,
                else => return,
            } else return,
            else => return,
        };

        // Try to delete as remote post first
        database.deleteRemotePost(self.db, object_uri) catch {};

        std.debug.print("Processed Delete for: {s}\n", .{object_uri});
    }

    // =========================================================================
    // WebFinger
    // =========================================================================

    /// Send WebFinger response for user discovery.
    /// Verifies the user exists before returning a response.
    pub fn handleWebFinger(self: *Federation, response: anytype, resource: []const u8) !void {
        const acct_prefix = "acct:";
        if (!std.mem.startsWith(u8, resource, acct_prefix)) {
            try response.writer.writeAll("{\"error\": \"Invalid resource format\"}");
            return;
        }

        const acct_part = resource[acct_prefix.len..];
        const at_pos = std.mem.indexOf(u8, acct_part, "@") orelse {
            try response.writer.writeAll("{\"error\": \"Invalid account format\"}");
            return;
        };

        const username = acct_part[0..at_pos];
        const domain = acct_part[at_pos + 1 ..];

        // Verify domain matches our instance
        if (!std.mem.eql(u8, domain, activitypub.instance_domain)) {
            try response.writer.writeAll("{\"error\": \"User not found\"}");
            return;
        }

        // Verify the user actually exists in the database
        const user = (try database.getUserByUsername(self.db, self.allocator, username)) orelse {
            try response.writer.writeAll("{\"error\": \"User not found\"}");
            return;
        };
        defer {
            self.allocator.free(user.username);
            self.allocator.free(user.email);
            if (user.display_name) |dn| self.allocator.free(dn);
            if (user.bio) |bio| self.allocator.free(bio);
            if (user.avatar_url) |au| self.allocator.free(au);
            if (user.header_url) |hu| self.allocator.free(hu);
            self.allocator.free(user.created_at);
        }

        const profile_url = try std.fmt.allocPrint(self.allocator, "{s}://{s}/users/{s}", .{ activitypub.instance_scheme, activitypub.instance_domain, username });
        defer self.allocator.free(profile_url);

        const atom_url = try std.fmt.allocPrint(self.allocator, "{s}://{s}/users/{s}.atom", .{ activitypub.instance_scheme, activitypub.instance_domain, username });
        defer self.allocator.free(atom_url);

        const webfinger = struct {
            subject: []const u8,
            links: []const struct {
                rel: []const u8,
                type: []const u8,
                href: []const u8,
            },
        }{
            .subject = resource,
            .links = &.{
                .{
                    .rel = "http://webfinger.net/rel/profile-page",
                    .type = "text/html",
                    .href = profile_url,
                },
                .{
                    .rel = "http://schemas.google.com/g/2010#updates-from",
                    .type = "application/atom+xml",
                    .href = atom_url,
                },
                .{
                    .rel = "self",
                    .type = "application/activity+json",
                    .href = profile_url,
                },
            },
        };

        var json_buf = std.array_list.Managed(u8).init(self.allocator);
        defer json_buf.deinit();

        try compat.jsonStringify(webfinger, .{}, json_buf.writer());
        try response.writer.writeAll(json_buf.items);
    }
};

// =========================================================================
// Helper functions
// =========================================================================

/// Extract a string value from a JSON object by key.
fn getJsonString(value: *std.json.Value, key: []const u8) !?[]const u8 {
    const field = value.object.get(key) orelse return null;
    return switch (field) {
        .string => |str| str,
        else => null,
    };
}

/// Extract a string from a field that might be a plain string URI or an object with an "id" field.
fn getJsonStringOrObjectId(allocator: std.mem.Allocator, value: *std.json.Value, key: []const u8) !?[]const u8 {
    _ = allocator;
    const field = value.object.get(key) orelse return null;
    return switch (field) {
        .string => |str| str,
        .object => |obj| if (obj.get("id")) |id_val| switch (id_val) {
            .string => |str| str,
            else => null,
        } else null,
        else => null,
    };
}

/// Extract domain from a URI like "https://mastodon.social/users/alice"
fn extractDomainFromUri(uri: []const u8) ?[]const u8 {
    // Skip scheme
    const after_scheme = if (std.mem.indexOf(u8, uri, "://")) |pos| uri[pos + 3 ..] else return null;
    // Find the first slash after the domain
    const domain_end = std.mem.indexOf(u8, after_scheme, "/") orelse after_scheme.len;
    if (domain_end == 0) return null;
    return after_scheme[0..domain_end];
}
