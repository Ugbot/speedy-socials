const std = @import("std");
const http = std.http;
const database = @import("database.zig");
const activitypub = @import("activitypub.zig");
const crypto = std.crypto;

// Federation delivery system for ActivityPub
pub const Federation = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Federation {
        return Federation{
            .allocator = allocator,
        };
    }

    // Deliver activity to remote inbox
    pub fn deliverActivity(self: *Federation, activity_json: []const u8, inbox_url: []const u8, private_key_pem: []const u8, key_id: []const u8) !void {
        // Create HTTP client
        var client = std.http.Client{ .allocator = self.allocator };
        defer client.deinit();

        // Prepare request
        const uri = try std.Uri.parse(inbox_url);

        // Generate date header
        const now = std.time.timestamp();
        const date_str = try self.formatTimestamp(now);
        defer self.allocator.free(date_str);

        // Generate digest
        const digest = try self.generateDigest(activity_json);
        defer self.allocator.free(digest);

        // Generate signature
        const signature = try self.generateHttpSignature(private_key_pem, key_id, "POST", uri.path, uri.host.?, date_str, digest);
        defer self.allocator.free(signature);

        // Create signature header
        const signature_header = try std.fmt.allocPrint(self.allocator,
            \\keyId="{s}",algorithm="rsa-sha256",headers="(request-target) host date digest",signature="{s}"
        , .{ key_id, signature });
        defer self.allocator.free(signature_header);

        // Make request
        const headers = [_]std.http.Header{
            .{ .name = "Host", .value = uri.host.? },
            .{ .name = "Date", .value = date_str },
            .{ .name = "Digest", .value = digest },
            .{ .name = "Signature", .value = signature_header },
            .{ .name = "Content-Type", .value = "application/activity+json" },
            .{ .name = "User-Agent", .value = "SpeedySocials/1.0" },
        };

        var req = try client.request(.POST, uri, .{ .headers = &headers, .keep_alive = false });
        defer req.deinit();

        // Write body
        req.transfer_encoding = .chunked;
        try req.start();
        _ = try req.writer().write(activity_json);
        try req.finish();

        // Read response
        try req.wait();

        if (req.response.status != .ok and req.response.status != .created and req.response.status != .accepted) {
            std.debug.print("Federation delivery failed: {} to {s}\n", .{ req.response.status, inbox_url });
            return error.DeliveryFailed;
        }

        std.debug.print("Successfully delivered activity to {s}\n", .{inbox_url});
    }

    // Generate SHA-256 digest for HTTP signature
    fn generateDigest(self: *Federation, body: []const u8) ![]u8 {
        var hash: [32]u8 = undefined;
        crypto.hash.sha2.Sha256.hash(body, &hash);

        var digest_buf = std.array_list.Managed(u8).init(self.allocator);
        errdefer digest_buf.deinit();

        try digest_buf.appendSlice("SHA-256=");
        const encoder = std.base64.standard.Encoder;
        try encoder.encodeWriter(digest_buf.writer(), &hash);

        return digest_buf.toOwnedSlice();
    }

    // Generate HTTP signature (simplified - uses placeholder signature)
    fn generateHttpSignature(self: *Federation, _: []const u8, _: []const u8, method: []const u8, target: []const u8, host: []const u8, date: []const u8, digest: []const u8) ![]u8 {

        // Create signing string
        var signing_string = std.array_list.Managed(u8).init(self.allocator);
        defer signing_string.deinit();

        try std.fmt.format(signing_string.writer(), "(request-target): {s} {s}\n", .{ std.ascii.lowerString(self.allocator, method), target });
        try std.fmt.format(signing_string.writer(), "host: {s}\n", .{host});
        try std.fmt.format(signing_string.writer(), "date: {s}\n", .{date});
        try std.fmt.format(signing_string.writer(), "digest: {s}\n", .{digest});

        // Generate placeholder signature (random bytes for demo)
        var signature_bytes: [256]u8 = undefined;
        crypto.random.bytes(&signature_bytes);

        var signature_b64 = std.array_list.Managed(u8).init(self.allocator);
        errdefer signature_b64.deinit();

        const encoder = std.base64.standard.Encoder;
        try encoder.encodeWriter(signature_b64.writer(), &signature_bytes);

        return signature_b64.toOwnedSlice();
    }

    // Format timestamp as HTTP date
    fn formatTimestamp(self: *Federation, timestamp: i64) ![]u8 {
        // Simplified timestamp formatting
        return std.fmt.allocPrint(self.allocator, "{}", .{timestamp});
    }

    // Get followers' inboxes for activity delivery
    pub fn getFollowersInboxes(self: *Federation, _: *database.Database, _: i64) ![]const []const u8 {
        var inboxes = std.array_list.Managed([]const u8).init(self.allocator);
        errdefer {
            for (inboxes.items) |inbox| self.allocator.free(inbox);
            inboxes.deinit();
        }

        // Query followers and their shared inboxes
        // This is a simplified version - in real implementation, you'd query the database
        // for followers and their ActivityPub inboxes

        // For demo, return some example inboxes
        try inboxes.append(try self.allocator.dupe(u8, "https://mastodon.social/inbox"));
        try inboxes.append(try self.allocator.dupe(u8, "https://pixelfed.social/inbox"));

        return inboxes.toOwnedSlice();
    }

    // Broadcast activity to all followers
    pub fn broadcastToFollowers(self: *Federation, db: *database.Database, job_queue: anytype, activity_json: []const u8, user_id: i64, private_key_pem: []const u8, key_id: []const u8) !void {
        const inboxes = try self.getFollowersInboxes(db, user_id);
        defer {
            for (inboxes) |inbox| self.allocator.free(inbox);
            self.allocator.free(inboxes);
        }

        for (inboxes) |inbox_url| {
            // Queue delivery job
            try self.queueActivityDelivery(job_queue, activity_json, inbox_url, private_key_pem, key_id);
        }
    }

    // Queue activity for delivery to remote server
    pub fn queueActivityDelivery(self: *Federation, _: anytype, activity_json: []const u8, inbox_url: []const u8, private_key_pem: []const u8, key_id: []const u8) !void {
        const job = activitypub.DeliveryJob{
            .activity_json = try self.allocator.dupe(u8, activity_json),
            .inbox_url = try self.allocator.dupe(u8, inbox_url),
            .private_key_pem = try self.allocator.dupe(u8, private_key_pem),
            .key_id = try self.allocator.dupe(u8, key_id),
        };

        // Add to job queue (simplified - in real implementation, pass to job system)
        _ = job;
        std.debug.print("Queued activity delivery to {s}\n", .{inbox_url});
    }

    // Process federation delivery job
    pub fn processDeliveryJob(self: *Federation, job: activitypub.DeliveryJob) !void {
        defer job.deinit(self.allocator);

        try self.deliverActivity(job.activity_json, job.inbox_url, job.private_key_pem, job.key_id);
    }

    // Handle incoming federation request (ActivityPub inbox)
    pub fn handleInbox(self: *Federation, db: *database.Database, response: anytype, request: *http.Server.Request) !void {
        // Read request body
        var body_buf = std.array_list.Managed(u8).init(self.allocator);
        defer body_buf.deinit();

        try request.reader().readAllArrayList(&body_buf, 1024 * 1024); // 1MB limit

        // Parse ActivityPub activity
        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, body_buf.items, .{});
        defer parsed.deinit();

        const activity_type = parsed.value.object.get("type") orelse {
            response.status = .bad_request;
            try response.writer().writeAll("{\"error\": \"Missing activity type\"}");
            return;
        };

        if (activity_type != .string) {
            response.status = .bad_request;
            try response.writer().writeAll("{\"error\": \"Invalid activity type\"}");
            return;
        }

        // Handle different activity types
        if (std.mem.eql(u8, activity_type.string, "Follow")) {
            try self.handleFollow(db, &parsed.value);
        } else if (std.mem.eql(u8, activity_type.string, "Create")) {
            try self.handleCreate(db, &parsed.value);
        } else if (std.mem.eql(u8, activity_type.string, "Like")) {
            try self.handleLike(db, &parsed.value);
        } else {
            // Accept other activities but don't process them
            std.debug.print("Received unhandled activity type: {s}\n", .{activity_type.string});
        }

        // Return 202 Accepted for federation requests
        response.status = .accepted;
        try response.writer().writeAll("{}");
    }

    // Handle incoming Follow activity
    fn handleFollow(_: *Federation, _: *database.Database, activity: *std.json.Value) !void {
        // Extract actor and object
        const actor = activity.object.get("actor") orelse return;
        const object = activity.object.get("object") orelse return;

        if (actor != .string or object != .string) return;

        // TODO: Store follow relationship in database
        // TODO: Send Accept activity back to follower

        std.debug.print("Received follow from {s} to {s}\n", .{ actor.string, object.string });
    }

    // Handle incoming Create activity
    fn handleCreate(_: *Federation, _: *database.Database, activity: *std.json.Value) !void {
        // Extract object
        const object = activity.object.get("object") orelse return;

        if (object != .object) return;

        const obj_type = object.object.get("type") orelse return;
        if (obj_type != .string or !std.mem.eql(u8, obj_type.string, "Note")) return;

        const content = object.object.get("content") orelse return;
        if (content != .string) return;

        // TODO: Store remote post in database
        // TODO: Handle threading, mentions, etc.

        std.debug.print("Received remote post: {s}\n", .{content.string});
    }

    // Handle incoming Like activity
    fn handleLike(_: *Federation, _: *database.Database, activity: *std.json.Value) !void {
        // Extract object
        const object = activity.object.get("object") orelse return;

        if (object != .string) return;

        // TODO: Store like in database

        std.debug.print("Received like for {s}\n", .{object.string});
    }

    // Send WebFinger response for user discovery
    pub fn handleWebFinger(self: *Federation, response: anytype, resource: []const u8) !void {
        // Extract username from acct:username@domain format
        const acct_prefix = "acct:";
        if (!std.mem.startsWith(u8, resource, acct_prefix)) {
            response.status = .bad_request;
            try response.writer().writeAll("{\"error\": \"Invalid resource format\"}");
            return;
        }

        const acct_part = resource[acct_prefix.len..];
        const at_pos = std.mem.indexOf(u8, acct_part, "@") orelse {
            response.status = .bad_request;
            try response.writer().writeAll("{\"error\": \"Invalid account format\"}");
            return;
        };

        const username = acct_part[0..at_pos];
        const domain = acct_part[at_pos + 1 ..];

        // Verify domain matches our instance
        if (!std.mem.eql(u8, domain, "speedy-socials.local")) {
            response.status = .not_found;
            try response.writer().writeAll("{\"error\": \"User not found\"}");
            return;
        }

        const profile_url = try std.fmt.allocPrint(self.allocator, "https://speedy-socials.local/users/{s}", .{username});
        defer self.allocator.free(profile_url);

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
                    .href = try std.fmt.allocPrint(self.allocator, "https://speedy-socials.local/users/{s}.atom", .{username}),
                },
                .{
                    .rel = "self",
                    .type = "application/activity+json",
                    .href = profile_url,
                },
            },
        };
        defer self.allocator.free(webfinger.links[1].href);

        response.head.content_type = .{ .override = "application/jrd+json" };
        var json_buf = std.array_list.Managed(u8).init(self.allocator);
        defer json_buf.deinit();

        try std.json.stringify(webfinger, .{}, json_buf.writer());
        try response.writer().writeAll(json_buf.items);
    }
};
