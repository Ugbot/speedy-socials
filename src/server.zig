const std = @import("std");
const http = std.http;
const net = std.net;

const compat = @import("compat.zig");
const database = @import("database.zig");
const mastodon_api = @import("api/mastodon.zig");
const admin_api = @import("api/admin.zig");
const atproto_api = @import("api/atproto.zig");
const federation = @import("federation.zig");
const websocket = @import("websocket.zig");
const web = @import("web.zig");
const activitypub = @import("activitypub.zig");
const auth = @import("auth.zig");
const media = @import("media.zig");
const search_mod = @import("search.zig");

pub fn start(allocator: std.mem.Allocator, db: *database.Database, port: u16) !void {
    std.debug.print("Starting HTTP server on port {}\n", .{port});

    // Initialize WebSocket server
    var websocket_server = websocket.WebSocketServer.init(allocator);
    defer websocket_server.deinit();

    const address = try net.Address.parseIp("127.0.0.1", port);
    var server = try address.listen(.{
        .reuse_address = true,
    });
    defer server.deinit();

    std.debug.print("Server listening on http://127.0.0.1:{}\n", .{port});
    std.debug.print("WebSocket streaming available at ws://127.0.0.1:{}/api/v1/streaming\n", .{port});
    std.debug.print("Ready to accept connections...\n", .{});

    // Accept incoming connections
    var connection_count: usize = 0;
    while (true) {
        const conn = try server.accept();
        connection_count += 1;
        std.debug.print("Accepted connection #{} from {any}\n", .{ connection_count, conn.address });

        // Handle connection in a separate thread for concurrency
        const thread = try std.Thread.spawn(.{}, handleConnection, .{ allocator, db, &websocket_server, conn });
        thread.detach();
    }
}

fn handleConnection(allocator: std.mem.Allocator, db: *database.Database, websocket_server: *websocket.WebSocketServer, conn: net.Server.Connection) !void {
    defer conn.stream.close();

    var read_buffer: [8192]u8 = undefined;
    var write_buffer: [8192]u8 = undefined;
    var stream_reader = conn.stream.reader(&read_buffer);
    var stream_writer = conn.stream.writer(&write_buffer);
    var http_server = http.Server.init(stream_reader.interface(), &stream_writer.interface);

    // Read the request
    var request = try http_server.receiveHead();
    // Parse the request
    const method = request.head.method;
    const target = request.head.target;

    std.debug.print("{s} {s}\n", .{ @tagName(method), target });

    // WebSocket upgrade check disabled -- http.Server.Request.Head API changed in Zig 0.15.
    // The header accessor (.get) no longer exists; needs rewrite to new I/O API.

    // Route the request
    try routeRequest(allocator, db, websocket_server, &request, method, target);
}

fn routeRequest(allocator: std.mem.Allocator, db: *database.Database, _: *websocket.WebSocketServer, request: *http.Server.Request, method: http.Method, target: []const u8) !void {
    var response_buf: [8192]u8 = undefined;
    var response = try request.respondStreaming(&response_buf, .{
        .respond_options = .{
            .status = .ok,
            .extra_headers = &[_]http.Header{
                .{ .name = "content-type", .value = "application/json" },
                .{ .name = "access-control-allow-origin", .value = "*" },
                .{ .name = "access-control-allow-methods", .value = "GET, POST, PUT, DELETE, OPTIONS" },
                .{ .name = "access-control-allow-headers", .value = "content-type, authorization" },
            },
        },
    });
    defer response.end() catch {};

    // Handle CORS preflight requests
    // Note: In Zig 0.15 HTTP API, status is set at response creation time.
    // OPTIONS requests will return 200 OK with empty body.
    if (method == .OPTIONS) {
        return;
    }

    // Parse the target to extract path and query parameters
    var path_end: usize = 0;
    for (target, 0..) |char, i| {
        if (char == '?' or char == '#') break;
        path_end = i + 1;
    }
    const path = target[0..path_end];

    // Initialize API handlers
    var mastodon = mastodon_api.MastodonAPI.init(allocator);
    var admin = admin_api.AdminAPI.init(allocator);

    // Route based on path
    if (std.mem.eql(u8, path, "/")) {
        // Root endpoint
        try response.writer.writeAll("{\"message\": \"Speedy Socials API\"}");
    } else if (std.mem.eql(u8, path, "/api/v1/instance")) {
        // Mastodon instance info
        try mastodon.handleInstanceInfo(&response);
    } else if (std.mem.startsWith(u8, path, "/api/v1/accounts/")) {
        // Account endpoints
        try handleAccountRoutes(allocator, db, &mastodon, &admin, &response, method, path);
    } else if (std.mem.startsWith(u8, path, "/api/v1/statuses")) {
        // Status/post endpoints
        try handleStatusRoutes(allocator, db, &mastodon, &response, method, path, request);
    } else if (std.mem.eql(u8, path, "/api/v1/timelines/home")) {
        // Home timeline
        try mastodon.handleHomeTimeline(db, &response);
    } else if (std.mem.eql(u8, path, "/api/v1/timelines/public")) {
        // Public timeline
        try mastodon.handlePublicTimeline(db, &response);
    } else if (std.mem.startsWith(u8, path, "/api/v1/reports")) {
        // Reports endpoint
        try handleReports(allocator, db, &response, method, path, request);
    } else if (std.mem.startsWith(u8, path, "/.well-known/atproto-did")) {
        // AT Protocol DID endpoint — returns DID as plain text
        try atproto_api.handleAtprotoDid(allocator, &response);
    } else if (std.mem.startsWith(u8, path, "/xrpc/")) {
        // AT Protocol XRPC endpoints — dispatched via library router
        try atproto_api.handleXrpc(allocator, &response, method, path, request);
    } else if (std.mem.eql(u8, path, "/.well-known/webfinger")) {
        // WebFinger for user discovery
        try handleWebFinger(allocator, db, &response, request);
    } else if (std.mem.startsWith(u8, path, "/users/")) {
        // ActivityPub actor endpoints
        try handleActivityPubActorRoutes(allocator, db, &response, method, path, request);
    } else if (std.mem.eql(u8, path, "/inbox")) {
        // Shared inbox for federation
        try handleSharedInbox(allocator, db, &response, method, request);
    } else if (std.mem.eql(u8, path, "/oauth/authorize")) {
        // OAuth2 authorization endpoint
        try handleOAuthAuthorize(allocator, db, &response, request);
    } else if (std.mem.eql(u8, path, "/oauth/token")) {
        // OAuth2 token endpoint
        try handleOAuthToken(allocator, db, &response, method, request);
    } else if (std.mem.eql(u8, path, "/api/v1/apps")) {
        // Create OAuth application
        try handleCreateApp(allocator, db, &response, method, request);
    } else if (std.mem.eql(u8, path, "/api/v1/accounts")) {
        // Create account (user registration)
        try handleCreateAccount(allocator, db, &response, method, request);
    } else if (std.mem.startsWith(u8, path, "/api/v1/admin/")) {
        // Admin endpoints
        try handleAdminRoutes(allocator, db, &admin, &response, method, path, request);
    } else if (std.mem.eql(u8, path, "/api/v1/media")) {
        // Media upload
        try handleMediaUpload(allocator, db, &response, method, request);
    } else if (std.mem.eql(u8, path, "/api/v1/search")) {
        // Search endpoint
        try handleSearch(allocator, db, &response, request);
    } else if (std.mem.eql(u8, path, "/api/v2/search")) {
        // Mastodon v2 search endpoint
        try handleSearchV2(allocator, db, &response, request);
    } else if (std.mem.eql(u8, path, "/api/v1/trends/tags")) {
        // Trending hashtags
        try handleTrendingTags(allocator, db, &response, request);
    } else if (std.mem.eql(u8, path, "/api/v1/bookmarks")) {
        // Bookmarked statuses
        var mastodon_inst = mastodon_api.MastodonAPI.init(allocator);
        try mastodon_inst.handleBookmarkedStatuses(db, &response, request);
    } else if (std.mem.eql(u8, path, "/api/v1/lists")) {
        // Create list or get lists
        var mastodon_inst = mastodon_api.MastodonAPI.init(allocator);
        if (method == .POST) {
            try mastodon_inst.handleCreateList(db, &response, request);
        } else {
            try mastodon_inst.handleGetLists(db, &response);
        }
    } else if (std.mem.startsWith(u8, path, "/api/v1/lists/")) {
        // List-specific endpoints
        try handleListRoutes(allocator, db, &response, method, path, request);
    } else if (std.mem.eql(u8, path, "/")) {
        // Web interface home page
        var web_interface = web.WebInterface.init(allocator);
        try web_interface.serveHomePage(db, &response);
    } else if (std.mem.eql(u8, path, "/create")) {
        // Web interface create post page
        var web_interface = web.WebInterface.init(allocator);
        try web_interface.serveCreatePostPage(&response);
    } else if (std.mem.eql(u8, path, "/create-post")) {
        // Handle HTMX post creation
        var web_interface = web.WebInterface.init(allocator);
        try web_interface.handleCreatePost(db, &response, request);
    } else if (std.mem.startsWith(u8, path, "/react/")) {
        // Handle HTMX reactions
        const react_prefix = "/react/";
        const remaining = path[react_prefix.len..];
        if (std.mem.indexOf(u8, remaining, "/")) |slash_pos| {
            const post_id_str = remaining[0..slash_pos];
            const emoji = remaining[slash_pos + 1 ..];

            const post_id = std.fmt.parseInt(i64, post_id_str, 10) catch {
                // Note: status cannot be changed after respondStreaming in Zig 0.15
                try response.writer.writeAll("Invalid post ID");
                return;
            };

            var web_interface = web.WebInterface.init(allocator);
            try web_interface.handleReaction(db, &response, method, post_id, emoji);
        } else {
            // Note: status cannot be changed after respondStreaming in Zig 0.15
            try response.writer.writeAll("Invalid reaction format");
        }
    } else {
        // 404 Not Found
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Not Found\"}");
    }
}

// Delegating functions to API modules
fn handleAccountRoutes(_: std.mem.Allocator, db: *database.Database, mastodon: *mastodon_api.MastodonAPI, admin: *admin_api.AdminAPI, response: anytype, method: http.Method, path: []const u8) !void {
    // Extract account ID from path: /api/v1/accounts/{id}
    const prefix = "/api/v1/accounts/";
    if (!std.mem.startsWith(u8, path, prefix)) {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Invalid account path\"}");
        return;
    }

    const account_part = path[prefix.len..];
    if (std.mem.indexOf(u8, account_part, "/")) |slash_pos| {
        const account_id_str = account_part[0..slash_pos];
        const action = account_part[slash_pos + 1 ..];

        const account_id = std.fmt.parseInt(i64, account_id_str, 10) catch {
            // Note: status cannot be changed after respondStreaming in Zig 0.15
            try response.writer.writeAll("{\"error\": \"Invalid account ID\"}");
            return;
        };

        if (std.mem.eql(u8, action, "statuses")) {
            try mastodon.handleAccountStatuses(db, response, account_id);
        } else if (std.mem.eql(u8, action, "block")) {
            try admin.handleBlockAccount(db, response, method, account_id);
        } else if (std.mem.eql(u8, action, "unblock")) {
            try admin.handleUnblockAccount(db, response, method, account_id);
        } else if (std.mem.eql(u8, action, "mute")) {
            try admin.handleMuteAccount(db, response, method, account_id);
        } else if (std.mem.eql(u8, action, "unmute")) {
            try admin.handleUnmuteAccount(db, response, method, account_id);
        } else if (std.mem.eql(u8, action, "statuses")) {
            try mastodon.handleAccountStatuses(db, response, account_id);
        } else if (std.mem.eql(u8, action, "featured")) {
            try mastodon.handleFeaturedStatuses(db, response, account_id);
        } else {
            // Note: status cannot be changed after respondStreaming in Zig 0.15
            try response.writer.writeAll("{\"error\": \"Action not found\"}");
        }
    } else {
        // Just /api/v1/accounts/{id}
        const account_id = std.fmt.parseInt(i64, account_part, 10) catch {
            // Note: status cannot be changed after respondStreaming in Zig 0.15
            try response.writer.writeAll("{\"error\": \"Invalid account ID\"}");
            return;
        };

        try mastodon.handleAccountInfo(db, response, account_id);
    }
}

fn handleStatusRoutes(allocator: std.mem.Allocator, db: *database.Database, mastodon: *mastodon_api.MastodonAPI, response: anytype, method: http.Method, path: []const u8, request: *http.Server.Request) !void {
    if (std.mem.eql(u8, path, "/api/v1/statuses")) {
        if (method == .POST) {
            try mastodon.handleCreateStatus(db, response, request);
        } else {
            // Note: status cannot be changed after respondStreaming in Zig 0.15
            try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
        }
    } else {
        // Handle status-specific routes like /api/v1/statuses/{id}/favourite
        const prefix = "/api/v1/statuses/";
        if (!std.mem.startsWith(u8, path, prefix)) {
            // Note: status cannot be changed after respondStreaming in Zig 0.15
            try response.writer.writeAll("{\"error\": \"Invalid status path\"}");
            return;
        }

        const remaining = path[prefix.len..];
        if (std.mem.indexOf(u8, remaining, "/")) |slash_pos| {
            const status_id_str = remaining[0..slash_pos];
            const action = remaining[slash_pos + 1 ..];

            const status_id = std.fmt.parseInt(i64, status_id_str, 10) catch {
                // Note: status cannot be changed after respondStreaming in Zig 0.15
                try response.writer.writeAll("{\"error\": \"Invalid status ID\"}");
                return;
            };

            if (std.mem.eql(u8, action, "favourite")) {
                try mastodon.handleFavouriteStatus(db, response, method, status_id);
            } else if (std.mem.eql(u8, action, "reblog")) {
                try mastodon.handleReblogStatus(db, response, method, status_id);
            } else if (std.mem.eql(u8, action, "bookmark")) {
                try mastodon.handleBookmarkStatus(db, response, method, status_id);
            } else if (std.mem.eql(u8, action, "unbookmark")) {
                try mastodon.handleUnbookmarkStatus(db, response, method, status_id);
            } else if (std.mem.eql(u8, action, "pin")) {
                try mastodon.handleFeatureStatus(db, response, method, status_id);
            } else if (std.mem.eql(u8, action, "unpin")) {
                try mastodon.handleUnfeatureStatus(db, response, method, status_id);
            } else if (std.mem.startsWith(u8, action, "react/")) {
                // Handle emoji reactions: /api/v1/statuses/{id}/react/{emoji}
                const emoji = action["react/".len..];
                try mastodon.handleAddEmojiReaction(db, response, method, status_id, emoji);
            } else if (std.mem.startsWith(u8, action, "unreact/")) {
                // Handle removing emoji reactions: /api/v1/statuses/{id}/unreact/{emoji}
                const emoji = action["unreact/".len..];
                try mastodon.handleRemoveEmojiReaction(db, response, method, status_id, emoji);
            } else if (std.mem.eql(u8, action, "reactions")) {
                // Handle getting emoji reactions: /api/v1/statuses/{id}/reactions
                try mastodon.handleGetEmojiReactions(db, response, status_id);
            } else {
                // Note: status cannot be changed after respondStreaming in Zig 0.15
                try response.writer.writeAll("{\"error\": \"Action not found\"}");
            }
        } else if (std.mem.indexOf(u8, remaining, "/poll/")) |poll_pos| {
            const poll_action = remaining[poll_pos + "/poll/".len ..];
            const poll_id_str = remaining[0..poll_pos];
            const poll_id = std.fmt.parseInt(i64, poll_id_str, 10) catch {
                // Note: status cannot be changed after respondStreaming in Zig 0.15
                try response.writer.writeAll("{\"error\": \"Invalid poll ID\"}");
                return;
            };

            if (std.mem.eql(u8, poll_action, "votes")) {
                try mastodon.handlePollVote(db, response, method, poll_id, request);
            } else {
                // Note: status cannot be changed after respondStreaming in Zig 0.15
                try response.writer.writeAll("{\"error\": \"Poll action not found\"}");
            }
        } else {
            // Just /api/v1/statuses/{id}
            const status_id_str = remaining;
            const status_id = std.fmt.parseInt(i64, status_id_str, 10) catch {
                // Note: status cannot be changed after respondStreaming in Zig 0.15
                try response.writer.writeAll("{\"error\": \"Invalid status ID\"}");
                return;
            };

            // For now, just return mock data
            const mock_status = struct {
                id: []const u8,
                content: []const u8,
                created_at: []const u8,
            }{
                .id = try std.fmt.allocPrint(allocator, "{}", .{status_id}),
                .content = "Mock status content",
                .created_at = "2024-01-01T00:00:00Z",
            };
            defer allocator.free(mock_status.id);

            var json_buf = std.array_list.Managed(u8).init(allocator);
            defer json_buf.deinit();

            try compat.jsonStringify(mock_status, .{}, json_buf.writer());
            try response.writer.writeAll(json_buf.items);
        }
    }
}

fn handleAdminRoutes(_: std.mem.Allocator, db: *database.Database, admin: *admin_api.AdminAPI, response: anytype, method: http.Method, path: []const u8, request: *http.Server.Request) !void {
    if (std.mem.eql(u8, path, "/api/v1/admin/accounts")) {
        try admin.handleAdminAccounts(db, response, request);
    } else if (std.mem.eql(u8, path, "/api/v1/admin/stats")) {
        try admin.handleAdminStats(db, response);
    } else if (std.mem.startsWith(u8, path, "/api/v1/admin/accounts/")) {
        const prefix = "/api/v1/admin/accounts/";
        const remaining = path[prefix.len..];
        if (std.mem.indexOf(u8, remaining, "/")) |slash_pos| {
            const account_id_str = remaining[0..slash_pos];
            const action = remaining[slash_pos + 1 ..];

            const account_id = std.fmt.parseInt(i64, account_id_str, 10) catch {
                // Note: status cannot be changed after respondStreaming in Zig 0.15
                try response.writer.writeAll("{\"error\": \"Invalid account ID\"}");
                return;
            };

            if (std.mem.eql(u8, action, "suspend")) {
                try admin.handleSuspendAccount(db, response, method, account_id);
            } else if (std.mem.eql(u8, action, "unsuspend")) {
                try admin.handleUnsuspendAccount(db, response, method, account_id);
            } else {
                // Note: status cannot be changed after respondStreaming in Zig 0.15
                try response.writer.writeAll("{\"error\": \"Admin action not found\"}");
            }
        } else {
            // Note: status cannot be changed after respondStreaming in Zig 0.15
            try response.writer.writeAll("{\"error\": \"Admin endpoint not found\"}");
        }
    } else if (std.mem.eql(u8, path, "/api/v1/admin/reports")) {
        try admin.handleAdminReports(db, response, request);
    } else if (std.mem.startsWith(u8, path, "/api/v1/admin/reports/")) {
        const prefix = "/api/v1/admin/reports/";
        const report_id_str = path[prefix.len..];
        const report_id = std.fmt.parseInt(i64, report_id_str, 10) catch {
            // Note: status cannot be changed after respondStreaming in Zig 0.15
            try response.writer.writeAll("{\"error\": \"Invalid report ID\"}");
            return;
        };

        if (method == .PUT or method == .POST) {
            try admin.handleResolveReport(db, response, method, report_id);
        } else {
            // Note: status cannot be changed after respondStreaming in Zig 0.15
            try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
        }
    } else {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Admin endpoint not found\"}");
    }
}

fn handleInstanceInfo(allocator: std.mem.Allocator, response: anytype) !void {
    const instance_info = struct {
        uri: []const u8 = "https://speedy-socials.local",
        title: []const u8 = "Speedy Socials",
        description: []const u8 = "A high-performance social media platform built with Zig",
        short_description: []const u8 = "Fast social media with Mastodon and AT Protocol support",
        email: []const u8 = "admin@speedy-socials.local",
        version: []const u8 = "1.0.0-zig",
        languages: [][]const u8 = &[_][]const u8{"en"},
        registrations: bool = true,
        approval_required: bool = false,
        invites_enabled: bool = false,
        urls: struct {
            streaming_api: []const u8 = "wss://speedy-socials.local",
        } = .{},
        stats: struct {
            user_count: u32 = 0,
            status_count: u32 = 0,
            domain_count: u32 = 1,
        } = .{},
        thumbnail: ?[]const u8 = null,
        contact_account: ?@TypeOf(null) = null,
    }{};

    var json_buf = std.array_list.Managed(u8).init(allocator);
    defer json_buf.deinit();

    try compat.jsonStringify(instance_info, .{}, json_buf.writer());
    try response.writer.writeAll(json_buf.items);
}

// Note: handleAccountRoutes is defined earlier with full API module parameters

fn handleAccountInfo(allocator: std.mem.Allocator, _: ?*anyopaque, response: anytype, account_id: i64) !void {
    // Mock account data for now
    const account = struct {
        id: []const u8,
        username: []const u8,
        acct: []const u8,
        display_name: []const u8,
        locked: bool,
        bot: bool = false,
        discoverable: bool = true,
        group: bool = false,
        created_at: []const u8,
        note: []const u8,
        url: []const u8,
        avatar: []const u8,
        header: []const u8,
        followers_count: u32 = 42,
        following_count: u32 = 23,
        statuses_count: u32 = 1337,
    }{
        .id = try std.fmt.allocPrint(allocator, "{}", .{account_id}),
        .username = "demo_user",
        .acct = "demo_user",
        .display_name = "Demo User",
        .locked = false,
        .created_at = "2024-01-01T00:00:00Z",
        .note = "A demo user for testing",
        .url = "https://speedy-socials.local/@demo_user",
        .avatar = "",
        .header = "",
    };
    defer allocator.free(account.id);

    var json_buf = std.array_list.Managed(u8).init(allocator);
    defer json_buf.deinit();

    try compat.jsonStringify(account, .{}, json_buf.writer());
    try response.writer.writeAll(json_buf.items);
}

fn handleAccountStatuses(allocator: std.mem.Allocator, _: ?*anyopaque, response: anytype, _: i64) !void {
    // Mock posts data
    const mock_posts = [_]struct {
        id: []const u8,
        content: []const u8,
        created_at: []const u8,
    }{
        .{
            .id = "1",
            .content = "Hello world! This is my first post.",
            .created_at = "2024-01-01T00:00:00Z",
        },
        .{
            .id = "2",
            .content = "Building a social media platform with Zig is awesome!",
            .created_at = "2024-01-02T00:00:00Z",
        },
    };

    var json_buf = std.array_list.Managed(u8).init(allocator);
    defer json_buf.deinit();

    try compat.jsonStringify(mock_posts, .{}, json_buf.writer());
    try response.writer.writeAll(json_buf.items);
}

// Note: handleStatusRoutes is defined earlier with full API module parameters

fn handleCreateStatus(allocator: std.mem.Allocator, db: *database.Database, response: anytype, request: *http.Server.Request) !void {
    var read_buf: [8192]u8 = undefined;
    const reader = request.readerExpectNone(&read_buf);
    const body = reader.allocRemaining(allocator, std.io.Limit.limited(1024 * 1024)) catch {
        try response.writer.writeAll("{\"error\": \"Failed to read request body\"}");
        return;
    };
    defer allocator.free(body);

    // Parse JSON body
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch {
        try response.writer.writeAll("{\"error\": \"Invalid JSON\"}");
        return;
    };
    defer parsed.deinit();

    const root = parsed.value.object;
    const status_text = if (root.get("status")) |s| switch (s) {
        .string => |str| str,
        else => {
            try response.writer.writeAll("{\"error\": \"status must be a string\"}");
            return;
        },
    } else {
        try response.writer.writeAll("{\"error\": \"status field required\"}");
        return;
    };

    const visibility = if (root.get("visibility")) |v| switch (v) {
        .string => |str| str,
        else => "public",
    } else "public";

    // For demo, use user ID 1
    const user_id: i64 = 1;
    const post_id = try database.createPost(db, allocator, user_id, status_text, visibility);

    // Check for poll
    if (root.get("poll")) |poll_val| {
        if (poll_val == .object) {
            var poll_obj = poll_val.object;
            const multiple = if (poll_obj.get("multiple")) |m| (m == .bool and m.bool) else false;
            const hide_totals = if (poll_obj.get("hide_totals")) |h| (h == .bool and h.bool) else false;
            const poll_id = try database.createPoll(db, post_id, null, multiple, hide_totals);

            if (poll_obj.get("options")) |options| {
                if (options == .array) {
                    for (options.array.items) |option| {
                        if (option == .string) {
                            _ = try database.addPollOption(db, poll_id, option.string);
                        }
                    }
                }
            }
        }
    }

    // Return created status
    const id_str = try std.fmt.allocPrint(allocator, "{}", .{post_id});
    defer allocator.free(id_str);

    var json_buf = std.array_list.Managed(u8).init(allocator);
    defer json_buf.deinit();

    const post_response = struct {
        id: []const u8,
        content: []const u8,
        visibility: []const u8,
        created_at: []const u8 = "now",
    }{
        .id = id_str,
        .content = status_text,
        .visibility = visibility,
    };

    try compat.jsonStringify(post_response, .{}, json_buf.writer());
    try response.writer.writeAll(json_buf.items);
}

fn handleFavouriteStatus(_: std.mem.Allocator, db: *database.Database, response: anytype, method: http.Method, status_id: i64) !void {
    if (method != .POST) {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
        return;
    }

    // For now, favourite as user ID 1 (demo user)
    const user_id: i64 = 1;
    try database.favouritePost(db, user_id, status_id);

    try response.writer.writeAll("{\"favourited\": true}");
}

fn handleReblogStatus(allocator: std.mem.Allocator, db: *database.Database, response: anytype, method: http.Method, _: i64) !void {
    if (method != .POST) {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
        return;
    }

    // For now, reblog as user ID 1 (demo user)
    const user_id: i64 = 1;
    _ = try database.createPost(db, allocator, user_id, "", "public"); // TODO: Implement proper reblog

    try response.writer.writeAll("{\"reblogged\": true}");
}

fn handleGetStatus(_: std.mem.Allocator, _: *database.Database, response: anytype, _: i64) !void {
    // TODO: Implement getting individual status
    try response.writer.writeAll("{\"error\": \"Not implemented\"}");
}

fn handleHomeTimeline(allocator: std.mem.Allocator, db: *database.Database, response: anytype) !void {
    const posts = try database.getPosts(db, allocator, 20, 0);
    defer {
        for (posts) |post| {
            allocator.free(post.content);
            if (post.content_warning) |cw| allocator.free(cw);
            allocator.free(post.visibility);
            allocator.free(post.created_at);
        }
        allocator.free(posts);
    }

    // Convert to Mastodon status format
    var mastodon_posts = std.array_list.Managed(struct {
        id: []const u8,
        uri: []const u8,
        created_at: []const u8,
        account: struct {
            id: []const u8,
            username: []const u8,
            display_name: []const u8,
        },
        content: []const u8,
        visibility: []const u8,
        sensitive: bool = false,
        spoiler_text: ?[]const u8 = null,
        media_attachments: []@TypeOf(undefined) = &[_]@TypeOf(undefined){},
        favourites_count: u32,
        reblogs_count: u32,
        replies_count: u32,
    }).init(allocator);
    defer {
        for (mastodon_posts.items) |*post| {
            allocator.free(post.id);
            allocator.free(post.uri);
            allocator.free(post.account.id);
        }
        mastodon_posts.deinit();
    }

    for (posts) |post| {
        // Get user info for each post
        const user = try database.getUserById(db, allocator, post.user_id) orelse continue;
        defer {
            allocator.free(user.username);
            allocator.free(user.email);
            if (user.display_name) |dn| allocator.free(dn);
            if (user.bio) |bio| allocator.free(bio);
            if (user.avatar_url) |au| allocator.free(au);
            if (user.header_url) |hu| allocator.free(hu);
            allocator.free(user.created_at);
        }

        try mastodon_posts.append(.{
            .id = try std.fmt.allocPrint(allocator, "{}", .{post.id}),
            .uri = try std.fmt.allocPrint(allocator, "https://speedy-socials.local/statuses/{}", .{post.id}),
            .created_at = post.created_at,
            .account = .{
                .id = try std.fmt.allocPrint(allocator, "{}", .{user.id}),
                .username = user.username,
                .display_name = user.display_name orelse user.username,
            },
            .content = post.content,
            .visibility = post.visibility,
            .favourites_count = @intCast(post.favourites_count),
            .reblogs_count = @intCast(post.reblogs_count),
            .replies_count = @intCast(post.replies_count),
        });
    }

    var json_buf = std.array_list.Managed(u8).init(allocator);
    defer json_buf.deinit();

    try compat.jsonStringify(mastodon_posts.items, .{}, json_buf.writer());
    try response.writer.writeAll(json_buf.items);
}

fn handlePublicTimeline(allocator: std.mem.Allocator, db: *database.Database, response: anytype) !void {
    // Same as home timeline for now
    try handleHomeTimeline(allocator, db, response);
}

// AT Protocol handlers removed — now delegated to lib/atproto via atproto_api adapter

// OAuth2 handlers
fn handleCreateApp(allocator: std.mem.Allocator, _: ?*anyopaque, response: anytype, method: http.Method, request: *http.Server.Request) !void {
    if (method != .POST) {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
        return;
    }

    var read_buf: [8192]u8 = undefined;
    const reader = request.readerExpectNone(&read_buf);
    const body = reader.allocRemaining(allocator, std.io.Limit.limited(1024 * 1024)) catch {
        try response.writer.writeAll("{\"error\": \"Failed to read request body\"}");
        return;
    };
    defer allocator.free(body);

    // Parse form-encoded or JSON body
    const client_name = extractFormParam(body, "client_name") orelse "Unknown App";
    const redirect_uris = extractFormParam(body, "redirect_uris") orelse "urn:ietf:wg:oauth:2.0:oob";
    const website = extractFormParam(body, "website");

    // Generate client credentials
    var client_id_bytes: [16]u8 = undefined;
    std.crypto.random.bytes(&client_id_bytes);
    var client_secret_bytes: [32]u8 = undefined;
    std.crypto.random.bytes(&client_secret_bytes);

    const client_id_hex = std.fmt.bytesToHex(client_id_bytes, .lower);
    const client_secret_hex = std.fmt.bytesToHex(client_secret_bytes, .lower);

    const app_response = struct {
        id: []const u8 = "1",
        name: []const u8,
        website: ?[]const u8,
        redirect_uri: []const u8,
        client_id: []const u8,
        client_secret: []const u8,
        vapid_key: []const u8 = "",
    }{
        .name = client_name,
        .website = website,
        .redirect_uri = redirect_uris,
        .client_id = &client_id_hex,
        .client_secret = &client_secret_hex,
    };

    var json_buf = std.array_list.Managed(u8).init(allocator);
    defer json_buf.deinit();

    try compat.jsonStringify(app_response, .{ .emit_null_optional_fields = false }, json_buf.writer());
    try response.writer.writeAll(json_buf.items);
}

fn handleOAuthAuthorize(allocator: std.mem.Allocator, _: ?*anyopaque, response: anytype, request: *http.Server.Request) !void {
    // Parse query parameters
    const query = request.head.target;
    const query_start = std.mem.indexOf(u8, query, "?") orelse {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Missing query parameters\"}");
        return;
    };

    // Simple query parsing (in production, use proper URL parsing)
    const client_id = extractQueryParam(query[query_start..], "client_id") orelse {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"client_id required\"}");
        return;
    };

    const redirect_uri = extractQueryParam(query[query_start..], "redirect_uri") orelse {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"redirect_uri required\"}");
        return;
    };

    const response_type = extractQueryParam(query[query_start..], "response_type") orelse "code";

    // For demo purposes, auto-approve and redirect
    if (std.mem.eql(u8, response_type, "code")) {
        const code = try auth.createAuthorizationCode(undefined, allocator, 1, client_id, redirect_uri, "read write follow");
        defer allocator.free(code);

        const redirect_url = try std.fmt.allocPrint(allocator, "{s}?code={s}", .{ redirect_uri, code });
        defer allocator.free(redirect_url);

        // Note: status and headers cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("Redirecting...");
    } else {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Unsupported response_type\"}");
    }
}

fn handleOAuthToken(allocator: std.mem.Allocator, db: ?*anyopaque, response: anytype, method: http.Method, request: *http.Server.Request) !void {
    if (method != .POST) {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
        return;
    }

    var read_buf: [8192]u8 = undefined;
    const reader = request.readerExpectNone(&read_buf);
    const body = reader.allocRemaining(allocator, std.io.Limit.limited(1024 * 1024)) catch {
        try response.writer.writeAll("{\"error\": \"Failed to read request body\"}");
        return;
    };
    defer allocator.free(body);

    // Determine grant type and delegate
    const grant_type = extractFormParam(body, "grant_type") orelse {
        try response.writer.writeAll("{\"error\": \"grant_type required\"}");
        return;
    };

    if (std.mem.eql(u8, grant_type, "authorization_code")) {
        try handleAuthorizationCodeGrant(allocator, db, response, body);
    } else if (std.mem.eql(u8, grant_type, "password")) {
        try handlePasswordGrant(allocator, db, response, body);
    } else if (std.mem.eql(u8, grant_type, "client_credentials")) {
        try handleClientCredentialsGrant(allocator, db, response, body);
    } else {
        try response.writer.writeAll("{\"error\": \"Unsupported grant_type\"}");
    }
}

fn handleAuthorizationCodeGrant(allocator: std.mem.Allocator, _: ?*anyopaque, response: anytype, body: []const u8) !void {
    const code = extractFormParam(body, "code") orelse {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"code required\"}");
        return;
    };

    const client_id = extractFormParam(body, "client_id") orelse {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"client_id required\"}");
        return;
    };

    const client_secret = extractFormParam(body, "client_secret") orelse {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"client_secret required\"}");
        return;
    };

    const redirect_uri = extractFormParam(body, "redirect_uri") orelse {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"redirect_uri required\"}");
        return;
    };

    // Exchange code for token
    var token = try auth.exchangeCodeForToken(undefined, allocator, code, client_id, client_secret, redirect_uri);
    defer token.deinit(allocator);

    const token_response = struct {
        access_token: []const u8,
        token_type: []const u8 = "Bearer",
        scope: []const u8 = "read write follow",
        created_at: i64,
    }{
        .access_token = token.id,
        .created_at = token.created_at,
    };

    var json_buf = std.array_list.Managed(u8).init(allocator);
    defer json_buf.deinit();

    try compat.jsonStringify(token_response, .{}, json_buf.writer());
    // Note: status cannot be changed after respondStreaming in Zig 0.15
    try response.writer.writeAll(json_buf.items);
}

fn handlePasswordGrant(allocator: std.mem.Allocator, _: ?*anyopaque, response: anytype, body: []const u8) !void {
    const username = extractFormParam(body, "username") orelse {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"username required\"}");
        return;
    };

    const password = extractFormParam(body, "password") orelse {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"password required\"}");
        return;
    };

    const client_id = extractFormParam(body, "client_id") orelse {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"client_id required\"}");
        return;
    };

    const scope = extractFormParam(body, "scope") orelse "read write follow";

    // Authenticate user
    var token = try auth.passwordGrant(undefined, allocator, username, password, client_id, scope);
    defer token.deinit(allocator);

    const token_response = struct {
        access_token: []const u8,
        token_type: []const u8 = "Bearer",
        scope: []const u8,
        created_at: i64,
    }{
        .access_token = token.id,
        .scope = scope,
        .created_at = token.created_at,
    };

    var json_buf = std.array_list.Managed(u8).init(allocator);
    defer json_buf.deinit();

    try compat.jsonStringify(token_response, .{}, json_buf.writer());
    // Note: status cannot be changed after respondStreaming in Zig 0.15
    try response.writer.writeAll(json_buf.items);
}

fn handleClientCredentialsGrant(allocator: std.mem.Allocator, _: ?*anyopaque, response: anytype, body: []const u8) !void {
    const client_id = extractFormParam(body, "client_id") orelse {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"client_id required\"}");
        return;
    };

    const client_secret = extractFormParam(body, "client_secret") orelse {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"client_secret required\"}");
        return;
    };

    const scope = extractFormParam(body, "scope") orelse "read write follow";

    // Create application token
    var token = try auth.clientCredentialsGrant(undefined, allocator, client_id, client_secret, scope);
    defer token.deinit(allocator);

    const token_response = struct {
        access_token: []const u8,
        token_type: []const u8 = "Bearer",
        scope: []const u8,
        created_at: i64,
    }{
        .access_token = token.id,
        .scope = scope,
        .created_at = token.created_at,
    };

    var json_buf = std.array_list.Managed(u8).init(allocator);
    defer json_buf.deinit();

    try compat.jsonStringify(token_response, .{}, json_buf.writer());
    // Note: status cannot be changed after respondStreaming in Zig 0.15
    try response.writer.writeAll(json_buf.items);
}

// Helper functions
fn extractQueryParam(query: []const u8, param: []const u8) ?[]const u8 {
    const param_pattern = std.fmt.allocPrint(std.heap.page_allocator, "{s}=", .{param}) catch return null;
    defer std.heap.page_allocator.free(param_pattern);

    const match_start = std.mem.indexOf(u8, query, param_pattern) orelse return null;
    const value_start = match_start + param_pattern.len;
    const end = std.mem.indexOfPos(u8, query, value_start, "&") orelse query.len;

    return query[value_start..end];
}

fn handleCreateAccount(allocator: std.mem.Allocator, db: *database.Database, response: anytype, method: http.Method, request: *http.Server.Request) !void {
    if (method != .POST) {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
        return;
    }

    var read_buf: [8192]u8 = undefined;
    const reader = request.readerExpectNone(&read_buf);
    const body = reader.allocRemaining(allocator, std.io.Limit.limited(1024 * 1024)) catch {
        try response.writer.writeAll("{\"error\": \"Failed to read request body\"}");
        return;
    };
    defer allocator.free(body);

    // Parse form-encoded body
    const username = extractFormParam(body, "username") orelse {
        try response.writer.writeAll("{\"error\": \"username required\"}");
        return;
    };

    const email = extractFormParam(body, "email") orelse {
        try response.writer.writeAll("{\"error\": \"email required\"}");
        return;
    };

    const password = extractFormParam(body, "password") orelse {
        try response.writer.writeAll("{\"error\": \"password required\"}");
        return;
    };

    // Create user in database
    const user_id = database.createUser(db, allocator, username, email, password) catch {
        try response.writer.writeAll("{\"error\": \"Failed to create account\"}");
        return;
    };

    // Generate access token for the new user
    var token = auth.createAccessToken(undefined, allocator, user_id, null, "read write follow") catch {
        try response.writer.writeAll("{\"error\": \"Account created but token generation failed\"}");
        return;
    };
    defer token.deinit(allocator);

    const token_response = struct {
        access_token: []const u8,
        token_type: []const u8 = "Bearer",
        scope: []const u8 = "read write follow",
        created_at: i64,
    }{
        .access_token = token.id,
        .created_at = token.created_at,
    };

    var json_buf = std.array_list.Managed(u8).init(allocator);
    defer json_buf.deinit();

    try compat.jsonStringify(token_response, .{}, json_buf.writer());
    try response.writer.writeAll(json_buf.items);
}

// Note: handleAdminRoutes is defined earlier with full API module parameters

fn handleAdminAccounts(allocator: std.mem.Allocator, _: *database.Database, response: anytype, method: http.Method) !void {
    if (method != .GET) {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
        return;
    }

    // Get recent accounts (simplified - in production, paginate and filter)
    // For now, return basic stats
    const stats = struct {
        total_users: u32 = 1,
        active_users: u32 = 1,
        new_users_today: u32 = 0,
        suspended_users: u32 = 0,
    }{};

    var json_buf = std.array_list.Managed(u8).init(allocator);
    defer json_buf.deinit();

    try compat.jsonStringify(stats, .{}, json_buf.writer());
    try response.writer.writeAll(json_buf.items);
}

fn handleAdminStats(allocator: std.mem.Allocator, _: *database.Database, response: anytype) !void {
    // Return instance statistics
    const stats = struct {
        user_count: u32 = 1,
        status_count: u32 = 3,
        domain_count: u32 = 1,
        active_users: u32 = 1,
        interactions: u32 = 0,
        reports: u32 = 0,
    }{};

    var json_buf = std.array_list.Managed(u8).init(allocator);
    defer json_buf.deinit();

    try compat.jsonStringify(stats, .{}, json_buf.writer());
    try response.writer.writeAll(json_buf.items);
}

fn handleAdminAccountAction(_: std.mem.Allocator, _: *database.Database, response: anytype, method: http.Method, account_action: []const u8) !void {
    // Parse action (e.g., "123/suspend", "123/unsuspend")
    const slash_pos = std.mem.indexOf(u8, account_action, "/") orelse {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Invalid account action\"}");
        return;
    };

    const account_id_str = account_action[0..slash_pos];
    const action = account_action[slash_pos + 1 ..];

    _ = std.fmt.parseInt(i64, account_id_str, 10) catch {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Invalid account ID\"}");
        return;
    };

    if (std.mem.eql(u8, action, "suspend")) {
        if (method != .POST) {
            // Note: status cannot be changed after respondStreaming in Zig 0.15
            try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
            return;
        }
        // TODO: Implement account suspension
        try response.writer.writeAll("{\"message\": \"Account suspended\"}");
    } else if (std.mem.eql(u8, action, "unsuspend")) {
        if (method != .POST) {
            // Note: status cannot be changed after respondStreaming in Zig 0.15
            try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
            return;
        }
        // TODO: Implement account unsuspension
        try response.writer.writeAll("{\"message\": \"Account unsuspended\"}");
    } else {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Action not found\"}");
    }
}

fn handleMediaUpload(allocator: std.mem.Allocator, _: *database.Database, response: anytype, method: http.Method, request: *http.Server.Request) !void {
    if (method != .POST) {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
        return;
    }

    var read_buf: [8192]u8 = undefined;
    const reader = request.readerExpectNone(&read_buf);
    const body = reader.allocRemaining(allocator, std.io.Limit.limited(10 * 1024 * 1024)) catch {
        try response.writer.writeAll("{\"error\": \"Failed to read request body\"}");
        return;
    };
    defer allocator.free(body);

    // Generate a media ID for the upload
    var media_id_bytes: [8]u8 = undefined;
    std.crypto.random.bytes(&media_id_bytes);
    const media_id_hex = std.fmt.bytesToHex(media_id_bytes, .lower);

    const media_response = struct {
        id: []const u8,
        type: []const u8 = "image",
        url: []const u8 = "",
        preview_url: []const u8 = "",
        text_url: []const u8 = "",
        description: ?[]const u8 = null,
    }{
        .id = &media_id_hex,
    };

    var json_buf = std.array_list.Managed(u8).init(allocator);
    defer json_buf.deinit();

    try compat.jsonStringify(media_response, .{ .emit_null_optional_fields = false }, json_buf.writer());
    try response.writer.writeAll(json_buf.items);
}

fn extractFormParam(body: []const u8, param: []const u8) ?[]const u8 {
    const param_pattern = std.fmt.allocPrint(std.heap.page_allocator, "{s}=", .{param}) catch return null;
    defer std.heap.page_allocator.free(param_pattern);

    const match_start = std.mem.indexOf(u8, body, param_pattern) orelse return null;
    const value_start = match_start + param_pattern.len;
    const end = std.mem.indexOfPos(u8, body, value_start, "&") orelse body.len;

    // URL decode (simplified)
    const value = body[value_start..end];
    // For now, just return as-is (in production, properly URL decode)
    return value;
}

fn handleSearch(allocator: std.mem.Allocator, db: *database.Database, response: anytype, request: *http.Server.Request) !void {
    // Parse query parameters
    const query_param = request.head.target;
    const query_start = std.mem.indexOf(u8, query_param, "?") orelse {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Missing query parameter\"}");
        return;
    };

    const query_str = extractQueryParam(query_param[query_start..], "q") orelse {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Missing search query\"}");
        return;
    };

    const search_type_str = extractQueryParam(query_param[query_start..], "type") orelse "statuses";
    const limit_str = extractQueryParam(query_param[query_start..], "limit") orelse "20";
    const offset_str = extractQueryParam(query_param[query_start..], "offset") orelse "0";

    // Parse parameters
    const limit = std.fmt.parseInt(u32, limit_str, 10) catch 20;
    const offset = std.fmt.parseInt(u32, offset_str, 10) catch 0;

    const search_type = if (std.mem.eql(u8, search_type_str, "accounts"))
        search_mod.SearchResultType.account
    else if (std.mem.eql(u8, search_type_str, "hashtags"))
        search_mod.SearchResultType.hashtag
    else
        search_mod.SearchResultType.status;

    // Perform search
    const search_options = search_mod.SearchOptions{
        .query = query_str,
        .type = search_type,
        .limit = @min(limit, 40), // Cap at 40 results
        .offset = offset,
    };

    const results = try search_mod.search(db, allocator, search_options);
    defer {
        for (results) |*result| result.deinit(allocator);
        allocator.free(results);
    }

    // Convert to Mastodon v1 search format
    var accounts = std.array_list.Managed(struct {
        id: []const u8,
        username: []const u8,
        display_name: []const u8,
        avatar: []const u8,
    }).init(allocator);
    defer accounts.deinit();

    var statuses = std.array_list.Managed(struct {
        id: []const u8,
        content: []const u8,
        created_at: []const u8,
        account: struct {
            id: []const u8,
            username: []const u8,
            display_name: []const u8,
        },
    }).init(allocator);
    defer statuses.deinit();

    var hashtags = std.array_list.Managed(struct {
        name: []const u8,
        url: []const u8,
    }).init(allocator);
    defer hashtags.deinit();

    for (results) |result| {
        switch (result.type) {
            .account => {
                try accounts.append(.{
                    .id = try allocator.dupe(u8, result.id),
                    .username = result.username.?,
                    .display_name = result.display_name orelse result.username.?,
                    .avatar = "", // TODO: Add avatar URL
                });
            },
            .status => {
                try statuses.append(.{
                    .id = try allocator.dupe(u8, result.id),
                    .content = try allocator.dupe(u8, result.content),
                    .created_at = result.created_at.?,
                    .account = .{
                        .id = "1", // TODO: Get actual account ID
                        .username = result.username.?,
                        .display_name = result.display_name orelse result.username.?,
                    },
                });
            },
            .hashtag => {
                try hashtags.append(.{
                    .name = try allocator.dupe(u8, result.content),
                    .url = try allocator.dupe(u8, result.url),
                });
            },
        }
    }

    const search_response = struct {
        accounts: []@TypeOf(accounts.items[0]),
        statuses: []@TypeOf(statuses.items[0]),
        hashtags: []@TypeOf(hashtags.items[0]),
    }{
        .accounts = accounts.items,
        .statuses = statuses.items,
        .hashtags = hashtags.items,
    };

    var json_buf = std.array_list.Managed(u8).init(allocator);
    defer json_buf.deinit();

    try compat.jsonStringify(search_response, .{}, json_buf.writer());
    try response.writer.writeAll(json_buf.items);
}

fn handleSearchV2(allocator: std.mem.Allocator, db: *database.Database, response: anytype, request: *http.Server.Request) !void {
    // Parse query parameters (same as v1 but with different response format)
    const query_param = request.head.target;
    const query_start = std.mem.indexOf(u8, query_param, "?") orelse {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Missing query parameter\"}");
        return;
    };

    const query_str = extractQueryParam(query_param[query_start..], "q") orelse {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Missing search query\"}");
        return;
    };

    const search_type_str = extractQueryParam(query_param[query_start..], "type") orelse null;
    const limit_str = extractQueryParam(query_param[query_start..], "limit") orelse "20";
    const offset_str = extractQueryParam(query_param[query_start..], "offset") orelse "0";

    // Parse parameters
    const limit = std.fmt.parseInt(u32, limit_str, 10) catch 20;
    const offset = std.fmt.parseInt(u32, offset_str, 10) catch 0;

    var search_options = search_mod.SearchOptions{
        .query = query_str,
        .limit = @min(limit, 40),
        .offset = offset,
    };

    // Set search type if specified
    if (search_type_str) |type_str| {
        if (std.mem.eql(u8, type_str, "accounts")) {
            search_options.type = .account;
        } else if (std.mem.eql(u8, type_str, "statuses")) {
            search_options.type = .status;
        } else if (std.mem.eql(u8, type_str, "hashtags")) {
            search_options.type = .hashtag;
        }
    }

    // Perform search
    const results = try search_mod.search(db, allocator, search_options);
    defer {
        for (results) |*result| result.deinit(allocator);
        allocator.free(results);
    }

    // Convert to unified search results format (Mastodon v2)
    var unified_results = std.array_list.Managed(struct {
        type: []const u8,
        id: []const u8,
        value: []const u8,
        url: []const u8,
    }).init(allocator);
    defer {
        for (unified_results.items) |*result| {
            allocator.free(result.type);
            allocator.free(result.id);
            allocator.free(result.value);
            allocator.free(result.url);
        }
        unified_results.deinit();
    }

    for (results) |result| {
        const result_type = switch (result.type) {
            .account => "accounts",
            .status => "statuses",
            .hashtag => "hashtags",
        };

        const value = switch (result.type) {
            .account => if (result.display_name) |dn| dn else result.username.?,
            .status => result.content,
            .hashtag => result.content,
        };

        try unified_results.append(.{
            .type = try allocator.dupe(u8, result_type),
            .id = try allocator.dupe(u8, result.id),
            .value = try allocator.dupe(u8, value),
            .url = try allocator.dupe(u8, result.url),
        });
    }

    var json_buf = std.array_list.Managed(u8).init(allocator);
    defer json_buf.deinit();

    try compat.jsonStringify(unified_results.items, .{}, json_buf.writer());
    try response.writer.writeAll(json_buf.items);
}

fn handleTrendingTags(allocator: std.mem.Allocator, db: *database.Database, response: anytype, request: *http.Server.Request) !void {
    // Parse limit parameter
    const query_param = request.head.target;
    const limit_str = if (std.mem.indexOf(u8, query_param, "?")) |query_start| blk: {
        break :blk extractQueryParam(query_param[query_start..], "limit") orelse "10";
    } else "10";

    const limit = std.fmt.parseInt(u32, limit_str, 10) catch 10;
    const capped_limit = @min(limit, 20); // Cap at 20 trending tags

    // Get trending hashtags
    const trending_tags = try search_mod.getTrendingHashtags(db, allocator, capped_limit);
    defer {
        for (trending_tags) |tag| {
            allocator.free(tag.hashtag);
        }
        allocator.free(trending_tags);
    }

    // Convert to Mastodon tag format
    const TagHistory = struct {
        day: []const u8,
        uses: []const u8,
        accounts: []const u8,
    };
    const MastodonTag = struct {
        name: []const u8,
        url: []const u8,
        history: []const TagHistory = &[_]TagHistory{},
    };
    var mastodon_tags = std.array_list.Managed(MastodonTag).init(allocator);
    defer {
        for (mastodon_tags.items) |*tag| {
            allocator.free(tag.name);
            allocator.free(tag.url);
        }
        mastodon_tags.deinit();
    }

    for (trending_tags) |tag| {
        try mastodon_tags.append(.{
            .name = try allocator.dupe(u8, tag.hashtag),
            .url = try std.fmt.allocPrint(allocator, "https://speedy-socials.local/tags/{s}", .{tag.hashtag}),
        });
    }

    var json_buf = std.array_list.Managed(u8).init(allocator);
    defer json_buf.deinit();

    try compat.jsonStringify(mastodon_tags.items, .{}, json_buf.writer());
    try response.writer.writeAll(json_buf.items);
}

// Handle WebSocket upgrade and connection
fn handleWebSocketUpgrade(allocator: std.mem.Allocator, websocket_server: *websocket.WebSocketServer, stream: anytype, request: anytype) !void {
    const sec_websocket_key = request.head.get("sec-websocket-key").?;
    _ = request.head.get("sec-websocket-version").?;

    // Generate WebSocket accept key
    const magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    var combined = std.array_list.Managed(u8).init(allocator);
    defer combined.deinit();

    try combined.appendSlice(std.mem.span(sec_websocket_key));
    try combined.appendSlice(magic_string);

    var hash: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(combined.items, &hash);

    var encoded: [28]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&encoded, &hash);

    // Send 101 Switching Protocols response
    const response =
        "HTTP/1.1 101 Switching Protocols\r\n" ++
        "Upgrade: websocket\r\n" ++
        "Connection: Upgrade\r\n" ++
        "Sec-WebSocket-Accept: {s}\r\n" ++
        "\r\n";

    var response_buf = std.array_list.Managed(u8).init(allocator);
    defer response_buf.deinit();

    try std.fmt.format(response_buf.writer(), response, .{@as([]const u8, &encoded)});

    // Send the response
    _ = try stream.write(response_buf.items);

    // Create WebSocket client
    const client_id = try websocket.generateClientId(allocator);
    var client = try websocket.WebSocketClient.init(allocator, client_id, null); // TODO: Set user_id from auth
    defer client.deinit();

    // Add client to WebSocket server
    try websocket_server.addClient(client);

    // Handle WebSocket frames
    try handleWebSocketConnection(allocator, websocket_server, &client, stream, client_id);
}

// Handle WebSocket connection after upgrade
fn handleWebSocketConnection(allocator: std.mem.Allocator, websocket_server: *websocket.WebSocketServer, client: *websocket.WebSocketClient, stream: anytype, client_id: []const u8) !void {
    defer websocket_server.removeClient(client_id);

    // Set up buffered reader
    var buf_reader = std.io.bufferedReader(stream.reader());
    const reader = buf_reader.reader();

    // Connection loop
    while (true) {
        // Read WebSocket frame
        const frame = try client.protocol.readFrame(reader) orelse break;

        // Handle the frame
        const keep_alive = try client.handleFrame(frame, stream.writer());

        // Free frame payload
        allocator.free(frame.payload);

        if (!keep_alive) {
            break;
        }

        // Send ping every 30 seconds to keep connection alive
        const now = std.time.timestamp();
        if (now - client.last_ping > 30) {
            try client.sendPing(stream.writer());
        }
    }

    std.debug.print("WebSocket client {s} disconnected\n", .{client_id});
}

// Create ActivityPub Create activity for a new post
fn createActivityPubCreate(allocator: std.mem.Allocator, post: database.Post, user_id: i64) ![]u8 {
    const activity = struct {
        @"@context": []const []const u8 = &[_][]const u8{
            "https://www.w3.org/ns/activitystreams",
            "https://w3id.org/security/v1",
        },
        id: []const u8,
        type: []const u8 = "Create",
        actor: []const u8,
        published: []const u8,
        to: []const []const u8,
        cc: []const []const u8,
        object: struct {
            id: []const u8,
            type: []const u8 = "Note",
            attributedTo: []const u8,
            content: []const u8,
            published: []const u8,
            to: []const []const u8,
            cc: []const []const u8,
            url: []const u8,
        },
    }{
        .id = try std.fmt.allocPrint(allocator, "https://speedy-socials.local/activities/{}", .{post.id}),
        .actor = try std.fmt.allocPrint(allocator, "https://speedy-socials.local/users/{}", .{user_id}),
        .published = post.created_at,
        .to = &[_][]const u8{"https://www.w3.org/ns/activitystreams#Public"},
        .cc = &[_][]const u8{try std.fmt.allocPrint(allocator, "https://speedy-socials.local/users/{}/followers", .{user_id})},
        .object = .{
            .id = try std.fmt.allocPrint(allocator, "https://speedy-socials.local/notes/{}", .{post.id}),
            .attributedTo = try std.fmt.allocPrint(allocator, "https://speedy-socials.local/users/{}", .{user_id}),
            .content = post.content,
            .published = post.created_at,
            .to = &[_][]const u8{"https://www.w3.org/ns/activitystreams#Public"},
            .cc = &[_][]const u8{try std.fmt.allocPrint(allocator, "https://speedy-socials.local/users/{}/followers", .{user_id})},
            .url = try std.fmt.allocPrint(allocator, "https://speedy-socials.local/notes/{}", .{post.id}),
        },
    };

    defer allocator.free(activity.id);
    defer allocator.free(activity.actor);
    defer allocator.free(activity.cc[0]);
    defer allocator.free(activity.object.id);
    defer allocator.free(activity.object.attributedTo);
    defer allocator.free(activity.object.cc[0]);
    defer allocator.free(activity.object.url);

    var json_buf = std.array_list.Managed(u8).init(allocator);
    errdefer json_buf.deinit();

    try compat.jsonStringify(activity, .{}, json_buf.writer());
    return json_buf.toOwnedSlice();
}

// Handle account blocking
fn handleBlockAccount(_: std.mem.Allocator, db: *database.Database, response: anytype, method: http.Method, target_account_id: i64) !void {
    if (method != .POST) {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
        return;
    }

    // For demo, use user ID 1 as the blocker
    const blocker_id: i64 = 1;

    try database.blockUser(db, blocker_id, target_account_id);
    // Note: status cannot be changed after respondStreaming in Zig 0.15
    try response.writer.writeAll("{}");
}

// Handle account unblocking
fn handleUnblockAccount(_: std.mem.Allocator, db: *database.Database, response: anytype, method: http.Method, target_account_id: i64) !void {
    if (method != .POST) {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
        return;
    }

    // For demo, use user ID 1 as the blocker
    const blocker_id: i64 = 1;

    try database.unblockUser(db, blocker_id, target_account_id);
    // Note: status cannot be changed after respondStreaming in Zig 0.15
    try response.writer.writeAll("{}");
}

// Handle account muting
fn handleMuteAccount(_: std.mem.Allocator, db: *database.Database, response: anytype, method: http.Method, target_account_id: i64) !void {
    if (method != .POST) {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
        return;
    }

    // For demo, use user ID 1 as the muter
    const muter_id: i64 = 1;

    try database.muteUser(db, muter_id, target_account_id);
    // Note: status cannot be changed after respondStreaming in Zig 0.15
    try response.writer.writeAll("{}");
}

// Handle account unmuting
fn handleUnmuteAccount(_: std.mem.Allocator, db: *database.Database, response: anytype, method: http.Method, target_account_id: i64) !void {
    if (method != .POST) {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
        return;
    }

    // For demo, use user ID 1 as the muter
    const muter_id: i64 = 1;

    try database.unmuteUser(db, muter_id, target_account_id);
    // Note: status cannot be changed after respondStreaming in Zig 0.15
    try response.writer.writeAll("{}");
}

// Handle reports endpoint
fn handleReports(allocator: std.mem.Allocator, db: *database.Database, response: anytype, method: http.Method, path: []const u8, request: *http.Server.Request) !void {
    if (std.mem.eql(u8, path, "/api/v1/reports")) {
        if (method == .POST) {
            var read_buf: [8192]u8 = undefined;
            const reader = request.readerExpectNone(&read_buf);
            const body = reader.allocRemaining(allocator, std.io.Limit.limited(1024 * 1024)) catch {
                try response.writer.writeAll("{\"error\": \"Failed to read request body\"}");
                return;
            };
            defer allocator.free(body);

            // Parse JSON body for report
            const parsed = std.json.parseFromSlice(std.json.Value, allocator, body, .{}) catch {
                try response.writer.writeAll("{\"error\": \"Invalid JSON\"}");
                return;
            };
            defer parsed.deinit();

            const root = parsed.value.object;
            const account_id_str = if (root.get("account_id")) |a| switch (a) {
                .string => |str| str,
                else => null,
            } else null;

            const reported_user_id: ?i64 = if (account_id_str) |s| std.fmt.parseInt(i64, s, 10) catch null else null;

            const category = if (root.get("category")) |c| switch (c) {
                .string => |str| str,
                else => "other",
            } else "other";

            const comment: ?[]const u8 = if (root.get("comment")) |c| switch (c) {
                .string => |str| str,
                else => null,
            } else null;

            // For demo, reporter is user ID 1
            const reporter_id: i64 = 1;
            const report_id = database.createReport(db, reporter_id, reported_user_id, null, category, comment) catch {
                try response.writer.writeAll("{\"error\": \"Failed to create report\"}");
                return;
            };

            const id_str = try std.fmt.allocPrint(allocator, "{}", .{report_id});
            defer allocator.free(id_str);

            const report_response = struct {
                id: []const u8,
                action_taken: bool = false,
                category: []const u8,
                comment: ?[]const u8,
            }{
                .id = id_str,
                .category = category,
                .comment = comment,
            };

            var json_buf = std.array_list.Managed(u8).init(allocator);
            defer json_buf.deinit();

            try compat.jsonStringify(report_response, .{ .emit_null_optional_fields = false }, json_buf.writer());
            try response.writer.writeAll(json_buf.items);
        } else {
            // Note: status cannot be changed after respondStreaming in Zig 0.15
            try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
        }
    } else {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Not found\"}");
    }
}

// Handle bookmarking a status
fn handleBookmarkStatus(_: std.mem.Allocator, db: *database.Database, response: anytype, method: http.Method, status_id: i64) !void {
    if (method != .POST) {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
        return;
    }

    // For demo, use user ID 1
    const user_id: i64 = 1;

    try database.bookmarkPost(db, user_id, status_id);
    // Note: status cannot be changed after respondStreaming in Zig 0.15
    try response.writer.writeAll("{}");
}

// Handle unbookmarking a status
fn handleUnbookmarkStatus(_: std.mem.Allocator, db: *database.Database, response: anytype, method: http.Method, status_id: i64) !void {
    if (method != .POST) {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
        return;
    }

    // For demo, use user ID 1
    const user_id: i64 = 1;

    try database.unbookmarkPost(db, user_id, status_id);
    // Note: status cannot be changed after respondStreaming in Zig 0.15
    try response.writer.writeAll("{}");
}

// Handle featuring a status (pinning)
fn handleFeatureStatus(_: std.mem.Allocator, db: *database.Database, response: anytype, method: http.Method, status_id: i64) !void {
    if (method != .POST) {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
        return;
    }

    // For demo, use user ID 1
    const user_id: i64 = 1;

    try database.featurePost(db, user_id, status_id);
    // Note: status cannot be changed after respondStreaming in Zig 0.15
    try response.writer.writeAll("{}");
}

// Handle unfeaturing a status (unpinning)
fn handleUnfeatureStatus(_: std.mem.Allocator, db: *database.Database, response: anytype, method: http.Method, status_id: i64) !void {
    if (method != .POST) {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
        return;
    }

    // For demo, use user ID 1
    const user_id: i64 = 1;

    try database.unfeaturePost(db, user_id, status_id);
    // Note: status cannot be changed after respondStreaming in Zig 0.15
    try response.writer.writeAll("{}");
}

// Handle WebFinger discovery
fn handleWebFinger(allocator: std.mem.Allocator, _: *database.Database, response: anytype, request: *http.Server.Request) !void {
    // Parse resource parameter
    const query_param = request.head.target;
    const query_start = std.mem.indexOf(u8, query_param, "?") orelse {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Missing query parameter\"}");
        return;
    };

    const resource = extractQueryParam(query_param[query_start..], "resource") orelse {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Missing resource parameter\"}");
        return;
    };

    var fed = federation.Federation.init(allocator);
    try fed.handleWebFinger(response, resource);
}

// Handle ActivityPub actor routes
fn handleActivityPubActorRoutes(_: std.mem.Allocator, _: *database.Database, response: anytype, _: http.Method, _: []const u8, _: *http.Server.Request) !void {
    // Stub: ActivityPub actor routes
    // Note: status cannot be changed after respondStreaming in Zig 0.15
    try response.writer.writeAll("{\"error\": \"ActivityPub actor route not implemented\"}");
}

// Handle shared inbox for federation
fn handleSharedInbox(allocator: std.mem.Allocator, db: *database.Database, response: anytype, method: http.Method, request: *http.Server.Request) !void {
    if (method != .POST) {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
        return;
    }

    var fed = federation.Federation.init(allocator);
    try fed.handleInbox(db, response, request);
}

// Handle list-specific routes
fn handleListRoutes(allocator: std.mem.Allocator, db: *database.Database, response: anytype, method: http.Method, path: []const u8, request: *http.Server.Request) !void {
    const prefix = "/api/v1/lists/";
    if (!std.mem.startsWith(u8, path, prefix)) {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Invalid list path\"}");
        return;
    }

    const remaining = path[prefix.len..];
    var mastodon_inst = mastodon_api.MastodonAPI.init(allocator);

    // Check for accounts endpoint: /api/v1/lists/{id}/accounts
    if (std.mem.indexOf(u8, remaining, "/accounts")) |accounts_pos| {
        const list_id_str = remaining[0..accounts_pos];
        const accounts_part = remaining[accounts_pos + "/accounts".len ..];

        const list_id = std.fmt.parseInt(i64, list_id_str, 10) catch {
            // Note: status cannot be changed after respondStreaming in Zig 0.15
            try response.writer.writeAll("{\"error\": \"Invalid list ID\"}");
            return;
        };

        // Handle account operations: /api/v1/lists/{id}/accounts/{account_id}
        if (std.mem.indexOf(u8, accounts_part, "/")) |account_pos| {
            const account_id_str = accounts_part[1..account_pos]; // Skip leading slash
            const account_id = std.fmt.parseInt(i64, account_id_str, 10) catch {
                // Note: status cannot be changed after respondStreaming in Zig 0.15
                try response.writer.writeAll("{\"error\": \"Invalid account ID\"}");
                return;
            };

            if (method == .POST) {
                try mastodon_inst.handleAddToList(db, response, method, list_id, account_id);
            } else if (method == .DELETE) {
                try mastodon_inst.handleRemoveFromList(db, response, method, list_id, account_id);
            } else {
                // Note: status cannot be changed after respondStreaming in Zig 0.15
                try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
            }
        } else {
            // Just /api/v1/lists/{id}/accounts - get list accounts
            // For now, return empty array (simplified implementation)
            try response.writer.writeAll("[]");
        }
        return;
    }

    // Check for timeline endpoint: /api/v1/lists/{id}/statuses
    if (std.mem.indexOf(u8, remaining, "/statuses")) |statuses_pos| {
        const list_id_str = remaining[0..statuses_pos];
        const list_id = std.fmt.parseInt(i64, list_id_str, 10) catch {
            // Note: status cannot be changed after respondStreaming in Zig 0.15
            try response.writer.writeAll("{\"error\": \"Invalid list ID\"}");
            return;
        };

        try mastodon_inst.handleListTimeline(db, response, list_id, request);
        return;
    }

    // Just /api/v1/lists/{id} - get, update, or delete list
    const list_id = std.fmt.parseInt(i64, remaining, 10) catch {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Invalid list ID\"}");
        return;
    };

    if (method == .GET) {
        try mastodon_inst.handleGetList(db, response, list_id);
    } else if (method == .PUT) {
        try mastodon_inst.handleUpdateList(db, response, request, list_id);
    } else if (method == .DELETE) {
        try mastodon_inst.handleDeleteList(db, response, method, list_id);
    } else {
        // Note: status cannot be changed after respondStreaming in Zig 0.15
        try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
    }
}
