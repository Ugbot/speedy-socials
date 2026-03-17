const std = @import("std");
const http = std.http;
const database = @import("../database.zig");
const activitypub = @import("../activitypub.zig");
const websocket = @import("../websocket.zig");
const compat = @import("../compat.zig");

// Mastodon API v1 endpoints
pub const MastodonAPI = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) MastodonAPI {
        return MastodonAPI{
            .allocator = allocator,
        };
    }

    // Handle instance information endpoint
    pub fn handleInstanceInfo(self: *MastodonAPI, response: anytype) !void {
        const instance = struct {
            uri: []const u8 = "speedy-socials.local",
            title: []const u8 = "Speedy Socials",
            description: []const u8 = "A high-performance social media platform built with Zig",
            short_description: []const u8 = "Fast social media in Zig",
            email: []const u8 = "admin@speedy-socials.local",
            version: []const u8 = "1.0.0",
            languages: []const []const u8 = &[_][]const u8{"en"},
            registrations: bool = true,
            approval_required: bool = false,
            invites_enabled: bool = false,
            urls: struct {
                streaming_api: []const u8 = "wss://speedy-socials.local",
            } = .{},
            stats: struct {
                user_count: u32 = 1,
                status_count: u32 = 3,
                domain_count: u32 = 1,
            } = .{},
            thumbnail: ?[]const u8 = null,
            contact_account: ?struct {
                id: []const u8 = "1",
                username: []const u8 = "admin",
                acct: []const u8 = "admin",
                display_name: []const u8 = "Admin",
                locked: bool = false,
                bot: bool = false,
                discoverable: bool = true,
                group: bool = false,
                created_at: []const u8 = "2024-01-01T00:00:00.000Z",
                note: []const u8 = "Instance administrator",
                url: []const u8 = "https://speedy-socials.local/@admin",
                avatar: []const u8 = "",
                header: []const u8 = "",
                followers_count: u32 = 0,
                following_count: u32 = 0,
                statuses_count: u32 = 0,
            } = .{},
        }{};

        var json_buf = std.array_list.Managed(u8).init(self.allocator);
        defer json_buf.deinit();

        try compat.jsonStringify(instance, .{}, json_buf.writer());
        try response.writer.writeAll(json_buf.items);
    }

    // Handle account information endpoint
    pub fn handleAccountInfo(self: *MastodonAPI, db: *database.Database, response: anytype, account_id: i64) !void {
        // Get user from database
        const user = (try database.getUserById(db, self.allocator, account_id)) orelse {
            response.status = .not_found;
            try response.writer.writeAll("{\"error\": \"Account not found\"}");
            return;
        };
        defer database.User.deinit(user, self.allocator);

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
            .id = try std.fmt.allocPrint(self.allocator, "{}", .{user.id}),
            .username = user.username,
            .acct = user.username,
            .display_name = user.display_name orelse user.username,
            .locked = user.is_locked,
            .created_at = user.created_at,
            .note = user.bio orelse "",
            .url = try std.fmt.allocPrint(self.allocator, "https://speedy-socials.local/@{s}", .{user.username}),
            .avatar = user.avatar_url orelse "",
            .header = user.header_url orelse "",
        };
        defer self.allocator.free(account.id);
        defer self.allocator.free(account.url);

        var json_buf = std.array_list.Managed(u8).init(self.allocator);
        defer json_buf.deinit();

        try compat.jsonStringify(account, .{}, json_buf.writer());
        try response.writer.writeAll(json_buf.items);
    }

    // Handle account statuses endpoint
    pub fn handleAccountStatuses(self: *MastodonAPI, db: *database.Database, response: anytype, account_id: i64) !void {
        const posts = try database.getPostsByUser(db, self.allocator, account_id, 20, 0);
        defer {
            for (posts) |post| database.Post.deinit(post, self.allocator);
            self.allocator.free(posts);
        }

        var mastodon_posts = std.array_list.Managed(struct {
            id: []const u8,
            content: []const u8,
            created_at: []const u8,
            visibility: []const u8,
            account: struct {
                id: []const u8,
                username: []const u8,
                display_name: []const u8,
            },
        }).init(self.allocator);
        defer {
            for (mastodon_posts.items) |post| {
                self.allocator.free(post.id);
                self.allocator.free(post.account.id);
            }
            mastodon_posts.deinit();
        }

        for (posts) |post| {
            try mastodon_posts.append(.{
                .id = try std.fmt.allocPrint(self.allocator, "{}", .{post.id}),
                .content = post.content,
                .created_at = post.created_at,
                .visibility = post.visibility,
                .account = .{
                    .id = try std.fmt.allocPrint(self.allocator, "{}", .{post.user_id}),
                    .username = "demo", // TODO: Get actual username
                    .display_name = "Demo User",
                },
            });
        }

        var json_buf = std.array_list.Managed(u8).init(self.allocator);
        defer json_buf.deinit();

        try compat.jsonStringify(mastodon_posts.items, .{}, json_buf.writer());
        try response.writer.writeAll(json_buf.items);
    }

    // Handle home timeline
    pub fn handleHomeTimeline(self: *MastodonAPI, db: *database.Database, response: anytype) !void {
        // For demo, return all posts
        const posts = try database.getPosts(db, self.allocator, 20, 0);
        defer {
            for (posts) |post| database.Post.deinit(post, self.allocator);
            self.allocator.free(posts);
        }

        try self.sendPostsWithPolls(db, response, posts);
    }

    // Send posts with poll information
    fn sendPostsWithPolls(self: *MastodonAPI, db: *database.Database, response: anytype, posts: []database.Post) !void {
        var mastodon_posts = std.array_list.Managed(struct {
            id: []const u8,
            content: []const u8,
            created_at: []const u8,
            visibility: []const u8,
            poll: ?struct {
                id: []const u8,
                expires_at: ?[]const u8,
                expired: bool,
                multiple: bool,
                votes_count: i64,
                voters_count: ?i64,
                options: []const struct {
                    title: []const u8,
                    votes_count: i64,
                },
                emojis: []const u8,
            },
            account: struct {
                id: []const u8,
                username: []const u8,
                display_name: []const u8,
            },
        }).init(self.allocator);
        defer {
            for (mastodon_posts.items) |post| {
                self.allocator.free(post.id);
                self.allocator.free(post.account.id);
                if (post.poll) |poll| {
                    self.allocator.free(poll.id);
                    for (poll.options) |option| {
                        self.allocator.free(option.title);
                    }
                    self.allocator.free(poll.options);
                }
            }
            mastodon_posts.deinit();
        }

        for (posts) |post| {
            const poll_data = if (post.poll) |poll| blk: {
                // Get poll options
                const options = try database.getPollOptions(db, self.allocator, poll.id);
                defer {
                    for (options) |option| database.PollOption.deinit(option, self.allocator);
                    self.allocator.free(options);
                }

                var mastodon_options = std.array_list.Managed(struct {
                    title: []const u8,
                    votes_count: i64,
                }).init(self.allocator);
                errdefer {
                    for (mastodon_options.items) |opt| self.allocator.free(opt.title);
                    mastodon_options.deinit();
                }

                for (options) |option| {
                    try mastodon_options.append(.{
                        .title = try self.allocator.dupe(u8, option.title),
                        .votes_count = if (poll.hide_totals) 0 else option.votes_count,
                    });
                }

                break :blk struct {
                    id: []const u8,
                    expires_at: ?[]const u8,
                    expired: bool,
                    multiple: bool,
                    votes_count: i64,
                    voters_count: ?i64,
                    options: []const struct {
                        title: []const u8,
                        votes_count: i64,
                    },
                    emojis: []const u8,
                }{
                    .id = try std.fmt.allocPrint(self.allocator, "{}", .{poll.id}),
                    .expires_at = poll.expires_at,
                    .expired = false, // TODO: Check expiration
                    .multiple = poll.multiple,
                    .votes_count = if (poll.hide_totals) 0 else poll.voters_count,
                    .voters_count = if (poll.hide_totals) null else poll.voters_count,
                    .options = try mastodon_options.toOwnedSlice(),
                    .emojis = &[_][]const u8{},
                };
            } else null;

            try mastodon_posts.append(.{
                .id = try std.fmt.allocPrint(self.allocator, "{}", .{post.id}),
                .content = post.content,
                .created_at = post.created_at,
                .visibility = post.visibility,
                .poll = poll_data,
                .account = .{
                    .id = try std.fmt.allocPrint(self.allocator, "{}", .{post.user_id}),
                    .username = "demo",
                    .display_name = "Demo User",
                },
            });
        }

        var json_buf = std.array_list.Managed(u8).init(self.allocator);
        defer json_buf.deinit();

        try compat.jsonStringify(mastodon_posts.items, .{}, json_buf.writer());
        try response.writer.writeAll(json_buf.items);
    }

    // Handle public timeline
    pub fn handlePublicTimeline(self: *MastodonAPI, db: *database.Database, response: anytype) !void {
        // Same as home timeline for now
        try self.handleHomeTimeline(db, response);
    }

    // Handle creating a status
    pub fn handleCreateStatus(self: *MastodonAPI, db: *database.Database, response: anytype, request: *http.Server.Request) !void {
        // Read request body
        var body_buf = std.array_list.Managed(u8).init(self.allocator);
        defer body_buf.deinit();

        try request.reader().readAllArrayList(&body_buf, 10 * 1024 * 1024); // 10MB limit

        // Parse JSON
        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, body_buf.items, .{});
        defer parsed.deinit();

        const status_text = parsed.value.object.get("status") orelse {
            response.status = .bad_request;
            try response.writer.writeAll("{\"error\": \"Missing status text\"}");
            return;
        };

        if (status_text != .string) {
            response.status = .bad_request;
            try response.writer.writeAll("{\"error\": \"Status must be a string\"}");
            return;
        }

        // Get visibility (default to "public")
        const visibility = if (parsed.value.object.get("visibility")) |vis| blk: {
            if (vis == .string) {
                break :blk vis.string;
            }
            break :blk "public";
        } else "public";

        // For demo, use user ID 1 (demo user)
        const user_id: i64 = 1;

        // Create post in database
        const post_id = try database.createPost(db, self.allocator, user_id, status_text.string, visibility);

        // Check if there's a poll in the request
        var poll_id: ?i64 = null;
        if (parsed.value.object.get("poll")) |poll_data| {
            if (poll_data == .object) {
                poll_id = try self.createPollFromRequest(db, poll_data.object, post_id);
            }
        }

        // Get the created post
        const post = (try database.getPostsByUser(db, self.allocator, user_id, 1, 0))[0];
        defer database.Post.deinit(post, self.allocator);

        // Create ActivityPub Create activity
        const activity_json = try self.createActivityPubCreate(post, user_id);
        defer self.allocator.free(activity_json);

        // Broadcast to followers (simplified - in real implementation, use job queue)
        const private_key_pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC...\n-----END PRIVATE KEY-----"; // Placeholder
        const key_id = try std.fmt.allocPrint(self.allocator, "https://speedy-socials.local/users/demo#main-key", .{});
        defer self.allocator.free(key_id);

        // Queue federation delivery (simplified - in real implementation, use job queue)
        try activitypub.broadcastToFollowers(self.allocator, db, undefined, activity_json, user_id, private_key_pem, key_id);

        // Return created post as Mastodon API response
        var json_buf = std.array_list.Managed(u8).init(self.allocator);
        defer json_buf.deinit();

        try self.createMastodonPostResponse(&json_buf, post);
        response.status = .created;
        try response.writer.writeAll(json_buf.items);
    }

    // Handle favouriting a status
    pub fn handleFavouriteStatus(_: *MastodonAPI, db: *database.Database, response: anytype, method: http.Method, status_id: i64) !void {
        if (method != .POST) {
            response.status = .method_not_allowed;
            try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
            return;
        }

        // For demo, use user ID 1
        const user_id: i64 = 1;

        try database.favouritePost(db, user_id, status_id);
        response.status = .ok;
        try response.writer.writeAll("{}");
    }

    // Handle reblogging a status
    pub fn handleReblogStatus(self: *MastodonAPI, db: *database.Database, response: anytype, method: http.Method, _: i64) !void {
        if (method != .POST) {
            response.status = .method_not_allowed;
            try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
            return;
        }

        // For demo, use user ID 1
        const user_id: i64 = 1;

        _ = try database.createPost(db, self.allocator, user_id, "", "public"); // TODO: Implement proper reblog
        response.status = .ok;
        try response.writer.writeAll("{}");
    }

    // Handle user registration
    pub fn handleRegisterAccount(self: *MastodonAPI, db: *database.Database, response: anytype, request: *http.Server.Request) !void {
        // Read request body
        var body_buf = std.array_list.Managed(u8).init(self.allocator);
        defer body_buf.deinit();

        try request.reader().readAllArrayList(&body_buf, 10 * 1024);

        // Parse JSON
        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, body_buf.items, .{});
        defer parsed.deinit();

        const username = parsed.value.object.get("username") orelse {
            response.status = .bad_request;
            try response.writer.writeAll("{\"error\": \"Missing username\"}");
            return;
        };

        const email = parsed.value.object.get("email") orelse {
            response.status = .bad_request;
            try response.writer.writeAll("{\"error\": \"Missing email\"}");
            return;
        };

        const password = parsed.value.object.get("password") orelse {
            response.status = .bad_request;
            try response.writer.writeAll("{\"error\": \"Missing password\"}");
            return;
        };

        if (username != .string or email != .string or password != .string) {
            response.status = .bad_request;
            try response.writer.writeAll("{\"error\": \"Invalid parameters\"}");
            return;
        }

        // Hash password (simplified)
        const password_hash = password.string; // TODO: Proper hashing

        // Create user
        const user_id = try database.createUser(db, self.allocator, username.string, email.string, password_hash);

        const account_response = struct {
            id: []const u8,
            username: []const u8,
            email: []const u8,
        }{
            .id = try std.fmt.allocPrint(self.allocator, "{}", .{user_id}),
            .username = username.string,
            .email = email.string,
        };
        defer self.allocator.free(account_response.id);

        var json_buf = std.array_list.Managed(u8).init(self.allocator);
        defer json_buf.deinit();

        try compat.jsonStringify(account_response, .{}, json_buf.writer());
        response.status = .ok;
        try response.writer.writeAll(json_buf.items);
    }

    // Create ActivityPub Create activity for a new post
    fn createActivityPubCreate(self: *MastodonAPI, post: database.Post, user_id: i64) ![]u8 {
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
            .id = try std.fmt.allocPrint(self.allocator, "https://speedy-socials.local/activities/{}", .{post.id}),
            .actor = try std.fmt.allocPrint(self.allocator, "https://speedy-socials.local/users/{}", .{user_id}),
            .published = post.created_at,
            .to = &[_][]const u8{"https://www.w3.org/ns/activitystreams#Public"},
            .cc = &[_][]const u8{try std.fmt.allocPrint(self.allocator, "https://speedy-socials.local/users/{}/followers", .{user_id})},
            .object = .{
                .id = try std.fmt.allocPrint(self.allocator, "https://speedy-socials.local/notes/{}", .{post.id}),
                .attributedTo = try std.fmt.allocPrint(self.allocator, "https://speedy-socials.local/users/{}", .{user_id}),
                .content = post.content,
                .published = post.created_at,
                .to = &[_][]const u8{"https://www.w3.org/ns/activitystreams#Public"},
                .cc = &[_][]const u8{try std.fmt.allocPrint(self.allocator, "https://speedy-socials.local/users/{}/followers", .{user_id})},
                .url = try std.fmt.allocPrint(self.allocator, "https://speedy-socials.local/notes/{}", .{post.id}),
            },
        };

        defer self.allocator.free(activity.id);
        defer self.allocator.free(activity.actor);
        defer self.allocator.free(activity.cc[0]);
        defer self.allocator.free(activity.object.id);
        defer self.allocator.free(activity.object.attributedTo);
        defer self.allocator.free(activity.object.cc[0]);
        defer self.allocator.free(activity.object.url);

        var json_buf = std.array_list.Managed(u8).init(self.allocator);
        errdefer json_buf.deinit();

        try compat.jsonStringify(activity, .{}, json_buf.writer());
        return json_buf.toOwnedSlice();
    }

    // Create a poll from request data
    fn createPollFromRequest(_: *MastodonAPI, db: *database.Database, poll_obj: std.json.ObjectMap, post_id: i64) !i64 {
        // Get poll options
        const options = poll_obj.get("options") orelse return error.MissingPollOptions;
        if (options != .array or options.array.items.len == 0) return error.InvalidPollOptions;

        // Get poll settings
        const multiple = if (poll_obj.get("multiple")) |m| blk: {
            break :blk m == .bool and m.bool;
        } else false;

        const hide_totals = if (poll_obj.get("hide_totals")) |h| blk: {
            break :blk h == .bool and h.bool;
        } else false;

        // Get expires_in (optional)
        const expires_at: ?[]const u8 = null;
        if (poll_obj.get("expires_in")) |exp| {
            if (exp == .integer) {
                // Convert seconds to timestamp (simplified)
                const expires_seconds = exp.integer;
                // For now, just ignore expiration
                _ = expires_seconds;
            }
        }

        // Create poll
        const poll_id = try database.createPoll(db, post_id, expires_at, multiple, hide_totals);

        // Add poll options
        for (options.array.items) |option| {
            if (option == .string) {
                _ = try database.addPollOption(db, poll_id, option.string);
            }
        }

        return poll_id;
    }

    // Create Mastodon API post response (simplified for now)
    fn createMastodonPostResponse(self: *MastodonAPI, json_buf: *std.array_list.Managed(u8), post: database.Post) !void {
        const mastodon_post = struct {
            id: []const u8,
            content: []const u8,
            created_at: []const u8,
            visibility: []const u8,
            account: struct {
                id: []const u8,
                username: []const u8,
                display_name: []const u8,
            },
        }{
            .id = try std.fmt.allocPrint(self.allocator, "{}", .{post.id}),
            .content = post.content,
            .created_at = post.created_at,
            .visibility = post.visibility,
            .account = .{
                .id = "1",
                .username = "demo",
                .display_name = "Demo User",
            },
        };
        defer self.allocator.free(mastodon_post.id);

        try compat.jsonStringify(mastodon_post, .{}, json_buf.writer());
    }

    // Handle voting on a poll
    pub fn handlePollVote(self: *MastodonAPI, db: *database.Database, response: anytype, method: http.Method, poll_id: i64, request: *http.Server.Request) !void {
        if (method != .POST) {
            response.status = .method_not_allowed;
            try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
            return;
        }

        // Read request body
        var body_buf = std.array_list.Managed(u8).init(self.allocator);
        defer body_buf.deinit();

        try request.reader().readAllArrayList(&body_buf, 1024);

        // Parse JSON
        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, body_buf.items, .{});
        defer parsed.deinit();

        const choices = parsed.value.object.get("choices") orelse {
            response.status = .bad_request;
            try response.writer.writeAll("{\"error\": \"Missing choices\"}");
            return;
        };

        if (choices != .array or choices.array.items.len == 0) {
            response.status = .bad_request;
            try response.writer.writeAll("{\"error\": \"Invalid choices\"}");
            return;
        }

        // Convert choice strings to option IDs
        var option_ids = std.array_list.Managed(i64).init(self.allocator);
        defer option_ids.deinit();

        for (choices.array.items) |choice| {
            if (choice == .string) {
                const option_id = try std.fmt.parseInt(i64, choice.string, 10);
                try option_ids.append(option_id);
            }
        }

        // For demo, use user ID 1
        const user_id: i64 = 1;

        // Vote on poll
        try database.voteOnPoll(db, poll_id, user_id, option_ids.items);

        response.status = .ok;
        try response.writer.writeAll("{}");
    }

    // Handle bookmarking a status
    pub fn handleBookmarkStatus(_: *MastodonAPI, db: *database.Database, response: anytype, method: http.Method, status_id: i64) !void {
        if (method != .POST) {
            response.status = .method_not_allowed;
            try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
            return;
        }

        // For demo, use user ID 1
        const user_id: i64 = 1;

        try database.bookmarkPost(db, user_id, status_id);
        response.status = .ok;
        try response.writer.writeAll("{}");
    }

    // Handle unbookmarking a status
    pub fn handleUnbookmarkStatus(_: *MastodonAPI, db: *database.Database, response: anytype, method: http.Method, status_id: i64) !void {
        if (method != .POST) {
            response.status = .method_not_allowed;
            try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
            return;
        }

        // For demo, use user ID 1
        const user_id: i64 = 1;

        try database.unbookmarkPost(db, user_id, status_id);
        response.status = .ok;
        try response.writer.writeAll("{}");
    }

    // Handle getting bookmarked statuses
    pub fn handleBookmarkedStatuses(self: *MastodonAPI, db: *database.Database, response: anytype, request: *http.Server.Request) !void {
        // Parse query parameters
        const query_param = request.head.target;
        const limit_str = if (std.mem.indexOf(u8, query_param, "?")) |query_start| blk: {
            break :blk extractQueryParam(query_param[query_start..], "limit") orelse "20";
        } else "20";

        const limit = std.fmt.parseInt(i64, limit_str, 10) catch 20;
        const capped_limit = @min(limit, 40); // Cap at 40 bookmarks

        // For demo, use user ID 1
        const user_id: i64 = 1;

        const posts = try database.getBookmarkedPosts(db, self.allocator, user_id, capped_limit, 0);
        defer {
            for (posts) |post| database.Post.deinit(post, self.allocator);
            self.allocator.free(posts);
        }

        try self.sendPostsWithPolls(db, response, posts);
    }

    // Handle creating a list
    pub fn handleCreateList(self: *MastodonAPI, db: *database.Database, response: anytype, request: *http.Server.Request) !void {
        // Read request body
        var body_buf = std.array_list.Managed(u8).init(self.allocator);
        defer body_buf.deinit();

        try request.reader().readAllArrayList(&body_buf, 1024);

        // Parse JSON
        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, body_buf.items, .{});
        defer parsed.deinit();

        const title = parsed.value.object.get("title") orelse {
            response.status = .bad_request;
            try response.writer.writeAll("{\"error\": \"Missing title\"}");
            return;
        };

        if (title != .string) {
            response.status = .bad_request;
            try response.writer.writeAll("{\"error\": \"Title must be a string\"}");
            return;
        }

        const replies_policy = if (parsed.value.object.get("replies_policy")) |rp| blk: {
            if (rp == .string) {
                break :blk rp.string;
            }
            break :blk "none";
        } else "none";

        // For demo, use user ID 1
        const user_id: i64 = 1;

        const list_id = try database.createList(db, user_id, title.string, replies_policy);

        const list_response = struct {
            id: []const u8,
            title: []const u8,
            replies_policy: []const u8,
        }{
            .id = try std.fmt.allocPrint(self.allocator, "{}", .{list_id}),
            .title = title.string,
            .replies_policy = replies_policy,
        };
        defer self.allocator.free(list_response.id);

        var json_buf = std.array_list.Managed(u8).init(self.allocator);
        defer json_buf.deinit();

        try compat.jsonStringify(list_response, .{}, json_buf.writer());
        response.status = .ok;
        try response.writer.writeAll(json_buf.items);
    }

    // Handle getting user lists
    pub fn handleGetLists(self: *MastodonAPI, db: *database.Database, response: anytype) !void {
        // For demo, use user ID 1
        const user_id: i64 = 1;

        const lists = try database.getLists(db, self.allocator, user_id);
        defer {
            for (lists) |list| database.List.deinit(list, self.allocator);
            self.allocator.free(lists);
        }

        var mastodon_lists = std.array_list.Managed(struct {
            id: []const u8,
            title: []const u8,
            replies_policy: []const u8,
        }).init(self.allocator);
        defer {
            for (mastodon_lists.items) |list| {
                self.allocator.free(list.id);
                self.allocator.free(list.title);
                self.allocator.free(list.replies_policy);
            }
            mastodon_lists.deinit();
        }

        for (lists) |list| {
            try mastodon_lists.append(.{
                .id = try std.fmt.allocPrint(self.allocator, "{}", .{list.id}),
                .title = try self.allocator.dupe(u8, list.title),
                .replies_policy = try self.allocator.dupe(u8, list.replies_policy),
            });
        }

        var json_buf = std.array_list.Managed(u8).init(self.allocator);
        defer json_buf.deinit();

        try compat.jsonStringify(mastodon_lists.items, .{}, json_buf.writer());
        try response.writer.writeAll(json_buf.items);
    }

    // Handle getting a specific list
    pub fn handleGetList(self: *MastodonAPI, db: *database.Database, response: anytype, list_id: i64) !void {
        const list = (try database.getList(db, self.allocator, list_id)) orelse {
            response.status = .not_found;
            try response.writer.writeAll("{\"error\": \"List not found\"}");
            return;
        };
        defer list.deinit(self.allocator);

        const list_response = struct {
            id: []const u8,
            title: []const u8,
            replies_policy: []const u8,
        }{
            .id = try std.fmt.allocPrint(self.allocator, "{}", .{list.id}),
            .title = list.title,
            .replies_policy = list.replies_policy,
        };
        defer self.allocator.free(list_response.id);

        var json_buf = std.array_list.Managed(u8).init(self.allocator);
        defer json_buf.deinit();

        try compat.jsonStringify(list_response, .{}, json_buf.writer());
        try response.writer.writeAll(json_buf.items);
    }

    // Handle updating a list
    pub fn handleUpdateList(self: *MastodonAPI, db: *database.Database, response: anytype, request: *http.Server.Request, list_id: i64) !void {
        // Read request body
        var body_buf = std.array_list.Managed(u8).init(self.allocator);
        defer body_buf.deinit();

        try request.reader().readAllArrayList(&body_buf, 1024);

        // Parse JSON
        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, body_buf.items, .{});
        defer parsed.deinit();

        const title = parsed.value.object.get("title") orelse {
            response.status = .bad_request;
            try response.writer.writeAll("{\"error\": \"Missing title\"}");
            return;
        };

        if (title != .string) {
            response.status = .bad_request;
            try response.writer.writeAll("{\"error\": \"Title must be a string\"}");
            return;
        }

        const replies_policy = if (parsed.value.object.get("replies_policy")) |rp| blk: {
            if (rp == .string) {
                break :blk rp.string;
            }
            break :blk "none";
        } else "none";

        try database.updateList(db, list_id, title.string, replies_policy);

        const list_response = struct {
            id: []const u8,
            title: []const u8,
            replies_policy: []const u8,
        }{
            .id = try std.fmt.allocPrint(self.allocator, "{}", .{list_id}),
            .title = title.string,
            .replies_policy = replies_policy,
        };
        defer self.allocator.free(list_response.id);

        var json_buf = std.array_list.Managed(u8).init(self.allocator);
        defer json_buf.deinit();

        try compat.jsonStringify(list_response, .{}, json_buf.writer());
        response.status = .ok;
        try response.writer.writeAll(json_buf.items);
    }

    // Handle deleting a list
    pub fn handleDeleteList(_: *MastodonAPI, db: *database.Database, response: anytype, method: http.Method, list_id: i64) !void {
        if (method != .DELETE) {
            response.status = .method_not_allowed;
            try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
            return;
        }

        try database.deleteList(db, list_id);
        response.status = .ok;
        try response.writer.writeAll("{}");
    }

    // Handle adding account to list
    pub fn handleAddToList(_: *MastodonAPI, db: *database.Database, response: anytype, method: http.Method, list_id: i64, account_id: i64) !void {
        if (method != .POST) {
            response.status = .method_not_allowed;
            try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
            return;
        }

        try database.addAccountToList(db, list_id, account_id);
        response.status = .ok;
        try response.writer.writeAll("{}");
    }

    // Handle removing account from list
    pub fn handleRemoveFromList(_: *MastodonAPI, db: *database.Database, response: anytype, method: http.Method, list_id: i64, account_id: i64) !void {
        if (method != .DELETE) {
            response.status = .method_not_allowed;
            try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
            return;
        }

        try database.removeAccountFromList(db, list_id, account_id);
        response.status = .ok;
        try response.writer.writeAll("{}");
    }

    // Handle getting list timeline
    pub fn handleListTimeline(self: *MastodonAPI, db: *database.Database, response: anytype, list_id: i64, request: *http.Server.Request) !void {
        // Parse query parameters
        const query_param = request.head.target;
        const limit_str = if (std.mem.indexOf(u8, query_param, "?")) |query_start| blk: {
            break :blk extractQueryParam(query_param[query_start..], "limit") orelse "20";
        } else "20";

        const limit = std.fmt.parseInt(i64, limit_str, 10) catch 20;
        const capped_limit = @min(limit, 40); // Cap at 40 posts

        const posts = try database.getListTimeline(db, self.allocator, list_id, capped_limit, 0);
        defer {
            for (posts) |post| database.Post.deinit(post, self.allocator);
            self.allocator.free(posts);
        }

        try self.sendPostsWithPolls(db, response, posts);
    }

    // Handle featuring a status (pinning)
    pub fn handleFeatureStatus(_: *MastodonAPI, db: *database.Database, response: anytype, method: http.Method, status_id: i64) !void {
        if (method != .POST) {
            response.status = .method_not_allowed;
            try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
            return;
        }

        // For demo, use user ID 1
        const user_id: i64 = 1;

        try database.featurePost(db, user_id, status_id);
        response.status = .ok;
        try response.writer.writeAll("{}");
    }

    // Handle unfeaturing a status (unpinning)
    pub fn handleUnfeatureStatus(_: *MastodonAPI, db: *database.Database, response: anytype, method: http.Method, status_id: i64) !void {
        if (method != .POST) {
            response.status = .method_not_allowed;
            try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
            return;
        }

        // For demo, use user ID 1
        const user_id: i64 = 1;

        try database.unfeaturePost(db, user_id, status_id);
        response.status = .ok;
        try response.writer.writeAll("{}");
    }

    // Handle getting featured statuses
    pub fn handleFeaturedStatuses(self: *MastodonAPI, db: *database.Database, response: anytype, account_id: i64) !void {
        const posts = try database.getFeaturedPosts(db, self.allocator, account_id);
        defer {
            for (posts) |post| database.Post.deinit(post, self.allocator);
            self.allocator.free(posts);
        }

        try self.sendPostsWithPolls(db, response, posts);
    }

    // Handle adding an emoji reaction
    pub fn handleAddEmojiReaction(_: *MastodonAPI, db: *database.Database, response: anytype, method: http.Method, status_id: i64, emoji: []const u8) !void {
        if (method != .PUT) {
            response.status = .method_not_allowed;
            try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
            return;
        }

        // For demo, use user ID 1
        const user_id: i64 = 1;

        try database.addEmojiReaction(db, user_id, status_id, emoji);
        response.status = .ok;
        try response.writer.writeAll("{}");
    }

    // Handle removing an emoji reaction
    pub fn handleRemoveEmojiReaction(_: *MastodonAPI, db: *database.Database, response: anytype, method: http.Method, status_id: i64, emoji: []const u8) !void {
        if (method != .DELETE) {
            response.status = .method_not_allowed;
            try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
            return;
        }

        // For demo, use user ID 1
        const user_id: i64 = 1;

        try database.removeEmojiReaction(db, user_id, status_id, emoji);
        response.status = .ok;
        try response.writer.writeAll("{}");
    }

    // Handle getting emoji reactions for a status
    pub fn handleGetEmojiReactions(self: *MastodonAPI, db: *database.Database, response: anytype, status_id: i64) !void {
        const reactions = try database.getEmojiReactions(db, self.allocator, status_id);
        defer {
            for (reactions) |reaction| self.allocator.free(reaction.emoji);
            self.allocator.free(reactions);
        }

        // Convert to Mastodon API format
        var mastodon_reactions = std.array_list.Managed(struct {
            name: []const u8,
            count: i64,
            me: bool,
        }).init(self.allocator);
        defer {
            for (mastodon_reactions.items) |reaction| {
                self.allocator.free(reaction.name);
            }
            mastodon_reactions.deinit();
        }

        for (reactions) |reaction| {
            try mastodon_reactions.append(.{
                .name = try self.allocator.dupe(u8, reaction.emoji),
                .count = reaction.count,
                .me = reaction.user_reacted,
            });
        }

        var json_buf = std.array_list.Managed(u8).init(self.allocator);
        defer json_buf.deinit();

        try compat.jsonStringify(mastodon_reactions.items, .{}, json_buf.writer());
        try response.writer.writeAll(json_buf.items);
    }
};

// Helper function to extract query parameters
fn extractQueryParam(query: []const u8, param_name: []const u8) ?[]const u8 {
    var param_iter = std.mem.split(u8, query[1..], "&"); // Skip the '?'
    while (param_iter.next()) |param| {
        if (std.mem.indexOf(u8, param, "=")) |equals_pos| {
            const key = param[0..equals_pos];
            const value = param[equals_pos + 1 ..];
            if (std.mem.eql(u8, key, param_name)) {
                return value;
            }
        }
    }
    return null;
}
