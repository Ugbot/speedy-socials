const std = @import("std");
const http = std.http;
const database = @import("database.zig");


// Simple web interface using HTMX
pub const WebInterface = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) WebInterface {
        return WebInterface{
            .allocator = allocator,
        };
    }

    // Serve the main timeline page
    pub fn serveHomePage(self: *WebInterface, db: *database.Database, response: anytype) !void {
        const html = try self.renderHomePage(db);
        defer self.allocator.free(html);

        try response.writer.writeAll(html);
    }

    // Serve the post creation page
    pub fn serveCreatePostPage(self: *WebInterface, response: anytype) !void {
        const html = try self.renderCreatePostPage();
        defer self.allocator.free(html);

        try response.writer.writeAll(html);
    }

    // Handle HTMX post creation
    pub fn handleCreatePost(self: *WebInterface, _: *database.Database, response: anytype, _: *http.Server.Request) !void {
        // Body reading not available in Zig 0.15 HTTP API
        _ = self;
        try response.writer.writeAll("<div class='error'>POST body reading not yet migrated to Zig 0.15</div>");
    }

    // Handle HTMX reaction
    pub fn handleReaction(self: *WebInterface, db: *database.Database, response: anytype, method: http.Method, post_id: i64, emoji: []const u8) !void {
        // Call database directly instead of going through Mastodon API mock
        const user_id: i64 = 1; // Demo user
        if (method == .POST) {
            try database.addEmojiReaction(db, user_id, post_id, emoji);
        } else if (method == .DELETE) {
            try database.removeEmojiReaction(db, user_id, post_id, emoji);
        }

        // Return updated reaction count
        const reactions = try database.getEmojiReactions(db, self.allocator, post_id);
        defer {
            for (reactions) |reaction| self.allocator.free(reaction.emoji);
            self.allocator.free(reactions);
        }

        var html = std.array_list.Managed(u8).init(self.allocator);
        defer html.deinit();

        try html.appendSlice("<div class='reactions' id='reactions-");
        try std.fmt.format(html.writer(), "{}", .{post_id});
        try html.appendSlice("'>");

        for (reactions) |reaction| {
            try std.fmt.format(html.writer(),
                \\<span class="reaction" hx-post="/react/{}/{s}" hx-target="#reactions-{}" hx-swap="innerHTML">
                \\{s} {}
                \\</span>
            , .{ post_id, reaction.emoji, post_id, reaction.emoji, reaction.count });
        }

        try html.appendSlice("</div>");

        try response.writer.writeAll(html.items);
    }

    // Render the home page with posts
    fn renderHomePage(self: *WebInterface, db: *database.Database) ![]u8 {
        const posts = try database.getPosts(db, self.allocator, 20, 0);
        defer {
            for (posts) |post| database.Post.deinit(post, self.allocator);
            self.allocator.free(posts);
        }

        var html = std.array_list.Managed(u8).init(self.allocator);
        errdefer html.deinit();

        // HTML head with HTMX
        try html.appendSlice(
            \\<!DOCTYPE html>
            \\<html lang="en">
            \\<head>
            \\    <meta charset="UTF-8">
            \\    <meta name="viewport" content="width=device-width, initial-scale=1.0">
            \\    <title>Speedy Socials</title>
            \\    <script src="https://unpkg.com/htmx.org@1.9.10"></script>
            \\    <style>
        );

        // CSS styles
        try html.appendSlice(
            \\
            \\        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
            \\        .container { max-width: 600px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            \\        .header { text-align: center; margin-bottom: 30px; }
            \\        .post { border-bottom: 1px solid #eee; padding: 15px 0; }
            \\        .post:last-child { border-bottom: none; }
            \\        .post-content { margin: 10px 0; line-height: 1.5; }
            \\        .post-meta { color: #666; font-size: 14px; }
            \\        .actions { margin-top: 10px; }
            \\        .reaction { display: inline-block; margin-right: 10px; padding: 4px 8px; background: #f0f0f0; border-radius: 4px; cursor: pointer; }
            \\        .reaction:hover { background: #e0e0e0; }
            \\        .create-post { margin-bottom: 20px; padding: 15px; background: #f9f9f9; border-radius: 8px; }
            \\        .create-post textarea { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; resize: vertical; }
            \\        .create-post button { background: #007bff; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; margin-top: 10px; }
            \\        .create-post button:hover { background: #0056b3; }
            \\        .success { color: #28a745; padding: 10px; background: #d4edda; border-radius: 4px; margin: 10px 0; }
            \\        .error { color: #dc3545; padding: 10px; background: #f8d7da; border-radius: 4px; margin: 10px 0; }
            \\    </style>
            \\</head>
            \\<body>
            \\    <div class="container">
            \\        <div class="header">
            \\            <h1>🚀 Speedy Socials</h1>
            \\            <p>A high-performance social media platform</p>
            \\        </div>
        );

        // Post creation form
        try html.appendSlice(
            \\
            \\        <div class="create-post">
            \\            <h3>Create a new post</h3>
            \\            <form hx-post="/create-post" hx-target="#result" hx-swap="innerHTML">
            \\                <textarea name="content" rows="3" placeholder="What's on your mind?" required></textarea>
            \\                <br>
            \\                <button type="submit">Post</button>
            \\            </form>
            \\            <div id="result"></div>
            \\        </div>
        );

        // Posts timeline
        try html.appendSlice(
            \\
            \\        <div id="posts">
            \\            <h3>Recent Posts</h3>
        );

        // Render each post
        for (posts) |post| {
            try html.appendSlice("<div class='post'>");

            // Post content
            try std.fmt.format(html.writer(), "<div class='post-content'>{s}</div>", .{post.content});

            // Post meta
            try std.fmt.format(html.writer(),
                \\<div class='post-meta'>Posted by User #{} • {s}</div>
            , .{ post.user_id, post.created_at });

            // Actions
            try html.appendSlice("<div class='actions'>");

            // Reactions
            try std.fmt.format(html.writer(),
                \\<div class='reactions' id='reactions-{}'>
            , .{post.id});

            // Get reactions for this post
            const reactions = try database.getEmojiReactions(db, self.allocator, post.id);
            for (reactions) |reaction| {
                try std.fmt.format(html.writer(),
                    \\<span class="reaction" hx-post="/react/{}/{s}" hx-target="#reactions-{}" hx-swap="innerHTML">
                    \\{s} {}
                    \\</span>
                , .{ post.id, reaction.emoji, post.id, reaction.emoji, reaction.count });
            }
            if (reactions.len > 0) {
                for (reactions) |reaction| self.allocator.free(reaction.emoji);
                self.allocator.free(reactions);
            }

            // Quick reaction buttons
            try std.fmt.format(html.writer(),
                \\<span class="reaction" hx-post="/react/{}/👍" hx-target="#reactions-{}" hx-swap="innerHTML">👍</span>
                \\<span class="reaction" hx-post="/react/{}/❤️" hx-target="#reactions-{}" hx-swap="innerHTML">❤️</span>
                \\<span class="reaction" hx-post="/react/{}/😂" hx-target="#reactions-{}" hx-swap="innerHTML">😂</span>
            , .{ post.id, post.id, post.id, post.id, post.id, post.id });

            try html.appendSlice("</div>"); // end reactions
            try html.appendSlice("</div>"); // end actions
            try html.appendSlice("</div>"); // end post
        }

        try html.appendSlice(
            \\
            \\        </div> <!-- end posts -->
            \\    </div> <!-- end container -->
            \\</body>
            \\</html>
        );

        return html.toOwnedSlice();
    }

    // Render the create post page
    fn renderCreatePostPage(self: *WebInterface) ![]u8 {
        const html =
            \\<!DOCTYPE html>
            \\<html lang="en">
            \\<head>
            \\    <meta charset="UTF-8">
            \\    <meta name="viewport" content="width=device-width, initial-scale=1.0">
            \\    <title>Create Post - Speedy Socials</title>
            \\    <script src="https://unpkg.com/htmx.org@1.9.10"></script>
            \\    <style>
            \\        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 20px; background: #f5f5f5; }
            \\        .container { max-width: 600px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            \\        .form-group { margin-bottom: 15px; }
            \\        textarea { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; resize: vertical; }
            \\        button { background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; }
            \\        button:hover { background: #0056b3; }
            \\        .success { color: #28a745; padding: 10px; background: #d4edda; border-radius: 4px; margin: 10px 0; }
            \\    </style>
            \\</head>
            \\<body>
            \\    <div class="container">
            \\        <h1>Create New Post</h1>
            \\        <form hx-post="/create-post" hx-target="#result">
            \\            <div class="form-group">
            \\                <label for="content">What's on your mind?</label>
            \\                <textarea id="content" name="content" rows="5" required></textarea>
            \\            </div>
            \\            <button type="submit">Create Post</button>
            \\        </form>
            \\        <div id="result"></div>
            \\        <br>
            \\        <a href="/">← Back to timeline</a>
            \\    </div>
            \\</body>
            \\</html>
        ;

        return self.allocator.dupe(u8, html);
    }

    // Extract form field from URL-encoded data
    fn extractFormField(self: *WebInterface, data: []const u8, field_name: []const u8) ?[]const u8 {
        var iter = std.mem.split(u8, data, "&");
        while (iter.next()) |pair| {
            if (std.mem.indexOf(u8, pair, "=")) |eq_pos| {
                const key = pair[0..eq_pos];
                const value = pair[eq_pos + 1 ..];
                if (std.mem.eql(u8, key, field_name)) {
                    // URL decode (simple implementation)
                    return self.urlDecode(value);
                }
            }
        }
        return null;
    }

    // Simple URL decode
    fn urlDecode(self: *WebInterface, input: []const u8) []const u8 {
        var result = std.array_list.Managed(u8).init(self.allocator);
        defer result.deinit();

        var i: usize = 0;
        while (i < input.len) {
            if (input[i] == '%' and i + 2 < input.len) {
                // Simple percent encoding decode (just + for space)
                if (input[i + 1] == '2' and input[i + 2] == '0') {
                    result.append(' ') catch {};
                    i += 3;
                } else {
                    result.appendSlice(input[i .. i + 3]) catch {};
                    i += 3;
                }
            } else if (input[i] == '+') {
                result.append(' ') catch {};
                i += 1;
            } else {
                result.append(input[i]) catch {};
                i += 1;
            }
        }

        return result.toOwnedSlice();
    }
};

// Mock types removed: handleCreatePost and handleReaction now use
// direct database calls or stubs instead of routing through Mastodon API mocks.
