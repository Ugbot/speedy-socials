const std = @import("std");
const database = @import("database.zig");

pub const SearchResultType = enum {
    account,
    status,
    hashtag,
};

pub const SearchResult = struct {
    id: []const u8,
    type: SearchResultType,
    content: []const u8,
    username: ?[]const u8 = null,
    display_name: ?[]const u8 = null,
    created_at: ?[]const u8 = null,
    url: []const u8,

    pub fn deinit(self: *SearchResult, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.content);
        if (self.username) |u| allocator.free(u);
        if (self.display_name) |dn| allocator.free(dn);
        if (self.created_at) |ca| allocator.free(ca);
        allocator.free(self.url);
    }
};

pub const SearchOptions = struct {
    query: []const u8,
    type: ?SearchResultType = null, // null = all types
    limit: u32 = 20,
    offset: u32 = 0,
    account_id: ?i64 = null, // for searching within specific account
};

// Initialize search indexes
pub fn initSearchIndexes(db: *database.Database) !void {
    // Create FTS virtual tables for posts
    try db.exec(
        \\CREATE VIRTUAL TABLE IF NOT EXISTS posts_fts USING fts5(
        \\    content, username, hashtags,
        \\    content_id UNINDEXED,
        \\    tokenize = 'porter unicode61'
        \\)
    , .{}, .{});

    // Create FTS virtual table for accounts
    try db.exec(
        \\CREATE VIRTUAL TABLE IF NOT EXISTS accounts_fts USING fts5(
        \\    username, display_name, bio,
        \\    account_id UNINDEXED,
        \\    tokenize = 'porter unicode61'
        \\)
    , .{}, .{});

    // Create triggers to keep FTS tables in sync
    try createPostSearchTriggers(db);
    try createAccountSearchTriggers(db);
}

fn createPostSearchTriggers(db: *database.Database) !void {
    // Insert trigger
    try db.exec(
        \\CREATE TRIGGER IF NOT EXISTS posts_fts_insert AFTER INSERT ON posts
        \\BEGIN
        \\    INSERT INTO posts_fts(content_id, content, username, hashtags)
        \\    SELECT
        \\        NEW.id,
        \\        NEW.content,
        \\        users.username,
        \\        (SELECT GROUP_CONCAT(DISTINCT SUBSTR(TRIM(word), 2))
        \\         FROM (SELECT SUBSTR(content, INSTR(content, '#') + 1,
        \\                            CASE INSTR(SUBSTR(content, INSTR(content, '#') + 1), ' ')
        \\                                 WHEN 0 THEN LENGTH(content)
        \\                                 ELSE INSTR(SUBSTR(content, INSTR(content, '#') + 1), ' ') - 1
        \\                            END) as word
        \\                FROM posts WHERE id = NEW.id))
        \\    FROM users WHERE users.id = NEW.user_id;
        \\END
    , .{}, .{});

    // Update trigger
    try db.exec(
        \\CREATE TRIGGER IF NOT EXISTS posts_fts_update AFTER UPDATE ON posts
        \\BEGIN
        \\    DELETE FROM posts_fts WHERE content_id = NEW.id;
        \\    INSERT INTO posts_fts(content_id, content, username, hashtags)
        \\    SELECT
        \\        NEW.id,
        \\        NEW.content,
        \\        users.username,
        \\        (SELECT GROUP_CONCAT(DISTINCT SUBSTR(TRIM(word), 2))
        \\         FROM (SELECT SUBSTR(content, INSTR(content, '#') + 1,
        \\                            CASE INSTR(SUBSTR(content, INSTR(content, '#') + 1), ' ')
        \\                                 WHEN 0 THEN LENGTH(content)
        \\                                 ELSE INSTR(SUBSTR(content, INSTR(content, '#') + 1), ' ') - 1
        \\                            END) as word
        \\                FROM posts WHERE id = NEW.id))
        \\    FROM users WHERE users.id = NEW.user_id;
        \\END
    , .{}, .{});

    // Delete trigger
    try db.exec(
        \\CREATE TRIGGER IF NOT EXISTS posts_fts_delete AFTER DELETE ON posts
        \\BEGIN
        \\    DELETE FROM posts_fts WHERE content_id = OLD.id;
        \\END
    , .{}, .{});
}

fn createAccountSearchTriggers(db: *database.Database) !void {
    // Insert trigger
    try db.exec(
        \\CREATE TRIGGER IF NOT EXISTS accounts_fts_insert AFTER INSERT ON users
        \\BEGIN
        \\    INSERT INTO accounts_fts(account_id, username, display_name, bio)
        \\    VALUES (NEW.id, NEW.username, NEW.display_name, NEW.bio);
        \\END
    , .{}, .{});

    // Update trigger
    try db.exec(
        \\CREATE TRIGGER IF NOT EXISTS accounts_fts_update AFTER UPDATE ON users
        \\BEGIN
        \\    UPDATE accounts_fts SET
        \\        username = NEW.username,
        \\        display_name = NEW.display_name,
        \\        bio = NEW.bio
        \\    WHERE account_id = NEW.id;
        \\END
    , .{}, .{});

    // Delete trigger
    try db.exec(
        \\CREATE TRIGGER IF NOT EXISTS accounts_fts_delete AFTER DELETE ON users
        \\BEGIN
        \\    DELETE FROM accounts_fts WHERE account_id = OLD.id;
        \\END
    , .{}, .{});
}

// Search posts
pub fn searchPosts(db: *database.Database, allocator: std.mem.Allocator, options: SearchOptions) ![]SearchResult {
    var results = std.array_list.Managed(SearchResult).init(allocator);
    errdefer {
        for (results.items) |*result| result.deinit(allocator);
        results.deinit();
    }

    // Build FTS query
    const query_sql = try std.fmt.allocPrint(allocator,
        \\SELECT
        \\    p.id, p.content, u.username, u.display_name, p.created_at,
        \\    posts_fts.rank
        \\FROM posts_fts
        \\JOIN posts p ON posts_fts.content_id = p.id
        \\JOIN users u ON p.user_id = u.id
        \\WHERE posts_fts MATCH ?
        \\ORDER BY posts_fts.rank
        \\LIMIT ? OFFSET ?
    , .{ options.limit, options.offset });
    defer allocator.free(query_sql);

    // Execute search
    var stmt = try db.prepare(query_sql);
    defer stmt.deinit();

    const rows = try stmt.all(allocator, .{}, .{options.query});
    defer {
        for (rows) |row| {
            allocator.free(row[0].?.text.?); // id
            allocator.free(row[1].?.text.?); // content
            allocator.free(row[2].?.text.?); // username
            if (row[3].?.text) |dn| allocator.free(dn); // display_name
            allocator.free(row[4].?.text.?); // created_at
        }
        allocator.free(rows);
    }

    for (rows) |row| {
        const id = try allocator.dupe(u8, row[0].?.text.?);
        const content = try allocator.dupe(u8, row[1].?.text.?);
        const username = try allocator.dupe(u8, row[2].?.text.?);
        const display_name = if (row[3].?.text) |dn| try allocator.dupe(u8, dn) else null;
        const created_at = try allocator.dupe(u8, row[4].?.text.?);

        const url = try std.fmt.allocPrint(allocator, "https://speedy-socials.local/posts/{}", .{id});

        try results.append(SearchResult{
            .id = id,
            .type = .status,
            .content = content,
            .username = username,
            .display_name = display_name,
            .created_at = created_at,
            .url = url,
        });
    }

    return results.toOwnedSlice();
}

// Search accounts
pub fn searchAccounts(db: *database.Database, allocator: std.mem.Allocator, options: SearchOptions) ![]SearchResult {
    var results = std.array_list.Managed(SearchResult).init(allocator);
    errdefer {
        for (results.items) |*result| result.deinit(allocator);
        results.deinit();
    }

    // Build FTS query
    const query_sql = try std.fmt.allocPrint(allocator,
        \\SELECT
        \\    u.id, u.username, u.display_name, u.bio, u.created_at,
        \\    accounts_fts.rank
        \\FROM accounts_fts
        \\JOIN users u ON accounts_fts.account_id = u.id
        \\WHERE accounts_fts MATCH ?
        \\ORDER BY accounts_fts.rank
        \\LIMIT ? OFFSET ?
    , .{ options.limit, options.offset });
    defer allocator.free(query_sql);

    // Execute search
    var stmt = try db.prepare(query_sql);
    defer stmt.deinit();

    const rows = try stmt.all(allocator, .{}, .{options.query});
    defer {
        for (rows) |row| {
            allocator.free(row[0].?.text.?); // id
            allocator.free(row[1].?.text.?); // username
            allocator.free(row[2].?.text.?); // display_name
            if (row[3].?.text) |bio| allocator.free(bio); // bio
            allocator.free(row[4].?.text.?); // created_at
        }
        allocator.free(rows);
    }

    for (rows) |row| {
        const id = try allocator.dupe(u8, row[0].?.text.?);
        const username = try allocator.dupe(u8, row[1].?.text.?);
        const display_name = if (row[2].?.text) |dn| try allocator.dupe(u8, dn) else null;
        const bio = if (row[3].?.text) |b| try allocator.dupe(u8, b) else "";
        const created_at = try allocator.dupe(u8, row[4].?.text.?);

        const url = try std.fmt.allocPrint(allocator, "https://speedy-socials.local/@{}", .{username});

        try results.append(SearchResult{
            .id = id,
            .type = .account,
            .content = bio,
            .username = username,
            .display_name = display_name,
            .created_at = created_at,
            .url = url,
        });
    }

    return results.toOwnedSlice();
}

// Search hashtags
pub fn searchHashtags(db: *database.Database, allocator: std.mem.Allocator, options: SearchOptions) ![]SearchResult {
    var results = std.array_list.Managed(SearchResult).init(allocator);
    errdefer {
        for (results.items) |*result| result.deinit(allocator);
        results.deinit();
    }

    // Query for hashtags
    const query_sql =
        \\SELECT DISTINCT hashtags.tag, COUNT(*) as post_count
        \\FROM (
        \\    SELECT SUBSTR(content, INSTR(content, '#') + 1,
        \\                   CASE INSTR(SUBSTR(content, INSTR(content, '#') + 1), ' ')
        \\                        WHEN 0 THEN LENGTH(content)
        \\                        ELSE INSTR(SUBSTR(content, INSTR(content, '#') + 1), ' ') - 1
        \\                   END) as tag
        \\    FROM posts
        \\    WHERE content LIKE '%#' || ? || '%'
        \\) as hashtags
        \\GROUP BY hashtags.tag
        \\ORDER BY post_count DESC
        \\LIMIT ?
    ;

    var stmt = try db.prepare(query_sql);
    defer stmt.deinit();

    const rows = try stmt.all(allocator, .{}, .{ options.query, options.limit });
    defer {
        for (rows) |row| {
            allocator.free(row[0].?.text.?); // hashtag
        }
        allocator.free(rows);
    }

    for (rows) |row| {
        const hashtag = try allocator.dupe(u8, row[0].?.text.?);
        const id = try std.fmt.allocPrint(allocator, "hashtag_{s}", .{hashtag});
        const url = try std.fmt.allocPrint(allocator, "https://speedy-socials.local/tags/{s}", .{hashtag});

        try results.append(SearchResult{
            .id = id,
            .type = .hashtag,
            .content = hashtag,
            .url = url,
        });
    }

    return results.toOwnedSlice();
}

// Unified search across all types
pub fn search(db: *database.Database, allocator: std.mem.Allocator, options: SearchOptions) ![]SearchResult {
    var all_results = std.array_list.Managed(SearchResult).init(allocator);
    errdefer {
        for (all_results.items) |*result| result.deinit(allocator);
        all_results.deinit();
    }

    // Search based on type filter
    if (options.type) |search_type| {
        switch (search_type) {
            .status => {
                const post_results = try searchPosts(db, allocator, options);
                defer allocator.free(post_results);
                try all_results.appendSlice(post_results);
            },
            .account => {
                const account_results = try searchAccounts(db, allocator, options);
                defer allocator.free(account_results);
                try all_results.appendSlice(account_results);
            },
            .hashtag => {
                const hashtag_results = try searchHashtags(db, allocator, options);
                defer allocator.free(hashtag_results);
                try all_results.appendSlice(hashtag_results);
            },
        }
    } else {
        // Search all types
        const post_results = try searchPosts(db, allocator, SearchOptions{
            .query = options.query,
            .type = .status,
            .limit = options.limit / 3 + 1,
            .offset = options.offset,
            .account_id = options.account_id,
        });
        defer allocator.free(post_results);

        const account_results = try searchAccounts(db, allocator, SearchOptions{
            .query = options.query,
            .type = .account,
            .limit = options.limit / 3 + 1,
            .offset = options.offset,
            .account_id = options.account_id,
        });
        defer allocator.free(account_results);

        const hashtag_results = try searchHashtags(db, allocator, SearchOptions{
            .query = options.query,
            .type = .hashtag,
            .limit = options.limit / 3 + 1,
            .offset = options.offset,
            .account_id = options.account_id,
        });
        defer allocator.free(hashtag_results);

        // Combine and sort by relevance (simplified)
        try all_results.appendSlice(post_results);
        try all_results.appendSlice(account_results);
        try all_results.appendSlice(hashtag_results);

        // Truncate to requested limit
        if (all_results.items.len > options.limit) {
            for (all_results.items[options.limit..]) |*result| {
                result.deinit(allocator);
            }
            all_results.shrinkRetainingCapacity(options.limit);
        }
    }

    return all_results.toOwnedSlice();
}

// Reindex all content (for maintenance)
pub fn reindexAll(db: *database.Database, allocator: std.mem.Allocator) !void {
    _ = allocator; // not used in this simplified version

    // Clear existing FTS data
    try db.exec("DELETE FROM posts_fts", .{}, .{});
    try db.exec("DELETE FROM accounts_fts", .{}, .{});

    // Rebuild from existing data
    try db.exec(
        \\INSERT INTO posts_fts(content_id, content, username, hashtags)
        \\SELECT
        \\    p.id,
        \\    p.content,
        \\    u.username,
        \\    NULL -- hashtags extraction would go here
        \\FROM posts p
        \\JOIN users u ON p.user_id = u.id
    , .{}, .{});

    try db.exec(
        \\INSERT INTO accounts_fts(account_id, username, display_name, bio)
        \\SELECT id, username, display_name, bio FROM users
    , .{}, .{});
}

// Get trending hashtags
pub fn getTrendingHashtags(db: *database.Database, allocator: std.mem.Allocator, limit: u32) ![]struct { hashtag: []const u8, count: u32 } {
    const query_sql =
        \\SELECT hashtags.tag, COUNT(*) as post_count
        \\FROM (
        \\    SELECT SUBSTR(content, INSTR(content, '#') + 1,
        \\                   CASE INSTR(SUBSTR(content, INSTR(content, '#') + 1), ' ')
        \\                        WHEN 0 THEN LENGTH(content)
        \\                        ELSE INSTR(SUBSTR(content, INSTR(content, '#') + 1), ' ') - 1
        \\                   END) as tag
        \\    FROM posts
        \\    WHERE created_at >= datetime('now', '-7 days')
        \\      AND content LIKE '%#%'
        \\) as hashtags
        \\GROUP BY hashtags.tag
        \\ORDER BY post_count DESC
        \\LIMIT ?
    ;

    var stmt = try db.prepare(query_sql);
    defer stmt.deinit();

    const rows = try stmt.all(allocator, .{}, .{limit});
    defer {
        for (rows) |row| {
            allocator.free(row[0].?.text.?); // hashtag
        }
        allocator.free(rows);
    }

    var results = try allocator.alloc(struct { hashtag: []const u8, count: u32 }, rows.len);
    errdefer allocator.free(results);

    for (rows, 0..) |row, i| {
        results[i] = .{
            .hashtag = try allocator.dupe(u8, row[0].?.text.?),
            .count = @intCast(row[1].?.int.?),
        };
    }

    return results;
}
