const std = @import("std");
const sqlite = @import("sqlite");
const search = @import("search.zig");

pub const Database = sqlite.Db;

/// Convenience wrapper: prepare a query and collect all rows into a slice.
/// Replaces the old `collectAlloc` that was removed from zig-sqlite.
pub fn collectAlloc(db: *Database, comptime T: type, allocator: std.mem.Allocator, comptime query: []const u8, _: anytype, values: anytype) ![]T {
    var stmt = try db.prepare(query);
    defer stmt.deinit();
    return stmt.all(T, allocator, .{}, values);
}

pub fn init(_: std.mem.Allocator) !Database {
    return try sqlite.Db.init(.{
        .mode = sqlite.Db.Mode{ .File = "speedy_socials.db" },
        .open_flags = .{
            .write = true,
            .create = true,
        },
        .threading_mode = .MultiThread,
    });
}

pub fn migrate(db: *Database) !void {
    // Create users table
    try db.exec(
        \\CREATE TABLE IF NOT EXISTS users (
        \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
        \\    username TEXT UNIQUE NOT NULL,
        \\    email TEXT UNIQUE NOT NULL,
        \\    password_hash TEXT NOT NULL,
        \\    display_name TEXT,
        \\    bio TEXT,
        \\    avatar_url TEXT,
        \\    header_url TEXT,
        \\    is_admin BOOLEAN DEFAULT FALSE,
        \\    is_locked BOOLEAN DEFAULT FALSE,
        \\    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        \\    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        \\)
    , .{}, .{});

    // Create posts/statuses table
    try db.exec(
        \\CREATE TABLE IF NOT EXISTS posts (
        \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
        \\    user_id INTEGER NOT NULL,
        \\    content TEXT NOT NULL,
        \\    content_warning TEXT,
        \\    visibility TEXT DEFAULT 'public',
        \\    reply_to_id INTEGER,
        \\    reblog_of_id INTEGER,
        \\    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        \\    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        \\    FOREIGN KEY (user_id) REFERENCES users(id),
        \\    FOREIGN KEY (reply_to_id) REFERENCES posts(id),
        \\    FOREIGN KEY (reblog_of_id) REFERENCES posts(id)
        \\)
    , .{}, .{});

    // Create follows table
    try db.exec(
        \\CREATE TABLE IF NOT EXISTS follows (
        \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
        \\    follower_id INTEGER NOT NULL,
        \\    following_id INTEGER NOT NULL,
        \\    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        \\    UNIQUE(follower_id, following_id),
        \\    FOREIGN KEY (follower_id) REFERENCES users(id),
        \\    FOREIGN KEY (following_id) REFERENCES users(id)
        \\)
    , .{}, .{});

    // Create favourites/likes table
    try db.exec(
        \\CREATE TABLE IF NOT EXISTS favourites (
        \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
        \\    user_id INTEGER NOT NULL,
        \\    post_id INTEGER NOT NULL,
        \\    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        \\    UNIQUE(user_id, post_id),
        \\    FOREIGN KEY (user_id) REFERENCES users(id),
        \\    FOREIGN KEY (post_id) REFERENCES posts(id)
        \\)
    , .{}, .{});

    // Create media_attachments table
    try db.exec(
        \\CREATE TABLE IF NOT EXISTS media_attachments (
        \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
        \\    post_id INTEGER,
        \\    file_path TEXT NOT NULL,
        \\    content_type TEXT NOT NULL,
        \\    file_size INTEGER NOT NULL,
        \\    width INTEGER,
        \\    height INTEGER,
        \\    description TEXT,
        \\    blurhash TEXT,
        \\    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        \\    FOREIGN KEY (post_id) REFERENCES posts(id)
        \\)
    , .{}, .{});

    // Create sessions table for authentication
    try db.exec(
        \\CREATE TABLE IF NOT EXISTS sessions (
        \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
        \\    user_id INTEGER NOT NULL,
        \\    token TEXT UNIQUE NOT NULL,
        \\    expires_at DATETIME NOT NULL,
        \\    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        \\    FOREIGN KEY (user_id) REFERENCES users(id)
        \\)
    , .{}, .{});

    // Create user_blocks table for blocking users
    try db.exec(
        \\CREATE TABLE IF NOT EXISTS user_blocks (
        \\    blocker_id INTEGER NOT NULL,
        \\    blocked_id INTEGER NOT NULL,
        \\    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        \\    PRIMARY KEY (blocker_id, blocked_id),
        \\    FOREIGN KEY (blocker_id) REFERENCES users(id),
        \\    FOREIGN KEY (blocked_id) REFERENCES users(id)
        \\)
    , .{}, .{});

    // Create user_mutes table for muting users
    try db.exec(
        \\CREATE TABLE IF NOT EXISTS user_mutes (
        \\    muter_id INTEGER NOT NULL,
        \\    muted_id INTEGER NOT NULL,
        \\    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        \\    PRIMARY KEY (muter_id, muted_id),
        \\    FOREIGN KEY (muter_id) REFERENCES users(id),
        \\    FOREIGN KEY (muted_id) REFERENCES users(id)
        \\)
    , .{}, .{});

    // Create reports table for moderation
    try db.exec(
        \\CREATE TABLE IF NOT EXISTS reports (
        \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
        \\    reporter_id INTEGER NOT NULL,
        \\    reported_user_id INTEGER,
        \\    reported_post_id INTEGER,
        \\    category TEXT NOT NULL,
        \\    comment TEXT,
        \\    status TEXT DEFAULT 'pending',
        \\    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        \\    resolved_at DATETIME,
        \\    FOREIGN KEY (reporter_id) REFERENCES users(id),
        \\    FOREIGN KEY (reported_user_id) REFERENCES users(id),
        \\    FOREIGN KEY (reported_post_id) REFERENCES posts(id)
        \\)
    , .{}, .{});

    // Create instance_blocks table for domain blocking
    try db.exec(
        \\CREATE TABLE IF NOT EXISTS instance_blocks (
        \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
        \\    domain TEXT NOT NULL UNIQUE,
        \\    severity TEXT NOT NULL DEFAULT 'suspend',
        \\    comment TEXT,
        \\    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        \\)
    , .{}, .{});

    // Create polls table for post polls
    try db.exec(
        \\CREATE TABLE IF NOT EXISTS polls (
        \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
        \\    post_id INTEGER NOT NULL,
        \\    expires_at DATETIME,
        \\    multiple BOOLEAN DEFAULT FALSE,
        \\    hide_totals BOOLEAN DEFAULT FALSE,
        \\    voters_count INTEGER DEFAULT 0,
        \\    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        \\    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
        \\)
    , .{}, .{});

    // Create poll_options table for poll choices
    try db.exec(
        \\CREATE TABLE IF NOT EXISTS poll_options (
        \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
        \\    poll_id INTEGER NOT NULL,
        \\    title TEXT NOT NULL,
        \\    votes_count INTEGER DEFAULT 0,
        \\    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        \\    FOREIGN KEY (poll_id) REFERENCES polls(id) ON DELETE CASCADE
        \\)
    , .{}, .{});

    // Create poll_votes table for tracking votes
    try db.exec(
        \\CREATE TABLE IF NOT EXISTS poll_votes (
        \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
        \\    poll_id INTEGER NOT NULL,
        \\    user_id INTEGER NOT NULL,
        \\    poll_option_id INTEGER NOT NULL,
        \\    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        \\    FOREIGN KEY (poll_id) REFERENCES polls(id) ON DELETE CASCADE,
        \\    FOREIGN KEY (user_id) REFERENCES users(id),
        \\    FOREIGN KEY (poll_option_id) REFERENCES poll_options(id) ON DELETE CASCADE,
        \\    UNIQUE(poll_id, user_id, poll_option_id)
        \\)
    , .{}, .{});

    // Create bookmarks table for saving posts
    try db.exec(
        \\CREATE TABLE IF NOT EXISTS bookmarks (
        \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
        \\    user_id INTEGER NOT NULL,
        \\    post_id INTEGER NOT NULL,
        \\    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        \\    FOREIGN KEY (user_id) REFERENCES users(id),
        \\    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
        \\    UNIQUE(user_id, post_id)
        \\)
    , .{}, .{});

    // Create lists table for user-created lists
    try db.exec(
        \\CREATE TABLE IF NOT EXISTS lists (
        \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
        \\    user_id INTEGER NOT NULL,
        \\    title TEXT NOT NULL,
        \\    replies_policy TEXT DEFAULT 'none',
        \\    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        \\    FOREIGN KEY (user_id) REFERENCES users(id)
        \\)
    , .{}, .{});

    // Create list_accounts table for accounts in lists
    try db.exec(
        \\CREATE TABLE IF NOT EXISTS list_accounts (
        \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
        \\    list_id INTEGER NOT NULL,
        \\    account_id INTEGER NOT NULL,
        \\    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        \\    FOREIGN KEY (list_id) REFERENCES lists(id) ON DELETE CASCADE,
        \\    FOREIGN KEY (account_id) REFERENCES users(id),
        \\    UNIQUE(list_id, account_id)
        \\)
    , .{}, .{});

    // Create featured_posts table for pinned posts
    try db.exec(
        \\CREATE TABLE IF NOT EXISTS featured_posts (
        \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
        \\    user_id INTEGER NOT NULL,
        \\    post_id INTEGER NOT NULL,
        \\    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        \\    FOREIGN KEY (user_id) REFERENCES users(id),
        \\    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
        \\    UNIQUE(user_id, post_id)
        \\)
    , .{}, .{});

    // Create emoji_reactions table for post reactions
    try db.exec(
        \\CREATE TABLE IF NOT EXISTS emoji_reactions (
        \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
        \\    user_id INTEGER NOT NULL,
        \\    post_id INTEGER NOT NULL,
        \\    emoji TEXT NOT NULL,
        \\    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        \\    FOREIGN KEY (user_id) REFERENCES users(id),
        \\    FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
        \\    UNIQUE(user_id, post_id, emoji)
        \\)
    , .{}, .{});

    // Create indexes for performance
    try db.exec("CREATE INDEX IF NOT EXISTS idx_posts_user_id ON posts(user_id)", .{}, .{});
    try db.exec("CREATE INDEX IF NOT EXISTS idx_posts_created_at ON posts(created_at DESC)", .{}, .{});
    try db.exec("CREATE INDEX IF NOT EXISTS idx_follows_follower ON follows(follower_id)", .{}, .{});
    try db.exec("CREATE INDEX IF NOT EXISTS idx_follows_following ON follows(following_id)", .{}, .{});
    try db.exec("CREATE INDEX IF NOT EXISTS idx_favourites_user ON favourites(user_id)", .{}, .{});
    try db.exec("CREATE INDEX IF NOT EXISTS idx_favourites_post ON favourites(post_id)", .{}, .{});

    // Initialize search indexes
    try search.initSearchIndexes(db);

    std.debug.print("Database migrations completed\n", .{});
}

// User operations
pub const User = struct {
    id: i64,
    username: []const u8,
    email: []const u8,
    display_name: ?[]const u8,
    bio: ?[]const u8,
    avatar_url: ?[]const u8,
    header_url: ?[]const u8,
    is_locked: bool,
    created_at: []const u8,
};

pub fn createUser(db: *Database, _: std.mem.Allocator, username: []const u8, email: []const u8, password_hash: []const u8) !i64 {
    return (try db.one(i64,
        \\INSERT INTO users (username, email, password_hash)
        \\VALUES (?, ?, ?)
        \\RETURNING id
    , .{}, .{ username, email, password_hash })).?;
}

pub fn getUserById(db: *Database, allocator: std.mem.Allocator, user_id: i64) !?User {
    return try db.oneAlloc(User, allocator,
        \\SELECT id, username, email, display_name, bio, avatar_url, header_url, is_locked, created_at
        \\FROM users WHERE id = ?
    , .{}, .{user_id});
}

pub fn getUserByUsername(db: *Database, allocator: std.mem.Allocator, username: []const u8) !?User {
    return try db.oneAlloc(User, allocator,
        \\SELECT id, username, email, display_name, bio, avatar_url, header_url, is_locked, created_at
        \\FROM users WHERE username = ?
    , .{}, .{username});
}

// Post operations
pub const Post = struct {
    id: i64,
    user_id: i64,
    content: []const u8,
    content_warning: ?[]const u8,
    visibility: []const u8,
    reply_to_id: ?i64,
    reblog_of_id: ?i64,
    created_at: []const u8,
    favourites_count: i64,
    reblogs_count: i64,
    replies_count: i64,

    pub fn deinit(self: Post, allocator: std.mem.Allocator) void {
        allocator.free(self.content);
        if (self.content_warning) |cw| allocator.free(cw);
        allocator.free(self.visibility);
        allocator.free(self.created_at);
    }
};

pub fn createPost(db: *Database, _: std.mem.Allocator, user_id: i64, content: []const u8, visibility: []const u8) !i64 {
    return (try db.one(i64,
        \\INSERT INTO posts (user_id, content, visibility)
        \\VALUES (?, ?, ?)
        \\RETURNING id
    , .{}, .{ user_id, content, visibility })).?;
}

pub fn getPosts(db: *Database, allocator: std.mem.Allocator, limit: i64, offset: i64) ![]Post {
    const posts = try collectAlloc(db,Post, allocator,
        \\SELECT
        \\    p.id,
        \\    p.user_id,
        \\    p.content,
        \\    p.content_warning,
        \\    p.visibility,
        \\    p.reply_to_id,
        \\    p.reblog_of_id,
        \\    p.created_at,
        \\    COALESCE(f.fav_count, 0) as favourites_count,
        \\    COALESCE(r.reblog_count, 0) as reblogs_count,
        \\    COALESCE(rep.reply_count, 0) as replies_count
        \\FROM posts p
        \\LEFT JOIN (SELECT post_id, COUNT(*) as fav_count FROM favourites GROUP BY post_id) f ON p.id = f.post_id
        \\LEFT JOIN (SELECT reblog_of_id, COUNT(*) as reblog_count FROM posts WHERE reblog_of_id IS NOT NULL GROUP BY reblog_of_id) r ON p.id = r.reblog_of_id
        \\LEFT JOIN (SELECT reply_to_id, COUNT(*) as reply_count FROM posts WHERE reply_to_id IS NOT NULL GROUP BY reply_to_id) rep ON p.id = rep.reply_to_id
        \\WHERE p.visibility = 'public'
        \\ORDER BY p.created_at DESC
        \\LIMIT ? OFFSET ?
    , allocator, .{ limit, offset });

    // Load polls for posts
    try loadPollsForPosts(db, allocator, posts);

    return posts;
}

pub fn getPostsByUser(db: *Database, allocator: std.mem.Allocator, user_id: i64, limit: i64, offset: i64) ![]Post {
    const posts = try collectAlloc(db,Post, allocator,
        \\SELECT
        \\    p.id,
        \\    p.user_id,
        \\    p.content,
        \\    p.content_warning,
        \\    p.visibility,
        \\    p.reply_to_id,
        \\    p.reblog_of_id,
        \\    p.created_at,
        \\    COALESCE(f.fav_count, 0) as favourites_count,
        \\    COALESCE(r.reblog_count, 0) as reblogs_count,
        \\    COALESCE(rep.reply_count, 0) as replies_count
        \\FROM posts p
        \\LEFT JOIN (SELECT post_id, COUNT(*) as fav_count FROM favourites GROUP BY post_id) f ON p.id = f.post_id
        \\LEFT JOIN (SELECT reblog_of_id, COUNT(*) as reblog_count FROM posts WHERE reblog_of_id IS NOT NULL GROUP BY reblog_of_id) r ON p.id = r.reblog_of_id
        \\LEFT JOIN (SELECT reply_to_id, COUNT(*) as reply_count FROM posts WHERE reply_to_id IS NOT NULL GROUP BY reply_to_id) rep ON p.id = rep.reply_to_id
        \\WHERE p.user_id = ?
        \\ORDER BY p.created_at DESC
        \\LIMIT ? OFFSET ?
    , allocator, .{ user_id, limit, offset });

    // Load polls for posts
    try loadPollsForPosts(db, allocator, posts);

    return posts;
}

// Follow operations
pub fn followUser(db: *Database, follower_id: i64, following_id: i64) !void {
    try db.exec(
        \\INSERT OR IGNORE INTO follows (follower_id, following_id)
        \\VALUES (?, ?)
    , .{}, .{ follower_id, following_id });
}

pub fn unfollowUser(db: *Database, follower_id: i64, following_id: i64) !void {
    try db.exec(
        \\DELETE FROM follows WHERE follower_id = ? AND following_id = ?
    , .{}, .{ follower_id, following_id });
}

pub fn isFollowing(db: *Database, follower_id: i64, following_id: i64) !bool {
    const count = try db.one(i64,
        \\SELECT COUNT(*) FROM follows WHERE follower_id = ? AND following_id = ?
    , .{}, .{ follower_id, following_id });
    return count.? > 0;
}

// Favourite operations
pub fn favouritePost(db: *Database, user_id: i64, post_id: i64) !void {
    try db.exec(
        \\INSERT OR IGNORE INTO favourites (user_id, post_id)
        \\VALUES (?, ?)
    , .{}, .{ user_id, post_id });
}

pub fn unfavouritePost(db: *Database, user_id: i64, post_id: i64) !void {
    try db.exec(
        \\DELETE FROM favourites WHERE user_id = ? AND post_id = ?
    , .{}, .{ user_id, post_id });
}

pub fn isFavourite(db: *Database, user_id: i64, post_id: i64) !bool {
    const count = try db.one(i64,
        \\SELECT COUNT(*) FROM favourites WHERE user_id = ? AND post_id = ?
    , .{}, .{ user_id, post_id });
    return count.? > 0;
}

// User blocking operations
pub fn blockUser(db: *Database, blocker_id: i64, blocked_id: i64) !void {
    try db.exec(
        \\INSERT OR IGNORE INTO user_blocks (blocker_id, blocked_id)
        \\VALUES (?, ?)
    , .{}, .{ blocker_id, blocked_id });

    // Also unfollow if following
    try db.exec(
        \\DELETE FROM follows WHERE follower_id = ? AND following_id = ?
    , .{}, .{ blocker_id, blocked_id });
}

pub fn unblockUser(db: *Database, blocker_id: i64, blocked_id: i64) !void {
    try db.exec(
        \\DELETE FROM user_blocks WHERE blocker_id = ? AND blocked_id = ?
    , .{}, .{ blocker_id, blocked_id });
}

pub fn isBlocked(db: *Database, blocker_id: i64, blocked_id: i64) !bool {
    const count = try db.one(i64,
        \\SELECT COUNT(*) FROM user_blocks WHERE blocker_id = ? AND blocked_id = ?
    , .{}, .{ blocker_id, blocked_id });
    return count.? > 0;
}

pub fn getBlockedUsers(db: *Database, allocator: std.mem.Allocator, user_id: i64) ![]i64 {
    return try collectAlloc(db,i64, allocator,
        \\SELECT blocked_id FROM user_blocks WHERE blocker_id = ?
        \\ORDER BY created_at DESC
    , .{}, .{user_id});
}

// User muting operations
pub fn muteUser(db: *Database, muter_id: i64, muted_id: i64) !void {
    try db.exec(
        \\INSERT OR IGNORE INTO user_mutes (muter_id, muted_id)
        \\VALUES (?, ?)
    , .{}, .{ muter_id, muted_id });
}

pub fn unmuteUser(db: *Database, muter_id: i64, muted_id: i64) !void {
    try db.exec(
        \\DELETE FROM user_mutes WHERE muter_id = ? AND muted_id = ?
    , .{}, .{ muter_id, muted_id });
}

pub fn isMuted(db: *Database, muter_id: i64, muted_id: i64) !bool {
    const count = try db.one(i64,
        \\SELECT COUNT(*) FROM user_mutes WHERE muter_id = ? AND muted_id = ?
    , .{}, .{ muter_id, muted_id });
    return count.? > 0;
}

pub fn getMutedUsers(db: *Database, allocator: std.mem.Allocator, user_id: i64) ![]i64 {
    return try collectAlloc(db,i64, allocator,
        \\SELECT muted_id FROM user_mutes WHERE muter_id = ?
        \\ORDER BY created_at DESC
    , .{}, .{user_id});
}

// Report operations
pub const Report = struct {
    id: i64,
    reporter_id: i64,
    reported_user_id: ?i64,
    reported_post_id: ?i64,
    category: []const u8,
    comment: ?[]const u8,
    status: []const u8,
    created_at: []const u8,
    resolved_at: ?[]const u8,

    pub fn deinit(self: Report, allocator: std.mem.Allocator) void {
        allocator.free(self.category);
        if (self.comment) |c| allocator.free(c);
        allocator.free(self.status);
        allocator.free(self.created_at);
        if (self.resolved_at) |r| allocator.free(r);
    }
};

pub fn createReport(db: *Database, reporter_id: i64, reported_user_id: ?i64, reported_post_id: ?i64, category: []const u8, comment: ?[]const u8) !i64 {
    return (try db.one(i64,
        \\INSERT INTO reports (reporter_id, reported_user_id, reported_post_id, category, comment)
        \\VALUES (?, ?, ?, ?, ?)
        \\RETURNING id
    , .{}, .{ reporter_id, reported_user_id, reported_post_id, category, comment })) orelse error.InsertFailed;
}

pub fn getReports(db: *Database, allocator: std.mem.Allocator, status: ?[]const u8, limit: i64, offset: i64) ![]Report {
    if (status) |s| {
        return try collectAlloc(db,Report, allocator,
            \\SELECT id, reporter_id, reported_user_id, reported_post_id, category, comment, status, created_at, resolved_at
            \\FROM reports
            \\WHERE status = ?
            \\ORDER BY created_at DESC
            \\LIMIT ? OFFSET ?
        , allocator, .{ s, limit, offset });
    } else {
        return try collectAlloc(db,Report, allocator,
            \\SELECT id, reporter_id, reported_user_id, reported_post_id, category, comment, status, created_at, resolved_at
            \\FROM reports
            \\ORDER BY created_at DESC
            \\LIMIT ? OFFSET ?
        , allocator, .{ limit, offset });
    }
}

pub fn resolveReport(db: *Database, report_id: i64) !void {
    try db.exec(
        \\UPDATE reports SET status = 'resolved', resolved_at = CURRENT_TIMESTAMP WHERE id = ?
    , .{}, .{report_id});
}

// Instance blocking operations
pub const InstanceBlock = struct {
    id: i64,
    domain: []const u8,
    severity: []const u8,
    comment: ?[]const u8,
    created_at: []const u8,

    pub fn deinit(self: InstanceBlock, allocator: std.mem.Allocator) void {
        allocator.free(self.domain);
        allocator.free(self.severity);
        allocator.free(self.created_at);
        if (self.comment) |c| allocator.free(c);
    }
};

pub fn blockInstance(db: *Database, domain: []const u8, severity: []const u8, comment: ?[]const u8) !i64 {
    return (try db.one(i64,
        \\INSERT INTO instance_blocks (domain, severity, comment)
        \\VALUES (?, ?, ?)
        \\RETURNING id
    , .{}, .{ domain, severity, comment })) orelse error.InsertFailed;
}

pub fn unblockInstance(db: *Database, domain: []const u8) !void {
    try db.exec(
        \\DELETE FROM instance_blocks WHERE domain = ?
    , .{}, .{domain});
}

pub fn isInstanceBlocked(db: *Database, domain: []const u8) !bool {
    const count = try db.one(i64,
        \\SELECT COUNT(*) FROM instance_blocks WHERE domain = ?
    , .{}, .{domain});
    return count.? > 0;
}

pub fn getInstanceBlocks(db: *Database, allocator: std.mem.Allocator) ![]InstanceBlock {
    return try collectAlloc(db,InstanceBlock, allocator,
        \\SELECT id, domain, severity, comment, created_at
        \\FROM instance_blocks
        \\ORDER BY created_at DESC
    , .{}, .{});
}

// Poll operations
pub const Poll = struct {
    id: i64,
    post_id: i64,
    expires_at: []const u8 = "",
    multiple: bool,
    hide_totals: bool,
    voters_count: i64,
    created_at: []const u8,

    pub fn deinit(self: Poll, allocator: std.mem.Allocator) void {
        if (self.expires_at.len > 0) allocator.free(self.expires_at);
        allocator.free(self.created_at);
    }
};

pub const PollOption = struct {
    id: i64,
    poll_id: i64,
    title: []const u8,
    votes_count: i64,
    created_at: []const u8,

    pub fn deinit(self: PollOption, allocator: std.mem.Allocator) void {
        allocator.free(self.title);
        allocator.free(self.created_at);
    }
};

pub fn createPoll(db: *Database, post_id: i64, expires_at: ?[]const u8, multiple: bool, hide_totals: bool) !i64 {
    return (try db.one(i64,
        \\INSERT INTO polls (post_id, expires_at, multiple, hide_totals)
        \\VALUES (?, ?, ?, ?)
        \\RETURNING id
    , .{}, .{ post_id, expires_at, multiple, hide_totals })) orelse error.InsertFailed;
}

pub fn addPollOption(db: *Database, poll_id: i64, title: []const u8) !i64 {
    return (try db.one(i64,
        \\INSERT INTO poll_options (poll_id, title)
        \\VALUES (?, ?)
        \\RETURNING id
    , .{}, .{ poll_id, title })) orelse error.InsertFailed;
}

pub fn getPoll(db: *Database, allocator: std.mem.Allocator, poll_id: i64) !?Poll {
    return try db.oneAlloc(Poll, allocator,
        \\SELECT id, post_id, expires_at, multiple, hide_totals, voters_count, created_at
        \\FROM polls WHERE id = ?
    , .{}, .{poll_id});
}

pub fn getPollOptions(db: *Database, allocator: std.mem.Allocator, poll_id: i64) ![]PollOption {
    return try collectAlloc(db,PollOption, allocator,
        \\SELECT id, poll_id, title, votes_count, created_at
        \\FROM poll_options
        \\WHERE poll_id = ?
        \\ORDER BY id
    , .{}, .{poll_id});
}

pub fn voteOnPoll(db: *Database, allocator: std.mem.Allocator, poll_id: i64, user_id: i64, option_ids: []const i64) !void {
    // Start transaction
    try db.exec("BEGIN", .{}, .{});
    errdefer db.exec("ROLLBACK", .{}, .{}) catch {};

    // Check if poll allows multiple votes
    const poll = (try getPoll(db, allocator, poll_id)) orelse {
        try db.exec("ROLLBACK", .{}, .{});
        return error.PollNotFound;
    };
    defer poll.deinit(allocator);

    // If not multiple choice, remove existing votes from this user
    if (!poll.multiple) {
        try db.exec(
            \\DELETE FROM poll_votes WHERE poll_id = ? AND user_id = ?
        , .{}, .{ poll_id, user_id });
    }

    // Add new votes
    for (option_ids) |option_id| {
        try db.exec(
            \\INSERT OR IGNORE INTO poll_votes (poll_id, user_id, poll_option_id)
            \\VALUES (?, ?, ?)
        , .{}, .{ poll_id, user_id, option_id });

        // Update vote count for option
        try db.exec(
            \\UPDATE poll_options SET votes_count = votes_count + 1 WHERE id = ?
        , .{}, .{option_id});
    }

    // Update total voter count if this is the first vote from this user
    const existing_votes = try db.one(i64,
        \\SELECT COUNT(*) FROM poll_votes WHERE poll_id = ? AND user_id = ?
    , .{}, .{ poll_id, user_id });

    if (existing_votes.? == 0) {
        try db.exec(
            \\UPDATE polls SET voters_count = voters_count + 1 WHERE id = ?
        , .{}, .{poll_id});
    }

    try db.exec("COMMIT", .{}, .{});
}

pub fn getPollVote(db: *Database, allocator: std.mem.Allocator, poll_id: i64, user_id: i64) ![]i64 {
    return try collectAlloc(db,i64, allocator,
        \\SELECT poll_option_id FROM poll_votes
        \\WHERE poll_id = ? AND user_id = ?
        \\ORDER BY poll_option_id
    , .{}, .{ poll_id, user_id });
}

pub fn isPollExpired(db: *Database, poll_id: i64) !bool {
    const result = try db.one(?[]const u8, db.arena.allocator(),
        \\SELECT expires_at FROM polls WHERE id = ? AND expires_at IS NOT NULL
    , .{}, .{poll_id});

    if (result) |expires_at| {
        defer db.arena.allocator().free(expires_at);
        // Simple check - in real implementation, compare with current time
        return false; // For now, assume polls don't expire
    }

    return false;
}

// Bookmark operations
pub fn bookmarkPost(db: *Database, user_id: i64, post_id: i64) !void {
    try db.exec(
        \\INSERT OR IGNORE INTO bookmarks (user_id, post_id)
        \\VALUES (?, ?)
    , .{}, .{ user_id, post_id });
}

pub fn unbookmarkPost(db: *Database, user_id: i64, post_id: i64) !void {
    try db.exec(
        \\DELETE FROM bookmarks WHERE user_id = ? AND post_id = ?
    , .{}, .{ user_id, post_id });
}

pub fn isBookmarked(db: *Database, user_id: i64, post_id: i64) !bool {
    const count = try db.one(i64,
        \\SELECT COUNT(*) FROM bookmarks WHERE user_id = ? AND post_id = ?
    , .{}, .{ user_id, post_id });
    return count.? > 0;
}

pub fn getBookmarkedPosts(db: *Database, allocator: std.mem.Allocator, user_id: i64, limit: i64, offset: i64) ![]Post {
    const posts = try collectAlloc(db,Post, allocator,
        \\SELECT
        \\    p.id,
        \\    p.user_id,
        \\    p.content,
        \\    p.content_warning,
        \\    p.visibility,
        \\    p.reply_to_id,
        \\    p.reblog_of_id,
        \\    p.created_at,
        \\    COALESCE(f.fav_count, 0) as favourites_count,
        \\    COALESCE(r.reblog_count, 0) as reblogs_count,
        \\    COALESCE(rep.reply_count, 0) as replies_count
        \\FROM posts p
        \\INNER JOIN bookmarks b ON p.id = b.post_id
        \\LEFT JOIN (SELECT post_id, COUNT(*) as fav_count FROM favourites GROUP BY post_id) f ON p.id = f.post_id
        \\LEFT JOIN (SELECT reblog_of_id, COUNT(*) as reblog_count FROM posts WHERE reblog_of_id IS NOT NULL GROUP BY reblog_of_id) r ON p.id = r.reblog_of_id
        \\LEFT JOIN (SELECT reply_to_id, COUNT(*) as reply_count FROM posts WHERE reply_to_id IS NOT NULL GROUP BY reply_to_id) rep ON p.id = rep.reply_to_id
        \\WHERE b.user_id = ?
        \\ORDER BY b.created_at DESC
        \\LIMIT ? OFFSET ?
    , allocator, .{ user_id, limit, offset });

    // Load polls for posts
    try loadPollsForPosts(db, allocator, posts);

    return posts;
}

// List operations
pub const List = struct {
    id: i64,
    user_id: i64,
    title: []const u8,
    replies_policy: []const u8,
    created_at: []const u8,

    pub fn deinit(self: List, allocator: std.mem.Allocator) void {
        allocator.free(self.title);
        allocator.free(self.replies_policy);
        allocator.free(self.created_at);
    }
};

pub fn createList(db: *Database, user_id: i64, title: []const u8, replies_policy: []const u8) !i64 {
    return (try db.one(i64,
        \\INSERT INTO lists (user_id, title, replies_policy)
        \\VALUES (?, ?, ?)
        \\RETURNING id
    , .{}, .{ user_id, title, replies_policy })) orelse error.InsertFailed;
}

pub fn getLists(db: *Database, allocator: std.mem.Allocator, user_id: i64) ![]List {
    return try collectAlloc(db,List, allocator,
        \\SELECT id, user_id, title, replies_policy, created_at
        \\FROM lists
        \\WHERE user_id = ?
        \\ORDER BY created_at DESC
    , .{}, .{user_id});
}

pub fn getList(db: *Database, allocator: std.mem.Allocator, list_id: i64) !?List {
    return try db.oneAlloc(List, allocator,
        \\SELECT id, user_id, title, replies_policy, created_at
        \\FROM lists WHERE id = ?
    , .{}, .{list_id});
}

pub fn updateList(db: *Database, list_id: i64, title: []const u8, replies_policy: []const u8) !void {
    try db.exec(
        \\UPDATE lists SET title = ?, replies_policy = ? WHERE id = ?
    , .{}, .{ title, replies_policy, list_id });
}

pub fn deleteList(db: *Database, list_id: i64) !void {
    try db.exec(
        \\DELETE FROM lists WHERE id = ?
    , .{}, .{list_id});
}

pub fn addAccountToList(db: *Database, list_id: i64, account_id: i64) !void {
    try db.exec(
        \\INSERT OR IGNORE INTO list_accounts (list_id, account_id)
        \\VALUES (?, ?)
    , .{}, .{ list_id, account_id });
}

pub fn removeAccountFromList(db: *Database, list_id: i64, account_id: i64) !void {
    try db.exec(
        \\DELETE FROM list_accounts WHERE list_id = ? AND account_id = ?
    , .{}, .{ list_id, account_id });
}

pub fn getListAccounts(db: *Database, allocator: std.mem.Allocator, list_id: i64) ![]i64 {
    return try collectAlloc(db,i64, allocator,
        \\SELECT account_id FROM list_accounts
        \\WHERE list_id = ?
        \\ORDER BY created_at
    , .{}, .{list_id});
}

pub fn getListTimeline(db: *Database, allocator: std.mem.Allocator, list_id: i64, limit: i64, offset: i64) ![]Post {
    const posts = try collectAlloc(db,Post, allocator,
        \\SELECT
        \\    p.id,
        \\    p.user_id,
        \\    p.content,
        \\    p.content_warning,
        \\    p.visibility,
        \\    p.reply_to_id,
        \\    p.reblog_of_id,
        \\    p.created_at,
        \\    COALESCE(f.fav_count, 0) as favourites_count,
        \\    COALESCE(r.reblog_count, 0) as reblogs_count,
        \\    COALESCE(rep.reply_count, 0) as replies_count
        \\FROM posts p
        \\INNER JOIN list_accounts la ON p.user_id = la.account_id
        \\LEFT JOIN (SELECT post_id, COUNT(*) as fav_count FROM favourites GROUP BY post_id) f ON p.id = f.post_id
        \\LEFT JOIN (SELECT reblog_of_id, COUNT(*) as reblog_count FROM posts WHERE reblog_of_id IS NOT NULL GROUP BY reblog_of_id) r ON p.id = r.reblog_of_id
        \\LEFT JOIN (SELECT reply_to_id, COUNT(*) as reply_count FROM posts WHERE reply_to_id IS NOT NULL GROUP BY reply_to_id) rep ON p.id = rep.reply_to_id
        \\WHERE la.list_id = ? AND p.visibility IN ('public', 'unlisted')
        \\ORDER BY p.created_at DESC
        \\LIMIT ? OFFSET ?
    , allocator, .{ list_id, limit, offset });

    // Load polls for posts
    try loadPollsForPosts(db, allocator, posts);

    return posts;
}

// Featured posts operations
pub fn featurePost(db: *Database, user_id: i64, post_id: i64) !void {
    try db.exec(
        \\INSERT OR IGNORE INTO featured_posts (user_id, post_id)
        \\VALUES (?, ?)
    , .{}, .{ user_id, post_id });
}

pub fn unfeaturePost(db: *Database, user_id: i64, post_id: i64) !void {
    try db.exec(
        \\DELETE FROM featured_posts WHERE user_id = ? AND post_id = ?
    , .{}, .{ user_id, post_id });
}

pub fn isPostFeatured(db: *Database, user_id: i64, post_id: i64) !bool {
    const count = try db.one(i64,
        \\SELECT COUNT(*) FROM featured_posts WHERE user_id = ? AND post_id = ?
    , .{}, .{ user_id, post_id });
    return count.? > 0;
}

pub fn getFeaturedPosts(db: *Database, allocator: std.mem.Allocator, user_id: i64) ![]Post {
    const posts = try collectAlloc(db,Post, allocator,
        \\SELECT
        \\    p.id,
        \\    p.user_id,
        \\    p.content,
        \\    p.content_warning,
        \\    p.visibility,
        \\    p.reply_to_id,
        \\    p.reblog_of_id,
        \\    p.created_at,
        \\    COALESCE(f.fav_count, 0) as favourites_count,
        \\    COALESCE(r.reblog_count, 0) as reblogs_count,
        \\    COALESCE(rep.reply_count, 0) as replies_count
        \\FROM posts p
        \\INNER JOIN featured_posts fp ON p.id = fp.post_id
        \\LEFT JOIN (SELECT post_id, COUNT(*) as fav_count FROM favourites GROUP BY post_id) f ON p.id = f.post_id
        \\LEFT JOIN (SELECT reblog_of_id, COUNT(*) as reblog_count FROM posts WHERE reblog_of_id IS NOT NULL GROUP BY reblog_of_id) r ON p.id = r.reblog_of_id
        \\LEFT JOIN (SELECT reply_to_id, COUNT(*) as reply_count FROM posts WHERE reply_to_id IS NOT NULL GROUP BY reply_to_id) rep ON p.id = rep.reply_to_id
        \\WHERE fp.user_id = ?
        \\ORDER BY fp.created_at DESC
    , allocator, .{user_id});

    // Load polls for posts
    try loadPollsForPosts(db, allocator, posts);

    return posts;
}

// Emoji reactions operations
pub fn addEmojiReaction(db: *Database, user_id: i64, post_id: i64, emoji: []const u8) !void {
    try db.exec(
        \\INSERT OR IGNORE INTO emoji_reactions (user_id, post_id, emoji)
        \\VALUES (?, ?, ?)
    , .{}, .{ user_id, post_id, emoji });
}

pub fn removeEmojiReaction(db: *Database, user_id: i64, post_id: i64, emoji: []const u8) !void {
    try db.exec(
        \\DELETE FROM emoji_reactions WHERE user_id = ? AND post_id = ? AND emoji = ?
    , .{}, .{ user_id, post_id, emoji });
}

pub const EmojiReaction = struct {
    emoji: []const u8,
    count: i64,
    user_reacted: bool,
};

pub fn getEmojiReactions(db: *Database, allocator: std.mem.Allocator, post_id: i64) ![]EmojiReaction {
    // For demo, use user ID 1 to check if current user reacted
    const current_user_id: i64 = 1;

    var reactions = std.array_list.Managed(EmojiReaction).init(allocator);
    errdefer {
        for (reactions.items) |reaction| allocator.free(reaction.emoji);
        reactions.deinit();
    }

    // Get all reactions for this post
    const reaction_rows = try collectAlloc(db,struct {
        emoji: []const u8,
        count: i64,
    }, allocator,
        \\SELECT emoji, COUNT(*) as count
        \\FROM emoji_reactions
        \\WHERE post_id = ?
        \\GROUP BY emoji
        \\ORDER BY count DESC
    , allocator, .{post_id});

    defer {
        for (reaction_rows) |row| allocator.free(row.emoji);
        allocator.free(reaction_rows);
    }

    for (reaction_rows) |row| {
        // Check if current user reacted with this emoji
        const user_reacted = (try db.one(i64,
            \\SELECT COUNT(*) FROM emoji_reactions
            \\WHERE user_id = ? AND post_id = ? AND emoji = ?
        , .{}, .{ current_user_id, post_id, row.emoji })) orelse 0;

        try reactions.append(.{
            .emoji = try allocator.dupe(u8, row.emoji),
            .count = row.count,
            .user_reacted = user_reacted > 0,
        });
    }

    return reactions.toOwnedSlice();
}

// Helper function to load polls for posts
// Polls are fetched separately via getPoll() when needed
fn loadPollsForPosts(_: *Database, _: std.mem.Allocator, _: []Post) !void {
    // Polls removed from Post struct to fix sqlite deserialization.
    // Use getPoll(db, allocator, poll_id) to fetch polls individually.
}
