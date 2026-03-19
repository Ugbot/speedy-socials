const std = @import("std");
const sqlite = @import("sqlite");

const api = @import("api.zig");
const atproto_api = @import("api/atproto.zig");
const activitypub = @import("activitypub.zig");
const database = @import("database.zig");
const server = @import("server.zig");
const jobs = @import("jobs.zig");
const email = @import("email.zig");
const cache = @import("cache.zig");
const ratelimit = @import("ratelimit.zig");

pub fn main() !void {
    std.debug.print("Starting Speedy Socials...\n", .{});

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("Allocator initialized\n", .{});

    // Initialize database
    std.debug.print("Initializing database...\n", .{});
    var db = try database.init(allocator);
    defer db.deinit();
    try database.migrate(&db);
    std.debug.print("Database ready\n", .{});

    try createDemoData(allocator, &db);
    std.debug.print("Demo data created\n", .{});

    // Configure instance domain from environment or default
    if (std.process.getEnvVarOwned(allocator, "INSTANCE_DOMAIN")) |domain| {
        activitypub.instance_domain = domain;
    } else |_| {}
    if (std.process.getEnvVarOwned(allocator, "INSTANCE_SCHEME")) |scheme| {
        activitypub.instance_scheme = scheme;
    } else |_| {}
    std.debug.print("Instance: {s}://{s}\n", .{ activitypub.instance_scheme, activitypub.instance_domain });

    std.debug.print("Speedy Socials - High-performance Zig social media platform\n", .{});
    std.debug.print("Supports Mastodon API and AT Protocol\n", .{});
    std.debug.print("Starting server on http://127.0.0.1:8080\n", .{});

    std.debug.print("About to call server.start...\n", .{});

    // Test database operations first
    std.debug.print("Testing database operations...\n", .{});
    const test_user = try database.getUserByUsername(&db, allocator, "demo");
    if (test_user) |user| {
        defer allocator.free(user.username);
        defer allocator.free(user.email);
        if (user.display_name) |dn| allocator.free(dn);
        if (user.bio) |bio| allocator.free(bio);
        if (user.avatar_url) |au| allocator.free(au);
        if (user.header_url) |hu| allocator.free(hu);
        defer allocator.free(user.created_at);
        std.debug.print("Found user: {s}\n", .{user.username});
    } else {
        std.debug.print("User not found\n", .{});
    }

    // Initialize rate limiter
    var rate_limiter = try ratelimit.initDefaultRateLimiter(allocator);
    defer rate_limiter.deinit();
    std.debug.print("Rate limiter initialized\n", .{});

    // Initialize cache
    var memory_cache = cache.LruCache.init(allocator, 10000); // 10k entries
    defer memory_cache.deinit();
    std.debug.print("Cache initialized\n", .{});

    // Initialize job queue and workers
    var job_queue = jobs.JobQueue.init(allocator, &db);
    defer job_queue.deinit();
    try job_queue.startWorkers(4); // 4 worker threads
    std.debug.print("Job queue initialized with 4 workers\n", .{});

    // Initialize email service (with dummy config for demo)
    const email_config = try email.createDefaultEmailConfig(allocator);
    defer allocator.free(email_config.smtp_host);
    defer allocator.free(email_config.username);
    defer allocator.free(email_config.password);
    defer allocator.free(email_config.from_address);

    var email_service = email.EmailService.init(allocator, email_config);
    defer email_service.deinit();
    std.debug.print("Email service initialized\n", .{});

    // Initialize AT Protocol PDS (backed by SQLite)
    try atproto_api.initGlobal(allocator, &db);
    defer atproto_api.deinitGlobal(allocator);
    std.debug.print("AT Protocol PDS initialized (SQLite-backed)\n", .{});

    // Start HTTP server
    try server.start(allocator, &db, 8080);
    std.debug.print("Server started successfully\n", .{});
}

fn createDemoData(allocator: std.mem.Allocator, db: *database.Database) !void {
    // Create demo user
    _ = try database.createUser(db, allocator, "demo", "demo@speedy-socials.local", "demo123");

    // Create some demo posts
    _ = try database.createPost(db, allocator, 1, "Welcome to Speedy Socials! 🚀 A high-performance social media platform built with Zig.", "public");
    _ = try database.createPost(db, allocator, 1, "Building decentralized social media is the future. No more walled gardens!", "public");
    _ = try database.createPost(db, allocator, 1, "Zig + SQLite = Blazing fast social media. Try it out!", "public");
}

test {
    _ = @import("api.zig");
    _ = @import("crypto_sig.zig");
    _ = @import("test_federation.zig");
    _ = @import("relay/mod.zig");
    _ = @import("relay/translate.zig");
    _ = @import("relay/identity_map.zig");
    _ = @import("relay/subscription.zig");
}
