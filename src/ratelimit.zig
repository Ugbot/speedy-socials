const std = @import("std");

pub const RateLimitType = enum {
    api_requests, // General API requests
    auth_attempts, // Authentication attempts
    search_requests, // Search queries
    media_uploads, // File uploads
    post_creation, // New posts/toots
};

pub const RateLimitConfig = struct {
    requests_per_window: u32,
    window_seconds: u32,
    burst_limit: u32 = 0, // Additional burst capacity
};

pub const RateLimitResult = enum {
    allowed,
    limited,
    blocked,
};

pub const ClientIdentifier = union(enum) {
    ip_address: []const u8,
    user_id: i64,
    api_token: []const u8,
};

// In-memory rate limiter (for production, use Redis)
pub const RateLimiter = struct {
    allocator: std.mem.Allocator,
    configs: std.StringHashMap(RateLimitConfig),
    counters: std.StringHashMap(ClientCounter),
    mutex: std.Thread.Mutex,

    pub const ClientCounter = struct {
        requests: u32 = 0,
        window_start: i64 = 0,
        violations: u32 = 0,
        blocked_until: i64 = 0,
    };

    pub fn init(allocator: std.mem.Allocator) RateLimiter {
        return RateLimiter{
            .allocator = allocator,
            .configs = std.StringHashMap(RateLimitConfig).init(allocator),
            .counters = std.StringHashMap(ClientCounter).init(allocator),
            .mutex = std.Thread.Mutex{},
        };
    }

    pub fn deinit(self: *RateLimiter) void {
        self.configs.deinit();
        self.counters.deinit();
    }

    // Configure rate limits for different types
    pub fn configureLimit(self: *RateLimiter, limit_type: RateLimitType, config: RateLimitConfig) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const type_str = @tagName(limit_type);
        try self.configs.put(type_str, config);
    }

    // Check if request is allowed
    pub fn checkLimit(self: *RateLimiter, limit_type: RateLimitType, client: ClientIdentifier) !RateLimitResult {
        self.mutex.lock();
        defer self.mutex.unlock();

        const type_str = @tagName(limit_type);
        const config = self.configs.get(type_str) orelse {
            // No limit configured, allow
            return .allowed;
        };

        const client_key = try self.makeClientKey(client, type_str);
        defer self.allocator.free(client_key);

        var counter = self.counters.get(client_key) orelse ClientCounter{
            .window_start = std.time.timestamp(),
        };

        const now = std.time.timestamp();

        // Check if client is currently blocked
        if (counter.blocked_until > now) {
            return .blocked;
        }

        // Reset counter if window has expired
        if (now - counter.window_start >= config.window_seconds) {
            counter.requests = 0;
            counter.window_start = now;
        }

        // Check rate limit
        const total_limit = config.requests_per_window + config.burst_limit;
        if (counter.requests >= total_limit) {
            // Increment violations
            counter.violations += 1;

            // Progressive blocking: 1st violation = 1 min, 2nd = 5 min, 3rd = 15 min, etc.
            const block_duration = switch (counter.violations) {
                1 => 60, // 1 minute
                2 => 300, // 5 minutes
                3 => 900, // 15 minutes
                4 => 3600, // 1 hour
                else => 86400, // 24 hours
            };

            counter.blocked_until = now + block_duration;
            try self.counters.put(client_key, counter);

            return .blocked;
        }

        // Allow request
        counter.requests += 1;
        try self.counters.put(client_key, counter);

        return .allowed;
    }

    // Get remaining requests for client
    pub fn getRemainingRequests(self: *RateLimiter, limit_type: RateLimitType, client: ClientIdentifier) !u32 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const type_str = @tagName(limit_type);
        const config = self.configs.get(type_str) orelse return std.math.maxInt(u32);

        const client_key = try self.makeClientKey(client, type_str);
        defer self.allocator.free(client_key);

        const counter = self.counters.get(client_key) orelse return config.requests_per_window;
        const total_limit = config.requests_per_window + config.burst_limit;

        if (counter.requests >= total_limit) {
            return 0;
        }

        return total_limit - counter.requests;
    }

    // Get reset time for rate limit
    pub fn getResetTime(self: *RateLimiter, limit_type: RateLimitType, client: ClientIdentifier) !i64 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const type_str = @tagName(limit_type);
        const config = self.configs.get(type_str) orelse return 0;

        const client_key = try self.makeClientKey(client, type_str);
        defer self.allocator.free(client_key);

        const counter = self.counters.get(client_key) orelse return 0;
        return counter.window_start + config.window_seconds;
    }

    // Create unique key for client + limit type combination
    fn makeClientKey(self: *RateLimiter, client: ClientIdentifier, type_str: []const u8) ![]u8 {
        return switch (client) {
            .ip_address => |ip| std.fmt.allocPrint(self.allocator, "ip:{s}:{s}", .{ ip, type_str }),
            .user_id => |uid| std.fmt.allocPrint(self.allocator, "user:{d}:{s}", .{ uid, type_str }),
            .api_token => |token| blk: {
                // Hash token for privacy (first 8 chars should be enough for uniqueness)
                const hash_len = @min(token.len, 8);
                break :blk std.fmt.allocPrint(self.allocator, "token:{s}:{s}", .{ token[0..hash_len], type_str });
            },
        };
    }

    // Clean up expired counters (maintenance function)
    pub fn cleanupExpired(self: *RateLimiter) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const now = std.time.timestamp();
        var keys_to_remove = std.array_list.Managed([]const u8).init(self.allocator);
        defer {
            for (keys_to_remove.items) |key| {
                self.allocator.free(key);
            }
            keys_to_remove.deinit();
        }

        var iter = self.counters.iterator();
        while (iter.next()) |entry| {
            const counter = entry.value_ptr;

            // Remove if window expired and no violations
            if (counter.violations == 0 and now - counter.window_start > 3600) { // 1 hour
                try keys_to_remove.append(try self.allocator.dupe(u8, entry.key_ptr.*));
            }
            // Remove if block expired
            else if (counter.blocked_until > 0 and now > counter.blocked_until and counter.violations > 0) {
                try keys_to_remove.append(try self.allocator.dupe(u8, entry.key_ptr.*));
            }
        }

        for (keys_to_remove.items) |key| {
            _ = self.counters.remove(key);
        }
    }
};

// HTTP middleware for rate limiting
pub fn rateLimitMiddleware(allocator: std.mem.Allocator, limiter: *RateLimiter, request: anytype, client_ip: []const u8) !bool {
    // Extract client identifier (prefer user ID if authenticated, fallback to IP)
    const client = ClientIdentifier{ .ip_address = client_ip };

    // Check API request limit
    const result = try limiter.checkLimit(.api_requests, client);
    switch (result) {
        .allowed => return true,
        .limited => {
            // Return rate limit headers
            const remaining = try limiter.getRemainingRequests(.api_requests, client);
            const reset_time = try limiter.getResetTime(.api_requests, client);

            // Set rate limit headers
            _ = request.head.get("X-RateLimit-Limit") orelse "300"; // 300 requests per 5 minutes
            _ = request.head.get("X-RateLimit-Remaining") orelse try std.fmt.allocPrint(allocator, "{}", .{remaining});
            _ = request.head.get("X-RateLimit-Reset") orelse try std.fmt.allocPrint(allocator, "{}", .{reset_time});

            return false;
        },
        .blocked => {
            // Client is blocked
            const reset_time = try limiter.getResetTime(.api_requests, client);
            _ = request.head.get("Retry-After") orelse try std.fmt.allocPrint(allocator, "{}", .{reset_time});
            return false;
        },
    }
}

// Default rate limit configurations
pub const DEFAULT_RATE_LIMITS = [_]struct {
    limit_type: RateLimitType,
    config: RateLimitConfig,
}{
    .{
        .limit_type = .api_requests,
        .config = RateLimitConfig{
            .requests_per_window = 300, // 300 requests
            .window_seconds = 300, // per 5 minutes
            .burst_limit = 50, // +50 burst capacity
        },
    },
    .{
        .limit_type = .auth_attempts,
        .config = RateLimitConfig{
            .requests_per_window = 5, // 5 auth attempts
            .window_seconds = 300, // per 5 minutes
        },
    },
    .{
        .limit_type = .search_requests,
        .config = RateLimitConfig{
            .requests_per_window = 30, // 30 searches
            .window_seconds = 60, // per minute
        },
    },
    .{
        .limit_type = .media_uploads,
        .config = RateLimitConfig{
            .requests_per_window = 10, // 10 uploads
            .window_seconds = 3600, // per hour
        },
    },
    .{
        .limit_type = .post_creation,
        .config = RateLimitConfig{
            .requests_per_window = 50, // 50 posts
            .window_seconds = 3600, // per hour
            .burst_limit = 10, // +10 burst
        },
    },
};

// Initialize rate limiter with default configs
pub fn initDefaultRateLimiter(allocator: std.mem.Allocator) !RateLimiter {
    var limiter = RateLimiter.init(allocator);

    for (DEFAULT_RATE_LIMITS) |limit| {
        try limiter.configureLimit(limit.limit_type, limit.config);
    }

    return limiter;
}
