const std = @import("std");

pub const CacheEntry = struct {
    key: []const u8,
    value: []const u8,
    expires_at: i64,
    created_at: i64,

    pub fn deinit(self: *CacheEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.key);
        allocator.free(self.value);
    }

    pub fn isExpired(self: CacheEntry) bool {
        const now = std.time.timestamp();
        return self.expires_at > 0 and now > self.expires_at;
    }
};

// In-memory LRU cache implementation
pub const LruCache = struct {
    allocator: std.mem.Allocator,
    capacity: usize,
    entries: std.StringHashMap(CacheEntry),
    access_order: std.array_list.AlignedManaged([]const u8, null), // For LRU eviction
    mutex: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator, capacity: usize) LruCache {
        return LruCache{
            .allocator = allocator,
            .capacity = capacity,
            .entries = std.StringHashMap(CacheEntry).init(allocator),
            .access_order = std.array_list.AlignedManaged([]const u8, null).init(allocator),
            .mutex = std.Thread.Mutex{},
        };
    }

    pub fn deinit(self: *LruCache) void {
        var iter = self.entries.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }
        self.entries.deinit();

        for (self.access_order.items) |key| {
            self.allocator.free(key);
        }
        self.access_order.deinit();
    }

    // Get a value from cache
    pub fn get(self: *LruCache, key: []const u8) ?[]const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        const entry = self.entries.get(key) orelse return null;

        // Check if expired
        if (entry.isExpired()) {
            self.removeEntry(key);
            return null;
        }

        // Update access order (move to front)
        self.updateAccessOrder(key);

        return entry.value;
    }

    // Set a value in cache
    pub fn set(self: *LruCache, key: []const u8, value: []const u8, ttl_seconds: i64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const key_copy = try self.allocator.dupe(u8, key);
        const value_copy = try self.allocator.dupe(u8, value);
        const now = std.time.timestamp();

        const entry = CacheEntry{
            .key = key_copy,
            .value = value_copy,
            .expires_at = if (ttl_seconds > 0) now + ttl_seconds else 0,
            .created_at = now,
        };

        // Check if key already exists
        if (self.entries.contains(key)) {
            // Update existing entry
            var old_entry = self.entries.get(key).?;
            old_entry.deinit(self.allocator);
            try self.entries.put(key, entry);
        } else {
            // Add new entry
            try self.entries.put(key, entry);

            // Check capacity and evict if necessary
            if (self.entries.count() > self.capacity) {
                try self.evictLru();
            }
        }

        // Update access order
        try self.updateAccessOrder(key);
    }

    // Delete a key from cache
    pub fn delete(self: *LruCache, key: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        self.removeEntry(key);
    }

    // Clear all entries
    pub fn clear(self: *LruCache) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var iter = self.entries.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.deinit(self.allocator);
        }

        self.entries.clearRetainingCapacity();

        for (self.access_order.items) |key| {
            self.allocator.free(key);
        }
        self.access_order.clearRetainingCapacity();
    }

    // Get cache statistics
    pub fn stats(self: *LruCache) struct {
        entries: usize,
        capacity: usize,
        hit_ratio: f32,
    } {
        return .{
            .entries = self.entries.count(),
            .capacity = self.capacity,
            .hit_ratio = 0.0, // Would need to track hits/misses
        };
    }

    // Internal: Remove an entry
    fn removeEntry(self: *LruCache, key: []const u8) void {
        if (self.entries.fetchRemove(key)) |kv| {
            kv.value.deinit(self.allocator);

            // Remove from access order
            for (self.access_order.items, 0..) |order_key, i| {
                if (std.mem.eql(u8, order_key, key)) {
                    std.mem.copyForwards([]const u8, self.access_order.items[i .. self.access_order.items.len - 1], self.access_order.items[i + 1 ..]);
                    self.access_order.items.len -= 1;
                    self.allocator.free(order_key);
                    break;
                }
            }
        }
    }

    // Internal: Update access order (move key to front)
    fn updateAccessOrder(self: *LruCache, key: []const u8) !void {
        // Remove from current position
        var found_index: ?usize = null;
        for (self.access_order.items, 0..) |order_key, i| {
            if (std.mem.eql(u8, order_key, key)) {
                found_index = i;
                break;
            }
        }

        if (found_index) |idx| {
            // Move to front
            const key_copy = self.access_order.items[idx];
            std.mem.copyForwards([]const u8, self.access_order.items[1 .. idx + 1], self.access_order.items[0..idx]);
            self.access_order.items[0] = key_copy;
        } else {
            // Add to front
            const key_copy = try self.allocator.dupe(u8, key);
            try self.access_order.insert(0, key_copy);
        }
    }

    // Internal: Evict least recently used entry
    fn evictLru(self: *LruCache) !void {
        if (self.access_order.items.len == 0) return;

        // Get the least recently used key (last in access order)
        const lru_key = self.access_order.items[self.access_order.items.len - 1];

        // Remove it
        self.removeEntry(lru_key);
    }

    // Cleanup expired entries (call periodically)
    pub fn cleanupExpired(self: *LruCache) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        var expired_keys = std.array_list.AlignedManaged([]const u8, null).init(self.allocator);
        defer {
            for (expired_keys.items) |key| {
                self.allocator.free(key);
            }
            expired_keys.deinit();
        }

        var iter = self.entries.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.isExpired()) {
                try expired_keys.append(try self.allocator.dupe(u8, entry.key_ptr.*));
            }
        }

        for (expired_keys.items) |key| {
            self.removeEntry(key);
        }
    }
};

// Cache key generators for common patterns
pub const CacheKeys = struct {
    pub fn userProfile(user_id: i64, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "user:profile:{d}", .{user_id});
    }

    pub fn userPosts(user_id: i64, page: u32, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "user:posts:{d}:{d}", .{ user_id, page });
    }

    pub fn postDetails(post_id: i64, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "post:details:{d}", .{post_id});
    }

    pub fn timelineHome(user_id: i64, page: u32, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "timeline:home:{d}:{d}", .{ user_id, page });
    }

    pub fn timelinePublic(page: u32, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "timeline:public:{d}", .{page});
    }

    pub fn searchResults(query: []const u8, type_str: []const u8, page: u32, allocator: std.mem.Allocator) ![]u8 {
        // Hash the query to avoid key length issues
        var hash_buf: [32]u8 = undefined;
        std.crypto.hash.sha3.Sha3_256.hash(query, &hash_buf, .{});
        const query_hash = std.fmt.fmtSliceHexLower(&hash_buf);

        return std.fmt.allocPrint(allocator, "search:{s}:{s}:{d}", .{ query_hash, type_str, page });
    }

    pub fn trendingTags(allocator: std.mem.Allocator) ![]u8 {
        return allocator.dupe(u8, "trending:tags");
    }

    pub fn apiRateLimit(client_id: []const u8, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "ratelimit:api:{s}", .{client_id});
    }
};

// Cache helper functions
pub fn cacheUserProfile(cache: *LruCache, db: *database.Database, allocator: std.mem.Allocator, user_id: i64) !void {
    // Get user from database
    const user = try database.getUserById(db, allocator, user_id) orelse return;
    defer allocator.free(user.username);
    defer allocator.free(user.email);
    if (user.display_name) |dn| allocator.free(dn);
    if (user.bio) |bio| allocator.free(bio);
    if (user.avatar_url) |au| allocator.free(au);
    if (user.header_url) |hu| allocator.free(hu);
    defer allocator.free(user.created_at);

    // Serialize to JSON
    const user_json = try std.json.stringifyAlloc(allocator, .{
        .id = user.id,
        .username = user.username,
        .display_name = user.display_name,
        .bio = user.bio,
        .avatar_url = user.avatar_url,
        .header_url = user.header_url,
        .created_at = user.created_at,
    }, .{});
    defer allocator.free(user_json);

    // Cache for 5 minutes
    const cache_key = try CacheKeys.userProfile(user_id, allocator);
    defer allocator.free(cache_key);

    try cache.set(cache_key, user_json, 300);
}

pub fn getCachedUserProfile(cache: *LruCache, allocator: std.mem.Allocator, user_id: i64) !?std.json.Value {
    const cache_key = try CacheKeys.userProfile(user_id, allocator);
    defer allocator.free(cache_key);

    const cached_json = cache.get(cache_key) orelse return null;

    // Parse JSON
    return try std.json.parseFromSlice(std.json.Value, allocator, cached_json, .{});
}

pub fn cacheTimeline(cache: *LruCache, allocator: std.mem.Allocator, cache_key: []const u8, posts: anytype) !void {
    const posts_json = try std.json.stringifyAlloc(allocator, posts, .{});
    defer allocator.free(posts_json);

    // Cache for 2 minutes
    try cache.set(cache_key, posts_json, 120);
}

pub fn getCachedTimeline(cache: *LruCache, allocator: std.mem.Allocator, cache_key: []const u8) !?std.json.Value {
    const cached_json = cache.get(cache_key) orelse return null;
    return try std.json.parseFromSlice(std.json.Value, allocator, cached_json, .{});
}

// Multi-level cache (memory + disk)
pub const MultiLevelCache = struct {
    memory_cache: LruCache,
    disk_cache_path: ?[]const u8 = null,

    pub fn init(allocator: std.mem.Allocator, capacity: usize) !MultiLevelCache {
        return MultiLevelCache{
            .memory_cache = LruCache.init(allocator, capacity),
        };
    }

    pub fn deinit(self: *MultiLevelCache) void {
        self.memory_cache.deinit();
        if (self.disk_cache_path) |path| {
            self.allocator.free(path);
        }
    }

    // TODO: Add disk caching layer for persistence across restarts
    // This would serialize cache entries to disk and load them on startup

    pub fn get(self: *MultiLevelCache, key: []const u8) ?[]const u8 {
        return self.memory_cache.get(key);
    }

    pub fn set(self: *MultiLevelCache, key: []const u8, value: []const u8, ttl_seconds: i64) !void {
        try self.memory_cache.set(key, value, ttl_seconds);
    }

    pub fn delete(self: *MultiLevelCache, key: []const u8) void {
        self.memory_cache.delete(key);
    }

    pub fn clear(self: *MultiLevelCache) void {
        self.memory_cache.clear();
    }

    pub fn cleanupExpired(self: *MultiLevelCache) !void {
        try self.memory_cache.cleanupExpired();
    }
};

// Import for database operations
const database = @import("database.zig");
