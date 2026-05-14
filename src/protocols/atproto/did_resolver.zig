//! DID resolution — did:plc + did:web.
//!
//! Both methods require an HTTP fetch in production. The fetch is
//! injected via a function pointer (`HttpFetcher`) so tests can supply
//! a stub. In `app/main.zig` the production fetcher will dispatch to
//! `core.workers.Pool` for blocking HTTP I/O.
//!
//! Tiger Style:
//!   * Bounded LRU cache. Cache size = `max_cache_entries`; eviction
//!     by oldest-touched.
//!   * No allocator on resolution paths — caller provides scratch.

const std = @import("std");
const core = @import("core");
const AtpError = core.errors.AtpError;
const assertLe = core.assert.assertLe;

const did_mod = @import("did.zig");

pub const max_cache_entries: u32 = 256;
pub const max_did_bytes: usize = 256;
pub const max_handle_bytes: usize = 256;
pub const max_document_bytes: usize = 16 * 1024;

pub const default_plc_directory: []const u8 = "https://plc.directory";

/// Function pointer that performs an HTTP GET. Implementation:
///   * production: submits a job to `core.workers.Pool` that opens a
///     TLS connection and reads the response into `out`.
///   * tests: a stub that fills `out` from an in-memory table.
pub const HttpFetcher = *const fn (
    url: []const u8,
    out: []u8,
) AtpError!usize;

pub const ResolverError = AtpError || error{NotFound};

pub const Resolver = struct {
    fetcher: HttpFetcher,
    plc_directory: []const u8 = default_plc_directory,
    cache: LRU = .{},

    pub fn init(fetcher: HttpFetcher) Resolver {
        return .{ .fetcher = fetcher };
    }

    pub fn setPlcDirectory(self: *Resolver, dir: []const u8) void {
        self.plc_directory = dir;
    }

    /// Resolve a DID to its DID document body. Returns slice into `out`.
    pub fn resolveDid(self: *Resolver, did_str: []const u8, out: []u8) ResolverError![]const u8 {
        if (self.cache.get(did_str)) |cached| {
            const cap = @min(cached.len, out.len);
            @memcpy(out[0..cap], cached[0..cap]);
            return out[0..cap];
        }
        const parsed = did_mod.parse(did_str) catch return error.BadDid;
        const url_buf_size: usize = 512;
        var url_buf: [url_buf_size]u8 = undefined;
        const url = switch (parsed.method()) {
            .plc => std.fmt.bufPrint(&url_buf, "{s}/{s}", .{ self.plc_directory, did_str }) catch return error.BufferTooSmall,
            .web => blk: {
                const id = parsed.identifier();
                // Replace %3A with :
                break :blk std.fmt.bufPrint(&url_buf, "https://{s}/.well-known/did.json", .{id}) catch return error.BufferTooSmall;
            },
            .other => return error.BadDid,
        };
        const n = self.fetcher(url, out) catch return error.NotFound;
        if (n == 0) return error.NotFound;
        self.cache.put(did_str, out[0..n]);
        return out[0..n];
    }

    /// Resolve a handle via did:web well-known.
    pub fn resolveHandle(self: *Resolver, handle: []const u8, out: []u8) ResolverError![]const u8 {
        var url_buf: [512]u8 = undefined;
        const url = std.fmt.bufPrint(&url_buf, "https://{s}/.well-known/atproto-did", .{handle}) catch return error.BufferTooSmall;
        const n = self.fetcher(url, out) catch return error.NotFound;
        if (n == 0) return error.NotFound;
        // Trim whitespace.
        var end: usize = n;
        while (end > 0 and (out[end - 1] == '\n' or out[end - 1] == '\r' or out[end - 1] == ' ' or out[end - 1] == '\t')) : (end -= 1) {}
        return out[0..end];
    }
};

const Entry = struct {
    key_buf: [max_did_bytes]u8 = undefined,
    key_len: u16 = 0,
    value_buf: [max_document_bytes]u8 = undefined,
    value_len: u16 = 0,
    touched: u64 = 0,
    used: bool = false,

    fn key(self: *const Entry) []const u8 {
        return self.key_buf[0..self.key_len];
    }
    fn value(self: *const Entry) []const u8 {
        return self.value_buf[0..self.value_len];
    }
};

pub const LRU = struct {
    entries: [max_cache_entries]Entry = undefined,
    touch_counter: u64 = 0,
    count: u32 = 0,

    pub fn get(self: *LRU, k: []const u8) ?[]const u8 {
        var i: u32 = 0;
        while (i < self.entries.len) : (i += 1) {
            const e = &self.entries[i];
            if (!e.used) continue;
            if (std.mem.eql(u8, e.key(), k)) {
                self.touch_counter += 1;
                e.touched = self.touch_counter;
                return e.value();
            }
        }
        return null;
    }

    pub fn put(self: *LRU, k: []const u8, v: []const u8) void {
        if (k.len > max_did_bytes or v.len > max_document_bytes) return;
        // Find vacant or oldest.
        var i: u32 = 0;
        var victim: u32 = 0;
        var oldest: u64 = std.math.maxInt(u64);
        var found_empty = false;
        while (i < self.entries.len) : (i += 1) {
            const e = &self.entries[i];
            if (!e.used) {
                victim = i;
                found_empty = true;
                break;
            }
            if (e.touched < oldest) {
                oldest = e.touched;
                victim = i;
            }
        }
        const e = &self.entries[victim];
        e.used = true;
        @memcpy(e.key_buf[0..k.len], k);
        e.key_len = @intCast(k.len);
        @memcpy(e.value_buf[0..v.len], v);
        e.value_len = @intCast(v.len);
        self.touch_counter += 1;
        e.touched = self.touch_counter;
        if (found_empty) {
            self.count += 1;
            assertLe(self.count, max_cache_entries);
        }
    }
};

// ── Tests ──────────────────────────────────────────────────────────

const testing = std.testing;

const Stub = struct {
    var current: [4096]u8 = undefined;
    var current_len: usize = 0;
    var url_seen: [512]u8 = undefined;
    var url_seen_len: usize = 0;
    var call_count: u32 = 0;

    fn fetch(url: []const u8, out: []u8) AtpError!usize {
        call_count += 1;
        const ul = @min(url.len, url_seen.len);
        @memcpy(url_seen[0..ul], url[0..ul]);
        url_seen_len = ul;
        const n = @min(current_len, out.len);
        @memcpy(out[0..n], current[0..n]);
        return n;
    }
    fn setResponse(body: []const u8) void {
        @memcpy(current[0..body.len], body);
        current_len = body.len;
    }
    fn reset() void {
        current_len = 0;
        url_seen_len = 0;
        call_count = 0;
    }
};

test "resolver: did:web hits well-known/did.json" {
    Stub.reset();
    Stub.setResponse("{\"id\":\"did:web:example.com\"}");
    var r = Resolver.init(Stub.fetch);
    var out: [256]u8 = undefined;
    const doc = try r.resolveDid("did:web:example.com", &out);
    try testing.expect(std.mem.indexOf(u8, doc, "did:web:example.com") != null);
    try testing.expect(std.mem.indexOf(u8, Stub.url_seen[0..Stub.url_seen_len], "/.well-known/did.json") != null);
}

test "resolver: did:plc hits configured directory" {
    Stub.reset();
    Stub.setResponse("{\"id\":\"did:plc:abc\"}");
    var r = Resolver.init(Stub.fetch);
    var out: [256]u8 = undefined;
    _ = try r.resolveDid("did:plc:abc123", &out);
    try testing.expect(std.mem.indexOf(u8, Stub.url_seen[0..Stub.url_seen_len], "plc.directory") != null);
}

test "resolver: cache prevents second fetch" {
    Stub.reset();
    Stub.setResponse("{\"id\":\"did:web:cached.com\"}");
    var r = Resolver.init(Stub.fetch);
    var out: [256]u8 = undefined;
    _ = try r.resolveDid("did:web:cached.com", &out);
    _ = try r.resolveDid("did:web:cached.com", &out);
    try testing.expectEqual(@as(u32, 1), Stub.call_count);
}

test "resolver: handle resolves to DID via well-known" {
    Stub.reset();
    Stub.setResponse("did:web:alice.example.com\n");
    var r = Resolver.init(Stub.fetch);
    var out: [128]u8 = undefined;
    const got = try r.resolveHandle("alice.example.com", &out);
    try testing.expectEqualStrings("did:web:alice.example.com", got);
}

test "resolver: empty fetch yields NotFound" {
    Stub.reset();
    Stub.setResponse("");
    var r = Resolver.init(Stub.fetch);
    var out: [128]u8 = undefined;
    try testing.expectError(error.NotFound, r.resolveDid("did:web:gone.example", &out));
}
