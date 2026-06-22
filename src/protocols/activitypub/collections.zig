//! Builders for the standard ActivityPub `OrderedCollection` /
//! `OrderedCollectionPage` shapes used by:
//!   * `/users/{u}/outbox`
//!   * `/users/{u}/followers`
//!   * `/users/{u}/following`
//!   * `/users/{u}/collections/featured`
//!
//! The items themselves come from storage in the next phase. To keep
//! this module pure, the caller hands us an iterator function pointer +
//! opaque state; we drive it bounded by `max_page_items` and emit the
//! JSON-LD shell around the items.
//!
//! Tiger Style: fixed buffer in, slice out. No allocator.

const std = @import("std");
const core = @import("core");
const FedError = core.errors.FedError;

pub const max_page_items: u32 = 40;

pub const CollectionKind = enum {
    outbox,
    followers,
    following,
    featured,
    /// AP-14: collection of Like activities the actor produced
    /// (FEP-c648).
    liked,
    /// Per-object reply collection — `/users/{u}/statuses/{id}/replies`.
    /// Its path segment is supplied via `Config.path` because it embeds
    /// the status id, unlike the fixed per-actor collections.
    replies,

    pub fn collectionId(self: CollectionKind) []const u8 {
        return switch (self) {
            .outbox => "outbox",
            .followers => "followers",
            .following => "following",
            .featured => "collections/featured",
            .liked => "liked",
            .replies => "replies",
        };
    }
};

/// Type-erased iterator: each call writes the next item's IRI/JSON
/// fragment into `out` and returns its slice. Return `null` when the
/// iterator is exhausted.
pub const ItemIterFn = *const fn (state: ?*anyopaque, out: []u8) ?[]const u8;

pub const Config = struct {
    /// Instance hostname, e.g. `social.example.com`.
    hostname: []const u8,
    /// Local actor username — the `{u}` in the URL.
    actor_username: []const u8,
    /// Which collection we are serving.
    kind: CollectionKind,
    /// Total item count for the `totalItems` field (storage knows the
    /// count; we publish it).
    total_items: u64,
    /// Optional path segment override (relative to the host, no leading
    /// slash). When empty the URL is `/users/{username}/{collectionId}`.
    /// Used by the per-object `replies` collection whose path embeds a
    /// status id (`users/{u}/statuses/{id}/replies`).
    path: []const u8 = "",

    /// Write the collection's host-relative path (without leading slash).
    fn writePath(self: Config, w: *W) WriteError!void {
        if (self.path.len > 0) {
            try w.writeAll(self.path);
        } else {
            try w.print("users/{s}/{s}", .{ self.actor_username, self.kind.collectionId() });
        }
    }
};

pub const WriteError = error{ BufferTooSmall, IteratorTooLarge };

const W = struct {
    buf: []u8,
    pos: usize = 0,

    fn writeAll(self: *W, s: []const u8) WriteError!void {
        if (self.pos + s.len > self.buf.len) return error.BufferTooSmall;
        @memcpy(self.buf[self.pos .. self.pos + s.len], s);
        self.pos += s.len;
    }

    fn print(self: *W, comptime fmt: []const u8, args: anytype) WriteError!void {
        const got = std.fmt.bufPrint(self.buf[self.pos..], fmt, args) catch return error.BufferTooSmall;
        self.pos += got.len;
    }

    fn slice(self: *W) []const u8 {
        return self.buf[0..self.pos];
    }
};

/// Write the index ("collection metadata") document — no items, just
/// `totalItems` + a pointer to `first` page.
pub fn writeIndex(cfg: Config, out: []u8) WriteError![]const u8 {
    var w = W{ .buf = out };
    try w.writeAll("{\"@context\":\"https://www.w3.org/ns/activitystreams\",\"id\":\"https://");
    try w.writeAll(cfg.hostname);
    try w.writeAll("/");
    try cfg.writePath(&w);
    try w.writeAll("\",\"type\":\"OrderedCollection\",\"totalItems\":");
    try w.print("{d}", .{cfg.total_items});
    try w.writeAll(",\"first\":\"https://");
    try w.writeAll(cfg.hostname);
    try w.writeAll("/");
    try cfg.writePath(&w);
    try w.writeAll("?page=1");
    try w.writeAll("\"}");
    return w.slice();
}

/// Write a single page. Pulls up to `max_page_items` items from `iter`,
/// each one a JSON fragment (an IRI string or an inlined object).
/// `page_n` controls the `id` URL and the `next` pointer (1-indexed).
///
/// AP-7: emits `next` (when `iter` had more than `max_page_items`)
/// and `prev` (when `page_n > 1`) so peers can walk large
/// collections end-to-end.
pub fn writePage(
    cfg: Config,
    page_n: u32,
    iter_state: ?*anyopaque,
    iter: ItemIterFn,
    out: []u8,
) WriteError![]const u8 {
    var w = W{ .buf = out };
    try w.writeAll("{\"@context\":\"https://www.w3.org/ns/activitystreams\",\"id\":\"https://");
    try w.writeAll(cfg.hostname);
    try w.writeAll("/");
    try cfg.writePath(&w);
    try w.print("?page={d}", .{page_n});
    try w.writeAll("\",\"type\":\"OrderedCollectionPage\",\"partOf\":\"https://");
    try w.writeAll(cfg.hostname);
    try w.writeAll("/");
    try cfg.writePath(&w);
    try w.writeAll("\",\"orderedItems\":[");

    var scratch: [1024]u8 = undefined;
    var i: u32 = 0;
    var wrote_one = false;
    while (i < max_page_items) : (i += 1) {
        const got = iter(iter_state, &scratch) orelse break;
        if (wrote_one) try w.writeAll(",");
        try w.writeAll(got);
        wrote_one = true;
    }
    try w.writeAll("]");

    // AP-7: did the iterator have more? Probe by asking once more.
    var more_scratch: [1024]u8 = undefined;
    const has_more = iter(iter_state, &more_scratch) != null;

    if (has_more) {
        try w.writeAll(",\"next\":\"https://");
        try w.writeAll(cfg.hostname);
        try w.writeAll("/");
        try cfg.writePath(&w);
        try w.print("?page={d}", .{page_n + 1});
        try w.writeAll("\"");
    }
    if (page_n > 1) {
        try w.writeAll(",\"prev\":\"https://");
        try w.writeAll(cfg.hostname);
        try w.writeAll("/");
        try cfg.writePath(&w);
        try w.print("?page={d}", .{page_n - 1});
        try w.writeAll("\"");
    }

    try w.writeAll("}");
    return w.slice();
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const TestIter = struct {
    items: [3][]const u8,
    cursor: usize = 0,

    fn next(state: ?*anyopaque, out: []u8) ?[]const u8 {
        const self: *TestIter = @ptrCast(@alignCast(state.?));
        if (self.cursor >= self.items.len) return null;
        const s = self.items[self.cursor];
        self.cursor += 1;
        if (out.len < s.len + 2) return null;
        out[0] = '"';
        @memcpy(out[1 .. 1 + s.len], s);
        out[1 + s.len] = '"';
        return out[0 .. s.len + 2];
    }
};

test "writeIndex shape" {
    var buf: [1024]u8 = undefined;
    const out = try writeIndex(.{
        .hostname = "example.com",
        .actor_username = "alice",
        .kind = .outbox,
        .total_items = 7,
    }, &buf);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"OrderedCollection\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"totalItems\":7") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "https://example.com/users/alice/outbox") != null);
}

test "AP-7: writePage emits next when iterator has more items" {
    const Big = struct {
        const Self = @This();
        cursor: u32 = 0,
        cap: u32,
        fn next(state: ?*anyopaque, out: []u8) ?[]const u8 {
            const self: *Self = @ptrCast(@alignCast(state.?));
            if (self.cursor >= self.cap) return null;
            self.cursor += 1;
            const s = "https://x/y";
            if (out.len < s.len + 2) return null;
            out[0] = '"';
            @memcpy(out[1 .. 1 + s.len], s);
            out[1 + s.len] = '"';
            return out[0 .. s.len + 2];
        }
    };
    var big = Big{ .cap = max_page_items + 5 };
    var buf: [4096]u8 = undefined;
    const out = try writePage(.{
        .hostname = "example.com",
        .actor_username = "alice",
        .kind = .followers,
        .total_items = max_page_items + 5,
    }, 1, @ptrCast(&big), Big.next, &buf);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"next\":\"https://example.com/users/alice/followers?page=2\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"prev\"") == null);
}

test "AP-7: writePage emits prev when page_n > 1" {
    var it = TestIter{ .items = .{ "https://a/1", "https://a/2", "https://a/3" } };
    var buf: [2048]u8 = undefined;
    const out = try writePage(.{
        .hostname = "example.com",
        .actor_username = "alice",
        .kind = .following,
        .total_items = 3,
    }, 3, @ptrCast(&it), TestIter.next, &buf);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"prev\":\"https://example.com/users/alice/following?page=2\"") != null);
}

test "writePage emits orderedItems from iterator" {
    var it = TestIter{ .items = .{
        "https://a/1",
        "https://a/2",
        "https://a/3",
    } };
    var buf: [2048]u8 = undefined;
    const out = try writePage(.{
        .hostname = "example.com",
        .actor_username = "bob",
        .kind = .followers,
        .total_items = 3,
    }, 1, @as(*anyopaque, &it), TestIter.next, &buf);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"OrderedCollectionPage\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"https://a/1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"https://a/3\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "page=1") != null);
}

test "writePage on empty iterator emits empty array" {
    const Empty = struct {
        fn iter(_: ?*anyopaque, _: []u8) ?[]const u8 {
            return null;
        }
    };
    var buf: [1024]u8 = undefined;
    const out = try writePage(.{
        .hostname = "example.com",
        .actor_username = "carol",
        .kind = .following,
        .total_items = 0,
    }, 1, null, Empty.iter, &buf);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"orderedItems\":[]") != null);
}

test "kind URL paths cover all four collections" {
    try std.testing.expectEqualStrings("outbox", CollectionKind.outbox.collectionId());
    try std.testing.expectEqualStrings("followers", CollectionKind.followers.collectionId());
    try std.testing.expectEqualStrings("following", CollectionKind.following.collectionId());
    try std.testing.expectEqualStrings("collections/featured", CollectionKind.featured.collectionId());
}

test "replies collection uses the per-object path override" {
    // Randomize the status id so the URL is built from the path, not a
    // hardcoded happy path.
    var prng = std.Random.DefaultPrng.init(0xBEEF);
    const id = prng.random().int(u32);
    var path_buf: [128]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "users/bob/statuses/{d}/replies", .{id});

    var buf: [1024]u8 = undefined;
    const out = try writeIndex(.{
        .hostname = "example.com",
        .actor_username = "bob",
        .kind = .replies,
        .total_items = 3,
        .path = path,
    }, &buf);
    var want_buf: [192]u8 = undefined;
    const want = try std.fmt.bufPrint(&want_buf, "https://example.com/users/bob/statuses/{d}/replies", .{id});
    try std.testing.expect(std.mem.indexOf(u8, out, want) != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"totalItems\":3") != null);
    // The default `/users/bob/replies` shape must NOT appear.
    try std.testing.expect(std.mem.indexOf(u8, out, "users/bob/replies") == null);
}

test "replies page emits per-object next/prev paths" {
    var it = TestIter{ .items = .{ "https://a/1", "https://a/2", "https://a/3" } };
    var buf: [2048]u8 = undefined;
    const out = try writePage(.{
        .hostname = "example.com",
        .actor_username = "bob",
        .kind = .replies,
        .total_items = 3,
        .path = "users/bob/statuses/77/replies",
    }, 2, @ptrCast(&it), TestIter.next, &buf);
    try std.testing.expect(std.mem.indexOf(u8, out, "https://example.com/users/bob/statuses/77/replies?page=2") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"prev\":\"https://example.com/users/bob/statuses/77/replies?page=1\"") != null);
}

test "writeIndex refuses too-small buffer" {
    var tiny: [16]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, writeIndex(.{
        .hostname = "x",
        .actor_username = "y",
        .kind = .outbox,
        .total_items = 0,
    }, &tiny));
}
