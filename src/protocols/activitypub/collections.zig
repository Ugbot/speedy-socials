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

    pub fn collectionId(self: CollectionKind) []const u8 {
        return switch (self) {
            .outbox => "outbox",
            .followers => "followers",
            .following => "following",
            .featured => "collections/featured",
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
    try w.print("/users/{s}/{s}", .{ cfg.actor_username, cfg.kind.collectionId() });
    try w.writeAll("\",\"type\":\"OrderedCollection\",\"totalItems\":");
    try w.print("{d}", .{cfg.total_items});
    try w.writeAll(",\"first\":\"https://");
    try w.writeAll(cfg.hostname);
    try w.print("/users/{s}/{s}?page=1", .{ cfg.actor_username, cfg.kind.collectionId() });
    try w.writeAll("\"}");
    return w.slice();
}

/// Write a single page. Pulls up to `max_page_items` items from `iter`,
/// each one a JSON fragment (an IRI string or an inlined object).
/// `page_n` controls the `id` URL and the `next` pointer (1-indexed).
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
    try w.print("/users/{s}/{s}?page={d}", .{ cfg.actor_username, cfg.kind.collectionId(), page_n });
    try w.writeAll("\",\"type\":\"OrderedCollectionPage\",\"partOf\":\"https://");
    try w.writeAll(cfg.hostname);
    try w.print("/users/{s}/{s}", .{ cfg.actor_username, cfg.kind.collectionId() });
    try w.writeAll("\",\"orderedItems\":[");

    var scratch: [1024]u8 = undefined;
    var i: u32 = 0;
    var wrote_one = false;
    while (i < max_page_items) : (i += 1) {
        const got = iter(iter_state, &scratch) orelse break;
        if (wrote_one) try w.writeAll(",");
        // Each `got` slice is either a quoted IRI like "\"https://...\""
        // or an inline JSON object. We write it verbatim.
        try w.writeAll(got);
        wrote_one = true;
    }
    // If the iterator handed us more than max_page_items items, the next
    // call after the loop body would set up the *next* page; we just
    // close this page and the caller computes pagination from the count
    // returned by writeIndex.
    try w.writeAll("]}");
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

test "writeIndex refuses too-small buffer" {
    var tiny: [16]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, writeIndex(.{
        .hostname = "x",
        .actor_username = "y",
        .kind = .outbox,
        .total_items = 0,
    }, &tiny));
}
