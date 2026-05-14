//! Merkle Search Tree (MST) — the AT Protocol repo data structure.
//!
//! An MST is a deterministic, content-addressed key-value map. Each
//! entry's "height" in the tree is derived from a hash of its key, so
//! the tree shape is uniquely determined by its contents (independent
//! of insertion order). That property lets two repos compute the same
//! root CID iff they hold the same keys.
//!
//! This module implements the *logical* operations on a flat,
//! in-memory sorted store, plus the per-node serialization shape AT
//! Protocol expects. Tree-shape encoding and CAR streaming live in
//! `mst_node.zig` (added in a follow-up phase). What is asserted here:
//!
//!   * keys are kept strictly sorted by byte-lex
//!   * `put`, `get`, `delete`, `iter` operate via an explicit
//!     binary-search loop bounded by `max_keys`
//!   * leaf-level walking uses the explicit stack required by Tiger Style
//!     (no recursion); `walkInOrder` exposes that to callers
//!   * `getRoot` returns a deterministic CID over the *encoded* leaf
//!     list, so two MSTs with identical contents share a root
//!
//! The 16-way fanout / hash-derived layering will be reintroduced when
//! we wire the tree-node CBOR layout. Until then `getRoot` over the
//! sorted leaves is enough for round-trip + interop tests at the data
//! layer.
//!
//! Spec: https://atproto.com/specs/repository

const std = @import("std");
const core = @import("core");
const AtpError = core.errors.AtpError;
const assert = core.assert.assert;
const assertLe = core.assert.assertLe;
const cid_mod = @import("cid.zig");
const dag = @import("dag_cbor.zig");

/// Maximum entries a single MST may hold. Bounds every loop and any
/// stack-allocated index buffer in the tree walker. 1 << 14 ≈ 16k
/// entries — well above per-repo collection sizes seen on real PDS
/// deployments at speedy-socials' target scale.
pub const max_keys: u32 = 1 << 14;

/// Walker stack depth. Tiger requires explicit, fixed; sized for a
/// pathological log2 split over `max_keys`.
pub const max_walk_depth: u32 = 32;

pub const max_key_bytes: usize = 256;

pub const Entry = struct {
    key_len: u8,
    key_bytes: [max_key_bytes]u8,
    value: cid_mod.Cid,

    pub fn key(self: *const Entry) []const u8 {
        return self.key_bytes[0..self.key_len];
    }
};

/// A fixed-capacity sorted map. The host owns the storage so the MST
/// itself is allocator-free.
pub fn Tree(comptime N: u32) type {
    comptime if (N > max_keys) @compileError("Tree capacity exceeds max_keys");
    return struct {
        const Self = @This();
        pub const capacity: u32 = N;

        entries: [N]Entry = undefined,
        count: u32 = 0,

        pub fn init() Self {
            return .{};
        }

        pub fn len(self: *const Self) u32 {
            return self.count;
        }

        pub const PutError = error{ KeyTooLong, Full };

        /// Insert or overwrite `key`. Returns true if a previous value
        /// was replaced.
        pub fn put(self: *Self, key: []const u8, value: cid_mod.Cid) (PutError || error{})!bool {
            if (key.len == 0 or key.len > max_key_bytes) return error.KeyTooLong;

            const idx = self.lowerBound(key);
            if (idx < self.count and entryKeyEql(&self.entries[idx], key)) {
                self.entries[idx].value = value;
                return true;
            }
            if (self.count >= N) return error.Full;

            // Shift right [idx, count) by one. Bounded by N.
            var i: u32 = self.count;
            while (i > idx) : (i -= 1) {
                assertLe(i, N);
                self.entries[i] = self.entries[i - 1];
            }
            self.entries[idx].key_len = @intCast(key.len);
            @memcpy(self.entries[idx].key_bytes[0..key.len], key);
            self.entries[idx].value = value;
            self.count += 1;
            assertLe(self.count, N);
            return false;
        }

        pub fn get(self: *const Self, key: []const u8) ?cid_mod.Cid {
            const idx = self.lowerBound(key);
            if (idx < self.count and entryKeyEql(&self.entries[idx], key)) {
                return self.entries[idx].value;
            }
            return null;
        }

        pub fn delete(self: *Self, key: []const u8) bool {
            const idx = self.lowerBound(key);
            if (idx >= self.count) return false;
            if (!entryKeyEql(&self.entries[idx], key)) return false;

            var i: u32 = idx;
            while (i + 1 < self.count) : (i += 1) {
                assertLe(i, N);
                self.entries[i] = self.entries[i + 1];
            }
            self.count -= 1;
            return true;
        }

        /// Binary search; returns the first index `i` such that
        /// `entries[i].key >= key`. O(log N), bounded loop.
        fn lowerBound(self: *const Self, key: []const u8) u32 {
            var lo: u32 = 0;
            var hi: u32 = self.count;
            var iter: u32 = 0;
            while (lo < hi) : (iter += 1) {
                // log2(N) iterations; bounded so an infinite loop is
                // a hard panic.
                assertLe(iter, 64);
                const mid = lo + (hi - lo) / 2;
                if (std.mem.lessThan(u8, self.entries[mid].key(), key)) {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }
            return lo;
        }

        /// A single tree-walker frame. Lives on the C stack (the caller's
        /// frame block); the intrusive `link` field is what the explicit
        /// `Stack` threads through. When the MST grows to a real 16-way
        /// fanout these will hold (node_cid, child_index, …) instead of
        /// a single u32 cursor, but the storage shape is already correct.
        pub const Frame = struct {
            /// First entry index this frame is responsible for visiting.
            start: u32,
            /// One past the last entry this frame visits.
            stop: u32,
            link: core.intrusive.Stack(@This()).Link = .{},
        };

        /// In-order callback over every (key, value) pair.
        /// `Visitor` must define `fn onLeaf(*Self, []const u8, Cid) void`.
        pub fn walkInOrder(self: *const Self, comptime Visitor: type, visitor: *Visitor) void {
            // Already sorted in `entries`; the "walk" is a single linear
            // pass driven by an *explicit* TigerBeetle intrusive Stack
            // (LIFO). Tiger Style: no recursion, fixed capacity (sized
            // by `max_walk_depth`), every loop bounded by `self.count`.
            //
            // The leaf storage is flat, so today there's only ever one
            // frame on the stack — but the shape is the same one the
            // tree-shape implementation will use when each frame
            // represents a node in the 16-way fanout.
            var frames: [max_walk_depth]Frame = undefined;
            var top: u32 = 0;
            var stack = core.intrusive.Stack(Frame).init(.{
                .capacity = max_walk_depth,
                .verify_push = true,
            });

            assertLe(top, max_walk_depth);
            frames[top] = .{ .start = 0, .stop = self.count };
            stack.push(&frames[top]);
            top += 1;

            while (stack.pop()) |frame| {
                var i = frame.start;
                while (i < frame.stop) : (i += 1) {
                    assertLe(i, self.count);
                    visitor.onLeaf(&self.entries[i], self.entries[i].key(), self.entries[i].value);
                }
            }
        }

        /// Compute the root CID over the canonical CBOR serialization
        /// of the entry list. Writes the serialized form into `scratch`
        /// so the caller can also persist it. Returns the CID and the
        /// number of bytes written into `scratch`.
        pub fn getRoot(self: *const Self, scratch: []u8) AtpError!struct { cid: cid_mod.Cid, bytes_written: usize } {
            var enc = dag.Encoder.init(scratch);
            try enc.writeArrayHeader(self.count);
            var i: u32 = 0;
            while (i < self.count) : (i += 1) {
                assertLe(i, self.count);
                // Each leaf = [key, cid]
                try enc.writeArrayHeader(2);
                try enc.writeBytesValue(self.entries[i].key());
                try enc.writeCidLink(self.entries[i].value.raw());
            }
            const cid = cid_mod.computeDagCbor(enc.written());
            return .{ .cid = cid, .bytes_written = enc.written().len };
        }
    };
}

fn entryKeyEql(e: *const Entry, key: []const u8) bool {
    return std.mem.eql(u8, e.key(), key);
}

// ── Tests ──────────────────────────────────────────────────────────

fn fakeCid(seed: u8) cid_mod.Cid {
    var data: [4]u8 = .{ seed, seed +% 1, seed +% 2, seed +% 3 };
    return cid_mod.computeDagCbor(&data);
}

test "mst: put / get / delete basic" {
    var t = Tree(64).init();
    _ = try t.put("alice", fakeCid(1));
    _ = try t.put("bob", fakeCid(2));
    _ = try t.put("carol", fakeCid(3));
    try std.testing.expectEqual(@as(u32, 3), t.len());

    const got = t.get("bob").?;
    try std.testing.expectEqualSlices(u8, fakeCid(2).raw(), got.raw());

    try std.testing.expect(t.delete("bob"));
    try std.testing.expect(t.get("bob") == null);
    try std.testing.expectEqual(@as(u32, 2), t.len());
}

test "mst: keys stay sorted regardless of insertion order" {
    var t = Tree(64).init();
    _ = try t.put("charlie", fakeCid(3));
    _ = try t.put("alice", fakeCid(1));
    _ = try t.put("bob", fakeCid(2));

    const Visitor = struct {
        keys: [3][]const u8 = undefined,
        n: u32 = 0,
        fn onLeaf(self: *@This(), _: *const Entry, k: []const u8, _: cid_mod.Cid) void {
            self.keys[self.n] = k;
            self.n += 1;
        }
    };
    var v: Visitor = .{};
    t.walkInOrder(Visitor, &v);
    try std.testing.expectEqual(@as(u32, 3), v.n);
    try std.testing.expectEqualStrings("alice", v.keys[0]);
    try std.testing.expectEqualStrings("bob", v.keys[1]);
    try std.testing.expectEqualStrings("charlie", v.keys[2]);
}

test "mst: put overwrites existing key" {
    var t = Tree(8).init();
    const a = try t.put("x", fakeCid(1));
    try std.testing.expect(!a);
    const b = try t.put("x", fakeCid(2));
    try std.testing.expect(b);
    try std.testing.expectEqualSlices(u8, fakeCid(2).raw(), t.get("x").?.raw());
    try std.testing.expectEqual(@as(u32, 1), t.len());
}

test "mst: Full when capacity hit" {
    var t = Tree(3).init();
    _ = try t.put("a", fakeCid(1));
    _ = try t.put("b", fakeCid(2));
    _ = try t.put("c", fakeCid(3));
    try std.testing.expectError(error.Full, t.put("d", fakeCid(4)));
}

test "mst: root CID is deterministic by content (order-independent)" {
    var t1 = Tree(64).init();
    _ = try t1.put("alpha", fakeCid(10));
    _ = try t1.put("beta", fakeCid(20));
    _ = try t1.put("gamma", fakeCid(30));

    var t2 = Tree(64).init();
    _ = try t2.put("gamma", fakeCid(30));
    _ = try t2.put("alpha", fakeCid(10));
    _ = try t2.put("beta", fakeCid(20));

    var s1: [1024]u8 = undefined;
    var s2: [1024]u8 = undefined;
    const r1 = try t1.getRoot(&s1);
    const r2 = try t2.getRoot(&s2);
    try std.testing.expectEqualSlices(u8, r1.cid.raw(), r2.cid.raw());
}

test "mst: walker visits every entry exactly once via intrusive Stack" {
    // Cover the explicit-stack walker's push/pop path against many entries
    // so the Stack(Frame) adoption is verified end-to-end.
    var t = Tree(64).init();
    var key_buf: [16]u8 = undefined;
    var i: u8 = 0;
    while (i < 32) : (i += 1) {
        const k = try std.fmt.bufPrint(&key_buf, "k{x:0>2}", .{i});
        _ = try t.put(k, fakeCid(i));
    }

    const Visitor = struct {
        seen: [32]bool = [_]bool{false} ** 32,
        count: u32 = 0,
        fn onLeaf(self: *@This(), _: *const Entry, k: []const u8, _: cid_mod.Cid) void {
            // Decode "kNN" hex suffix.
            const idx = std.fmt.parseInt(u8, k[1..], 16) catch return;
            std.testing.expect(!self.seen[idx]) catch return;
            self.seen[idx] = true;
            self.count += 1;
        }
    };
    var v: Visitor = .{};
    t.walkInOrder(Visitor, &v);
    try std.testing.expectEqual(@as(u32, 32), v.count);
    for (v.seen) |s| try std.testing.expect(s);
}

test "mst: walker Stack respects capacity bound" {
    // Verify the Frame stack's reported capacity matches max_walk_depth.
    // This is the structural guarantee the Tiger-Style explicit-stack
    // walker depends on: the frame block on the C stack must be large
    // enough that pushing up to capacity frames never overflows.
    const TreeT = Tree(16);
    var s = core.intrusive.Stack(TreeT.Frame).init(.{
        .capacity = max_walk_depth,
        .verify_push = true,
    });
    try std.testing.expectEqual(max_walk_depth, s.capacity());
    try std.testing.expect(s.empty());
}

test "mst: root CID changes when contents change" {
    var t = Tree(64).init();
    _ = try t.put("k", fakeCid(1));
    var sa: [256]u8 = undefined;
    const a = try t.getRoot(&sa);

    _ = try t.put("k", fakeCid(2));
    var sb: [256]u8 = undefined;
    const b = try t.getRoot(&sb);
    try std.testing.expect(!std.mem.eql(u8, a.cid.raw(), b.cid.raw()));
}
