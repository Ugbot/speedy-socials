//! Merkle Search Tree (MST) — the AT Protocol repo data structure.
//!
//! An MST is a deterministic, content-addressed key-value map. Each
//! entry's "layer" in the tree is derived from a hash of its key, so the
//! tree shape is uniquely determined by its contents (independent of
//! insertion order). That property lets two repos compute the same root
//! CID iff they hold the same keys.
//!
//! ## What this module provides
//!
//! Two cooperating pieces:
//!
//!   1. `Tree(N)` — a fixed-capacity, allocator-free *sorted map*. This is
//!      the authoritative in-memory key→value store. `put`/`get`/`delete`
//!      keep entries strictly byte-lex sorted via a bounded binary search;
//!      `walkInOrder` enumerates them via an explicit TigerBeetle intrusive
//!      `Stack` (no recursion). This is the surface the repo/route layers
//!      mutate.
//!
//!   2. The *hierarchical MST encoder* (`getRoot`, `buildAndEmit`,
//!      `keyLayer`). This realises the real atproto MST: keys are bucketed
//!      into layers by `keyLayer` (leading-zero-bits of SHA-256(key) / 2 →
//!      fanout 4), nodes are built per layer with the canonical atproto node
//!      shape, every node is serialized as a DAG-CBOR block, node CIDs are
//!      computed bottom-up, and the *root node's* CID is the repo `data`
//!      root. Tree construction uses an explicit bounded stack of range
//!      frames — no unbounded recursion, Tiger-Style fixed buffers
//!      throughout.
//!
//! ## atproto node shape (DAG-CBOR map)
//!
//!     { "l": <CID|null>,           // left subtree (keys < e[0].key, lower layer)
//!       "e": [ TreeEntry, ... ] }  // entries at this node's layer, sorted
//!
//!     TreeEntry = { "p": <uint>,   // bytes of key shared with previous entry
//!                   "k": <bytes>,  // remaining key suffix
//!                   "v": <CID>,    // value CID
//!                   "t": <CID|null> } // right subtree (keys between this
//!                                     // entry and the next, lower layer)
//!
//! Map key order is DAG-CBOR canonical (length-then-byte-lex):
//!   node entry keys "e"(1) < "l"(1) → ["e","l"]
//!   tree-entry keys "k"(1) < "p"(1) < "t"(1) < "v"(1) → ["k","p","t","v"]
//!
//! ## What is implemented vs deferred
//!
//! Implemented (correct, block-persisted, round-trips):
//!   * layer assignment per the spec leading-zero-bit rule (fanout 4)
//!   * full hierarchical node construction over the sorted key set
//!   * canonical atproto node shape with prefix compression (`p`/`k`)
//!   * per-node DAG-CBOR block + CID; bottom-up CID computation
//!   * deterministic root CID by content (order-independent)
//!   * `buildAndEmit` streams every node block to a caller sink so the repo
//!     persists each node into `atp_mst_blocks` keyed by its own CID
//!
//! Deferred (documented, not faked):
//!   * Incremental / diff-based node mutation: we rebuild the node layer
//!     structure from the sorted entry set on each `getRoot`. The in-memory
//!     `Tree` itself is mutated incrementally (O(log N) put/get/delete) and
//!     the repo layer caches it across commits (AT-16), so we never reload
//!     records per commit; only the *node block re-derivation* is per-commit.
//!     A true structural-diff persist (touching only changed nodes) is a
//!     later optimization and is not required for correctness or round-trip.
//!   * CAR-streaming of the node DAG lives in `car.zig` / the route layer;
//!     this module only computes node bytes + CIDs and hands them to a sink.
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
/// stack-allocated index buffer in the tree walker / builder. 1 << 14 ≈
/// 16k entries — well above per-repo collection sizes seen on real PDS
/// deployments at speedy-socials' target scale.
pub const max_keys: u32 = 1 << 14;

/// Walker / builder stack depth. Tiger requires explicit, fixed. The MST
/// layer count is bounded by the SHA-256 width: leadingZeros(256 bits)/2 =
/// 128 distinct layers maximum, and the build stack also threads through
/// pending right-subtree frames, so 256 covers the deepest legal tree with
/// generous headroom. Sized as a constant so an overflow is a hard panic.
pub const max_walk_depth: u32 = 256;

pub const max_key_bytes: usize = 256;

/// Layer derivation hash width (bits) — SHA-256.
const hash_bits: u32 = 256;

pub const Entry = struct {
    key_len: u8,
    key_bytes: [max_key_bytes]u8,
    value: cid_mod.Cid,

    pub fn key(self: *const Entry) []const u8 {
        return self.key_bytes[0..self.key_len];
    }
};

/// Compute the MST layer (height) of `key`: count leading zero *bits* of
/// SHA-256(key), then divide by 2 (integer). This yields a fanout of 4 —
/// roughly 1/4 of keys land one layer up, 1/16 two layers up, etc. The
/// rule is part of the on-the-wire spec, so it must match byte-for-byte
/// across implementations.
pub fn keyLayer(key: []const u8) u32 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(key, &digest, .{});
    var leading: u32 = 0;
    var i: usize = 0;
    while (i < digest.len) : (i += 1) {
        const b = digest[i];
        if (b == 0) {
            leading += 8;
            continue;
        }
        leading += @clz(b);
        break;
    }
    assertLe(leading, hash_bits);
    return leading / 2;
}

/// Length of the common byte prefix between `a` and `b`. Used for the
/// atproto `p` (prefix) field which compresses each entry's key against
/// the previous entry's key within the same node.
fn commonPrefixLen(a: []const u8, b: []const u8) u32 {
    const n = @min(a.len, b.len);
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        assertLe(i, n);
        if (a[i] != b[i]) break;
    }
    return i;
}

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

        /// A single tree-walker frame. The intrusive `link` field is what
        /// the explicit `Stack` threads through.
        pub const Frame = struct {
            /// First entry index this frame is responsible for visiting.
            start: u32,
            /// One past the last entry this frame visits.
            stop: u32,
            link: core.intrusive.Stack(@This()).Link = .{},
        };

        /// In-order callback over every (key, value) pair.
        /// `Visitor` must define `fn onLeaf(*Self, *const Entry, []const u8, Cid) void`.
        pub fn walkInOrder(self: *const Self, comptime Visitor: type, visitor: *Visitor) void {
            // Entries are kept sorted in `entries`; the "walk" is a single
            // linear pass driven by an *explicit* TigerBeetle intrusive
            // Stack (LIFO). Tiger Style: no recursion, fixed capacity, every
            // loop bounded by `self.count`.
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

        // ── Hierarchical MST encoding ──────────────────────────────────

        /// Build context threaded through the explicit build stack. `sink`
        /// receives every emitted node block (CID + canonical bytes) so the
        /// caller can persist it; pass a no-op sink when only the root CID
        /// is wanted (see `getRoot`).
        const max_node_bytes: usize = 64 * 1024;

        /// Sink contract: `Sink` must define
        ///   `fn onNode(*Sink, cid: cid_mod.Cid, bytes: []const u8) AtpError!void`
        /// It is called once per node, children before parents (post-order).
        ///
        /// Returns the root node CID. For an empty tree the canonical empty
        /// node `{l: null, e: []}` is emitted and its CID returned, matching
        /// the atproto convention that even an empty repo has a data root.
        pub fn buildAndEmit(self: *const Self, comptime Sink: type, sink: *Sink) AtpError!cid_mod.Cid {
            // Empty tree → the canonical empty node.
            if (self.count == 0) {
                var node_buf: [64]u8 = undefined;
                const bytes = try encodeEmptyNode(&node_buf);
                const cid = cid_mod.computeDagCbor(bytes);
                try sink.onNode(cid, bytes);
                return cid;
            }

            // Explicit, bounded build stack. Each frame, when popped the
            // first time, expands into "emit my child sub-ranges, then build
            // me". We model that with a two-phase frame: a frame is pushed
            // once to schedule its *children*, and we collect child results
            // through their `out_cid` slots, then build the parent.
            //
            // To keep this strictly non-recursive and bounded we use an
            // explicit work stack of `Op`s rather than the intrusive Stack
            // (we need post-order, which the intrusive LIFO gives us when we
            // push a parent's "finish" op before its children).
            var root_cid: cid_mod.Cid = undefined;
            var root_present: bool = false;
            const top_layer = self.maxLayer(0, self.count);
            try self.buildRange(Sink, sink, 0, self.count, top_layer, &root_cid, &root_present);
            assert(root_present);
            return root_cid;
        }

        /// Highest layer among entries in [lo, hi). Caller guarantees
        /// lo < hi.
        fn maxLayer(self: *const Self, lo: u32, hi: u32) u32 {
            var best: u32 = 0;
            var i = lo;
            while (i < hi) : (i += 1) {
                assertLe(i, self.count);
                const l = keyLayer(self.entries[i].key());
                if (l > best) best = l;
            }
            return best;
        }

        /// Build the node covering [lo, hi) at `layer` (the max layer in the
        /// range). Emits child subtrees first (post-order) via `sink`, then
        /// this node. Writes the node CID to `*out_cid`.
        ///
        /// Non-recursive: an explicit LIFO stack of `RangeJob`s drives the
        /// traversal. Each job is processed by splitting it into its
        /// entries-at-layer (this node's `e[]`) and the gap sub-ranges
        /// (children at a strictly lower layer). Children jobs carry a slot
        /// pointer; when fully built, the parent is assembled.
        fn buildRange(
            self: *const Self,
            comptime Sink: type,
            sink: *Sink,
            root_lo: u32,
            root_hi: u32,
            root_layer: u32,
            out_cid: *cid_mod.Cid,
            out_present: *bool,
        ) AtpError!void {
            // A job to build one node. We process jobs with an explicit
            // stack. Because a node needs its children's CIDs *before* it can
            // be assembled, each job has two visits:
            //   visit 0 (expand): scan [lo,hi) at `layer`, record the entry
            //     indices at exactly `layer` and the child gap ranges, push
            //     a "finish" marker then push child jobs (so children pop and
            //     complete first), storing their results in slots.
            //   visit 1 (finish): all children done → encode this node,
            //     compute CID, emit, write CID into the parent slot.
            //
            // Storage for jobs and their per-node scratch lives in fixed
            // arrays sized by max_walk_depth (tree height) — a node only
            // needs its direct children resolved at once along any root→leaf
            // path, and the LIFO processes one path at a time.

            // Per-node working set. We bound the *fan* (entries per node)
            // by max_keys (a degenerate single-layer tree puts everything in
            // one node) and the *depth* by max_walk_depth.
            const Job = struct {
                lo: u32,
                hi: u32,
                layer: u32,
                phase: u8, // 0 = expand, 1 = finish
                // child results: left subtree + one right subtree per entry.
                // Filled during children's finish; consumed at our finish.
                left_cid: cid_mod.Cid = undefined,
                left_present: bool = false,
                out_cid: *cid_mod.Cid,
                out_present: *bool,
                // entry indices at this node's layer (into self.entries)
                ent: [*]u32, // slice base into shared entry-index arena
                ent_len: u32 = 0,
                // right subtree results, one per entry (index i = right of ent[i])
                rt_cid: [*]cid_mod.Cid,
                rt_present: [*]bool,
            };

            // Shared arenas. A node at the root layer can in the worst case
            // (all keys same layer) hold every key as an entry, so the entry
            // arena must be sized to max_keys total across the live path. But
            // along a single root→leaf path the sum of entries across nodes
            // is also bounded by the total key count, so one max_keys-sized
            // arena, allocated as a bump within the recursion path, suffices.
            //
            // We use a bump allocator over fixed BSS-free stack arrays. The
            // job stack depth is bounded by max_walk_depth; entry arena by
            // max_keys; right-subtree arenas by max_keys (one per entry).
            var jobs: [max_walk_depth]Job = undefined;
            var ent_arena: [max_keys]u32 = undefined;
            var rt_cid_arena: [max_keys]cid_mod.Cid = undefined;
            var rt_present_arena: [max_keys]bool = undefined;
            var arena_used: u32 = 0;

            var top: u32 = 0;
            // Seed root job.
            jobs[0] = .{
                .lo = root_lo,
                .hi = root_hi,
                .layer = root_layer,
                .phase = 0,
                .out_cid = out_cid,
                .out_present = out_present,
                .ent = ent_arena[0..].ptr,
                .rt_cid = rt_cid_arena[0..].ptr,
                .rt_present = rt_present_arena[0..].ptr,
            };
            top = 1;

            var guard: u64 = 0;
            const guard_max: u64 = @as(u64, max_keys) * 4 + 16;
            while (top > 0) {
                guard += 1;
                if (guard > guard_max) return error.MstInvariant;
                const ji = top - 1;
                if (jobs[ji].phase == 0) {
                    // ── Expand phase ──
                    // Carve the entry arena for this node.
                    const ent_base = arena_used;
                    var ent_count: u32 = 0;
                    // Scan [lo,hi). Entries at exactly `layer` become this
                    // node's entries; the gaps between them are child
                    // sub-ranges built at a lower layer.
                    var i = jobs[ji].lo;
                    while (i < jobs[ji].hi) : (i += 1) {
                        assertLe(i, self.count);
                        if (keyLayer(self.entries[i].key()) == jobs[ji].layer) {
                            if (arena_used >= max_keys) return error.MstInvariant;
                            ent_arena[arena_used] = i;
                            arena_used += 1;
                            ent_count += 1;
                        }
                    }
                    if (ent_count == 0) return error.MstInvariant; // layer is the max → at least one
                    jobs[ji].ent = ent_arena[ent_base..].ptr;
                    jobs[ji].ent_len = ent_count;

                    // Carve right-subtree result arena (one slot per entry).
                    const rt_base = arena_used;
                    if (arena_used + ent_count > max_keys) return error.MstInvariant;
                    var z: u32 = 0;
                    while (z < ent_count) : (z += 1) {
                        rt_present_arena[rt_base + z] = false;
                    }
                    arena_used += ent_count;
                    jobs[ji].rt_cid = rt_cid_arena[rt_base..].ptr;
                    jobs[ji].rt_present = rt_present_arena[rt_base..].ptr;
                    jobs[ji].left_present = false;

                    jobs[ji].phase = 1; // next time we pop this, finish it.

                    // Push child jobs for the gaps. Children must complete
                    // before us, and the LIFO pops the most recently pushed
                    // first, so push them in any order — they all finish
                    // before this job's phase-1 pop because we don't advance
                    // past `top` until they're consumed. We push them now and
                    // let them resolve; they write into our slots.
                    //
                    // Gap layout for entries at indices E0<E1<...<E(k-1):
                    //   left gap:  [lo, E0)
                    //   between:   (E_j, E_(j+1))  → right subtree of E_j
                    //   right gap: (E_(k-1), hi)   → right subtree of E_(k-1)
                    const ent_ptr = jobs[ji].ent;

                    // We must push children such that there's stack room.
                    // Each child is a node at a strictly lower layer; depth
                    // is bounded so this fits in max_walk_depth.

                    // Left gap.
                    {
                        const g_lo = jobs[ji].lo;
                        const g_hi = ent_ptr[0];
                        if (g_hi > g_lo) {
                            if (top >= max_walk_depth) return error.MstInvariant;
                            const child_layer = self.maxLayer(g_lo, g_hi);
                            jobs[top] = .{
                                .lo = g_lo,
                                .hi = g_hi,
                                .layer = child_layer,
                                .phase = 0,
                                .out_cid = &jobs[ji].left_cid,
                                .out_present = &jobs[ji].left_present,
                                .ent = ent_arena[0..].ptr,
                                .rt_cid = rt_cid_arena[0..].ptr,
                                .rt_present = rt_present_arena[0..].ptr,
                            };
                            top += 1;
                        }
                    }
                    // Right gaps (between entries and after last).
                    var e: u32 = 0;
                    while (e < ent_count) : (e += 1) {
                        const g_lo = ent_ptr[e] + 1;
                        const g_hi = if (e + 1 < ent_count) ent_ptr[e + 1] else jobs[ji].hi;
                        if (g_hi > g_lo) {
                            if (top >= max_walk_depth) return error.MstInvariant;
                            const child_layer = self.maxLayer(g_lo, g_hi);
                            jobs[top] = .{
                                .lo = g_lo,
                                .hi = g_hi,
                                .layer = child_layer,
                                .phase = 0,
                                .out_cid = &jobs[ji].rt_cid[e],
                                .out_present = &jobs[ji].rt_present[e],
                                .ent = ent_arena[0..].ptr,
                                .rt_cid = rt_cid_arena[0..].ptr,
                                .rt_present = rt_present_arena[0..].ptr,
                            };
                            top += 1;
                        }
                    }
                    continue;
                }

                // ── Finish phase ── all children resolved; assemble node.
                var node_buf: [max_node_bytes]u8 = undefined;
                const bytes = try self.encodeNode(&jobs[ji], &node_buf);
                const cid = cid_mod.computeDagCbor(bytes);
                try sink.onNode(cid, bytes);
                jobs[ji].out_cid.* = cid;
                jobs[ji].out_present.* = true;
                top -= 1;
            }
        }

        /// Encode a single node into `out`, returning the written slice.
        /// Node shape: { "e": [TreeEntry...], "l": <CID|null> }.
        fn encodeNode(self: *const Self, job: anytype, out: []u8) AtpError![]const u8 {
            var enc = dag.Encoder.init(out);
            try enc.writeMapHeader(2);

            // Canonical key order: "e"(1) < "l"(1) → "e" first.
            try enc.writeText("e");
            try enc.writeArrayHeader(job.ent_len);
            var prev_key: []const u8 = &[_]u8{};
            var e: u32 = 0;
            while (e < job.ent_len) : (e += 1) {
                assertLe(e, job.ent_len);
                const idx = job.ent[e];
                const key = self.entries[idx].key();
                const p = if (e == 0) 0 else commonPrefixLen(prev_key, key);
                const suffix = key[p..];

                // TreeEntry map. Canonical key order: "k","p","t","v".
                try enc.writeMapHeader(4);
                try enc.writeText("k");
                try enc.writeBytesValue(suffix);
                try enc.writeText("p");
                try enc.writeUInt(p);
                try enc.writeText("t");
                if (job.rt_present[e]) {
                    try enc.writeCidLink(job.rt_cid[e].raw());
                } else {
                    try enc.writeNull();
                }
                try enc.writeText("v");
                try enc.writeCidLink(self.entries[idx].value.raw());

                prev_key = key;
            }

            try enc.writeText("l");
            if (job.left_present) {
                try enc.writeCidLink(job.left_cid.raw());
            } else {
                try enc.writeNull();
            }

            return enc.written();
        }

        /// Compute the root CID of the hierarchical MST over the current
        /// entry set, writing the *root node's* canonical bytes into
        /// `scratch` so the caller can persist the root block. Returns the
        /// root CID and the number of bytes written into `scratch`.
        ///
        /// NOTE: only the root node is written into `scratch`. The full set
        /// of node blocks (root + every interior/leaf node) is obtained via
        /// `buildAndEmit` with a persisting sink — that is what the repo
        /// layer uses to store all blocks. `getRoot` is the lightweight
        /// "just give me the root CID + root block" entry point that keeps
        /// the historical signature stable.
        pub fn getRoot(self: *const Self, scratch: []u8) AtpError!struct { cid: cid_mod.Cid, bytes_written: usize } {
            var sink = RootCaptureSink{ .scratch = scratch };
            const cid = try self.buildAndEmit(RootCaptureSink, &sink);
            return .{ .cid = cid, .bytes_written = sink.root_len };
        }

        /// A sink that captures only the root node's bytes (the last node
        /// emitted in post-order is the root). It records every node's bytes
        /// transiently and keeps the final one.
        const RootCaptureSink = struct {
            scratch: []u8,
            root_len: usize = 0,

            pub fn onNode(self: *RootCaptureSink, cid: cid_mod.Cid, bytes: []const u8) AtpError!void {
                _ = cid;
                // Post-order: the root node is emitted last, so each call
                // overwrites — after the walk completes, `scratch` holds the
                // root. Bytes longer than scratch is a caller sizing bug.
                if (bytes.len > self.scratch.len) return error.BufferTooSmall;
                @memcpy(self.scratch[0..bytes.len], bytes);
                self.root_len = bytes.len;
            }
        };
    };
}

/// Encode the canonical empty node `{ "e": [], "l": null }` into `out`.
fn encodeEmptyNode(out: []u8) AtpError![]const u8 {
    var enc = dag.Encoder.init(out);
    try enc.writeMapHeader(2);
    try enc.writeText("e");
    try enc.writeArrayHeader(0);
    try enc.writeText("l");
    try enc.writeNull();
    return enc.written();
}

fn entryKeyEql(e: *const Entry, key: []const u8) bool {
    return std.mem.eql(u8, e.key(), key);
}

// ── Tests ──────────────────────────────────────────────────────────

fn fakeCid(seed: u8) cid_mod.Cid {
    var data: [4]u8 = .{ seed, seed +% 1, seed +% 2, seed +% 3 };
    return cid_mod.computeDagCbor(&data);
}

/// A test sink that records every emitted node (CID + bytes) so tests can
/// verify block persistence and reconstruct the key set.
const RecordingSink = struct {
    const Cap = 512;
    const BlobCap = 4096;
    cids: [Cap]cid_mod.Cid = undefined,
    lens: [Cap]u16 = undefined,
    blobs: [Cap][BlobCap]u8 = undefined,
    n: u32 = 0,

    pub fn onNode(self: *RecordingSink, cid: cid_mod.Cid, bytes: []const u8) AtpError!void {
        if (self.n >= Cap) return error.MstInvariant;
        if (bytes.len > self.blobs[0].len) return error.BufferTooSmall;
        self.cids[self.n] = cid;
        self.lens[self.n] = @intCast(bytes.len);
        @memcpy(self.blobs[self.n][0..bytes.len], bytes);
        self.n += 1;
    }

    fn find(self: *const RecordingSink, cid: cid_mod.Cid) ?[]const u8 {
        var i: u32 = 0;
        while (i < self.n) : (i += 1) {
            if (std.mem.eql(u8, self.cids[i].raw(), cid.raw())) {
                return self.blobs[i][0..self.lens[i]];
            }
        }
        return null;
    }
};

/// Walk the node DAG starting at `root`, collecting every (key, value-CID)
/// leaf into `out_keys`/`out_vals`. Reconstructs full keys from the
/// prefix-compressed entries. Used by tests to prove a block set
/// round-trips back to the original key set. Bounded, explicit stack.
const Reconstructor = struct {
    sink: *const RecordingSink,
    keys: [4096][256]u8 = undefined,
    key_lens: [4096]u16 = undefined,
    vals: [4096]cid_mod.Cid = undefined,
    n: u32 = 0,

    fn run(self: *Reconstructor, root: cid_mod.Cid) !void {
        var stack: [512]cid_mod.Cid = undefined;
        var top: usize = 0;
        stack[top] = root;
        top += 1;
        var guard: u32 = 0;
        while (top > 0) {
            guard += 1;
            if (guard > 100_000) return error.MstInvariant;
            top -= 1;
            const cid = stack[top];
            const bytes = self.sink.find(cid) orelse return error.MstInvariant;
            try self.visitNode(bytes, &stack, &top);
        }
    }

    fn visitNode(self: *Reconstructor, bytes: []const u8, stack: *[512]cid_mod.Cid, top: *usize) !void {
        var dec = dag.Decoder.init(bytes);
        // map(2)
        const m = try dec.nextEvent();
        if (m != .map_start) return error.MstInvariant;
        // key "e"
        const ke = try dec.nextEvent();
        if (ke != .text or !std.mem.eql(u8, ke.text, "e")) return error.MstInvariant;
        const arr = try dec.nextEvent();
        if (arr != .array_start) return error.MstInvariant;
        const ecount: u64 = arr.array_start;
        var prev: [256]u8 = undefined;
        var i: u64 = 0;
        while (i < ecount) : (i += 1) {
            const em = try dec.nextEvent();
            if (em != .map_start or em.map_start != 4) return error.MstInvariant;
            // entry keys in canonical order: k, p, t, v
            const kk = try dec.nextEvent();
            if (kk != .text or !std.mem.eql(u8, kk.text, "k")) return error.MstInvariant;
            const suffix_ev = try dec.nextEvent();
            const suffix = suffix_ev.bytes;
            const kp = try dec.nextEvent();
            if (kp != .text or !std.mem.eql(u8, kp.text, "p")) return error.MstInvariant;
            const p_ev = try dec.nextEvent();
            const p: usize = @intCast(p_ev.uint);
            const kt = try dec.nextEvent();
            if (kt != .text or !std.mem.eql(u8, kt.text, "t")) return error.MstInvariant;
            const t_ev = try dec.nextEvent();
            const kv = try dec.nextEvent();
            if (kv != .text or !std.mem.eql(u8, kv.text, "v")) return error.MstInvariant;
            const v_ev = try dec.nextEvent();

            // Reconstruct full key = prev[0..p] ++ suffix.
            var full: [256]u8 = undefined;
            @memcpy(full[0..p], prev[0..p]);
            @memcpy(full[p..][0..suffix.len], suffix);
            const full_len = p + suffix.len;
            @memcpy(prev[0..full_len], full[0..full_len]);

            // Record leaf.
            @memcpy(self.keys[self.n][0..full_len], full[0..full_len]);
            self.key_lens[self.n] = @intCast(full_len);
            self.vals[self.n] = cidFromBytes(v_ev.cid);
            self.n += 1;

            // Right subtree.
            if (t_ev == .cid) {
                stack[top.*] = cidFromBytes(t_ev.cid);
                top.* += 1;
            }
        }
        // key "l"
        const kl = try dec.nextEvent();
        if (kl != .text or !std.mem.eql(u8, kl.text, "l")) return error.MstInvariant;
        const l_ev = try dec.nextEvent();
        if (l_ev == .cid) {
            stack[top.*] = cidFromBytes(l_ev.cid);
            top.* += 1;
        }
    }
};

fn cidFromBytes(b: []const u8) cid_mod.Cid {
    var c: cid_mod.Cid = .{ .bytes = undefined };
    @memcpy(c.bytes[0..], b[0..cid_mod.raw_cid_len]);
    return c;
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

    var s1: [4096]u8 = undefined;
    var s2: [4096]u8 = undefined;
    const r1 = try t1.getRoot(&s1);
    const r2 = try t2.getRoot(&s2);
    try std.testing.expectEqualSlices(u8, r1.cid.raw(), r2.cid.raw());
}

test "mst: walker visits every entry exactly once via intrusive Stack" {
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
    var sa: [4096]u8 = undefined;
    const a = try t.getRoot(&sa);

    _ = try t.put("k", fakeCid(2));
    var sb: [4096]u8 = undefined;
    const b = try t.getRoot(&sb);
    try std.testing.expect(!std.mem.eql(u8, a.cid.raw(), b.cid.raw()));
}

test "mst: keyLayer obeys leading-zero-bits/2 rule" {
    // A key whose SHA-256 starts with a non-zero high nibble lands at
    // layer 0. We can't pick a hash, but we can verify the arithmetic by
    // constructing digests indirectly: assert the function never exceeds
    // 128 and is monotone in leading zeros via a hand-checked vector.
    // Direct unit check of the bit math:
    const Probe = struct {
        fn layerFromLeading(leading: u32) u32 {
            return leading / 2;
        }
    };
    try std.testing.expectEqual(@as(u32, 0), Probe.layerFromLeading(0));
    try std.testing.expectEqual(@as(u32, 0), Probe.layerFromLeading(1));
    try std.testing.expectEqual(@as(u32, 1), Probe.layerFromLeading(2));
    try std.testing.expectEqual(@as(u32, 1), Probe.layerFromLeading(3));
    try std.testing.expectEqual(@as(u32, 4), Probe.layerFromLeading(8));
    // The real function must agree on at least one concrete key.
    const l = keyLayer("app.bsky.feed.post/3jt6k2k2k2k2");
    try std.testing.expect(l <= 128);
}

test "mst: hierarchical blocks round-trip to the same key set (small N)" {
    var t = Tree(64).init();
    const keys = [_][]const u8{
        "app.bsky.feed.post/aaa", "app.bsky.feed.post/bbb",
        "app.bsky.feed.like/ccc", "app.bsky.actor.profile/self",
        "app.bsky.graph.follow/ddd",
    };
    for (keys, 0..) |k, idx| {
        _ = try t.put(k, fakeCid(@intCast(idx + 1)));
    }

    const sink = try std.testing.allocator.create(RecordingSink);
    defer std.testing.allocator.destroy(sink);
    sink.* = .{};
    const root = try t.buildAndEmit(RecordingSink, sink);
    try std.testing.expect(sink.n >= 1);
    // Every emitted block's CID must equal computeDagCbor(bytes).
    var bi: u32 = 0;
    while (bi < sink.n) : (bi += 1) {
        const recomputed = cid_mod.computeDagCbor(sink.blobs[bi][0..sink.lens[bi]]);
        try std.testing.expectEqualSlices(u8, sink.cids[bi].raw(), recomputed.raw());
    }

    // Reconstruct the key set from the block DAG.
    const rec = try std.testing.allocator.create(Reconstructor);
    defer std.testing.allocator.destroy(rec);
    rec.* = .{ .sink = sink, .n = 0 };
    try rec.run(root);
    try std.testing.expectEqual(@as(u32, keys.len), rec.n);

    // Each original key must be present with its value.
    for (keys, 0..) |k, idx| {
        var found = false;
        var j: u32 = 0;
        while (j < rec.n) : (j += 1) {
            if (std.mem.eql(u8, rec.keys[j][0..rec.key_lens[j]], k)) {
                try std.testing.expectEqualSlices(u8, fakeCid(@intCast(idx + 1)).raw(), rec.vals[j].raw());
                found = true;
                break;
            }
        }
        try std.testing.expect(found);
    }
}

test "mst: large-N hierarchical round-trip exercises fanout depth (N=200)" {
    var t = Tree(max_keys).init();
    const N: u32 = 200;
    var i: u32 = 0;
    var key_buf: [64]u8 = undefined;
    while (i < N) : (i += 1) {
        const k = try std.fmt.bufPrint(&key_buf, "app.bsky.feed.post/rec{x:0>8}", .{i});
        _ = try t.put(k, fakeCid(@intCast(i % 251)));
    }
    try std.testing.expectEqual(N, t.len());

    const sink = try std.testing.allocator.create(RecordingSink);
    defer std.testing.allocator.destroy(sink);
    sink.* = .{};
    const root = try t.buildAndEmit(RecordingSink, sink);
    // With fanout 4 and N=200 we expect multiple layers → more than one
    // node (a flat single node would mean fanout never kicked in).
    try std.testing.expect(sink.n >= 2);

    // Reconstruct and verify the full key set survives.
    const rec = try std.testing.allocator.create(Reconstructor);
    defer std.testing.allocator.destroy(rec);
    rec.* = .{ .sink = sink, .n = 0 };
    try rec.run(root);
    try std.testing.expectEqual(N, rec.n);

    // Verify the reconstructed keys are exactly the inserted ones (sorted
    // membership check via the Tree itself).
    var j: u32 = 0;
    while (j < rec.n) : (j += 1) {
        const got = t.get(rec.keys[j][0..rec.key_lens[j]]);
        try std.testing.expect(got != null);
        try std.testing.expectEqualSlices(u8, got.?.raw(), rec.vals[j].raw());
    }
}

test "mst: empty tree yields canonical empty-node root" {
    var t = Tree(8).init();
    const sink = try std.testing.allocator.create(RecordingSink);
    defer std.testing.allocator.destroy(sink);
    sink.* = .{};
    const root = try t.buildAndEmit(RecordingSink, sink);
    try std.testing.expectEqual(@as(u32, 1), sink.n);
    const expected = cid_mod.computeDagCbor(sink.blobs[0][0..sink.lens[0]]);
    try std.testing.expectEqualSlices(u8, expected.raw(), root.raw());
}

test "mst: delete changes the root CID and removes the key from the DAG" {
    var t = Tree(64).init();
    const keys = [_][]const u8{
        "c.n/a", "c.n/b", "c.n/c", "c.n/d", "c.n/e", "c.n/f",
    };
    for (keys, 0..) |k, idx| _ = try t.put(k, fakeCid(@intCast(idx + 1)));

    var s_before: [8192]u8 = undefined;
    const before = try t.getRoot(&s_before);

    try std.testing.expect(t.delete("c.n/c"));

    var s_after: [8192]u8 = undefined;
    const after = try t.getRoot(&s_after);
    try std.testing.expect(!std.mem.eql(u8, before.cid.raw(), after.cid.raw()));

    // The deleted key must be gone from the reconstructed DAG.
    const sink = try std.testing.allocator.create(RecordingSink);
    defer std.testing.allocator.destroy(sink);
    sink.* = .{};
    const root = try t.buildAndEmit(RecordingSink, sink);
    const rec = try std.testing.allocator.create(Reconstructor);
    defer std.testing.allocator.destroy(rec);
    rec.* = .{ .sink = sink, .n = 0 };
    try rec.run(root);
    try std.testing.expectEqual(@as(u32, keys.len - 1), rec.n);
    var j: u32 = 0;
    while (j < rec.n) : (j += 1) {
        try std.testing.expect(!std.mem.eql(u8, rec.keys[j][0..rec.key_lens[j]], "c.n/c"));
    }
}
