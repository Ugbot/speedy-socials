//! Incremental-MST benchmark (independent perf verification).
//!
//! The atproto repo `data` root is an MST over the repo's records. On a
//! commit that touches ONE record, a naive implementation re-derives and
//! re-persists every node in the tree; the incremental encoder
//! (`Tree.buildAndEmitIncremental`) re-emits only the nodes on the changed
//! root→leaf path, reusing every clean sibling subtree's cached CID.
//!
//! This bench measures, for N = 500 and N = 2000 records:
//!   * blocks-written on a full rebuild (every node)            = full
//!   * blocks-written on a +1-record incremental commit          = incr
//!   * the block-write reduction ratio                           = full/incr
//!   * wall-clock ns for each, as a secondary signal
//!
//! "Blocks written" is the dominant cost: each block is a DAG-CBOR encode
//! + SHA-256 CID + a row written to `atp_mst_blocks`. The claim under test
//! is ~200x fewer block writes on the +1 commit. We MEASURE and print the
//! real ratio; magnitude depends on tree shape (fanout 4), so we assert
//! only a conservative floor and report the true number.

const std = @import("std");
const core = @import("core");
const atproto = @import("protocol_atproto");
const mst = atproto.mst;
const cid_mod = atproto.cid;

const Cid = cid_mod.Cid;
const atproto_errors = core.errors.AtpError;

fn nowNs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(std.c.CLOCK.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

/// Sink that only counts emitted node blocks — models the per-commit
/// block-write cost without the SQLite row (which is linear in the count
/// we measure, so the ratio is what matters).
const CountSink = struct {
    n: u32 = 0,
    pub fn onNode(self: *CountSink, cid: Cid, bytes: []const u8) atproto_errors!void {
        _ = cid;
        _ = bytes;
        self.n += 1;
    }
};

fn fakeCid(seed: u64) Cid {
    var data: [8]u8 = undefined;
    std.mem.writeInt(u64, &data, seed, .little);
    return cid_mod.computeDagCbor(&data);
}

fn keyFor(buf: []u8, i: u32) []const u8 {
    return std.fmt.bufPrint(buf, "app.bsky.feed.post/rec{x:0>10}", .{i}) catch unreachable;
}

const Tree = mst.Tree(mst.max_keys);

fn runOne(comptime N: u32, alloc: std.mem.Allocator) !void {
    const tree = try alloc.create(Tree);
    defer alloc.destroy(tree);
    tree.* = Tree.init();

    var kb: [64]u8 = undefined;
    var i: u32 = 0;
    while (i < N) : (i += 1) {
        _ = try tree.put(keyFor(&kb, i), fakeCid(i));
    }

    // ── Full rebuild: count every node block + time it. ──
    var full_sink: CountSink = .{};
    const f0 = nowNs();
    _ = try tree.buildAndEmit(CountSink, &full_sink);
    const full_ns = nowNs() - f0;
    const full_blocks = full_sink.n;

    // ── Warm the incremental cache (first incremental persist does a full
    //    rebuild that populates the node cache), then do a +1-record commit
    //    and count ONLY the nodes the incremental encoder re-emits. ──
    var warm_sink: CountSink = .{};
    _ = try tree.buildAndEmitIncremental(CountSink, &warm_sink, null);

    // +1 record (a new leaf) — the realistic single-record commit.
    _ = try tree.put(keyFor(&kb, N), fakeCid(N));

    var incr_sink: CountSink = .{};
    var emitted: u32 = 0;
    const inc_start = nowNs();
    _ = try tree.buildAndEmitIncremental(CountSink, &incr_sink, &emitted);
    const incr_ns = nowNs() - inc_start;

    const ratio = @as(f64, @floatFromInt(full_blocks)) / @as(f64, @floatFromInt(@max(emitted, 1)));
    const time_ratio = @as(f64, @floatFromInt(full_ns)) / @as(f64, @floatFromInt(@max(incr_ns, 1)));

    std.debug.print("mst-bench: N={d}\n", .{N});
    std.debug.print("  full rebuild  : {d:>5} blocks  {d:>8.1} us\n", .{ full_blocks, @as(f64, @floatFromInt(full_ns)) / 1000.0 });
    std.debug.print("  +1 incremental: {d:>5} blocks  {d:>8.1} us\n", .{ emitted, @as(f64, @floatFromInt(incr_ns)) / 1000.0 });
    std.debug.print("  block-write reduction : {d:.1}x   (wall-clock {d:.1}x)\n", .{ ratio, time_ratio });

    // Correctness: the +1 incremental commit must re-emit FEWER blocks than
    // a full rebuild, and at least one (the new leaf's path to root).
    if (emitted == 0) return error.NothingEmitted;
    if (emitted >= full_blocks) return error.IncrementalNotFewer;
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    try runOne(500, alloc);
    try runOne(2000, alloc);
}
