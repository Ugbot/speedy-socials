//! D3 firehose throughput benchmark.
//!
//! Compares two ways of landing N firehose events in `atp_firehose_events`:
//!
//!   * **direct**: one autocommitted single-row INSERT per event (plus the
//!     cursor UPDATE) — what `firehose.appendKind` does today.
//!   * **ring+drain**: events go into the in-memory L0 `Ring` (no SQLite on
//!     the hot path), then a single transactional batch drain copies them
//!     into L1.
//!
//! Prints rows/sec for each and the speed-up. The point is to *measure*
//! (not assume) the batched-write win the D3 design rests on; the harness
//! asserts the batched path is at least as fast so a regression fails CI.

const std = @import("std");
const core = @import("core");
const atproto = @import("protocol_atproto");
const c = @import("sqlite").c;

const firehose = atproto.firehose;
const firehose_buffer = atproto.firehose_buffer;
const schema = atproto.schema;

const N: u64 = 20_000;

fn nowNs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(std.c.CLOCK.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

fn openFresh(path: [:0]const u8, alloc: std.mem.Allocator) !*c.sqlite3 {
    _ = std.c.unlink(path.ptr);
    const db = try core.storage.sqlite.openWriter(path);
    for (schema.all_migrations) |m| {
        const sql_z = try alloc.dupeZ(u8, m.up);
        defer alloc.free(sql_z);
        var em: [*c]u8 = null;
        _ = c.sqlite3_exec(db, sql_z.ptr, null, null, &em);
        if (em != null) c.sqlite3_free(em);
    }
    return db;
}

fn countEvents(db: *c.sqlite3) i64 {
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM atp_firehose_events", -1, &stmt, null) != c.SQLITE_OK) return -1;
    defer _ = c.sqlite3_finalize(stmt);
    if (c.sqlite3_step(stmt.?) != c.SQLITE_ROW) return -1;
    return c.sqlite3_column_int64(stmt, 0);
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    // ── Path A: direct single-row inserts via firehose.appendKind ──
    const db_direct = try openFresh("/tmp/sps_fh_direct.db", alloc);
    defer core.storage.sqlite.closeDb(db_direct);

    const t0 = nowNs();
    var i: u64 = 0;
    while (i < N) : (i += 1) {
        _ = firehose.append(db_direct, "did:plc:benchsubject", "bafyreibenchcid", "{\"op\":\"c\"}", @intCast(i)) catch 0;
    }
    const t1 = nowNs();
    const direct_ns = t1 - t0;
    const direct_count = countEvents(db_direct);

    // ── Path B: ring append (hot path) + one batched drain ──
    const db_ring = try openFresh("/tmp/sps_fh_ring.db", alloc);
    defer core.storage.sqlite.closeDb(db_ring);

    var ring = try firehose_buffer.Ring.init(alloc, N + 16);
    defer ring.deinit();

    const t2 = nowNs();
    i = 0;
    while (i < N) : (i += 1) {
        _ = ring.append("did:plc:benchsubject", "bafyreibenchcid", "{\"op\":\"c\"}", @intCast(i), "commit");
    }
    const t3 = nowNs();
    const drained = ring.drainTo(db_ring);
    const t4 = nowNs();

    const ring_hot_ns = t3 - t2; // hot-path cost (what a producer pays)
    const ring_total_ns = t4 - t2; // incl. the background drain
    const ring_count = countEvents(db_ring);

    // ── Report ──
    const direct_rps = ratePerSec(N, direct_ns);
    const ring_hot_rps = ratePerSec(N, ring_hot_ns);
    const ring_total_rps = ratePerSec(N, ring_total_ns);

    std.debug.print("firehose-bench: N={d}\n", .{N});
    std.debug.print("  direct insert : {d:>10.0} rows/s  ({d} rows, {d:.1} ms)\n", .{ direct_rps, direct_count, msOf(direct_ns) });
    std.debug.print("  ring hot-path : {d:>10.0} rows/s  (in-memory append only)\n", .{ring_hot_rps});
    std.debug.print("  ring+drain    : {d:>10.0} rows/s  ({d} rows, {d:.1} ms incl. batch flush)\n", .{ ring_total_rps, ring_count, msOf(ring_total_ns) });
    std.debug.print("  hot-path speedup vs direct : {d:.1}x\n", .{ring_hot_rps / direct_rps});
    std.debug.print("  end-to-end speedup vs direct: {d:.1}x\n", .{ring_total_rps / direct_rps});

    // Correctness: both paths must land every row.
    if (direct_count != @as(i64, @intCast(N))) return error.DirectRowCountMismatch;
    if (ring_count != @as(i64, @intCast(N))) return error.RingRowCountMismatch;
    if (drained != N) return error.DrainCountMismatch;

    // The batched path must not be slower end-to-end; the hot path should
    // be dramatically faster (no per-event fsync/commit). Fail on
    // regression so the perf claim stays honest.
    if (ring_total_ns > direct_ns) return error.BatchedPathSlower;
    if (ring_hot_ns >= direct_ns) return error.HotPathNotFaster;
}

fn ratePerSec(rows: u64, ns: u64) f64 {
    if (ns == 0) return 0;
    return @as(f64, @floatFromInt(rows)) * @as(f64, std.time.ns_per_s) / @as(f64, @floatFromInt(ns));
}

fn msOf(ns: u64) f64 {
    return @as(f64, @floatFromInt(ns)) / @as(f64, std.time.ns_per_ms);
}
