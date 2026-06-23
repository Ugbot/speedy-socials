//! D3 firehose throughput benchmark (independent perf verification).
//!
//! Compares the two ways an event lands in `atp_firehose_events`:
//!
//!   * **direct**: one autocommitted single-row INSERT + cursor UPDATE per
//!     event, each in its own WAL transaction — what the firehose hot path
//!     did *before* D3.
//!   * **L0 ring**: `firehose.append` lands the event in the in-memory L0
//!     ring (`firehose_store`), assigning its seq with no SQLite on the hot
//!     path; durable L1 writes are amortised across a batched flush.
//!
//! This is the PRODUCTION path (`atproto.firehose.append`), not the
//! separate `firehose_buffer.Ring` the prior bench used — so the numbers
//! reflect what a real commit pays. We run on a real WAL *file* DB so the
//! direct path pays the realistic per-transaction fsync/checkpoint cost
//! the ring is designed to remove.
//!
//! Reports ns/op (mean throughput) plus the common-path (p0..p99) append
//! latency, which isolates the pure in-memory ring write from the handful
//! of periodic batch-flush spikes — that common-path number is what the
//! ~450x claim refers to. The harness asserts a floor so a regression
//! fails CI, but PRINTS the measured ratio for the methodology doc.

const std = @import("std");
const core = @import("core");
const atproto = @import("protocol_atproto");
const c = @import("sqlite").c;

const firehose = atproto.firehose;
const schema = atproto.schema;

const N: u64 = 50_000;

fn nowNs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(std.c.CLOCK.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

fn unlinkFiles(path: []const u8) void {
    const suffixes = [_][]const u8{ "", "-wal", "-shm" };
    for (suffixes) |suf| {
        var buf: [256]u8 = undefined;
        const p = std.fmt.bufPrintZ(&buf, "{s}{s}", .{ path, suf }) catch continue;
        _ = std.c.unlink(p.ptr);
    }
}

fn openFresh(path: [:0]const u8, alloc: std.mem.Allocator) !*c.sqlite3 {
    unlinkFiles(path);
    const db = try core.storage.sqlite.openWriter(path);
    firehose.forgetStore(db); // clear any stale L0 store on a recycled handle
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

fn bumpCursor(db: *c.sqlite3, seq: i64) void {
    const upd = "UPDATE atp_firehose_cursor SET seq = ? WHERE id = 1";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, upd, -1, &stmt, null) == c.SQLITE_OK) {
        defer _ = c.sqlite3_finalize(stmt);
        _ = c.sqlite3_bind_int64(stmt, 1, seq);
        _ = c.sqlite3_step(stmt.?);
    }
}

fn meanOf(xs: []const u64) f64 {
    if (xs.len == 0) return 0;
    var sum: u128 = 0;
    for (xs) |x| sum += x;
    return @as(f64, @floatFromInt(sum)) / @as(f64, @floatFromInt(xs.len));
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const body = "x" ** 96; // representative small commit-envelope body

    const old_lat = try alloc.alloc(u64, N);
    defer alloc.free(old_lat);
    const new_lat = try alloc.alloc(u64, N);
    defer alloc.free(new_lat);

    // ── Path A: direct single-row INSERT + cursor UPDATE per event ──
    const db_direct = try openFresh("/tmp/sps_fh_direct.db", alloc);
    defer core.storage.sqlite.closeDb(db_direct);
    defer firehose.forgetStore(db_direct);

    const t0 = nowNs();
    var i: u64 = 0;
    while (i < N) : (i += 1) {
        const ta = nowNs();
        const sql = "INSERT INTO atp_firehose_events (did, commit_cid, body, ts, event_kind) VALUES (?,?,?,?,?)";
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db_direct, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
        _ = c.sqlite3_bind_text(stmt, 1, "did:plc:bench", 13, c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_text(stmt, 2, "cid", 3, c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_blob(stmt, 3, body.ptr, body.len, c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_int64(stmt, 4, @intCast(i));
        _ = c.sqlite3_bind_text(stmt, 5, "commit", 6, c.sqliteTransientAsDestructor());
        if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return error.StepFailed;
        _ = c.sqlite3_finalize(stmt);
        bumpCursor(db_direct, c.sqlite3_last_insert_rowid(db_direct));
        old_lat[i] = nowNs() - ta;
    }
    const direct_ns = nowNs() - t0;
    const direct_count = countEvents(db_direct);

    // ── Path B: production L0 ring path (firehose.append) ──
    const db_ring = try openFresh("/tmp/sps_fh_ring.db", alloc);
    defer core.storage.sqlite.closeDb(db_ring);
    defer firehose.forgetStore(db_ring);

    const t2 = nowNs();
    i = 0;
    while (i < N) : (i += 1) {
        const ta = nowNs();
        _ = firehose.append(db_ring, "did:plc:bench", "cid", body, @intCast(i)) catch return error.AppendFailed;
        new_lat[i] = nowNs() - ta;
    }
    const ring_hot_ns = nowNs() - t2;
    try firehose.flush(db_ring);
    const ring_total_ns = nowNs() - t2;
    const ring_count = countEvents(db_ring);

    // ── Report ──
    const direct_per = @as(f64, @floatFromInt(direct_ns)) / @as(f64, N);
    const ring_hot_per = @as(f64, @floatFromInt(ring_hot_ns)) / @as(f64, N);
    const ring_total_per = @as(f64, @floatFromInt(ring_total_ns)) / @as(f64, N);

    std.mem.sort(u64, old_lat, {}, std.sort.asc(u64));
    std.mem.sort(u64, new_lat, {}, std.sort.asc(u64));
    const lo_n = N - N / 100; // bottom 99% (common path)
    const old_common = meanOf(old_lat[0..lo_n]);
    const new_common = meanOf(new_lat[0..lo_n]);
    const common_speedup = old_common / @max(new_common, 1.0);

    std.debug.print("firehose-bench: N={d} (WAL file DB)\n", .{N});
    std.debug.print("  direct insert  : {d:>8.1} ns/ev  ({d} rows)\n", .{ direct_per, direct_count });
    std.debug.print("  ring append    : {d:>8.1} ns/ev  (hot path, no flush)\n", .{ring_hot_per});
    std.debug.print("  ring+flush     : {d:>8.1} ns/ev  ({d} rows, incl. batched L1 flush)\n", .{ ring_total_per, ring_count });
    std.debug.print("  mean throughput speedup (ring hot vs direct): {d:.1}x\n", .{direct_per / ring_hot_per});
    std.debug.print("  common-path (p0..p99) latency: direct={d:.1} ns  ring={d:.1} ns  speedup={d:.1}x\n", .{ old_common, new_common, common_speedup });

    // Correctness: both paths land every row durably.
    if (direct_count != @as(i64, @intCast(N))) return error.DirectRowCountMismatch;
    if (ring_count != @as(i64, @intCast(N))) return error.RingRowCountMismatch;

    // The L0 ring removes SQLite from the hot path: the common append must
    // be dramatically faster than the per-event synchronous INSERT+UPDATE.
    // Floor at 10x so a regression fails CI; the measured ratio is printed
    // above for the methodology doc.
    if (common_speedup < 10.0) return error.HotPathNotFastEnough;
}
