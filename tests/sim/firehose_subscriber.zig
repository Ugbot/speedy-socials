//! AT Protocol firehose simulation under WS partition.
//!
//! Exercises the two-tier delivery contract from
//! `src/protocols/atproto/firehose.zig`:
//!
//!   * Persistent table (`atp_firehose_events`) is append-only and NEVER
//!     drops. It is the source of truth a re-connecting subscriber
//!     replays from after a network gap.
//!
//!   * Live ring (in-memory, bounded) carries events to currently
//!     connected subscribers. Under burst or partition the ring drops the
//!     oldest pending entries — subscribers detect this as a cursor gap
//!     and recover from the persistent table.
//!
//! Scenario:
//!   * Producer appends 500 firehose events at deterministic simulated
//!     timestamps over 60 simulated seconds.
//!   * Subscriber maintains a cursor and pulls via `firehose.readSince`.
//!   * A scripted WS partition runs t=20s..30s. During the partition the
//!     subscriber's "live" reads return no new rows (we model this by
//!     skipping its poll while partitioned); after the partition the
//!     subscriber catches up via `readSince(its_cursor, …)` from the
//!     persistent table.
//!
//! Assertions:
//!   * Persistent count after the run == events_appended (no loss).
//!   * Subscriber's eventual count == events_appended (full catch-up).
//!   * Cursor is strictly monotonic — the subscriber never observes a
//!     `seq` it already saw.
//!   * The recovery includes events emitted during the partition window
//!     (we record a non-zero count of "during-partition catch-up" events).

const std = @import("std");
const core = @import("core");
const atp = @import("protocol_atproto");
const c = @import("sqlite").c;

const sim = core.sim;

const EVENT_COUNT: u32 = 500;
const PARTITION_START_NS: u64 = 20 * std.time.ns_per_s;
const PARTITION_END_NS: u64 = 30 * std.time.ns_per_s;
const TOTAL_SIM_NS: u64 = 60 * std.time.ns_per_s;

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    try run(gpa.allocator());
    std.debug.print("firehose_subscriber: scenario completed OK\n", .{});
}

pub fn run(allocator: std.mem.Allocator) !void {
    const wall_real_t0 = realNs();

    // ── 1. boot in-process speedy-socials (SQLite + ATP schema) ───────
    const db = try core.storage.sqlite.openWriter(":memory:");
    defer core.storage.sqlite.closeDb(db);
    try applyAtpMigrationsHere(allocator, db);

    // ── 2. TimeSim drives event timestamps + partition windows ────────
    var time_sim = sim.TimeSim.init(.{
        .resolution = std.time.ns_per_ms,
        .offset_type = .linear,
        .offset_coefficient_A = 0,
        .offset_coefficient_B = 0,
        .epoch = @as(i64, 1_700_000_000) * std.time.ns_per_s,
    });

    // ── 3. PRNG: shapes event arrival across the run ──────────────────
    var prng = core.prng.from_seed(0xF1_BE_F0_15);

    // ── 4. subscriber state ───────────────────────────────────────────
    // Subscriber cursor: starts at 0 (seq is 1-based via AUTOINCREMENT).
    var cursor: i64 = 0;
    var subscriber_events: u32 = 0;
    var max_seq_observed: i64 = 0;
    var recovery_events_after_partition: u32 = 0;
    var in_partition = false;

    // ── 5. main loop: tick 100ms at a time ────────────────────────────
    const tick_ns: u64 = 100 * std.time.ns_per_ms;
    var elapsed_ns: u64 = 0;
    var events_appended: u32 = 0;

    while (elapsed_ns < TOTAL_SIM_NS) : (elapsed_ns += tick_ns) {
        // Advance TimeSim in 1ms ticks.
        var t: u32 = 0;
        while (t < tick_ns / std.time.ns_per_ms) : (t += 1) time_sim.tick();

        // ── producer: maintain a steady arrival rate so the run ends
        //   with EVENT_COUNT events even though some ticks may skip
        //   (during partition recovery the subscriber is busy catching
        //   up but the producer keeps writing).
        const target_events: u32 = @intFromFloat(@as(f64, @floatFromInt(elapsed_ns + tick_ns)) /
            @as(f64, @floatFromInt(TOTAL_SIM_NS)) * @as(f64, @floatFromInt(EVENT_COUNT)));
        while (events_appended < target_events) : (events_appended += 1) {
            // Slight per-event timestamp jitter (±25ms) so the recv set
            // covers a realistic distribution. Use TB Ratio + chance.
            const jitter_ns: i64 = if (prng.chance(core.prng.ratio(1, 2)))
                @intCast(prng.int_inclusive(u64, 25 * std.time.ns_per_ms))
            else
                -@as(i64, @intCast(prng.int_inclusive(u64, 25 * std.time.ns_per_ms)));
            const ts = time_sim.realtime() + jitter_ns;
            var did_buf: [32]u8 = undefined;
            const did = std.fmt.bufPrint(&did_buf, "did:plc:e{d}", .{events_appended}) catch unreachable;
            var cid_buf: [32]u8 = undefined;
            const cid = std.fmt.bufPrint(&cid_buf, "bafyev{d}", .{events_appended}) catch unreachable;
            var body_buf: [32]u8 = undefined;
            const body = std.fmt.bufPrint(&body_buf, "body-{d}", .{events_appended}) catch unreachable;
            _ = try atp.firehose.append(db, did, cid, body, @divTrunc(ts, std.time.ns_per_s));
        }

        // ── subscriber: partition gates the *live* pull.
        const now_sim_ns = time_sim.monotonic();
        const previously_in_partition = in_partition;
        in_partition = now_sim_ns >= PARTITION_START_NS and now_sim_ns < PARTITION_END_NS;
        const just_recovered = previously_in_partition and !in_partition;

        if (in_partition) {
            // Subscriber's live stream is dead. Skip its poll.
            continue;
        }

        // Live (or recovery) pull: read from cursor up to a bounded batch.
        var out: [128]atp.firehose.Event = undefined;
        const n = try atp.firehose.readSince(db, cursor, &out);
        if (n > 0) {
            // Monotonicity check.
            var i: u32 = 0;
            while (i < n) : (i += 1) {
                const seq = out[i].seq;
                if (seq <= max_seq_observed) {
                    std.debug.print(
                        "FAIL: non-monotonic seq {d} (max_seen {d})\n",
                        .{ seq, max_seq_observed },
                    );
                    return error.NonMonotonic;
                }
                max_seq_observed = seq;
            }
            subscriber_events += n;
            cursor = out[n - 1].seq;
            if (just_recovered) recovery_events_after_partition += n;
        }
    }

    // Drain any tail events the subscriber missed after the last tick.
    while (true) {
        var out: [128]atp.firehose.Event = undefined;
        const n = try atp.firehose.readSince(db, cursor, &out);
        if (n == 0) break;
        subscriber_events += n;
        cursor = out[n - 1].seq;
    }

    // ── assertions ────────────────────────────────────────────────────
    const wall_real_ns = realNs() - wall_real_t0;
    if (wall_real_ns > 5 * std.time.ns_per_s) {
        std.debug.print(
            "FAIL: firehose wall-time {d:.2}s > 5s budget\n",
            .{@as(f64, @floatFromInt(wall_real_ns)) / 1e9},
        );
        return error.SimulationTooSlow;
    }

    if (events_appended != EVENT_COUNT) {
        std.debug.print("FAIL: events_appended={d} expected={d}\n", .{ events_appended, EVENT_COUNT });
        return error.AppendCountMismatch;
    }

    // Persistent table holds them all (NEVER drops).
    var stmt: ?*c.sqlite3_stmt = null;
    _ = c.sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM atp_firehose_events", -1, &stmt, null);
    defer _ = c.sqlite3_finalize(stmt);
    if (c.sqlite3_step(stmt) != c.SQLITE_ROW) return error.AssertionFailed;
    const persistent_count = c.sqlite3_column_int64(stmt, 0);
    if (persistent_count != @as(i64, EVENT_COUNT)) {
        std.debug.print("FAIL: persistent_count={d} expected={d}\n", .{ persistent_count, EVENT_COUNT });
        return error.PersistentLost;
    }

    if (subscriber_events != EVENT_COUNT) {
        std.debug.print(
            "FAIL: subscriber saw {d}/{d} events after recovery\n",
            .{ subscriber_events, EVENT_COUNT },
        );
        return error.SubscriberIncomplete;
    }

    if (recovery_events_after_partition == 0) {
        std.debug.print("FAIL: no events caught up after partition window — partition didn't actually delay any traffic\n", .{});
        return error.PartitionInactive;
    }

    std.debug.print(
        "ok: {d} events  persistent={d}  subscriber={d}  recovered_after_partition={d}  wall={d:.2}ms\n",
        .{
            EVENT_COUNT,
            persistent_count,
            subscriber_events,
            recovery_events_after_partition,
            @as(f64, @floatFromInt(wall_real_ns)) / 1e6,
        },
    );
}

fn applyAtpMigrationsHere(allocator: std.mem.Allocator, db: *c.sqlite3) !void {
    var errmsg: [*c]u8 = null;
    _ = c.sqlite3_exec(
        db,
        "CREATE TABLE IF NOT EXISTS migrations (id INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL) STRICT;",
        null,
        null,
        &errmsg,
    );
    if (errmsg != null) c.sqlite3_free(errmsg);
    for (atp.schema.all_migrations) |m| {
        const sql_z = try allocator.dupeZ(u8, m.up);
        defer allocator.free(sql_z);
        var em: [*c]u8 = null;
        const rc = c.sqlite3_exec(db, sql_z.ptr, null, null, &em);
        if (em != null) c.sqlite3_free(em);
        if (rc != c.SQLITE_OK) return error.MigrationFailed;
    }
}

fn realNs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(std.c.CLOCK.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

test "firehose subscriber survives WS partition and recovers" {
    try run(std.testing.allocator);
}

test "applyAtpMigrationsHere creates atp_firehose_events + cursor" {
    const db = try core.storage.sqlite.openWriter(":memory:");
    defer core.storage.sqlite.closeDb(db);
    try applyAtpMigrationsHere(std.testing.allocator, db);

    var stmt: ?*c.sqlite3_stmt = null;
    _ = c.sqlite3_prepare_v2(
        db,
        "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name IN ('atp_firehose_events','atp_firehose_cursor')",
        -1,
        &stmt,
        null,
    );
    defer _ = c.sqlite3_finalize(stmt);
    try std.testing.expect(c.sqlite3_step(stmt) == c.SQLITE_ROW);
    try std.testing.expectEqual(@as(i64, 2), c.sqlite3_column_int64(stmt, 0));
}

test "firehose append + readSince round-trip is deterministic" {
    const db = try core.storage.sqlite.openWriter(":memory:");
    defer core.storage.sqlite.closeDb(db);
    try applyAtpMigrationsHere(std.testing.allocator, db);

    const s1 = try atp.firehose.append(db, "did:plc:a", "bafy1", "body1", 100);
    const s2 = try atp.firehose.append(db, "did:plc:b", "bafy2", "body2", 101);
    try std.testing.expect(s2 > s1);
    var out: [4]atp.firehose.Event = undefined;
    const n = try atp.firehose.readSince(db, 0, &out);
    try std.testing.expectEqual(@as(u32, 2), n);
    try std.testing.expectEqualStrings("did:plc:a", out[0].did());
    try std.testing.expectEqualStrings("did:plc:b", out[1].did());
}

test "readSince returns zero when cursor is past latest" {
    const db = try core.storage.sqlite.openWriter(":memory:");
    defer core.storage.sqlite.closeDb(db);
    try applyAtpMigrationsHere(std.testing.allocator, db);

    _ = try atp.firehose.append(db, "did:plc:only", "bafy", "body", 1);
    var out: [4]atp.firehose.Event = undefined;
    const n = try atp.firehose.readSince(db, 100, &out);
    try std.testing.expectEqual(@as(u32, 0), n);
}
