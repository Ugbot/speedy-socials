//! Federation E2E simulation: real `outbox_worker` against the vendored
//! TigerBeetle `PacketSimulator` + `TimeSim`.
//!
//! Boot model:
//!   * In-process `:memory:` SQLite, AP plugin schema applied.
//!   * `TimeSim` (linear drift coefficient B = 5 — ~5e-9 fractional drift)
//!     projected through `TimeSimClock` to drive the outbox worker's clock.
//!   * `outbox_worker.setDeliverHook` is wired to a closure that:
//!       1. parses the outbox payload to recover the activity id
//!       2. submits a `Packet` from NODE_LOCAL → NODE_PEER to `PacketSimulator`
//!       3. returns `transient_failure` so the worker leaves the row
//!          `pending` with attempts++. The simulator decides whether the
//!          packet actually arrives at the peer. Confirmed deliveries are
//!          stamped back into `ap_federation_outbox` as `state='done'`
//!          out-of-band — modelling a real federation receiver that acks
//!          asynchronously rather than synchronously.
//!
//! Network configuration:
//!   * exp latency mean 50ms, floor 5ms
//!   * 5% packet loss
//!   * scripted partition t=10s..15s, both directions
//!   * max in-flight per path: 64
//!
//! Scenario:
//!   * Enqueue 100 `Create(Note)` deliveries from `local` to `peer_mastodon`.
//!   * Tick `TimeSim` + `PacketSimulator` in lockstep for 120 simulated
//!     seconds, calling `outbox_worker.tickOnce` every simulated 100ms.
//!
//! Assertions:
//!   * Every Activity ID appears in the peer recv log at least once.
//!   * No dead-letter entries (all delivered within max_delivery_attempts=8).
//!   * `federation_outbox` ends in state='done' for all 100 rows.
//!   * Wall-time of the simulation under 5 real seconds.

const std = @import("std");
const core = @import("core");
const ap = @import("protocol_activitypub");
const c = @import("sqlite").c;

const sim = core.sim;

const Activity = struct {
    id: u32,
    src: sim.NodeId,
    dst: sim.NodeId,
    body: [16]u8,

    pub fn from(p: Activity) sim.NodeId {
        return p.src;
    }
    pub fn to(p: Activity) sim.NodeId {
        return p.dst;
    }
    pub fn payload(p: Activity) []const u8 {
        return std.mem.asBytes(&p.id);
    }
    pub fn copy(p: Activity) Activity {
        return p;
    }
};

const NODE_LOCAL: sim.NodeId = 0;
const NODE_PEER: sim.NodeId = 1;
const ACTIVITY_COUNT: u32 = 100;
const PEER_INBOX_PREFIX = "https://peer-mastodon.example/users/u";

// ── Shared scenario state ─────────────────────────────────────────────
// The deliver hook is a `*const fn` with no closure capture; the
// scenario keeps mutable state in a module-level pointer the hook
// reaches through `current_state`.

const State = struct {
    net: *sim.PacketSimulator(Activity),
    submitted_attempts: u64 = 0,
};

var current_state: ?*State = null;

fn parsePayloadActivityId(payload: []const u8) ?u32 {
    // Payload format: "act:<id>". Small enough to fit in the AP outbox
    // inline payload buffer.
    const prefix = "act:";
    if (payload.len <= prefix.len) return null;
    if (!std.mem.startsWith(u8, payload, prefix)) return null;
    return std.fmt.parseInt(u32, payload[prefix.len..], 10) catch null;
}

fn deliverHook(
    _: []const u8,
    payload: []const u8,
    _: []const u8,
) ap.outbox_worker.DeliveryResult {
    const st = current_state orelse return .transient_failure;
    const aid = parsePayloadActivityId(payload) orelse return .permanent_failure;
    const a: Activity = .{
        .id = aid,
        .src = NODE_LOCAL,
        .dst = NODE_PEER,
        .body = std.mem.zeroes([16]u8),
    };
    // Submitting may fail if the path is full and we can't evict
    // (PacketSimulator does evict-oldest on overflow, so this is rare).
    st.net.submit(a) catch return .transient_failure;
    st.submitted_attempts += 1;
    // Returning `transient_failure` keeps the row `pending`. The receiver
    // ACK loop below stamps `state='done'` for activities that actually
    // arrive at the peer, modelling async federation receipt.
    return .transient_failure;
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    try run(gpa.allocator());
    std.debug.print("federate_with_mastodon: scenario completed OK\n", .{});
}

pub fn run(allocator: std.mem.Allocator) !void {
    const wall_real_t0 = realNs();

    // ── 1. boot in-process speedy-socials (SQLite + AP schema) ────────
    const db = try core.storage.sqlite.openWriter(":memory:");
    defer core.storage.sqlite.closeDb(db);
    try applyApMigrationsHere(allocator, db);

    // ── 2. TimeSim w/ small drift; project through TimeSimClock ───────
    var time_sim = sim.TimeSim.init(.{
        .resolution = std.time.ns_per_ms,
        // Linear drift coefficient B: scaled by 1e-9, so B=5 → 5 ppb.
        .offset_type = .linear,
        .offset_coefficient_A = 0,
        .offset_coefficient_B = 5,
        .epoch = @as(i64, 1_700_000_000) * std.time.ns_per_s,
    });
    var ts_clock = core.clock.TimeSimClock.init(&time_sim);

    // ── 3. PacketSimulator ────────────────────────────────────────────
    var net = try sim.PacketSimulator(Activity).init(allocator, .{
        .node_count = 2,
        .seed = 0xFED_C0DE,
        .one_way_delay_mean_ns = 50 * std.time.ns_per_ms,
        .one_way_delay_min_ns = 5 * std.time.ns_per_ms,
        .packet_loss_probability = 0.05,
        .path_capacity = 64,
    });
    defer net.deinit();

    try net.add_partition(.{
        .from = NODE_LOCAL,
        .to = NODE_PEER,
        .starts_at_ns = 10 * std.time.ns_per_s,
        .ends_at_ns = 15 * std.time.ns_per_s,
    });
    try net.add_partition(.{
        .from = NODE_PEER,
        .to = NODE_LOCAL,
        .starts_at_ns = 10 * std.time.ns_per_s,
        .ends_at_ns = 15 * std.time.ns_per_s,
    });

    // ── 4. shared state for the deliver hook ──────────────────────────
    var state: State = .{ .net = &net };
    current_state = &state;
    defer current_state = null;

    ap.outbox_worker.setDeliverHook(deliverHook);
    defer ap.outbox_worker.setDeliverHook(null);

    // Peer recv log: activity id → delivery count (idempotency expected).
    var peer_recv = std.AutoHashMap(u32, u32).init(allocator);
    defer peer_recv.deinit();

    // ── 5. enqueue 100 Create(Note) deliveries ────────────────────────
    {
        var i: u32 = 0;
        while (i < ACTIVITY_COUNT) : (i += 1) {
            var payload_buf: [32]u8 = undefined;
            const payload = std.fmt.bufPrint(&payload_buf, "act:{d}", .{i}) catch unreachable;
            var inbox_buf: [128]u8 = undefined;
            const inbox = std.fmt.bufPrint(&inbox_buf, "{s}{d}/inbox", .{ PEER_INBOX_PREFIX, i }) catch unreachable;
            const recipients = [_]ap.delivery.Recipient{.{ .inbox = inbox }};
            _ = try ap.delivery.enqueueDeliveries(db, ts_clock.clock(), &recipients, payload, "kid-local");
        }
    }

    // ── 6. drive the real outbox_worker in lockstep with TimeSim/net ──
    var rng = core.rng.Rng.init(0xFED);
    var worker: ap.outbox_worker.Worker = .{};
    worker.db = db;
    worker.clock = ts_clock.clock();
    worker.rng = &rng;

    const tick_ns: u64 = 100 * std.time.ns_per_ms;
    const total_sim_ns: u64 = 120 * std.time.ns_per_s;
    var elapsed_ns: u64 = 0;

    while (elapsed_ns < total_sim_ns) : (elapsed_ns += tick_ns) {
        // a) advance TimeSim by 100ms in 1ms native ticks.
        var t: u32 = 0;
        while (t < tick_ns / std.time.ns_per_ms) : (t += 1) time_sim.tick();

        // b) run worker once. Due rows get their hook fired and submitted to net.
        _ = worker.tickOnce() catch {};

        // c) advance the network and drain delivered packets to peer recv.
        _ = try net.advance(tick_ns);
        for (net.delivered.items) |pending| {
            const gop = try peer_recv.getOrPut(pending.packet.id);
            if (!gop.found_existing) gop.value_ptr.* = 0;
            gop.value_ptr.* += 1;

            // ACK: stamp the outbox row(s) for this activity id as done.
            try markActivityDone(allocator, db, pending.packet.id);
        }
        net.delivered.clearRetainingCapacity();

        // Early-exit: every activity has been ACKed.
        if (peer_recv.count() == ACTIVITY_COUNT) {
            // Flush any in-flight remaining ticks and break.
            _ = try net.advance(1 * std.time.ns_per_s);
            for (net.delivered.items) |pending| {
                const gop = try peer_recv.getOrPut(pending.packet.id);
                if (!gop.found_existing) gop.value_ptr.* = 0;
                gop.value_ptr.* += 1;
            }
            net.delivered.clearRetainingCapacity();
            break;
        }
    }

    // ── 7. assertions ─────────────────────────────────────────────────
    // (a) wall-time bound.
    const wall_real_t1 = realNs();
    const wall_real_ns: u64 = wall_real_t1 - wall_real_t0;
    if (wall_real_ns > 5 * std.time.ns_per_s) {
        std.debug.print(
            "FAIL: simulation wall-time {d:.2}s exceeds 5s budget\n",
            .{@as(f64, @floatFromInt(wall_real_ns)) / 1e9},
        );
        return error.SimulationTooSlow;
    }

    // (b) every activity ID appears in peer recv log.
    var missing: u32 = 0;
    var aid: u32 = 0;
    while (aid < ACTIVITY_COUNT) : (aid += 1) {
        if (peer_recv.get(aid) == null) missing += 1;
    }
    if (missing != 0) {
        std.debug.print(
            "FAIL: {d}/{d} activities never reached peer recv log\n",
            .{ missing, ACTIVITY_COUNT },
        );
        return error.MissingDeliveries;
    }

    // (c) no dead-letter rows.
    {
        var stmt: ?*c.sqlite3_stmt = null;
        _ = c.sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM ap_federation_dead_letter", -1, &stmt, null);
        defer _ = c.sqlite3_finalize(stmt);
        if (c.sqlite3_step(stmt) != c.SQLITE_ROW) return error.AssertionFailed;
        const dead_count = c.sqlite3_column_int64(stmt, 0);
        if (dead_count != 0) {
            std.debug.print("FAIL: {d} entries in ap_federation_dead_letter\n", .{dead_count});
            return error.DeadLetter;
        }
    }

    // (d) all 100 outbox rows in state='done'.
    {
        var stmt: ?*c.sqlite3_stmt = null;
        _ = c.sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM ap_federation_outbox WHERE state='done'", -1, &stmt, null);
        defer _ = c.sqlite3_finalize(stmt);
        if (c.sqlite3_step(stmt) != c.SQLITE_ROW) return error.AssertionFailed;
        const done_count = c.sqlite3_column_int64(stmt, 0);
        if (done_count != @as(i64, ACTIVITY_COUNT)) {
            var diag: ?*c.sqlite3_stmt = null;
            _ = c.sqlite3_prepare_v2(db, "SELECT state, COUNT(*) FROM ap_federation_outbox GROUP BY state", -1, &diag, null);
            defer _ = c.sqlite3_finalize(diag);
            while (c.sqlite3_step(diag) == c.SQLITE_ROW) {
                const sp = c.sqlite3_column_text(diag, 0);
                const sl: usize = @intCast(c.sqlite3_column_bytes(diag, 0));
                const cnt = c.sqlite3_column_int64(diag, 1);
                std.debug.print("  state={s} count={d}\n", .{ sp[0..sl], cnt });
            }
            std.debug.print("FAIL: {d}/{d} outbox rows in state='done'\n", .{ done_count, ACTIVITY_COUNT });
            return error.NotAllDone;
        }
    }

    std.debug.print(
        "ok: {d} activities delivered  wall={d:.2}ms  attempts={d}  dropped_loss={d} dropped_partition={d} dropped_capacity={d} duplicates={d}\n",
        .{
            ACTIVITY_COUNT,
            @as(f64, @floatFromInt(wall_real_ns)) / 1e6,
            state.submitted_attempts,
            net.dropped_loss,
            net.dropped_partition,
            net.dropped_capacity,
            countDuplicates(&peer_recv),
        },
    );
}

fn applyApMigrationsHere(allocator: std.mem.Allocator, db: *c.sqlite3) !void {
    var errmsg: [*c]u8 = null;
    _ = c.sqlite3_exec(
        db,
        "CREATE TABLE IF NOT EXISTS migrations (id INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL) STRICT;",
        null,
        null,
        &errmsg,
    );
    if (errmsg != null) c.sqlite3_free(errmsg);
    for (ap.schema.all_migrations) |m| {
        const sql_z = try allocator.dupeZ(u8, m.up);
        defer allocator.free(sql_z);
        var em: [*c]u8 = null;
        const rc = c.sqlite3_exec(db, sql_z.ptr, null, null, &em);
        if (em != null) c.sqlite3_free(em);
        if (rc != c.SQLITE_OK) return error.MigrationFailed;
    }
}

fn markActivityDone(allocator: std.mem.Allocator, db: *c.sqlite3, aid: u32) !void {
    var payload_buf: [32]u8 = undefined;
    const payload = std.fmt.bufPrint(&payload_buf, "act:{d}", .{aid}) catch unreachable;
    const payload_z = try allocator.dupeZ(u8, payload);
    defer allocator.free(payload_z);

    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "UPDATE ap_federation_outbox SET state='done' WHERE payload = ? AND state = 'pending'";
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return;
    }
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_blob(stmt, 1, payload_z.ptr, @intCast(payload.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_step(stmt);
}

fn realNs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(std.c.CLOCK.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

fn countDuplicates(map: *const std.AutoHashMap(u32, u32)) u32 {
    var dups: u32 = 0;
    var it = map.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.* > 1) dups += (entry.value_ptr.* - 1);
    }
    return dups;
}

test "federation E2E: real outbox_worker drives SimIo network" {
    try run(std.testing.allocator);
}

test "parsePayloadActivityId round-trips valid and rejects invalid" {
    try std.testing.expectEqual(@as(?u32, 42), parsePayloadActivityId("act:42"));
    try std.testing.expectEqual(@as(?u32, 0), parsePayloadActivityId("act:0"));
    try std.testing.expectEqual(@as(?u32, null), parsePayloadActivityId(""));
    try std.testing.expectEqual(@as(?u32, null), parsePayloadActivityId("act:"));
    try std.testing.expectEqual(@as(?u32, null), parsePayloadActivityId("no:prefix"));
    try std.testing.expectEqual(@as(?u32, null), parsePayloadActivityId("act:abc"));
}

test "applyApMigrationsHere creates ap_federation_outbox + ap_federation_dead_letter" {
    const db = try core.storage.sqlite.openWriter(":memory:");
    defer core.storage.sqlite.closeDb(db);
    try applyApMigrationsHere(std.testing.allocator, db);

    var stmt: ?*c.sqlite3_stmt = null;
    _ = c.sqlite3_prepare_v2(
        db,
        "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name IN ('ap_federation_outbox','ap_federation_dead_letter')",
        -1,
        &stmt,
        null,
    );
    defer _ = c.sqlite3_finalize(stmt);
    try std.testing.expect(c.sqlite3_step(stmt) == c.SQLITE_ROW);
    try std.testing.expectEqual(@as(i64, 2), c.sqlite3_column_int64(stmt, 0));
}

test "markActivityDone only updates matching pending rows" {
    const db = try core.storage.sqlite.openWriter(":memory:");
    defer core.storage.sqlite.closeDb(db);
    try applyApMigrationsHere(std.testing.allocator, db);

    var sc = core.clock.SimClock.init(1_700_000_000);
    const recipients = [_]ap.delivery.Recipient{.{ .inbox = "https://peer.example/inbox" }};
    _ = try ap.delivery.enqueueDeliveries(db, sc.clock(), &recipients, "act:7", "kid");
    _ = try ap.delivery.enqueueDeliveries(db, sc.clock(), &recipients, "act:8", "kid");

    try markActivityDone(std.testing.allocator, db, 7);

    var stmt: ?*c.sqlite3_stmt = null;
    _ = c.sqlite3_prepare_v2(
        db,
        "SELECT COUNT(*) FROM ap_federation_outbox WHERE state='done'",
        -1,
        &stmt,
        null,
    );
    defer _ = c.sqlite3_finalize(stmt);
    try std.testing.expect(c.sqlite3_step(stmt) == c.SQLITE_ROW);
    try std.testing.expectEqual(@as(i64, 1), c.sqlite3_column_int64(stmt, 0));
}
