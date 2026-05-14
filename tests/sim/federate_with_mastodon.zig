//! Federation simulation scenario: speedy-socials ↔ a simulated Mastodon peer.
//!
//! Scope: proof-of-concept. We do not yet boot a full in-process server with
//! SimIo + the real outbox_worker — that requires plumbing SimIo through
//! `core.storage`, which Tranche 4 deliberately scopes out (the outbox_worker
//! and storage modules are owned by other tranches and are not edited here).
//!
//! What we *do* exercise end-to-end:
//!   * `TimeSim` drives a deterministic clock for the run.
//!   * `PacketSimulator` carries 20 AP-Create(Note) deliveries over a flaky
//!     link with realistic mean latency (50ms exponential), 5% packet loss,
//!     and a scripted partition at t=10s lasting 5s.
//!   * Local mirrors the outbox worker's policy: at-least-once delivery with
//!     bounded retries (we treat `max_delivery_attempts=8` to match
//!     `outbox_worker.zig`).
//!   * Peer (simulated Mastodon) records every Activity it receives.
//!
//! Assertions:
//!   * Every Activity ID is delivered at least once.
//!   * No activity exceeds max_delivery_attempts (no dead-letter).
//!   * All 20 activities reach terminal state=`done`.
//!
//! When the storage / outbox plumbing matures (post-Tranche 4), this file
//! should be promoted to drive the *real* outbox_worker — keep the scenario
//! data shape stable so that swap-in is mechanical.

const std = @import("std");
const core = @import("core");
const sim = core.sim;
const fuzz = core.testing.fuzz;

const NodeId = sim.NodeId;
const Activity = struct {
    id: u32,
    src: NodeId,
    dst: NodeId,
    // 16-byte body simulates an Object-IRI / dag-cbor blob.
    body: [16]u8,

    pub fn from(p: Activity) NodeId {
        return p.src;
    }
    pub fn to(p: Activity) NodeId {
        return p.dst;
    }
    pub fn payload(p: Activity) []const u8 {
        return std.mem.asBytes(&p.id);
    }
    pub fn copy(p: Activity) Activity {
        return p;
    }
};

const NODE_LOCAL: NodeId = 0;
const NODE_PEER: NodeId = 1;
const ACTIVITY_COUNT: u32 = 20;
const MAX_DELIVERY_ATTEMPTS: u32 = 8;

const OutboxRow = struct {
    activity_id: u32,
    attempts: u32 = 0,
    state: enum { pending, done, dead_letter } = .pending,
};

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    try run(allocator);
    std.debug.print("federate_with_mastodon: scenario completed OK\n", .{});
}

pub fn run(allocator: std.mem.Allocator) !void {
    // ── time ──────────────────────────────────────────────────────────
    // 1ms tick resolution, no drift — drift is exercised in the dedicated
    // TimeSim tests; this scenario isolates network behaviour.
    var time_sim = sim.TimeSim.init(.{
        .resolution = std.time.ns_per_ms,
        .offset_type = .linear,
        .offset_coefficient_A = 0,
        .offset_coefficient_B = 0,
        .epoch = @as(i64, 1_700_000_000) * std.time.ns_per_s,
    });

    // ── network ───────────────────────────────────────────────────────
    var net = try sim.PacketSimulator(Activity).init(allocator, .{
        .node_count = 2,
        .seed = 0xFED_C0DE,
        .one_way_delay_mean_ns = 50 * std.time.ns_per_ms,
        .one_way_delay_min_ns = 5 * std.time.ns_per_ms,
        .packet_loss_probability = 0.05,
        .path_capacity = 256,
    });
    defer net.deinit();

    // One injected partition at t=10s lasting 5s, both directions.
    const partition_start_ns: u64 = 10 * std.time.ns_per_s;
    const partition_end_ns: u64 = 15 * std.time.ns_per_s;
    try net.add_partition(.{
        .from = NODE_LOCAL,
        .to = NODE_PEER,
        .starts_at_ns = partition_start_ns,
        .ends_at_ns = partition_end_ns,
    });
    try net.add_partition(.{
        .from = NODE_PEER,
        .to = NODE_LOCAL,
        .starts_at_ns = partition_start_ns,
        .ends_at_ns = partition_end_ns,
    });

    // ── outbox table (local side) ─────────────────────────────────────
    var outbox: [ACTIVITY_COUNT]OutboxRow = undefined;
    var i: u32 = 0;
    while (i < ACTIVITY_COUNT) : (i += 1) outbox[i] = .{ .activity_id = i };

    // ── peer recv log ─────────────────────────────────────────────────
    var peer_recv = std.AutoHashMap(u32, u32).init(allocator); // id -> recv_count
    defer peer_recv.deinit();

    // ── simulation loop ───────────────────────────────────────────────
    // Tick every 100ms for up to 60s. At each tick:
    //   * advance net by 100ms (delivers ready packets).
    //   * drain delivered packets to peer log.
    //   * scan outbox: re-submit any pending row whose retry timer is up.
    //
    // The retry timer follows a simple exponential backoff floor of 200ms
    // * 2^attempts, capped at 5s — same shape as outbox_worker but in
    //   simulated time. Submission is idempotent on the receiver side
    //   (peer treats duplicate IDs as already-seen), modelling
    //   federation idempotency.

    var prng = std.Random.Xoshiro256.init(0xFED);
    // Use a deterministic body per activity.
    var activities: [ACTIVITY_COUNT]Activity = undefined;
    for (&activities, 0..) |*a, idx| {
        a.* = .{ .id = @intCast(idx), .src = NODE_LOCAL, .dst = NODE_PEER, .body = undefined };
        prng.random().bytes(&a.body);
    }

    // Last-attempt timestamp per row (simulated ns).
    var last_attempt_ns = [_]u64{0} ** ACTIVITY_COUNT;
    // Mark not-yet-attempted so the first submit fires immediately.
    var never_attempted = [_]bool{true} ** ACTIVITY_COUNT;

    const tick_ns: u64 = 100 * std.time.ns_per_ms;
    const total_ticks: u32 = 600; // 60s
    // Stagger initial enqueue: one activity every ~750ms so the burst
    // straddles the t=10s..15s partition window. This is what makes the
    // scenario meaningful — without staggering, every packet would have
    // long since delivered before t=10s.
    const enqueue_stride_ticks: u32 = 7;
    var tick_idx: u32 = 0;
    while (tick_idx < total_ticks) : (tick_idx += 1) {
        // Resubmit pending rows whose backoff has elapsed.
        for (&outbox, 0..) |*row, k| {
            if (row.state != .pending) continue;
            // Gate first attempt by stride — simulates outbox dequeue cadence.
            if (never_attempted[k] and tick_idx < @as(u32, @intCast(k)) * enqueue_stride_ticks) continue;
            if (!never_attempted[k]) {
                const backoff_ms: u64 = @min(
                    @as(u64, 5_000),
                    @as(u64, 200) * (@as(u64, 1) << @intCast(@min(row.attempts, 6))),
                );
                const elapsed = time_sim.monotonic() - last_attempt_ns[k];
                if (elapsed < backoff_ms * std.time.ns_per_ms) continue;
            }
            if (row.attempts >= MAX_DELIVERY_ATTEMPTS) {
                row.state = .dead_letter;
                continue;
            }
            try net.submit(activities[k]);
            row.attempts += 1;
            last_attempt_ns[k] = time_sim.monotonic();
            never_attempted[k] = false;
        }

        // Advance simulated time + network.
        _ = try net.advance(tick_ns);
        var j: u32 = 0;
        while (j < tick_ns / std.time.ns_per_ms) : (j += 1) time_sim.tick();

        // Drain delivered packets to peer.
        for (net.delivered.items) |p| {
            const gop = try peer_recv.getOrPut(p.packet.id);
            if (!gop.found_existing) {
                gop.value_ptr.* = 0;
            }
            gop.value_ptr.* += 1;

            // Mark outbox row done (idempotent — the peer ack would do
            // this in the real system).
            if (p.packet.id < ACTIVITY_COUNT and outbox[p.packet.id].state == .pending) {
                outbox[p.packet.id].state = .done;
            }
        }
        net.delivered.clearRetainingCapacity();
    }

    // ── assertions ────────────────────────────────────────────────────
    // 1. Every Activity ID appears in the peer's recv log at least once.
    var missing: u32 = 0;
    var k: u32 = 0;
    while (k < ACTIVITY_COUNT) : (k += 1) {
        if (peer_recv.get(k) == null) missing += 1;
    }
    if (missing != 0) {
        std.debug.print("FAIL: {} activity IDs were never delivered\n", .{missing});
        return error.MissingDeliveries;
    }

    // 2. No dead-letter rows.
    for (outbox) |row| {
        if (row.state == .dead_letter) {
            std.debug.print(
                "FAIL: activity {} dead-lettered after {} attempts\n",
                .{ row.activity_id, row.attempts },
            );
            return error.DeadLetter;
        }
    }

    // 3. All 20 rows in state=done.
    for (outbox) |row| {
        if (row.state != .done) {
            std.debug.print(
                "FAIL: activity {} ended in state={s} (attempts={})\n",
                .{ row.activity_id, @tagName(row.state), row.attempts },
            );
            return error.NotAllDone;
        }
    }

    std.debug.print(
        "ok: {} activities delivered, dropped_loss={} dropped_partition={} dropped_capacity={}\n",
        .{ ACTIVITY_COUNT, net.dropped_loss, net.dropped_partition, net.dropped_capacity },
    );
}

test "federate_with_mastodon: at-least-once under loss + partition" {
    try run(std.testing.allocator);
}
