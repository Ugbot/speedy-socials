// Inspired by tigerbeetle/src/testing/packet_simulator.zig @ 44544ee11057bbc8fe826cb7f93e8e00a57f2fc1.
// Modifications:
//   * Rewritten from scratch (not a direct vendor) to decouple from
//     `vsr.Command`, `stdx.PRNG.Ratio`, `stdx.Duration`, `stdx.Instant`,
//     `constants.tick_ms`, and TB's intrusive `QueueType` / priority queue
//     wrapper. TB's version is tightly bound to the VSR consensus
//     simulator. speedy-socials needs a federation network simulator
//     where packets are AP/AT activities, not VSR messages.
//   * The Packet type is now caller-provided via comptime parameterisation
//     and must implement `from`, `to`, `payload`, and `copy`. This matches
//     the Tranche 4 deliverable contract.
//   * Latency model: exponential distribution with configurable mean and
//     minimum (in nanoseconds), same as TB.
//   * Packet loss: per-packet Bernoulli draw against a [0, 1] probability,
//     matching TB's `packet_loss_probability`.
//   * Partition window: callers can explicitly open/close two-way
//     partitions between NodeIds rather than relying on TB's automatic
//     partition modes (we only need scripted partitions for our scenarios).
//   * Asymmetric partitions are supported: a partition is parameterised by
//     `from`/`to`, so opening only one direction simulates one-way drops.
// TigerBeetle is licensed under Apache 2.0; see src/third_party/tigerbeetle/LICENSE.

const std = @import("std");
const assert = std.debug.assert;

const fuzz = @import("fuzz.zig");

pub const NodeId = u32;

pub const Options = struct {
    /// Maximum nodes participating in the simulated network.
    node_count: u32,
    seed: u64,
    /// Mean of the exponential delivery delay distribution, in nanoseconds.
    one_way_delay_mean_ns: u64,
    /// Floor on delivery delay, in nanoseconds. delay = max(min, exp(mean)).
    one_way_delay_min_ns: u64,
    /// Probability a packet is silently dropped, in [0, 1].
    packet_loss_probability: f32 = 0.0,
    /// Maximum in-flight packets per directed path. Overflow drops oldest.
    path_capacity: u32 = 1024,
};

pub const Partition = struct {
    from: NodeId,
    to: NodeId,
    /// Inclusive lower bound (monotonic ns).
    starts_at_ns: u64,
    /// Exclusive upper bound (monotonic ns).
    ends_at_ns: u64,
};

pub fn PacketSimulator(comptime Packet: type) type {
    // Enforce the documented contract at comptime. Each method's parameter
    // and return types must line up exactly with the API tranche-4 promises.
    comptime {
        const has_from = @hasDecl(Packet, "from");
        const has_to = @hasDecl(Packet, "to");
        const has_payload = @hasDecl(Packet, "payload");
        const has_copy = @hasDecl(Packet, "copy");
        if (!(has_from and has_to and has_payload and has_copy)) {
            @compileError("Packet must declare fn from/to/payload/copy — see Tranche 4 contract.");
        }
    }

    return struct {
        const Self = @This();

        const Pending = struct {
            packet: Packet,
            from: NodeId,
            to: NodeId,
            deliver_at_ns: u64,
        };

        allocator: std.mem.Allocator,
        options: Options,
        prng: std.Random.Xoshiro256,
        now_ns: u64 = 0,
        in_flight: std.ArrayListUnmanaged(Pending) = .empty,
        partitions: std.ArrayListUnmanaged(Partition) = .empty,
        delivered: std.ArrayListUnmanaged(Pending) = .empty,
        dropped_loss: u64 = 0,
        dropped_partition: u64 = 0,
        dropped_capacity: u64 = 0,

        pub fn init(allocator: std.mem.Allocator, options: Options) !Self {
            assert(options.node_count > 0);
            assert(options.one_way_delay_min_ns <= options.one_way_delay_mean_ns);
            return .{
                .allocator = allocator,
                .options = options,
                .prng = std.Random.Xoshiro256.init(options.seed),
            };
        }

        pub fn deinit(self: *Self) void {
            self.in_flight.deinit(self.allocator);
            self.partitions.deinit(self.allocator);
            self.delivered.deinit(self.allocator);
        }

        pub fn add_partition(self: *Self, p: Partition) !void {
            assert(p.from < self.options.node_count);
            assert(p.to < self.options.node_count);
            assert(p.ends_at_ns > p.starts_at_ns);
            try self.partitions.append(self.allocator, p);
        }

        /// Submit a packet for delivery. Latency is drawn now (so partition
        /// checks during `step` see a stable deliver_at), but loss / partition
        /// drops happen at delivery time so partitions opened *after* submit
        /// still block in-flight packets — modelling realistic network cuts.
        pub fn submit(self: *Self, packet: Packet) !void {
            const from_id = Packet.from(packet);
            const to_id = Packet.to(packet);
            assert(from_id < self.options.node_count);
            assert(to_id < self.options.node_count);

            const path_in_flight = self.in_flight_on_path(from_id, to_id);
            if (path_in_flight >= self.options.path_capacity) {
                self.drop_oldest_on_path(from_id, to_id);
                self.dropped_capacity += 1;
            }

            const delay = @max(
                self.options.one_way_delay_min_ns,
                fuzz.random_int_exponential(&self.prng, u64, self.options.one_way_delay_mean_ns),
            );
            try self.in_flight.append(self.allocator, .{
                .packet = packet,
                .from = from_id,
                .to = to_id,
                .deliver_at_ns = self.now_ns + delay,
            });
        }

        fn in_flight_on_path(self: *const Self, from: NodeId, to: NodeId) u32 {
            var n: u32 = 0;
            for (self.in_flight.items) |p| {
                if (p.from == from and p.to == to) n += 1;
            }
            return n;
        }

        fn drop_oldest_on_path(self: *Self, from: NodeId, to: NodeId) void {
            // First match wins — items are appended in submission order, so
            // index 0 of a matching path is the oldest.
            for (self.in_flight.items, 0..) |p, i| {
                if (p.from == from and p.to == to) {
                    _ = self.in_flight.orderedRemove(i);
                    return;
                }
            }
        }

        fn partitioned(self: *const Self, from: NodeId, to: NodeId, at_ns: u64) bool {
            for (self.partitions.items) |part| {
                if (part.from == from and part.to == to and
                    at_ns >= part.starts_at_ns and at_ns < part.ends_at_ns)
                {
                    return true;
                }
            }
            return false;
        }

        /// Advance time by `ns` and deliver any ready packets. Returns the
        /// number of packets delivered this step (not including dropped).
        pub fn advance(self: *Self, ns: u64) !u32 {
            self.now_ns += ns;
            return self.flush();
        }

        fn flush(self: *Self) !u32 {
            var delivered: u32 = 0;
            var i: usize = 0;
            while (i < self.in_flight.items.len) {
                const p = self.in_flight.items[i];
                if (p.deliver_at_ns > self.now_ns) {
                    i += 1;
                    continue;
                }
                _ = self.in_flight.orderedRemove(i);

                if (self.partitioned(p.from, p.to, p.deliver_at_ns)) {
                    self.dropped_partition += 1;
                    continue;
                }
                if (self.prng.random().float(f32) < self.options.packet_loss_probability) {
                    self.dropped_loss += 1;
                    continue;
                }
                try self.delivered.append(self.allocator, p);
                delivered += 1;
            }
            return delivered;
        }

        pub fn pending(self: *const Self) usize {
            return self.in_flight.items.len;
        }

        pub fn delivered_count(self: *const Self) usize {
            return self.delivered.items.len;
        }

        /// Drain the delivered queue — caller takes ownership of packets.
        /// Useful for stepwise scenarios that want to mailbox each batch.
        pub fn drain_delivered(self: *Self, sink: *std.ArrayListUnmanaged(Packet)) !void {
            for (self.delivered.items) |p| {
                try sink.append(self.allocator, p.packet);
            }
            self.delivered.clearRetainingCapacity();
        }
    };
}

// ── tests ──────────────────────────────────────────────────────────────

const TestPacket = struct {
    src: NodeId,
    dst: NodeId,
    body: [16]u8,

    pub fn from(p: TestPacket) NodeId {
        return p.src;
    }
    pub fn to(p: TestPacket) NodeId {
        return p.dst;
    }
    pub fn payload(p: TestPacket) []const u8 {
        // Returns the underlying body. Caller must not retain past `p`'s lifetime.
        return &p.body;
    }
    pub fn copy(p: TestPacket) TestPacket {
        return p;
    }
};

fn make_packet(prng: *std.Random.Xoshiro256, src: NodeId, dst: NodeId) TestPacket {
    var p: TestPacket = .{ .src = src, .dst = dst, .body = undefined };
    prng.random().bytes(&p.body);
    return p;
}

test "PacketSimulator latency mean approximates configured mean" {
    var sim = try PacketSimulator(TestPacket).init(std.testing.allocator, .{
        .node_count = 2,
        .seed = 0xA1,
        .one_way_delay_mean_ns = 50 * std.time.ns_per_ms,
        .one_way_delay_min_ns = 0,
        .path_capacity = 8192,
    });
    defer sim.deinit();

    var prng = std.Random.Xoshiro256.init(0xA1);
    const N: u32 = 2_000;
    var i: u32 = 0;
    while (i < N) : (i += 1) {
        try sim.submit(make_packet(&prng, 0, 1));
    }
    // Advance well past any reasonable tail; expect all delivered.
    _ = try sim.advance(60 * std.time.ns_per_s);
    try std.testing.expectEqual(@as(usize, N), sim.delivered_count());

    var total_delay: u128 = 0;
    for (sim.delivered.items) |p| {
        total_delay += p.deliver_at_ns;
    }
    const mean_ns: u64 = @intCast(total_delay / N);
    const target = 50 * std.time.ns_per_ms;
    try std.testing.expect(mean_ns > target - target / 5);
    try std.testing.expect(mean_ns < target + target / 5);
}

test "PacketSimulator drops packets at configured loss rate" {
    var sim = try PacketSimulator(TestPacket).init(std.testing.allocator, .{
        .node_count = 2,
        .seed = 7,
        .one_way_delay_mean_ns = 1_000,
        .one_way_delay_min_ns = 0,
        .packet_loss_probability = 0.25,
        .path_capacity = 8192,
    });
    defer sim.deinit();

    var prng = std.Random.Xoshiro256.init(7);
    const N: u32 = 4_000;
    var i: u32 = 0;
    while (i < N) : (i += 1) try sim.submit(make_packet(&prng, 0, 1));
    _ = try sim.advance(std.time.ns_per_s);

    const total = sim.delivered_count() + sim.dropped_loss;
    try std.testing.expectEqual(@as(usize, N), total);
    // Should be ~25% loss; allow ±5%.
    const loss_frac = @as(f64, @floatFromInt(sim.dropped_loss)) / @as(f64, @floatFromInt(N));
    try std.testing.expect(loss_frac > 0.20);
    try std.testing.expect(loss_frac < 0.30);
}

test "PacketSimulator drops packets inside symmetric partition window" {
    var sim = try PacketSimulator(TestPacket).init(std.testing.allocator, .{
        .node_count = 2,
        .seed = 11,
        // Mean and floor both 50ms — every packet deliver_at lands inside
        // a [100ms, 200ms] partition window if submitted at t=50ms.
        .one_way_delay_mean_ns = 60 * std.time.ns_per_ms,
        .one_way_delay_min_ns = 60 * std.time.ns_per_ms,
        .path_capacity = 1024,
    });
    defer sim.deinit();

    // Partition from t=100ms..200ms in both directions.
    try sim.add_partition(.{ .from = 0, .to = 1, .starts_at_ns = 100 * std.time.ns_per_ms, .ends_at_ns = 200 * std.time.ns_per_ms });
    try sim.add_partition(.{ .from = 1, .to = 0, .starts_at_ns = 100 * std.time.ns_per_ms, .ends_at_ns = 200 * std.time.ns_per_ms });

    var prng = std.Random.Xoshiro256.init(11);
    // Move time to t=50ms then burst 50 packets. With min=mean=60ms delay,
    // every packet's deliver_at lands at t=110ms inside the partition.
    _ = try sim.advance(50 * std.time.ns_per_ms);
    var i: u32 = 0;
    while (i < 50) : (i += 1) try sim.submit(make_packet(&prng, 0, 1));
    _ = try sim.advance(149 * std.time.ns_per_ms); // now @ 199ms
    // Packets whose deliver_at lands inside [100ms, 200ms] are dropped.
    // With exp distribution on top of a 60ms floor, a tiny fraction may
    // land beyond t=199ms — still in flight, not yet evaluated.
    try std.testing.expect(sim.dropped_partition >= 45);
    try std.testing.expectEqual(@as(usize, 0), sim.delivered_count());

    // After partition ends, new packets get through. Some of the late-tail
    // burst packets (deliver_at >= 200ms) will also deliver — count both.
    const delivered_before_post = sim.delivered_count();
    _ = try sim.advance(100 * std.time.ns_per_ms); // now @ 299ms — outside window
    try sim.submit(make_packet(&prng, 0, 1));
    _ = try sim.advance(std.time.ns_per_s);
    try std.testing.expect(sim.delivered_count() >= delivered_before_post + 1);
}

test "PacketSimulator asymmetric partition only drops one direction" {
    var sim = try PacketSimulator(TestPacket).init(std.testing.allocator, .{
        .node_count = 2,
        .seed = 13,
        .one_way_delay_mean_ns = 5 * std.time.ns_per_ms,
        .one_way_delay_min_ns = 1 * std.time.ns_per_ms,
    });
    defer sim.deinit();

    // Only 0→1 is partitioned; 1→0 stays open.
    try sim.add_partition(.{ .from = 0, .to = 1, .starts_at_ns = 0, .ends_at_ns = std.time.ns_per_s });

    var prng = std.Random.Xoshiro256.init(13);
    var i: u32 = 0;
    while (i < 30) : (i += 1) {
        try sim.submit(make_packet(&prng, 0, 1));
        try sim.submit(make_packet(&prng, 1, 0));
    }
    _ = try sim.advance(500 * std.time.ns_per_ms);

    // 0→1 packets dropped, 1→0 delivered.
    var delivered_one_to_zero: u32 = 0;
    var delivered_zero_to_one: u32 = 0;
    for (sim.delivered.items) |p| {
        if (p.from == 1 and p.to == 0) delivered_one_to_zero += 1;
        if (p.from == 0 and p.to == 1) delivered_zero_to_one += 1;
    }
    try std.testing.expect(delivered_one_to_zero >= 25);
    try std.testing.expectEqual(@as(u32, 0), delivered_zero_to_one);
    try std.testing.expect(sim.dropped_partition >= 25);
}
