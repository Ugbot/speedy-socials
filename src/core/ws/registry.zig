//! Sharded WebSocket subscription registry.
//!
//! Sharding model (Tiger Style: no locks on the hot path):
//!
//!   For a given `stream_key`, the home shard is determined by
//!   `hash(stream_key) % ws_subscription_shards`. **Only one worker
//!   "owns" a given shard**; that worker is the sole mutator of the
//!   shard's subscription pool and event ring. Producers from other
//!   threads communicate with the owner by pushing into the shard's
//!   `BoundedMpsc` command queue (`subscribe`, `unsubscribe`,
//!   `broadcast`). The owner drains the queue in its tick and applies
//!   the commands serially. The hot path is therefore lock-free for
//!   the owner and only briefly spinlocked for cross-thread producers
//!   inside the MPSC.
//!
//!   This means the *visible* subscription state, and the event ring,
//!   may lag the producer by up to one drain cycle — exactly the
//!   trade-off Tiger Style asks for: bounded latency, no locks on the
//!   read path, no allocation on either path.
//!
//!   Events carry caller-owned `[]const u8` slices. The lifetime
//!   contract: the slice must outlive the broadcast until the owner
//!   has processed it (typically: the payload lives in a per-shard
//!   broadcast arena owned by the producer / event source, or is a
//!   string constant).

const std = @import("std");
const limits = @import("../limits.zig");
const errors_mod = @import("../errors.zig");
const WsError = errors_mod.WsError;
const static = @import("../static.zig");
const event_ring_mod = @import("event_ring.zig");
const assert_mod = @import("../assert.zig");
const assert = assert_mod.assert;
const assertLe = assert_mod.assertLe;

/// Max bytes for a stream key (e.g. "firehose", "user:alice").
/// Stream keys live in caller storage; the registry hashes by value
/// and stores them by-reference (caller must keep the slice alive
/// for the subscription lifetime). This bound is enforced so the
/// hash loop and equality check are themselves bounded.
pub const max_stream_key_bytes: usize = 128;

/// Connection handle the registry stores on behalf of the owner.
/// Opaque to the registry — typically a connection-pool index.
pub const ConnHandle = u32;

/// Identifier returned to the subscriber for later unsubscribe.
pub const SubscriptionId = u64;

pub const shard_count: u32 = limits.ws_subscription_shards;

/// Slots per shard. Total registry capacity remains
/// `limits.max_subscriptions`, partitioned evenly.
pub const subscriptions_per_shard: u32 = blk: {
    if (limits.max_subscriptions % shard_count != 0) {
        @compileError("max_subscriptions must be divisible by ws_subscription_shards");
    }
    break :blk limits.max_subscriptions / shard_count;
};

/// Event ring capacity per shard. Power-of-two for fast modulo.
pub const events_per_shard: u32 = event_ring_mod.default_capacity;

/// Command queue depth per shard. Sized so a burst of cross-thread
/// activity does not back-pressure into producer code paths.
pub const commands_per_shard: u32 = 512;

/// One event in flight to subscribers. Slice lifetime is caller-
/// managed per the contract at the top of this file.
pub const Event = struct {
    payload: []const u8,
    /// Producer-assigned tag for filtering / multi-stream demux.
    /// Carried verbatim through the ring; meaning is producer-defined.
    tag: u32,
};

const EventRing = event_ring_mod.EventRing(Event, events_per_shard);

/// One subscriber. Identified by `(stream_key, conn)`; the registry
/// allows the same `conn` to hold multiple subscriptions to different
/// streams within the same shard.
pub const Subscription = struct {
    stream_key: []const u8,
    conn: ConnHandle,
    id: SubscriptionId,
    /// Last event sequence delivered to this subscriber.
    cursor: u64,
    /// Set to false when the slot is free.
    active: bool,
};

const SubPool = static.StaticPool(Subscription, subscriptions_per_shard);

/// Per-stream event ring + sequence accounting. Streams are stored
/// in a fixed-capacity table within each shard. When a stream's
/// table entry is exhausted, broadcasts to that stream are rejected
/// with `RegistryShardFull`.
const StreamSlot = struct {
    stream_key: []const u8,
    active: bool,
    ring: EventRing,
    /// Number of subscriptions referencing this stream. When zero,
    /// the slot is reclaimable.
    refcount: u32,
};

const max_streams_per_shard: u32 = subscriptions_per_shard; // worst case 1:1

pub const Command = union(enum) {
    subscribe: struct {
        stream_key: []const u8,
        conn: ConnHandle,
        id: SubscriptionId,
    },
    unsubscribe: struct {
        id: SubscriptionId,
    },
    broadcast: struct {
        stream_key: []const u8,
        event: Event,
    },
};

const CommandQueue = static.BoundedMpsc(Command, commands_per_shard);

pub const Shard = struct {
    subs: SubPool,
    streams: [max_streams_per_shard]StreamSlot,
    streams_used: u32,
    commands: CommandQueue,
    /// Strictly diagnostic: how many broadcast commands have been
    /// applied since boot.
    applied_broadcasts: u64,
    /// Broadcasts dropped because the stream slot table is full.
    dropped_broadcasts: u64,

    pub fn initInPlace(self: *Shard) void {
        self.subs.initInPlace();
        var i: usize = 0;
        while (i < self.streams.len) : (i += 1) {
            self.streams[i] = .{
                .stream_key = &.{},
                .active = false,
                .ring = EventRing.init(),
                .refcount = 0,
            };
        }
        self.streams_used = 0;
        self.commands = CommandQueue.init();
        self.applied_broadcasts = 0;
        self.dropped_broadcasts = 0;
    }

    /// Find an active stream slot by key. O(streams_per_shard);
    /// loop bound asserted.
    fn findStream(self: *Shard, key: []const u8) ?u32 {
        var i: u32 = 0;
        while (i < self.streams.len) : (i += 1) {
            assertLe(i, self.streams.len);
            const s = &self.streams[i];
            if (s.active and std.mem.eql(u8, s.stream_key, key)) return i;
        }
        return null;
    }

    fn findOrCreateStream(self: *Shard, key: []const u8) WsError!u32 {
        if (self.findStream(key)) |idx| return idx;
        var i: u32 = 0;
        while (i < self.streams.len) : (i += 1) {
            if (!self.streams[i].active) {
                self.streams[i] = .{
                    .stream_key = key,
                    .active = true,
                    .ring = EventRing.init(),
                    .refcount = 0,
                };
                self.streams_used += 1;
                return i;
            }
        }
        return error.RegistryShardFull;
    }

    fn releaseStream(self: *Shard, idx: u32) void {
        assert(idx < self.streams.len);
        const slot = &self.streams[idx];
        assert(slot.active);
        assert(slot.refcount > 0);
        slot.refcount -= 1;
        if (slot.refcount == 0) {
            slot.active = false;
            slot.stream_key = &.{};
            self.streams_used -= 1;
        }
    }

    /// Apply one command. Called only by the shard owner.
    fn applyCommand(self: *Shard, cmd: Command) WsError!void {
        switch (cmd) {
            .subscribe => |s| {
                if (s.stream_key.len > max_stream_key_bytes) return error.StreamKeyTooLong;
                const slot = self.subs.acquire() catch return error.RegistryExhausted;
                const stream_idx = self.findOrCreateStream(s.stream_key) catch |err| {
                    self.subs.release(slot.index);
                    return err;
                };
                slot.ptr.* = .{
                    .stream_key = s.stream_key,
                    .conn = s.conn,
                    .id = s.id,
                    .cursor = self.streams[stream_idx].ring.nextSeq(),
                    .active = true,
                };
                self.streams[stream_idx].refcount += 1;
            },
            .unsubscribe => |u| {
                if (self.findSubByIdMut(u.id)) |found| {
                    if (self.findStream(found.ptr.stream_key)) |stream_idx| {
                        self.releaseStream(stream_idx);
                    }
                    found.ptr.active = false;
                    self.subs.release(found.index);
                } else return error.SubscriptionNotFound;
            },
            .broadcast => |b| {
                if (b.stream_key.len > max_stream_key_bytes) return error.StreamKeyTooLong;
                const stream_idx = self.findStream(b.stream_key) orelse {
                    // No subscribers for this stream — drop silently.
                    self.dropped_broadcasts += 1;
                    return;
                };
                _ = self.streams[stream_idx].ring.push(b.event);
                self.applied_broadcasts += 1;
            },
        }
    }

    const SubFound = struct { index: SubPool.Index, ptr: *Subscription };

    fn findSubByIdMut(self: *Shard, id: SubscriptionId) ?SubFound {
        var i: SubPool.Index = 0;
        while (i < SubPool.capacity) : (i += 1) {
            assertLe(i, SubPool.capacity);
            const p = self.subs.get(i);
            if (p.active and p.id == id) return .{ .index = i, .ptr = p };
        }
        return null;
    }

    /// Drain up to `max_commands` queued commands. Owner-only. Returns
    /// the number processed. Errors short-circuit drain so the caller
    /// can decide; remaining queued commands stay queued.
    pub fn drainCommands(self: *Shard, max_commands: u32) WsError!u32 {
        var processed: u32 = 0;
        while (processed < max_commands) : (processed += 1) {
            const cmd = self.commands.tryPop() orelse break;
            try self.applyCommand(cmd);
        }
        assertLe(processed, max_commands);
        return processed;
    }

    /// Iterator over active subscriptions belonging to a given stream.
    /// Owner-only.
    pub const SubIterator = struct {
        shard: *Shard,
        stream_key: []const u8,
        cursor: SubPool.Index,

        pub fn next(self: *SubIterator) ?*Subscription {
            while (self.cursor < SubPool.capacity) {
                const p = self.shard.subs.get(self.cursor);
                self.cursor += 1;
                if (p.active and std.mem.eql(u8, p.stream_key, self.stream_key)) return p;
            }
            return null;
        }
    };

    pub fn iterStream(self: *Shard, stream_key: []const u8) SubIterator {
        return .{ .shard = self, .stream_key = stream_key, .cursor = 0 };
    }

    pub fn streamRing(self: *Shard, stream_key: []const u8) ?*EventRing {
        if (self.findStream(stream_key)) |idx| return &self.streams[idx].ring;
        return null;
    }
};

pub const Registry = struct {
    shards: [shard_count]Shard,
    next_sub_id: std.atomic.Value(u64),

    pub fn initInPlace(self: *Registry) void {
        var i: usize = 0;
        while (i < self.shards.len) : (i += 1) {
            self.shards[i].initInPlace();
        }
        self.next_sub_id = std.atomic.Value(u64).init(1);
    }

    pub fn shardFor(self: *Registry, stream_key: []const u8) *Shard {
        const h = hashKey(stream_key);
        return &self.shards[@as(usize, @intCast(h % shard_count))];
    }

    /// Producer-side: queue a subscribe for the owner to apply.
    /// Returns the assigned subscription id immediately; the
    /// subscription is *not* yet visible until the owner drains.
    pub fn subscribe(self: *Registry, stream_key: []const u8, conn: ConnHandle) WsError!SubscriptionId {
        if (stream_key.len > max_stream_key_bytes) return error.StreamKeyTooLong;
        const id = self.next_sub_id.fetchAdd(1, .monotonic);
        const shard = self.shardFor(stream_key);
        shard.commands.push(.{ .subscribe = .{
            .stream_key = stream_key,
            .conn = conn,
            .id = id,
        } }) catch return error.RegistryShardFull;
        return id;
    }

    pub fn unsubscribe(self: *Registry, stream_key: []const u8, id: SubscriptionId) WsError!void {
        if (stream_key.len > max_stream_key_bytes) return error.StreamKeyTooLong;
        const shard = self.shardFor(stream_key);
        shard.commands.push(.{ .unsubscribe = .{ .id = id } }) catch return error.RegistryShardFull;
    }

    /// Queue a broadcast for the owner to fan out. The payload slice
    /// must remain valid until the owner has drained.
    pub fn broadcast(self: *Registry, stream_key: []const u8, event: Event) WsError!void {
        if (stream_key.len > max_stream_key_bytes) return error.StreamKeyTooLong;
        const shard = self.shardFor(stream_key);
        shard.commands.push(.{ .broadcast = .{
            .stream_key = stream_key,
            .event = event,
        } }) catch return error.RegistryShardFull;
    }
};

/// FNV-1a 64. Fixed iteration count = key length; bound asserted.
fn hashKey(key: []const u8) u64 {
    var h: u64 = 0xCBF29CE484222325;
    var i: usize = 0;
    assertLe(key.len, max_stream_key_bytes);
    while (i < key.len) : (i += 1) {
        h ^= key[i];
        h *%= 0x100000001B3;
    }
    return h;
}

// ── tests ──────────────────────────────────────────────────────

const testing = std.testing;

fn newRegistry() !*Registry {
    const reg = try testing.allocator.create(Registry);
    reg.initInPlace();
    return reg;
}

test "Registry subscribe/drain makes subscription visible" {
    const reg = try newRegistry();
    defer testing.allocator.destroy(reg);

    const key = "firehose";
    const id = try reg.subscribe(key, 42);

    const shard = reg.shardFor(key);
    // Pre-drain: no subscription visible.
    var it = shard.iterStream(key);
    try testing.expect(it.next() == null);

    const n = try shard.drainCommands(16);
    try testing.expectEqual(@as(u32, 1), n);

    var it2 = shard.iterStream(key);
    const sub = it2.next() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u32, 42), sub.conn);
    try testing.expectEqual(id, sub.id);
    try testing.expect(it2.next() == null);
}

test "Registry unsubscribe removes subscription" {
    const reg = try newRegistry();
    defer testing.allocator.destroy(reg);

    const key = "stream-a";
    const id = try reg.subscribe(key, 1);
    const shard = reg.shardFor(key);
    _ = try shard.drainCommands(16);

    try reg.unsubscribe(key, id);
    _ = try shard.drainCommands(16);

    var it = shard.iterStream(key);
    try testing.expect(it.next() == null);
}

test "Registry shards different streams to (likely) different shards" {
    const reg = try newRegistry();
    defer testing.allocator.destroy(reg);

    // Force several keys; assert that at least two distinct shards
    // are hit. The hash is deterministic so this is reproducible.
    var seen = [_]bool{false} ** shard_count;
    const keys = [_][]const u8{ "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel" };
    var distinct: u32 = 0;
    for (keys) |k| {
        const idx = hashKey(k) % shard_count;
        if (!seen[idx]) {
            seen[idx] = true;
            distinct += 1;
        }
    }
    try testing.expect(distinct >= 2);
}

test "Registry broadcast records to stream ring" {
    const reg = try newRegistry();
    defer testing.allocator.destroy(reg);

    const key = "firehose";
    _ = try reg.subscribe(key, 7);
    const shard = reg.shardFor(key);
    _ = try shard.drainCommands(16);

    const payload = "hello world";
    try reg.broadcast(key, .{ .payload = payload, .tag = 1 });
    try reg.broadcast(key, .{ .payload = payload, .tag = 2 });
    _ = try shard.drainCommands(16);

    const ring = shard.streamRing(key) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u64, 2), ring.nextSeq());
}

test "Registry broadcast with no subscribers is dropped silently" {
    const reg = try newRegistry();
    defer testing.allocator.destroy(reg);

    try reg.broadcast("nobody-home", .{ .payload = "x", .tag = 0 });
    const shard = reg.shardFor("nobody-home");
    _ = try shard.drainCommands(16);
    try testing.expectEqual(@as(u64, 0), shard.applied_broadcasts);
    try testing.expectEqual(@as(u64, 1), shard.dropped_broadcasts);
}

test "Registry rejects oversize stream key" {
    const reg = try newRegistry();
    defer testing.allocator.destroy(reg);

    var huge: [max_stream_key_bytes + 1]u8 = undefined;
    @memset(&huge, 'k');
    try testing.expectError(error.StreamKeyTooLong, reg.subscribe(&huge, 1));
    try testing.expectError(error.StreamKeyTooLong, reg.broadcast(&huge, .{ .payload = "", .tag = 0 }));
}

test "Registry broadcast ring overwrites oldest when full" {
    const reg = try newRegistry();
    defer testing.allocator.destroy(reg);

    const key = "burst";
    _ = try reg.subscribe(key, 0);
    const shard = reg.shardFor(key);
    _ = try shard.drainCommands(16);

    // Send more events than the ring can hold; ring should overwrite.
    const overshoot: u32 = events_per_shard + 32;
    var i: u32 = 0;
    while (i < overshoot) : (i += 1) {
        try reg.broadcast(key, .{ .payload = "evt", .tag = i });
        _ = try shard.drainCommands(16);
    }

    const ring = shard.streamRing(key) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u64, overshoot), ring.nextSeq());
    try testing.expectEqual(@as(u64, overshoot - events_per_shard), ring.oldestSeq());
    try testing.expectEqual(@as(u64, overshoot - events_per_shard), ring.dropped());
}

test "Registry iteration sees only matching stream subs" {
    const reg = try newRegistry();
    defer testing.allocator.destroy(reg);

    // Choose keys that intentionally land in the same shard so we can
    // assert iteration filters by stream_key rather than just shard.
    var keys: [16][]const u8 = undefined;
    keys[0] = "topic-a";
    var found_pair = false;
    var k_idx: usize = 1;
    while (k_idx < 16) : (k_idx += 1) {
        // Try a sequence of candidate keys until one collides with keys[0].
        const candidates = [_][]const u8{ "topic-b", "topic-c", "topic-d", "topic-e", "topic-f", "topic-g", "topic-h", "topic-i" };
        for (candidates) |c| {
            if (hashKey(c) % shard_count == hashKey(keys[0]) % shard_count and !std.mem.eql(u8, c, keys[0])) {
                keys[1] = c;
                found_pair = true;
                break;
            }
        }
        if (found_pair) break;
    }
    if (!found_pair) return; // skip if no collision in this build's shard layout

    const a = try reg.subscribe(keys[0], 100);
    const b = try reg.subscribe(keys[1], 200);
    _ = a;
    _ = b;
    const shard = reg.shardFor(keys[0]);
    _ = try shard.drainCommands(16);

    var ait = shard.iterStream(keys[0]);
    const sa = ait.next() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u32, 100), sa.conn);
    try testing.expect(ait.next() == null);

    var bit = shard.iterStream(keys[1]);
    const sb = bit.next() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u32, 200), sb.conn);
    try testing.expect(bit.next() == null);
}

test "Registry unsubscribe unknown id returns error" {
    const reg = try newRegistry();
    defer testing.allocator.destroy(reg);
    try reg.unsubscribe("nope", 12345);
    const shard = reg.shardFor("nope");
    try testing.expectError(error.SubscriptionNotFound, shard.drainCommands(16));
}
