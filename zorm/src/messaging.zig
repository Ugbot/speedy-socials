//! zorm S8 — TYPED MESSAGING.
//!
//! The same comptime-reflected entity zorm persists to a DB can also be
//! published to a stream (a `Sink`) or pushed onto a work queue (a `Queue`),
//! carrying its schema fingerprint in the payload. This file is the bridge
//! between zorm's reflection/codec layers and a message transport:
//!
//!   * `Sink`  — fire-and-forget publish to a topic, with a routing `key`.
//!   * `Queue` — durable enqueue + batch claim (dequeue) + ack/nack, the
//!               classic work-queue lifecycle.
//!
//! Both are runtime vtables (mirroring `contract.Backend`'s style) so a host
//! can supply any concrete transport (Kafka, NATS, Redis Streams, an
//! in-memory ring, …) via a zero-cost adapter. zorm never depends on a
//! specific broker.
//!
//! Tiger Style: bounded buffers, NO heap allocation. The caller supplies the
//! serialize `scratch` slice, the `key_buf`, and (for claim) the `items` and
//! `out_values` slices. All per-field dispatch happens at comptime inside the
//! codec; this layer only routes bytes + derives a key from the entity PK.
//!
//! Wire payload format == `codec.zig` (an 8-byte schema fingerprint prefix
//! followed by positional field encodings). A consumer that deserializes with
//! the WRONG entity type gets a fingerprint mismatch and rejects the message
//! (the codec's `error.BadStatement`).
//!
//! Error variants used (all from `contract.Error`, none invented):
//!   * BufferTooSmall — serialize `scratch`/JSON `out`/`key_buf` too small.
//!   * BadStatement   — codec rejected a payload (fingerprint mismatch or a
//!                      truncated/malformed payload) on consume/claim.
//!   * plus whatever a concrete Sink/Queue surfaces (BackendFailed, …).

const std = @import("std");
const contract = @import("contract.zig");
const reflect = @import("reflect.zig");
const bind = @import("bind.zig");
const codec = @import("codec.zig");
const schema_desc = @import("schema_desc.zig");

const Error = contract.Error;

// ── Interfaces ───────────────────────────────────────────────────────────

/// A publish-only message transport. A host supplies one via a zero-cost
/// adapter; zorm publishes serialized entities (and schema descriptors) to a
/// topic with a routing/partition `key`.
pub const Sink = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        publish: *const fn (ptr: *anyopaque, topic: []const u8, key: []const u8, payload: []const u8) Error!void,
    };

    pub fn publish(self: Sink, topic: []const u8, key: []const u8, payload: []const u8) Error!void {
        return self.vtable.publish(self.ptr, topic, key, payload);
    }
};

/// Maximum payload bytes a single `QueueItem` carries inline. Bounded so a
/// claim batch is a fixed-size, heap-free `[]QueueItem` the caller owns. This
/// must be ≥ the largest serialized entity payload the host enqueues; entity
/// inline byte caps are themselves ≤ `contract.max_inline_bytes` (1024) per
/// field, so 2048 comfortably holds a small-to-medium entity. Hosts with
/// larger entities should claim into their own wider `QueueItem`-shaped type
/// or raise this bound in a fork.
pub const queue_item_payload_cap: usize = 2048;

/// One claimed work-queue item: a transport-assigned `id` (used to ack/nack)
/// plus a bounded inline payload. Bounded + copyable; no borrowed slices, so
/// a claimed batch outlives the transport call that produced it.
pub const QueueItem = struct {
    id: i64 = 0,
    payload: [queue_item_payload_cap]u8 = undefined,
    payload_len: u16 = 0,

    /// The payload bytes actually written (the codec wire image).
    pub fn payloadSlice(self: *const QueueItem) []const u8 {
        return self.payload[0..self.payload_len];
    }

    /// Copy `bytes` into this item's inline payload. Surfaces
    /// `error.BufferTooSmall` if the payload exceeds the inline bound — a
    /// transport adapter calls this when filling a claim batch.
    pub fn setPayload(self: *QueueItem, bytes: []const u8) Error!void {
        if (bytes.len > queue_item_payload_cap) return Error.BufferTooSmall;
        @memcpy(self.payload[0..bytes.len], bytes);
        self.payload_len = @intCast(bytes.len);
    }
};

/// A durable work-queue transport: enqueue a payload, claim a batch of
/// pending items, then ack (done) or nack (redeliver) each by id.
pub const Queue = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        enqueue: *const fn (ptr: *anyopaque, topic: []const u8, payload: []const u8) Error!void,
        dequeueBatch: *const fn (ptr: *anyopaque, topic: []const u8, out: []QueueItem) Error!usize,
        ack: *const fn (ptr: *anyopaque, id: i64) Error!void,
        nack: *const fn (ptr: *anyopaque, id: i64) Error!void,
    };

    pub fn enqueue(self: Queue, topic: []const u8, payload: []const u8) Error!void {
        return self.vtable.enqueue(self.ptr, topic, payload);
    }
    pub fn dequeueBatch(self: Queue, topic: []const u8, out: []QueueItem) Error!usize {
        return self.vtable.dequeueBatch(self.ptr, topic, out);
    }
    pub fn ack(self: Queue, id: i64) Error!void {
        return self.vtable.ack(self.ptr, id);
    }
    pub fn nack(self: Queue, id: i64) Error!void {
        return self.vtable.nack(self.ptr, id);
    }
};

// ── Typed operations (comptime over the entity type) ─────────────────────

/// Render entity `value`'s primary key as routing-key bytes into `key_buf`,
/// returning the written prefix. A text/blob PK copies its slice bytes
/// verbatim; an int/auto PK is formatted as a decimal string. Uses
/// `bind.bindPk` so the key derivation stays in lock-step with how zorm binds
/// the PK for storage. Surfaces `error.BufferTooSmall` if `key_buf` cannot
/// hold the rendered key.
pub fn keyFor(comptime T: type, value: *const T, key_buf: []u8) Error![]const u8 {
    const bv = bind.bindPk(T, value);
    switch (bv) {
        .text, .blob => {
            const s = switch (bv) {
                .text => |t| t,
                .blob => |b| b,
                else => unreachable,
            };
            if (s.len > key_buf.len) return Error.BufferTooSmall;
            @memcpy(key_buf[0..s.len], s);
            return key_buf[0..s.len];
        },
        .int => |i| {
            return std.fmt.bufPrint(key_buf, "{d}", .{i}) catch return Error.BufferTooSmall;
        },
        .real => |r| {
            // A real PK is unusual but representable; format it decimally so
            // the key is still deterministic text.
            return std.fmt.bufPrint(key_buf, "{d}", .{r}) catch return Error.BufferTooSmall;
        },
        .null_ => return key_buf[0..0],
    }
}

/// The maximum routing-key length `publish` renders on its internal stack
/// buffer. A text/blob PK is bounded by `contract.max_inline_bytes` (1024);
/// a decimal int/float fits well within that. We size the stack buffer to
/// that bound so any valid entity PK renders without truncation.
const key_stack_cap: usize = contract.max_inline_bytes;

/// Serialize `value` (codec wire image, fingerprint-prefixed) into `scratch`,
/// derive its routing key from the PK, and publish to `topic` via `sink`.
pub fn publish(comptime T: type, sink: Sink, topic: []const u8, value: *const T, scratch: []u8) Error!void {
    const payload = try codec.serialize(T, value, scratch);
    var key_buf: [key_stack_cap]u8 = undefined;
    const key = try keyFor(T, value, &key_buf);
    return sink.publish(topic, key, payload);
}

/// Emit the `Schema(T)` JSON descriptor (via `schema_desc.toJson`) into `out`
/// and publish it to `topic` keyed by the table name, so a schema registry /
/// consumer can discover the entity's wire schema + fingerprint.
pub fn publishSchema(comptime T: type, sink: Sink, topic: []const u8, out: []u8) Error!void {
    const json = try schema_desc.toJson(T, out);
    const key = schema_desc.Schema(T).table;
    return sink.publish(topic, key, json);
}

/// Decode a received `payload` (codec wire image) into `out`. A fingerprint
/// mismatch (wrong-schema message) or a truncated/malformed payload propagates
/// the codec's `error.BadStatement`, so a consumer rejects bad messages.
pub fn consume(comptime T: type, payload: []const u8, out: *T) Error!void {
    return codec.deserialize(T, payload, out);
}

/// Serialize `value` into `scratch` and enqueue it onto `topic` via `queue`.
pub fn enqueue(comptime T: type, queue: Queue, topic: []const u8, value: *const T, scratch: []u8) Error!void {
    const payload = try codec.serialize(T, value, scratch);
    return queue.enqueue(topic, payload);
}

/// Claim a batch from `topic`: dequeue into `items`, then deserialize each
/// claimed item's payload into the matching `out_values[i]`. Returns the count
/// claimed (bounded by `min(items.len, out_values.len)`). A malformed/wrong-
/// schema item propagates the codec error (the batch is partially filled up to
/// that point; the caller still holds the ids in `items` to nack).
pub fn claim(comptime T: type, queue: Queue, topic: []const u8, items: []QueueItem, out_values: []T) Error!usize {
    const cap = @min(items.len, out_values.len);
    if (cap == 0) return 0;
    const got = try queue.dequeueBatch(topic, items[0..cap]);
    const n = @min(got, cap);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        try codec.deserialize(T, items[i].payloadSlice(), &out_values[i]);
    }
    return n;
}

// ── Tests ──────────────────────────────────────────────────────────────

const fields = @import("fields.zig");
const testing = std.testing;

// ---- Mock transports (self-contained; no external broker) ---------------

/// Records the most recent publish (topic/key/payload) into fixed buffers and
/// counts total publishes. Heap-free.
const MockSink = struct {
    topic_buf: [128]u8 = undefined,
    topic_len: usize = 0,
    key_buf: [contract.max_inline_bytes]u8 = undefined,
    key_len: usize = 0,
    payload_buf: [4096]u8 = undefined,
    payload_len: usize = 0,
    count: usize = 0,

    fn publishImpl(ptr: *anyopaque, topic: []const u8, key: []const u8, payload: []const u8) Error!void {
        const self: *MockSink = @ptrCast(@alignCast(ptr));
        if (topic.len > self.topic_buf.len) return Error.BufferTooSmall;
        if (key.len > self.key_buf.len) return Error.BufferTooSmall;
        if (payload.len > self.payload_buf.len) return Error.BufferTooSmall;
        @memcpy(self.topic_buf[0..topic.len], topic);
        self.topic_len = topic.len;
        @memcpy(self.key_buf[0..key.len], key);
        self.key_len = key.len;
        @memcpy(self.payload_buf[0..payload.len], payload);
        self.payload_len = payload.len;
        self.count += 1;
    }

    const vtable = Sink.VTable{ .publish = publishImpl };

    fn sink(self: *MockSink) Sink {
        return .{ .ptr = self, .vtable = &vtable };
    }
    fn lastTopic(self: *const MockSink) []const u8 {
        return self.topic_buf[0..self.topic_len];
    }
    fn lastKey(self: *const MockSink) []const u8 {
        return self.key_buf[0..self.key_len];
    }
    fn lastPayload(self: *const MockSink) []const u8 {
        return self.payload_buf[0..self.payload_len];
    }
};

/// Fixed-capacity in-memory work queue: a ring of {id, topic, payload, live}
/// slots with a monotonic id counter. Linear scan (no hashmap — the 0.16
/// stripped std has no usable ArrayHashMap). enqueue appends a live slot;
/// dequeueBatch returns the oldest live, matching-topic slots (FIFO) and marks
/// them claimed (not yet acked); ack removes a slot by id; nack returns it to
/// the live, unclaimed pool for redelivery.
const MockQueue = struct {
    const capacity = 64;
    const Slot = struct {
        id: i64 = 0,
        topic: [64]u8 = undefined,
        topic_len: usize = 0,
        payload: [queue_item_payload_cap]u8 = undefined,
        payload_len: usize = 0,
        live: bool = false, // occupied (enqueued, not yet acked)
        claimed: bool = false, // handed out by a dequeue, awaiting ack/nack
    };

    slots: [capacity]Slot = [_]Slot{.{}} ** capacity,
    next_id: i64 = 1,

    fn topicEql(self: *const MockQueue, idx: usize, topic: []const u8) bool {
        return std.mem.eql(u8, self.slots[idx].topic[0..self.slots[idx].topic_len], topic);
    }

    fn enqueueImpl(ptr: *anyopaque, topic: []const u8, payload: []const u8) Error!void {
        const self: *MockQueue = @ptrCast(@alignCast(ptr));
        if (topic.len > 64) return Error.BufferTooSmall;
        if (payload.len > queue_item_payload_cap) return Error.BufferTooSmall;
        var i: usize = 0;
        while (i < capacity) : (i += 1) {
            if (!self.slots[i].live) {
                var s = &self.slots[i];
                s.id = self.next_id;
                self.next_id += 1;
                @memcpy(s.topic[0..topic.len], topic);
                s.topic_len = topic.len;
                @memcpy(s.payload[0..payload.len], payload);
                s.payload_len = payload.len;
                s.live = true;
                s.claimed = false;
                return;
            }
        }
        return Error.BackendFailed; // queue full
    }

    fn dequeueBatchImpl(ptr: *anyopaque, topic: []const u8, out: []QueueItem) Error!usize {
        const self: *MockQueue = @ptrCast(@alignCast(ptr));
        var n: usize = 0;
        // FIFO: lowest id first among live, unclaimed, matching-topic slots.
        while (n < out.len) {
            var best: ?usize = null;
            var i: usize = 0;
            while (i < capacity) : (i += 1) {
                const s = &self.slots[i];
                if (s.live and !s.claimed and self.topicEql(i, topic)) {
                    if (best == null or s.id < self.slots[best.?].id) best = i;
                }
            }
            const idx = best orelse break;
            const s = &self.slots[idx];
            out[n].id = s.id;
            try out[n].setPayload(s.payload[0..s.payload_len]);
            s.claimed = true;
            n += 1;
        }
        return n;
    }

    fn ackImpl(ptr: *anyopaque, id: i64) Error!void {
        const self: *MockQueue = @ptrCast(@alignCast(ptr));
        var i: usize = 0;
        while (i < capacity) : (i += 1) {
            if (self.slots[i].live and self.slots[i].id == id) {
                self.slots[i] = .{}; // free the slot
                return;
            }
        }
        return Error.NotFound;
    }

    fn nackImpl(ptr: *anyopaque, id: i64) Error!void {
        const self: *MockQueue = @ptrCast(@alignCast(ptr));
        var i: usize = 0;
        while (i < capacity) : (i += 1) {
            if (self.slots[i].live and self.slots[i].id == id) {
                self.slots[i].claimed = false; // redeliver
                return;
            }
        }
        return Error.NotFound;
    }

    const vtable = Queue.VTable{
        .enqueue = enqueueImpl,
        .dequeueBatch = dequeueBatchImpl,
        .ack = ackImpl,
        .nack = nackImpl,
    };

    fn queue(self: *MockQueue) Queue {
        return .{ .ptr = self, .vtable = &vtable };
    }
    fn liveCount(self: *const MockQueue) usize {
        var n: usize = 0;
        for (self.slots) |s| {
            if (s.live) n += 1;
        }
        return n;
    }
};

// ---- Test entities ------------------------------------------------------

const Role = enum { member, admin, owner };

const Rich = struct {
    pub const zorm_table = "rich_msg";
    id: fields.Pk(64) = .{}, // text PK
    handle: fields.Text(128) = .{},
    bio: ?fields.Text(256) = null,
    role: Role = .member,
    active: bool = false,
    count: i64 = 0,
    ratio: f64 = 0,
};

const AutoThing = struct {
    pub const zorm_table = "auto_msg";
    id: fields.AutoPk = .{}, // auto/int PK
    name: fields.Text(32) = .{},
    n: i64 = 0,
};

/// A structurally-different entity (different fields → different fingerprint)
/// for the wrong-schema rejection test.
const Other = struct {
    pub const zorm_table = "other_msg";
    id: fields.Pk(64) = .{},
    title: fields.Text(64) = .{},
    weight: f64 = 0,
};

fn randomRich(prng: *std.Random.DefaultPrng, bio_present: bool) Rich {
    const rnd = prng.random();
    var v: Rich = .{};
    var sbuf: [300]u8 = undefined;

    const id_len = rnd.intRangeAtMost(usize, 1, 64);
    for (0..id_len) |i| sbuf[i] = rnd.intRangeAtMost(u8, 'a', 'z');
    v.id.set(sbuf[0..id_len]);

    const h_len = rnd.intRangeAtMost(usize, 0, 128);
    for (0..h_len) |i| sbuf[i] = rnd.intRangeAtMost(u8, 'A', 'Z');
    v.handle.set(sbuf[0..h_len]);

    if (bio_present) {
        const b_len = rnd.intRangeAtMost(usize, 0, 256);
        for (0..b_len) |i| sbuf[i] = rnd.intRangeAtMost(u8, ' ', '~');
        var bio: fields.Text(256) = .{};
        bio.set(sbuf[0..b_len]);
        v.bio = bio;
    } else {
        v.bio = null;
    }

    v.role = switch (rnd.intRangeAtMost(u8, 0, 2)) {
        0 => .member,
        1 => .admin,
        else => .owner,
    };
    v.active = rnd.boolean();
    v.count = rnd.int(i64);
    v.ratio = @bitCast(rnd.int(u64));
    return v;
}

fn expectRichEqual(a: *const Rich, b: *const Rich) !void {
    try testing.expectEqualStrings(a.id.slice(), b.id.slice());
    try testing.expectEqualStrings(a.handle.slice(), b.handle.slice());
    if (a.bio == null) {
        try testing.expect(b.bio == null);
    } else {
        try testing.expect(b.bio != null);
        try testing.expectEqualStrings(a.bio.?.slice(), b.bio.?.slice());
    }
    try testing.expectEqual(a.role, b.role);
    try testing.expectEqual(a.active, b.active);
    try testing.expectEqual(a.count, b.count);
    try testing.expectEqual(@as(u64, @bitCast(a.ratio)), @as(u64, @bitCast(b.ratio)));
}

test "publish → consume round-trips a rich entity (randomized, bio present + null)" {
    var prng = std.Random.DefaultPrng.init(0x5005_1A15);
    var sink_state = MockSink{};
    const sink = sink_state.sink();
    var scratch: [4096]u8 = undefined;

    var iter: usize = 0;
    while (iter < 32) : (iter += 1) {
        const bio_present = (iter & 1) == 0;
        const src = randomRich(&prng, bio_present);

        try publish(Rich, sink, "rich-topic", &src, &scratch);
        try testing.expectEqualStrings("rich-topic", sink_state.lastTopic());

        var dst: Rich = .{};
        dst.bio = fields.Text(256).from("poison"); // prove null is written
        try consume(Rich, sink_state.lastPayload(), &dst);
        try expectRichEqual(&src, &dst);
    }
    try testing.expectEqual(@as(usize, 32), sink_state.count);
}

test "published key == text PK bytes" {
    var sink_state = MockSink{};
    const sink = sink_state.sink();
    var scratch: [1024]u8 = undefined;

    var src: Rich = .{};
    src.id.set("did:plc:alice123");
    src.handle.set("alice");

    try publish(Rich, sink, "t", &src, &scratch);
    try testing.expectEqualStrings("did:plc:alice123", sink_state.lastKey());
}

test "published key == decimal of an auto/int PK" {
    var sink_state = MockSink{};
    const sink = sink_state.sink();
    var scratch: [1024]u8 = undefined;

    var src: AutoThing = .{};
    src.id.value = 9876543210;
    src.name.set("widget");
    src.n = 7;

    try publish(AutoThing, sink, "t", &src, &scratch);
    try testing.expectEqualStrings("9876543210", sink_state.lastKey());

    // keyFor directly, for a few more values.
    var kb: [32]u8 = undefined;
    var z: AutoThing = .{};
    z.id.value = 0;
    try testing.expectEqualStrings("0", try keyFor(AutoThing, &z, &kb));
    z.id.value = -42;
    try testing.expectEqualStrings("-42", try keyFor(AutoThing, &z, &kb));
}

test "enqueue several, claim a batch, ack removes them" {
    var q_state = MockQueue{};
    const q = q_state.queue();
    var scratch: [1024]u8 = undefined;

    var prng = std.Random.DefaultPrng.init(0xC1A1_3D);
    const total = 5;
    var sent: [total]AutoThing = undefined;
    var i: usize = 0;
    while (i < total) : (i += 1) {
        var v: AutoThing = .{};
        v.id.value = @intCast(i + 1);
        v.n = prng.random().int(i64);
        v.name.set("item");
        sent[i] = v;
        try enqueue(AutoThing, q, "jobs", &v, &scratch);
    }
    try testing.expectEqual(@as(usize, total), q_state.liveCount());

    // Claim a batch of 3.
    var items: [3]QueueItem = undefined;
    var vals: [3]AutoThing = undefined;
    const claimed = try claim(AutoThing, q, "jobs", &items, &vals);
    try testing.expectEqual(@as(usize, 3), claimed);

    // Deserialized values match the first three sent (FIFO).
    i = 0;
    while (i < claimed) : (i += 1) {
        try testing.expectEqual(sent[i].id.value, vals[i].id.value);
        try testing.expectEqual(sent[i].n, vals[i].n);
        try testing.expectEqualStrings(sent[i].name.slice(), vals[i].name.slice());
    }

    // Ack the claimed ids → they're removed.
    i = 0;
    while (i < claimed) : (i += 1) {
        try q.ack(items[i].id);
    }
    try testing.expectEqual(@as(usize, total - 3), q_state.liveCount());

    // A second claim returns only the remaining 2.
    var items2: [10]QueueItem = undefined;
    var vals2: [10]AutoThing = undefined;
    const claimed2 = try claim(AutoThing, q, "jobs", &items2, &vals2);
    try testing.expectEqual(@as(usize, 2), claimed2);

    // Ack the rest → queue empty → a third claim returns zero.
    i = 0;
    while (i < claimed2) : (i += 1) try q.ack(items2[i].id);
    var items3: [4]QueueItem = undefined;
    var vals3: [4]AutoThing = undefined;
    try testing.expectEqual(@as(usize, 0), try claim(AutoThing, q, "jobs", &items3, &vals3));
}

test "nack returns an item for redelivery" {
    var q_state = MockQueue{};
    const q = q_state.queue();
    var scratch: [512]u8 = undefined;

    var v: AutoThing = .{};
    v.id.value = 1;
    v.n = 99;
    v.name.set("retry");
    try enqueue(AutoThing, q, "jobs", &v, &scratch);

    var items: [4]QueueItem = undefined;
    var vals: [4]AutoThing = undefined;
    try testing.expectEqual(@as(usize, 1), try claim(AutoThing, q, "jobs", &items, &vals));
    // While claimed, it is not re-handed-out.
    var items_b: [4]QueueItem = undefined;
    var vals_b: [4]AutoThing = undefined;
    try testing.expectEqual(@as(usize, 0), try claim(AutoThing, q, "jobs", &items_b, &vals_b));

    // Nack → redelivered on the next claim.
    try q.nack(items[0].id);
    try testing.expectEqual(@as(usize, 1), try claim(AutoThing, q, "jobs", &items_b, &vals_b));
    try testing.expectEqual(@as(i64, 99), vals_b[0].n);
}

test "consume of a different-schema payload returns the codec error" {
    var sink_state = MockSink{};
    const sink = sink_state.sink();
    var scratch: [1024]u8 = undefined;

    // Sanity: the two entities really do have different fingerprints.
    try testing.expect(schema_desc.Schema(Rich).fingerprint != schema_desc.Schema(Other).fingerprint);

    var a: Rich = .{};
    a.id.set("k");
    a.handle.set("h");
    try publish(Rich, sink, "t", &a, &scratch);

    // Consume entity A's bytes as entity B → fingerprint mismatch → BadStatement.
    var b: Other = .{};
    try testing.expectError(Error.BadStatement, consume(Other, sink_state.lastPayload(), &b));
}

test "publishSchema yields JSON containing the table name + fingerprint" {
    var sink_state = MockSink{};
    const sink = sink_state.sink();
    var out: [2048]u8 = undefined;

    try publishSchema(Rich, sink, "schema-registry", &out);

    // Key is the table name.
    try testing.expectEqualStrings(schema_desc.Schema(Rich).table, sink_state.lastKey());

    const json = sink_state.lastPayload();
    try testing.expect(std.mem.indexOf(u8, json, "\"table\":\"rich_msg\"") != null);

    var fp_buf: [40]u8 = undefined;
    const fp_needle = try std.fmt.bufPrint(&fp_buf, "\"fingerprint\":{d}", .{schema_desc.Schema(Rich).fingerprint});
    try testing.expect(std.mem.indexOf(u8, json, fp_needle) != null);
}

test "keyFor: BufferTooSmall when the text PK exceeds key_buf" {
    var src: Rich = .{};
    src.id.set("a-long-primary-key-value");
    var tiny: [4]u8 = undefined;
    try testing.expectError(Error.BufferTooSmall, keyFor(Rich, &src, &tiny));
}

test "QueueItem.setPayload bounds the inline payload" {
    var item: QueueItem = .{};
    try item.setPayload("hello");
    try testing.expectEqualStrings("hello", item.payloadSlice());

    var big: [queue_item_payload_cap + 1]u8 = undefined;
    @memset(&big, 'x');
    try testing.expectError(Error.BufferTooSmall, item.setPayload(&big));
}
