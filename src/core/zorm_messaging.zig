//! Zero-cost bridges from this app's `core.stream` / `core.queue`
//! interfaces to the standalone `zorm` library's messaging contract, so a
//! zorm-typed entity can be published to the stream (Kafka/Redis/NATS) or
//! enqueued onto the work queue (DbQueue) carrying its codec'd payload +
//! schema — with no transport-specific code at the call site.
//!
//! These mirror `storage/zorm_adapter.zig` (the DB bridge): a thin struct
//! holds the source interface at a stable address and exposes a
//! `zorm.Sink` / `zorm.Queue` whose vtable forwards to it.

const std = @import("std");
const zorm = @import("zorm");
const stream = @import("stream.zig");
const queue = @import("queue.zig");
const clock_mod = @import("clock.zig");

// ── stream.Sink → zorm.Sink ──────────────────────────────────────────────

/// Wraps a `core.stream.Sink` as a `zorm.Sink`. zorm's publish supplies a
/// key (empty string ⇒ "no key"); core's sink takes an optional key.
pub const StreamSink = struct {
    src: stream.Sink,

    pub fn init(src: stream.Sink) StreamSink {
        return .{ .src = src };
    }

    pub fn sink(self: *StreamSink) zorm.Sink {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn publishImpl(ptr: *anyopaque, topic: []const u8, key: []const u8, payload: []const u8) zorm.Error!void {
        const self: *StreamSink = @ptrCast(@alignCast(ptr));
        const opt_key: ?[]const u8 = if (key.len == 0) null else key;
        self.src.publish(topic, opt_key, payload) catch |e| return switch (e) {
            error.InvalidMessage => zorm.Error.BadBinding,
            error.PublishFailed => zorm.Error.BackendFailed,
        };
    }

    const vtable = zorm.Sink.VTable{ .publish = publishImpl };
};

// ── queue.QueueProvider → zorm.Queue ─────────────────────────────────────

/// Wraps a `core.queue.QueueProvider` as a `zorm.Queue`. zorm's queue model
/// is deliberately simpler than core's (no meta, no explicit not-before/
/// retry time): enqueued jobs are eligible immediately and a nack reschedules
/// for immediate retry. The wall clock provides the `now`/eligibility time
/// core needs. ack/nack key purely on the job id (the provider's SQL does
/// too), so the topic is irrelevant there.
pub const QueueBridge = struct {
    provider: queue.QueueProvider,
    clock: clock_mod.Clock,

    pub fn init(provider: queue.QueueProvider, clock: clock_mod.Clock) QueueBridge {
        return .{ .provider = provider, .clock = clock };
    }

    pub fn queueIface(self: *QueueBridge) zorm.Queue {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn mapErr(e: queue.Error) zorm.Error {
        return switch (e) {
            error.QueueFull => zorm.Error.BackendFailed,
            error.BackendFailed => zorm.Error.BackendFailed,
            error.PayloadTooLarge => zorm.Error.BufferTooSmall,
        };
    }

    fn enqueueImpl(ptr: *anyopaque, topic: []const u8, payload: []const u8) zorm.Error!void {
        const self: *QueueBridge = @ptrCast(@alignCast(ptr));
        const now = self.clock.wallUnix();
        self.provider.enqueue(topic, "", payload, "", now) catch |e| return mapErr(e);
    }

    /// Max jobs peeked per `dequeueBatch` call. `core.queue.Job` is large
    /// (~8.7 KiB) and the temp batch lives on the stack, so this is bounded;
    /// `dequeueBatch` is a PEEK (rows stay pending until ack/nack), so a
    /// larger `out` is served across successive claim→ack cycles, not by
    /// looping here (which would re-read the same un-acked rows).
    const max_peek: usize = 16;

    fn dequeueBatchImpl(ptr: *anyopaque, topic: []const u8, out: []zorm.QueueItem) zorm.Error!usize {
        const self: *QueueBridge = @ptrCast(@alignCast(ptr));
        const now = self.clock.wallUnix();

        var jobs: [max_peek]queue.Job = undefined;
        const want = @min(@min(jobs.len, out.len), max_peek);
        if (want == 0) return 0;
        const got = self.provider.dequeueBatch(topic, now, jobs[0..want]) catch |e| return mapErr(e);
        for (jobs[0..got], 0..) |*job, i| {
            out[i].id = job.id;
            out[i].setPayload(job.payload()) catch |e| return e;
        }
        return got;
    }

    fn ackImpl(ptr: *anyopaque, id: i64) zorm.Error!void {
        const self: *QueueBridge = @ptrCast(@alignCast(ptr));
        var job = queue.Job{ .id = id };
        self.provider.ack("", &job) catch |e| return mapErr(e);
    }

    fn nackImpl(ptr: *anyopaque, id: i64) zorm.Error!void {
        const self: *QueueBridge = @ptrCast(@alignCast(ptr));
        var job = queue.Job{ .id = id };
        const retry_at = self.clock.wallUnix(); // eligible again immediately
        self.provider.nack("", &job, retry_at) catch |e| return mapErr(e);
    }

    const vtable = zorm.Queue.VTable{
        .enqueue = enqueueImpl,
        .dequeueBatch = dequeueBatchImpl,
        .ack = ackImpl,
        .nack = nackImpl,
    };
};

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

/// An event entity that is BOTH persistable and transportable by zorm.
const PostEvent = struct {
    pub const zorm_table = "post_events";
    id: zorm.Pk(64) = .{},
    actor: zorm.Text(64) = .{},
    body: zorm.Text(128) = .{},
    likes: i64 = 0,
};

test "StreamSink: publish a typed entity through a core.stream sink" {
    // A capturing core.stream.Sink.
    const Capture = struct {
        topic_buf: [64]u8 = undefined,
        topic_len: usize = 0,
        key_buf: [64]u8 = undefined,
        key_len: usize = 0,
        payload_buf: [512]u8 = undefined,
        payload_len: usize = 0,
        count: u32 = 0,

        fn pub_(ptr: *anyopaque, topic: []const u8, key: ?[]const u8, payload: []const u8) stream.Error!void {
            const s: *@This() = @ptrCast(@alignCast(ptr));
            @memcpy(s.topic_buf[0..topic.len], topic);
            s.topic_len = topic.len;
            if (key) |k| {
                @memcpy(s.key_buf[0..k.len], k);
                s.key_len = k.len;
            }
            @memcpy(s.payload_buf[0..payload.len], payload);
            s.payload_len = payload.len;
            s.count += 1;
        }
        fn flush_(_: *anyopaque) stream.Error!void {}
        fn close_(_: *anyopaque) void {}
        const vt = stream.Sink.VTable{ .publish = pub_, .flush = flush_, .close = close_ };
    };
    var cap = Capture{};
    const core_sink = stream.Sink{ .ptr = &cap, .vtable = &Capture.vt };

    var bridge = StreamSink.init(core_sink);
    const zsink = bridge.sink();

    var ev = PostEvent{
        .id = zorm.Pk(64).from("evt-1"),
        .actor = zorm.Text(64).from("did:plc:alice"),
        .body = zorm.Text(128).from("hello world"),
        .likes = 42,
    };
    var scratch: [512]u8 = undefined;
    try zorm.publish(PostEvent, zsink, "social.posts", &ev, &scratch);

    try testing.expectEqual(@as(u32, 1), cap.count);
    try testing.expectEqualStrings("social.posts", cap.topic_buf[0..cap.topic_len]);
    // Key derived from the PK.
    try testing.expectEqualStrings("evt-1", cap.key_buf[0..cap.key_len]);

    // The captured payload deserializes back to the same entity.
    var got: PostEvent = .{};
    try zorm.consume(PostEvent, cap.payload_buf[0..cap.payload_len], &got);
    try testing.expectEqualStrings("did:plc:alice", got.actor.slice());
    try testing.expectEqualStrings("hello world", got.body.slice());
    try testing.expectEqual(@as(i64, 42), got.likes);
}

test "QueueBridge: typed enqueue + claim + ack through DbQueue on real SQLite" {
    const storage = @import("storage.zig");
    const sqlite = storage.sqlite;
    const db_queue = @import("queue/db_queue.zig");

    const c = @import("sqlite").c;
    const db = try sqlite.openWriter(":memory:");
    defer sqlite.closeDb(db);
    const sql_z = try testing.allocator.dupeZ(u8, queue.db_queue_migration.up);
    defer testing.allocator.free(sql_z);
    var em: [*c]u8 = null;
    _ = c.sqlite3_exec(db, sql_z.ptr, null, null, &em);
    if (em != null) c.sqlite3_free(em);

    var dq = db_queue.DbQueue.init(db);
    var sim = clock_mod.SimClock.init(1_700_000_000);

    var bridge = QueueBridge.init(dq.provider(), sim.clock());
    const zq = bridge.queueIface();

    // Enqueue three typed events.
    var scratch: [512]u8 = undefined;
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        var ev = PostEvent{ .likes = @intCast(i) };
        var idb: [64]u8 = undefined;
        ev.id.set(std.fmt.bufPrint(&idb, "e{d}", .{i}) catch unreachable);
        ev.actor.set("did:plc:bob");
        ev.body.set("queued body");
        try zorm.enqueue(PostEvent, zq, "jobs.posts", &ev, &scratch);
    }

    // Claim the batch as typed values.
    var items: [8]zorm.QueueItem = undefined;
    var vals: [8]PostEvent = undefined;
    const n = try zorm.claim(PostEvent, zq, "jobs.posts", &items, &vals);
    try testing.expectEqual(@as(usize, 3), n);
    for (vals[0..n]) |v| {
        try testing.expectEqualStrings("did:plc:bob", v.actor.slice());
        try testing.expectEqualStrings("queued body", v.body.slice());
    }

    // Ack them; a second claim is empty.
    for (items[0..n]) |*it| try zq.ack(it.id);
    var items2: [8]zorm.QueueItem = undefined;
    var vals2: [8]PostEvent = undefined;
    try testing.expectEqual(@as(usize, 0), try zorm.claim(PostEvent, zq, "jobs.posts", &items2, &vals2));
}
