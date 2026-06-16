//! Pluggable event-stream sink.
//!
//! Domain events (the AT firehose, relay translations) are published to
//! an external streaming system through a single `Sink` vtable so the
//! engine stays decoupled from any specific broker. Three implementations
//! ship in tree:
//!
//!   * `NullSink` — the default. Every publish is a no-op; zero cost
//!     beyond one optional-check + indirect call.
//!   * `LogSink`  — records published (topic, key, payload-length) into a
//!     bounded ring so tests can assert what was emitted without a broker.
//!   * `KafkaSink` — real librdkafka producer (compiled only under
//!     `-Dkafka`; see `stream/kafka_sink.zig`). Exposed here as
//!     `KafkaSink` when the build flag is set, otherwise absent.
//!
//! Selection happens at boot from `STREAM_BACKEND=null|log|kafka`.
//!
//! Tiger Style: no allocation on the publish path. `LogSink` stores a
//! fixed-size prefix of each payload in a static ring guarded by a
//! spinlock; the producer never blocks on a slow consumer.

const std = @import("std");
const build_options = @import("build_options");
const Spinlock = @import("static.zig").Spinlock;

pub const Sink = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Publish one event. `key` partitions/orders within a topic
        /// (e.g. the repo DID); `payload` is the serialized event. The
        /// callee must not retain `topic`/`key`/`payload` past the call.
        publish: *const fn (ctx: *anyopaque, topic: []const u8, key: []const u8, payload: []const u8) void,
        /// Block until buffered events are handed to the transport.
        flush: *const fn (ctx: *anyopaque) void,
        /// Release resources. Idempotent.
        close: *const fn (ctx: *anyopaque) void,
    };

    pub fn publish(self: Sink, topic: []const u8, key: []const u8, payload: []const u8) void {
        self.vtable.publish(self.ctx, topic, key, payload);
    }
    pub fn flush(self: Sink) void {
        self.vtable.flush(self.ctx);
    }
    pub fn close(self: Sink) void {
        self.vtable.close(self.ctx);
    }
};

// ── Global sink ─────────────────────────────────────────────────────────

var global_sink: ?Sink = null;

pub fn setGlobal(s: ?Sink) void {
    global_sink = s;
}

pub fn global() ?Sink {
    return global_sink;
}

/// Publish through the global sink, if one is installed. Safe to call
/// from any thread; the sink impl owns its own synchronisation.
pub fn publish(topic: []const u8, key: []const u8, payload: []const u8) void {
    if (global_sink) |s| s.publish(topic, key, payload);
}

pub fn flush() void {
    if (global_sink) |s| s.flush();
}

// ── NullSink (default) ───────────────────────────────────────────────────

pub const NullSink = struct {
    var inst: NullSink = .{};

    fn publishImpl(_: *anyopaque, _: []const u8, _: []const u8, _: []const u8) void {}
    fn flushImpl(_: *anyopaque) void {}
    fn closeImpl(_: *anyopaque) void {}

    const vtable: Sink.VTable = .{
        .publish = publishImpl,
        .flush = flushImpl,
        .close = closeImpl,
    };

    pub fn sink() Sink {
        return .{ .ctx = &inst, .vtable = &vtable };
    }
};

// ── LogSink (test / observability) ───────────────────────────────────────

pub const LogSink = struct {
    pub const max_records: usize = 256;
    pub const max_topic: usize = 64;
    pub const max_key: usize = 128;
    pub const max_payload_prefix: usize = 256;

    pub const Record = struct {
        topic_buf: [max_topic]u8 = undefined,
        topic_len: u16 = 0,
        key_buf: [max_key]u8 = undefined,
        key_len: u16 = 0,
        payload_len: usize = 0,
        payload_buf: [max_payload_prefix]u8 = undefined,
        payload_prefix_len: u16 = 0,

        pub fn topic(self: *const Record) []const u8 {
            return self.topic_buf[0..self.topic_len];
        }
        pub fn key(self: *const Record) []const u8 {
            return self.key_buf[0..self.key_len];
        }
        pub fn payloadPrefix(self: *const Record) []const u8 {
            return self.payload_buf[0..self.payload_prefix_len];
        }
    };

    records: [max_records]Record = undefined,
    /// Number of valid entries currently in the ring (≤ max_records).
    count: usize = 0,
    /// Next write slot (wraps).
    head: usize = 0,
    /// Total ever published (does not wrap) — useful for "how many".
    total: u64 = 0,
    lock: Spinlock = .{},

    fn publishImpl(ctx: *anyopaque, topic: []const u8, key: []const u8, payload: []const u8) void {
        const self: *LogSink = @ptrCast(@alignCast(ctx));
        self.lock.lock();
        defer self.lock.unlock();

        var r: Record = .{};
        const tn = @min(topic.len, max_topic);
        @memcpy(r.topic_buf[0..tn], topic[0..tn]);
        r.topic_len = @intCast(tn);
        const kn = @min(key.len, max_key);
        @memcpy(r.key_buf[0..kn], key[0..kn]);
        r.key_len = @intCast(kn);
        r.payload_len = payload.len;
        const pn = @min(payload.len, max_payload_prefix);
        @memcpy(r.payload_buf[0..pn], payload[0..pn]);
        r.payload_prefix_len = @intCast(pn);

        self.records[self.head] = r;
        self.head = (self.head + 1) % max_records;
        if (self.count < max_records) self.count += 1;
        self.total += 1;
    }

    fn flushImpl(_: *anyopaque) void {}
    fn closeImpl(_: *anyopaque) void {}

    const vtable: Sink.VTable = .{
        .publish = publishImpl,
        .flush = flushImpl,
        .close = closeImpl,
    };

    pub fn sink(self: *LogSink) Sink {
        return .{ .ctx = self, .vtable = &vtable };
    }

    /// Most-recently published record, or null if none.
    pub fn last(self: *LogSink) ?Record {
        self.lock.lock();
        defer self.lock.unlock();
        if (self.count == 0) return null;
        const idx = (self.head + max_records - 1) % max_records;
        return self.records[idx];
    }

    pub fn publishedCount(self: *LogSink) u64 {
        self.lock.lock();
        defer self.lock.unlock();
        return self.total;
    }
};

// ── KafkaSink (only under -Dkafka) ───────────────────────────────────────

/// Re-export the real librdkafka producer when the build flag is set. The
/// import is comptime-gated so the cImport (which needs librdkafka headers)
/// is never analysed in the default build.
pub const kafka_enabled = build_options.kafka;
pub const KafkaSink = if (build_options.kafka)
    @import("stream/kafka_sink.zig").KafkaSink
else
    struct {};

// ── Tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "NullSink: publish/flush/close are no-ops and global routing works" {
    setGlobal(NullSink.sink());
    defer setGlobal(null);
    // Must not crash; nothing observable.
    publish("firehose", "did:plc:abc", "payload");
    flush();
    global().?.close();
}

test "LogSink: records topic/key/payload and counts, ring wraps" {
    var ls: LogSink = .{};
    const s = ls.sink();

    var prng = std.Random.DefaultPrng.init(0x10_65_1_4);
    const rand = prng.random();

    // Publish more than the ring holds; total counts all, count caps.
    const n: usize = LogSink.max_records + 37;
    var i: usize = 0;
    var last_payload_len: usize = 0;
    while (i < n) : (i += 1) {
        var key_buf: [16]u8 = undefined;
        const klen = rand.intRangeAtMost(usize, 1, key_buf.len);
        rand.bytes(key_buf[0..klen]);
        var pay_buf: [600]u8 = undefined;
        const plen = rand.intRangeAtMost(usize, 0, pay_buf.len);
        rand.bytes(pay_buf[0..plen]);
        last_payload_len = plen;
        s.publish("firehose", key_buf[0..klen], pay_buf[0..plen]);
    }

    try testing.expectEqual(@as(u64, n), ls.publishedCount());
    try testing.expectEqual(LogSink.max_records, ls.count);

    const rec = ls.last() orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("firehose", rec.topic());
    // payload_len is the true length even when only a prefix is stored.
    try testing.expectEqual(last_payload_len, rec.payload_len);
    try testing.expect(rec.payloadPrefix().len <= LogSink.max_payload_prefix);
    try testing.expect(rec.payloadPrefix().len == @min(last_payload_len, LogSink.max_payload_prefix));
}

test "LogSink: oversized topic/key are truncated to the static buffers" {
    var ls: LogSink = .{};
    const s = ls.sink();
    const big_topic = "t" ** (LogSink.max_topic + 50);
    const big_key = "k" ** (LogSink.max_key + 50);
    s.publish(big_topic, big_key, "x");
    const rec = ls.last().?;
    try testing.expectEqual(@as(usize, LogSink.max_topic), rec.topic().len);
    try testing.expectEqual(@as(usize, LogSink.max_key), rec.key().len);
}

test "global publish with no sink installed is a silent no-op" {
    setGlobal(null);
    publish("firehose", "k", "v"); // must not crash
    flush();
}

test {
    // Pull the Kafka sink's tests into the test binary only when it is
    // compiled (so the default, librdkafka-free build stays unaffected).
    if (build_options.kafka) _ = @import("stream/kafka_sink.zig");
}
