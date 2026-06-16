//! Pluggable streaming sink.
//!
//! A `Sink` is a tiny vtable — `publish` / `flush` / `close` — over a
//! concrete backend. Backends are selected at boot by the operator via
//! the `STREAM_BACKEND` environment variable and installed as the
//! process-global sink with `setGlobal`. Publish sites call
//! `stream.publish(topic, key, payload)` and never learn which backend
//! is wired underneath.
//!
//! Backends (all runtime-selectable OPTIONS, never replacements):
//!   * `null`  — `NullSink`: drops every message. Default; zero cost.
//!   * `log`   — `LogSink`:  one ring-log line per publish. Dev default.
//!   * `redis` — `redis_sink.RedisSink`:  XADD to a Redis Stream.
//!   * `nats`  — `nats_sink.NatsSink`:    PUB to a NATS subject.
//!   * `kafka` — see `stream/kafka_sink.zig`. The vendored pure-Zig
//!               driver does not compile against this toolchain's
//!               stripped std (it depends on `std.time.milliTimestamp`,
//!               `std.net.Address`, and `std.Thread`, all absent here),
//!               so the Kafka backend is reported as unavailable rather
//!               than shipped as fake code. See that file for the full
//!               technical writeup.
//!
//! Tiger Style: the sink owns its client for the whole process
//! lifetime; `publish` is best-effort and bounded — a broker error is
//! logged and swallowed so a flaky broker can never crash the server.

const std = @import("std");
const core_log = @import("log.zig");
const Spinlock = @import("static.zig").Spinlock;

pub const redis_sink = @import("stream/redis_sink.zig");
pub const nats_sink = @import("stream/nats_sink.zig");
pub const kafka_sink = @import("stream/kafka_sink.zig");

/// Upper bound on a single topic/subject name. Keeps stack buffers in
/// the backends bounded and rejects pathological inputs at the door.
pub const max_topic_bytes: usize = 256;
/// Upper bound on a single message key.
pub const max_key_bytes: usize = 256;
/// Upper bound on a single payload. 1 MiB matches the NATS default
/// max_payload and is comfortably above any firehose frame.
pub const max_payload_bytes: usize = 1024 * 1024;

pub const Error = error{
    /// The topic/key/payload violated a bound. Caught at the vtable
    /// boundary so backends never see oversized inputs.
    InvalidMessage,
    /// The backend refused or could not deliver. Publish sites treat
    /// this as transient and best-effort; `stream.publish` swallows it.
    PublishFailed,
};

/// Which backend an operator asked for via `STREAM_BACKEND`.
pub const Backend = enum {
    null_sink,
    log,
    kafka,
    redis,
    nats,

    /// Parse the `STREAM_BACKEND` env value. `null`/empty → `null_sink`.
    pub fn parse(s: []const u8) ?Backend {
        if (s.len == 0) return .null_sink;
        if (std.mem.eql(u8, s, "null")) return .null_sink;
        if (std.mem.eql(u8, s, "log")) return .log;
        if (std.mem.eql(u8, s, "kafka")) return .kafka;
        if (std.mem.eql(u8, s, "redis")) return .redis;
        if (std.mem.eql(u8, s, "nats")) return .nats;
        return null;
    }
};

/// The runtime sink interface. Concrete backends expose a `sink()`
/// method returning one of these.
pub const Sink = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        publish: *const fn (ptr: *anyopaque, topic: []const u8, key: ?[]const u8, payload: []const u8) Error!void,
        flush: *const fn (ptr: *anyopaque) Error!void,
        close: *const fn (ptr: *anyopaque) void,
    };

    /// Publish one message. Validates bounds at the boundary, then
    /// forwards to the backend.
    pub fn publish(self: Sink, topic: []const u8, key: ?[]const u8, payload: []const u8) Error!void {
        if (topic.len == 0 or topic.len > max_topic_bytes) return error.InvalidMessage;
        if (key) |k| {
            if (k.len > max_key_bytes) return error.InvalidMessage;
        }
        if (payload.len > max_payload_bytes) return error.InvalidMessage;
        return self.vtable.publish(self.ptr, topic, key, payload);
    }

    pub fn flush(self: Sink) Error!void {
        return self.vtable.flush(self.ptr);
    }

    pub fn close(self: Sink) void {
        self.vtable.close(self.ptr);
    }
};

// ──────────────────────────────────────────────────────────────────────
// Process-global sink.
// ──────────────────────────────────────────────────────────────────────

var global_sink: ?Sink = null;

/// Install the process-global sink. Called once at boot. Not
/// thread-safe; intended to run before the accept loop starts.
pub fn setGlobal(s: ?Sink) void {
    global_sink = s;
}

pub fn global() ?Sink {
    return global_sink;
}

/// Best-effort publish through the global sink. A missing sink is a
/// no-op. A backend error is logged at `warn` and swallowed — a flaky
/// broker must never take down a publish site.
pub fn publish(topic: []const u8, key: ?[]const u8, payload: []const u8) void {
    const s = global_sink orelse return;
    s.publish(topic, key, payload) catch |err| {
        if (core_log.global()) |ring| {
            var buf: [192]u8 = undefined;
            const line = std.fmt.bufPrint(
                &buf,
                "stream publish dropped: topic={s} payload_bytes={d} err={s}",
                .{ topic, payload.len, @errorName(err) },
            ) catch buf[0..0];
            ring.record(.warn, "stream", line, &.{});
        }
    };
}

/// Best-effort flush through the global sink.
pub fn flush() void {
    const s = global_sink orelse return;
    s.flush() catch |err| {
        if (core_log.global()) |ring| {
            var buf: [96]u8 = undefined;
            const line = std.fmt.bufPrint(&buf, "stream flush failed: err={s}", .{@errorName(err)}) catch buf[0..0];
            ring.record(.warn, "stream", line, &.{});
        }
    };
}

// ──────────────────────────────────────────────────────────────────────
// NullSink — drops everything. Default backend, zero cost.
// ──────────────────────────────────────────────────────────────────────

pub const NullSink = struct {
    pub fn init() NullSink {
        return .{};
    }

    fn doPublish(_: *anyopaque, _: []const u8, _: ?[]const u8, _: []const u8) Error!void {
        return;
    }
    fn doFlush(_: *anyopaque) Error!void {
        return;
    }
    fn doClose(_: *anyopaque) void {
        return;
    }

    pub fn sink(self: *NullSink) Sink {
        return .{ .ptr = self, .vtable = &.{ .publish = doPublish, .flush = doFlush, .close = doClose } };
    }
};

// ──────────────────────────────────────────────────────────────────────
// LogSink — one ring-log line per publish. Dev default beyond `null`.
// ──────────────────────────────────────────────────────────────────────

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
    count: usize = 0,
    head: usize = 0,
    total: u64 = 0,
    lock: Spinlock = .{},

    pub fn init() LogSink {
        return .{};
    }

    fn doPublish(ptr: *anyopaque, topic: []const u8, key: ?[]const u8, payload: []const u8) Error!void {
        const self: *LogSink = @ptrCast(@alignCast(ptr));
        const k = key orelse "";
        self.lock.lock();
        defer self.lock.unlock();

        var r: Record = .{};
        const tn = @min(topic.len, max_topic);
        @memcpy(r.topic_buf[0..tn], topic[0..tn]);
        r.topic_len = @intCast(tn);
        const kn = @min(k.len, max_key);
        @memcpy(r.key_buf[0..kn], k[0..kn]);
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
    fn doFlush(_: *anyopaque) Error!void {
        return;
    }
    fn doClose(_: *anyopaque) void {
        return;
    }

    pub fn sink(self: *LogSink) Sink {
        return .{ .ptr = self, .vtable = &.{ .publish = doPublish, .flush = doFlush, .close = doClose } };
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

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

test "Backend.parse maps known values, null/empty default, unknown rejected" {
    try std.testing.expectEqual(Backend.null_sink, Backend.parse("").?);
    try std.testing.expectEqual(Backend.null_sink, Backend.parse("null").?);
    try std.testing.expectEqual(Backend.log, Backend.parse("log").?);
    try std.testing.expectEqual(Backend.kafka, Backend.parse("kafka").?);
    try std.testing.expectEqual(Backend.redis, Backend.parse("redis").?);
    try std.testing.expectEqual(Backend.nats, Backend.parse("nats").?);
    try std.testing.expectEqual(@as(?Backend, null), Backend.parse("rabbitmq"));
}

test "NullSink drops everything and never errors" {
    var ns = NullSink.init();
    const s = ns.sink();
    try s.publish("topic", "key", "payload");
    try s.publish("topic", null, "");
    try s.flush();
    s.close();
}

test "Sink.publish enforces bounds at the vtable boundary" {
    var ns = NullSink.init();
    const s = ns.sink();
    // Empty topic rejected.
    try std.testing.expectError(error.InvalidMessage, s.publish("", "k", "p"));
    // Oversized topic rejected.
    var big_topic: [max_topic_bytes + 1]u8 = undefined;
    @memset(&big_topic, 'a');
    try std.testing.expectError(error.InvalidMessage, s.publish(&big_topic, "k", "p"));
    // Oversized key rejected.
    var big_key: [max_key_bytes + 1]u8 = undefined;
    @memset(&big_key, 'k');
    try std.testing.expectError(error.InvalidMessage, s.publish("t", &big_key, "p"));
}

test "global setGlobal/publish is a no-op without a sink and routes when set" {
    setGlobal(null);
    publish("t", "k", "p"); // no sink: must not crash
    flush();

    var ns = NullSink.init();
    setGlobal(ns.sink());
    defer setGlobal(null);
    publish("t", "k", "p"); // routed; NullSink swallows
    flush();
    try std.testing.expect(global() != null);
}

test {
    _ = redis_sink;
    _ = nats_sink;
    _ = kafka_sink;
}
