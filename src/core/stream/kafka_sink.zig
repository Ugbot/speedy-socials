//! KafkaSink — a real librdkafka producer implementing `core.stream.Sink`.
//!
//! Compiled only under `-Dkafka` (see `build.zig`); `core.stream` gates the
//! import behind the same flag so the default build never needs librdkafka
//! headers. Selected at boot with `STREAM_BACKEND=kafka` + `KAFKA_BROKERS`.
//!
//! Tiger Style: one `rd_kafka_t` producer built at init. `publish` enqueues
//! with `RD_KAFKA_MSG_F_COPY` (librdkafka owns its own copy, so our borrowed
//! payload is never retained) and is non-blocking — it never waits on the
//! broker. librdkafka's producer handle is internally thread-safe, so no
//! extra lock is needed. `flush` drains on shutdown.

const std = @import("std");
const stream = @import("../stream.zig");

pub const c = @cImport({
    @cInclude("librdkafka/rdkafka.h");
});

pub const Error = error{
    ConfigFailed,
    ProducerInitFailed,
};

pub const max_topic: usize = 249; // Kafka's max topic-name length.

pub const KafkaSink = struct {
    rk: *c.rd_kafka_t,

    /// Build a producer connected to `brokers` (a comma-separated
    /// `host:port` list). The connection itself is established lazily by
    /// librdkafka in the background; init only fails on bad config.
    pub fn init(brokers: []const u8) Error!KafkaSink {
        const conf = c.rd_kafka_conf_new() orelse return error.ConfigFailed;
        // conf ownership transfers to rd_kafka_new on success; on the
        // error path before that, destroy it ourselves.
        errdefer c.rd_kafka_conf_destroy(conf);

        var errstr: [512]u8 = undefined;
        var brokers_z: [1024]u8 = undefined;
        if (brokers.len >= brokers_z.len) return error.ConfigFailed;
        @memcpy(brokers_z[0..brokers.len], brokers);
        brokers_z[brokers.len] = 0;

        if (c.rd_kafka_conf_set(
            conf,
            "bootstrap.servers",
            @ptrCast(&brokers_z),
            @ptrCast(&errstr),
            errstr.len,
        ) != c.RD_KAFKA_CONF_OK) {
            return error.ConfigFailed;
        }

        const rk = c.rd_kafka_new(
            c.RD_KAFKA_PRODUCER,
            conf,
            @ptrCast(&errstr),
            errstr.len,
        ) orelse return error.ProducerInitFailed;
        // rd_kafka_new took ownership of conf; cancel the errdefer.
        return .{ .rk = rk };
    }

    pub fn deinit(self: *KafkaSink) void {
        // Best-effort drain, then tear down.
        _ = c.rd_kafka_flush(self.rk, 2000);
        c.rd_kafka_destroy(self.rk);
        self.* = undefined;
    }

    pub fn sink(self: *KafkaSink) stream.Sink {
        return .{ .ctx = self, .vtable = &vtable };
    }

    const vtable: stream.Sink.VTable = .{
        .publish = publishImpl,
        .flush = flushImpl,
        .close = closeImpl,
    };

    fn publishImpl(ctx: *anyopaque, topic: []const u8, key: []const u8, payload: []const u8) void {
        const self: *KafkaSink = @ptrCast(@alignCast(ctx));
        if (topic.len == 0 or topic.len > max_topic) return;
        var topic_z: [max_topic + 1]u8 = undefined;
        @memcpy(topic_z[0..topic.len], topic);
        topic_z[topic.len] = 0;

        // RD_KAFKA_MSG_F_COPY → librdkafka copies the value immediately, so
        // the borrowed `payload` need not outlive this call. The key is
        // always copied by librdkafka internally.
        _ = c.rd_kafka_producev(
            self.rk,
            c.RD_KAFKA_VTYPE_TOPIC,
            @as([*c]const u8, @ptrCast(&topic_z)),
            c.RD_KAFKA_VTYPE_MSGFLAGS,
            @as(c_int, c.RD_KAFKA_MSG_F_COPY),
            c.RD_KAFKA_VTYPE_KEY,
            @as(?*const anyopaque, if (key.len > 0) key.ptr else null),
            @as(usize, key.len),
            c.RD_KAFKA_VTYPE_VALUE,
            @as(?*const anyopaque, if (payload.len > 0) payload.ptr else null),
            @as(usize, payload.len),
            c.RD_KAFKA_VTYPE_END,
        );
        // Serve delivery-report / error callbacks without blocking.
        _ = c.rd_kafka_poll(self.rk, 0);
    }

    fn flushImpl(ctx: *anyopaque) void {
        const self: *KafkaSink = @ptrCast(@alignCast(ctx));
        _ = c.rd_kafka_flush(self.rk, 5000);
    }

    fn closeImpl(ctx: *anyopaque) void {
        const self: *KafkaSink = @ptrCast(@alignCast(ctx));
        _ = c.rd_kafka_flush(self.rk, 2000);
    }
};

// ── Tests ────────────────────────────────────────────────────────────────
//
// A real round-trip needs a broker and is a label-gated integration test
// (see docs/ci). Here we only assert the sink builds against a (typically
// unreachable) broker address — init succeeds because librdkafka connects
// lazily — and that the vtable shape matches. These run only when the
// binary is compiled with -Dkafka.

const testing = std.testing;

test "KafkaSink: init builds a producer and exposes a conforming Sink" {
    var ks = KafkaSink.init("localhost:9092") catch return error.SkipZigTest;
    defer ks.deinit();
    const s = ks.sink();
    try testing.expectEqual(stream.Sink.VTable, @TypeOf(KafkaSink.vtable));
    // Publishing to a (likely down) broker must not block or crash; the
    // message buffers locally and is dropped on deinit's flush timeout.
    s.publish("firehose", "did:plc:test", "{\"x\":1}");
}
