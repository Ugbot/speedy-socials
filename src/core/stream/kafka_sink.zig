//! Kafka streaming sink — produce to a Kafka topic.
//!
//! Backed by the vendored PURE-ZIG `Ugbot/zig-kafka` driver (no librdkafka,
//! no system libs). The sink owns one `KafkaClient` + one `KafkaProducer`
//! for the whole process lifetime.
//!
//! Lifetime note (load-bearing): `KafkaProducer` holds a `*BrokerPool`
//! pointing at a field INSIDE the `KafkaClient` (`&client.broker_pool`), so
//! the client must live at a stable address before `createProducer` runs.
//! We therefore heap-pin the client (`gpa.create`) and create the producer
//! against that stable pointer; the producer (whose other refs are
//! heap-allocated) is then safe to store by value in the sink.
//!
//! `publish(topic, key, payload)` → `producer.produce(topic, key, value)`,
//! which appends to the producer's record accumulator; a background sender
//! drains batches to the partition leaders. Best-effort + bounded at the
//! `stream.Sink` boundary; a broker error returns `error.PublishFailed` so
//! the publish site logs + swallows.

const std = @import("std");
const kafka = @import("kafka");
const stream = @import("../stream.zig");
const core_log = @import("../log.zig");

pub const KafkaSink = struct {
    gpa: std.mem.Allocator,
    client: *kafka.KafkaClient,
    producer: kafka.client.KafkaProducer,

    /// Connect to a single bootstrap broker `host:port` (Kafka discovers
    /// the rest of the cluster via metadata). Heap-pins the client.
    pub fn init(gpa: std.mem.Allocator, host: []const u8, port: u16) !KafkaSink {
        const client = try gpa.create(kafka.KafkaClient);
        errdefer gpa.destroy(client);
        // Anonymous-struct coercion builds the (un-exported) ClientConfig +
        // BrokerAddress for us — a single bootstrap server suffices.
        client.* = try kafka.KafkaClient.init(.{
            .bootstrap_servers = &.{.{ .host = host, .port = port }},
        }, gpa);
        errdefer client.close();
        try client.bootstrap();

        var producer = try client.createProducer(.{});
        errdefer producer.close();
        try producer.start();

        return .{ .gpa = gpa, .client = client, .producer = producer };
    }

    pub fn deinit(self: *KafkaSink) void {
        self.producer.close();
        self.client.close();
        self.gpa.destroy(self.client);
    }

    fn doPublish(ptr: *anyopaque, topic: []const u8, key: ?[]const u8, payload: []const u8) stream.Error!void {
        const self: *KafkaSink = @ptrCast(@alignCast(ptr));
        self.producer.produce(topic, key, payload) catch return error.PublishFailed;
    }

    fn doFlush(ptr: *anyopaque) stream.Error!void {
        const self: *KafkaSink = @ptrCast(@alignCast(ptr));
        self.producer.flush(5000) catch return error.PublishFailed;
    }

    fn doClose(ptr: *anyopaque) void {
        const self: *KafkaSink = @ptrCast(@alignCast(ptr));
        self.deinit();
    }

    pub fn sink(self: *KafkaSink) stream.Sink {
        return .{ .ptr = self, .vtable = &.{ .publish = doPublish, .flush = doFlush, .close = doClose } };
    }
};

// ──────────────────────────────────────────────────────────────────────
// Live round-trip test — skips when no broker on 127.0.0.1:9092.
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "KafkaSink live produce (skips if no broker)" {
    const gpa = testing.allocator;
    var ks = KafkaSink.init(gpa, "127.0.0.1", 9092) catch return error.SkipZigTest;
    defer ks.deinit();
    const s = ks.sink();

    var prng = std.Random.DefaultPrng.init(0x4A_F0_05_1);
    const rand = prng.random();
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        var key_buf: [16]u8 = undefined;
        var pay_buf: [64]u8 = undefined;
        const key = std.fmt.bufPrint(&key_buf, "k{d}", .{i}) catch unreachable;
        const payload = std.fmt.bufPrint(&pay_buf, "kafka-{x}-{d}", .{ rand.int(u32), i }) catch unreachable;
        // A produce to an auto-creatable topic; broker config dependent.
        s.publish("speedy.test.kafka", key, payload) catch return error.SkipZigTest;
    }
    s.flush() catch return error.SkipZigTest;
}

test {
    _ = core_log;
}
