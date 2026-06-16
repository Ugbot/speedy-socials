//! Redis streaming sink — XADD to a Redis Stream.
//!
//! Backed by the vendored pure-Zig `lalinsky/redis.zig` driver (built on
//! `std.Io`, no system libs). The sink owns one `redis.Client` for the
//! whole process lifetime; the client carries a small connection pool,
//! so `publish` reuses a pooled connection rather than allocating per
//! call.
//!
//! `publish(topic, key, payload)` issues:
//!     XADD <topic> * key <key> payload <payload>
//! which appends one entry to the stream named `topic`. XADD returns the
//! generated entry ID (a bulk string) which we read into a small stack
//! buffer and discard — we only care that the command succeeded.
//!
//! There is no high-level publish in the driver, so we drop to the raw
//! `Protocol.execBulkString` path: acquire a `*Connection` from the
//! client pool, run the command over `conn.protocol()`, then release the
//! connection back to the pool (marking it healthy/unhealthy so the pool
//! can recycle a broken socket). This mirrors how the driver's own
//! `Client.del`/`incr` helpers get a connection.

const std = @import("std");
const redis = @import("redis");
const stream = @import("../stream.zig");
const core_log = @import("../log.zig");
const rng_mod = @import("../rng.zig");

pub const RedisSink = struct {
    client: redis.Client,

    /// Connect to `server` (host:port, e.g. "127.0.0.1:6379"). The
    /// returned sink owns the client and must be `deinit`-ed at process
    /// exit.
    pub fn init(gpa: std.mem.Allocator, io: std.Io, server: []const u8) !RedisSink {
        const client = try redis.Client.init(gpa, io, server, .{});
        return .{ .client = client };
    }

    pub fn deinit(self: *RedisSink) void {
        self.client.deinit();
    }

    /// XADD one entry. Best-effort at the `stream.publish` layer; this
    /// returns `error.PublishFailed` on any driver/broker error so the
    /// caller can log+swallow.
    fn doPublish(ptr: *anyopaque, topic: []const u8, key: ?[]const u8, payload: []const u8) stream.Error!void {
        const self: *RedisSink = @ptrCast(@alignCast(ptr));
        const k = key orelse "";

        const conn = self.client.pool.acquire() catch return error.PublishFailed;
        var ok = false;
        defer self.client.pool.release(conn, ok);

        const proto = conn.protocol();
        // XADD <topic> * key <k> payload <payload>. Bounds are enforced
        // by Sink.publish before we get here.
        var id_buf: [64]u8 = undefined;
        _ = proto.execBulkString(
            &.{ "XADD", topic, "*", "key", k, "payload", payload },
            &id_buf,
        ) catch |err| {
            // Connection is only safe to reuse if the protocol stream is
            // still intact; the driver tells us via isResumable.
            ok = redis.Protocol.isResumable(err);
            return error.PublishFailed;
        };
        ok = true;
    }

    fn doFlush(_: *anyopaque) stream.Error!void {
        // XADD is synchronous (we read the reply before returning), so
        // there is nothing buffered to flush.
        return;
    }

    fn doClose(ptr: *anyopaque) void {
        const self: *RedisSink = @ptrCast(@alignCast(ptr));
        self.deinit();
    }

    pub fn sink(self: *RedisSink) stream.Sink {
        return .{ .ptr = self, .vtable = &.{ .publish = doPublish, .flush = doFlush, .close = doClose } };
    }
};

// ──────────────────────────────────────────────────────────────────────
// Live round-trip test.
//
// Skips (error.SkipZigTest) when no Redis broker is reachable on
// 127.0.0.1:6379. When the broker is up, it XADDs to a uniquely-named
// test stream and verifies the entry landed via XLEN.
// ──────────────────────────────────────────────────────────────────────

const test_server = "127.0.0.1:6379";

test "RedisSink live XADD round-trip (skips if no broker)" {
    const gpa = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var rsink = RedisSink.init(gpa, io, test_server) catch return error.SkipZigTest;
    defer rsink.deinit();

    // Probe with a PING so we skip cleanly when the port is open but the
    // server is not actually speaking RESP (or is down).
    rsink.client.ping() catch return error.SkipZigTest;

    const s = rsink.sink();

    // Unique stream name per run so repeated runs don't accumulate.
    var prng = rng_mod.Rng.initFromOs();
    var name_buf: [64]u8 = undefined;
    const seed = prng.random().int(u64);
    const topic = std.fmt.bufPrint(&name_buf, "speedy:test:stream:{x}", .{seed}) catch unreachable;

    // Publish a handful of randomized messages.
    const n: usize = 5;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        var key_buf: [32]u8 = undefined;
        var payload_buf: [64]u8 = undefined;
        const key = std.fmt.bufPrint(&key_buf, "k{d}", .{i}) catch unreachable;
        const payload = std.fmt.bufPrint(&payload_buf, "payload-{x}-{d}", .{ prng.random().int(u32), i }) catch unreachable;
        try s.publish(topic, key, payload);
    }
    try s.flush();

    // Verify with XLEN via a raw command on a pooled connection.
    const conn = try rsink.client.pool.acquire();
    var ok = false;
    defer rsink.client.pool.release(conn, ok);
    const proto = conn.protocol();
    const len = try proto.execInteger(&.{ "XLEN", topic });
    ok = true;
    try std.testing.expectEqual(@as(i64, @intCast(n)), len);

    // Clean up the test stream (best-effort).
    _ = proto.execInteger(&.{ "DEL", topic }) catch {};
}

test "RedisSink unreachable broker yields PublishFailed, never crashes" {
    const gpa = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Port 1 is reserved/unused — init may succeed (lazy connect) but
    // publish must fail gracefully, not panic.
    var rsink = RedisSink.init(gpa, io, "127.0.0.1:1") catch return;
    defer rsink.deinit();
    const s = rsink.sink();
    const r = s.publish("speedy:test:unreachable", "k", "p");
    try std.testing.expectError(error.PublishFailed, r);
}

test {
    std.testing.refAllDecls(RedisSink);
    _ = core_log;
}
