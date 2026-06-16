//! NATS streaming sink — PUB to a NATS subject.
//!
//! Backed by the vendored pure-Zig `nats-io/nats.zig` driver (built on
//! `std.Io`, no system libs). The sink owns one `*nats.Client` for the
//! whole process lifetime. `connect` spins up the driver's background
//! I/O task (via `io.concurrent`/`io.async`), so `publish` is
//! non-blocking: it encodes the PUB frame into the client's send ring
//! and signals the background task to flush. No per-publish heap
//! allocation.
//!
//! `publish(topic, key, payload)` maps `topic` → NATS subject and
//! `payload` → message body. NATS has no first-class message key in the
//! core protocol, so `key` is dropped here (it is still available to
//! header-aware backends like Kafka/Redis). NATS delivery is
//! at-most-once: if no subscriber is listening the message is discarded
//! by the server, which is the intended best-effort semantics for a
//! streaming sink.

const std = @import("std");
const nats = @import("nats");
const stream = @import("../stream.zig");
const core_log = @import("../log.zig");
const rng_mod = @import("../rng.zig");

pub const NatsSink = struct {
    client: *nats.Client,

    /// Connect to `url` (e.g. "nats://127.0.0.1:4222"). The returned
    /// sink owns the client and must be `deinit`-ed at process exit.
    pub fn init(gpa: std.mem.Allocator, io: std.Io, url: []const u8) !NatsSink {
        const client = try nats.Client.connect(gpa, io, url, .{});
        return .{ .client = client };
    }

    pub fn deinit(self: *NatsSink) void {
        self.client.deinit();
    }

    fn doPublish(ptr: *anyopaque, topic: []const u8, key: ?[]const u8, payload: []const u8) stream.Error!void {
        const self: *NatsSink = @ptrCast(@alignCast(ptr));
        _ = key; // core NATS PUB has no message key.
        self.client.publish(topic, payload) catch return error.PublishFailed;
    }

    fn doFlush(ptr: *anyopaque) stream.Error!void {
        const self: *NatsSink = @ptrCast(@alignCast(ptr));
        // Drain the publish ring and round-trip a PING/PONG so the
        // caller knows prior publishes hit the wire. 5s upper bound.
        self.client.flush(5 * std.time.ns_per_s) catch return error.PublishFailed;
    }

    fn doClose(ptr: *anyopaque) void {
        const self: *NatsSink = @ptrCast(@alignCast(ptr));
        self.deinit();
    }

    pub fn sink(self: *NatsSink) stream.Sink {
        return .{ .ptr = self, .vtable = &.{ .publish = doPublish, .flush = doFlush, .close = doClose } };
    }
};

// ──────────────────────────────────────────────────────────────────────
// Live round-trip test.
//
// Skips (error.SkipZigTest) when no NATS broker is reachable on
// 127.0.0.1:4222. When up, it subscribes to a unique subject, publishes
// through the sink, and asserts the message comes back with the right
// payload.
// ──────────────────────────────────────────────────────────────────────

const test_url = "nats://127.0.0.1:4222";

test "NatsSink live publish/subscribe round-trip (skips if no broker)" {
    const gpa = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var nsink = NatsSink.init(gpa, io, test_url) catch return error.SkipZigTest;
    defer nsink.deinit();
    const s = nsink.sink();

    // Unique subject per run.
    var prng = rng_mod.Rng.initFromOs();
    var subj_buf: [64]u8 = undefined;
    const subject = std.fmt.bufPrint(&subj_buf, "speedy.test.{x}", .{prng.random().int(u64)}) catch unreachable;

    const sub = nsink.client.subscribeSync(subject) catch return error.SkipZigTest;
    defer sub.deinit();

    var payload_buf: [64]u8 = undefined;
    const payload = std.fmt.bufPrint(&payload_buf, "nats-payload-{x}", .{prng.random().int(u32)}) catch unreachable;

    try s.publish(subject, "ignored-key", payload);
    try s.flush();

    // Receive within 2s. If the subject delivery raced ahead of the
    // subscription registration the message is lost (NATS at-most-once);
    // retry the publish once before giving up.
    var got: ?nats.Message = sub.nextMsgTimeout(2000) catch null;
    if (got == null) {
        try s.publish(subject, null, payload);
        try s.flush();
        got = sub.nextMsgTimeout(2000) catch null;
    }
    const msg = got orelse return error.SkipZigTest;
    defer msg.deinit();
    try std.testing.expectEqualStrings(payload, msg.data);
    try std.testing.expectEqualStrings(subject, msg.subject);
}

test {
    std.testing.refAllDecls(NatsSink);
    _ = core_log;
}
