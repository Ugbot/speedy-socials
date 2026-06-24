//! Redis/Valkey streaming sink — XADD to a Redis Stream.
//!
//! Backed by the IN-TREE pure-Zig RESP client (`core/redis/`: the from-
//! scratch hiredis-equivalent — `resp.zig` codec + `conn.zig` socket +
//! `pool.zig`). No vendored driver, no `std.Io`: the connection is a blocking
//! `std.c` TCP socket, exactly like the MySQL driver. The sink owns one
//! bounded connection pool for the process lifetime; `publish` checks out a
//! pooled connection, issues one command, and returns it.
//!
//! `publish(topic, key, payload)` issues:
//!     XADD <topic> * key <key> payload <payload>
//! appending one entry to the stream named `topic`. XADD returns the
//! generated entry ID (a bulk string) which we read into a small stack
//! buffer and discard — we only care that the command succeeded.

const std = @import("std");
const conn_mod = @import("../redis/conn.zig");
const pool_mod = @import("../redis/pool.zig");
const stream = @import("../stream.zig");
const core_log = @import("../log.zig");
const rng_mod = @import("../rng.zig");

/// Pooled connections per sink. Bounded (Tiger Style); publish acquires one.
const pool_capacity: usize = 8;

pub const RedisSink = struct {
    pool: *pool_mod.Pool,

    /// Connect to `server` (`host:port`, or `redis://[user:pass@]host:port
    /// [/db]`). Eagerly opens one connection so a bad/unreachable endpoint
    /// fails here, not on the first publish. Owns the pool; `deinit` at exit.
    pub fn init(gpa: std.mem.Allocator, server: []const u8) !RedisSink {
        const opts = parseServer(server);
        const pool = try pool_mod.Pool.init(gpa, opts, pool_capacity);
        return .{ .pool = pool };
    }

    pub fn deinit(self: *RedisSink) void {
        self.pool.deinit();
    }

    /// XADD one entry. Best-effort at the `stream.publish` layer; returns
    /// `error.PublishFailed` on any client/broker error so the caller can
    /// log + swallow.
    fn doPublish(ptr: *anyopaque, topic: []const u8, key: ?[]const u8, payload: []const u8) stream.Error!void {
        const self: *RedisSink = @ptrCast(@alignCast(ptr));
        const k = key orelse "";

        const c = self.pool.acquire() catch return error.PublishFailed;
        var ok = false;
        defer self.pool.release(c, ok);

        // XADD <topic> * key <k> payload <payload>. Bounds were enforced by
        // Sink.publish before we got here. The returned entry-id bulk is
        // copied into id_buf and discarded.
        var id_buf: [64]u8 = undefined;
        _ = c.execBulkString(&.{ "XADD", topic, "*", "key", k, "payload", payload }, &id_buf) catch {
            // Only recycle the connection if its byte stream is still aligned.
            ok = c.isHealthy();
            return error.PublishFailed;
        };
        ok = true;
    }

    fn doFlush(_: *anyopaque) stream.Error!void {
        // XADD is synchronous (the reply is read before returning) — nothing
        // is buffered to flush.
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

/// Parse `host:port` or `redis://[user:pass@]host:port[/db]` (also
/// `rediss://`, recognised but TLS not yet implemented) into client options.
fn parseServer(server: []const u8) conn_mod.Options {
    var s = server;
    inline for (.{ "redis://", "rediss://" }) |scheme| {
        if (std.mem.startsWith(u8, s, scheme)) {
            s = s[scheme.len..];
            break;
        }
    }
    var opts = conn_mod.Options{};
    if (std.mem.indexOfScalar(u8, s, '@')) |at| {
        const userinfo = s[0..at];
        s = s[at + 1 ..];
        if (std.mem.indexOfScalar(u8, userinfo, ':')) |colon| {
            if (colon > 0) opts.username = userinfo[0..colon];
            opts.password = userinfo[colon + 1 ..];
        } else if (userinfo.len > 0) {
            opts.password = userinfo;
        }
    }
    if (std.mem.indexOfScalar(u8, s, '/')) |slash| {
        opts.db = std.fmt.parseInt(u32, s[slash + 1 ..], 10) catch 0;
        s = s[0..slash];
    }
    if (std.mem.lastIndexOfScalar(u8, s, ':')) |colon| {
        opts.host = s[0..colon];
        opts.port = std.fmt.parseInt(u16, s[colon + 1 ..], 10) catch 6379;
    } else if (s.len > 0) {
        opts.host = s;
    }
    return opts;
}

// ──────────────────────────────────────────────────────────────────────
// Tests. The live round-trip skips (error.SkipZigTest) when no broker is
// reachable on 127.0.0.1:6379; the in-tree pool connects eagerly, so a
// missing broker surfaces as an init error we map to a skip.
// ──────────────────────────────────────────────────────────────────────

const test_server = "127.0.0.1:6379";

test "parseServer: host:port, scheme, auth, db" {
    {
        const o = parseServer("127.0.0.1:6379");
        try std.testing.expectEqualStrings("127.0.0.1", o.host);
        try std.testing.expectEqual(@as(u16, 6379), o.port);
        try std.testing.expect(o.password == null);
    }
    {
        const o = parseServer("redis://:secret@cache:6380/3");
        try std.testing.expectEqualStrings("cache", o.host);
        try std.testing.expectEqual(@as(u16, 6380), o.port);
        try std.testing.expectEqualStrings("secret", o.password.?);
        try std.testing.expectEqual(@as(u32, 3), o.db);
    }
    {
        const o = parseServer("rediss://u:p@h:7000");
        try std.testing.expectEqualStrings("h", o.host);
        try std.testing.expectEqualStrings("u", o.username.?);
        try std.testing.expectEqualStrings("p", o.password.?);
    }
}

test "RedisSink live XADD round-trip (skips if no broker)" {
    const gpa = std.testing.allocator;
    var rsink = RedisSink.init(gpa, test_server) catch return error.SkipZigTest;
    defer rsink.deinit();
    const s = rsink.sink();

    // Unique stream name per run so repeated runs don't accumulate.
    var prng = rng_mod.Rng.initFromOs();
    var name_buf: [64]u8 = undefined;
    const topic = std.fmt.bufPrint(&name_buf, "speedy:test:stream:{x}", .{prng.random().int(u64)}) catch unreachable;

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

    // Verify with XLEN, then clean up the stream.
    const c = try rsink.pool.acquire();
    var ok = false;
    defer rsink.pool.release(c, ok);
    const len = try c.execInteger(&.{ "XLEN", topic });
    ok = true;
    try std.testing.expectEqual(@as(i64, @intCast(n)), len);
    _ = c.execInteger(&.{ "DEL", topic }) catch {};
}

test "RedisSink unreachable broker fails gracefully (no crash)" {
    const gpa = std.testing.allocator;
    // Port 1 is reserved/unused. The eager pool connect should fail at init;
    // if it somehow succeeds, publish must fail rather than panic.
    var rsink = RedisSink.init(gpa, "127.0.0.1:1") catch return;
    defer rsink.deinit();
    const s = rsink.sink();
    try std.testing.expectError(error.PublishFailed, s.publish("speedy:test:unreachable", "k", "p"));
}

test {
    std.testing.refAllDecls(RedisSink);
    _ = core_log;
}
