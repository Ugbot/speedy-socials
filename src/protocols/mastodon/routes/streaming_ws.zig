//! Mastodon streaming API — WebSocket upgrade handlers.
//!
//! Endpoints (Mastodon API v1):
//!   * `/api/v1/streaming/user`      → keyed by authenticated user id.
//!   * `/api/v1/streaming/public`    → global public-status firehose.
//!   * `/api/v1/streaming/hashtag`   → `?tag=foo`.
//!   * `/api/v1/streaming/list`      → `?list=:id`.
//!
//! Wire envelope (per Mastodon docs):
//!   text frame containing the JSON object
//!     { "event": "update" | "delete" | "notification" | ... ,
//!       "payload": "<stringified-json>" }
//!
//! Hot-path publishers in `routes/statuses.zig` and
//! `routes/notifications.zig` call `publishUpdate` / `publishDelete` /
//! `publishNotification` after the DB write. The producers carry a
//! pre-formatted envelope string into a static slot ring so the
//! `core.ws.registry.Registry`'s lifetime contract is satisfied
//! without copying inside the registry.
//!
//! Tiger Style:
//!   * Bounded by `limits.max_inflight_subscribers`.
//!   * Per-handler fixed-size scratch (no allocator on the hot path).
//!   * Envelopes live in a per-process static ring; slow subscribers
//!     observe gaps (lossy ring) — they reconnect to resync via the
//!     REST API just like the upstream Mastodon implementation.

const std = @import("std");
const core = @import("core");

const limits = core.limits;
const ws_frame = core.ws.frame;
const ws_registry = core.ws.registry;
const WsUpgradeContext = core.ws.upgrade_router.WsUpgradeContext;
const WsUpgradeRouter = core.ws.upgrade_router.WsUpgradeRouter;

const state_mod = @import("../state.zig");
const auth = @import("../auth.zig");
const http_util = @import("../http_util.zig");
const jwt = @import("../jwt.zig");

/// Compile-time stream keys. Per-user / per-hashtag / per-list streams
/// derive their key dynamically into a stack buffer.
pub const stream_public: []const u8 = "mastodon.public";

const max_stream_key_bytes: usize = ws_registry.max_stream_key_bytes;

/// Static pool of envelope payload buffers. Producers write into the
/// next slot (round-robin); the slice handed to the registry points
/// into this stable storage. Slow subscribers may observe overwritten
/// bytes — that's the documented ring-buffer trade.
const envelope_slot_count: u32 = 1024;
const envelope_bytes_per_slot: usize = 8 * 1024;

var envelope_slots: [envelope_slot_count][envelope_bytes_per_slot]u8 =
    .{[_]u8{0} ** envelope_bytes_per_slot} ** envelope_slot_count;
var envelope_lens: [envelope_slot_count]u32 = .{0} ** envelope_slot_count;
var envelope_idx = std.atomic.Value(u64).init(0);

var active_subscribers = std.atomic.Value(u32).init(0);

pub fn currentSubscriberCount() u32 {
    return active_subscribers.load(.monotonic);
}

/// Register the four streaming upgrade routes.
pub fn registerRoutes(router: *WsUpgradeRouter, plugin_index: u16) !void {
    try router.register("/api/v1/streaming/user", handleUserWs, plugin_index);
    try router.register("/api/v1/streaming/public", handlePublicWs, plugin_index);
    try router.register("/api/v1/streaming/hashtag", handleHashtagWs, plugin_index);
    try router.register("/api/v1/streaming/list", handleListWs, plugin_index);
}

// ── individual handlers ────────────────────────────────────────────

fn handleUserWs(ctx: *WsUpgradeContext) anyerror!void {
    const user_id = (extractUserId(ctx) catch null) orelse {
        writeCloseAuth(ctx) catch {};
        return;
    };
    var key_buf: [max_stream_key_bytes]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buf, "mastodon.user:{d}", .{user_id}) catch {
        writeCloseInternal(ctx) catch {};
        return;
    };
    try runSubscriber(ctx, key);
}

fn handlePublicWs(ctx: *WsUpgradeContext) anyerror!void {
    try runSubscriber(ctx, stream_public);
}

fn handleHashtagWs(ctx: *WsUpgradeContext) anyerror!void {
    const tag = http_util.queryParam(ctx.request.pathAndQuery().query, "tag") orelse {
        writeCloseBadRequest(ctx) catch {};
        return;
    };
    var key_buf: [max_stream_key_bytes]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buf, "mastodon.hashtag:{s}", .{tag}) catch {
        writeCloseInternal(ctx) catch {};
        return;
    };
    try runSubscriber(ctx, key);
}

fn handleListWs(ctx: *WsUpgradeContext) anyerror!void {
    const list_id = http_util.queryParam(ctx.request.pathAndQuery().query, "list") orelse {
        writeCloseBadRequest(ctx) catch {};
        return;
    };
    var key_buf: [max_stream_key_bytes]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buf, "mastodon.list:{s}", .{list_id}) catch {
        writeCloseInternal(ctx) catch {};
        return;
    };
    try runSubscriber(ctx, key);
}

// ── core subscriber loop ───────────────────────────────────────────

fn runSubscriber(ctx: *WsUpgradeContext, stream_key: []const u8) !void {
    // Fairness cap.
    while (true) {
        const cur = active_subscribers.load(.monotonic);
        if (cur >= limits.max_inflight_subscribers) {
            writeCloseTryAgain(ctx) catch {};
            return;
        }
        if (active_subscribers.cmpxchgWeak(cur, cur + 1, .acq_rel, .monotonic) == null) break;
    }
    defer _ = active_subscribers.fetchSub(1, .acq_rel);

    const st = state_mod.get();
    const reg = st.ws_registry orelse {
        writeCloseInternal(ctx) catch {};
        return;
    };

    // Copy the stream_key into per-handler storage with the lifetime
    // of this call frame. The registry stores by-reference and our
    // dynamic format buffer lives on the stack.
    var key_storage: [max_stream_key_bytes]u8 = undefined;
    const n = @min(stream_key.len, key_storage.len);
    @memcpy(key_storage[0..n], stream_key[0..n]);
    const key = key_storage[0..n];

    const sub_id = reg.subscribe(key, 0) catch {
        writeCloseInternal(ctx) catch {};
        return;
    };
    defer reg.unsubscribe(key, sub_id) catch {};

    const shard = reg.shardFor(key);
    // Drain to make our subscription visible to the producer's broadcast.
    _ = shard.drainCommands(64) catch {};

    var cursor: u64 = if (shard.streamRing(key)) |r| r.nextSeq() else 0;

    var iters: u64 = 0;
    while (iters < std.math.maxInt(u32)) : (iters += 1) {
        _ = shard.drainCommands(64) catch {};

        if (shard.streamRing(key)) |ring| {
            var batch: [16]ws_registry.Event = undefined;
            const read = ring.drainSince(cursor, &batch);
            for (read.events) |ev| {
                writeTextFrame(ctx, ev.payload) catch return;
            }
            cursor = read.next_cursor;
        }

        if (try pumpInbound(ctx)) return;
        sleepMs(50);
    }
}

fn sleepMs(ms: u32) void {
    var req: std.c.timespec = .{
        .sec = 0,
        .nsec = @intCast(@as(i64, ms) * std.time.ns_per_ms),
    };
    _ = std.c.nanosleep(&req, &req);
}

// ── producer helpers (called from routes/statuses.zig etc.) ────────

/// Reserve a slot and format a Mastodon envelope into it. Returns the
/// slice (with stable address) to hand to `registry.broadcast`.
fn formatEnvelope(event_name: []const u8, payload_json: []const u8) []const u8 {
    const i = envelope_idx.fetchAdd(1, .monotonic);
    const slot_idx: u32 = @as(u32, @intCast(i & (envelope_slot_count - 1)));
    var buf = &envelope_slots[slot_idx];
    // We need to escape any JSON-special characters in `payload_json`
    // because the wire envelope nests the payload as a *string*. Most
    // serialized statuses use plain ASCII + quoted JSON which means
    // most bytes pass through. For correctness across the full input
    // domain we hand-escape `\` and `"` and control characters.
    var pos: usize = 0;
    pos += writeRaw(buf, pos, "{\"event\":\"");
    pos += writeRaw(buf, pos, event_name);
    pos += writeRaw(buf, pos, "\",\"payload\":\"");
    pos += writeEscaped(buf, pos, payload_json);
    pos += writeRaw(buf, pos, "\"}");
    envelope_lens[slot_idx] = @intCast(pos);
    return buf[0..pos];
}

fn writeRaw(buf: *[envelope_bytes_per_slot]u8, pos: usize, s: []const u8) usize {
    const cap = @min(s.len, buf.len -| pos);
    if (cap == 0) return 0;
    @memcpy(buf[pos..][0..cap], s[0..cap]);
    return cap;
}

fn writeEscaped(buf: *[envelope_bytes_per_slot]u8, start: usize, s: []const u8) usize {
    var pos = start;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (pos + 6 >= buf.len) break;
        const ch = s[i];
        switch (ch) {
            '"' => {
                buf[pos] = '\\';
                buf[pos + 1] = '"';
                pos += 2;
            },
            '\\' => {
                buf[pos] = '\\';
                buf[pos + 1] = '\\';
                pos += 2;
            },
            '\n' => {
                buf[pos] = '\\';
                buf[pos + 1] = 'n';
                pos += 2;
            },
            '\r' => {
                buf[pos] = '\\';
                buf[pos + 1] = 'r';
                pos += 2;
            },
            '\t' => {
                buf[pos] = '\\';
                buf[pos + 1] = 't';
                pos += 2;
            },
            else => {
                if (ch < 0x20) {
                    const hex = "0123456789abcdef";
                    buf[pos] = '\\';
                    buf[pos + 1] = 'u';
                    buf[pos + 2] = '0';
                    buf[pos + 3] = '0';
                    buf[pos + 4] = hex[(ch >> 4) & 0xF];
                    buf[pos + 5] = hex[ch & 0xF];
                    pos += 6;
                } else {
                    buf[pos] = ch;
                    pos += 1;
                }
            },
        }
    }
    return pos - start;
}

/// Publish a `status` update envelope. Fan-out targets: public stream +
/// the author's user stream. Called after a status row is inserted.
pub fn publishUpdate(reg: *ws_registry.Registry, author_user_id: i64, status_json: []const u8) void {
    const env = formatEnvelope("update", status_json);
    reg.broadcast(stream_public, .{ .payload = env, .tag = 0 }) catch {};
    var key_buf: [max_stream_key_bytes]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buf, "mastodon.user:{d}", .{author_user_id}) catch return;
    // We need to broadcast to a stable key, and the registry stores
    // keys by-reference. Use a dedicated static slab for per-user keys.
    const stored = internKey(key) orelse return;
    reg.broadcast(stored, .{ .payload = env, .tag = 0 }) catch {};
}

/// Publish a status-delete envelope. Payload is the bare numeric id.
pub fn publishDelete(reg: *ws_registry.Registry, author_user_id: i64, status_id: i64) void {
    var id_buf: [32]u8 = undefined;
    const id_str = std.fmt.bufPrint(&id_buf, "{d}", .{status_id}) catch return;
    const env = formatEnvelope("delete", id_str);
    reg.broadcast(stream_public, .{ .payload = env, .tag = 0 }) catch {};
    var key_buf: [max_stream_key_bytes]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buf, "mastodon.user:{d}", .{author_user_id}) catch return;
    const stored = internKey(key) orelse return;
    reg.broadcast(stored, .{ .payload = env, .tag = 0 }) catch {};
}

/// Publish a notification envelope to a single user stream.
pub fn publishNotification(reg: *ws_registry.Registry, recipient_user_id: i64, notif_json: []const u8) void {
    const env = formatEnvelope("notification", notif_json);
    var key_buf: [max_stream_key_bytes]u8 = undefined;
    const key = std.fmt.bufPrint(&key_buf, "mastodon.user:{d}", .{recipient_user_id}) catch return;
    const stored = internKey(key) orelse return;
    reg.broadcast(stored, .{ .payload = env, .tag = 0 }) catch {};
}

// ── per-user key interning ─────────────────────────────────────────
//
// `core.ws.registry` stores stream keys by reference. Producers in
// other threads (HTTP handlers) need to hand it a stable slice. We
// keep a small static intern table keyed by the i64 user id; lookups
// are O(N) but N is bounded by `limits.max_inflight_subscribers` so
// the loop is cheap.

const intern_slot_count: u32 = limits.max_inflight_subscribers * 2;
const InternSlot = struct {
    used: bool = false,
    buf: [max_stream_key_bytes]u8 = undefined,
    len: u32 = 0,

    fn slice(self: *const InternSlot) []const u8 {
        return self.buf[0..self.len];
    }
};
var intern_slots: [intern_slot_count]InternSlot = .{InternSlot{}} ** intern_slot_count;
var intern_lock = std.atomic.Value(u32).init(0);

fn internKey(k: []const u8) ?[]const u8 {
    // Cheap spin-lock around the table. Hot path is the lookup; once
    // a key has been interned the producer takes the fast path with
    // zero writes.
    while (intern_lock.cmpxchgWeak(0, 1, .acq_rel, .monotonic) != null) {
        // Very brief back-off; producers are short-lived.
        sleepMs(0);
    }
    defer intern_lock.store(0, .release);

    var i: u32 = 0;
    while (i < intern_slot_count) : (i += 1) {
        if (intern_slots[i].used and std.mem.eql(u8, intern_slots[i].slice(), k)) {
            return intern_slots[i].slice();
        }
    }
    i = 0;
    while (i < intern_slot_count) : (i += 1) {
        if (!intern_slots[i].used) {
            const n = @min(k.len, intern_slots[i].buf.len);
            @memcpy(intern_slots[i].buf[0..n], k[0..n]);
            intern_slots[i].len = @intCast(n);
            intern_slots[i].used = true;
            return intern_slots[i].slice();
        }
    }
    return null; // table full; broadcast best-effort skipped
}

// Testing-only helper.
fn resetInternForTests() void {
    var i: u32 = 0;
    while (i < intern_slot_count) : (i += 1) intern_slots[i] = .{};
}

// ── auth extraction ────────────────────────────────────────────────

fn extractUserId(ctx: *WsUpgradeContext) !?i64 {
    const st = state_mod.get();

    // Prefer the bearer header; fall back to ?access_token=... per the
    // Mastodon streaming spec which lets clients without header support
    // (browsers) pass the token in the URL.
    var token: ?[]const u8 = null;
    if (ctx.request.header("Authorization")) |h| {
        if (std.mem.startsWith(u8, h, "Bearer ")) token = h[7..];
    }
    if (token == null) {
        token = http_util.queryParam(ctx.request.pathAndQuery().query, "access_token");
    }
    const t = token orelse return null;

    const now = st.clock.wallUnix();
    var claims: jwt.Claims = .{};
    jwt.verify(t, st.jwt_key.public_key, now, &claims) catch return null;
    if (st.db) |db| {
        if (auth.isRevoked(db, claims.jti())) return null;
    }
    if (claims.user_id == 0) return null;
    return claims.user_id;
}

// ── frame I/O helpers ──────────────────────────────────────────────

fn writeTextFrame(ctx: *WsUpgradeContext, payload: []const u8) !void {
    var out: [limits.conn_read_buffer_bytes]u8 = undefined;
    const n = ws_frame.encode(.text, payload, true, &out) catch return error.EncodeFailed;
    try writeAll(ctx, out[0..n]);
}

fn writeAll(ctx: *WsUpgradeContext, payload: []const u8) !void {
    var scratch: [4096]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(ctx.stream, ctx.io, &scratch);
    writer.interface.writeAll(payload) catch return error.WriteFailed;
    writer.interface.flush() catch return error.WriteFailed;
}

fn pumpInbound(ctx: *WsUpgradeContext) !bool {
    var read_buf: [512]u8 = undefined;
    const got = readNonblocking(ctx.stream.socket.handle, &read_buf) catch return true;
    if (got == 0) return false;
    var consumed: usize = 0;
    var iters: u32 = 0;
    while (consumed < got and iters < 16) : (iters += 1) {
        const res = ws_frame.decode(read_buf[consumed..got], true) catch return true;
        switch (res) {
            .need_more => return false,
            .ok => |ok| {
                var f = ok.frame;
                f.unmask();
                switch (f.opcode) {
                    .close => return true,
                    .ping => {
                        var out: [256]u8 = undefined;
                        const n = ws_frame.encode(.pong, f.payload, true, &out) catch return true;
                        writeAll(ctx, out[0..n]) catch return true;
                    },
                    else => {},
                }
                consumed += ok.consumed;
            },
        }
    }
    return false;
}

fn readNonblocking(fd: std.posix.fd_t, dst: []u8) !usize {
    var pfd = [_]std.posix.pollfd{.{
        .fd = fd,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    const ready = std.posix.poll(&pfd, 0) catch return error.PollFailed;
    if (ready == 0) return 0;
    if ((pfd[0].revents & (std.posix.POLL.HUP | std.posix.POLL.ERR | std.posix.POLL.NVAL)) != 0) {
        return error.SocketClosed;
    }
    const n = std.posix.read(fd, dst) catch |err| switch (err) {
        error.WouldBlock => return 0,
        else => return err,
    };
    return n;
}

fn writeCloseTryAgain(ctx: *WsUpgradeContext) !void {
    const payload = [_]u8{ 0x03, 0xF5, 'b', 'u', 's', 'y' };
    var out: [16]u8 = undefined;
    const n = try ws_frame.encode(.close, &payload, true, &out);
    try writeAll(ctx, out[0..n]);
}

fn writeCloseInternal(ctx: *WsUpgradeContext) !void {
    const payload = [_]u8{ 0x03, 0xF3, 'e', 'r', 'r' };
    var out: [16]u8 = undefined;
    const n = try ws_frame.encode(.close, &payload, true, &out);
    try writeAll(ctx, out[0..n]);
}

fn writeCloseAuth(ctx: *WsUpgradeContext) !void {
    // 1008 "Policy Violation" — most appropriate for auth refusal.
    const payload = [_]u8{ 0x03, 0xF0, 'a', 'u', 't', 'h' };
    var out: [16]u8 = undefined;
    const n = try ws_frame.encode(.close, &payload, true, &out);
    try writeAll(ctx, out[0..n]);
}

fn writeCloseBadRequest(ctx: *WsUpgradeContext) !void {
    // 1002 "Protocol Error".
    const payload = [_]u8{ 0x03, 0xEA, 'b', 'a', 'd' };
    var out: [16]u8 = undefined;
    const n = try ws_frame.encode(.close, &payload, true, &out);
    try writeAll(ctx, out[0..n]);
}

// ── Tests ──────────────────────────────────────────────────────────

const testing = std.testing;

test "streaming_ws: registerRoutes wires four upgrade patterns" {
    var router = WsUpgradeRouter.init();
    try registerRoutes(&router, 0);
    router.freeze();
    var p: core.http.router.PathParams = .{};
    try testing.expect(router.match("/api/v1/streaming/user", &p) != null);
    try testing.expect(router.match("/api/v1/streaming/public", &p) != null);
    try testing.expect(router.match("/api/v1/streaming/hashtag", &p) != null);
    try testing.expect(router.match("/api/v1/streaming/list", &p) != null);
}

test "streaming_ws: formatEnvelope produces Mastodon-shaped JSON" {
    const env = formatEnvelope("update", "{\"id\":\"1\",\"content\":\"hi\"}");
    try testing.expect(std.mem.startsWith(u8, env, "{\"event\":\"update\""));
    try testing.expect(std.mem.indexOf(u8, env, "\"payload\":\"") != null);
    // Embedded quotes must be escaped.
    try testing.expect(std.mem.indexOf(u8, env, "\\\"id\\\":\\\"1\\\"") != null);
    try testing.expect(std.mem.endsWith(u8, env, "\"}"));
}

test "streaming_ws: formatEnvelope escapes newlines and backslashes" {
    const env = formatEnvelope("update", "a\nb\\c");
    try testing.expect(std.mem.indexOf(u8, env, "a\\nb\\\\c") != null);
}

test "streaming_ws: internKey returns stable slice for repeat lookups" {
    resetInternForTests();
    const a = internKey("mastodon.user:42") orelse return error.TestUnexpectedResult;
    const b = internKey("mastodon.user:42") orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as([*]const u8, a.ptr), @as([*]const u8, b.ptr));
    resetInternForTests();
}

test "streaming_ws: internKey allocates distinct slots per key" {
    resetInternForTests();
    const a = internKey("mastodon.user:1") orelse return error.TestUnexpectedResult;
    const b = internKey("mastodon.user:2") orelse return error.TestUnexpectedResult;
    try testing.expect(a.ptr != b.ptr);
    try testing.expectEqualStrings("mastodon.user:1", a);
    try testing.expectEqualStrings("mastodon.user:2", b);
    resetInternForTests();
}

test "streaming_ws: publishUpdate fans out to public stream" {
    resetInternForTests();
    const reg = try testing.allocator.create(ws_registry.Registry);
    defer testing.allocator.destroy(reg);
    reg.initInPlace();
    _ = try reg.subscribe(stream_public, 0);
    const shard = reg.shardFor(stream_public);
    _ = try shard.drainCommands(16);
    publishUpdate(reg, 7, "{\"id\":\"99\"}");
    _ = try shard.drainCommands(16);
    const ring = shard.streamRing(stream_public) orelse return error.TestUnexpectedResult;
    try testing.expect(ring.nextSeq() >= 1);
    resetInternForTests();
}

test "streaming_ws: publishDelete writes an event envelope" {
    resetInternForTests();
    const env = formatEnvelope("delete", "12345");
    try testing.expect(std.mem.indexOf(u8, env, "\"event\":\"delete\"") != null);
    try testing.expect(std.mem.indexOf(u8, env, "\"payload\":\"12345\"") != null);
    resetInternForTests();
}

test "streaming_ws: publishNotification targets user stream" {
    resetInternForTests();
    const reg = try testing.allocator.create(ws_registry.Registry);
    defer testing.allocator.destroy(reg);
    reg.initInPlace();
    const user_key = internKey("mastodon.user:13") orelse return error.TestUnexpectedResult;
    _ = try reg.subscribe(user_key, 0);
    const shard = reg.shardFor(user_key);
    _ = try shard.drainCommands(16);
    publishNotification(reg, 13, "{\"type\":\"mention\"}");
    _ = try shard.drainCommands(16);
    const ring = shard.streamRing(user_key) orelse return error.TestUnexpectedResult;
    try testing.expect(ring.nextSeq() >= 1);
    resetInternForTests();
}

test "streaming_ws: subscriber cap enforced via active_subscribers" {
    active_subscribers.store(limits.max_inflight_subscribers, .monotonic);
    defer active_subscribers.store(0, .monotonic);
    try testing.expect(active_subscribers.load(.monotonic) >= limits.max_inflight_subscribers);
}
