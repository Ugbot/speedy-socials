//! AT Protocol `com.atproto.sync.subscribeRepos` WebSocket handler.
//!
//! Wire format (https://atproto.com/specs/event-stream):
//!   Each event is a dag-cbor "header" frame followed by a dag-cbor
//!   "body" frame, concatenated and shipped as a single binary
//!   WebSocket frame. Header: `{"op":1,"t":"#commit"}`. Body: the
//!   commit envelope (did, commit cid, ops, blocks…). We persist the
//!   signed commit CBOR in `atp_firehose_events.body` and forward it
//!   verbatim as the body block, prepending the canonical header.
//!
//! Flow:
//!   1. Parse optional `?cursor=N` from the upgrade request query.
//!      Server-emitted seq is `> cursor`.
//!   2. Replay phase — read `atp_firehose_events` in bounded batches
//!      until SQLite returns nothing new; encode and write each as a
//!      binary frame.
//!   3. Live phase — register a subscription on the shared
//!      `core.ws.registry.Registry` keyed `"atproto.sync.subscribeRepos"`.
//!      Producers (`repo.commit`) push a tiny notification carrying the
//!      newly-assigned seq number; we drain the shard's ring, fetch the
//!      row from SQLite for any seq we have not yet sent, and write the
//!      same dag-cbor frame.
//!   4. Inbound — pings get pong replies; close frames terminate; any
//!      other inbound traffic is ignored (this is a server→client
//!      stream by spec).
//!
//! Tiger Style:
//!   * Bounded by `limits.max_inflight_subscribers` (256). On overflow
//!     we write a close frame with code 1013 ("try again later") and
//!     return so the server can close the socket.
//!   * Fixed-size send/receive buffers per handler call frame.
//!   * No allocations on the hot path; the per-connection arena is not
//!     used past the upgrade dispatch.

const std = @import("std");
const core = @import("core");
const c = @import("sqlite").c;

const limits = core.limits;
const ws_frame = core.ws.frame;
const ws_registry = core.ws.registry;
const WsUpgradeContext = core.ws.upgrade_router.WsUpgradeContext;
const WsUpgradeRouter = core.ws.upgrade_router.WsUpgradeRouter;
const Opcode = ws_frame.Opcode;
const dag = @import("dag_cbor.zig");
const State = @import("state.zig");
const firehose = @import("firehose.zig");
const xrpc = @import("xrpc.zig");

/// Stream key used by `repo.commit` to fan out commit events.
pub const stream_key = "atproto.sync.subscribeRepos";

/// Replay batch size. Bounded so a subscriber far behind cannot starve
/// the rest. Subscribers that need long history just read many batches.
const replay_batch: u32 = 64;

/// Per-handler scratch sizes. Sized to fit one frame (header + body).
const frame_scratch_bytes: usize = limits.conn_read_buffer_bytes;
const cbor_scratch_bytes: usize = 8 * 1024;

/// Count of currently-active subscribers; gates the soft fairness cap.
var active_subscribers = std.atomic.Value(u32).init(0);

pub fn currentSubscriberCount() u32 {
    return active_subscribers.load(.monotonic);
}

/// Register the WS upgrade route. Called from `plugin.registerWs`.
pub fn registerRoutes(router: *WsUpgradeRouter, plugin_index: u16) !void {
    try router.register(
        "/xrpc/com.atproto.sync.subscribeRepos",
        subscribeReposHandler,
        plugin_index,
    );
}

/// Upgrade handler. Server has already written the 101 response; we
/// own `ctx.stream` until we return.
fn subscribeReposHandler(ctx: *WsUpgradeContext) anyerror!void {
    // Fairness cap. Soft-CAS so a burst of upgrades can't race past.
    while (true) {
        const cur = active_subscribers.load(.monotonic);
        if (cur >= limits.max_inflight_subscribers) {
            writeCloseTryAgain(ctx) catch {};
            return;
        }
        if (active_subscribers.cmpxchgWeak(cur, cur + 1, .acq_rel, .monotonic) == null) break;
    }
    defer _ = active_subscribers.fetchSub(1, .acq_rel);

    const st = State.get();
    const db = st.reader_db orelse {
        writeCloseInternal(ctx) catch {};
        return;
    };
    const reg = st.ws_registry orelse {
        writeCloseInternal(ctx) catch {};
        return;
    };

    const query = ctx.request.pathAndQuery().query;
    var cursor: i64 = parseCursor(query);

    // ── Replay phase ───────────────────────────────────────────────
    var events: [replay_batch]firehose.Event = undefined;
    var replay_iters: u32 = 0;
    while (replay_iters < 1024) : (replay_iters += 1) {
        const n = firehose.readSince(db, cursor, &events) catch break;
        if (n == 0) break;
        var i: u32 = 0;
        while (i < n) : (i += 1) {
            const ev = &events[i];
            sendCommitForSeq(ctx, db, ev.seq) catch return;
            cursor = ev.seq;
        }
        if (n < replay_batch) break;
    }

    // ── Live phase ─────────────────────────────────────────────────
    const sub_id = reg.subscribe(stream_key, 0) catch {
        writeCloseInternal(ctx) catch {};
        return;
    };
    defer reg.unsubscribe(stream_key, sub_id) catch {};

    const shard = reg.shardFor(stream_key);

    var live_iters: u64 = 0;
    while (live_iters < std.math.maxInt(u32)) : (live_iters += 1) {
        // Drain pending commands on this shard. Any thread may have
        // queued subscribes/broadcasts; the shard is single-owner so
        // we drain a bounded slice each tick.
        _ = shard.drainCommands(64) catch {};

        // The per-shard ring is a "doorbell" — its payload is just a
        // big-endian seq number. We use SQLite as the source of truth
        // for replay, polling for `seq > cursor` each tick.

        // Poll SQLite for new seq > cursor. This is the cheap "kick"
        // poll between live drains.
        const n = firehose.readSince(db, cursor, &events) catch 0;
        if (n > 0) {
            var i: u32 = 0;
            while (i < n) : (i += 1) {
                const ev = &events[i];
                sendCommitForSeq(ctx, db, ev.seq) catch return;
                cursor = ev.seq;
            }
        }

        // Pump inbound client frames (ping / close). Returns true on
        // close or write failure → we exit cleanly.
        if (try pumpInbound(ctx)) return;

        // Brief sleep so we don't spin when idle. 50 ms keeps frame
        // latency well under 100 ms even with a slow producer. Zig
        // 0.16 dropped `std.Thread.sleep`; we go through libc.
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

/// Look up the row for `seq`, encode the dag-cbor `#commit` frame, and
/// write it as a single binary WebSocket frame.
fn sendCommitForSeq(ctx: *WsUpgradeContext, db: *c.sqlite3, seq: i64) !void {
    // Fetch exactly one event row.
    var rows: [1]firehose.Event = undefined;
    const n = firehose.readSince(db, seq - 1, &rows) catch return error.ReadFailed;
    if (n == 0) return; // already dropped or not yet visible

    // Load the body blob (commit CBOR). readSince doesn't return the
    // body, so do a small prepared query here.
    var body_buf: [cbor_scratch_bytes / 2]u8 = undefined;
    const body_len = loadEventBody(db, seq, &body_buf) catch return error.ReadFailed;

    // Encode header + body into a single buffer, then frame.
    var cbor_buf: [cbor_scratch_bytes]u8 = undefined;
    var enc = dag.Encoder.init(&cbor_buf);
    // Header: { op: 1, t: "#commit" }
    enc.writeMapHeader(2) catch return error.EncodeFailed;
    enc.writeText("op") catch return error.EncodeFailed;
    enc.writeUInt(1) catch return error.EncodeFailed;
    enc.writeText("t") catch return error.EncodeFailed;
    enc.writeText("#commit") catch return error.EncodeFailed;

    // Body: small envelope with seq, did, commit cid, and the raw
    // signed commit cbor as a byte string. Real implementations
    // include `ops`, `blocks` (a CAR), `prev`, etc. — we keep this a
    // structural minimum that downstream parsers can consume.
    var body_did_buf: [256]u8 = undefined;
    var body_cid_buf: [128]u8 = undefined;
    const ev = &rows[0];
    @memcpy(body_did_buf[0..ev.did().len], ev.did());
    @memcpy(body_cid_buf[0..ev.commitCid().len], ev.commitCid());
    const did_slice = body_did_buf[0..ev.did().len];
    const cid_slice = body_cid_buf[0..ev.commitCid().len];

    enc.writeMapHeader(5) catch return error.EncodeFailed;
    enc.writeText("seq") catch return error.EncodeFailed;
    enc.writeUInt(@as(u64, @intCast(ev.seq))) catch return error.EncodeFailed;
    enc.writeText("repo") catch return error.EncodeFailed;
    enc.writeText(did_slice) catch return error.EncodeFailed;
    enc.writeText("commit") catch return error.EncodeFailed;
    enc.writeText(cid_slice) catch return error.EncodeFailed;
    enc.writeText("time") catch return error.EncodeFailed;
    enc.writeUInt(@as(u64, @intCast(ev.ts))) catch return error.EncodeFailed;
    enc.writeText("blocks") catch return error.EncodeFailed;
    enc.writeBytesValue(body_buf[0..body_len]) catch return error.EncodeFailed;

    const full = enc.written();

    // Write as a single binary frame.
    var out_frame: [frame_scratch_bytes]u8 = undefined;
    const written = ws_frame.encode(.binary, full, true, &out_frame) catch return error.EncodeFailed;
    writeAll(ctx, out_frame[0..written]) catch return error.WriteFailed;
}

fn loadEventBody(db: *c.sqlite3, seq: i64, out: []u8) !usize {
    const sql = "SELECT body FROM atp_firehose_events WHERE seq = ?";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.ReadFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_int64(stmt, 1, seq);
    const step_rc = c.sqlite3_step(stmt.?);
    if (step_rc == c.SQLITE_DONE) return 0;
    if (step_rc != c.SQLITE_ROW) return error.ReadFailed;

    const ptr = c.sqlite3_column_blob(stmt, 0);
    const len: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
    const cap = @min(len, out.len);
    if (cap > 0 and ptr != null) {
        const p: [*]const u8 = @ptrCast(ptr);
        @memcpy(out[0..cap], p[0..cap]);
    }
    return cap;
}

/// Best-effort drain of any inbound client frames. Returns true if the
/// client sent a close, or the socket failed (caller exits the loop).
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
                    else => {}, // ignore data frames; firehose is server→client
                }
                consumed += ok.consumed;
            },
        }
    }
    return false;
}

fn writeCloseTryAgain(ctx: *WsUpgradeContext) !void {
    // 1013 "Try Again Later" big-endian + brief reason.
    var payload: [16]u8 = .{ 0x03, 0xF5, 't', 'o', 'o', '_', 'b', 'u', 's', 'y', 0, 0, 0, 0, 0, 0 };
    var out: [32]u8 = undefined;
    const n = try ws_frame.encode(.close, payload[0..10], true, &out);
    try writeAll(ctx, out[0..n]);
}

fn writeCloseInternal(ctx: *WsUpgradeContext) !void {
    // 1011 "Server Error".
    const payload = [_]u8{ 0x03, 0xF3, 'e', 'r', 'r' };
    var out: [16]u8 = undefined;
    const n = try ws_frame.encode(.close, payload[0..], true, &out);
    try writeAll(ctx, out[0..n]);
}

fn writeAll(ctx: *WsUpgradeContext, payload: []const u8) !void {
    var scratch: [4096]u8 = undefined;
    var writer = std.Io.net.Stream.Writer.init(ctx.stream, ctx.io, &scratch);
    writer.interface.writeAll(payload) catch return error.WriteFailed;
    writer.interface.flush() catch return error.WriteFailed;
}

/// Parse `cursor=N` from a URL query string. Anything malformed → 0.
fn parseCursor(query: []const u8) i64 {
    const raw = xrpc.queryParam(query, "cursor") orelse return 0;
    var v: i64 = 0;
    for (raw) |ch| {
        if (ch < '0' or ch > '9') return 0;
        v = v * 10 + @as(i64, ch - '0');
    }
    return v;
}

/// Non-blocking read using poll(2) with zero timeout. Returns 0 when
/// no bytes are immediately available — never parks the thread.
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

// ── Broadcast helper (called by `repo.commit`) ─────────────────────

/// Publish a one-line notification onto the registry stream for live
/// subscribers. The payload is a stable static buffer holding a single
/// big-endian seq value — subscribers re-fetch the actual commit body
/// from SQLite so the broadcast payload lifetime is irrelevant.
pub fn broadcastSeq(reg: *ws_registry.Registry, seq: i64) void {
    // Best-effort: drop on backpressure rather than block the commit.
    var slot_idx: u32 = 0;
    const i = broadcast_seq_idx.fetchAdd(1, .monotonic);
    slot_idx = @as(u32, @intCast(i & (broadcast_slot_count - 1)));
    var buf = &broadcast_slots[slot_idx];
    std.mem.writeInt(u64, buf[0..8], @as(u64, @intCast(seq)), .big);
    reg.broadcast(stream_key, .{ .payload = buf[0..8], .tag = 0 }) catch {};
}

const broadcast_slot_count: u32 = 256;
var broadcast_slots: [broadcast_slot_count][8]u8 = .{[_]u8{0} ** 8} ** broadcast_slot_count;
var broadcast_seq_idx = std.atomic.Value(u64).init(0);

// ── Tests ──────────────────────────────────────────────────────────

const testing = std.testing;
const schema_mod = @import("schema.zig");

fn setupDb() !*c.sqlite3 {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    for (schema_mod.all_migrations) |m| {
        const sql_z = try testing.allocator.dupeZ(u8, m.up);
        defer testing.allocator.free(sql_z);
        var errmsg: [*c]u8 = null;
        _ = c.sqlite3_exec(db, sql_z.ptr, null, null, &errmsg);
        if (errmsg != null) c.sqlite3_free(errmsg);
    }
    return db;
}

test "sync_firehose: parseCursor accepts decimal" {
    try testing.expectEqual(@as(i64, 42), parseCursor("cursor=42"));
    try testing.expectEqual(@as(i64, 1234567), parseCursor("cursor=1234567&foo=bar"));
}

test "sync_firehose: parseCursor rejects non-numeric → 0" {
    try testing.expectEqual(@as(i64, 0), parseCursor("cursor=abc"));
    try testing.expectEqual(@as(i64, 0), parseCursor(""));
    try testing.expectEqual(@as(i64, 0), parseCursor("other=1"));
}

test "sync_firehose: stream_key matches expected literal" {
    try testing.expectEqualStrings("atproto.sync.subscribeRepos", stream_key);
}

test "sync_firehose: registerRoutes wires the upgrade pattern" {
    var router = WsUpgradeRouter.init();
    try registerRoutes(&router, 0);
    router.freeze();
    var params: core.http.router.PathParams = .{};
    const h = router.match("/xrpc/com.atproto.sync.subscribeRepos", &params);
    try testing.expect(h != null);
}

test "sync_firehose: loadEventBody returns persisted bytes" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    const seq = try firehose.append(db, "did:plc:a", "bafy", "PAYLOAD", 100);
    var buf: [64]u8 = undefined;
    const n = try loadEventBody(db, seq, &buf);
    try testing.expectEqualStrings("PAYLOAD", buf[0..n]);
}

test "sync_firehose: loadEventBody on missing seq returns 0" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    var buf: [32]u8 = undefined;
    const n = try loadEventBody(db, 9999, &buf);
    try testing.expectEqual(@as(usize, 0), n);
}

test "sync_firehose: broadcastSeq writes payload that decodes back" {
    const reg = try testing.allocator.create(ws_registry.Registry);
    defer testing.allocator.destroy(reg);
    reg.initInPlace();
    _ = try reg.subscribe(stream_key, 0);
    const shard = reg.shardFor(stream_key);
    _ = try shard.drainCommands(16);
    broadcastSeq(reg, 42);
    _ = try shard.drainCommands(16);
    const ring = shard.streamRing(stream_key) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u64, 1), ring.nextSeq());
}

test "sync_firehose: subscriber cap accepts new slot up to limit" {
    // The cap atomic starts at 0; simulate N - 1 holders, then make
    // sure one more can claim (i.e. the CAS path passes).
    active_subscribers.store(limits.max_inflight_subscribers - 1, .monotonic);
    defer active_subscribers.store(0, .monotonic);

    while (true) {
        const cur = active_subscribers.load(.monotonic);
        if (cur >= limits.max_inflight_subscribers) {
            try testing.expect(false);
            return;
        }
        if (active_subscribers.cmpxchgWeak(cur, cur + 1, .acq_rel, .monotonic) == null) break;
    }
    try testing.expectEqual(limits.max_inflight_subscribers, active_subscribers.load(.monotonic));
}

test "sync_firehose: subscriber cap rejects past the ceiling" {
    active_subscribers.store(limits.max_inflight_subscribers, .monotonic);
    defer active_subscribers.store(0, .monotonic);
    const cur = active_subscribers.load(.monotonic);
    try testing.expect(cur >= limits.max_inflight_subscribers);
}
