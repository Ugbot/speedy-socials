//! W5.1 — AT→AP firehose consumer.
//!
//! When the local AT firehose appends a row (any `atproto.repo.commit`
//! call), the in-process sink fires synchronously on the writer
//! thread, copies the minimum-needed fields into a bounded ring, and
//! returns immediately. A separate worker thread drains the ring at
//! its own pace, queries `atp_records` for the new records the commit
//! introduced, and runs each through `relay.handleFirehoseEvent` to
//! produce an AP activity + a translation-log entry.
//!
//! Why not push the translation onto the writer thread directly?
//! `firehose.append` is on the storage writer's hot path. Holding
//! that thread to do translation, identity-map upserts, and arena
//! work would back-pressure every record write across every plugin.
//! The ring is the decoupling boundary.
//!
//! Why ring + worker thread (not a `core.workers.Pool` job)?
//! - The pool is for *bursty* per-request work; the consumer is a
//!   long-lived background fiber.
//! - A `core.workers.Pool(N)` submission for every record would burn
//!   queue slots and obscure cause when something falls behind.
//! A dedicated thread is the right shape — one producer, one
//! consumer, no allocation on either side.
//!
//! Scope today: the consumer translates each new record and appends
//! to `relay_translation_log`. Federation delivery (signing the
//! resulting AP activity + enqueuing into `ap_federation_outbox` for
//! each follower) is a downstream concern that needs a per-synthetic-
//! actor signing key + a followers table — both still to come. The
//! translation log is the verifiable evidence that the pipeline is
//! live.

const std = @import("std");
const core = @import("core");
const c = @import("sqlite").c;
const atproto = @import("protocol_atproto");
const activitypub = @import("protocol_activitypub");
const firehose = atproto.firehose;
const Arena = core.arena.Arena;

const plugin = @import("plugin.zig");
const state = @import("state.zig");
const subscription = @import("subscription.zig");

/// W6: optional AP inbox URL to deliver translated AT events to. When
/// set (typically via `RELAY_BRIDGE_AP_TARGET` env at boot), every
/// successful AT→AP translation enqueues a row in `ap_federation_outbox`
/// addressed at this inbox. When unset, the consumer still translates
/// + logs but does not deliver. Bounded to 512 bytes; longer URLs are
/// rejected at setBridgeTargetInbox.
var bridge_target_inbox_buf: [512]u8 = undefined;
var bridge_target_inbox_len: u16 = 0;

pub fn setBridgeTargetInbox(url: []const u8) void {
    if (url.len > bridge_target_inbox_buf.len) {
        bridge_target_inbox_len = 0;
        return;
    }
    @memcpy(bridge_target_inbox_buf[0..url.len], url);
    bridge_target_inbox_len = @intCast(url.len);
}

fn bridgeTargetInbox() []const u8 {
    return bridge_target_inbox_buf[0..bridge_target_inbox_len];
}

/// Sized for a comfortable burst headroom. Tuning: a firehose append
/// rate of ~1k/s and a consumer thread that processes ~10k/s leaves
/// the ring near-empty in steady state; 512 entries holds ~half a
/// second of writes before the producer would have to drop.
pub const ring_capacity: usize = 512;

/// What the sink hands the worker. Bounded inline storage — no heap
/// reference into the writer thread's scratch.
pub const QueueItem = struct {
    seq: i64 = 0,
    ts: i64 = 0,
    did_buf: [256]u8 = undefined,
    did_len: u16 = 0,
    cid_buf: [128]u8 = undefined,
    cid_len: u16 = 0,

    pub fn did(self: *const QueueItem) []const u8 {
        return self.did_buf[0..self.did_len];
    }
    pub fn commitCid(self: *const QueueItem) []const u8 {
        return self.cid_buf[0..self.cid_len];
    }
};

/// Drop policy. Tracked on the consumer so ops can observe queue
/// pressure via the admin status route.
pub const Stats = struct {
    enqueued: std.atomic.Value(u64) = .init(0),
    dropped: std.atomic.Value(u64) = .init(0),
    translated_ok: std.atomic.Value(u64) = .init(0),
    translated_err: std.atomic.Value(u64) = .init(0),
};

const Ring = core.stdx.RingBufferType(QueueItem, .{ .array = ring_capacity });

/// Sleep for `ns` nanoseconds via `std.c.nanosleep`. Zig 0.16 retired
/// `std.Thread.sleep`; the replacement `std.Io.sleep` requires an
/// `Io` handle our worker thread does not own. `nanosleep` is the
/// least-disruptive portable substitute on the macOS / Linux targets
/// speedy-socials ships against.
fn sleepNs(ns: u64) void {
    var req: std.c.timespec = .{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    _ = std.c.nanosleep(&req, &req);
}

/// Single-process singleton. The sink ABI carries no closure
/// pointer, so the singleton is the only practical shape. The
/// consumer is created once per process and lives until shutdown.
var instance: ?*Consumer = null;

pub const Consumer = struct {
    ring: Ring,
    /// Coarse spinlock guarding `ring`. Producer (firehose writer
    /// thread) and consumer (this struct's worker thread) contend
    /// only on the head/tail mutation, which is short.
    lock: std.atomic.Value(bool) = .init(false),
    stop: std.atomic.Value(bool) = .init(false),

    thread: ?std.Thread = null,
    /// Writer-side DB connection. The consumer uses it to read the
    /// records the firehose seq covered + write translation-log
    /// rows. Shared single-writer semantics: the relay's `state`
    /// already exposes a db pointer attached at boot.
    db: *c.sqlite3,
    clock: core.clock.Clock,
    relay_host_buf: [256]u8 = undefined,
    relay_host_len: u16 = 0,
    stats: Stats = .{},

    pub fn relayHost(self: *const Consumer) []const u8 {
        return self.relay_host_buf[0..self.relay_host_len];
    }
};

/// Spawn the consumer. Idempotent — calling twice returns the
/// already-installed instance.
///
/// D1/D2: the consumer uses its OWN sqlite handle (passed in by
/// the composition root), not the writer-thread's handle. Sqlite
/// connections opened with `SQLITE_OPEN_NOMUTEX` must not be
/// shared across threads, so each long-lived consumer thread gets
/// its own. File-level WAL locking + `busy_timeout` serialize the
/// rare concurrent writes between this thread and the main
/// HTTP-handler thread cleanly.
pub fn start(
    allocator: std.mem.Allocator,
    db: *c.sqlite3,
    clock: core.clock.Clock,
    relay_host: []const u8,
) !*Consumer {
    if (instance) |existing| return existing;
    if (relay_host.len == 0 or relay_host.len > 256) return error.InvalidRelayHost;

    const self = try allocator.create(Consumer);
    self.* = .{
        .ring = Ring.init(),
        .db = db,
        .clock = clock,
    };
    @memcpy(self.relay_host_buf[0..relay_host.len], relay_host);
    self.relay_host_len = @intCast(relay_host.len);

    instance = self;

    // Register the sink BEFORE spawning the worker so we don't miss
    // events that fire while the thread is starting up.
    firehose.registerLocalSink(onLocalFirehose);

    self.thread = try std.Thread.spawn(.{}, workerLoop, .{self});
    return self;
}

/// Tear down. Stops the worker, drains nothing further, unregisters
/// the sink. Safe to call from `relay.deinit`.
pub fn stop(allocator: std.mem.Allocator) void {
    const self = instance orelse return;
    firehose.registerLocalSink(null);
    self.stop.store(true, .release);
    if (self.thread) |t| t.join();
    allocator.destroy(self);
    instance = null;
}

/// Test-only handle. Returns the live consumer if started.
pub fn current() ?*Consumer {
    return instance;
}

// ── Sink ──────────────────────────────────────────────────────────

fn onLocalFirehose(seq: i64, did: []const u8, commit_cid: []const u8, body: []const u8, ts: i64) void {
    _ = body; // not needed: the consumer re-queries atp_records by did+ts
    const self = instance orelse return;

    var item: QueueItem = .{ .seq = seq, .ts = ts };
    const did_n = @min(did.len, item.did_buf.len);
    @memcpy(item.did_buf[0..did_n], did[0..did_n]);
    item.did_len = @intCast(did_n);
    const cid_n = @min(commit_cid.len, item.cid_buf.len);
    @memcpy(item.cid_buf[0..cid_n], commit_cid[0..cid_n]);
    item.cid_len = @intCast(cid_n);

    pushBlocking(self, item);
}

fn pushBlocking(self: *Consumer, item: QueueItem) void {
    // TTAS spinlock for ring access. Bounded short-critical-section.
    while (self.lock.swap(true, .acquire)) std.atomic.spinLoopHint();
    defer self.lock.store(false, .release);

    if (self.ring.full()) {
        // Drop-oldest policy: matches the WS subscription registry's
        // shape (`docs/design/protocol-relay.md`). Operators see the
        // dropped count on the admin status route.
        _ = self.ring.pop();
        _ = self.stats.dropped.fetchAdd(1, .monotonic);
    }
    self.ring.push_assume_capacity(item);
    _ = self.stats.enqueued.fetchAdd(1, .monotonic);
}

// ── Worker ────────────────────────────────────────────────────────

fn workerLoop(self: *Consumer) void {
    while (!self.stop.load(.acquire)) {
        const item = popBlocking(self) orelse continue;
        processItem(self, &item) catch |err| {
            std.log.warn("relay consumer: processItem failed: {s}", .{@errorName(err)});
            _ = self.stats.translated_err.fetchAdd(1, .monotonic);
        };
    }
}

fn popBlocking(self: *Consumer) ?QueueItem {
    // Try-pop under the spinlock; on empty, sleep briefly and retry.
    // Zig 0.16's stdlib does not expose a Thread.Mutex / Condition pair
    // (those moved into `std.Io.{Mutex,Condition}` which need an Io
    // handle the consumer thread does not have at hand). A 2 ms poll
    // is well below the firehose translation latency budget and
    // costs ~500 wakeups/s in the idle case — negligible.
    while (true) {
        if (self.stop.load(.acquire)) return null;
        while (self.lock.swap(true, .acquire)) std.atomic.spinLoopHint();
        if (self.ring.pop()) |item| {
            self.lock.store(false, .release);
            return item;
        }
        self.lock.store(false, .release);
        sleepNs(2 * std.time.ns_per_ms);
    }
}

const RecordRow = struct {
    uri_buf: [512]u8 = undefined,
    uri_len: u16 = 0,
    collection_buf: [128]u8 = undefined,
    collection_len: u16 = 0,
    value_buf: [8192]u8 = undefined,
    value_len: u16 = 0,

    pub fn uri(self: *const RecordRow) []const u8 {
        return self.uri_buf[0..self.uri_len];
    }
    pub fn collection(self: *const RecordRow) []const u8 {
        return self.collection_buf[0..self.collection_len];
    }
    pub fn value(self: *const RecordRow) []const u8 {
        return self.value_buf[0..self.value_len];
    }
};

fn processItem(self: *Consumer, item: *const QueueItem) !void {
    // Find every record this commit introduced. The repo writer
    // stamps `indexed_at` with the commit's wall-clock seconds, the
    // same value the firehose event records as `ts`. A composite
    // (did, indexed_at) match is precise *enough*: two commits to
    // the same repo in the same second would merge here, but the
    // record translator is idempotent on `at_uri` (the translation
    // log keys on it) so the worst case is duplicate log entries.
    var rows: [16]RecordRow = undefined;
    const n = try loadRecordsForCommit(self.db, item.did(), item.ts, &rows);
    if (n == 0) {
        // Commit may have been a delete-only commit, or the records
        // table is empty for some reason. Not an error path.
        return;
    }

    var arena_buf: [32 * 1024]u8 = undefined;
    for (rows[0..n]) |row| {
        var arena = Arena.init(&arena_buf);
        const ev: plugin.FirehoseEvent = .{
            .at_uri = row.uri(),
            .did = item.did(),
            .collection = row.collection(),
            .record_json = row.value(),
            .fallback_created_at = "",
        };
        const out = plugin.handleFirehoseEvent(
            self.db,
            self.clock,
            self.relayHost(),
            ev,
            &arena,
        ) catch |err| switch (err) {
            // Unsupported collections (threadgate, lists, …) are
            // expected — the relay only translates the four core
            // shapes today. Don't count as errors.
            error.UnsupportedKind => continue,
            else => return err,
        };
        _ = self.stats.translated_ok.fetchAdd(1, .monotonic);

        // W6: deliver the translated activity to the configured AP
        // bridge target inbox (if set). Failure to enqueue is logged
        // but not fatal — the translation itself is recorded in
        // `relay_translation_log` either way.
        const target = bridgeTargetInbox();
        if (target.len > 0) {
            enqueueApDelivery(self.db, self.clock, &arena, out, target) catch |err| {
                std.log.warn("relay consumer: enqueueApDelivery failed: {s}", .{@errorName(err)});
            };
        }
    }
}

/// Build the AP activity JSON from `out` and enqueue one row in
/// `ap_federation_outbox` addressed at `target_inbox`. The key_id we
/// stamp on the outbox row is `<actor>#main-key`, the standard
/// convention; the AP outbox worker will use it when fetching the
/// signing key (or, today, when the synthetic AP actor's key infra
/// lands, will sign with it directly).
fn enqueueApDelivery(
    db: *c.sqlite3,
    clock: core.clock.Clock,
    arena: *Arena,
    out: anytype,
    target_inbox: []const u8,
) !void {
    const alloc = arena.allocator();
    var key_id_buf: [256 + 9]u8 = undefined; // actor + "#main-key"
    if (out.actor.len + 9 > key_id_buf.len) return error.OutOfMemory;
    @memcpy(key_id_buf[0..out.actor.len], out.actor);
    @memcpy(key_id_buf[out.actor.len..][0..9], "#main-key");
    const key_id = key_id_buf[0 .. out.actor.len + 9];

    // Minimal Create{Note} JSON envelope. Other activity types (Like,
    // Announce, Follow) get type-specific shapes. The outbox worker
    // delivers the bytes verbatim; we don't need to be lexicon-perfect
    // for the at-least-one-recipient bridge case.
    const payload = try buildApActivityJson(arena, out);

    const recipients = [_]activitypub.delivery.Recipient{.{ .inbox = target_inbox }};
    _ = try activitypub.delivery.enqueueDeliveries(db, clock, &recipients, payload, key_id);
    _ = alloc; // silence unused when we don't take more arena allocations
}

fn buildApActivityJson(arena: *Arena, out: anytype) ![]const u8 {
    const alloc = arena.allocator();
    // Generous upper bound. Real activities are well under 4 KiB; if
    // we ever cross 16 KiB the bridge needs a richer shape anyway.
    const buf = try alloc.alloc(u8, 16 * 1024);
    const type_str: []const u8 = switch (out.activity_type) {
        .create => "Create",
        .like => "Like",
        .announce => "Announce",
        .follow => "Follow",
        else => "Note",
    };
    const written = switch (out.activity_type) {
        .create => try std.fmt.bufPrint(buf,
            \\{{"@context":"https://www.w3.org/ns/activitystreams","id":"{s}","type":"{s}","actor":"{s}","published":"{s}","to":["{s}"],"object":{{"id":"{s}","type":"Note","content":"{s}","attributedTo":"{s}","published":"{s}"}}}}
        , .{ out.id, type_str, out.actor, out.published, out.to, out.object_id, out.content_html, out.actor, out.published }),
        .like, .announce => try std.fmt.bufPrint(buf,
            \\{{"@context":"https://www.w3.org/ns/activitystreams","id":"{s}","type":"{s}","actor":"{s}","object":"{s}","published":"{s}","to":["{s}"]}}
        , .{ out.id, type_str, out.actor, out.object_id, out.published, out.to }),
        .follow => try std.fmt.bufPrint(buf,
            \\{{"@context":"https://www.w3.org/ns/activitystreams","id":"{s}","type":"Follow","actor":"{s}","object":"{s}","to":["{s}"]}}
        , .{ out.id, out.actor, out.object_id, out.to }),
        else => try std.fmt.bufPrint(buf,
            \\{{"@context":"https://www.w3.org/ns/activitystreams","id":"{s}","type":"{s}","actor":"{s}"}}
        , .{ out.id, type_str, out.actor }),
    };
    return written;
}

fn loadRecordsForCommit(db: *c.sqlite3, did: []const u8, ts: i64, out: []RecordRow) !u32 {
    const sql = "SELECT uri, collection, value FROM atp_records WHERE did = ? AND indexed_at = ? ORDER BY uri ASC LIMIT ?";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, did.ptr, @intCast(did.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(stmt, 2, ts);
    _ = c.sqlite3_bind_int64(stmt, 3, @intCast(out.len));

    var n: u32 = 0;
    while (n < out.len) {
        const step_rc = c.sqlite3_step(stmt.?);
        if (step_rc == c.SQLITE_DONE) break;
        if (step_rc != c.SQLITE_ROW) return error.StepFailed;
        var row: RecordRow = .{};
        const uri_ptr = c.sqlite3_column_text(stmt, 0);
        const uri_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
        if (uri_ptr != null and uri_len > 0) {
            const cap = @min(uri_len, row.uri_buf.len);
            @memcpy(row.uri_buf[0..cap], uri_ptr[0..cap]);
            row.uri_len = @intCast(cap);
        }
        const col_ptr = c.sqlite3_column_text(stmt, 1);
        const col_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 1));
        if (col_ptr != null and col_len > 0) {
            const cap = @min(col_len, row.collection_buf.len);
            @memcpy(row.collection_buf[0..cap], col_ptr[0..cap]);
            row.collection_len = @intCast(cap);
        }
        const val_ptr = c.sqlite3_column_blob(stmt, 2);
        const val_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 2));
        if (val_ptr != null and val_len > 0) {
            const cap = @min(val_len, row.value_buf.len);
            const p: [*]const u8 = @ptrCast(val_ptr);
            @memcpy(row.value_buf[0..cap], p[0..cap]);
            row.value_len = @intCast(cap);
        }
        out[n] = row;
        n += 1;
    }
    return n;
}

// ── Tests ─────────────────────────────────────────────────────────

const testing = std.testing;
const schema_mod = @import("schema.zig");
const at_schema = atproto.schema;

fn setupDb() !*c.sqlite3 {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    // Apply AT schema (we need atp_repos, atp_records, atp_firehose_*).
    for (at_schema.all_migrations) |m| {
        const sql_z = try testing.allocator.dupeZ(u8, m.up);
        defer testing.allocator.free(sql_z);
        var errmsg: [*c]u8 = null;
        _ = c.sqlite3_exec(db, sql_z.ptr, null, null, &errmsg);
        if (errmsg != null) c.sqlite3_free(errmsg);
    }
    // Apply AP schema so ap_federation_outbox exists when the bridge
    // target enqueue test runs.
    for (activitypub.schema.all_migrations) |m| {
        const sql_z = try testing.allocator.dupeZ(u8, m.up);
        defer testing.allocator.free(sql_z);
        var errmsg: [*c]u8 = null;
        _ = c.sqlite3_exec(db, sql_z.ptr, null, null, &errmsg);
        if (errmsg != null) c.sqlite3_free(errmsg);
    }
    // Apply relay schema.
    for (schema_mod.all_migrations) |m| {
        const sql_z = try testing.allocator.dupeZ(u8, m.up);
        defer testing.allocator.free(sql_z);
        var errmsg: [*c]u8 = null;
        _ = c.sqlite3_exec(db, sql_z.ptr, null, null, &errmsg);
        if (errmsg != null) c.sqlite3_free(errmsg);
    }
    return db;
}

fn insertRecord(db: *c.sqlite3, uri: []const u8, did: []const u8, collection: []const u8, value: []const u8, indexed_at: i64) !void {
    const sql = "INSERT INTO atp_records (uri, did, collection, rkey, cid, value, indexed_at) VALUES (?,?,?,'rkey1','bafycid', ?, ?)";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, uri.ptr, @intCast(uri.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 2, did.ptr, @intCast(did.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 3, collection.ptr, @intCast(collection.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_blob(stmt, 4, value.ptr, @intCast(value.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(stmt, 5, indexed_at);
    if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return error.StepFailed;
}

test "consumer: end-to-end firehose append → translation log entry" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);

    // Seed: a record row that the commit "introduced." The relay
    // consumer queries atp_records by (did, indexed_at).
    const did = "did:plc:alice";
    const uri = "at://did:plc:alice/app.bsky.feed.post/abc123";
    const value = "{\"$type\":\"app.bsky.feed.post\",\"text\":\"Hello relay\",\"createdAt\":\"2026-05-16T00:00:00Z\"}";
    const ts: i64 = 1_715_000_000;
    try insertRecord(db, uri, did, "app.bsky.feed.post", value, ts);

    var sc = core.clock.SimClock.init(ts);
    const consumer = try start(testing.allocator, db, sc.clock(), "relay.test");
    defer stop(testing.allocator);

    // Trigger the sink via a real firehose append.
    _ = try firehose.append(db, did, "bafycid", value, ts);

    // Spin until the worker has run (or give up after a budget).
    var spin: u32 = 0;
    while (spin < 500) : (spin += 1) {
        if (consumer.stats.translated_ok.load(.monotonic) > 0) break;
        sleepNs(2 * std.time.ns_per_ms);
    }
    try testing.expect(consumer.stats.translated_ok.load(.monotonic) >= 1);

    // Verify the translation log got an at_to_ap row keyed on our uri.
    var log_rows: [4]subscription.LogEntry = undefined;
    const n = try subscription.listLog(db, 0, &log_rows);
    try testing.expect(n >= 1);
    try testing.expectEqual(subscription.Direction.at_to_ap, log_rows[0].direction);
    try testing.expectEqualStrings(uri, log_rows[0].sourceId());
}

test "consumer: bridge target inbox enqueues into ap_federation_outbox" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);

    const did = "did:plc:bridge_alice";
    const uri = "at://did:plc:bridge_alice/app.bsky.feed.post/post1";
    const value = "{\"$type\":\"app.bsky.feed.post\",\"text\":\"bridged\",\"createdAt\":\"2026-05-19T00:00:00Z\"}";
    const ts: i64 = 1_716_000_000;
    try insertRecord(db, uri, did, "app.bsky.feed.post", value, ts);

    setBridgeTargetInbox("https://mastodon.example/users/eve/inbox");
    defer setBridgeTargetInbox("");

    var sc = core.clock.SimClock.init(ts);
    const consumer = try start(testing.allocator, db, sc.clock(), "relay.test");
    defer stop(testing.allocator);

    _ = try firehose.append(db, did, "bafycid", value, ts);

    var spin: u32 = 0;
    while (spin < 500) : (spin += 1) {
        if (consumer.stats.translated_ok.load(.monotonic) > 0) break;
        sleepNs(2 * std.time.ns_per_ms);
    }
    try testing.expect(consumer.stats.translated_ok.load(.monotonic) >= 1);

    // Wait a beat for the post-translation enqueue to land.
    sleepNs(50 * std.time.ns_per_ms);

    // Assert the row landed in ap_federation_outbox addressed at the
    // configured bridge target.
    var outbox_count: i64 = -1;
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "SELECT count(*) FROM ap_federation_outbox WHERE target_inbox = ?", -1, &stmt, null) == c.SQLITE_OK) {
        defer _ = c.sqlite3_finalize(stmt);
        const target = "https://mastodon.example/users/eve/inbox";
        _ = c.sqlite3_bind_text(stmt, 1, target, target.len, c.sqliteTransientAsDestructor());
        if (c.sqlite3_step(stmt.?) == c.SQLITE_ROW) {
            outbox_count = c.sqlite3_column_int64(stmt, 0);
        }
    }
    try testing.expectEqual(@as(i64, 1), outbox_count);

    // Spot-check the payload — it should contain "Create" and our text.
    var payload_buf: [4096]u8 = undefined;
    var payload_len: usize = 0;
    var p2: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "SELECT payload FROM ap_federation_outbox LIMIT 1", -1, &p2, null) == c.SQLITE_OK) {
        defer _ = c.sqlite3_finalize(p2);
        if (c.sqlite3_step(p2.?) == c.SQLITE_ROW) {
            const ptr = c.sqlite3_column_text(p2, 0);
            const n: usize = @intCast(c.sqlite3_column_bytes(p2, 0));
            const cap = @min(n, payload_buf.len);
            if (ptr != null and cap > 0) {
                @memcpy(payload_buf[0..cap], ptr[0..cap]);
                payload_len = cap;
            }
        }
    }
    try testing.expect(std.mem.indexOf(u8, payload_buf[0..payload_len], "\"type\":\"Create\"") != null);
    try testing.expect(std.mem.indexOf(u8, payload_buf[0..payload_len], "bridged") != null);
}

test "consumer: unsupported collection is silently skipped (no error log row)" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);

    const did = "did:plc:bob";
    const uri = "at://did:plc:bob/app.bsky.feed.threadgate/x";
    const ts: i64 = 1_715_000_100;
    try insertRecord(db, uri, did, "app.bsky.feed.threadgate", "{}", ts);

    var sc = core.clock.SimClock.init(ts);
    const consumer = try start(testing.allocator, db, sc.clock(), "relay.test");
    defer stop(testing.allocator);

    _ = try firehose.append(db, did, "bafycid", "{}", ts);

    var spin: u32 = 0;
    while (spin < 100) : (spin += 1) {
        if (consumer.stats.enqueued.load(.monotonic) > 0) break;
        sleepNs(2 * std.time.ns_per_ms);
    }
    // Give the worker a beat to actually pop the item.
    sleepNs(50 * std.time.ns_per_ms);

    try testing.expect(consumer.stats.enqueued.load(.monotonic) >= 1);
    try testing.expectEqual(@as(u64, 0), consumer.stats.translated_ok.load(.monotonic));
    try testing.expectEqual(@as(u64, 0), consumer.stats.translated_err.load(.monotonic));
}
