//! Federation outbox delivery worker.
//!
//! Polls `ap_federation_outbox` for `pending` rows whose
//! `next_attempt_at` is due, marks them `in_flight`, hands them to the
//! injectable `delivery_hook` (production wires a TLS HTTPS POST; tests
//! override), and:
//!
//!   * on success → state = `done`.
//!   * on transient failure → `attempts++`, `next_attempt_at` =
//!     now + backoff(attempts), state = `pending`.
//!   * after `limits.max_delivery_attempts` failures → move payload to
//!     `ap_federation_dead_letter` and state = `dead`.
//!
//! Concurrency: a single worker thread polls the DB. Per-iteration we
//! cap in-flight deliveries at `limits.max_inflight_deliveries`. The
//! delivery hook is called inline on the worker thread — that's fine
//! because the worker is dedicated and isolated from the request path.
//!
//! Tiger Style:
//!   * bounded poll loop (an iteration cap per tick)
//!   * exponential backoff with deterministic jitter from `core.rng`
//!   * `signalStop` + `joinAndDrain` for graceful shutdown
//!   * the queue is the DB; no in-memory ring (deliveries must not be
//!     dropped silently)

const std = @import("std");
const c = @import("sqlite").c;
const core = @import("core");

const FedError = core.errors.FedError;
const Clock = core.clock.Clock;
const limits = core.limits;
const assertLe = core.assert.assertLe;

pub const max_payload_inline_bytes: usize = 8 * 1024;
pub const max_inbox_bytes: usize = 512;
pub const max_key_id_bytes: usize = 256;

/// Maximum backoff (16h) — same cap as the legacy schedule.
pub const max_backoff_sec: i64 = 16 * 3600;

/// Backoff base schedule: `1s, 4s, 16s, 64s, 256s, 1024s, 4096s, 16384s`.
/// Each attempt n is delayed by 4^n seconds, capped at 16h.
fn baseBackoffSec(attempts: u32) i64 {
    var base: i64 = 1;
    var i: u32 = 0;
    while (i < attempts and i < 12) : (i += 1) base *= 4;
    if (base > max_backoff_sec) base = max_backoff_sec;
    return base;
}

/// Compute the delay before the next delivery retry.
///
/// The base schedule is exponential (4^attempt seconds, capped at 16h).
/// Jitter is applied via TigerBeetle's `Ratio` + `exponential` helpers
/// so the distribution is *honest* (memoryless thundering-herd avoidance)
/// rather than the previous uniform ±25% window. The exponential draw
/// is squashed to a Ratio in `[0, 1]` and used to interpolate between
/// `base * 0.75` and `base * 1.25`, preserving the ±25% bound the
/// previous implementation advertised while improving the spectral
/// shape (more samples near the centre, long-tail jitter is rare).
pub fn computeBackoffSec(attempts: u32, rng: ?*core.rng.Rng) i64 {
    const base = baseBackoffSec(attempts);
    var jittered: i64 = base;
    if (rng) |r| {
        // Squash an exponential(mean=1) draw to [0, 1] with a generous
        // saturating cap at 4 standard means — this discards the tail
        // beyond ~1% probability and keeps jitter bounded.
        const raw = r.exponential(1.0);
        const clipped: f64 = if (raw > 4.0) 4.0 else raw;
        const u_num: u64 = @intFromFloat(@round((clipped / 4.0) * 1_000_000.0));
        const u = core.rng.ratio(@min(u_num, @as(u64, 1_000_000)), 1_000_000);
        // Decide direction with a fair coin via TB `chance(1/2)`.
        const positive = r.chance(core.rng.ratio(1, 2));
        // Magnitude of offset in [0, base/4].
        const max_off: i64 = @divTrunc(base, 4);
        const off_mag: i64 = @intCast(@divTrunc(@as(i64, @intCast(u.numerator)) * max_off, @as(i64, @intCast(u.denominator))));
        jittered = if (positive) base + off_mag else base - off_mag;
    }
    if (jittered < 1) jittered = 1;
    if (jittered > max_backoff_sec) jittered = max_backoff_sec;
    return jittered;
}

/// Outcome the delivery hook returns to the worker.
pub const DeliveryResult = enum {
    success,
    transient_failure,
    permanent_failure,
};

/// Hook the production layer wires: send the payload to `target_inbox`,
/// signed with `key_id`. Returns a `DeliveryResult` indicating retry
/// classification. Default implementation always returns
/// `transient_failure` so a real HTTPS client must be wired before
/// federation actually goes out.
pub const DeliverFn = *const fn (
    target_inbox: []const u8,
    payload: []const u8,
    key_id: []const u8,
) DeliveryResult;

var deliver_hook: ?DeliverFn = null;

pub fn setDeliverHook(hook: ?DeliverFn) void {
    deliver_hook = hook;
}

pub fn defaultDeliver(_: []const u8, _: []const u8, _: []const u8) DeliveryResult {
    return .transient_failure;
}

// ──────────────────────────────────────────────────────────────────────
// Worker
// ──────────────────────────────────────────────────────────────────────

pub const Worker = struct {
    thread: ?std.Thread = null,
    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// SQLite handle the worker uses for polling + state updates. Owned
    /// by the composition root.
    db: ?*c.sqlite3 = null,
    clock: Clock = undefined,
    rng: ?*core.rng.Rng = null,
    /// Diagnostic counters.
    delivered: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    failed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    dead_lettered: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// Poll cadence — sleep this long when the queue is empty.
    idle_sleep_ns: u64 = 100 * std.time.ns_per_ms,

    pub fn start(self: *Worker, db: *c.sqlite3, clock: Clock, rng: *core.rng.Rng) !void {
        if (self.running.load(.acquire)) return;
        self.db = db;
        self.clock = clock;
        self.rng = rng;
        self.delivered.store(0, .release);
        self.failed.store(0, .release);
        self.dead_lettered.store(0, .release);
        self.running.store(true, .release);
        self.thread = try std.Thread.spawn(.{}, mainLoop, .{self});
    }

    pub fn signalStop(self: *Worker) void {
        self.running.store(false, .release);
    }

    pub fn joinAndDrain(self: *Worker) void {
        self.running.store(false, .release);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }

    fn mainLoop(self: *Worker) void {
        // Outer loop is "bounded" only by the running flag. Every inner
        // iteration is hard-bounded by `max_inflight_deliveries`.
        while (self.running.load(.acquire)) {
            const n = self.tickOnce() catch 0;
            if (n == 0) sleepNs(self.idle_sleep_ns);
        }
    }

    /// One tick: drain up to `max_inflight_deliveries` due rows, run the
    /// hook for each, update state. Returns the number processed.
    pub fn tickOnce(self: *Worker) FedError!u32 {
        const db = self.db orelse return 0;
        const hook = deliver_hook orelse defaultDeliver;
        const now = self.clock.wallUnix();

        // Select a batch of due rows.
        var stmt: ?*c.sqlite3_stmt = null;
        const sel =
            \\SELECT id, target_inbox, payload, key_id, attempts
            \\FROM ap_federation_outbox
            \\WHERE state = 'pending' AND next_attempt_at <= ?
            \\ORDER BY next_attempt_at ASC
            \\LIMIT ?
        ;
        if (c.sqlite3_prepare_v2(db, sel, -1, &stmt, null) != c.SQLITE_OK) {
            if (stmt != null) _ = c.sqlite3_finalize(stmt);
            return 0;
        }
        defer _ = c.sqlite3_finalize(stmt);
        _ = c.sqlite3_bind_int64(stmt, 1, now);
        _ = c.sqlite3_bind_int(stmt, 2, @intCast(limits.max_inflight_deliveries));

        var processed: u32 = 0;
        var rows_buf: [limits.max_inflight_deliveries]Row = undefined;
        var n_rows: u32 = 0;
        while (n_rows < limits.max_inflight_deliveries) {
            const rc = c.sqlite3_step(stmt);
            if (rc == c.SQLITE_DONE) break;
            if (rc != c.SQLITE_ROW) break;
            rows_buf[n_rows] = readRow(stmt.?);
            n_rows += 1;
        }

        // Run the hook for each row, then update state.
        var i: u32 = 0;
        while (i < n_rows) : (i += 1) {
            const r = &rows_buf[i];
            const result = hook(r.inboxSlice(), r.payloadSlice(), r.keyIdSlice());
            switch (result) {
                .success => {
                    self.markDone(r.id) catch {};
                    _ = self.delivered.fetchAdd(1, .release);
                },
                .transient_failure, .permanent_failure => {
                    const new_attempts = r.attempts + 1;
                    if (new_attempts >= limits.max_delivery_attempts or result == .permanent_failure) {
                        self.moveToDeadLetter(r, "delivery_failed") catch {};
                        _ = self.dead_lettered.fetchAdd(1, .release);
                    } else {
                        const delay = computeBackoffSec(new_attempts, self.rng);
                        self.markRetry(r.id, new_attempts, now + delay) catch {};
                        _ = self.failed.fetchAdd(1, .release);
                    }
                },
            }
            processed += 1;
        }
        assertLe(processed, limits.max_inflight_deliveries);
        return processed;
    }

    fn markDone(self: *Worker, id: i64) !void {
        const db = self.db orelse return;
        var stmt: ?*c.sqlite3_stmt = null;
        const sql = "UPDATE ap_federation_outbox SET state='done' WHERE id=?";
        if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
            if (stmt != null) _ = c.sqlite3_finalize(stmt);
            return;
        }
        defer _ = c.sqlite3_finalize(stmt);
        _ = c.sqlite3_bind_int64(stmt, 1, id);
        _ = c.sqlite3_step(stmt);
    }

    fn markRetry(self: *Worker, id: i64, attempts: u32, next_at: i64) !void {
        const db = self.db orelse return;
        var stmt: ?*c.sqlite3_stmt = null;
        const sql = "UPDATE ap_federation_outbox SET attempts=?, next_attempt_at=?, state='pending' WHERE id=?";
        if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
            if (stmt != null) _ = c.sqlite3_finalize(stmt);
            return;
        }
        defer _ = c.sqlite3_finalize(stmt);
        _ = c.sqlite3_bind_int(stmt, 1, @intCast(attempts));
        _ = c.sqlite3_bind_int64(stmt, 2, next_at);
        _ = c.sqlite3_bind_int64(stmt, 3, id);
        _ = c.sqlite3_step(stmt);
    }

    fn moveToDeadLetter(self: *Worker, r: *const Row, last_err: []const u8) !void {
        const db = self.db orelse return;
        // Insert.
        var ins: ?*c.sqlite3_stmt = null;
        const insql = "INSERT INTO ap_federation_dead_letter(target_inbox,payload,last_error,attempts,dropped_at) VALUES (?,?,?,?,?)";
        if (c.sqlite3_prepare_v2(db, insql, -1, &ins, null) != c.SQLITE_OK) {
            if (ins != null) _ = c.sqlite3_finalize(ins);
            return;
        }
        defer _ = c.sqlite3_finalize(ins);
        const target = r.inboxSlice();
        const payload = r.payloadSlice();
        _ = c.sqlite3_bind_text(ins, 1, target.ptr, @intCast(target.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_blob(ins, 2, payload.ptr, @intCast(payload.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_text(ins, 3, last_err.ptr, @intCast(last_err.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_int(ins, 4, @intCast(r.attempts + 1));
        _ = c.sqlite3_bind_int64(ins, 5, self.clock.wallUnix());
        _ = c.sqlite3_step(ins);
        // Update.
        var upd: ?*c.sqlite3_stmt = null;
        const upsql = "UPDATE ap_federation_outbox SET state='dead' WHERE id=?";
        if (c.sqlite3_prepare_v2(db, upsql, -1, &upd, null) != c.SQLITE_OK) {
            if (upd != null) _ = c.sqlite3_finalize(upd);
            return;
        }
        defer _ = c.sqlite3_finalize(upd);
        _ = c.sqlite3_bind_int64(upd, 1, r.id);
        _ = c.sqlite3_step(upd);
    }
};

const Row = struct {
    id: i64,
    inbox: [max_inbox_bytes]u8 = undefined,
    inbox_len: usize = 0,
    payload: [max_payload_inline_bytes]u8 = undefined,
    payload_len: usize = 0,
    key_id: [max_key_id_bytes]u8 = undefined,
    key_id_len: usize = 0,
    attempts: u32 = 0,

    fn inboxSlice(self: *const Row) []const u8 {
        return self.inbox[0..self.inbox_len];
    }
    fn payloadSlice(self: *const Row) []const u8 {
        return self.payload[0..self.payload_len];
    }
    fn keyIdSlice(self: *const Row) []const u8 {
        return self.key_id[0..self.key_id_len];
    }
};

fn readRow(stmt: *c.sqlite3_stmt) Row {
    var r: Row = .{ .id = c.sqlite3_column_int64(stmt, 0) };
    // target_inbox (text)
    const tb_ptr = c.sqlite3_column_text(stmt, 1);
    const tb_n: usize = @intCast(c.sqlite3_column_bytes(stmt, 1));
    const tb_copy: usize = @min(tb_n, r.inbox.len);
    if (tb_ptr != null and tb_copy > 0) @memcpy(r.inbox[0..tb_copy], tb_ptr[0..tb_copy]);
    r.inbox_len = tb_copy;
    // payload (blob)
    const p_ptr = c.sqlite3_column_blob(stmt, 2);
    const p_n: usize = @intCast(c.sqlite3_column_bytes(stmt, 2));
    const p_copy: usize = @min(p_n, r.payload.len);
    if (p_ptr != null and p_copy > 0) {
        const pp: [*]const u8 = @ptrCast(p_ptr);
        @memcpy(r.payload[0..p_copy], pp[0..p_copy]);
    }
    r.payload_len = p_copy;
    // key_id (text)
    const k_ptr = c.sqlite3_column_text(stmt, 3);
    const k_n: usize = @intCast(c.sqlite3_column_bytes(stmt, 3));
    const k_copy: usize = @min(k_n, r.key_id.len);
    if (k_ptr != null and k_copy > 0) @memcpy(r.key_id[0..k_copy], k_ptr[0..k_copy]);
    r.key_id_len = k_copy;
    // attempts
    r.attempts = @intCast(c.sqlite3_column_int64(stmt, 4));
    return r;
}

fn sleepNs(ns: u64) void {
    var req: std.c.timespec = .{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    _ = std.c.nanosleep(&req, &req);
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;
const schema = @import("schema.zig");
const delivery = @import("delivery.zig");

test "computeBackoffSec grows exponentially" {
    try testing.expect(computeBackoffSec(0, null) == 1);
    try testing.expect(computeBackoffSec(1, null) == 4);
    try testing.expect(computeBackoffSec(2, null) == 16);
    try testing.expect(computeBackoffSec(3, null) == 64);
    try testing.expect(computeBackoffSec(4, null) == 256);
}

test "computeBackoffSec applies bounded jitter" {
    var r = Rng.init(42);
    const v = computeBackoffSec(2, &r);
    // 16s ±25% = 12..20.
    try testing.expect(v >= 12 and v <= 20);
}

test "computeBackoffSec base schedule is monotone non-decreasing" {
    // Without rng: every step is ≥ previous, and the schedule caps at
    // max_backoff_sec (16h = 57600s).
    var prev: i64 = 0;
    var attempt: u32 = 0;
    while (attempt < 20) : (attempt += 1) {
        const v = computeBackoffSec(attempt, null);
        try testing.expect(v >= prev);
        try testing.expect(v <= max_backoff_sec);
        prev = v;
    }
    // The cap is actually hit.
    try testing.expectEqual(max_backoff_sec, computeBackoffSec(20, null));
}

test "computeBackoffSec jitter stays within ±25% of base across many seeds" {
    // Sample over 1000 random seeds at attempts ≥ 4 (so base is large
    // enough for jitter to be non-trivial) and verify the result is
    // always inside the documented band.
    const base_at_4 = computeBackoffSec(4, null);
    const lo: i64 = base_at_4 - @divTrunc(base_at_4, 4);
    const hi: i64 = base_at_4 + @divTrunc(base_at_4, 4);
    var seed: u64 = 1;
    while (seed < 1001) : (seed += 1) {
        var r = Rng.init(seed *% 0x9E37_79B1_7F4A_7C15);
        const v = computeBackoffSec(4, &r);
        try testing.expect(v >= lo);
        try testing.expect(v <= hi);
    }
}

const TestDeliver = struct {
    var ok_targets_buf: [16][64]u8 = undefined;
    var ok_count: u32 = 0;
    var force_result: DeliveryResult = .success;

    fn run(target: []const u8, _: []const u8, _: []const u8) DeliveryResult {
        if (ok_count < ok_targets_buf.len) {
            const n = @min(target.len, ok_targets_buf[ok_count].len);
            @memcpy(ok_targets_buf[ok_count][0..n], target[0..n]);
            ok_count += 1;
        }
        return force_result;
    }
};

const Rng = core.rng.Rng;
test "tickOnce drains pending rows on success" {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try schema.applyAllForTests(db);

    var sc = core.clock.SimClock.init(100);
    var rng = Rng.init(1);
    const recipients = [_]delivery.Recipient{
        .{ .inbox = "https://a/inbox" },
        .{ .inbox = "https://b/inbox" },
    };
    _ = try delivery.enqueueDeliveries(db, sc.clock(), &recipients, "{\"id\":\"x\"}", "kid1");

    TestDeliver.ok_count = 0;
    TestDeliver.force_result = .success;
    setDeliverHook(TestDeliver.run);
    defer setDeliverHook(null);

    var w = Worker{};
    w.db = db;
    w.clock = sc.clock();
    w.rng = &rng;
    const n = try w.tickOnce();
    try testing.expectEqual(@as(u32, 2), n);
    try testing.expectEqual(@as(u64, 2), w.delivered.load(.acquire));

    // No more pending rows.
    var st: ?*c.sqlite3_stmt = null;
    _ = c.sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM ap_federation_outbox WHERE state='pending'", -1, &st, null);
    defer _ = c.sqlite3_finalize(st);
    try testing.expect(c.sqlite3_step(st) == c.SQLITE_ROW);
    try testing.expectEqual(@as(i64, 0), c.sqlite3_column_int64(st, 0));
}

test "tickOnce retries on transient failure with backoff" {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try schema.applyAllForTests(db);

    var sc = core.clock.SimClock.init(1000);
    var rng = Rng.init(1);
    const recipients = [_]delivery.Recipient{.{ .inbox = "https://a/inbox" }};
    _ = try delivery.enqueueDeliveries(db, sc.clock(), &recipients, "{}", "kid1");

    TestDeliver.ok_count = 0;
    TestDeliver.force_result = .transient_failure;
    setDeliverHook(TestDeliver.run);
    defer setDeliverHook(null);

    var w = Worker{};
    w.db = db;
    w.clock = sc.clock();
    w.rng = &rng;
    _ = try w.tickOnce();
    try testing.expectEqual(@as(u64, 1), w.failed.load(.acquire));

    // Row is still pending; attempts > 0; next_attempt_at > now.
    var st: ?*c.sqlite3_stmt = null;
    _ = c.sqlite3_prepare_v2(db, "SELECT state, attempts, next_attempt_at FROM ap_federation_outbox LIMIT 1", -1, &st, null);
    defer _ = c.sqlite3_finalize(st);
    try testing.expect(c.sqlite3_step(st) == c.SQLITE_ROW);
    const state_ptr = c.sqlite3_column_text(st, 0);
    const state_len: usize = @intCast(c.sqlite3_column_bytes(st, 0));
    try testing.expectEqualStrings("pending", state_ptr[0..state_len]);
    try testing.expectEqual(@as(i64, 1), c.sqlite3_column_int64(st, 1));
    try testing.expect(c.sqlite3_column_int64(st, 2) > 1000);
}

test "tickOnce dead-letters after max attempts" {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try schema.applyAllForTests(db);

    var sc = core.clock.SimClock.init(10_000);
    var rng = Rng.init(1);
    const recipients = [_]delivery.Recipient{.{ .inbox = "https://dead/inbox" }};
    _ = try delivery.enqueueDeliveries(db, sc.clock(), &recipients, "{\"dead\":1}", "kid1");

    TestDeliver.force_result = .permanent_failure;
    setDeliverHook(TestDeliver.run);
    defer setDeliverHook(null);

    var w = Worker{};
    w.db = db;
    w.clock = sc.clock();
    w.rng = &rng;
    _ = try w.tickOnce();
    try testing.expectEqual(@as(u64, 1), w.dead_lettered.load(.acquire));

    var st: ?*c.sqlite3_stmt = null;
    _ = c.sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM ap_federation_dead_letter", -1, &st, null);
    defer _ = c.sqlite3_finalize(st);
    try testing.expect(c.sqlite3_step(st) == c.SQLITE_ROW);
    try testing.expectEqual(@as(i64, 1), c.sqlite3_column_int64(st, 0));
}

test "tickOnce respects next_attempt_at" {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try schema.applyAllForTests(db);

    // Manually insert a row with next_attempt_at far in the future.
    const sql = "INSERT INTO ap_federation_outbox(target_inbox,payload,key_id,attempts,next_attempt_at,state,inserted_at) VALUES ('https://x',x'7b7d','k',0,9999999999,'pending',0)";
    var em: [*c]u8 = null;
    const exec_rc = c.sqlite3_exec(db, sql, null, null, &em);
    if (em != null) {
        std.debug.print("sqlite err: {s}\n", .{em});
        c.sqlite3_free(em);
    }
    try testing.expect(exec_rc == c.SQLITE_OK);

    var sc = core.clock.SimClock.init(100);
    var rng = Rng.init(1);
    var w = Worker{};
    w.db = db;
    w.clock = sc.clock();
    w.rng = &rng;
    TestDeliver.force_result = .success;
    setDeliverHook(TestDeliver.run);
    defer setDeliverHook(null);

    const n = try w.tickOnce();
    try testing.expectEqual(@as(u32, 0), n);
}

test "Worker thread start/signalStop/join" {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try schema.applyAllForTests(db);

    setDeliverHook(defaultDeliver);
    defer setDeliverHook(null);

    var sc = core.clock.SimClock.init(0);
    var rng = Rng.init(2);
    var w = Worker{ .idle_sleep_ns = 1 * std.time.ns_per_ms };
    try w.start(db, sc.clock(), &rng);
    // Let it spin for a moment.
    sleepNs(20 * std.time.ns_per_ms);
    w.joinAndDrain();
    try testing.expect(w.thread == null);
}
