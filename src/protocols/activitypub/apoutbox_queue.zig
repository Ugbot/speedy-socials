//! `ApOutboxQueue` — a `core.queue.QueueProvider` backed by the existing
//! `ap_federation_outbox` / `ap_federation_dead_letter` tables.
//!
//! This is the seam that makes federation delivery pluggable: the producers
//! (`delivery.enqueueDeliveries`, AP routes, the relay bridge) and the
//! `outbox_worker` consumer all talk to a `QueueProvider`, and this is the
//! DEFAULT implementation — it issues exactly the SQL the hand-written paths
//! used, so behavior (and every existing test/sim) is unchanged. Swap the
//! provider (via `delivery.setDeliveryQueue`) to `core.queue.global()`
//! (DbQueue) or a Redis/NATS-backed provider and federation delivery rides
//! that queue instead, with no other code change.
//!
//! Mapping (the generic Job ↔ the outbox row):
//!   key     ← target_inbox      payload ← payload     meta ← key_id
//!   id      ← rowid             attempts ← attempts
//! `shared_inbox` is vestigial at this layer — `dedupRecipients` already
//! collapsed it into `target_inbox` before enqueue, and nothing reads it
//! back — so it is not carried through the generic Job.

const std = @import("std");
const core = @import("core");
const c = @import("sqlite").c;

const queue = core.queue;
const Clock = core.clock.Clock;
const Job = queue.Job;
const Error = queue.Error;

pub const ApOutboxQueue = struct {
    db: *c.sqlite3,
    clock: Clock,

    pub fn init(db: *c.sqlite3, clock: Clock) ApOutboxQueue {
        return .{ .db = db, .clock = clock };
    }

    pub fn provider(self: *ApOutboxQueue) queue.QueueProvider {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable = queue.QueueProvider.VTable{
        .enqueue = enqueueImpl,
        .dequeueBatch = dequeueBatchImpl,
        .ack = ackImpl,
        .nack = nackImpl,
        .deadLetter = deadLetterImpl,
    };

    fn enqueueImpl(ptr: *anyopaque, topic: []const u8, key: []const u8, payload: []const u8, meta: []const u8, not_before_unix: i64) Error!void {
        _ = topic;
        const self: *ApOutboxQueue = @ptrCast(@alignCast(ptr));
        // Honor the queue contract: reject oversized at enqueue (a visible
        // backpressure error beats silently truncating a delivery later).
        if (key.len > queue.max_key_bytes or payload.len > queue.max_payload_bytes or meta.len > queue.max_meta_bytes) {
            return error.PayloadTooLarge;
        }
        var stmt: ?*c.sqlite3_stmt = null;
        const sql =
            \\INSERT INTO ap_federation_outbox
            \\  (target_inbox, shared_inbox, payload, key_id, attempts, next_attempt_at, state, inserted_at)
            \\VALUES (?, NULL, ?, ?, 0, ?, 'pending', ?)
        ;
        if (c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null) != c.SQLITE_OK) {
            if (stmt != null) _ = c.sqlite3_finalize(stmt);
            return error.BackendFailed;
        }
        defer _ = c.sqlite3_finalize(stmt);
        _ = c.sqlite3_bind_text(stmt, 1, key.ptr, @intCast(key.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_blob(stmt, 2, payload.ptr, @intCast(payload.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_text(stmt, 3, meta.ptr, @intCast(meta.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_int64(stmt, 4, not_before_unix);
        _ = c.sqlite3_bind_int64(stmt, 5, not_before_unix);
        if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.QueueFull;
    }

    fn dequeueBatchImpl(ptr: *anyopaque, topic: []const u8, now_unix: i64, out: []Job) Error!usize {
        _ = topic;
        const self: *ApOutboxQueue = @ptrCast(@alignCast(ptr));
        if (out.len == 0) return 0;
        var stmt: ?*c.sqlite3_stmt = null;
        const sql =
            \\SELECT id, target_inbox, payload, key_id, attempts
            \\FROM ap_federation_outbox
            \\WHERE state = 'pending' AND next_attempt_at <= ?
            \\ORDER BY next_attempt_at ASC
            \\LIMIT ?
        ;
        if (c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null) != c.SQLITE_OK) {
            if (stmt != null) _ = c.sqlite3_finalize(stmt);
            return error.BackendFailed;
        }
        defer _ = c.sqlite3_finalize(stmt);
        _ = c.sqlite3_bind_int64(stmt, 1, now_unix);
        _ = c.sqlite3_bind_int(stmt, 2, @intCast(out.len));

        var n: usize = 0;
        while (n < out.len) {
            const rc = c.sqlite3_step(stmt);
            if (rc == c.SQLITE_DONE) break;
            if (rc != c.SQLITE_ROW) return error.BackendFailed;
            out[n] = .{};
            out[n].id = c.sqlite3_column_int64(stmt, 0);
            out[n].attempts = @intCast(c.sqlite3_column_int(stmt, 4));
            // Clamp each field to the Job cap before `set` so an oversized
            // row truncates-and-proceeds (exactly the old `readRow`
            // behavior) instead of erroring the whole batch — which would
            // poison-pill the worker on a row that never leaves 'pending'.
            // The caps are identical to the worker's old inline buffers,
            // so well-formed rows are unaffected.
            const k = clamp(columnSlice(stmt, 1), queue.max_key_bytes);
            const p = clamp(columnBlob(stmt, 2), queue.max_payload_bytes);
            const m = clamp(columnSlice(stmt, 3), queue.max_meta_bytes);
            out[n].set(k, p, m) catch return error.BackendFailed;
            n += 1;
        }
        return n;
    }

    fn ackImpl(ptr: *anyopaque, topic: []const u8, job: *const Job) Error!void {
        _ = topic;
        const self: *ApOutboxQueue = @ptrCast(@alignCast(ptr));
        try self.execById("UPDATE ap_federation_outbox SET state='done' WHERE id=?", job.id);
    }

    fn nackImpl(ptr: *anyopaque, topic: []const u8, job: *const Job, retry_at_unix: i64) Error!void {
        _ = topic;
        const self: *ApOutboxQueue = @ptrCast(@alignCast(ptr));
        var stmt: ?*c.sqlite3_stmt = null;
        const sql = "UPDATE ap_federation_outbox SET attempts=?, next_attempt_at=?, state='pending' WHERE id=?";
        if (c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null) != c.SQLITE_OK) {
            if (stmt != null) _ = c.sqlite3_finalize(stmt);
            return error.BackendFailed;
        }
        defer _ = c.sqlite3_finalize(stmt);
        _ = c.sqlite3_bind_int(stmt, 1, @intCast(job.attempts + 1));
        _ = c.sqlite3_bind_int64(stmt, 2, retry_at_unix);
        _ = c.sqlite3_bind_int64(stmt, 3, job.id);
        if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.BackendFailed;
    }

    fn deadLetterImpl(ptr: *anyopaque, topic: []const u8, job: *const Job, reason: []const u8) Error!void {
        _ = topic;
        const self: *ApOutboxQueue = @ptrCast(@alignCast(ptr));
        var ins: ?*c.sqlite3_stmt = null;
        const insql = "INSERT INTO ap_federation_dead_letter(target_inbox,payload,last_error,attempts,dropped_at) VALUES (?,?,?,?,?)";
        if (c.sqlite3_prepare_v2(self.db, insql, -1, &ins, null) != c.SQLITE_OK) {
            if (ins != null) _ = c.sqlite3_finalize(ins);
            return error.BackendFailed;
        }
        defer _ = c.sqlite3_finalize(ins);
        const target = job.key();
        const payload = job.payload();
        _ = c.sqlite3_bind_text(ins, 1, target.ptr, @intCast(target.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_blob(ins, 2, payload.ptr, @intCast(payload.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_text(ins, 3, reason.ptr, @intCast(reason.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_int(ins, 4, @intCast(job.attempts + 1));
        _ = c.sqlite3_bind_int64(ins, 5, self.clock.wallUnix());
        _ = c.sqlite3_step(ins);
        try self.execById("UPDATE ap_federation_outbox SET state='dead' WHERE id=?", job.id);
    }

    fn execById(self: *ApOutboxQueue, sql: [*:0]const u8, id: i64) Error!void {
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null) != c.SQLITE_OK) {
            if (stmt != null) _ = c.sqlite3_finalize(stmt);
            return error.BackendFailed;
        }
        defer _ = c.sqlite3_finalize(stmt);
        _ = c.sqlite3_bind_int64(stmt, 1, id);
        if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.BackendFailed;
    }
};

fn clamp(s: []const u8, cap: usize) []const u8 {
    return s[0..@min(s.len, cap)];
}

fn columnSlice(stmt: ?*c.sqlite3_stmt, idx: c_int) []const u8 {
    const ptr = c.sqlite3_column_text(stmt, idx);
    if (ptr == null) return "";
    const len: usize = @intCast(c.sqlite3_column_bytes(stmt, idx));
    return ptr[0..len];
}

fn columnBlob(stmt: ?*c.sqlite3_stmt, idx: c_int) []const u8 {
    const ptr = c.sqlite3_column_blob(stmt, idx);
    if (ptr == null) return "";
    const len: usize = @intCast(c.sqlite3_column_bytes(stmt, idx));
    const p: [*]const u8 = @ptrCast(ptr);
    return p[0..len];
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;
const sqlite_mod = core.storage.sqlite;
const schema = @import("schema.zig");

fn countRows(db: *c.sqlite3, sql: [*:0]const u8) i64 {
    var st: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql, -1, &st, null) != c.SQLITE_OK) return -1;
    defer _ = c.sqlite3_finalize(st);
    if (c.sqlite3_step(st) != c.SQLITE_ROW) return -1;
    return c.sqlite3_column_int64(st, 0);
}

test "ApOutboxQueue: enqueue/dequeue/ack/nack/deadLetter over ap_federation_outbox (randomized)" {
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try schema.applyAllForTests(db);

    var sc = core.clock.SimClock.init(1000);
    var apq = ApOutboxQueue.init(db, sc.clock());
    const p = apq.provider();

    // Enqueue a randomized batch, all eligible at t=1000.
    var prng = std.Random.DefaultPrng.init(testing.random_seed);
    const rand = prng.random();
    const total: usize = rand.intRangeAtMost(usize, 4, 20);
    var i: usize = 0;
    while (i < total) : (i += 1) {
        var inbox_buf: [64]u8 = undefined;
        var pay_buf: [128]u8 = undefined;
        const inbox = try std.fmt.bufPrint(&inbox_buf, "https://h{d}.example/inbox", .{i});
        const plen = rand.intRangeAtMost(usize, 1, pay_buf.len);
        rand.bytes(pay_buf[0..plen]);
        try p.enqueue(queue.topic_ap_outbox, inbox, pay_buf[0..plen], "kid-1", 1000);
    }
    try testing.expectEqual(@as(i64, @intCast(total)), countRows(db, "SELECT COUNT(*) FROM ap_federation_outbox WHERE state='pending'"));

    // Claim a bounded batch; payload/meta round-trip. (The order among
    // equal next_attempt_at is unspecified, so assert shape not identity.)
    var batch: [3]Job = undefined;
    const claimed = try p.dequeueBatch(queue.topic_ap_outbox, 1000, &batch);
    try testing.expectEqual(@as(usize, 3), claimed);
    for (batch[0..claimed]) |*j| {
        try testing.expect(std.mem.startsWith(u8, j.key(), "https://h"));
        try testing.expectEqualStrings("kid-1", j.meta());
        try testing.expectEqual(@as(u32, 0), j.attempts);
    }

    // ack(done), nack(retry+1/reschedule), deadLetter(park).
    try p.ack(queue.topic_ap_outbox, &batch[0]);
    try p.nack(queue.topic_ap_outbox, &batch[1], 5000);
    try p.deadLetter(queue.topic_ap_outbox, &batch[2], "boom");

    try testing.expectEqual(@as(i64, 1), countRows(db, "SELECT COUNT(*) FROM ap_federation_outbox WHERE state='done'"));
    try testing.expectEqual(@as(i64, 1), countRows(db, "SELECT COUNT(*) FROM ap_federation_dead_letter WHERE last_error='boom'"));

    // The nacked row: attempts incremented to 1, not claimable before 5000.
    try testing.expectEqual(@as(i64, 1), countRows(db, "SELECT attempts FROM ap_federation_outbox WHERE state='pending' AND attempts=1"));
    var early: [8]Job = undefined;
    const due_now = try p.dequeueBatch(queue.topic_ap_outbox, 1000, &early);
    // The remaining (total-3) untouched rows are due; the nacked one is not.
    try testing.expectEqual(@as(usize, @min(@as(usize, 8), total - 3)), due_now);
    for (early[0..due_now]) |*j| {
        try testing.expect(j.attempts == 0); // nacked row (attempts=1) excluded until 5000
    }
}

test "ApOutboxQueue: oversized payload rejected at enqueue" {
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try schema.applyAllForTests(db);
    var sc = core.clock.SimClock.init(0);
    var apq = ApOutboxQueue.init(db, sc.clock());
    const p = apq.provider();
    var big: [queue.max_payload_bytes + 1]u8 = undefined;
    @memset(&big, 'x');
    try testing.expectError(error.PayloadTooLarge, p.enqueue(queue.topic_ap_outbox, "https://x/inbox", &big, "k", 0));
}

test {
    testing.refAllDecls(ApOutboxQueue);
}
