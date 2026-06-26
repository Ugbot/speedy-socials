//! `DbQueue` — the default SQLite-backed `QueueProvider`.
//!
//! A durable, topic-partitioned job queue over a single `core_queue`
//! table: enqueue appends a `pending` row; `dequeueBatch` claims the due
//! rows (oldest first); `ack` deletes a completed job; `nack` reschedules
//! with an incremented attempt count; `deadLetter` parks the row as
//! `dead` with a reason for inspection. The same semantics the AP
//! delivery outbox already uses (pending / next-attempt / attempts /
//! dead-letter), generalized behind `core.queue.QueueProvider` so a
//! Redis/NATS/Kafka-backed queue can drop in without touching callers.
//!
//! Tiger Style: synchronous prepare/step on the caller's handle (no
//! per-op allocation); claims are bounded by the caller's `out` slice and
//! payloads by the fixed `Job` buffers (enforced via `Job.set`). Reads of
//! the same handle from multiple threads follow the existing repo
//! convention (WAL + busy_timeout); the AP outbox worker is single.

const std = @import("std");
const c = @import("sqlite").c;
const queue = @import("../queue.zig");
const schema = @import("../storage/schema.zig");

const Job = queue.Job;
const Error = queue.Error;
const QueueProvider = queue.QueueProvider;

/// Schema for the generic durable queue. Registered by the composition
/// root alongside the other core migrations.
pub const migration: schema.Migration = .{
    .id = 70,
    .name = "core:queue",
    .up =
    \\CREATE TABLE IF NOT EXISTS core_queue (
    \\    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    \\    topic       TEXT NOT NULL,
    \\    key         TEXT NOT NULL DEFAULT '',
    \\    payload     BLOB NOT NULL,
    \\    meta        TEXT NOT NULL DEFAULT '',
    \\    attempts    INTEGER NOT NULL DEFAULT 0,
    \\    not_before  INTEGER NOT NULL DEFAULT 0,
    \\    state       TEXT NOT NULL DEFAULT 'pending',
    \\    dead_reason TEXT,
    \\    created_at  INTEGER NOT NULL DEFAULT 0
    \\);
    \\CREATE INDEX IF NOT EXISTS idx_core_queue_claim
    \\    ON core_queue (topic, state, not_before, id);
    ,
    .up_pg =
    \\CREATE TABLE IF NOT EXISTS core_queue (
    \\    id          BIGSERIAL PRIMARY KEY,
    \\    topic       TEXT NOT NULL,
    \\    key         TEXT NOT NULL DEFAULT '',
    \\    payload     BYTEA NOT NULL,
    \\    meta        TEXT NOT NULL DEFAULT '',
    \\    attempts    BIGINT NOT NULL DEFAULT 0,
    \\    not_before  BIGINT NOT NULL DEFAULT 0,
    \\    state       TEXT NOT NULL DEFAULT 'pending',
    \\    dead_reason TEXT,
    \\    created_at  BIGINT NOT NULL DEFAULT 0
    \\);
    \\CREATE INDEX IF NOT EXISTS idx_core_queue_claim
    \\    ON core_queue (topic, state, not_before, id);
    ,
    .down = null,
};

pub const DbQueue = struct {
    db: *c.sqlite3,

    pub fn init(db: *c.sqlite3) DbQueue {
        return .{ .db = db };
    }

    pub fn provider(self: *DbQueue) QueueProvider {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: QueueProvider.VTable = .{
        .enqueue = doEnqueue,
        .dequeueBatch = doDequeueBatch,
        .ack = doAck,
        .nack = doNack,
        .deadLetter = doDeadLetter,
    };

    fn doEnqueue(
        ptr: *anyopaque,
        topic: []const u8,
        key: []const u8,
        payload: []const u8,
        meta: []const u8,
        not_before_unix: i64,
    ) Error!void {
        const self: *DbQueue = @ptrCast(@alignCast(ptr));
        if (key.len > queue.max_key_bytes or payload.len > queue.max_payload_bytes or meta.len > queue.max_meta_bytes) {
            return error.PayloadTooLarge;
        }
        var stmt: ?*c.sqlite3_stmt = null;
        const sql =
            \\INSERT INTO core_queue (topic, key, payload, meta, attempts, not_before, state, created_at)
            \\VALUES (?, ?, ?, ?, 0, ?, 'pending', ?)
        ;
        if (c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.BackendFailed;
        defer _ = c.sqlite3_finalize(stmt);
        bindText(stmt, 1, topic);
        bindText(stmt, 2, key);
        _ = c.sqlite3_bind_blob(stmt, 3, payload.ptr, @intCast(payload.len), c.sqliteTransientAsDestructor());
        bindText(stmt, 4, meta);
        _ = c.sqlite3_bind_int64(stmt, 5, not_before_unix);
        _ = c.sqlite3_bind_int64(stmt, 6, not_before_unix);
        if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return error.BackendFailed;
    }

    fn doDequeueBatch(ptr: *anyopaque, topic: []const u8, now_unix: i64, out: []Job) Error!usize {
        const self: *DbQueue = @ptrCast(@alignCast(ptr));
        if (out.len == 0) return 0;
        var stmt: ?*c.sqlite3_stmt = null;
        const sql =
            \\SELECT id, attempts, key, payload, meta FROM core_queue
            \\WHERE topic = ? AND state = 'pending' AND not_before <= ?
            \\ORDER BY id ASC LIMIT ?
        ;
        if (c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.BackendFailed;
        defer _ = c.sqlite3_finalize(stmt);
        bindText(stmt, 1, topic);
        _ = c.sqlite3_bind_int64(stmt, 2, now_unix);
        _ = c.sqlite3_bind_int64(stmt, 3, @intCast(out.len));

        var n: usize = 0;
        while (n < out.len) {
            const rc = c.sqlite3_step(stmt.?);
            if (rc == c.SQLITE_DONE) break;
            if (rc != c.SQLITE_ROW) return error.BackendFailed;
            var job: Job = .{};
            job.id = c.sqlite3_column_int64(stmt, 0);
            job.attempts = @intCast(c.sqlite3_column_int64(stmt, 1));
            const k = columnSlice(stmt, 2);
            const p = columnBlob(stmt, 3);
            const m = columnSlice(stmt, 4);
            job.set(k, p, m) catch return error.PayloadTooLarge;
            out[n] = job;
            n += 1;
        }
        return n;
    }

    fn doAck(ptr: *anyopaque, topic: []const u8, job: *const Job) Error!void {
        const self: *DbQueue = @ptrCast(@alignCast(ptr));
        _ = topic;
        try self.execById("DELETE FROM core_queue WHERE id = ?", job.id);
    }

    fn doNack(ptr: *anyopaque, topic: []const u8, job: *const Job, retry_at_unix: i64) Error!void {
        const self: *DbQueue = @ptrCast(@alignCast(ptr));
        _ = topic;
        var stmt: ?*c.sqlite3_stmt = null;
        const sql = "UPDATE core_queue SET attempts = attempts + 1, not_before = ?, state = 'pending' WHERE id = ?";
        if (c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.BackendFailed;
        defer _ = c.sqlite3_finalize(stmt);
        _ = c.sqlite3_bind_int64(stmt, 1, retry_at_unix);
        _ = c.sqlite3_bind_int64(stmt, 2, job.id);
        if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return error.BackendFailed;
    }

    fn doDeadLetter(ptr: *anyopaque, topic: []const u8, job: *const Job, reason: []const u8) Error!void {
        const self: *DbQueue = @ptrCast(@alignCast(ptr));
        _ = topic;
        var stmt: ?*c.sqlite3_stmt = null;
        const sql = "UPDATE core_queue SET state = 'dead', dead_reason = ? WHERE id = ?";
        if (c.sqlite3_prepare_v2(self.db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.BackendFailed;
        defer _ = c.sqlite3_finalize(stmt);
        bindText(stmt, 1, reason);
        _ = c.sqlite3_bind_int64(stmt, 2, job.id);
        if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return error.BackendFailed;
    }

    fn execById(self: *DbQueue, sql: []const u8, id: i64) Error!void {
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(self.db, sql.ptr, @intCast(sql.len), &stmt, null) != c.SQLITE_OK) return error.BackendFailed;
        defer _ = c.sqlite3_finalize(stmt);
        _ = c.sqlite3_bind_int64(stmt, 1, id);
        if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return error.BackendFailed;
    }
};

fn bindText(stmt: ?*c.sqlite3_stmt, idx: c_int, s: []const u8) void {
    _ = c.sqlite3_bind_text(stmt, idx, s.ptr, @intCast(s.len), c.sqliteTransientAsDestructor());
}

fn columnSlice(stmt: ?*c.sqlite3_stmt, idx: c_int) []const u8 {
    const p = c.sqlite3_column_text(stmt, idx);
    const n: usize = @intCast(c.sqlite3_column_bytes(stmt, idx));
    if (p == null or n == 0) return "";
    return p[0..n];
}

fn columnBlob(stmt: ?*c.sqlite3_stmt, idx: c_int) []const u8 {
    const p = c.sqlite3_column_blob(stmt, idx);
    const n: usize = @intCast(c.sqlite3_column_bytes(stmt, idx));
    if (p == null or n == 0) return "";
    const bp: [*]const u8 = @ptrCast(p);
    return bp[0..n];
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;
const sqlite = @import("../storage/sqlite.zig");

fn setupDb() !*c.sqlite3 {
    const db = try sqlite.openWriter(":memory:");
    const sql_z = try testing.allocator.dupeZ(u8, migration.up);
    defer testing.allocator.free(sql_z);
    var em: [*c]u8 = null;
    _ = c.sqlite3_exec(db, sql_z.ptr, null, null, &em);
    if (em != null) c.sqlite3_free(em);
    return db;
}

test "DbQueue: enqueue/dequeue/ack round-trip (randomized)" {
    const db = try setupDb();
    defer sqlite.closeDb(db);
    var q = DbQueue.init(db);
    const p = q.provider();

    var prng = std.Random.DefaultPrng.init(0x0_DB_0_05);
    const rand = prng.random();
    const n: usize = 12;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        var pay: [128]u8 = undefined;
        const plen = rand.intRangeAtMost(usize, 1, pay.len);
        rand.bytes(pay[0..plen]);
        try p.enqueue("ap_outbox", "https://inbox.example/u", pay[0..plen], "key-id-1", 1000);
    }

    // Claim a batch; oldest-first, only due jobs.
    var batch: [8]Job = undefined;
    const claimed = try p.dequeueBatch("ap_outbox", 1000, &batch);
    try testing.expectEqual(@as(usize, 8), claimed);
    try testing.expectEqualStrings("https://inbox.example/u", batch[0].key());
    try testing.expectEqualStrings("key-id-1", batch[0].meta());

    // Ack the first 8; 4 remain.
    var j: usize = 0;
    while (j < claimed) : (j += 1) try p.ack("ap_outbox", &batch[j]);
    const remaining = try p.dequeueBatch("ap_outbox", 1000, &batch);
    try testing.expectEqual(@as(usize, 4), remaining);
}

test "DbQueue: not_before gates claims; nack reschedules + counts attempts" {
    const db = try setupDb();
    defer sqlite.closeDb(db);
    var q = DbQueue.init(db);
    const p = q.provider();

    // Eligible at t=5000; not claimable at t=1000.
    try p.enqueue("t", "k", "payload", "", 5000);
    var batch: [4]Job = undefined;
    try testing.expectEqual(@as(usize, 0), try p.dequeueBatch("t", 1000, &batch));
    try testing.expectEqual(@as(usize, 1), try p.dequeueBatch("t", 5000, &batch));
    try testing.expectEqual(@as(u32, 0), batch[0].attempts);

    // Nack → not claimable before retry_at, attempts incremented.
    try p.nack("t", &batch[0], 9000);
    try testing.expectEqual(@as(usize, 0), try p.dequeueBatch("t", 8000, &batch));
    const again = try p.dequeueBatch("t", 9000, &batch);
    try testing.expectEqual(@as(usize, 1), again);
    try testing.expectEqual(@as(u32, 1), batch[0].attempts);
}

test "DbQueue: deadLetter parks the job out of the pending set" {
    const db = try setupDb();
    defer sqlite.closeDb(db);
    var q = DbQueue.init(db);
    const p = q.provider();

    try p.enqueue("t", "k", "payload", "", 0);
    var batch: [4]Job = undefined;
    try testing.expectEqual(@as(usize, 1), try p.dequeueBatch("t", 1, &batch));
    try p.deadLetter("t", &batch[0], "max attempts exceeded");
    // No longer claimable.
    try testing.expectEqual(@as(usize, 0), try p.dequeueBatch("t", 1, &batch));
    // The row persists for inspection.
    var cnt: ?*c.sqlite3_stmt = null;
    _ = c.sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM core_queue WHERE state='dead'", -1, &cnt, null);
    defer _ = c.sqlite3_finalize(cnt);
    _ = c.sqlite3_step(cnt);
    try testing.expectEqual(@as(i64, 1), c.sqlite3_column_int64(cnt, 0));
}

test "DbQueue: oversized payload rejected at enqueue" {
    const db = try setupDb();
    defer sqlite.closeDb(db);
    var q = DbQueue.init(db);
    const p = q.provider();
    var big: [queue.max_payload_bytes + 1]u8 = undefined;
    @memset(&big, 'x');
    try testing.expectError(error.PayloadTooLarge, p.enqueue("t", "k", &big, "", 0));
}
