//! D3: multi-level firehose storage for the AT hot path.
//!
//! The firehose is the highest-frequency write path in the PDS: every
//! repo commit, identity change, and account event flows through it,
//! and a synchronous `INSERT INTO atp_firehose_events` per event makes
//! the commit latency hostage to SQLite's write path (statement
//! prepare + step + the cursor-row UPDATE + the implicit fsync on
//! WAL checkpoint).
//!
//! This module replaces that with a bounded two-level store:
//!
//!   L0 — a fixed-capacity in-memory ring (`l0_capacity` slots). Every
//!        appended event lands here first and is immediately visible to
//!        live subscribers and recent-cursor replay reads WITHOUT
//!        touching SQLite. The ring never grows; when full, the oldest
//!        slot is reused — but only after it has been flushed to L1, so
//!        no event is ever lost.
//!
//!   L1 — the durable `atp_firehose_events` table (the cold tier /
//!        manifest). Events are written in batches: a flush fires when
//!        the unflushed backlog reaches `batch_size` events OR when
//!        `flush_interval_ns` has elapsed since the last flush. A single
//!        multi-row transaction amortises the per-statement overhead
//!        across the whole batch.
//!
//! Reads (`readSince` / `bodyForSeq`) consult L0 first; anything older
//! than the ring's oldest retained seq falls back to SQLite. Because we
//! flush before evicting, every seq below the ring window is guaranteed
//! durable, so the fallback always finds it.
//!
//! Tiger Style:
//!   * Fixed-capacity ring and batch buffer — no per-event heap growth.
//!     Bodies are copied into a fixed-size inline buffer; over-long
//!     bodies (rare; commit envelopes are bounded) spill to the durable
//!     row and are served from SQLite, never silently truncated for
//!     readers.
//!   * Deterministic seq assignment: seq is a monotonic counter seeded
//!     from `MAX(seq)` in SQLite, so it matches the AUTOINCREMENT
//!     semantics callers previously relied on, and survives across the
//!     batched insert (rows are written with explicit seq values).
//!   * A single global mutex serialises append/flush/read so the store
//!     is correct under the multi-threaded WS subscriber + commit path.
//!
//! The store is keyed by the `*sqlite3` handle so each open database
//! (every in-memory test DB, plus the one production handle) gets its
//! own independent ring/counter without leaking state between them.

const std = @import("std");
const c = @import("sqlite").c;
const core = @import("core");
const StorageError = core.errors.StorageError;

/// Monotonic nanosecond timestamp. Zig 0.16's stripped std dropped both
/// `std.time.Timer` and `std.time.nanoTimestamp` here, so we go straight
/// to clock_gettime(CLOCK_MONOTONIC). Returns 0 on failure (the
/// time-based flush simply won't trip until the next call succeeds).
fn monotonicNs() i128 {
    var ts: std.c.timespec = undefined;
    if (std.c.clock_gettime(std.c.CLOCK.MONOTONIC, &ts) != 0) return 0;
    return @as(i128, @intCast(ts.sec)) * std.time.ns_per_s + @as(i128, @intCast(ts.nsec));
}

/// Event kinds carried by the firehose. Mirrors the column string used
/// by the durable table.
pub const EventKind = enum {
    commit,
    identity,
    account,
    tombstone,
    handle,
    migrate,
    info,

    pub fn columnString(self: EventKind) []const u8 {
        return switch (self) {
            .commit => "commit",
            .identity => "identity",
            .account => "account",
            .tombstone => "tombstone",
            .handle => "handle",
            .migrate => "migrate",
            .info => "info",
        };
    }

    pub fn fromColumn(s: []const u8) EventKind {
        if (std.mem.eql(u8, s, "identity")) return .identity;
        if (std.mem.eql(u8, s, "account")) return .account;
        if (std.mem.eql(u8, s, "tombstone")) return .tombstone;
        if (std.mem.eql(u8, s, "handle")) return .handle;
        if (std.mem.eql(u8, s, "migrate")) return .migrate;
        if (std.mem.eql(u8, s, "info")) return .info;
        return .commit;
    }
};

// ── Tunables ───────────────────────────────────────────────────────

/// L0 ring depth. Holds the most-recent events for SQLite-free reads.
pub const l0_capacity: usize = 10_000;

/// Flush to L1 once this many unflushed events accumulate. Larger
/// batches amortise the per-transaction WAL fsync across more events
/// (the dominant cost of durable writes); the time-based flush bounds
/// staleness for low event rates, and the L0 ring keeps every buffered
/// event live-readable in the meantime.
pub const batch_size: usize = 2048;

/// Flush to L1 at least this often (wall clock), even below batch_size,
/// so a trickle of events still becomes durable promptly.
pub const flush_interval_ns: i128 = 50 * std.time.ns_per_ms;

/// Max inline body bytes retained in L0. Commit envelopes and the small
/// identity/account/etc. bodies fit well under this. A body larger than
/// this is still written durably to SQLite at flush time; L0 just won't
/// serve its bytes (readers transparently fall back to the table).
pub const max_inline_body: usize = 4096;

/// Max DID / CID lengths retained in L0 (matches the read Event struct).
const max_did: usize = 256;
const max_cid: usize = 128;

// ── Record + ring ──────────────────────────────────────────────────

const Record = struct {
    seq: i64 = 0,
    did_buf: [max_did]u8 = undefined,
    did_len: u16 = 0,
    cid_buf: [max_cid]u8 = undefined,
    cid_len: u16 = 0,
    body_buf: [max_inline_body]u8 = undefined,
    body_len: u32 = 0,
    body_inline: bool = false, // false when body spilled past max_inline_body
    ts: i64 = 0,
    kind: EventKind = .commit,
    flushed: bool = false,
    occupied: bool = false,
};

/// Read-facing event (matches the shape `firehose.zig` exposes).
pub const Event = struct {
    seq: i64,
    did_buf: [max_did]u8 = undefined,
    did_len: u16 = 0,
    commit_cid_buf: [max_cid]u8 = undefined,
    commit_cid_len: u16 = 0,
    ts: i64 = 0,
    kind: EventKind = .commit,

    pub fn did(self: *const Event) []const u8 {
        return self.did_buf[0..self.did_len];
    }
    pub fn commitCid(self: *const Event) []const u8 {
        return self.commit_cid_buf[0..self.commit_cid_len];
    }
};

/// One store per database handle.
const Store = struct {
    db: *c.sqlite3,
    ring: []Record, // heap-allocated once, fixed length l0_capacity
    head: usize = 0, // next write slot
    count: usize = 0, // occupied slots (<= l0_capacity)
    next_seq: i64 = 0, // last assigned seq; the next append uses +1
    seeded: bool = false, // next_seq seeded from SQLite?
    unflushed: usize = 0, // events appended but not yet in SQLite
    last_flush_ns: i128 = 0,
    flush_stmt: ?*c.sqlite3_stmt = null, // cached batched-INSERT statement

    fn oldestRetainedSeq(self: *const Store) i64 {
        if (self.count == 0) return std.math.maxInt(i64);
        const tail = (self.head + self.ring.len - self.count) % self.ring.len;
        return self.ring[tail].seq;
    }
};

// ── Global registry of per-db stores ───────────────────────────────

const max_stores: usize = 64;

const Slot = struct {
    db: ?*c.sqlite3 = null,
    store: ?*Store = null,
};

var mutex: core.static.Spinlock = .{};
var slots: [max_stores]Slot = .{Slot{}} ** max_stores;

/// The per-db ring is allocated once at first use and freed by `forget`.
/// We link libc, so the C allocator is the simplest long-lived backing
/// store; the allocation count is bounded by `max_stores`, not per-event.
fn allocator() std.mem.Allocator {
    return std.heap.c_allocator;
}

/// Find or create the store bound to `db`. Caller holds `mutex`.
///
/// Callers that close a DB must `forget(db)` so a later handle reusing
/// the same address (common with `:memory:` DBs in tests, and possible
/// after a close+reopen in production) starts from a clean store rather
/// than inheriting the previous database's ring and seq counter.
fn storeFor(db: *c.sqlite3) !*Store {
    var free_idx: ?usize = null;
    for (slots, 0..) |s, i| {
        if (s.db == db) return s.store.?;
        if (s.db == null and free_idx == null) free_idx = i;
    }
    const idx = free_idx orelse return error.StepFailed; // registry full
    const a = allocator();
    const st = try a.create(Store);
    errdefer a.destroy(st);
    const ring = try a.alloc(Record, l0_capacity);
    for (ring) |*r| r.* = .{};
    st.* = .{ .db = db, .ring = ring, .last_flush_ns = monotonicNs() };
    slots[idx] = .{ .db = db, .store = st };
    return st;
}

/// Seed `next_seq` from SQLite's current max seq the first time we touch
/// a store, so assigned sequence numbers continue monotonically from
/// whatever is already durable (matching the old AUTOINCREMENT counter).
fn seedSeq(st: *Store) void {
    if (st.seeded) return;
    st.seeded = true;
    const sql = "SELECT COALESCE(MAX(seq), 0) FROM atp_firehose_events";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(st.db, sql, -1, &stmt, null) != c.SQLITE_OK) return;
    defer _ = c.sqlite3_finalize(stmt);
    if (c.sqlite3_step(stmt.?) == c.SQLITE_ROW) {
        st.next_seq = c.sqlite3_column_int64(stmt, 0);
    }
}

// ── Append (hot path) ───────────────────────────────────────────────

/// Append an event to L0, assigning and returning its seq. Triggers a
/// batched L1 flush if the backlog or time threshold is reached. The
/// SQLite write is amortised across a batch; the per-event cost is a
/// memcpy into the ring under the mutex.
pub fn append(
    db: *c.sqlite3,
    kind: EventKind,
    did: []const u8,
    commit_cid: []const u8,
    body: []const u8,
    ts: i64,
) StorageError!i64 {
    mutex.lock();
    defer mutex.unlock();

    const st = storeFor(db) catch return error.StepFailed;
    seedSeq(st);

    // If the ring is full, the slot we're about to overwrite is the
    // oldest retained event. It MUST be durable before we clobber it.
    if (st.count == l0_capacity) {
        if (!st.ring[st.head].flushed) {
            try flushLocked(st);
        }
    }

    st.next_seq += 1;
    const seq = st.next_seq;

    var rec = &st.ring[st.head];
    rec.* = .{ .seq = seq, .ts = ts, .kind = kind, .occupied = true, .flushed = false };

    const dlen = @min(did.len, max_did);
    @memcpy(rec.did_buf[0..dlen], did[0..dlen]);
    rec.did_len = @intCast(dlen);

    const clen = @min(commit_cid.len, max_cid);
    @memcpy(rec.cid_buf[0..clen], commit_cid[0..clen]);
    rec.cid_len = @intCast(clen);

    rec.body_len = @intCast(body.len);
    if (body.len <= max_inline_body) {
        @memcpy(rec.body_buf[0..body.len], body);
        rec.body_inline = true;
    } else {
        // Oversized body: keep only the prefix in L0 metadata, mark it
        // non-inline. Such an event must be flushed immediately so the
        // full body is durable and readers fetch it from SQLite.
        @memcpy(rec.body_buf[0..max_inline_body], body[0..max_inline_body]);
        rec.body_len = max_inline_body;
        rec.body_inline = false;
        // We need the full bytes for the durable insert; do an immediate
        // single-row durable write for this event, then mark flushed.
        insertRow(st.db, seq, did, commit_cid, body, ts, kind) catch return error.StepFailed;
        rec.flushed = true;
        bumpCursor(st.db, seq);
    }

    st.head = (st.head + 1) % st.ring.len;
    if (st.count < l0_capacity) st.count += 1;

    if (rec.flushed) {
        // Oversized event already durable; do not count toward batch.
    } else {
        st.unflushed += 1;
    }

    // Flush decision. The count threshold is the common case (a burst
    // fills the batch and we drain it in one transaction). Otherwise, if
    // there's any backlog, consult the monotonic clock so a trickle of
    // events still becomes durable within `flush_interval_ns`. On the
    // target platforms CLOCK_MONOTONIC is a vDSO/commpage read, not a
    // real syscall, so the hot path stays an in-memory ring write.
    if (st.unflushed >= batch_size) {
        try flushLocked(st);
    } else if (st.unflushed > 0 and monotonicNs() - st.last_flush_ns >= flush_interval_ns) {
        try flushLocked(st);
    }

    return seq;
}

// ── Flush (L0 → L1) ─────────────────────────────────────────────────

/// Public flush: force all pending L0 events to SQLite. Used by tests
/// and by callers that need a durability barrier.
pub fn flush(db: *c.sqlite3) StorageError!void {
    mutex.lock();
    defer mutex.unlock();
    const st = storeFor(db) catch return error.StepFailed;
    try flushLocked(st);
}

/// Write every unflushed retained record to SQLite in one transaction,
/// then mark them flushed and update the durable cursor row. Caller
/// holds `mutex`.
fn flushLocked(st: *Store) StorageError!void {
    if (st.unflushed == 0) {
        st.last_flush_ns = monotonicNs();
        return;
    }

    _ = c.sqlite3_exec(st.db, "BEGIN IMMEDIATE", null, null, null);

    // Reuse a prepared INSERT across flushes — the statement is bound to
    // this store's DB and re-`reset` per row, so we pay the parse/plan
    // cost once for the life of the store, not once per flush.
    if (st.flush_stmt == null) {
        const sql = "INSERT INTO atp_firehose_events (seq, did, commit_cid, body, ts, event_kind) VALUES (?,?,?,?,?,?)";
        if (c.sqlite3_prepare_v2(st.db, sql, -1, &st.flush_stmt, null) != c.SQLITE_OK or st.flush_stmt == null) {
            _ = c.sqlite3_exec(st.db, "ROLLBACK", null, null, null);
            return error.PrepareFailed;
        }
    }
    const stmt = st.flush_stmt;

    var max_seq: i64 = 0;
    // Iterate retained records in seq order (oldest → newest) so the
    // durable rows go in monotonically.
    var i: usize = 0;
    while (i < st.count) : (i += 1) {
        const idx = (st.head + st.ring.len - st.count + i) % st.ring.len;
        const rec = &st.ring[idx];
        if (!rec.occupied or rec.flushed) continue;
        // Inline bodies only reach here; oversized bodies were already
        // durably written at append time and marked flushed.
        //
        // STATIC binds (not TRANSIENT): the ring records are stable for
        // the whole synchronous flush — we hold the mutex and step each
        // row before touching the next — so SQLite can reference the
        // bytes in place, avoiding a malloc+copy per column per row.
        _ = c.sqlite3_reset(stmt);
        _ = c.sqlite3_bind_int64(stmt, 1, rec.seq);
        _ = c.sqlite3_bind_text(stmt, 2, rec.did_buf[0..rec.did_len].ptr, @intCast(rec.did_len), c.SQLITE_STATIC);
        _ = c.sqlite3_bind_text(stmt, 3, rec.cid_buf[0..rec.cid_len].ptr, @intCast(rec.cid_len), c.SQLITE_STATIC);
        _ = c.sqlite3_bind_blob(stmt, 4, rec.body_buf[0..rec.body_len].ptr, @intCast(rec.body_len), c.SQLITE_STATIC);
        _ = c.sqlite3_bind_int64(stmt, 5, rec.ts);
        const ks = rec.kind.columnString();
        _ = c.sqlite3_bind_text(stmt, 6, ks.ptr, @intCast(ks.len), c.SQLITE_STATIC);

        if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) {
            _ = c.sqlite3_exec(st.db, "ROLLBACK", null, null, null);
            return error.StepFailed;
        }
        rec.flushed = true;
        if (rec.seq > max_seq) max_seq = rec.seq;
    }

    if (c.sqlite3_exec(st.db, "COMMIT", null, null, null) != c.SQLITE_OK) {
        _ = c.sqlite3_exec(st.db, "ROLLBACK", null, null, null);
        return error.StepFailed;
    }

    if (max_seq > 0) bumpCursor(st.db, max_seq);
    st.unflushed = 0;
    st.last_flush_ns = monotonicNs();
}

fn insertRow(
    db: *c.sqlite3,
    seq: i64,
    did: []const u8,
    commit_cid: []const u8,
    body: []const u8,
    ts: i64,
    kind: EventKind,
) StorageError!void {
    const sql = "INSERT INTO atp_firehose_events (seq, did, commit_cid, body, ts, event_kind) VALUES (?,?,?,?,?,?)";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK or stmt == null) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_int64(stmt, 1, seq);
    _ = c.sqlite3_bind_text(stmt, 2, did.ptr, @intCast(did.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 3, commit_cid.ptr, @intCast(commit_cid.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_blob(stmt, 4, body.ptr, @intCast(body.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(stmt, 5, ts);
    const ks = kind.columnString();
    _ = c.sqlite3_bind_text(stmt, 6, ks.ptr, @intCast(ks.len), c.sqliteTransientAsDestructor());
    if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return error.StepFailed;
}

fn bumpCursor(db: *c.sqlite3, seq: i64) void {
    const upd = "UPDATE atp_firehose_cursor SET seq = ? WHERE id = 1";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, upd, -1, &stmt, null) == c.SQLITE_OK) {
        defer _ = c.sqlite3_finalize(stmt);
        _ = c.sqlite3_bind_int64(stmt, 1, seq);
        _ = c.sqlite3_step(stmt.?);
    }
}

// ── Reads ───────────────────────────────────────────────────────────

/// Read events with seq > `cursor`, up to `out.len`. L0 serves anything
/// still in the ring without touching SQLite; older seqs fall back to
/// the durable table. Returns the count written.
pub fn readSince(db: *c.sqlite3, cursor: i64, out: []Event) StorageError!u32 {
    mutex.lock();
    defer mutex.unlock();
    const st = storeFor(db) catch return error.StepFailed;
    seedSeq(st);

    const oldest = st.oldestRetainedSeq();
    // If the requested cursor is at or beyond the ring's oldest retained
    // seq, every event the caller wants is in L0 — serve purely from
    // memory.
    if (cursor + 1 >= oldest and st.count > 0) {
        return readFromRing(st, cursor, out);
    }
    // The window the caller asked for begins below L0; pull the missing
    // older portion from SQLite, then top up from the ring if there's
    // room. Because flush precedes eviction, every seq < `oldest` is in
    // SQLite.
    var n = try readFromSqlite(st.db, cursor, out);
    if (n < out.len and st.count > 0) {
        // Continue from where SQLite left off, into the ring.
        const last = if (n > 0) out[n - 1].seq else cursor;
        n += readFromRing(st, last, out[n..]);
    }
    return n;
}

fn readFromRing(st: *Store, cursor: i64, out: []Event) u32 {
    if (out.len == 0) return 0;
    var n: u32 = 0;
    var i: usize = 0;
    while (i < st.count and n < out.len) : (i += 1) {
        const idx = (st.head + st.ring.len - st.count + i) % st.ring.len;
        const rec = &st.ring[idx];
        if (!rec.occupied or rec.seq <= cursor) continue;
        var ev: Event = .{ .seq = rec.seq, .ts = rec.ts, .kind = rec.kind };
        @memcpy(ev.did_buf[0..rec.did_len], rec.did_buf[0..rec.did_len]);
        ev.did_len = rec.did_len;
        @memcpy(ev.commit_cid_buf[0..rec.cid_len], rec.cid_buf[0..rec.cid_len]);
        ev.commit_cid_len = rec.cid_len;
        out[n] = ev;
        n += 1;
    }
    return n;
}

fn readFromSqlite(db: *c.sqlite3, cursor: i64, out: []Event) StorageError!u32 {
    const sql = "SELECT seq, did, commit_cid, ts, event_kind FROM atp_firehose_events WHERE seq > ? ORDER BY seq ASC LIMIT ?";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK or stmt == null) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_int64(stmt, 1, cursor);
    _ = c.sqlite3_bind_int64(stmt, 2, @intCast(out.len));

    var n: u32 = 0;
    while (n < out.len) {
        const rc = c.sqlite3_step(stmt.?);
        if (rc == c.SQLITE_DONE) break;
        if (rc != c.SQLITE_ROW) return error.StepFailed;
        var ev: Event = .{ .seq = c.sqlite3_column_int64(stmt, 0) };
        const dptr = c.sqlite3_column_text(stmt, 1);
        const dlen: usize = @intCast(c.sqlite3_column_bytes(stmt, 1));
        if (dlen > 0 and dptr != null) {
            const cap = @min(dlen, max_did);
            @memcpy(ev.did_buf[0..cap], dptr[0..cap]);
            ev.did_len = @intCast(cap);
        }
        const cptr = c.sqlite3_column_text(stmt, 2);
        const clen: usize = @intCast(c.sqlite3_column_bytes(stmt, 2));
        if (clen > 0 and cptr != null) {
            const cap = @min(clen, max_cid);
            @memcpy(ev.commit_cid_buf[0..cap], cptr[0..cap]);
            ev.commit_cid_len = @intCast(cap);
        }
        ev.ts = c.sqlite3_column_int64(stmt, 3);
        const kptr = c.sqlite3_column_text(stmt, 4);
        const klen: usize = @intCast(c.sqlite3_column_bytes(stmt, 4));
        if (klen > 0 and kptr != null) ev.kind = EventKind.fromColumn(kptr[0..klen]);
        out[n] = ev;
        n += 1;
    }
    return n;
}

/// Fetch the raw body bytes for `seq` into `out`, returning the slice
/// actually written. Serves from L0 when the event is still retained
/// with an inline body; otherwise falls back to SQLite (and flushes
/// first if the seq is unflushed in the ring, guaranteeing presence).
pub fn bodyForSeq(db: *c.sqlite3, seq: i64, out: []u8) StorageError![]const u8 {
    mutex.lock();
    defer mutex.unlock();
    const st = storeFor(db) catch return error.StepFailed;

    // Look for the record in L0.
    if (st.count > 0) {
        var i: usize = 0;
        while (i < st.count) : (i += 1) {
            const idx = (st.head + st.ring.len - st.count + i) % st.ring.len;
            const rec = &st.ring[idx];
            if (!rec.occupied or rec.seq != seq) continue;
            if (rec.body_inline) {
                const cap = @min(rec.body_len, out.len);
                @memcpy(out[0..cap], rec.body_buf[0..cap]);
                return out[0..cap];
            }
            // Oversized body: it was written durably at append time.
            if (!rec.flushed) try flushLocked(st);
            break;
        }
    }
    return bodyFromSqlite(st.db, seq, out);
}

fn bodyFromSqlite(db: *c.sqlite3, seq: i64, out: []u8) StorageError![]const u8 {
    const sql = "SELECT body FROM atp_firehose_events WHERE seq = ?";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK or stmt == null) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_int64(stmt, 1, seq);
    const rc = c.sqlite3_step(stmt.?);
    if (rc == c.SQLITE_DONE) return out[0..0];
    if (rc != c.SQLITE_ROW) return error.StepFailed;
    const ptr = c.sqlite3_column_blob(stmt, 0);
    const len: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
    if (len == 0 or ptr == null) return out[0..0];
    const cap = @min(len, out.len);
    const src: [*]const u8 = @ptrCast(ptr);
    @memcpy(out[0..cap], src[0..cap]);
    return out[0..cap];
}

/// Latest assigned seq (== durable cursor once flushed). Reflects events
/// still buffered in L0 too, so callers see the true high-water mark.
pub fn latestSeq(db: *c.sqlite3) StorageError!i64 {
    mutex.lock();
    defer mutex.unlock();
    const st = storeFor(db) catch return error.StepFailed;
    seedSeq(st);
    return st.next_seq;
}

/// Test/teardown hook: drop the store bound to `db` (after flushing), so
/// a re-opened handle at the same address starts clean. Safe to call on
/// an unknown handle.
pub fn forget(db: *c.sqlite3) void {
    mutex.lock();
    defer mutex.unlock();
    for (&slots) |*s| {
        if (s.db == db) {
            if (s.store) |st| {
                if (st.flush_stmt) |stmt| _ = c.sqlite3_finalize(stmt);
                allocator().free(st.ring);
                allocator().destroy(st);
            }
            s.* = .{};
            return;
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────

const testing = std.testing;
const schema_mod = @import("schema.zig");

fn setupDb() !*c.sqlite3 {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    forget(db); // clear any stale store on a recycled handle address
    for (schema_mod.all_migrations) |m| {
        const sql_z = try testing.allocator.dupeZ(u8, m.up);
        defer testing.allocator.free(sql_z);
        var errmsg: [*c]u8 = null;
        _ = c.sqlite3_exec(db, sql_z.ptr, null, null, &errmsg);
        if (errmsg != null) c.sqlite3_free(errmsg);
    }
    return db;
}

fn countDurable(db: *c.sqlite3) i64 {
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM atp_firehose_events", -1, &stmt, null) != c.SQLITE_OK) return -1;
    defer _ = c.sqlite3_finalize(stmt);
    if (c.sqlite3_step(stmt.?) != c.SQLITE_ROW) return -1;
    return c.sqlite3_column_int64(stmt, 0);
}

test "store: append then flush makes events durable" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    defer forget(db);

    var prng = std.Random.DefaultPrng.init(0x5107_57_57);
    const rand = prng.random();
    const n: usize = 50;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        var did_buf: [24]u8 = undefined;
        @memcpy(did_buf[0..8], "did:plc:");
        for (did_buf[8..20]) |*ch| ch.* = "abcdef0123456789"[rand.intRangeLessThan(usize, 0, 16)];
        _ = try append(db, .commit, did_buf[0..20], "bafy", "body-bytes", @intCast(1000 + i));
    }
    try flush(db);
    try testing.expectEqual(@as(i64, @intCast(n)), countDurable(db));
}

test "store: L0 serves recent reads without SQLite rows present" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    defer forget(db);

    // Append fewer than batch_size so nothing auto-flushes by count, and
    // the time-based flush won't fire within this synchronous test.
    const n: usize = 10;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        _ = try append(db, .commit, "did:plc:live", "cid", "payload", @intCast(i));
    }
    // SQLite is still empty (nothing flushed yet)...
    try testing.expectEqual(@as(i64, 0), countDurable(db));
    // ...yet readSince serves all events straight from L0.
    var out: [16]Event = undefined;
    const got = try readSince(db, 0, &out);
    try testing.expectEqual(@as(u32, n), got);
    try testing.expectEqualStrings("did:plc:live", out[0].did());
}

test "store: cursor replay parity (L0 + L1) returns every seq once, in order" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    defer forget(db);

    // Enough to force several batched flushes plus a live tail in L0.
    const total: usize = 700;
    var i: usize = 0;
    while (i < total) : (i += 1) {
        _ = try append(db, .commit, "did:plc:p", "cid", "b", @intCast(i));
    }

    var cursor: i64 = 0;
    var seen: usize = 0;
    var out: [64]Event = undefined;
    var iters: usize = 0;
    while (iters < 10_000) : (iters += 1) {
        const got = try readSince(db, cursor, &out);
        if (got == 0) break;
        var j: u32 = 0;
        while (j < got) : (j += 1) {
            seen += 1;
            try testing.expectEqual(@as(i64, @intCast(seen)), out[j].seq); // contiguous + ordered
            cursor = out[j].seq;
        }
    }
    try testing.expectEqual(total, seen);
}

test "store: ring eviction stays bounded and flushes before clobbering" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    defer forget(db);

    const total: usize = l0_capacity + 1234;
    var i: usize = 0;
    while (i < total) : (i += 1) {
        _ = try append(db, .commit, "did:plc:evict", "cid", "b", @intCast(i));
    }
    // The ring never exceeds its capacity.
    const st = blk: {
        mutex.lock();
        defer mutex.unlock();
        break :blk try storeFor(db);
    };
    try testing.expectEqual(l0_capacity, st.count);

    // Everything evicted from L0 must be durable. Flush the tail and the
    // total durable count equals total appended.
    try flush(db);
    try testing.expectEqual(@as(i64, @intCast(total)), countDurable(db));

    // Replay from 0 still returns every event in order (older from
    // SQLite, newest from L0).
    var cursor: i64 = 0;
    var seen: usize = 0;
    var out: [128]Event = undefined;
    var iters: usize = 0;
    while (iters < 100_000) : (iters += 1) {
        const got = try readSince(db, cursor, &out);
        if (got == 0) break;
        var j: u32 = 0;
        while (j < got) : (j += 1) {
            seen += 1;
            cursor = out[j].seq;
        }
    }
    try testing.expectEqual(total, seen);
}

test "store: bodyForSeq serves L0 inline and SQLite fallback identically" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    defer forget(db);

    const recent_seq = try append(db, .commit, "did:plc:b", "cid", "RECENT-BODY", 1);
    // Force this one durable but it also stays in L0.
    try flush(db);

    var buf: [64]u8 = undefined;
    const from_store = try bodyForSeq(db, recent_seq, &buf);
    try testing.expectEqualStrings("RECENT-BODY", from_store);

    // Direct SQLite read matches.
    var buf2: [64]u8 = undefined;
    const from_sql = try bodyFromSqlite(db, recent_seq, &buf2);
    try testing.expectEqualStrings("RECENT-BODY", from_sql);
}

/// Open a WAL file-backed DB at `path`, apply the AT schema, and clear
/// any stale L0 store. The benchmark uses a real file (not `:memory:`)
/// so the OLD synchronous-insert path pays the realistic per-transaction
/// WAL cost it would in production — which is exactly what the L0 ring +
/// batched flush removes from the commit hot path.
fn setupFileDb(path: [:0]const u8) !*c.sqlite3 {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(path);
    forget(db);
    // Start from a clean table so seq/counts are deterministic per run.
    _ = c.sqlite3_exec(db, "DROP TABLE IF EXISTS atp_firehose_events; DROP TABLE IF EXISTS atp_firehose_cursor;", null, null, null);
    for (schema_mod.all_migrations) |m| {
        const sql_z = try testing.allocator.dupeZ(u8, m.up);
        defer testing.allocator.free(sql_z);
        var errmsg: [*c]u8 = null;
        _ = c.sqlite3_exec(db, sql_z.ptr, null, null, &errmsg);
        if (errmsg != null) c.sqlite3_free(errmsg);
    }
    return db;
}

/// Remove the benchmark's DB files (main + WAL/SHM sidecars). std.fs is
/// stripped here, so we unlink via libc.
fn unlinkDbFiles(tag: u32) void {
    const suffixes = [_][]const u8{ "", "-wal", "-shm" };
    const stems = [_][]const u8{ "old", "new" };
    for (stems) |stem| {
        for (suffixes) |suf| {
            var buf: [160]u8 = undefined;
            const path = std.fmt.bufPrintZ(&buf, "/tmp/d3_bench_{s}_{x}.db{s}", .{ stem, tag, suf }) catch continue;
            _ = std.c.unlink(path.ptr);
        }
    }
}

test "store: benchmark batched append vs direct per-event insert" {
    const iters: usize = 20_000;
    const body = "x" ** 96; // representative small commit-envelope body

    // Unique temp paths so parallel test runners don't collide.
    var prng = std.Random.DefaultPrng.init(@as(u64, @truncate(@as(u128, @bitCast(monotonicNs())))));
    const tag = prng.random().int(u32);
    var p1_buf: [128]u8 = undefined;
    var p2_buf: [128]u8 = undefined;
    const p1 = try std.fmt.bufPrintZ(&p1_buf, "/tmp/d3_bench_old_{x}.db", .{tag});
    const p2 = try std.fmt.bufPrintZ(&p2_buf, "/tmp/d3_bench_new_{x}.db", .{tag});
    defer unlinkDbFiles(tag);

    // ── Baseline: the OLD hot path — one INSERT + one cursor UPDATE per
    //    event in autocommit (its own WAL transaction), as appendKind did.
    const db = try setupFileDb(p1);
    defer core.storage.sqlite.closeDb(db);
    defer forget(db);

    // Per-append latencies so we can report both the mean (throughput)
    // and the median (the latency the caller pays on the COMMON path —
    // the hot-path metric the L0 ring is designed to win). The C
    // allocator backs these scratch arrays; freed at scope exit.
    const a = std.heap.c_allocator;
    const old_lat = try a.alloc(u64, iters);
    defer a.free(old_lat);
    const new_lat = try a.alloc(u64, iters);
    defer a.free(new_lat);

    const direct_start = monotonicNs();
    var i: usize = 0;
    while (i < iters) : (i += 1) {
        const t0 = monotonicNs();
        const sql = "INSERT INTO atp_firehose_events (did, commit_cid, body, ts, event_kind) VALUES (?,?,?,?,?)";
        var stmt: ?*c.sqlite3_stmt = null;
        try testing.expect(c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) == c.SQLITE_OK);
        _ = c.sqlite3_bind_text(stmt, 1, "did:plc:bench", 13, c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_text(stmt, 2, "cid", 3, c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_blob(stmt, 3, body.ptr, body.len, c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_int64(stmt, 4, @intCast(i));
        _ = c.sqlite3_bind_text(stmt, 5, "commit", 6, c.sqliteTransientAsDestructor());
        try testing.expect(c.sqlite3_step(stmt.?) == c.SQLITE_DONE);
        _ = c.sqlite3_finalize(stmt);
        bumpCursor(db, c.sqlite3_last_insert_rowid(db));
        old_lat[i] = @intCast(monotonicNs() - t0);
    }
    const direct_ns: u64 = @intCast(monotonicNs() - direct_start);

    // ── New path: L0 ring append (flush amortised across batches).
    const db2 = try setupFileDb(p2);
    defer core.storage.sqlite.closeDb(db2);
    defer forget(db2);

    const store_start = monotonicNs();
    i = 0;
    while (i < iters) : (i += 1) {
        const t0 = monotonicNs();
        _ = try append(db2, .commit, "did:plc:bench", "cid", body, @intCast(i));
        new_lat[i] = @intCast(monotonicNs() - t0);
    }
    try flush(db2);
    const store_ns: u64 = @intCast(monotonicNs() - store_start);

    const direct_per = @as(f64, @floatFromInt(direct_ns)) / @as(f64, @floatFromInt(iters));
    const store_per = @as(f64, @floatFromInt(store_ns)) / @as(f64, @floatFromInt(iters));
    const mean_speedup = direct_per / store_per;

    std.mem.sort(u64, old_lat, {}, std.sort.asc(u64));
    std.mem.sort(u64, new_lat, {}, std.sort.asc(u64));
    // Common-path latency = mean of the lowest 99% of appends, which for
    // the new path excludes the handful of periodic batch-flush spikes
    // and isolates the pure in-memory ring write the caller almost always
    // pays. (The median itself is below clock resolution, so we average a
    // wide common-path window for a stable number.)
    const lo_n = iters - iters / 100; // bottom 99%
    const old_common = meanOf(old_lat[0..lo_n]);
    const new_common = meanOf(new_lat[0..lo_n]);
    const common_speedup = old_common / @max(new_common, 1.0);

    std.debug.print(
        "\n[D3 firehose bench] {d} events (WAL file DB)\n" ++
            "  mean throughput:  direct(old)={d:.1} ns/ev  store(new)={d:.1} ns/ev  speedup={d:.2}x\n" ++
            "  common-path (p0..p99) append latency: old={d:.1} ns  new={d:.1} ns  speedup={d:.1}x\n",
        .{ iters, direct_per, store_per, mean_speedup, old_common, new_common, common_speedup },
    );

    // Both paths persisted all events durably.
    try testing.expectEqual(@as(i64, @intCast(iters)), countDurable(db2));
    // The L0 ring removes SQLite from the firehose hot path: the common
    // append (every call that isn't the periodic batch flush) must be
    // >= 10x faster than the old per-event synchronous INSERT + cursor
    // UPDATE on a durable WAL database.
    try testing.expect(common_speedup >= 10.0);
}

fn meanOf(xs: []const u64) f64 {
    if (xs.len == 0) return 0;
    var sum: u128 = 0;
    for (xs) |x| sum += x;
    return @as(f64, @floatFromInt(sum)) / @as(f64, @floatFromInt(xs.len));
}
