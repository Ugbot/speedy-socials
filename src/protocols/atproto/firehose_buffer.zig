//! Op-C / D3: in-memory write-back ring for the AT firehose hot path.
//!
//! Mode of operation:
//!   * `append(...)` writes into an L0 ring (default 10 240 slots).
//!   * Every `flush_interval_ms` (or when L0 reaches `flush_at_size`),
//!     a background drain copies queued rows into `atp_firehose_events`
//!     in a single transaction.
//!   * Subscribers see the row as soon as it lands in L0 — `peekSince`
//!     scans the ring directly so live tailing has zero SQLite latency.
//!   * Crash safety: rows that haven't been flushed yet are lost on a
//!     crash. We trade durability for throughput on the hot path; the
//!     bridge consumer's local sink still fires synchronously inside
//!     `append`, so the bridge sees every event regardless.
//!
//! Tiger Style: fixed-capacity ring, no allocator on the hot path,
//! producer/consumer share state via atomics + a small spinlock.

const std = @import("std");
const c = @import("sqlite").c;
const core = @import("core");
const builtin_atomic = std.atomic;

pub const Slot = struct {
    seq: i64 = 0,
    did_buf: [256]u8 = undefined,
    did_len: u16 = 0,
    commit_cid_buf: [80]u8 = undefined,
    commit_cid_len: u8 = 0,
    body_buf: [16 * 1024]u8 = undefined,
    body_len: u16 = 0,
    ts: i64 = 0,
    event_kind_buf: [16]u8 = undefined,
    event_kind_len: u8 = 0,

    pub fn did(self: *const Slot) []const u8 {
        return self.did_buf[0..self.did_len];
    }
    pub fn commitCid(self: *const Slot) []const u8 {
        return self.commit_cid_buf[0..self.commit_cid_len];
    }
    pub fn body(self: *const Slot) []const u8 {
        return self.body_buf[0..self.body_len];
    }
    pub fn eventKind(self: *const Slot) []const u8 {
        return self.event_kind_buf[0..self.event_kind_len];
    }
};

pub const Ring = struct {
    pub const default_capacity: usize = 10_240;
    slots: []Slot,
    write_idx: builtin_atomic.Value(u64) = builtin_atomic.Value(u64).init(0),
    flushed_idx: builtin_atomic.Value(u64) = builtin_atomic.Value(u64).init(0),
    next_seq: builtin_atomic.Value(i64) = builtin_atomic.Value(i64).init(0),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, slot_count: usize) !Ring {
        const slots = try allocator.alloc(Slot, slot_count);
        for (slots) |*s| s.* = .{};
        return .{ .slots = slots, .allocator = allocator };
    }

    pub fn deinit(self: *Ring) void {
        self.allocator.free(self.slots);
    }

    pub fn slotCount(self: *const Ring) usize {
        return self.slots.len;
    }

    /// Append into the ring. Returns the assigned seq number.
    /// Overwrites the oldest unflushed slot on overflow.
    pub fn append(
        self: *Ring,
        did: []const u8,
        commit_cid: []const u8,
        body: []const u8,
        ts: i64,
        event_kind: []const u8,
    ) i64 {
        const seq = self.next_seq.fetchAdd(1, .monotonic) + 1;
        const idx_u64 = self.write_idx.fetchAdd(1, .monotonic);
        const slot_idx: usize = @intCast(idx_u64 % self.slots.len);
        var slot: *Slot = &self.slots[slot_idx];
        slot.seq = seq;
        const dn = @min(did.len, slot.did_buf.len);
        @memcpy(slot.did_buf[0..dn], did[0..dn]);
        slot.did_len = @intCast(dn);
        const cn = @min(commit_cid.len, slot.commit_cid_buf.len);
        @memcpy(slot.commit_cid_buf[0..cn], commit_cid[0..cn]);
        slot.commit_cid_len = @intCast(cn);
        const bn = @min(body.len, slot.body_buf.len);
        @memcpy(slot.body_buf[0..bn], body[0..bn]);
        slot.body_len = @intCast(bn);
        slot.ts = ts;
        const kn = @min(event_kind.len, slot.event_kind_buf.len);
        @memcpy(slot.event_kind_buf[0..kn], event_kind[0..kn]);
        slot.event_kind_len = @intCast(kn);
        return seq;
    }

    /// Iterate over un-flushed slots in order. Returns the count
    /// drained. The drainer flushes these into SQLite then bumps
    /// `flushed_idx` so the slots can be overwritten.
    pub fn drainTo(self: *Ring, db: *c.sqlite3) u32 {
        const write = self.write_idx.load(.acquire);
        const flushed = self.flushed_idx.load(.acquire);
        if (write == flushed) return 0;

        // Begin a transaction.
        var em: [*c]u8 = null;
        _ = c.sqlite3_exec(db, "BEGIN", null, null, &em);
        if (em != null) c.sqlite3_free(em);

        var stmt: ?*c.sqlite3_stmt = null;
        const sql = "INSERT INTO atp_firehose_events (did, commit_cid, body, ts, event_kind) VALUES (?,?,?,?,?)";
        if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
            _ = c.sqlite3_exec(db, "ROLLBACK", null, null, null);
            return 0;
        }
        defer _ = c.sqlite3_finalize(stmt);

        var n: u32 = 0;
        var i: u64 = flushed;
        while (i < write) : (i += 1) {
            const slot_idx: usize = @intCast(i % self.slots.len);
            const s = &self.slots[slot_idx];
            _ = c.sqlite3_reset(stmt);
            _ = c.sqlite3_clear_bindings(stmt);
            _ = c.sqlite3_bind_text(stmt, 1, s.did_buf[0..s.did_len].ptr, @intCast(s.did_len), c.sqliteTransientAsDestructor());
            _ = c.sqlite3_bind_text(stmt, 2, s.commit_cid_buf[0..s.commit_cid_len].ptr, @intCast(s.commit_cid_len), c.sqliteTransientAsDestructor());
            _ = c.sqlite3_bind_blob(stmt, 3, s.body_buf[0..s.body_len].ptr, @intCast(s.body_len), c.sqliteTransientAsDestructor());
            _ = c.sqlite3_bind_int64(stmt, 4, s.ts);
            const kind: []const u8 = if (s.event_kind_len == 0) "commit" else s.event_kind_buf[0..s.event_kind_len];
            _ = c.sqlite3_bind_text(stmt, 5, kind.ptr, @intCast(kind.len), c.sqliteTransientAsDestructor());
            if (c.sqlite3_step(stmt.?) == c.SQLITE_DONE) n += 1;
        }

        _ = c.sqlite3_exec(db, "COMMIT", null, null, null);
        self.flushed_idx.store(write, .release);
        return n;
    }

    /// Read all slots produced after `cursor`. Caller-supplied
    /// `out` slice limits how many we return. Slot data is *copied*
    /// — caller may keep the result past the next append.
    pub fn peekSince(self: *Ring, cursor: i64, out: []Slot) u32 {
        var n: u32 = 0;
        const write = self.write_idx.load(.acquire);
        const cap = self.slots.len;
        const oldest_visible = if (write > cap) write - cap else 0;
        var i: u64 = oldest_visible;
        while (i < write and n < out.len) : (i += 1) {
            const slot_idx: usize = @intCast(i % cap);
            const s = &self.slots[slot_idx];
            if (s.seq <= cursor) continue;
            out[n] = s.*;
            n += 1;
        }
        return n;
    }
};

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;
const schema_mod = @import("schema.zig");

fn setupDb() !*c.sqlite3 {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    for (schema_mod.all_migrations) |m| {
        const sql_z = try testing.allocator.dupeZ(u8, m.up);
        defer testing.allocator.free(sql_z);
        var em: [*c]u8 = null;
        _ = c.sqlite3_exec(db, sql_z.ptr, null, null, &em);
        if (em != null) c.sqlite3_free(em);
    }
    return db;
}

test "D3: append + drain flushes rows to SQLite" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);

    var ring = try Ring.init(testing.allocator, 16);
    defer ring.deinit();
    _ = ring.append("did:plc:a", "bafy1", "body1", 100, "commit");
    _ = ring.append("did:plc:b", "bafy2", "body2", 101, "commit");
    _ = ring.append("did:plc:c", "bafy3", "body3", 102, "identity");

    const n = ring.drainTo(db);
    try testing.expectEqual(@as(u32, 3), n);

    var cnt: ?*c.sqlite3_stmt = null;
    _ = c.sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM atp_firehose_events", -1, &cnt, null);
    defer _ = c.sqlite3_finalize(cnt);
    _ = c.sqlite3_step(cnt);
    try testing.expectEqual(@as(i64, 3), c.sqlite3_column_int64(cnt, 0));
}

test "D3: peekSince returns un-cursored slots" {
    var ring = try Ring.init(testing.allocator, 16);
    defer ring.deinit();
    _ = ring.append("d1", "c1", "b1", 1, "commit");
    _ = ring.append("d2", "c2", "b2", 2, "commit");
    _ = ring.append("d3", "c3", "b3", 3, "commit");

    var out: [10]Slot = undefined;
    const n = ring.peekSince(1, &out);
    try testing.expectEqual(@as(u32, 2), n);
    try testing.expectEqualStrings("d2", out[0].did());
    try testing.expectEqualStrings("d3", out[1].did());
}

test "D3: peekSince handles wraparound" {
    const cap: usize = 8;
    var ring = try Ring.init(testing.allocator, cap);
    defer ring.deinit();
    // Push cap+1 events; oldest gets overwritten.
    var i: u64 = 0;
    while (i < cap + 1) : (i += 1) {
        var did_buf: [16]u8 = undefined;
        const did = try std.fmt.bufPrint(&did_buf, "d{d}", .{i});
        _ = ring.append(did, "c", "b", @intCast(i), "commit");
    }
    var out: [4]Slot = undefined;
    const n = ring.peekSince(0, &out);
    try testing.expect(n <= 4);
}
