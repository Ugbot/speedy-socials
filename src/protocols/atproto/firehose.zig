//! Firehose event emission + storage.
//!
//! Persistent table (`atp_firehose_events`) is append-only and NEVER drops.
//! Subscribers replay from a `cursor` (sequence number) then live-tail via
//! the per-shard event ring in `core/ws/registry.zig`. The live ring may
//! drop oldest events under burst — subscribers detect the gap (their
//! cursor < oldest available seq), reconnect, and resume from the
//! persistent table.
//!
//! The seq column on `atp_firehose_events` is a SQLite AUTOINCREMENT
//! INTEGER PRIMARY KEY, which gives us a monotonic counter without an
//! explicit cursor table read on every append. The `atp_firehose_cursor`
//! row is used by tests and external consumers wanting a "last emitted"
//! snapshot.

const std = @import("std");
const c = @import("sqlite").c;
const core = @import("core");
const StorageError = core.errors.StorageError;

/// W5.1: an in-process notification fired synchronously from
/// `append()` after a row has been committed. The relay's firehose
/// consumer registers here at boot to pick up AT→AP translation work
/// without re-using the existing WebSocket subscriber path (which is
/// for external clients).
///
/// At most one sink may be installed at a time. The caller must keep
/// the sink alive for the duration of the process; we hold a raw
/// function pointer.
pub const LocalSink = *const fn (seq: i64, did: []const u8, commit_cid: []const u8, body: []const u8, ts: i64) void;

var local_sink: ?LocalSink = null;

pub fn registerLocalSink(sink: ?LocalSink) void {
    local_sink = sink;
}

pub fn currentLocalSink() ?LocalSink {
    return local_sink;
}

/// AT-3: kinds of events the firehose can carry. Subscribers need
/// each kind so AppViews / relays can keep their identity caches in
/// sync as accounts mutate.
pub const EventKind = enum {
    commit,
    identity,
    account,
    tombstone,

    pub fn columnString(self: EventKind) []const u8 {
        return switch (self) {
            .commit => "commit",
            .identity => "identity",
            .account => "account",
            .tombstone => "tombstone",
        };
    }

    pub fn fromColumn(s: []const u8) EventKind {
        if (std.mem.eql(u8, s, "identity")) return .identity;
        if (std.mem.eql(u8, s, "account")) return .account;
        if (std.mem.eql(u8, s, "tombstone")) return .tombstone;
        return .commit;
    }
};

/// Append a firehose event row of the given kind. Returns the assigned
/// sequence number. `commit_cid` is the empty string for non-commit
/// events; `body` is the type-appropriate payload (CBOR).
pub fn appendKind(
    db: *c.sqlite3,
    kind: EventKind,
    did: []const u8,
    commit_cid: []const u8,
    body: []const u8,
    ts: i64,
) StorageError!i64 {
    const sql = "INSERT INTO atp_firehose_events (did, commit_cid, body, ts, event_kind) VALUES (?,?,?,?,?)";
    var stmt: ?*c.sqlite3_stmt = null;
    const rc = c.sqlite3_prepare_v2(db, sql, -1, &stmt, null);
    if (rc != c.SQLITE_OK or stmt == null) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);

    _ = c.sqlite3_bind_text(stmt, 1, did.ptr, @intCast(did.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 2, commit_cid.ptr, @intCast(commit_cid.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_blob(stmt, 3, body.ptr, @intCast(body.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(stmt, 4, ts);
    const kind_str = kind.columnString();
    _ = c.sqlite3_bind_text(stmt, 5, kind_str.ptr, @intCast(kind_str.len), c.sqliteTransientAsDestructor());

    const step_rc = c.sqlite3_step(stmt.?);
    if (step_rc != c.SQLITE_DONE) return error.StepFailed;
    const seq = c.sqlite3_last_insert_rowid(db);

    const upd_sql = "UPDATE atp_firehose_cursor SET seq = ? WHERE id = 1";
    var ustmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, upd_sql, -1, &ustmt, null) == c.SQLITE_OK) {
        defer _ = c.sqlite3_finalize(ustmt);
        _ = c.sqlite3_bind_int64(ustmt, 1, seq);
        _ = c.sqlite3_step(ustmt.?);
    }

    if (local_sink) |sink| sink(seq, did, commit_cid, body, ts);

    // Phase H: mirror every firehose event to the pluggable stream sink
    // (Kafka/log/null). Keyed by repo DID so a topic stays per-repo
    // ordered. Best-effort + non-blocking; a null sink is a no-op.
    core.stream.publish("firehose", did, body);

    return seq;
}

/// Append a `#commit` event. Kept as a thin alias on appendKind so
/// existing callers don't need to thread the kind enum through.
pub fn append(
    db: *c.sqlite3,
    did: []const u8,
    commit_cid: []const u8,
    body: []const u8,
    ts: i64,
) StorageError!i64 {
    return appendKind(db, .commit, did, commit_cid, body, ts);
}

/// AT-3: emit an `#identity` event so subscribers refresh their
/// handle-to-DID cache. `handle` may be empty when the change is
/// purely a key rotation; in that case the body just signals "go
/// re-resolve this DID."
pub fn appendIdentity(
    db: *c.sqlite3,
    did: []const u8,
    handle: []const u8,
    ts: i64,
) StorageError!i64 {
    // Body: `{did, time, handle?}` as canonical CBOR. The seq is added
    // by sync_firehose when it frames the event for the wire.
    var buf: [512]u8 = undefined;
    const body = encodeIdentityBody(did, handle, &buf) catch return error.StepFailed;
    return appendKind(db, .identity, did, "", body, ts);
}

/// AT-3: emit an `#account` event. `active` reflects whether the
/// account is usable; `status` is one of "takendown" / "suspended" /
/// "deactivated" / "deleted" and is omitted when `active` is true.
pub fn appendAccount(
    db: *c.sqlite3,
    did: []const u8,
    active: bool,
    status: []const u8,
    ts: i64,
) StorageError!i64 {
    var buf: [256]u8 = undefined;
    const body = encodeAccountBody(did, active, status, &buf) catch return error.StepFailed;
    return appendKind(db, .account, did, "", body, ts);
}

/// AT-3: emit a `#tombstone` event (deprecated in newer atproto but
/// still consumed by older AppViews). Marks the entire repo as
/// permanently gone.
pub fn appendTombstone(
    db: *c.sqlite3,
    did: []const u8,
    ts: i64,
) StorageError!i64 {
    var buf: [128]u8 = undefined;
    const body = encodeTombstoneBody(did, &buf) catch return error.StepFailed;
    return appendKind(db, .tombstone, did, "", body, ts);
}

const dag = @import("dag_cbor.zig");

fn encodeIdentityBody(did: []const u8, handle: []const u8, out: []u8) !([]const u8) {
    var enc = dag.Encoder.init(out);
    const have_handle = handle.len > 0;
    // Canonical key order (length-then-lex): "did" (3) < "time" (4) — and
    // optionally "handle" (6).
    try enc.writeMapHeader(if (have_handle) 3 else 2);
    try enc.writeText("did");
    try enc.writeText(did);
    try enc.writeText("time");
    try enc.writeText("");
    if (have_handle) {
        try enc.writeText("handle");
        try enc.writeText(handle);
    }
    return enc.written();
}

fn encodeAccountBody(did: []const u8, active: bool, status: []const u8, out: []u8) !([]const u8) {
    var enc = dag.Encoder.init(out);
    const have_status = status.len > 0;
    // Keys (length-then-lex): "did" (3) < "time" (4) < "active" (6) < "status" (6 — same len; "active" < "status" lex).
    try enc.writeMapHeader(if (have_status) 4 else 3);
    try enc.writeText("did");
    try enc.writeText(did);
    try enc.writeText("time");
    try enc.writeText("");
    try enc.writeText("active");
    try enc.writeBool(active);
    if (have_status) {
        try enc.writeText("status");
        try enc.writeText(status);
    }
    return enc.written();
}

fn encodeTombstoneBody(did: []const u8, out: []u8) !([]const u8) {
    var enc = dag.Encoder.init(out);
    try enc.writeMapHeader(2);
    try enc.writeText("did");
    try enc.writeText(did);
    try enc.writeText("time");
    try enc.writeText("");
    return enc.written();
}

pub const Event = struct {
    seq: i64,
    did_buf: [256]u8 = undefined,
    did_len: u16 = 0,
    commit_cid_buf: [128]u8 = undefined,
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

/// Read events with seq > `cursor`, up to `out.len`. Returns the count
/// written.
pub fn readSince(
    db: *c.sqlite3,
    cursor: i64,
    out: []Event,
) StorageError!u32 {
    const sql = "SELECT seq, did, commit_cid, ts, event_kind FROM atp_firehose_events WHERE seq > ? ORDER BY seq ASC LIMIT ?";
    var stmt: ?*c.sqlite3_stmt = null;
    const rc = c.sqlite3_prepare_v2(db, sql, -1, &stmt, null);
    if (rc != c.SQLITE_OK or stmt == null) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);

    _ = c.sqlite3_bind_int64(stmt, 1, cursor);
    _ = c.sqlite3_bind_int64(stmt, 2, @intCast(out.len));

    var n: u32 = 0;
    while (n < out.len) {
        const step_rc = c.sqlite3_step(stmt.?);
        if (step_rc == c.SQLITE_DONE) break;
        if (step_rc != c.SQLITE_ROW) return error.StepFailed;

        var ev: Event = .{ .seq = c.sqlite3_column_int64(stmt, 0) };
        const did_ptr = c.sqlite3_column_text(stmt, 1);
        const did_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 1));
        if (did_len > 0 and did_ptr != null) {
            const cap = @min(did_len, ev.did_buf.len);
            @memcpy(ev.did_buf[0..cap], did_ptr[0..cap]);
            ev.did_len = @intCast(cap);
        }
        const cid_ptr = c.sqlite3_column_text(stmt, 2);
        const cid_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 2));
        if (cid_len > 0 and cid_ptr != null) {
            const cap = @min(cid_len, ev.commit_cid_buf.len);
            @memcpy(ev.commit_cid_buf[0..cap], cid_ptr[0..cap]);
            ev.commit_cid_len = @intCast(cap);
        }
        ev.ts = c.sqlite3_column_int64(stmt, 3);

        const kind_ptr = c.sqlite3_column_text(stmt, 4);
        const kind_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 4));
        if (kind_len > 0 and kind_ptr != null) {
            ev.kind = EventKind.fromColumn(kind_ptr[0..kind_len]);
        }

        out[n] = ev;
        n += 1;
    }
    return n;
}

pub fn latestSeq(db: *c.sqlite3) StorageError!i64 {
    const sql = "SELECT seq FROM atp_firehose_cursor WHERE id = 1";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    const step_rc = c.sqlite3_step(stmt.?);
    if (step_rc == c.SQLITE_ROW) return c.sqlite3_column_int64(stmt, 0);
    return 0;
}

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

test "firehose: append + readSince" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);

    const s1 = try append(db, "did:plc:a", "bafy1", "body1", 1000);
    const s2 = try append(db, "did:plc:b", "bafy2", "body2", 1001);
    const s3 = try append(db, "did:plc:c", "bafy3", "body3", 1002);
    try testing.expect(s2 > s1);
    try testing.expect(s3 > s2);

    var out: [10]Event = undefined;
    const n = try readSince(db, s1, &out);
    try testing.expectEqual(@as(u32, 2), n);
    try testing.expectEqualStrings("did:plc:b", out[0].did());
    try testing.expectEqualStrings("bafy3", out[1].commitCid());
}

test "Phase H: firehose append publishes each event to the stream sink" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);

    var ls: core.stream.LogSink = .{};
    core.stream.setGlobal(ls.sink());
    defer core.stream.setGlobal(null);

    // Randomized DIDs/bodies so we're not asserting on a hardcoded path.
    var prng = std.Random.DefaultPrng.init(0xF1_4E_05_E);
    const rand = prng.random();
    const n: usize = 16;
    var last_did_buf: [32]u8 = undefined;
    var last_did_len: usize = 0;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        var did_buf: [32]u8 = undefined;
        const dlen = 10 + rand.intRangeAtMost(usize, 0, 20);
        @memcpy(did_buf[0..8], "did:plc:");
        for (did_buf[8..dlen]) |*ch| ch.* = "abcdefghijklmnop"[rand.intRangeLessThan(usize, 0, 16)];
        @memcpy(last_did_buf[0..dlen], did_buf[0..dlen]);
        last_did_len = dlen;
        _ = try append(db, did_buf[0..dlen], "bafycid", "event-body", @intCast(1000 + i));
    }

    // Every append published exactly once, to the firehose topic, keyed
    // by the repo DID.
    try testing.expectEqual(@as(u64, n), ls.publishedCount());
    const rec = ls.last() orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("firehose", rec.topic());
    try testing.expectEqualStrings(last_did_buf[0..last_did_len], rec.key());
    try testing.expectEqualStrings("event-body", rec.payloadPrefix());
}

test "firehose: latestSeq tracks last append" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    try testing.expectEqual(@as(i64, 0), try latestSeq(db));
    _ = try append(db, "did:plc:x", "c1", "b1", 1);
    _ = try append(db, "did:plc:x", "c2", "b2", 2);
    try testing.expect((try latestSeq(db)) >= 2);
}

test "firehose: empty readSince" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    var out: [4]Event = undefined;
    const n = try readSince(db, 0, &out);
    try testing.expectEqual(@as(u32, 0), n);
}

test "AT-3: append commit defaults event_kind to commit" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    _ = try append(db, "did:plc:x", "bafy1", "body", 1);
    var out: [4]Event = undefined;
    const n = try readSince(db, 0, &out);
    try testing.expectEqual(@as(u32, 1), n);
    try testing.expectEqual(EventKind.commit, out[0].kind);
}

test "AT-3: appendIdentity writes #identity row" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    _ = try appendIdentity(db, "did:plc:rename", "newalias.example", 99);
    var out: [4]Event = undefined;
    const n = try readSince(db, 0, &out);
    try testing.expectEqual(@as(u32, 1), n);
    try testing.expectEqual(EventKind.identity, out[0].kind);
    try testing.expectEqualStrings("did:plc:rename", out[0].did());
}

test "AT-3: appendAccount with status emits #account row" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    _ = try appendAccount(db, "did:plc:gone", false, "takendown", 100);
    var out: [4]Event = undefined;
    const n = try readSince(db, 0, &out);
    try testing.expectEqual(@as(u32, 1), n);
    try testing.expectEqual(EventKind.account, out[0].kind);
}

test "AT-3: appendTombstone emits #tombstone row" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    _ = try appendTombstone(db, "did:plc:dead", 200);
    var out: [4]Event = undefined;
    const n = try readSince(db, 0, &out);
    try testing.expectEqual(@as(u32, 1), n);
    try testing.expectEqual(EventKind.tombstone, out[0].kind);
}

test "AT-3: encodeIdentityBody includes handle when supplied" {
    var buf: [256]u8 = undefined;
    const body = try encodeIdentityBody("did:plc:a", "alice.example", &buf);
    // Map of length 3 → 0xA3
    try testing.expectEqual(@as(u8, 0xA3), body[0]);
    try testing.expect(std.mem.indexOf(u8, body, "handle") != null);
    try testing.expect(std.mem.indexOf(u8, body, "alice.example") != null);
}

test "AT-3: encodeIdentityBody omits handle when empty" {
    var buf: [256]u8 = undefined;
    const body = try encodeIdentityBody("did:plc:b", "", &buf);
    // Map of length 2 → 0xA2
    try testing.expectEqual(@as(u8, 0xA2), body[0]);
    try testing.expect(std.mem.indexOf(u8, body, "handle") == null);
}
