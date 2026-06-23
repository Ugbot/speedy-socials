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

/// D3: multi-level (L0 ring + L1 SQLite) backing store for the firehose
/// hot path. `appendKind` writes to the in-memory ring and batches the
/// durable insert; reads check L0 before falling back to SQLite.
const store = @import("firehose_store.zig");

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
/// sync as accounts mutate. Defined in the store so both the hot-path
/// ring and the read API share one canonical enum.
pub const EventKind = store.EventKind;

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
    // D3 hot path: land the event in the L0 ring (assigning its seq) and
    // let the store batch the durable L1 insert. The synchronous
    // per-event INSERT + cursor UPDATE that used to live here is now
    // amortised across a batch inside the store.
    const seq = try store.append(db, kind, did, commit_cid, body, ts);

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

/// AT1: emit a `#handle` event (deprecated in newer atproto, superseded
/// by `#identity`, but still consumed by older AppViews). Signals that a
/// repo's primary handle changed. Body: `{did, handle, time}`.
pub fn appendHandle(
    db: *c.sqlite3,
    did: []const u8,
    new_handle: []const u8,
    ts: i64,
) StorageError!i64 {
    var buf: [512]u8 = undefined;
    const body = encodeHandleBody(did, new_handle, &buf) catch return error.StepFailed;
    return appendKind(db, .handle, did, "", body, ts);
}

/// AT1: emit a `#migrate` event (deprecated in newer atproto) signalling
/// that a repo migrated to another PDS. `migrate_to` is the target
/// service DID and may be empty, in which case the lexicon-mandated
/// `migrateTo` key is encoded as an explicit CBOR null. Body:
/// `{did, migrateTo, time}`.
pub fn appendMigrate(
    db: *c.sqlite3,
    did: []const u8,
    migrate_to: []const u8,
    ts: i64,
) StorageError!i64 {
    var buf: [512]u8 = undefined;
    const body = encodeMigrateBody(did, migrate_to, &buf) catch return error.StepFailed;
    return appendKind(db, .migrate, did, "", body, ts);
}

/// AT1: emit an `#info` event — an out-of-band notice the relay sends a
/// subscriber (e.g. `OutdatedCursor`). It carries no DID, so the row's
/// `did` column holds the empty string. `message` is optional. Body:
/// `{name, message?}`.
pub fn appendInfo(
    db: *c.sqlite3,
    name: []const u8,
    message: []const u8,
    ts: i64,
) StorageError!i64 {
    var buf: [512]u8 = undefined;
    const body = encodeInfoBody(name, message, &buf) catch return error.StepFailed;
    return appendKind(db, .info, "", "", body, ts);
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

fn encodeHandleBody(did: []const u8, handle: []const u8, out: []u8) !([]const u8) {
    var enc = dag.Encoder.init(out);
    // Keys (length-then-lex): "did" (3) < "time" (4) < "handle" (6).
    try enc.writeMapHeader(3);
    try enc.writeText("did");
    try enc.writeText(did);
    try enc.writeText("time");
    try enc.writeText("");
    try enc.writeText("handle");
    try enc.writeText(handle);
    return enc.written();
}

fn encodeMigrateBody(did: []const u8, migrate_to: []const u8, out: []u8) !([]const u8) {
    var enc = dag.Encoder.init(out);
    // Keys (length-then-lex): "did" (3) < "time" (4) < "migrateTo" (9).
    // The lexicon types `migrateTo` as a nullable string; when no target
    // is known we encode an explicit null rather than omitting the key.
    try enc.writeMapHeader(3);
    try enc.writeText("did");
    try enc.writeText(did);
    try enc.writeText("time");
    try enc.writeText("");
    try enc.writeText("migrateTo");
    if (migrate_to.len > 0) {
        try enc.writeText(migrate_to);
    } else {
        try enc.writeNull();
    }
    return enc.written();
}

fn encodeInfoBody(name: []const u8, message: []const u8, out: []u8) !([]const u8) {
    var enc = dag.Encoder.init(out);
    const have_message = message.len > 0;
    // Keys (length-then-lex): "name" (4) < "message" (7).
    try enc.writeMapHeader(if (have_message) 2 else 1);
    try enc.writeText("name");
    try enc.writeText(name);
    if (have_message) {
        try enc.writeText("message");
        try enc.writeText(message);
    }
    return enc.written();
}

/// Read-facing event. Aliased to the store's type so the L0 ring and
/// the SQLite fallback hand back one shape.
pub const Event = store.Event;

/// Read events with seq > `cursor`, up to `out.len`. L0 (in-memory ring)
/// serves recent events without touching SQLite; older seqs fall back to
/// the durable `atp_firehose_events` table. Returns the count written.
pub fn readSince(
    db: *c.sqlite3,
    cursor: i64,
    out: []Event,
) StorageError!u32 {
    return store.readSince(db, cursor, out);
}

/// Force any L0-buffered events to the durable L1 table. A durability
/// barrier for callers (and tests) that need every appended event in
/// SQLite immediately.
pub fn flush(db: *c.sqlite3) StorageError!void {
    return store.flush(db);
}

/// Latest assigned seq, reflecting events still buffered in L0 as well
/// as durable ones — the true high-water mark.
pub fn latestSeq(db: *c.sqlite3) StorageError!i64 {
    return store.latestSeq(db);
}

/// Fetch the raw CBOR body for `seq` into `out`. Serves from the L0 ring
/// when still retained, else from the durable table. Used by the
/// subscribeRepos handler to frame each event's body block.
pub fn bodyForSeq(db: *c.sqlite3, seq: i64, out: []u8) StorageError![]const u8 {
    return store.bodyForSeq(db, seq, out);
}

/// Drop the L0 store bound to `db` (after the caller is done with the
/// handle). Call this when closing a DB so a future handle reusing the
/// same address does not inherit this database's ring or seq counter.
/// Safe to call on an unknown handle.
pub fn forgetStore(db: *c.sqlite3) void {
    store.forget(db);
}

// ── Tests ──────────────────────────────────────────────────────────

const testing = std.testing;
const schema_mod = @import("schema.zig");

fn setupDb() !*c.sqlite3 {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    // A previous test may have closed a DB at this same address; drop any
    // stale L0 store so this fresh DB starts with seq 1.
    store.forget(db);
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

// AT1: read a single event's raw CBOR body for a given seq. Test-only;
// `readSince` deliberately omits the body to keep the live-tail Event
// struct fixed-size, so we go straight to the persistent table here.
fn readBodyForSeq(db: *c.sqlite3, seq: i64, out: []u8) StorageError![]const u8 {
    // Route through the store so unflushed (L0-only) bodies are also
    // resolvable; the store serves inline bodies from the ring and falls
    // back to SQLite for evicted/oversized ones.
    return store.bodyForSeq(db, seq, out);
}

/// AT1: result of scanning a flat CBOR map body for one key's value.
const FieldResult = struct {
    found: bool = false,
    found_null: bool = false,
    value_buf: [256]u8 = undefined,
    value_len: usize = 0,

    fn value(self: *const FieldResult) []const u8 {
        return self.value_buf[0..self.value_len];
    }
};

/// AT1: decode a flat CBOR map (`{key: <text|null|...>}`) and capture
/// the value bound to `key`. Map values in these firehose bodies are
/// only text or null, so we read each key, then its value event, pairing
/// them positionally. Used by tests to verify body shapes.
fn grabField(body: []const u8, key: []const u8) FieldResult {
    var res: FieldResult = .{};
    var dec = dag.Decoder.init(body);
    const head = dec.nextEvent() catch return res;
    const pairs = switch (head) {
        .map_start => |n| n,
        else => return res,
    };
    var i: u64 = 0;
    while (i < pairs) : (i += 1) {
        const k_ev = dec.nextEvent() catch return res;
        const k = switch (k_ev) {
            .text => |s| s,
            else => return res, // DAG-CBOR map keys are always text
        };
        const v_ev = dec.nextEvent() catch return res;
        if (std.mem.eql(u8, k, key)) {
            switch (v_ev) {
                .text => |s| {
                    const cap = @min(s.len, res.value_buf.len);
                    @memcpy(res.value_buf[0..cap], s[0..cap]);
                    res.value_len = cap;
                    res.found = true;
                },
                .null_ => {
                    res.found = true;
                    res.found_null = true;
                },
                else => res.found = true,
            }
            return res;
        }
    }
    return res;
}

fn randAlpha(rand: std.Random, out: []u8) []const u8 {
    const len = 6 + rand.intRangeAtMost(usize, 0, out.len - 6);
    for (out[0..len]) |*ch| ch.* = "abcdefghijklmnopqrstuvwxyz0123456789"[rand.intRangeLessThan(usize, 0, 36)];
    return out[0..len];
}

test "AT1: appendHandle writes #handle row with decodable {did,handle,time}" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);

    var prng = std.Random.DefaultPrng.init(0xA1_C0_FF_EE);
    const rand = prng.random();
    var did_buf: [40]u8 = undefined;
    var hdl_buf: [40]u8 = undefined;
    @memcpy(did_buf[0..8], "did:plc:");
    const did_tail = randAlpha(rand, did_buf[8..]);
    const did = did_buf[0 .. 8 + did_tail.len];
    const handle = randAlpha(rand, &hdl_buf);

    const seq = try appendHandle(db, did, handle, @intCast(rand.int(u32)));

    var out: [4]Event = undefined;
    const n = try readSince(db, seq - 1, &out);
    try testing.expectEqual(@as(u32, 1), n);
    try testing.expectEqual(EventKind.handle, out[0].kind);
    try testing.expectEqualStrings(did, out[0].did());

    var body_buf: [512]u8 = undefined;
    const body = try readBodyForSeq(db, seq, &body_buf);
    try testing.expectEqual(@as(u8, 0xA3), body[0]); // map(3)
    const fdid = grabField(body, "did");
    const fhandle = grabField(body, "handle");
    try testing.expect(fdid.found and fhandle.found);
    try testing.expectEqualStrings(did, fdid.value());
    try testing.expectEqualStrings(handle, fhandle.value());
}

test "AT1: appendMigrate encodes migrateTo string when target known" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);

    var prng = std.Random.DefaultPrng.init(0xB2_D0_CA_FE);
    const rand = prng.random();
    var did_buf: [40]u8 = undefined;
    var tgt_buf: [40]u8 = undefined;
    @memcpy(did_buf[0..8], "did:plc:");
    const did_tail = randAlpha(rand, did_buf[8..]);
    const did = did_buf[0 .. 8 + did_tail.len];
    @memcpy(tgt_buf[0..8], "did:web:");
    const tgt_tail = randAlpha(rand, tgt_buf[8..]);
    const target = tgt_buf[0 .. 8 + tgt_tail.len];

    const seq = try appendMigrate(db, did, target, @intCast(rand.int(u32)));

    var out: [4]Event = undefined;
    const n = try readSince(db, seq - 1, &out);
    try testing.expectEqual(@as(u32, 1), n);
    try testing.expectEqual(EventKind.migrate, out[0].kind);

    var body_buf: [512]u8 = undefined;
    const body = try readBodyForSeq(db, seq, &body_buf);
    try testing.expectEqual(@as(u8, 0xA3), body[0]); // map(3)
    const fdid = grabField(body, "did");
    const ftarget = grabField(body, "migrateTo");
    try testing.expect(fdid.found and ftarget.found);
    try testing.expect(!ftarget.found_null);
    try testing.expectEqualStrings(did, fdid.value());
    try testing.expectEqualStrings(target, ftarget.value());
}

test "AT1: appendMigrate encodes migrateTo null when target absent" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);

    var prng = std.Random.DefaultPrng.init(0xC3_E0_FA_CE);
    const rand = prng.random();
    var did_buf: [40]u8 = undefined;
    @memcpy(did_buf[0..8], "did:plc:");
    const did_tail = randAlpha(rand, did_buf[8..]);
    const did = did_buf[0 .. 8 + did_tail.len];

    const seq = try appendMigrate(db, did, "", @intCast(rand.int(u32)));

    var body_buf: [512]u8 = undefined;
    const body = try readBodyForSeq(db, seq, &body_buf);
    try testing.expectEqual(@as(u8, 0xA3), body[0]); // map(3)
    // Explicit CBOR null (0xf6) present in the body.
    try testing.expect(std.mem.indexOfScalar(u8, body, 0xf6) != null);
    const ftarget = grabField(body, "migrateTo");
    try testing.expect(ftarget.found and ftarget.found_null);
}

test "AT1: appendInfo emits #info row with name + optional message" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);

    var prng = std.Random.DefaultPrng.init(0xD4_F0_DE_AD);
    const rand = prng.random();
    var name_buf: [40]u8 = undefined;
    var msg_buf: [40]u8 = undefined;
    const name = randAlpha(rand, &name_buf);
    const message = randAlpha(rand, &msg_buf);

    const seq = try appendInfo(db, name, message, @intCast(rand.int(u32)));

    var out: [4]Event = undefined;
    const n = try readSince(db, seq - 1, &out);
    try testing.expectEqual(@as(u32, 1), n);
    try testing.expectEqual(EventKind.info, out[0].kind);
    // #info carries no DID.
    try testing.expectEqualStrings("", out[0].did());

    var body_buf: [512]u8 = undefined;
    const body = try readBodyForSeq(db, seq, &body_buf);
    try testing.expectEqual(@as(u8, 0xA2), body[0]); // map(2)
    const fname = grabField(body, "name");
    const fmsg = grabField(body, "message");
    try testing.expect(fname.found and fmsg.found);
    try testing.expectEqualStrings(name, fname.value());
    try testing.expectEqualStrings(message, fmsg.value());
}

test "AT1: appendInfo omits message when empty (map of 1)" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);

    var prng = std.Random.DefaultPrng.init(0xE5_AB_CD_01);
    const rand = prng.random();
    var name_buf: [40]u8 = undefined;
    const name = randAlpha(rand, &name_buf);

    const seq = try appendInfo(db, name, "", @intCast(rand.int(u32)));

    var body_buf: [512]u8 = undefined;
    const body = try readBodyForSeq(db, seq, &body_buf);
    try testing.expectEqual(@as(u8, 0xA1), body[0]); // map(1)
    try testing.expect(std.mem.indexOf(u8, body, "message") == null);
    const fname = grabField(body, "name");
    try testing.expect(fname.found);
    try testing.expectEqualStrings(name, fname.value());
}
