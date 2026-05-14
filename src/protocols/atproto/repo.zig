//! Repository — content-addressed record store backed by SQLite.
//!
//! Tiger Style:
//!   * No allocator on hot paths; commits use stack-bound encoder
//!     buffers.
//!   * Every loop bounded. The MST cap from `mst.zig` covers the
//!     in-memory tree; SQLite enforces row counts via LIMIT.
//!   * Errors typed via `errors.AtpError | errors.StorageError`.
//!
//! A "commit" is:
//!   * compute new record CID over its CBOR-serialized value
//!   * upsert into the in-memory MST (for this DID)
//!   * compute data root CID over MST
//!   * build commit object {did, version, prev, data, rev}
//!   * sign with the repo's Ed25519 key
//!   * persist record row + mst block + commit row atomically
//!   * append a firehose event
//!   * update atp_repos head pointer

const std = @import("std");
const c = @import("sqlite").c;
const core = @import("core");

const AtpError = core.errors.AtpError;
const StorageError = core.errors.StorageError;

const cid_mod = @import("cid.zig");
const dag = @import("dag_cbor.zig");
const mst = @import("mst.zig");
const keypair = @import("keypair.zig");
const tid_mod = @import("tid.zig");
const firehose = @import("firehose.zig");
const sync_firehose = @import("sync_firehose.zig");
const state_mod = @import("state.zig");

pub const Error = AtpError || StorageError;

pub const commit_version: u32 = 3;

pub const Commit = struct {
    cid_buf: [cid_mod.string_cid_len]u8 = undefined,
    cid_len: u8 = 0,
    data_cid_buf: [cid_mod.string_cid_len]u8 = undefined,
    data_cid_len: u8 = 0,
    rev_buf: [tid_mod.tid_len]u8 = undefined,

    pub fn cidStr(self: *const Commit) []const u8 {
        return self.cid_buf[0..self.cid_len];
    }
    pub fn dataCidStr(self: *const Commit) []const u8 {
        return self.data_cid_buf[0..self.data_cid_len];
    }
    pub fn rev(self: *const Commit) []const u8 {
        return self.rev_buf[0..];
    }
};

pub const Operation = struct {
    /// Collection NSID, e.g. "app.bsky.feed.post".
    collection: []const u8,
    /// Record key (rkey). Empty → caller wants a TID auto-assigned.
    rkey: []const u8 = "",
    /// CBOR-encoded record value.
    value_cbor: []const u8,
};

/// Lookup or create the per-repo row. Returns the signing key seed
/// (32 bytes deterministic from DID + caller's seed mixer).
pub fn ensureRepo(
    db: *c.sqlite3,
    did: []const u8,
    signing_did_key: []const u8,
    created_at: i64,
) Error!void {
    const sql = "INSERT OR IGNORE INTO atp_repos (did, signing_key, created_at) VALUES (?,?,?)";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, did.ptr, @intCast(did.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 2, signing_did_key.ptr, @intCast(signing_did_key.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(stmt, 3, created_at);
    if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return error.StepFailed;
}

pub const RepoMeta = struct {
    head_cid_buf: [cid_mod.string_cid_len]u8 = undefined,
    head_cid_len: u8 = 0,
    head_rev_buf: [tid_mod.tid_len]u8 = undefined,
    head_rev_len: u8 = 0,
    signing_key_buf: [128]u8 = undefined,
    signing_key_len: u8 = 0,

    pub fn headCid(self: *const RepoMeta) []const u8 {
        return self.head_cid_buf[0..self.head_cid_len];
    }
    pub fn headRev(self: *const RepoMeta) []const u8 {
        return self.head_rev_buf[0..self.head_rev_len];
    }
    pub fn signingKey(self: *const RepoMeta) []const u8 {
        return self.signing_key_buf[0..self.signing_key_len];
    }
};

pub fn loadRepoMeta(db: *c.sqlite3, did: []const u8, out: *RepoMeta) Error!bool {
    const sql = "SELECT head_cid, head_rev, signing_key FROM atp_repos WHERE did = ?";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, did.ptr, @intCast(did.len), c.sqliteTransientAsDestructor());
    const rc = c.sqlite3_step(stmt.?);
    if (rc == c.SQLITE_DONE) return false;
    if (rc != c.SQLITE_ROW) return error.StepFailed;

    out.head_cid_len = 0;
    out.head_rev_len = 0;
    out.signing_key_len = 0;
    if (c.sqlite3_column_type(stmt, 0) == c.SQLITE_TEXT) {
        const p = c.sqlite3_column_text(stmt, 0);
        const n: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
        const cap = @min(n, out.head_cid_buf.len);
        if (cap > 0) @memcpy(out.head_cid_buf[0..cap], p[0..cap]);
        out.head_cid_len = @intCast(cap);
    }
    if (c.sqlite3_column_type(stmt, 1) == c.SQLITE_TEXT) {
        const p = c.sqlite3_column_text(stmt, 1);
        const n: usize = @intCast(c.sqlite3_column_bytes(stmt, 1));
        const cap = @min(n, out.head_rev_buf.len);
        if (cap > 0) @memcpy(out.head_rev_buf[0..cap], p[0..cap]);
        out.head_rev_len = @intCast(cap);
    }
    if (c.sqlite3_column_type(stmt, 2) == c.SQLITE_TEXT) {
        const p = c.sqlite3_column_text(stmt, 2);
        const n: usize = @intCast(c.sqlite3_column_bytes(stmt, 2));
        const cap = @min(n, out.signing_key_buf.len);
        if (cap > 0) @memcpy(out.signing_key_buf[0..cap], p[0..cap]);
        out.signing_key_len = @intCast(cap);
    }
    return true;
}

const ScanCtx = struct {
    tree: *mst.Tree(mst.max_keys),
    err: ?AtpError = null,
};

/// Reload the in-memory MST from `atp_records` rows for `did`.
pub fn loadTree(db: *c.sqlite3, did: []const u8, tree: *mst.Tree(mst.max_keys)) Error!void {
    const sql = "SELECT collection, rkey, cid FROM atp_records WHERE did = ? ORDER BY collection, rkey LIMIT ?";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, did.ptr, @intCast(did.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(stmt, 2, @intCast(mst.max_keys));

    var n: u32 = 0;
    while (n < mst.max_keys) : (n += 1) {
        const rc = c.sqlite3_step(stmt.?);
        if (rc == c.SQLITE_DONE) break;
        if (rc != c.SQLITE_ROW) return error.StepFailed;

        var key_buf: [mst.max_key_bytes]u8 = undefined;
        const coll_ptr = c.sqlite3_column_text(stmt, 0);
        const coll_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
        const rkey_ptr = c.sqlite3_column_text(stmt, 1);
        const rkey_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 1));
        const total = coll_len + 1 + rkey_len;
        if (total > key_buf.len) return error.MstInvariant;
        @memcpy(key_buf[0..coll_len], coll_ptr[0..coll_len]);
        key_buf[coll_len] = '/';
        @memcpy(key_buf[coll_len + 1 ..][0..rkey_len], rkey_ptr[0..rkey_len]);

        const cid_ptr = c.sqlite3_column_text(stmt, 2);
        const cid_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 2));
        var cid_view: [cid_mod.string_cid_len]u8 = undefined;
        if (cid_len > cid_view.len) return error.MstInvariant;
        @memcpy(cid_view[0..cid_len], cid_ptr[0..cid_len]);
        const parsed = try cid_mod.parseString(cid_view[0..cid_len]);
        _ = tree.put(key_buf[0..total], parsed) catch return error.MstInvariant;
    }
}

/// Append-only commit. Mutates the tree, persists record + MST block +
/// commit row, emits a firehose event. Operations are applied in order;
/// no support for delete/swap here — those are added by the route layer.
pub fn commit(
    db: *c.sqlite3,
    did: []const u8,
    signing_kp: keypair.Ed25519KeyPair,
    rev: tid_mod.Tid,
    tree: *mst.Tree(mst.max_keys),
    ops: []const Operation,
    committed_at: i64,
    auto_rkey: ?tid_mod.Tid,
) Error!Commit {
    var commit_out: Commit = .{};

    // Apply ops in order.
    var i: usize = 0;
    while (i < ops.len) : (i += 1) {
        const op = ops[i];
        var rkey_buf: [tid_mod.tid_len]u8 = undefined;
        const rkey = if (op.rkey.len > 0) op.rkey else blk: {
            const t = auto_rkey orelse return error.CommitInvalid;
            @memcpy(rkey_buf[0..tid_mod.tid_len], t.str());
            break :blk rkey_buf[0..tid_mod.tid_len];
        };

        const record_cid = cid_mod.computeDagCbor(op.value_cbor);
        var record_cid_str: [cid_mod.string_cid_len]u8 = undefined;
        const record_cid_s = try cid_mod.encodeString(record_cid, &record_cid_str);

        // Build collection/rkey key for the tree.
        var key_buf: [mst.max_key_bytes]u8 = undefined;
        const klen = op.collection.len + 1 + rkey.len;
        if (klen > key_buf.len) return error.MstInvariant;
        @memcpy(key_buf[0..op.collection.len], op.collection);
        key_buf[op.collection.len] = '/';
        @memcpy(key_buf[op.collection.len + 1 ..][0..rkey.len], rkey);
        _ = tree.put(key_buf[0..klen], record_cid) catch return error.MstInvariant;

        // Build at-uri.
        var uri_buf: [512]u8 = undefined;
        const uri_str = std.fmt.bufPrint(&uri_buf, "at://{s}/{s}/{s}", .{ did, op.collection, rkey }) catch return error.BufferTooSmall;

        // Persist record row.
        const ins_sql = "INSERT OR REPLACE INTO atp_records (uri, did, collection, rkey, cid, value, indexed_at) VALUES (?,?,?,?,?,?,?)";
        var ins_stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db, ins_sql, -1, &ins_stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(ins_stmt);
        _ = c.sqlite3_bind_text(ins_stmt, 1, uri_str.ptr, @intCast(uri_str.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_text(ins_stmt, 2, did.ptr, @intCast(did.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_text(ins_stmt, 3, op.collection.ptr, @intCast(op.collection.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_text(ins_stmt, 4, rkey.ptr, @intCast(rkey.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_text(ins_stmt, 5, record_cid_s.ptr, @intCast(record_cid_s.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_blob(ins_stmt, 6, op.value_cbor.ptr, @intCast(op.value_cbor.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_int64(ins_stmt, 7, committed_at);
        if (c.sqlite3_step(ins_stmt.?) != c.SQLITE_DONE) return error.StepFailed;
    }

    // Compute new MST root.
    var mst_scratch: [64 * 1024]u8 = undefined;
    const root = try tree.getRoot(&mst_scratch);

    var data_cid_str: [cid_mod.string_cid_len]u8 = undefined;
    const data_cid_s = try cid_mod.encodeString(root.cid, &data_cid_str);

    // Persist MST block.
    const mst_sql = "INSERT OR REPLACE INTO atp_mst_blocks (cid, did, data) VALUES (?,?,?)";
    var mst_stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, mst_sql, -1, &mst_stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(mst_stmt);
    _ = c.sqlite3_bind_text(mst_stmt, 1, data_cid_s.ptr, @intCast(data_cid_s.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(mst_stmt, 2, did.ptr, @intCast(did.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_blob(mst_stmt, 3, mst_scratch[0..root.bytes_written].ptr, @intCast(root.bytes_written), c.sqliteTransientAsDestructor());
    if (c.sqlite3_step(mst_stmt.?) != c.SQLITE_DONE) return error.StepFailed;

    // Build commit object CBOR.
    var commit_buf: [4096]u8 = undefined;
    var enc = dag.Encoder.init(&commit_buf);
    try enc.writeMapHeader(5);
    try enc.writeText("did");
    try enc.writeText(did);
    try enc.writeText("version");
    try enc.writeUInt(commit_version);
    try enc.writeText("data");
    try enc.writeCidLink(root.cid.raw());
    try enc.writeText("rev");
    try enc.writeText(rev.str());
    try enc.writeText("prev");
    try enc.writeNull();

    const commit_cid = cid_mod.computeDagCbor(enc.written());
    var commit_cid_str: [cid_mod.string_cid_len]u8 = undefined;
    const commit_cid_s = try cid_mod.encodeString(commit_cid, &commit_cid_str);

    const sig = signing_kp.sign(enc.written());

    // Persist commit row.
    const commit_sql = "INSERT INTO atp_commits (cid, did, rev, prev_cid, data_cid, signature, committed_at) VALUES (?,?,?,?,?,?,?)";
    var commit_stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, commit_sql, -1, &commit_stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(commit_stmt);
    _ = c.sqlite3_bind_text(commit_stmt, 1, commit_cid_s.ptr, @intCast(commit_cid_s.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(commit_stmt, 2, did.ptr, @intCast(did.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(commit_stmt, 3, rev.str().ptr, @intCast(rev.str().len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_null(commit_stmt, 4);
    _ = c.sqlite3_bind_text(commit_stmt, 5, data_cid_s.ptr, @intCast(data_cid_s.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_blob(commit_stmt, 6, &sig, @intCast(sig.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(commit_stmt, 7, committed_at);
    if (c.sqlite3_step(commit_stmt.?) != c.SQLITE_DONE) return error.StepFailed;

    // Update repo head.
    const upd_sql = "UPDATE atp_repos SET head_cid = ?, head_rev = ? WHERE did = ?";
    var upd_stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, upd_sql, -1, &upd_stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(upd_stmt);
    _ = c.sqlite3_bind_text(upd_stmt, 1, commit_cid_s.ptr, @intCast(commit_cid_s.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(upd_stmt, 2, rev.str().ptr, @intCast(rev.str().len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(upd_stmt, 3, did.ptr, @intCast(did.len), c.sqliteTransientAsDestructor());
    if (c.sqlite3_step(upd_stmt.?) != c.SQLITE_DONE) return error.StepFailed;

    // Emit firehose event. Body = commit CBOR (signed). Subscribers
    // reconstruct individual records by reading atp_records.
    const new_seq = firehose.append(db, did, commit_cid_s, enc.written(), committed_at) catch |e| switch (e) {
        else => return e,
    };

    // W2.1: best-effort broadcast to live WS subscribers. The
    // notification carries the seq number; subscribers re-fetch the
    // commit body from SQLite (see `sync_firehose.zig`). A missing
    // registry (early boot) silently drops — replay covers the gap
    // on the next subscriber reconnect.
    if (state_mod.get().ws_registry) |reg| {
        sync_firehose.broadcastSeq(reg, new_seq);
    }

    @memcpy(commit_out.cid_buf[0..commit_cid_s.len], commit_cid_s);
    commit_out.cid_len = @intCast(commit_cid_s.len);
    @memcpy(commit_out.data_cid_buf[0..data_cid_s.len], data_cid_s);
    commit_out.data_cid_len = @intCast(data_cid_s.len);
    @memcpy(commit_out.rev_buf[0..tid_mod.tid_len], rev.str());

    return commit_out;
}

pub const RecordRow = struct {
    cid_buf: [cid_mod.string_cid_len]u8 = undefined,
    cid_len: u8 = 0,
    value_buf: [4096]u8 = undefined,
    value_len: u16 = 0,
    indexed_at: i64 = 0,

    pub fn cidStr(self: *const RecordRow) []const u8 {
        return self.cid_buf[0..self.cid_len];
    }
    pub fn value(self: *const RecordRow) []const u8 {
        return self.value_buf[0..self.value_len];
    }
};

pub fn getRecord(
    db: *c.sqlite3,
    did: []const u8,
    collection: []const u8,
    rkey: []const u8,
    out: *RecordRow,
) Error!bool {
    const sql = "SELECT cid, value, indexed_at FROM atp_records WHERE did = ? AND collection = ? AND rkey = ?";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, did.ptr, @intCast(did.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 2, collection.ptr, @intCast(collection.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 3, rkey.ptr, @intCast(rkey.len), c.sqliteTransientAsDestructor());
    const rc = c.sqlite3_step(stmt.?);
    if (rc == c.SQLITE_DONE) return false;
    if (rc != c.SQLITE_ROW) return error.StepFailed;

    const cid_ptr = c.sqlite3_column_text(stmt, 0);
    const cid_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
    const cap = @min(cid_len, out.cid_buf.len);
    if (cap > 0) @memcpy(out.cid_buf[0..cap], cid_ptr[0..cap]);
    out.cid_len = @intCast(cap);

    const val_ptr = c.sqlite3_column_blob(stmt, 1);
    const val_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 1));
    const val_cap = @min(val_len, out.value_buf.len);
    if (val_cap > 0 and val_ptr != null) {
        const p: [*]const u8 = @ptrCast(val_ptr);
        @memcpy(out.value_buf[0..val_cap], p[0..val_cap]);
    }
    out.value_len = @intCast(val_cap);
    out.indexed_at = c.sqlite3_column_int64(stmt, 2);
    return true;
}

pub fn deleteRecord(
    db: *c.sqlite3,
    did: []const u8,
    collection: []const u8,
    rkey: []const u8,
) Error!bool {
    const sql = "DELETE FROM atp_records WHERE did = ? AND collection = ? AND rkey = ?";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, did.ptr, @intCast(did.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 2, collection.ptr, @intCast(collection.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 3, rkey.ptr, @intCast(rkey.len), c.sqliteTransientAsDestructor());
    if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return error.StepFailed;
    return c.sqlite3_changes(db) > 0;
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

fn makeKey() keypair.Ed25519KeyPair {
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x42);
    return keypair.Ed25519KeyPair.fromSeed(seed);
}

test "repo: ensure + commit + getRecord round-trip" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);

    const kp = makeKey();
    try ensureRepo(db, "did:plc:alice", "did:key:zAlice", 1000);

    var tree: mst.Tree(mst.max_keys) = .{};
    var rng = core.rng.Rng.init(0x42);
    var ts = tid_mod.State.init(&rng);
    var sc = core.clock.SimClock.init(1_700_000_000);
    const rev = ts.next(sc.clock());

    var record_cbor: [128]u8 = undefined;
    var enc = dag.Encoder.init(&record_cbor);
    try enc.writeMapHeader(2);
    try enc.writeText("$type");
    try enc.writeText("app.bsky.feed.post");
    try enc.writeText("text");
    try enc.writeText("hello world");

    const ops = [_]Operation{
        .{ .collection = "app.bsky.feed.post", .rkey = "abc123", .value_cbor = enc.written() },
    };
    const commit_out = try commit(db, "did:plc:alice", kp, rev, &tree, &ops, 1_700_000_000, null);
    try testing.expect(commit_out.cid_len > 0);

    var row: RecordRow = .{};
    try testing.expect(try getRecord(db, "did:plc:alice", "app.bsky.feed.post", "abc123", &row));
    try testing.expectEqualSlices(u8, enc.written(), row.value());
}

test "repo: loadRepoMeta returns head after commit" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    const kp = makeKey();
    try ensureRepo(db, "did:plc:bob", "did:key:zBob", 100);

    var tree: mst.Tree(mst.max_keys) = .{};
    var rng = core.rng.Rng.init(0x7);
    var ts = tid_mod.State.init(&rng);
    var sc = core.clock.SimClock.init(200);
    const rev = ts.next(sc.clock());

    var cb: [64]u8 = undefined;
    var enc = dag.Encoder.init(&cb);
    try enc.writeMapHeader(1);
    try enc.writeText("k");
    try enc.writeText("v");

    const ops = [_]Operation{.{ .collection = "x.test.note", .rkey = "r1", .value_cbor = enc.written() }};
    const c1 = try commit(db, "did:plc:bob", kp, rev, &tree, &ops, 200, null);

    var meta: RepoMeta = .{};
    try testing.expect(try loadRepoMeta(db, "did:plc:bob", &meta));
    try testing.expectEqualStrings(c1.cidStr(), meta.headCid());
}

test "repo: MST persistence + reload gives same root" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    const kp = makeKey();
    try ensureRepo(db, "did:plc:c", "did:key:z", 10);

    var tree1: mst.Tree(mst.max_keys) = .{};
    var rng = core.rng.Rng.init(0x1);
    var ts = tid_mod.State.init(&rng);
    var sc = core.clock.SimClock.init(11);
    const rev = ts.next(sc.clock());

    var cb: [32]u8 = undefined;
    var enc = dag.Encoder.init(&cb);
    try enc.writeMapHeader(1);
    try enc.writeText("a");
    try enc.writeUInt(1);

    const ops = [_]Operation{
        .{ .collection = "x.test.note", .rkey = "r1", .value_cbor = enc.written() },
        .{ .collection = "x.test.note", .rkey = "r2", .value_cbor = enc.written() },
    };
    const commit1 = try commit(db, "did:plc:c", kp, rev, &tree1, &ops, 11, null);

    // Reload into a fresh tree.
    var tree2: mst.Tree(mst.max_keys) = .{};
    try loadTree(db, "did:plc:c", &tree2);
    var s2: [64 * 1024]u8 = undefined;
    const r2 = try tree2.getRoot(&s2);
    var data_cid_str: [cid_mod.string_cid_len]u8 = undefined;
    const data_cid_s = try cid_mod.encodeString(r2.cid, &data_cid_str);
    try testing.expectEqualStrings(commit1.dataCidStr(), data_cid_s);
}

test "repo: deleteRecord removes row" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    const kp = makeKey();
    try ensureRepo(db, "did:plc:d", "did:key:z", 1);

    var tree: mst.Tree(mst.max_keys) = .{};
    var rng = core.rng.Rng.init(0x3);
    var ts = tid_mod.State.init(&rng);
    var sc = core.clock.SimClock.init(2);
    const rev = ts.next(sc.clock());

    var cb: [16]u8 = undefined;
    var enc = dag.Encoder.init(&cb);
    try enc.writeMapHeader(0);
    const ops = [_]Operation{.{ .collection = "n.s.r", .rkey = "k1", .value_cbor = enc.written() }};
    _ = try commit(db, "did:plc:d", kp, rev, &tree, &ops, 2, null);

    try testing.expect(try deleteRecord(db, "did:plc:d", "n.s.r", "k1"));
    var row: RecordRow = .{};
    try testing.expect(!(try getRecord(db, "did:plc:d", "n.s.r", "k1", &row)));
}

test "repo: commit emits firehose event" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    const kp = makeKey();
    try ensureRepo(db, "did:plc:e", "did:key:z", 1);

    var tree: mst.Tree(mst.max_keys) = .{};
    var rng = core.rng.Rng.init(0x4);
    var ts = tid_mod.State.init(&rng);
    var sc = core.clock.SimClock.init(2);
    const rev = ts.next(sc.clock());

    var cb: [16]u8 = undefined;
    var enc = dag.Encoder.init(&cb);
    try enc.writeMapHeader(0);
    const ops = [_]Operation{.{ .collection = "n.s.r", .rkey = "k1", .value_cbor = enc.written() }};
    _ = try commit(db, "did:plc:e", kp, rev, &tree, &ops, 2, null);

    var events: [4]firehose.Event = undefined;
    const n = try firehose.readSince(db, 0, &events);
    try testing.expect(n >= 1);
    try testing.expectEqualStrings("did:plc:e", events[0].did());
}
