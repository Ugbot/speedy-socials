//! Public media-plugin API.
//!
//! Other plugins (Mastodon, AT Protocol) delegate their upload routes
//! here so the storage, content-addressing, and metadata logic lives in
//! exactly one place. The HTTP-shaped wrappers in `routes.zig` are thin
//! adapters over these primitives.
//!
//! Tiger Style: every primitive takes caller-provided buffers / db
//! handle. No allocator on the hot path.

const std = @import("std");
const c = @import("sqlite").c;
const core = @import("core");

const limits = core.limits;
const multipart_mod = @import("multipart.zig");
const image = @import("image.zig");
const blurhash = @import("blurhash.zig");
const pixels = @import("pixels.zig");
const state = @import("state.zig");

pub const Error = error{
    DbNotReady,
    PayloadTooLarge,
    PrepareFailed,
    StepFailed,
    EncodeFailed,
    UnsupportedFormat,
};

/// Stored attachment metadata returned to the caller. The caller is
/// responsible for serializing this back as a Mastodon/AT-shaped JSON
/// envelope.
pub const StoredAttachment = struct {
    id: i64 = 0,
    /// Hex-encoded sha256 (32 bytes → 64 ASCII chars).
    cid_buf: [64]u8 = undefined,
    cid_len: usize = 0,
    kind_buf: [16]u8 = undefined,
    kind_len: usize = 0,
    mime_buf: [128]u8 = undefined,
    mime_len: usize = 0,
    blurhash_buf: [40]u8 = undefined,
    blurhash_len: usize = 0,
    width: ?u32 = null,
    height: ?u32 = null,
    size: u64 = 0,
    description_buf: [512]u8 = undefined,
    description_len: usize = 0,
    focus_x: f32 = 0,
    focus_y: f32 = 0,
    created_at: i64 = 0,

    pub fn cidStr(self: *const StoredAttachment) []const u8 {
        return self.cid_buf[0..self.cid_len];
    }
    pub fn kindStr(self: *const StoredAttachment) []const u8 {
        return self.kind_buf[0..self.kind_len];
    }
    pub fn mimeStr(self: *const StoredAttachment) []const u8 {
        return self.mime_buf[0..self.mime_len];
    }
    pub fn blurhashStr(self: *const StoredAttachment) []const u8 {
        return self.blurhash_buf[0..self.blurhash_len];
    }
    pub fn descriptionStr(self: *const StoredAttachment) []const u8 {
        return self.description_buf[0..self.description_len];
    }
};

/// Content-addressing helper. SHA-256 hex; we keep the same shape the
/// media route was already producing so existing URLs survive.
fn blobCid(bytes: []const u8, out: *[64]u8) []const u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &hash, .{});
    const hex = "0123456789abcdef";
    for (hash, 0..) |b, i| {
        out[i * 2] = hex[b >> 4];
        out[i * 2 + 1] = hex[b & 0x0F];
    }
    return out[0..64];
}

fn kindForMime(mime: []const u8) []const u8 {
    if (std.mem.startsWith(u8, mime, "image/gif")) return "gifv";
    if (std.mem.startsWith(u8, mime, "image/")) return "image";
    if (std.mem.startsWith(u8, mime, "video/")) return "video";
    if (std.mem.startsWith(u8, mime, "audio/")) return "audio";
    return "unknown";
}

/// Store a parsed multipart `file` part. `description` / `focus_x`/y
/// are optional metadata from sibling multipart fields. Returns a
/// fully-populated `StoredAttachment`.
pub fn storeUpload(
    owner_user_id: i64,
    part: *const multipart_mod.Part,
    description: []const u8,
    focus_x: f32,
    focus_y: f32,
    out: *StoredAttachment,
) Error!void {
    const st = state.get();
    const db = st.db orelse return error.DbNotReady;
    if (part.body.len == 0) return error.PayloadTooLarge; // empty is its own kind of bad
    if (part.body.len > limits.max_upload_bytes) return error.PayloadTooLarge;

    const sniffed = image.sniff(part.body);
    var mime: []const u8 = sniffed.mime;
    if (sniffed.kind == .unknown) {
        if (part.contentType()) |ct| mime = ct;
    }
    const kind = kindForMime(mime);

    var bh: []const u8 = pixels.stub_blurhash;
    var blurhash_buf: [40]u8 = undefined;
    if (sniffed.kind == .png and sniffed.width != null and sniffed.height != null) {
        const w = sniffed.width.?;
        const h = sniffed.height.?;
        if (w <= 2048 and h <= 2048) {
            var stack_scratch: [1 << 18]u8 = undefined;
            var rgba_out: [pixels.sample_dim * pixels.sample_dim * 4]u8 = undefined;
            const needed: usize = 5 * @as(usize, w) * @as(usize, h) + 1024;
            if (needed <= stack_scratch.len) {
                if (pixels.sample(part.body, sniffed, &stack_scratch, &rgba_out)) |sampled| {
                    if (blurhash.encode(sampled.rgba, pixels.sample_dim, pixels.sample_dim, 4, 3, &blurhash_buf)) |hash| {
                        bh = hash;
                    } else |_| {}
                } else |_| {}
            }
        }
    }

    var cid_buf: [64]u8 = undefined;
    const cid = blobCid(part.body, &cid_buf);

    const created_at = st.clock.wallUnix();

    try storeBlob(db, cid, mime, part.body, created_at);
    const att_id = insertAttachment(db, .{
        .owner_user_id = owner_user_id,
        .blob_cid = cid,
        .kind = kind,
        .description = description,
        .focus_x = focus_x,
        .focus_y = focus_y,
        .blurhash = bh,
        .width = sniffed.width,
        .height = sniffed.height,
        .mime = mime,
        .size = part.body.len,
        .created_at = created_at,
    }) catch return error.StepFailed;

    out.* = .{};
    out.id = att_id;
    @memcpy(out.cid_buf[0..cid.len], cid);
    out.cid_len = cid.len;
    @memcpy(out.kind_buf[0..kind.len], kind);
    out.kind_len = kind.len;
    @memcpy(out.mime_buf[0..mime.len], mime);
    out.mime_len = mime.len;
    @memcpy(out.blurhash_buf[0..bh.len], bh);
    out.blurhash_len = bh.len;
    out.width = sniffed.width;
    out.height = sniffed.height;
    out.size = part.body.len;
    const d_n = @min(description.len, out.description_buf.len);
    if (d_n > 0) @memcpy(out.description_buf[0..d_n], description[0..d_n]);
    out.description_len = d_n;
    out.focus_x = focus_x;
    out.focus_y = focus_y;
    out.created_at = created_at;
}

/// Store a raw blob (no multipart) and return its CID. Used by
/// `com.atproto.repo.uploadBlob` which posts the bytes directly.
pub fn storeBlobBytes(
    did: []const u8,
    mime: []const u8,
    bytes: []const u8,
    out_cid: *[64]u8,
) Error![]const u8 {
    _ = did; // single-DID-per-blob is recorded indirectly via insertAttachment caller side
    const st = state.get();
    const db = st.db orelse return error.DbNotReady;
    if (bytes.len == 0 or bytes.len > limits.max_upload_bytes) return error.PayloadTooLarge;
    if (bytes.len > limits.media_inline_threshold_bytes) return error.PayloadTooLarge;
    const cid = blobCid(bytes, out_cid);
    const now = st.clock.wallUnix();
    try storeBlob(db, cid, mime, bytes, now);
    return cid;
}

// ── SQL helpers (kept in lock-step with routes.zig) ────────────────

fn storeBlob(db: *c.sqlite3, cid: []const u8, mime: []const u8, data: []const u8, created_at: i64) Error!void {
    {
        var sel: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db, "SELECT 1 FROM atp_blobs WHERE cid = ?", -1, &sel, null) != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(sel);
        _ = c.sqlite3_bind_text(sel, 1, cid.ptr, @intCast(cid.len), c.sqliteTransientAsDestructor());
        const rc = c.sqlite3_step(sel.?);
        if (rc == c.SQLITE_ROW) {
            var upd: ?*c.sqlite3_stmt = null;
            if (c.sqlite3_prepare_v2(db, "UPDATE atp_blobs SET ref_count = ref_count + 1 WHERE cid = ?", -1, &upd, null) != c.SQLITE_OK) return error.PrepareFailed;
            defer _ = c.sqlite3_finalize(upd);
            _ = c.sqlite3_bind_text(upd, 1, cid.ptr, @intCast(cid.len), c.sqliteTransientAsDestructor());
            if (c.sqlite3_step(upd.?) != c.SQLITE_DONE) return error.StepFailed;
            return;
        }
    }
    if (data.len > limits.media_inline_threshold_bytes) return error.PayloadTooLarge;
    var ins: ?*c.sqlite3_stmt = null;
    const ins_sql = "INSERT INTO atp_blobs(cid, did, mime, size, ref_count, data, created_at) VALUES (?, ?, ?, ?, 1, ?, ?)";
    if (c.sqlite3_prepare_v2(db, ins_sql, -1, &ins, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(ins);
    _ = c.sqlite3_bind_text(ins, 1, cid.ptr, @intCast(cid.len), c.sqliteTransientAsDestructor());
    const did_placeholder: []const u8 = "did:plc:media";
    _ = c.sqlite3_bind_text(ins, 2, did_placeholder.ptr, @intCast(did_placeholder.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(ins, 3, mime.ptr, @intCast(mime.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(ins, 4, @intCast(data.len));
    _ = c.sqlite3_bind_blob(ins, 5, data.ptr, @intCast(data.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(ins, 6, created_at);
    if (c.sqlite3_step(ins.?) != c.SQLITE_DONE) return error.StepFailed;
}

const InsertParams = struct {
    owner_user_id: i64,
    blob_cid: []const u8,
    kind: []const u8,
    description: []const u8,
    focus_x: f32,
    focus_y: f32,
    blurhash: []const u8,
    width: ?u32,
    height: ?u32,
    mime: []const u8,
    size: usize,
    created_at: i64,
};

fn insertAttachment(db: *c.sqlite3, p: InsertParams) !i64 {
    const sql =
        "INSERT INTO media_attachments(owner_user_id, blob_cid, kind, description, focus_x, focus_y, blurhash, width, height, mime, size, created_at) " ++
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_int64(stmt, 1, p.owner_user_id);
    _ = c.sqlite3_bind_text(stmt, 2, p.blob_cid.ptr, @intCast(p.blob_cid.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 3, p.kind.ptr, @intCast(p.kind.len), c.sqliteTransientAsDestructor());
    if (p.description.len > 0) {
        _ = c.sqlite3_bind_text(stmt, 4, p.description.ptr, @intCast(p.description.len), c.sqliteTransientAsDestructor());
    } else {
        _ = c.sqlite3_bind_null(stmt, 4);
    }
    _ = c.sqlite3_bind_double(stmt, 5, p.focus_x);
    _ = c.sqlite3_bind_double(stmt, 6, p.focus_y);
    if (p.blurhash.len > 0) {
        _ = c.sqlite3_bind_text(stmt, 7, p.blurhash.ptr, @intCast(p.blurhash.len), c.sqliteTransientAsDestructor());
    } else {
        _ = c.sqlite3_bind_null(stmt, 7);
    }
    if (p.width) |w| _ = c.sqlite3_bind_int64(stmt, 8, @intCast(w)) else _ = c.sqlite3_bind_null(stmt, 8);
    if (p.height) |h| _ = c.sqlite3_bind_int64(stmt, 9, @intCast(h)) else _ = c.sqlite3_bind_null(stmt, 9);
    _ = c.sqlite3_bind_text(stmt, 10, p.mime.ptr, @intCast(p.mime.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(stmt, 11, @intCast(p.size));
    _ = c.sqlite3_bind_int64(stmt, 12, p.created_at);
    if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return error.StepFailed;
    return c.sqlite3_last_insert_rowid(db);
}

// ── tests ──────────────────────────────────────────────────────────

const testing = std.testing;
const sched = @import("schema.zig");

fn setupDb() !*c.sqlite3 {
    const db = try core.storage.sqlite.openWriter(":memory:");
    var schemas = core.storage.Schema.init();
    try schemas.register(core.storage.bootstrap_migration);
    for (sched.all_migrations) |m| try schemas.register(m);
    try schemas.applyAll(db);
    var errmsg: [*c]u8 = null;
    var buf: [4096]u8 = undefined;
    @memcpy(buf[0..sched.blobs_create_sql.len], sched.blobs_create_sql);
    buf[sched.blobs_create_sql.len] = 0;
    if (c.sqlite3_exec(db, &buf, null, null, &errmsg) != c.SQLITE_OK) {
        if (errmsg != null) c.sqlite3_free(errmsg);
        return error.StepFailed;
    }
    return db;
}

// SimClock + Rng must outlive every call into `state` that reads them
// through the vtable pointer, so we stash them in module-level slots
// the tests share. Keeping them off the per-test stack frame matches
// how the boot path keeps the real clock alive for the server's run.
var test_clock_storage: core.clock.SimClock = undefined;
var test_rng_storage: core.rng.Rng = undefined;

fn primeState(db: *c.sqlite3) void {
    state.reset();
    test_rng_storage = core.rng.Rng.init(0x99);
    test_clock_storage = core.clock.SimClock.init(1_700_000_000);
    state.init(test_clock_storage.clock(), &test_rng_storage);
    state.attachDb(db);
}

test "api: storeUpload round-trips into media_attachments + atp_blobs" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    primeState(db);
    defer state.reset();

    var headers: [limits.max_multipart_headers_per_part]multipart_mod.Header = undefined;
    headers[0] = .{ .name = "Content-Disposition", .value = "form-data; name=\"file\"; filename=\"a.txt\"" };
    headers[1] = .{ .name = "Content-Type", .value = "text/plain" };
    var part: multipart_mod.Part = .{ .headers = headers, .header_count = 2, .body = "abcdef" };

    var stored: StoredAttachment = .{ .id = 0 };
    try storeUpload(7, &part, "hi", 0.0, 0.0, &stored);
    try testing.expect(stored.id > 0);
    try testing.expectEqual(@as(u64, 6), stored.size);
    try testing.expectEqualStrings("unknown", stored.kindStr());

    // Verify atp_blobs row.
    var s: ?*c.sqlite3_stmt = null;
    _ = c.sqlite3_prepare_v2(db, "SELECT size FROM atp_blobs WHERE cid = ?", -1, &s, null);
    defer _ = c.sqlite3_finalize(s);
    _ = c.sqlite3_bind_text(s, 1, stored.cid_buf[0..stored.cid_len].ptr, @intCast(stored.cid_len), c.sqliteTransientAsDestructor());
    try testing.expectEqual(@as(c_int, c.SQLITE_ROW), c.sqlite3_step(s.?));
    try testing.expectEqual(@as(i64, 6), c.sqlite3_column_int64(s.?, 0));
}

test "api: storeBlobBytes returns deterministic CID" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    primeState(db);
    defer state.reset();

    var cid_buf_a: [64]u8 = undefined;
    const cid_a = try storeBlobBytes("did:plc:x", "image/png", "PAYLOAD", &cid_buf_a);
    var cid_buf_b: [64]u8 = undefined;
    const cid_b = try storeBlobBytes("did:plc:x", "image/png", "PAYLOAD", &cid_buf_b);
    try testing.expectEqualStrings(cid_a, cid_b);
}

test "api: storeBlobBytes rejects oversize body" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    primeState(db);
    defer state.reset();
    var huge: [limits.media_inline_threshold_bytes + 1]u8 = undefined;
    @memset(&huge, 'X');
    var cid_buf: [64]u8 = undefined;
    try testing.expectError(error.PayloadTooLarge, storeBlobBytes("did:plc:big", "application/octet-stream", &huge, &cid_buf));
}

test "api: storeUpload rejects empty body" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    primeState(db);
    defer state.reset();
    var headers: [limits.max_multipart_headers_per_part]multipart_mod.Header = undefined;
    headers[0] = .{ .name = "Content-Disposition", .value = "form-data; name=\"file\"" };
    var part: multipart_mod.Part = .{ .headers = headers, .header_count = 1, .body = "" };
    var stored: StoredAttachment = .{ .id = 0 };
    try testing.expectError(error.PayloadTooLarge, storeUpload(0, &part, "", 0, 0, &stored));
}
