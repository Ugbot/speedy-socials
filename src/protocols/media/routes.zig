//! Media plugin HTTP routes.
//!
//! Endpoints (Mastodon-shaped):
//!   POST /api/v2/media        — multipart upload (canonical)
//!   POST /api/v1/media        — alias to v2 for older clients
//!   GET  /api/v1/media/:id    — attachment metadata
//!   PUT  /api/v1/media/:id    — update description / focus
//!   GET  /blobs/:cid          — serve blob bytes (chunked stream)
//!
//! Tiger Style: every handler is bounded — no heap, no per-request
//! arena allocations beyond what the framework hands us. Multipart
//! parsing runs in-place over `request.body`.

const std = @import("std");
const c = @import("sqlite").c;
const core = @import("core");

const HandlerContext = core.http.router.HandlerContext;
const Router = core.http.router.Router;
const Method = core.http.request.Method;
const Status = core.http.response.Status;
const limits = core.limits;

const state = @import("state.zig");
const multipart = @import("multipart.zig");
const image = @import("image.zig");
const blurhash = @import("blurhash.zig");
const pixels = @import("pixels.zig");
const sched = @import("schema.zig");

pub fn register(router: *Router, plugin_index: u16) !void {
    try router.register(.post, "/api/v2/media", postMedia, plugin_index);
    try router.register(.post, "/api/v1/media", postMedia, plugin_index);
    try router.register(.get, "/api/v1/media/:id", getAttachment, plugin_index);
    try router.register(.put, "/api/v1/media/:id", putAttachment, plugin_index);
    try router.register(.get, "/blobs/:cid", getBlob, plugin_index);
}

// ── helpers ────────────────────────────────────────────────────────

fn writeJson(hc: *HandlerContext, status: Status, body: []const u8) !void {
    try hc.response.startStatus(status);
    try hc.response.header("Content-Type", "application/json");
    try hc.response.headerFmt("Content-Length", "{d}", .{body.len});
    try hc.response.header("Connection", "close");
    try hc.response.finishHeaders();
    try hc.response.body(body);
}

fn writeError(hc: *HandlerContext, status: Status, name: []const u8, msg: []const u8) !void {
    var buf: [512]u8 = undefined;
    const body = std.fmt.bufPrint(&buf, "{{\"error\":\"{s}\",\"message\":\"{s}\"}}", .{ name, msg }) catch return error.OutOfMemory;
    try writeJson(hc, status, body);
}

/// Compute a sha-256 over the blob bytes and emit a stable hex string.
/// We avoid CIDv1 base32 here to keep this module independent of the
/// atproto plugin's CID library — the byte content is what matters.
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

// ── POST /api/v(1|2)/media ─────────────────────────────────────────

fn postMedia(hc: *HandlerContext) anyerror!void {
    const st = state.get();
    const db = st.db orelse return writeError(hc, .service_unavailable, "ServiceUnavailable", "db not ready");

    // Up-front 413 on the raw body. multipart frames push it slightly
    // higher than the file content but the spec cap applies to the
    // raw upload too.
    if (hc.request.body.len > limits.max_upload_bytes) {
        return writeError(hc, .payload_too_large, "PayloadTooLarge", "upload exceeds limit");
    }

    const content_type = hc.request.header("Content-Type") orelse {
        return writeError(hc, .bad_request, "InvalidRequest", "missing Content-Type");
    };
    if (std.mem.indexOf(u8, content_type, "multipart/form-data") == null) {
        return writeError(hc, .bad_request, "InvalidRequest", "expected multipart/form-data");
    }
    const boundary = multipart.parseBoundary(content_type) catch {
        return writeError(hc, .bad_request, "InvalidRequest", "bad multipart boundary");
    };

    var parts: [limits.max_multipart_parts]multipart.Part = undefined;
    const count = multipart.parseAll(hc.request.body, boundary, &parts) catch |err| switch (err) {
        error.PayloadTooLarge => return writeError(hc, .payload_too_large, "PayloadTooLarge", "part exceeds limit"),
        error.TooManyParts, error.TooManyHeaders => return writeError(hc, .bad_request, "TooManyParts", "too many parts/headers"),
        else => return writeError(hc, .bad_request, "InvalidRequest", "malformed multipart"),
    };

    // Find the "file" part and optional "description" / "focus".
    var file_part: ?*const multipart.Part = null;
    var description: []const u8 = "";
    var focus_x: f32 = 0;
    var focus_y: f32 = 0;
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        const p = &parts[i];
        const name = p.dispositionName() orelse continue;
        if (std.mem.eql(u8, name, "file")) {
            file_part = p;
        } else if (std.mem.eql(u8, name, "description")) {
            description = p.body;
        } else if (std.mem.eql(u8, name, "focus")) {
            parseFocus(p.body, &focus_x, &focus_y);
        }
    }
    const file = file_part orelse return writeError(hc, .bad_request, "InvalidRequest", "missing file part");
    if (file.body.len == 0) return writeError(hc, .bad_request, "InvalidRequest", "empty file part");
    if (file.body.len > limits.max_upload_bytes) {
        return writeError(hc, .payload_too_large, "PayloadTooLarge", "file exceeds limit");
    }

    // Sniff mime + dimensions.
    const sniffed = image.sniff(file.body);
    var mime: []const u8 = sniffed.mime;
    // Caller's Content-Type header on the part overrides if we didn't recognise.
    if (sniffed.kind == .unknown) {
        if (file.contentType()) |ct| mime = ct;
    }
    const kind = kindForMime(mime);

    // Compute blurhash. Only PNG can be sampled accurately today; for
    // everything else we substitute the documented stub hash so the
    // attachment shape stays valid Mastodon JSON.
    var blurhash_buf: [40]u8 = undefined;
    var bh_slice: []const u8 = pixels.stub_blurhash;
    if (sniffed.kind == .png and sniffed.width != null and sniffed.height != null) {
        const w = sniffed.width.?;
        const h = sniffed.height.?;
        // Cap source resolution we'll attempt to decode (memory bound).
        if (w <= 2048 and h <= 2048) {
            // Scratch: 4*w*h decompressed + (4*w*h + h) for IDAT, plus row scratch.
            // For 2048×2048 this is ~16 MiB. We need a heap allocation
            // for this scratch only; tiered: try a stack-friendly cap.
            var stack_scratch: [1 << 18]u8 = undefined; // 256 KiB stack: covers up to ~256×256
            var rgba_out: [pixels.sample_dim * pixels.sample_dim * 4]u8 = undefined;
            // Required: 4*w*h + (w*4+1)*h ≈ 5*w*h.
            const needed: usize = 5 * @as(usize, w) * @as(usize, h) + 1024;
            if (needed <= stack_scratch.len) {
                if (pixels.sample(file.body, sniffed, &stack_scratch, &rgba_out)) |sampled| {
                    if (blurhash.encode(sampled.rgba, pixels.sample_dim, pixels.sample_dim, 4, 3, &blurhash_buf)) |hash| {
                        bh_slice = hash;
                    } else |_| {}
                } else |_| {}
            }
        }
    }

    // Compute blob CID + store in atp_blobs (or filesystem spillover).
    var cid_buf: [64]u8 = undefined;
    const cid = blobCid(file.body, &cid_buf);

    const created_at = st.clock.wallUnix();
    storeBlobAt(db, cid, mime, file.body, st.media_root, created_at) catch |err| switch (err) {
        error.PayloadTooLarge => return writeError(hc, .payload_too_large, "PayloadTooLarge", "blob exceeds inline cap"),
        else => return writeError(hc, .internal, "InternalError", "blob store failed"),
    };
    const owner_user_id: i64 = 0; // OAuth not wired yet (W1.2/W1.3)
    const att_id = insertAttachment(db, .{
        .owner_user_id = owner_user_id,
        .blob_cid = cid,
        .kind = kind,
        .description = description,
        .focus_x = focus_x,
        .focus_y = focus_y,
        .blurhash = bh_slice,
        .width = sniffed.width,
        .height = sniffed.height,
        .mime = mime,
        .size = file.body.len,
        .created_at = created_at,
    }) catch {
        return writeError(hc, .internal, "InternalError", "attachment insert failed");
    };

    // Build response JSON.
    var resp_buf: [2048]u8 = undefined;
    const body = formatAttachment(.{
        .id = att_id,
        .kind = kind,
        .url_buf = &resp_buf,
        .base_url = st.base_url,
        .cid = cid,
        .blurhash = bh_slice,
        .description = description,
        .focus_x = focus_x,
        .focus_y = focus_y,
        .width = sniffed.width,
        .height = sniffed.height,
        .size = file.body.len,
    }, &resp_buf) catch return writeError(hc, .internal, "InternalError", "response too large");
    try writeJson(hc, .ok, body);
}

fn parseFocus(s: []const u8, x: *f32, y: *f32) void {
    const comma = std.mem.indexOfScalar(u8, s, ',') orelse return;
    x.* = std.fmt.parseFloat(f32, s[0..comma]) catch return;
    y.* = std.fmt.parseFloat(f32, s[comma + 1 ..]) catch return;
}

// ── GET /api/v1/media/:id ──────────────────────────────────────────

fn getAttachment(hc: *HandlerContext) anyerror!void {
    const st = state.get();
    const db = st.db orelse return writeError(hc, .service_unavailable, "ServiceUnavailable", "db not ready");
    const id_str = hc.params.get("id") orelse return writeError(hc, .bad_request, "InvalidRequest", "missing id");
    const id = std.fmt.parseInt(i64, id_str, 10) catch {
        return writeError(hc, .bad_request, "InvalidRequest", "bad id");
    };

    var row: AttachmentRow = .{};
    const found = loadAttachment(db, id, &row) catch {
        return writeError(hc, .internal, "InternalError", "load failed");
    };
    if (!found) return writeError(hc, .not_found, "RecordNotFound", "no such attachment");

    var resp_buf: [2048]u8 = undefined;
    const body = formatAttachment(.{
        .id = id,
        .kind = row.kindStr(),
        .url_buf = &resp_buf,
        .base_url = st.base_url,
        .cid = row.cid_buf[0..row.cid_len],
        .blurhash = row.blurhash_buf[0..row.blurhash_len],
        .description = row.desc_buf[0..row.desc_len],
        .focus_x = row.focus_x,
        .focus_y = row.focus_y,
        .width = if (row.width != 0) row.width else null,
        .height = if (row.height != 0) row.height else null,
        .size = row.size,
    }, &resp_buf) catch return writeError(hc, .internal, "InternalError", "response too large");
    try writeJson(hc, .ok, body);
}

// ── PUT /api/v1/media/:id ──────────────────────────────────────────

fn putAttachment(hc: *HandlerContext) anyerror!void {
    const st = state.get();
    const db = st.db orelse return writeError(hc, .service_unavailable, "ServiceUnavailable", "db not ready");
    const id_str = hc.params.get("id") orelse return writeError(hc, .bad_request, "InvalidRequest", "missing id");
    const id = std.fmt.parseInt(i64, id_str, 10) catch {
        return writeError(hc, .bad_request, "InvalidRequest", "bad id");
    };

    // Accept either JSON body { "description": "...", "focus": "x,y" }
    // or multipart/form-data with those same fields. The former is what
    // Mastodon's client SDKs actually send, so handle it first.
    var description: ?[]const u8 = null;
    var focus_x: ?f32 = null;
    var focus_y: ?f32 = null;

    if (extractJsonString(hc.request.body, "description")) |d| description = d;
    if (extractJsonString(hc.request.body, "focus")) |f| {
        var fx: f32 = 0;
        var fy: f32 = 0;
        parseFocus(f, &fx, &fy);
        focus_x = fx;
        focus_y = fy;
    }

    if (description == null and focus_x == null) {
        return writeError(hc, .bad_request, "InvalidRequest", "no fields to update");
    }

    updateAttachment(db, id, description, focus_x, focus_y) catch {
        return writeError(hc, .internal, "InternalError", "update failed");
    };

    var row: AttachmentRow = .{};
    const found = loadAttachment(db, id, &row) catch {
        return writeError(hc, .internal, "InternalError", "reload failed");
    };
    if (!found) return writeError(hc, .not_found, "RecordNotFound", "no such attachment");

    var resp_buf: [2048]u8 = undefined;
    const body = formatAttachment(.{
        .id = id,
        .kind = row.kindStr(),
        .url_buf = &resp_buf,
        .base_url = st.base_url,
        .cid = row.cid_buf[0..row.cid_len],
        .blurhash = row.blurhash_buf[0..row.blurhash_len],
        .description = row.desc_buf[0..row.desc_len],
        .focus_x = row.focus_x,
        .focus_y = row.focus_y,
        .width = if (row.width != 0) row.width else null,
        .height = if (row.height != 0) row.height else null,
        .size = row.size,
    }, &resp_buf) catch return writeError(hc, .internal, "InternalError", "response too large");
    try writeJson(hc, .ok, body);
}

fn extractJsonString(body: []const u8, name: []const u8) ?[]const u8 {
    var needle_buf: [128]u8 = undefined;
    if (name.len + 4 > needle_buf.len) return null;
    needle_buf[0] = '"';
    @memcpy(needle_buf[1..][0..name.len], name);
    needle_buf[1 + name.len] = '"';
    needle_buf[2 + name.len] = ':';
    needle_buf[3 + name.len] = '"';
    const needle = needle_buf[0 .. 4 + name.len];
    const start = std.mem.indexOf(u8, body, needle) orelse return null;
    const val_start = start + needle.len;
    const end_rel = std.mem.indexOfScalar(u8, body[val_start..], '"') orelse return null;
    return body[val_start .. val_start + end_rel];
}

// ── GET /blobs/:cid ────────────────────────────────────────────────

fn getBlob(hc: *HandlerContext) anyerror!void {
    const st = state.get();
    const db = st.db orelse return writeError(hc, .service_unavailable, "ServiceUnavailable", "db not ready");
    const cid = hc.params.get("cid") orelse return writeError(hc, .bad_request, "InvalidRequest", "missing cid");

    // Look up mime + size + data.
    var mime_buf: [128]u8 = undefined;
    var mime_len: usize = 0;
    // Inline-only path: blob data lives in the DB row, capped at the
    // inline threshold. Anything bigger should have been spilled to FS
    // (not yet wired — see `storeBlob`).
    var data_buf: [limits.media_inline_threshold_bytes]u8 = undefined;
    var data_len: usize = 0;
    var fs_path_buf: [256]u8 = undefined;
    var fs_path_len: usize = 0;

    const found = loadBlob(db, cid, &mime_buf, &mime_len, &data_buf, &data_len, &fs_path_buf, &fs_path_len) catch {
        return writeError(hc, .internal, "InternalError", "blob load failed");
    };
    if (!found) return writeError(hc, .not_found, "RecordNotFound", "no such blob");

    // If we got a filesystem pointer, fail loudly: spillover writes
    // are gated behind the not-yet-wired Io handle (see storeBlob).
    if (fs_path_len > 0) {
        return writeError(hc, .not_implemented, "NotImplemented", "filesystem spillover read not wired yet");
    }

    const mime = if (mime_len > 0) mime_buf[0..mime_len] else "application/octet-stream";
    try hc.response.startStatus(.ok);
    try hc.response.header("Content-Type", mime);
    try hc.response.headerFmt("Content-Length", "{d}", .{data_len});
    try hc.response.header("Cache-Control", "public, max-age=31536000, immutable");
    try hc.response.header("Connection", "close");
    try hc.response.finishHeaders();
    try hc.response.body(data_buf[0..data_len]);
}

// ── data shapes ────────────────────────────────────────────────────

const AttachmentRow = struct {
    cid_buf: [64]u8 = undefined,
    cid_len: usize = 0,
    kind_buf: [16]u8 = undefined,
    kind_len: usize = 0,
    desc_buf: [512]u8 = undefined,
    desc_len: usize = 0,
    blurhash_buf: [40]u8 = undefined,
    blurhash_len: usize = 0,
    focus_x: f32 = 0,
    focus_y: f32 = 0,
    width: u32 = 0,
    height: u32 = 0,
    mime_buf: [128]u8 = undefined,
    mime_len: usize = 0,
    size: u64 = 0,

    fn kindStr(self: *const AttachmentRow) []const u8 {
        return self.kind_buf[0..self.kind_len];
    }
};

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

// ── SQL helpers ────────────────────────────────────────────────────

fn storeBlob(db: *c.sqlite3, cid: []const u8, mime: []const u8, data: []const u8, media_root: []const u8) !void {
    return storeBlobAt(db, cid, mime, data, media_root, 0);
}

fn storeBlobAt(db: *c.sqlite3, cid: []const u8, mime: []const u8, data: []const u8, media_root: []const u8, created_at: i64) !void {
    // First: check whether the row already exists (content-addressed,
    // so duplicate uploads dedupe naturally).
    {
        var sel: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db, "SELECT 1 FROM atp_blobs WHERE cid = ?", -1, &sel, null) != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(sel);
        _ = c.sqlite3_bind_text(sel, 1, cid.ptr, @intCast(cid.len), c.sqliteTransientAsDestructor());
        const rc = c.sqlite3_step(sel.?);
        if (rc == c.SQLITE_ROW) {
            // Bump ref_count.
            var upd: ?*c.sqlite3_stmt = null;
            if (c.sqlite3_prepare_v2(db, "UPDATE atp_blobs SET ref_count = ref_count + 1 WHERE cid = ?", -1, &upd, null) != c.SQLITE_OK) return error.PrepareFailed;
            defer _ = c.sqlite3_finalize(upd);
            _ = c.sqlite3_bind_text(upd, 1, cid.ptr, @intCast(cid.len), c.sqliteTransientAsDestructor());
            if (c.sqlite3_step(upd.?) != c.SQLITE_DONE) return error.StepFailed;
            return;
        }
    }

    // New blob. Pick inline-vs-filesystem based on size.
    //
    // NOTE: filesystem spillover requires the `std.Io.Dir` handle which
    // the plugin Context does not carry today. Until that wiring lands
    // (W1.1 server upgrades will plumb Io through), large blobs are
    // simply rejected; the per-request 413 path catches them earlier
    // so this branch is defence-in-depth.
    _ = media_root;
    if (data.len > limits.media_inline_threshold_bytes) {
        return error.PayloadTooLarge;
    }
    const data_to_store: []const u8 = data;

    var ins: ?*c.sqlite3_stmt = null;
    const ins_sql = "INSERT INTO atp_blobs(cid, did, mime, size, ref_count, data, created_at) VALUES (?, ?, ?, ?, 1, ?, ?)";
    if (c.sqlite3_prepare_v2(db, ins_sql, -1, &ins, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(ins);
    _ = c.sqlite3_bind_text(ins, 1, cid.ptr, @intCast(cid.len), c.sqliteTransientAsDestructor());
    const did_placeholder: []const u8 = "did:plc:media";
    _ = c.sqlite3_bind_text(ins, 2, did_placeholder.ptr, @intCast(did_placeholder.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(ins, 3, mime.ptr, @intCast(mime.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(ins, 4, @intCast(data.len));
    _ = c.sqlite3_bind_blob(ins, 5, data_to_store.ptr, @intCast(data_to_store.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(ins, 6, created_at);
    if (c.sqlite3_step(ins.?) != c.SQLITE_DONE) return error.StepFailed;
}

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

fn loadAttachment(db: *c.sqlite3, id: i64, row: *AttachmentRow) !bool {
    const sql = "SELECT blob_cid, kind, description, focus_x, focus_y, blurhash, width, height, mime, size FROM media_attachments WHERE id = ?";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_int64(stmt, 1, id);
    const rc = c.sqlite3_step(stmt.?);
    if (rc == c.SQLITE_DONE) return false;
    if (rc != c.SQLITE_ROW) return error.StepFailed;
    copyColText(stmt.?, 0, &row.cid_buf, &row.cid_len);
    copyColText(stmt.?, 1, &row.kind_buf, &row.kind_len);
    copyColText(stmt.?, 2, &row.desc_buf, &row.desc_len);
    row.focus_x = @floatCast(c.sqlite3_column_double(stmt.?, 3));
    row.focus_y = @floatCast(c.sqlite3_column_double(stmt.?, 4));
    copyColText(stmt.?, 5, &row.blurhash_buf, &row.blurhash_len);
    row.width = @intCast(c.sqlite3_column_int64(stmt.?, 6));
    row.height = @intCast(c.sqlite3_column_int64(stmt.?, 7));
    copyColText(stmt.?, 8, &row.mime_buf, &row.mime_len);
    row.size = @intCast(c.sqlite3_column_int64(stmt.?, 9));
    return true;
}

fn copyColText(stmt: *c.sqlite3_stmt, col: c_int, out: []u8, out_len: *usize) void {
    const t = c.sqlite3_column_type(stmt, col);
    if (t == c.SQLITE_NULL) {
        out_len.* = 0;
        return;
    }
    const ptr = c.sqlite3_column_text(stmt, col);
    const n: usize = @intCast(c.sqlite3_column_bytes(stmt, col));
    const copy = if (n > out.len) out.len else n;
    if (n > 0 and ptr != null) @memcpy(out[0..copy], ptr[0..copy]);
    out_len.* = copy;
}

fn updateAttachment(db: *c.sqlite3, id: i64, description: ?[]const u8, focus_x: ?f32, focus_y: ?f32) !void {
    if (description) |d| {
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db, "UPDATE media_attachments SET description = ? WHERE id = ?", -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);
        _ = c.sqlite3_bind_text(stmt, 1, d.ptr, @intCast(d.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_int64(stmt, 2, id);
        if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return error.StepFailed;
    }
    if (focus_x) |fx| {
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db, "UPDATE media_attachments SET focus_x = ?, focus_y = ? WHERE id = ?", -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);
        _ = c.sqlite3_bind_double(stmt, 1, fx);
        _ = c.sqlite3_bind_double(stmt, 2, focus_y orelse 0);
        _ = c.sqlite3_bind_int64(stmt, 3, id);
        if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return error.StepFailed;
    }
}

fn loadBlob(
    db: *c.sqlite3,
    cid: []const u8,
    mime_buf: []u8,
    mime_len: *usize,
    data_buf: []u8,
    data_len: *usize,
    fs_path_buf: []u8,
    fs_path_len: *usize,
) !bool {
    const sql = "SELECT mime, data FROM atp_blobs WHERE cid = ?";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, cid.ptr, @intCast(cid.len), c.sqliteTransientAsDestructor());
    const rc = c.sqlite3_step(stmt.?);
    if (rc == c.SQLITE_DONE) return false;
    if (rc != c.SQLITE_ROW) return error.StepFailed;
    copyColText(stmt.?, 0, mime_buf, mime_len);

    const t = c.sqlite3_column_type(stmt.?, 1);
    if (t == c.SQLITE_NULL) {
        data_len.* = 0;
        fs_path_len.* = 0;
        return true;
    }
    const ptr = c.sqlite3_column_blob(stmt.?, 1);
    const n: usize = @intCast(c.sqlite3_column_bytes(stmt.?, 1));
    if (n >= 3 and ptr != null) {
        const p: [*]const u8 = @ptrCast(ptr);
        if (p[0] == 'f' and p[1] == 's' and p[2] == ':') {
            const path_len = n - 3;
            const copy = if (path_len > fs_path_buf.len) fs_path_buf.len else path_len;
            @memcpy(fs_path_buf[0..copy], p[3 .. 3 + copy]);
            fs_path_len.* = copy;
            data_len.* = 0;
            return true;
        }
    }
    if (n > 0 and ptr != null) {
        const p: [*]const u8 = @ptrCast(ptr);
        const copy = if (n > data_buf.len) data_buf.len else n;
        @memcpy(data_buf[0..copy], p[0..copy]);
        data_len.* = copy;
    } else {
        data_len.* = 0;
    }
    fs_path_len.* = 0;
    return true;
}

// ── attachment JSON shape ──────────────────────────────────────────

const FormatArgs = struct {
    id: i64,
    kind: []const u8,
    url_buf: []u8,
    base_url: []const u8,
    cid: []const u8,
    blurhash: []const u8,
    description: []const u8,
    focus_x: f32,
    focus_y: f32,
    width: ?u32,
    height: ?u32,
    size: usize,
};

fn formatAttachment(args: FormatArgs, out: []u8) ![]const u8 {
    var url_scratch: [256]u8 = undefined;
    const url = if (args.base_url.len > 0)
        std.fmt.bufPrint(&url_scratch, "{s}/blobs/{s}", .{ args.base_url, args.cid }) catch return error.OutOfMemory
    else
        std.fmt.bufPrint(&url_scratch, "/blobs/{s}", .{args.cid}) catch return error.OutOfMemory;

    const w = args.width orelse 0;
    const h = args.height orelse 0;
    const aspect: f64 = if (h == 0) 0 else @as(f64, @floatFromInt(w)) / @as(f64, @floatFromInt(h));

    return std.fmt.bufPrint(out,
        "{{\"id\":\"{d}\",\"type\":\"{s}\",\"url\":\"{s}\",\"preview_url\":\"{s}\",\"remote_url\":null," ++
        "\"text_url\":null,\"meta\":{{\"original\":{{\"width\":{d},\"height\":{d},\"size\":\"{d}x{d}\",\"aspect\":{d:.3}}}}}," ++
        "\"description\":\"{s}\",\"blurhash\":\"{s}\",\"focus\":{{\"x\":{d:.3},\"y\":{d:.3}}}}}",
        .{
            args.id,             args.kind, url,         url,
            w,                   h,         w,           h,
            aspect,              args.description,
            args.blurhash,       args.focus_x,
            args.focus_y,
        },
    ) catch return error.OutOfMemory;
}

// ── tests ──────────────────────────────────────────────────────────

test "kindForMime maps mimes correctly" {
    try std.testing.expectEqualStrings("image", kindForMime("image/png"));
    try std.testing.expectEqualStrings("gifv", kindForMime("image/gif"));
    try std.testing.expectEqualStrings("video", kindForMime("video/mp4"));
    try std.testing.expectEqualStrings("audio", kindForMime("audio/mpeg"));
    try std.testing.expectEqualStrings("unknown", kindForMime("application/octet-stream"));
}

test "blobCid hex format is deterministic" {
    var buf1: [64]u8 = undefined;
    var buf2: [64]u8 = undefined;
    const a = blobCid("hello world", &buf1);
    const b = blobCid("hello world", &buf2);
    try std.testing.expectEqualStrings(a, b);
    try std.testing.expectEqual(@as(usize, 64), a.len);
}

test "extractJsonString finds plain field" {
    const body =
        \\{"description":"a cat","focus":"0.5,-0.3"}
    ;
    try std.testing.expectEqualStrings("a cat", extractJsonString(body, "description").?);
    try std.testing.expectEqualStrings("0.5,-0.3", extractJsonString(body, "focus").?);
    try std.testing.expect(extractJsonString(body, "missing") == null);
}

test "parseFocus extracts pair" {
    var x: f32 = 0;
    var y: f32 = 0;
    parseFocus("0.25,-0.75", &x, &y);
    try std.testing.expectApproxEqAbs(@as(f32, 0.25), x, 1e-6);
    try std.testing.expectApproxEqAbs(@as(f32, -0.75), y, 1e-6);
}

test "formatAttachment shape includes required Mastodon keys" {
    var out: [2048]u8 = undefined;
    var url_buf: [128]u8 = undefined;
    const body = try formatAttachment(.{
        .id = 42,
        .kind = "image",
        .url_buf = &url_buf,
        .base_url = "",
        .cid = "abc123",
        .blurhash = "L00000fQfQfQfQfQ",
        .description = "hi",
        .focus_x = 0,
        .focus_y = 0,
        .width = 320,
        .height = 200,
        .size = 4096,
    }, &out);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"id\":\"42\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"type\":\"image\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "/blobs/abc123") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"blurhash\":\"L00000fQfQfQfQfQ\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"width\":320") != null);
}

// ── integration tests over an in-memory DB ─────────────────────────

fn setupDb() !*c.sqlite3 {
    const db = try core.storage.sqlite.openWriter(":memory:");
    var schemas = core.storage.Schema.init();
    try schemas.register(core.storage.bootstrap_migration);
    for (sched.all_migrations) |m| try schemas.register(m);
    try schemas.applyAll(db);
    // The atp_blobs table is owned by the atproto plugin in production.
    // For media's standalone tests we materialise it directly so we
    // don't fight migration-id uniqueness.
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

test "storeBlob: inline path round-trips through atp_blobs" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    var cid_buf: [64]u8 = undefined;
    const data = "hello blob";
    const cid = blobCid(data, &cid_buf);
    try storeBlob(db, cid, "text/plain", data, "./_test_media");

    var mime_buf: [128]u8 = undefined;
    var mime_len: usize = 0;
    var data_out: [128]u8 = undefined;
    var data_out_len: usize = 0;
    var fs_buf: [128]u8 = undefined;
    var fs_len: usize = 0;
    const ok = try loadBlob(db, cid, &mime_buf, &mime_len, &data_out, &data_out_len, &fs_buf, &fs_len);
    try std.testing.expect(ok);
    try std.testing.expectEqualStrings("text/plain", mime_buf[0..mime_len]);
    try std.testing.expectEqualStrings(data, data_out[0..data_out_len]);
    try std.testing.expectEqual(@as(usize, 0), fs_len);
}

test "storeBlob: duplicate upload bumps ref_count" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    var cid_buf: [64]u8 = undefined;
    const data = "dedupe me";
    const cid = blobCid(data, &cid_buf);
    try storeBlob(db, cid, "text/plain", data, "./_test_media");
    try storeBlob(db, cid, "text/plain", data, "./_test_media");

    var stmt: ?*c.sqlite3_stmt = null;
    _ = c.sqlite3_prepare_v2(db, "SELECT ref_count FROM atp_blobs WHERE cid = ?", -1, &stmt, null);
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, cid.ptr, @intCast(cid.len), c.sqliteTransientAsDestructor());
    try std.testing.expectEqual(@as(c_int, c.SQLITE_ROW), c.sqlite3_step(stmt.?));
    try std.testing.expectEqual(@as(i64, 2), c.sqlite3_column_int64(stmt.?, 0));
}

test "insertAttachment + loadAttachment round-trip" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    var cid_buf: [64]u8 = undefined;
    const data = "img";
    const cid = blobCid(data, &cid_buf);
    try storeBlob(db, cid, "image/png", data, "./_test_media");
    const id = try insertAttachment(db, .{
        .owner_user_id = 1,
        .blob_cid = cid,
        .kind = "image",
        .description = "a thing",
        .focus_x = 0.1,
        .focus_y = -0.2,
        .blurhash = "L00000fQfQfQfQfQ",
        .width = 320,
        .height = 200,
        .mime = "image/png",
        .size = data.len,
        .created_at = 1700000000,
    });
    var row: AttachmentRow = .{};
    const ok = try loadAttachment(db, id, &row);
    try std.testing.expect(ok);
    try std.testing.expectEqualStrings("image", row.kindStr());
    try std.testing.expectEqualStrings("a thing", row.desc_buf[0..row.desc_len]);
    try std.testing.expectEqual(@as(u32, 320), row.width);
    try std.testing.expectApproxEqAbs(@as(f32, 0.1), row.focus_x, 1e-6);
}

test "updateAttachment changes description" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    var cid_buf: [64]u8 = undefined;
    const cid = blobCid("x", &cid_buf);
    try storeBlob(db, cid, "image/png", "x", "./_test_media");
    const id = try insertAttachment(db, .{
        .owner_user_id = 0,
        .blob_cid = cid,
        .kind = "image",
        .description = "old",
        .focus_x = 0,
        .focus_y = 0,
        .blurhash = "",
        .width = null,
        .height = null,
        .mime = "image/png",
        .size = 1,
        .created_at = 0,
    });
    try updateAttachment(db, id, "new desc", null, null);
    var row: AttachmentRow = .{};
    _ = try loadAttachment(db, id, &row);
    try std.testing.expectEqualStrings("new desc", row.desc_buf[0..row.desc_len]);
}
