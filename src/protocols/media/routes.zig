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
const response_stream = core.http.response_stream;
const limits = core.limits;

/// Bounded chunk buffer for streaming filesystem blobs out as HTTP/1.1
/// chunked transfer encoding. Tiger Style: a single fixed-size read window
/// — no per-request heap, no full-file buffer. The whole blob is moved
/// through this 64 KiB window regardless of its size on disk.
const blob_stream_chunk_bytes: usize = 64 * 1024;

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
    const db = st.dbHandle() orelse return writeError(hc, .service_unavailable, "ServiceUnavailable", "db not ready");

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
    const db = st.dbHandle() orelse return writeError(hc, .service_unavailable, "ServiceUnavailable", "db not ready");
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
    const db = st.dbHandle() orelse return writeError(hc, .service_unavailable, "ServiceUnavailable", "db not ready");
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
    const db = st.dbHandle() orelse return writeError(hc, .service_unavailable, "ServiceUnavailable", "db not ready");
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

    const mime = if (mime_len > 0) mime_buf[0..mime_len] else "application/octet-stream";

    if (fs_path_len > 0) {
        // Filesystem spillover (W5.5). The `fs:<cid>` marker in the db row
        // points at `<media_root>/<cid>` on disk. These blobs are, by
        // construction, larger than `media_inline_threshold_bytes` (1 MiB)
        // — bigger than the fixed `conn.write_buf` — so they cannot be
        // buffered into a single `Builder` body. Stream them out as
        // HTTP/1.1 chunked transfer encoding through the socket sink,
        // moving the file through a bounded 64 KiB window. No full-file
        // buffer, no heap.
        const sink = hc.sink orelse return writeError(hc, .internal, "InternalError", "no response sink");
        const path = fs_path_buf[0..fs_path_len];
        streamBlobFileChunked(sink, st.media_root, path, mime) catch {
            // The handler may have already pushed the chunked head and
            // some frames before the read failed mid-file; mark the
            // response streamed so the server tears the connection down
            // (truncated body) rather than emitting a fresh 500 that would
            // corrupt the framing. If nothing has been written yet this
            // still yields a closed connection, which clients treat as a
            // failed transfer.
            hc.streamed = true;
            return;
        };
        hc.streamed = true;
        return;
    }

    try hc.response.startStatus(.ok);
    try hc.response.header("Content-Type", mime);
    try hc.response.headerFmt("Content-Length", "{d}", .{data_len});
    try hc.response.header("Cache-Control", "public, max-age=31536000, immutable");
    try hc.response.header("Connection", "close");
    try hc.response.finishHeaders();
    try hc.response.body(data_buf[0..data_len]);
}

/// Read `<media_root>/<cid>` into `out`. Returns the number of bytes
/// read. Errors if the file is larger than `out.len`.
fn readBlobFileInto(media_root: []const u8, cid: []const u8, out: []u8) !usize {
    var path_buf: [512]u8 = undefined;
    const path_z = try blobFilePath(media_root, cid, &path_buf);

    const fd = std.c.open(path_z, .{ .ACCMODE = .RDONLY }, @as(std.c.mode_t, 0));
    if (fd < 0) return error.StepFailed;
    defer _ = std.c.close(fd);

    var total: usize = 0;
    while (total < out.len) {
        const want = out.len - total;
        const got = std.c.read(fd, out.ptr + total, want);
        if (got < 0) return error.StepFailed;
        if (got == 0) break;
        total += @intCast(got);
    }
    return total;
}

/// Build the on-disk path `<media_root>/<cid>` (NUL-terminated) into
/// `path_buf`. Returns the C string pointer. Errors if it would overflow.
fn blobFilePath(media_root: []const u8, cid: []const u8, path_buf: []u8) ![*:0]const u8 {
    if (media_root.len + 1 + cid.len + 1 > path_buf.len) return error.PayloadTooLarge;
    var n: usize = 0;
    @memcpy(path_buf[n..][0..media_root.len], media_root);
    n += media_root.len;
    path_buf[n] = '/';
    n += 1;
    @memcpy(path_buf[n..][0..cid.len], cid);
    n += cid.len;
    path_buf[n] = 0;
    return @ptrCast(path_buf.ptr);
}

/// Stream `<media_root>/<cid>` to `sink` as an HTTP/1.1 chunked-transfer
/// response. The file is moved through a fixed 64 KiB window — no full
/// buffer, no heap, regardless of file size. Each read becomes one chunk
/// frame (`<hex-len>\r\n<bytes>\r\n`); a terminating zero-length chunk
/// closes the body. Errors propagate (the caller tears the connection
/// down); a partial write before the error truncates the transfer.
fn streamBlobFileChunked(
    sink: core.http.router.BodySink,
    media_root: []const u8,
    cid: []const u8,
    mime: []const u8,
) !void {
    var path_buf: [512]u8 = undefined;
    const path_z = try blobFilePath(media_root, cid, &path_buf);

    const fd = std.c.open(path_z, .{ .ACCMODE = .RDONLY }, @as(std.c.mode_t, 0));
    if (fd < 0) return error.StepFailed;
    defer _ = std.c.close(fd);

    // Emit the response head (status + headers + blank line) first.
    var head_buf: [256]u8 = undefined;
    const head_len = try response_stream.writeChunkedHead(
        &head_buf,
        .ok,
        mime,
        "public, max-age=31536000, immutable",
    );
    try sink.writeAll(head_buf[0..head_len]);

    // The frame buffer holds one 64 KiB read plus chunked framing overhead
    // (hex length + CRLFs). `writeChunkFrame` requires payload + 16 + 4.
    var read_buf: [blob_stream_chunk_bytes]u8 = undefined;
    var frame_buf: [blob_stream_chunk_bytes + 32]u8 = undefined;
    while (true) {
        const got = std.c.read(fd, &read_buf, read_buf.len);
        if (got < 0) return error.StepFailed;
        if (got == 0) break;
        const n: usize = @intCast(got);
        const frame_len = try response_stream.writeChunkFrame(&frame_buf, read_buf[0..n]);
        try sink.writeAll(frame_buf[0..frame_len]);
    }

    // Terminating zero-length chunk ends the body.
    var end_buf: [8]u8 = undefined;
    const end_len = try response_stream.writeChunkedEnd(&end_buf);
    try sink.writeAll(end_buf[0..end_len]);
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
    // W5.5: large blobs spill to disk under `media_root/<cid>`. The
    // db row stores `data = "fs:<cid>"` — the same prefix convention
    // `loadBlob` already understands. When no media_root is wired,
    // oversize uploads still fail loud with PayloadTooLarge (the
    // request path normally catches them earlier on body-size).
    var fs_marker_buf: [3 + 256]u8 = undefined;
    var stored_slice: []const u8 = data;
    if (data.len > limits.media_inline_threshold_bytes) {
        if (media_root.len == 0) return error.PayloadTooLarge;
        if (cid.len > 256) return error.PayloadTooLarge;
        try writeBlobFile(media_root, cid, data);
        @memcpy(fs_marker_buf[0..3], "fs:");
        @memcpy(fs_marker_buf[3..][0..cid.len], cid);
        stored_slice = fs_marker_buf[0 .. 3 + cid.len];
    }

    var ins: ?*c.sqlite3_stmt = null;
    const ins_sql = "INSERT INTO atp_blobs(cid, did, mime, size, ref_count, data, created_at) VALUES (?, ?, ?, ?, 1, ?, ?)";
    if (c.sqlite3_prepare_v2(db, ins_sql, -1, &ins, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(ins);
    _ = c.sqlite3_bind_text(ins, 1, cid.ptr, @intCast(cid.len), c.sqliteTransientAsDestructor());
    const did_placeholder: []const u8 = "did:plc:media";
    _ = c.sqlite3_bind_text(ins, 2, did_placeholder.ptr, @intCast(did_placeholder.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(ins, 3, mime.ptr, @intCast(mime.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(ins, 4, @intCast(data.len));
    _ = c.sqlite3_bind_blob(ins, 5, stored_slice.ptr, @intCast(stored_slice.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(ins, 6, created_at);
    if (c.sqlite3_step(ins.?) != c.SQLITE_DONE) return error.StepFailed;
}

/// Write `data` to `<media_root>/<cid>` using POSIX `open`/`write`/`close`
/// directly. Zig 0.16's `std.Io.Dir` needs an `Io` handle threaded
/// from the composition root; the plugin Context does not carry one
/// today. The `media_root` directory is created at boot by
/// `app/main.zig` (via `mkdir` of the env-supplied path); we assume
/// it exists.
fn writeBlobFile(media_root: []const u8, cid: []const u8, data: []const u8) !void {
    var path_buf: [512]u8 = undefined;
    if (media_root.len + 1 + cid.len + 1 > path_buf.len) return error.PayloadTooLarge;
    var n: usize = 0;
    @memcpy(path_buf[n..][0..media_root.len], media_root);
    n += media_root.len;
    path_buf[n] = '/';
    n += 1;
    @memcpy(path_buf[n..][0..cid.len], cid);
    n += cid.len;
    path_buf[n] = 0;
    const path_z: [*:0]const u8 = @ptrCast(&path_buf);

    const fd = std.c.open(path_z, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, @as(std.c.mode_t, 0o644));
    if (fd < 0) return error.StepFailed;
    defer _ = std.c.close(fd);
    var written: usize = 0;
    while (written < data.len) {
        const want = data.len - written;
        const w = std.c.write(fd, data.ptr + written, want);
        if (w < 0) return error.StepFailed;
        written += @intCast(w);
        if (w == 0) return error.StepFailed;
    }
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

test "storeBlobAt: oversize payload spills to media_root and reads back" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);

    // Create a unique scratch dir for this test run.
    const dir_path = "./_test_media_spillover";
    _ = std.c.mkdir(dir_path, @as(std.c.mode_t, 0o755));

    // Payload deliberately bigger than the inline cap.
    const big_len = limits.media_inline_threshold_bytes + 12_345;
    const big = try std.testing.allocator.alloc(u8, big_len);
    defer std.testing.allocator.free(big);
    for (big, 0..) |*b, i| b.* = @intCast(i & 0xff);

    var cid_buf: [64]u8 = undefined;
    const cid = blobCid(big, &cid_buf);
    try storeBlobAt(db, cid, "application/octet-stream", big, dir_path, 12345);

    // Verify the db row carries the `fs:<cid>` marker.
    var mime_buf: [128]u8 = undefined;
    var mime_len: usize = 0;
    var data_out: [16]u8 = undefined; // intentionally tiny — we expect zero inline bytes
    var data_out_len: usize = 0;
    var fs_buf: [256]u8 = undefined;
    var fs_len: usize = 0;
    const ok = try loadBlob(db, cid, &mime_buf, &mime_len, &data_out, &data_out_len, &fs_buf, &fs_len);
    try std.testing.expect(ok);
    try std.testing.expectEqualStrings("application/octet-stream", mime_buf[0..mime_len]);
    try std.testing.expectEqual(@as(usize, 0), data_out_len);
    try std.testing.expectEqualStrings(cid, fs_buf[0..fs_len]);

    // Read the file back through the same helper the GET handler uses
    // and check byte-for-byte equality.
    const echo = try std.testing.allocator.alloc(u8, big_len + 8);
    defer std.testing.allocator.free(echo);
    const got = try readBlobFileInto(dir_path, fs_buf[0..fs_len], echo);
    try std.testing.expectEqual(big_len, got);
    try std.testing.expectEqualSlices(u8, big, echo[0..got]);

    // Cleanup: unlink the blob + rmdir.
    var path_buf: [512]u8 = undefined;
    const path_n = std.fmt.bufPrintZ(&path_buf, "{s}/{s}", .{ dir_path, cid }) catch unreachable;
    _ = std.c.unlink(path_n.ptr);
    _ = std.c.rmdir(dir_path);
}

// Capturing BodySink for tests: appends every write into a fixed buffer
// so we can inspect the full chunked response a handler emits. Sized for
// the test blob plus chunked framing overhead; overflow fails the write.
const CaptureSink = struct {
    buf: [512 * 1024]u8 = undefined,
    len: usize = 0,

    fn writeAll(ptr: *anyopaque, bytes: []const u8) core.http.router.BodySink.Error!void {
        const self: *CaptureSink = @ptrCast(@alignCast(ptr));
        if (self.len + bytes.len > self.buf.len) return error.WriteFailed;
        @memcpy(self.buf[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    fn sink(self: *CaptureSink) core.http.router.BodySink {
        return .{ .ctx = self, .writeAllFn = CaptureSink.writeAll };
    }

    fn wire(self: *const CaptureSink) []const u8 {
        return self.buf[0..self.len];
    }
};

// Decode an HTTP/1.1 chunked transfer body (the part after the head's
// blank line) into `out`. Returns the decoded byte count.
fn dechunk(body: []const u8, out: []u8) !usize {
    var i: usize = 0;
    var w: usize = 0;
    while (i < body.len) {
        // Parse the hex chunk-size line.
        const line_end = std.mem.indexOfPos(u8, body, i, "\r\n") orelse return error.BadChunk;
        const size = try std.fmt.parseInt(usize, body[i..line_end], 16);
        i = line_end + 2;
        if (size == 0) break; // terminator
        if (i + size + 2 > body.len) return error.BadChunk;
        if (w + size > out.len) return error.BadChunk;
        @memcpy(out[w .. w + size], body[i .. i + size]);
        w += size;
        i += size;
        // Trailing CRLF after the chunk data.
        if (body[i] != '\r' or body[i + 1] != '\n') return error.BadChunk;
        i += 2;
    }
    return w;
}

test "streamBlobFileChunked: large blob round-trips through chunked encoding" {
    const dir_path = "./_test_media_chunked";
    _ = std.c.mkdir(dir_path, @as(std.c.mode_t, 0o755));

    // A blob deliberately larger than the 64 KiB streaming window, with a
    // non-multiple size so the final chunk is partial. Bytes are random
    // (seeded off the wall clock so runs differ) — not a hardcoded pattern.
    const blob_len = blob_stream_chunk_bytes * 2 + 7_777;
    const src = try std.testing.allocator.alloc(u8, blob_len);
    defer std.testing.allocator.free(src);
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(std.c.CLOCK.REALTIME, &ts);
    const seed: u64 = @bitCast(@as(i64, ts.sec) *% 1_000_000_000 +% @as(i64, ts.nsec));
    var prng = std.Random.DefaultPrng.init(seed);
    prng.random().bytes(src);

    var cid_buf: [64]u8 = undefined;
    const cid = blobCid(src, &cid_buf);
    try writeBlobFile(dir_path, cid, src);

    // Stream it out through a capturing sink. Heap-box the sink so the
    // 512 KiB capture buffer doesn't blow the test's stack frame.
    const cap = try std.testing.allocator.create(CaptureSink);
    defer std.testing.allocator.destroy(cap);
    cap.* = .{};
    try streamBlobFileChunked(cap.sink(), dir_path, cid, "image/png");

    const wire = cap.wire();

    // Head: status, chunked encoding, content-type, immutable cache.
    const head_end = std.mem.indexOf(u8, wire, "\r\n\r\n").? + 4;
    const head = wire[0..head_end];
    try std.testing.expect(std.mem.startsWith(u8, head, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, head, "Transfer-Encoding: chunked\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, head, "Content-Type: image/png\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, head, "Cache-Control: public, max-age=31536000, immutable\r\n") != null);

    // Body: dechunk and compare byte-for-byte with the source blob.
    const decoded = try std.testing.allocator.alloc(u8, blob_len);
    defer std.testing.allocator.free(decoded);
    const n = try dechunk(wire[head_end..], decoded);
    try std.testing.expectEqual(blob_len, n);
    try std.testing.expectEqualSlices(u8, src, decoded[0..n]);

    // The wire must end with the terminating zero-length chunk.
    try std.testing.expect(std.mem.endsWith(u8, wire, "0\r\n\r\n"));

    // Cleanup.
    var path_buf: [512]u8 = undefined;
    const path_n = std.fmt.bufPrintZ(&path_buf, "{s}/{s}", .{ dir_path, cid }) catch unreachable;
    _ = std.c.unlink(path_n.ptr);
    _ = std.c.rmdir(dir_path);
}

test "storeBlobAt: oversize without media_root still rejects with PayloadTooLarge" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    const big_len = limits.media_inline_threshold_bytes + 1;
    const big = try std.testing.allocator.alloc(u8, big_len);
    defer std.testing.allocator.free(big);
    @memset(big, 'x');
    var cid_buf: [64]u8 = undefined;
    const cid = blobCid(big, &cid_buf);
    try std.testing.expectError(error.PayloadTooLarge, storeBlobAt(db, cid, "x/y", big, "", 0));
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
