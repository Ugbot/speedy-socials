//! Mastodon media routes — thin wrappers over the media plugin.
//!
//! The actual storage, content-addressing, blurhash and DB writes all
//! live in `protocol_media.api`. We only do the Mastodon-shape
//! envelope here: parse the multipart, hand the file part to the media
//! plugin, format the Mastodon `MediaAttachment` JSON.

const std = @import("std");
const core = @import("core");
const media = @import("protocol_media");

const HandlerContext = core.http.router.HandlerContext;
const Status = core.http.response.Status;
const limits = core.limits;

const http_util = @import("../http_util.zig");

fn parseFocus(s: []const u8, x: *f32, y: *f32) void {
    const comma = std.mem.indexOfScalar(u8, s, ',') orelse return;
    x.* = std.fmt.parseFloat(f32, s[0..comma]) catch return;
    y.* = std.fmt.parseFloat(f32, s[comma + 1 ..]) catch return;
}

fn writeAttachment(hc: *HandlerContext, stored: *const media.api.StoredAttachment) !void {
    const base_url = media.state.get().base_url;
    var url_buf: [256]u8 = undefined;
    const url = if (base_url.len > 0)
        std.fmt.bufPrint(&url_buf, "{s}/blobs/{s}", .{ base_url, stored.cidStr() }) catch return http_util.writeError(hc, .internal, "url buf")
    else
        std.fmt.bufPrint(&url_buf, "/blobs/{s}", .{stored.cidStr()}) catch return http_util.writeError(hc, .internal, "url buf");

    const w = stored.width orelse 0;
    const h = stored.height orelse 0;
    const aspect: f64 = if (h == 0) 0 else @as(f64, @floatFromInt(w)) / @as(f64, @floatFromInt(h));

    var resp: [2048]u8 = undefined;
    const body = std.fmt.bufPrint(&resp,
        "{{\"id\":\"{d}\",\"type\":\"{s}\",\"url\":\"{s}\",\"preview_url\":\"{s}\",\"remote_url\":null," ++
        "\"text_url\":null,\"meta\":{{\"original\":{{\"width\":{d},\"height\":{d},\"size\":\"{d}x{d}\",\"aspect\":{d:.3}}}}}," ++
        "\"description\":\"{s}\",\"blurhash\":\"{s}\",\"focus\":{{\"x\":{d:.3},\"y\":{d:.3}}}}}",
        .{
            stored.id, stored.kindStr(), url, url,
            w, h, w, h, aspect,
            stored.descriptionStr(), stored.blurhashStr(),
            stored.focus_x, stored.focus_y,
        },
    ) catch return http_util.writeError(hc, .internal, "format failed");
    try http_util.writeJsonBody(hc, .ok, body);
}

fn doUpload(hc: *HandlerContext) anyerror!void {
    if (hc.request.body.len > limits.max_upload_bytes) {
        return http_util.writeError(hc, .payload_too_large, "upload exceeds limit");
    }
    const ct = hc.request.header("Content-Type") orelse {
        return http_util.writeError(hc, .bad_request, "missing Content-Type");
    };
    if (std.mem.indexOf(u8, ct, "multipart/form-data") == null) {
        return http_util.writeError(hc, .bad_request, "expected multipart/form-data");
    }
    const boundary = media.multipart.parseBoundary(ct) catch {
        return http_util.writeError(hc, .bad_request, "bad boundary");
    };

    var parts: [limits.max_multipart_parts]media.multipart.Part = undefined;
    const count = media.multipart.parseAll(hc.request.body, boundary, &parts) catch |err| switch (err) {
        error.PayloadTooLarge => return http_util.writeError(hc, .payload_too_large, "part too large"),
        error.TooManyParts, error.TooManyHeaders => return http_util.writeError(hc, .bad_request, "too many parts"),
        else => return http_util.writeError(hc, .bad_request, "malformed multipart"),
    };

    var file_part: ?*const media.multipart.Part = null;
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
    const file = file_part orelse return http_util.writeError(hc, .bad_request, "missing file");

    // Mastodon OAuth is wired (W1.3) but route-side owner extraction is
    // a separate ticket — supply 0 until the bearer-to-user-id resolver
    // lands. Storage is unaffected; blob content-addresses identically.
    const owner_user_id: i64 = 0;

    var stored: media.api.StoredAttachment = .{ .id = 0 };
    media.api.storeUpload(owner_user_id, file, description, focus_x, focus_y, &stored) catch |err| switch (err) {
        error.DbNotReady => return http_util.writeError(hc, .service_unavailable, "db not ready"),
        error.PayloadTooLarge => return http_util.writeError(hc, .payload_too_large, "blob too large"),
        else => return http_util.writeError(hc, .internal, "store failed"),
    };

    try writeAttachment(hc, &stored);
}

pub fn handleUploadV1(hc: *HandlerContext) anyerror!void {
    return doUpload(hc);
}

pub fn handleUploadV2(hc: *HandlerContext) anyerror!void {
    return doUpload(hc);
}
