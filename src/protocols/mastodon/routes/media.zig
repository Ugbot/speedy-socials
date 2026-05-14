//! Mastodon media routes.
//!
//! Stubbed at 501 — uploads, thumbnails, and blurhash live in the
//! W1.4 media plugin. When that lands, this file becomes a thin
//! delegation to `protocol_media.handleUpload`. See the FEATURE_TODO
//! W1.4 entry.

const std = @import("std");
const core = @import("core");
const HandlerContext = core.http.router.HandlerContext;
const http_util = @import("../http_util.zig");

pub fn handleUploadV1(hc: *HandlerContext) anyerror!void {
    try http_util.writeError(hc, .not_implemented, "media uploads land in W1.4 media plugin");
}

pub fn handleUploadV2(hc: *HandlerContext) anyerror!void {
    try http_util.writeError(hc, .not_implemented, "media uploads land in W1.4 media plugin");
}
