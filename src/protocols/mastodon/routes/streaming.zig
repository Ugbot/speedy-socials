//! Mastodon streaming routes — HTTP fall-through.
//!
//! W2.1: real-time streaming is implemented as a WebSocket upgrade
//! (see `routes/streaming_ws.zig`). The server's accept loop dispatches
//! `Upgrade: websocket` requests to the upgrade router *before* this
//! HTTP handler runs, so this handler only sees plain (non-upgrade)
//! GETs — those receive a JSON 400 telling the client to upgrade.

const std = @import("std");
const core = @import("core");
const HandlerContext = core.http.router.HandlerContext;
const http_util = @import("../http_util.zig");

fn writeUpgradeRequired(hc: *HandlerContext) !void {
    try hc.response.startStatus(.bad_request);
    try hc.response.header("Content-Type", "application/json; charset=utf-8");
    const body = "{\"error\":\"streaming requires a WebSocket Upgrade (RFC 6455)\"}";
    try hc.response.headerFmt("Content-Length", "{d}", .{body.len});
    try hc.response.header("Connection", "close");
    try hc.response.finishHeaders();
    try hc.response.body(body);
}

pub fn handleUser(hc: *HandlerContext) anyerror!void {
    try writeUpgradeRequired(hc);
}
pub fn handlePublic(hc: *HandlerContext) anyerror!void {
    try writeUpgradeRequired(hc);
}
pub fn handleHashtag(hc: *HandlerContext) anyerror!void {
    try writeUpgradeRequired(hc);
}
pub fn handleList(hc: *HandlerContext) anyerror!void {
    try writeUpgradeRequired(hc);
}
