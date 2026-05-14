//! Mastodon streaming routes.
//!
//! WebSocket upgrade plumbing lands in W1.1 (`register_ws_upgrade` on the
//! Plugin contract + server-side hand-off). Until that merges these
//! handlers return 501 and a `Sec-WebSocket-Plumbing-Pending` header so
//! a curl probe can tell the difference between "endpoint missing" and
//! "endpoint exists but transport not wired".
//!
//! Wiring sketch (paste this into a follow-up diff once W1.1 lands):
//!
//!   1. The plugin's `register_ws_upgrade` hook subscribes "/api/v1/streaming"
//!      to a per-stream `EventRing` (one ring per stream type).
//!   2. On `POST /api/v1/statuses` (statuses.zig) we publish the new
//!      Status JSON onto the public + user rings.
//!   3. The streaming handler reads the ring's tail position from a
//!      query/header and forwards frames over the upgraded socket.
//!
//! For now the route exists so clients receive a clear 501.

const std = @import("std");
const core = @import("core");
const HandlerContext = core.http.router.HandlerContext;
const http_util = @import("../http_util.zig");

fn writeUnimplemented(hc: *HandlerContext) !void {
    try hc.response.startStatus(.not_implemented);
    try hc.response.header("Content-Type", "application/json; charset=utf-8");
    try hc.response.header("Sec-WebSocket-Plumbing-Pending", "W1.1");
    const body = "{\"error\":\"streaming requires WS upgrade plumbing landed in W1.1\"}";
    try hc.response.headerFmt("Content-Length", "{d}", .{body.len});
    try hc.response.header("Connection", "close");
    try hc.response.finishHeaders();
    try hc.response.body(body);
}

pub fn handleUser(hc: *HandlerContext) anyerror!void {
    try writeUnimplemented(hc);
}
pub fn handlePublic(hc: *HandlerContext) anyerror!void {
    try writeUnimplemented(hc);
}
pub fn handleHashtag(hc: *HandlerContext) anyerror!void {
    try writeUnimplemented(hc);
}
pub fn handleList(hc: *HandlerContext) anyerror!void {
    try writeUnimplemented(hc);
}
