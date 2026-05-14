//! Mastodon API instance metadata routes.

const std = @import("std");
const core = @import("core");
const HandlerContext = core.http.router.HandlerContext;

const state_mod = @import("../state.zig");
const http_util = @import("../http_util.zig");
const db_mod = @import("../db.zig");
const serialize = @import("../serialize.zig");

pub fn handleInstance(hc: *HandlerContext) anyerror!void {
    const st = state_mod.get();
    const users: i64 = if (st.db) |db| db_mod.countUsers(db) else 0;
    const statuses: i64 = if (st.db) |db| db_mod.countStatuses(db) else 0;
    var buf: [4096]u8 = undefined;
    const out = serialize.writeInstance(.{
        .hostname = st.hostname(),
        .user_count = users,
        .status_count = statuses,
        .domain_count = 1,
    }, &buf) catch return http_util.writeError(hc, .internal, "instance buf");
    try http_util.writeJsonBody(hc, .ok, out);
}

pub fn handleInstancePeers(hc: *HandlerContext) anyerror!void {
    // No peer cache yet. Return an empty array.
    try http_util.writeJsonBody(hc, .ok, "[]");
}

pub fn handleInstanceActivity(hc: *HandlerContext) anyerror!void {
    // Weekly activity stats. Return an empty array — clients fall back
    // to the values in /instance.
    try http_util.writeJsonBody(hc, .ok, "[]");
}
