//! Mastodon API notifications routes.

const std = @import("std");
const core = @import("core");
const HandlerContext = core.http.router.HandlerContext;

const state_mod = @import("../state.zig");
const auth = @import("../auth.zig");
const http_util = @import("../http_util.zig");
const db_mod = @import("../db.zig");
const serialize = @import("../serialize.zig");

pub fn handleList(hc: *HandlerContext) anyerror!void {
    const st = state_mod.get();
    const claims = (try auth.requireScope(hc, "read")) orelse return;
    if (claims.user_id == 0) return http_util.writeError(hc, .forbidden, "client-only token");
    const db = st.db orelse return http_util.writeError(hc, .service_unavailable, "db not ready");

    var iter = db_mod.queryNotifications(db, claims.user_id, 40);
    defer iter.deinit();

    var out_buf: [16 * 1024]u8 = undefined;
    var pos: usize = 0;
    out_buf[pos] = '[';
    pos += 1;
    var first = true;
    var row: db_mod.NotificationRow = .{};
    while (iter.next(&row)) {
        if (!first) {
            out_buf[pos] = ',';
            pos += 1;
        }
        first = false;
        var iso_buf: [32]u8 = undefined;
        const iso = serialize.formatIsoTimestamp(row.created_at, &iso_buf) catch "1970-01-01T00:00:00Z";
        const w = serialize.writeNotification(.{
            .id = row.id,
            .type = row.typeStr(),
            .created_at_iso = iso,
            .account_acct = row.fromAccount(),
            .hostname = st.hostname(),
            .status_id = row.status_id,
        }, out_buf[pos..]) catch return http_util.writeError(hc, .internal, "buf");
        pos += w.len;
    }
    if (pos >= out_buf.len) return http_util.writeError(hc, .internal, "buf full");
    out_buf[pos] = ']';
    pos += 1;
    try http_util.writeJsonBody(hc, .ok, out_buf[0..pos]);
}

pub fn handleClear(hc: *HandlerContext) anyerror!void {
    const st = state_mod.get();
    const claims = (try auth.requireScope(hc, "write")) orelse return;
    if (claims.user_id == 0) return http_util.writeError(hc, .forbidden, "client-only token");
    const db = st.db orelse return http_util.writeError(hc, .service_unavailable, "db not ready");
    db_mod.clearNotifications(db, claims.user_id) catch {};
    try http_util.writeJsonBody(hc, .ok, "{}");
}
