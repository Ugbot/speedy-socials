//! Mastodon API app routes — verify_credentials.
//! POST /api/v1/apps is handled by `oauth.handleCreateApp`.

const std = @import("std");
const core = @import("core");
const HandlerContext = core.http.router.HandlerContext;

const state_mod = @import("../state.zig");
const auth = @import("../auth.zig");
const http_util = @import("../http_util.zig");
const db_mod = @import("../db.zig");
const serialize = @import("../serialize.zig");

pub fn handleVerifyAppCredentials(hc: *HandlerContext) anyerror!void {
    const st = state_mod.get();
    const claims = (try auth.requireScope(hc, "read")) orelse return;
    const db = st.db orelse return http_util.writeError(hc, .service_unavailable, "db not ready");

    // Look up the app by id. We don't store client_id on the token; we
    // store app_id (claims.app_id) and resolve from there.
    var stmt: ?*@import("sqlite").c.sqlite3_stmt = null;
    const c_sqlite = @import("sqlite").c;
    const sql = "SELECT name, COALESCE(website,''), client_id FROM mastodon_apps WHERE id = ?";
    if (c_sqlite.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c_sqlite.SQLITE_OK) {
        if (stmt != null) _ = c_sqlite.sqlite3_finalize(stmt);
        return http_util.writeError(hc, .not_found, "unknown app");
    }
    defer _ = c_sqlite.sqlite3_finalize(stmt);
    _ = c_sqlite.sqlite3_bind_int64(stmt, 1, claims.app_id);
    if (c_sqlite.sqlite3_step(stmt) != c_sqlite.SQLITE_ROW) {
        return http_util.writeError(hc, .not_found, "unknown app");
    }
    var name_buf: [128]u8 = undefined;
    var web_buf: [256]u8 = undefined;
    var cid_buf: [64]u8 = undefined;
    const np = c_sqlite.sqlite3_column_text(stmt, 0);
    const nn: usize = @intCast(c_sqlite.sqlite3_column_bytes(stmt, 0));
    const nlen = @min(nn, name_buf.len);
    if (np != null and nlen > 0) @memcpy(name_buf[0..nlen], np[0..nlen]);
    const wp = c_sqlite.sqlite3_column_text(stmt, 1);
    const wn: usize = @intCast(c_sqlite.sqlite3_column_bytes(stmt, 1));
    const wlen = @min(wn, web_buf.len);
    if (wp != null and wlen > 0) @memcpy(web_buf[0..wlen], wp[0..wlen]);
    const cp = c_sqlite.sqlite3_column_text(stmt, 2);
    const cn: usize = @intCast(c_sqlite.sqlite3_column_bytes(stmt, 2));
    const clen = @min(cn, cid_buf.len);
    if (cp != null and clen > 0) @memcpy(cid_buf[0..clen], cp[0..clen]);

    _ = db_mod.findAppByClientId; // touch to keep import used

    var out_buf: [1024]u8 = undefined;
    const out = std.fmt.bufPrint(&out_buf,
        "{{\"name\":\"{s}\",\"website\":\"{s}\",\"vapid_key\":\"\"}}",
        .{ name_buf[0..nlen], web_buf[0..wlen] },
    ) catch return http_util.writeError(hc, .internal, "buf");
    _ = serialize.writeAccount; // keep import alive even if unused
    try http_util.writeJsonBody(hc, .ok, out);
}
