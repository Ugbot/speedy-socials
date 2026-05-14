//! Mastodon API status routes.

const std = @import("std");
const core = @import("core");
const HandlerContext = core.http.router.HandlerContext;

const state_mod = @import("../state.zig");
const auth = @import("../auth.zig");
const http_util = @import("../http_util.zig");
const db_mod = @import("../db.zig");
const serialize = @import("../serialize.zig");

fn parseId(s: []const u8) i64 {
    var val: i64 = 0;
    var digits: u32 = 0;
    for (s) |ch| {
        if (ch < '0' or ch > '9') break;
        val = val * 10 + @as(i64, ch - '0');
        digits += 1;
    }
    if (digits == 0) return 0;
    return val;
}

pub fn handleCreateStatus(hc: *HandlerContext) anyerror!void {
    const st = state_mod.get();
    const claims = (try auth.requireScope(hc, "write")) orelse return;
    if (claims.user_id == 0) return http_util.writeError(hc, .forbidden, "client-only token");
    const db = st.db orelse return http_util.writeError(hc, .service_unavailable, "db not ready");

    const body = hc.request.body;
    const status_text = http_util.jsonString(body, "status") orelse
        http_util.formField(body, "status") orelse {
        return http_util.writeError(hc, .bad_request, "status required");
    };
    const user = db_mod.findUserById(db, claims.user_id) orelse return http_util.writeError(hc, .not_found, "user gone");
    const now = st.clock.wallUnix();
    var ap_id_buf: [256]u8 = undefined;
    const ap_id = std.fmt.bufPrint(&ap_id_buf, "https://{s}/@{s}/{d}", .{ st.hostname(), user.username(), now }) catch return http_util.writeError(hc, .internal, "uri");
    const status_id = db_mod.insertStatus(db, user.id, ap_id, status_text, now) catch {
        return http_util.writeError(hc, .internal, "insert failed");
    };

    try writeStatusJson(hc, st, db, status_id, user, status_text, now);
}

pub fn handleGetStatus(hc: *HandlerContext) anyerror!void {
    const st = state_mod.get();
    const db = st.db orelse return http_util.writeError(hc, .service_unavailable, "db not ready");
    const id_str = hc.params.get("id") orelse return http_util.writeError(hc, .bad_request, "id required");
    const id = parseId(id_str);
    const row = db_mod.findStatusById(db, id) orelse return http_util.writeError(hc, .not_found, "unknown status");
    const author = db_mod.findUserById(db, row.actor_id) orelse return http_util.writeError(hc, .not_found, "author gone");
    try writeStatusJson(hc, st, db, row.id, author, row.content(), row.published);
}

pub fn handleDeleteStatus(hc: *HandlerContext) anyerror!void {
    const st = state_mod.get();
    const claims = (try auth.requireScope(hc, "write")) orelse return;
    if (claims.user_id == 0) return http_util.writeError(hc, .forbidden, "client-only token");
    const db = st.db orelse return http_util.writeError(hc, .service_unavailable, "db not ready");
    const id_str = hc.params.get("id") orelse return http_util.writeError(hc, .bad_request, "id required");
    const id = parseId(id_str);
    const deleted = db_mod.deleteStatus(db, id, claims.user_id) catch false;
    if (!deleted) return http_util.writeError(hc, .not_found, "unknown status");
    try http_util.writeJsonBody(hc, .ok, "{}");
}

pub fn handleFavourite(hc: *HandlerContext) anyerror!void {
    try favouriteToggle(hc, true);
}
pub fn handleUnfavourite(hc: *HandlerContext) anyerror!void {
    try favouriteToggle(hc, false);
}

fn favouriteToggle(hc: *HandlerContext, favourite: bool) !void {
    const st = state_mod.get();
    const claims = (try auth.requireScope(hc, "write")) orelse return;
    if (claims.user_id == 0) return http_util.writeError(hc, .forbidden, "client-only token");
    const db = st.db orelse return http_util.writeError(hc, .service_unavailable, "db not ready");
    const id_str = hc.params.get("id") orelse return http_util.writeError(hc, .bad_request, "id required");
    const id = parseId(id_str);
    if (favourite) {
        db_mod.addFavourite(db, id, claims.user_id, st.clock.wallUnix()) catch {};
    } else {
        db_mod.removeFavourite(db, id, claims.user_id) catch {};
    }
    const row = db_mod.findStatusById(db, id) orelse return http_util.writeError(hc, .not_found, "unknown status");
    const author = db_mod.findUserById(db, row.actor_id) orelse return http_util.writeError(hc, .not_found, "author gone");
    try writeStatusJson(hc, st, db, row.id, author, row.content(), row.published);
}

pub fn handleReblog(hc: *HandlerContext) anyerror!void {
    try reblogToggle(hc, true);
}
pub fn handleUnreblog(hc: *HandlerContext) anyerror!void {
    try reblogToggle(hc, false);
}

fn reblogToggle(hc: *HandlerContext, reblog: bool) !void {
    const st = state_mod.get();
    const claims = (try auth.requireScope(hc, "write")) orelse return;
    if (claims.user_id == 0) return http_util.writeError(hc, .forbidden, "client-only token");
    const db = st.db orelse return http_util.writeError(hc, .service_unavailable, "db not ready");
    const id_str = hc.params.get("id") orelse return http_util.writeError(hc, .bad_request, "id required");
    const id = parseId(id_str);
    if (reblog) {
        db_mod.addReblog(db, id, claims.user_id, st.clock.wallUnix()) catch {};
    } else {
        db_mod.removeReblog(db, id, claims.user_id) catch {};
    }
    const row = db_mod.findStatusById(db, id) orelse return http_util.writeError(hc, .not_found, "unknown status");
    const author = db_mod.findUserById(db, row.actor_id) orelse return http_util.writeError(hc, .not_found, "author gone");
    try writeStatusJson(hc, st, db, row.id, author, row.content(), row.published);
}

pub fn writeStatusJson(hc: *HandlerContext, st: *state_mod.State, db: *@import("sqlite").c.sqlite3, status_id: i64, author: db_mod.UserRow, content: []const u8, published_unix: i64) !void {
    var author_iso_buf: [32]u8 = undefined;
    const author_iso = serialize.formatIsoTimestamp(author.created_at, &author_iso_buf) catch "1970-01-01T00:00:00Z";
    var status_iso_buf: [32]u8 = undefined;
    const status_iso = serialize.formatIsoTimestamp(published_unix, &status_iso_buf) catch "1970-01-01T00:00:00Z";

    var out_buf: [8192]u8 = undefined;
    const out = serialize.writeStatus(.{
        .id = status_id,
        .created_at_iso = status_iso,
        .content_html = content,
        .favourites_count = db_mod.countFavourites(db, status_id),
        .reblogs_count = db_mod.countReblogs(db, status_id),
        .account = .{
            .id = author.id,
            .username = author.username(),
            .acct = author.username(),
            .display_name = author.displayName(),
            .note = author.bio(),
            .hostname = st.hostname(),
            .created_at_iso = author_iso,
        },
    }, &out_buf) catch return http_util.writeError(hc, .internal, "status buf");
    try http_util.writeJsonBody(hc, .ok, out);
}
