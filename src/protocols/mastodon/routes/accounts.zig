//! Mastodon API account routes.

const std = @import("std");
const core = @import("core");
const HandlerContext = core.http.router.HandlerContext;

const state_mod = @import("../state.zig");
const auth = @import("../auth.zig");
const http_util = @import("../http_util.zig");
const db_mod = @import("../db.zig");
const serialize = @import("../serialize.zig");

fn parseId(s: []const u8) i64 {
    var i: usize = 0;
    var val: i64 = 0;
    var digits: u32 = 0;
    while (i < s.len and s[i] >= '0' and s[i] <= '9') : (i += 1) {
        val = val * 10 + @as(i64, s[i] - '0');
        digits += 1;
    }
    if (digits == 0) return 0;
    return val;
}

fn writeAccountForUser(hc: *HandlerContext, st: *state_mod.State, u: db_mod.UserRow) !void {
    var iso_buf: [32]u8 = undefined;
    const iso = serialize.formatIsoTimestamp(u.created_at, &iso_buf) catch "1970-01-01T00:00:00Z";

    const db = st.db.?;
    var acct_uri_buf: [256]u8 = undefined;
    const acct_uri = std.fmt.bufPrint(&acct_uri_buf, "https://{s}/users/{s}", .{ st.hostname(), u.username() }) catch return http_util.writeError(hc, .internal, "uri buf");

    var out_buf: [4096]u8 = undefined;
    const out = serialize.writeAccount(.{
        .id = u.id,
        .username = u.username(),
        .acct = u.username(),
        .display_name = u.displayName(),
        .note = u.bio(),
        .hostname = st.hostname(),
        .created_at_iso = iso,
        .followers_count = db_mod.countFollows(db, "followee", acct_uri),
        .following_count = db_mod.countFollows(db, "follower", acct_uri),
        .locked = u.is_locked,
    }, &out_buf) catch return http_util.writeError(hc, .internal, "account buf");
    try http_util.writeJsonBody(hc, .ok, out);
}

pub fn handleGetAccount(hc: *HandlerContext) anyerror!void {
    const st = state_mod.get();
    const db = st.db orelse return http_util.writeError(hc, .service_unavailable, "db not ready");
    const id_str = hc.params.get("id") orelse return http_util.writeError(hc, .bad_request, "id required");
    const id = parseId(id_str);
    if (id == 0) return http_util.writeError(hc, .not_found, "unknown account");
    const u = db_mod.findUserById(db, id) orelse return http_util.writeError(hc, .not_found, "unknown account");
    try writeAccountForUser(hc, st, u);
}

pub fn handleVerifyCredentials(hc: *HandlerContext) anyerror!void {
    const st = state_mod.get();
    const claims = (try auth.requireScope(hc, "read")) orelse return;
    if (claims.user_id == 0) return http_util.writeError(hc, .forbidden, "client-only token");
    const db = st.db orelse return http_util.writeError(hc, .service_unavailable, "db not ready");
    const u = db_mod.findUserById(db, claims.user_id) orelse return http_util.writeError(hc, .not_found, "user gone");
    try writeAccountForUser(hc, st, u);
}

pub fn handleAccountStatuses(hc: *HandlerContext) anyerror!void {
    const st = state_mod.get();
    const db = st.db orelse return http_util.writeError(hc, .service_unavailable, "db not ready");
    const id_str = hc.params.get("id") orelse return http_util.writeError(hc, .bad_request, "id required");
    const actor_id = parseId(id_str);

    const pq = hc.request.pathAndQuery();
    const since = if (http_util.queryParam(pq.query, "since_id")) |s| parseId(s) else 0;
    const max = if (http_util.queryParam(pq.query, "max_id")) |s| parseId(s) else 0;
    const limit = if (http_util.queryParam(pq.query, "limit")) |s| parseId(s) else 20;

    var iter = db_mod.queryStatuses(db, actor_id, since, max, limit);
    defer iter.deinit();

    var out_buf: [16 * 1024]u8 = undefined;
    var pos: usize = 0;
    out_buf[pos] = '[';
    pos += 1;
    var first = true;
    var row: db_mod.StatusRow = undefined;
    while (iter.next(&row)) {
        if (!first) {
            out_buf[pos] = ',';
            pos += 1;
        }
        first = false;
        const author = db_mod.findUserById(db, row.actor_id) orelse continue;
        var author_iso_buf: [32]u8 = undefined;
        const author_iso = serialize.formatIsoTimestamp(author.created_at, &author_iso_buf) catch "1970-01-01T00:00:00Z";
        var status_iso_buf: [32]u8 = undefined;
        const status_iso = serialize.formatIsoTimestamp(row.published, &status_iso_buf) catch "1970-01-01T00:00:00Z";
        const status_json = serialize.writeStatus(.{
            .id = row.id,
            .created_at_iso = status_iso,
            .content_html = row.content(),
            .favourites_count = db_mod.countFavourites(db, row.id),
            .reblogs_count = db_mod.countReblogs(db, row.id),
            .account = .{
                .id = author.id,
                .username = author.username(),
                .acct = author.username(),
                .display_name = author.displayName(),
                .note = author.bio(),
                .hostname = st.hostname(),
                .created_at_iso = author_iso,
            },
        }, out_buf[pos..]) catch return http_util.writeError(hc, .internal, "status buf");
        pos += status_json.len;
    }
    if (pos >= out_buf.len) return http_util.writeError(hc, .internal, "response buf");
    out_buf[pos] = ']';
    pos += 1;
    try http_util.writeJsonBody(hc, .ok, out_buf[0..pos]);
}

pub fn handleAccountFollowers(hc: *HandlerContext) anyerror!void {
    // Empty array — we don't yet materialize follower account profiles.
    _ = hc.params.get("id");
    try http_util.writeJsonBody(hc, .ok, "[]");
}

pub fn handleAccountFollowing(hc: *HandlerContext) anyerror!void {
    _ = hc.params.get("id");
    try http_util.writeJsonBody(hc, .ok, "[]");
}

pub fn handleAccountFollow(hc: *HandlerContext) anyerror!void {
    const st = state_mod.get();
    const claims = (try auth.requireScope(hc, "follow")) orelse return;
    if (claims.user_id == 0) return http_util.writeError(hc, .forbidden, "client-only token");
    const db = st.db orelse return http_util.writeError(hc, .service_unavailable, "db not ready");
    const id_str = hc.params.get("id") orelse return http_util.writeError(hc, .bad_request, "id required");
    const target_id = parseId(id_str);
    const me = db_mod.findUserById(db, claims.user_id) orelse return http_util.writeError(hc, .not_found, "user gone");
    const target = db_mod.findUserById(db, target_id) orelse return http_util.writeError(hc, .not_found, "unknown account");

    var me_uri: [256]u8 = undefined;
    var tgt_uri: [256]u8 = undefined;
    const me_str = std.fmt.bufPrint(&me_uri, "https://{s}/users/{s}", .{ st.hostname(), me.username() }) catch return http_util.writeError(hc, .internal, "uri");
    const tgt_str = std.fmt.bufPrint(&tgt_uri, "https://{s}/users/{s}", .{ st.hostname(), target.username() }) catch return http_util.writeError(hc, .internal, "uri");

    db_mod.upsertFollow(db, me_str, tgt_str, "accepted", st.clock.wallUnix()) catch {
        return http_util.writeError(hc, .internal, "follow failed");
    };
    // Emit a notification for the target.
    db_mod.insertNotification(db, target.id, "follow", me_str, 0, st.clock.wallUnix()) catch {};

    try writeRelationship(hc, target_id, true, false);
}

pub fn handleAccountUnfollow(hc: *HandlerContext) anyerror!void {
    const st = state_mod.get();
    const claims = (try auth.requireScope(hc, "follow")) orelse return;
    if (claims.user_id == 0) return http_util.writeError(hc, .forbidden, "client-only token");
    const db = st.db orelse return http_util.writeError(hc, .service_unavailable, "db not ready");
    const id_str = hc.params.get("id") orelse return http_util.writeError(hc, .bad_request, "id required");
    const target_id = parseId(id_str);
    const me = db_mod.findUserById(db, claims.user_id) orelse return http_util.writeError(hc, .not_found, "user gone");
    const target = db_mod.findUserById(db, target_id) orelse return http_util.writeError(hc, .not_found, "unknown account");

    var me_uri: [256]u8 = undefined;
    var tgt_uri: [256]u8 = undefined;
    const me_str = std.fmt.bufPrint(&me_uri, "https://{s}/users/{s}", .{ st.hostname(), me.username() }) catch return http_util.writeError(hc, .internal, "uri");
    const tgt_str = std.fmt.bufPrint(&tgt_uri, "https://{s}/users/{s}", .{ st.hostname(), target.username() }) catch return http_util.writeError(hc, .internal, "uri");
    db_mod.removeFollow(db, me_str, tgt_str) catch {};
    try writeRelationship(hc, target_id, false, false);
}

fn writeRelationship(hc: *HandlerContext, target_id: i64, following: bool, requested: bool) !void {
    var buf: [512]u8 = undefined;
    const out = std.fmt.bufPrint(&buf,
        "{{\"id\":\"{d}\",\"following\":{s},\"showing_reblogs\":true,\"notifying\":false," ++
        "\"followed_by\":false,\"blocking\":false,\"blocked_by\":false,\"muting\":false," ++
        "\"muting_notifications\":false,\"requested\":{s},\"domain_blocking\":false," ++
        "\"endorsed\":false,\"note\":\"\"}}",
        .{ target_id, if (following) "true" else "false", if (requested) "true" else "false" },
    ) catch return http_util.writeError(hc, .internal, "rel buf");
    try http_util.writeJsonBody(hc, .ok, out);
}

const testing = std.testing;

test "parseId basic" {
    try testing.expectEqual(@as(i64, 42), parseId("42"));
    try testing.expectEqual(@as(i64, 0), parseId(""));
    try testing.expectEqual(@as(i64, 0), parseId("abc"));
}
