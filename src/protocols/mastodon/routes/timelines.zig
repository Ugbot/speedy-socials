//! Mastodon API timeline routes (home/public/hashtag).

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
    var d: u32 = 0;
    for (s) |ch| {
        if (ch < '0' or ch > '9') break;
        val = val * 10 + @as(i64, ch - '0');
        d += 1;
    }
    if (d == 0) return 0;
    return val;
}

pub fn handleHome(hc: *HandlerContext) anyerror!void {
    // For now home == public. A real federated timeline filters by
    // ap_follows; left as a follow-up once the relay landed.
    _ = (try auth.requireScope(hc, "read")) orelse return;
    try writeTimeline(hc, "", 0);
}

pub fn handlePublic(hc: *HandlerContext) anyerror!void {
    try writeTimeline(hc, "", 0);
}

pub fn handleHashtag(hc: *HandlerContext) anyerror!void {
    const tag = hc.params.get("hashtag") orelse return http_util.writeError(hc, .bad_request, "hashtag required");
    try writeTimeline(hc, tag, 0);
}

fn writeTimeline(hc: *HandlerContext, hashtag_filter: []const u8, _: i64) !void {
    const st = state_mod.get();
    const db = st.db orelse return http_util.writeError(hc, .service_unavailable, "db not ready");

    const pq = hc.request.pathAndQuery();
    const since = if (http_util.queryParam(pq.query, "since_id")) |s| parseId(s) else 0;
    const max = if (http_util.queryParam(pq.query, "max_id")) |s| parseId(s) else 0;
    const limit = if (http_util.queryParam(pq.query, "limit")) |s| parseId(s) else 20;

    var iter = db_mod.queryStatuses(db, 0, since, max, limit);
    defer iter.deinit();

    var out_buf: [32 * 1024]u8 = undefined;
    var pos: usize = 0;
    out_buf[pos] = '[';
    pos += 1;
    var first = true;
    var row: db_mod.StatusRow = undefined;
    while (iter.next(&row)) {
        // Hashtag filter: case-insensitive substring search inside content.
        if (hashtag_filter.len > 0) {
            const haystack = row.content();
            var match = false;
            var needle_buf: [128]u8 = undefined;
            if (hashtag_filter.len + 1 < needle_buf.len) {
                needle_buf[0] = '#';
                @memcpy(needle_buf[1..][0..hashtag_filter.len], hashtag_filter);
                const needle = needle_buf[0 .. 1 + hashtag_filter.len];
                match = std.mem.indexOf(u8, haystack, needle) != null;
            }
            if (!match) continue;
        }
        if (!first) {
            if (pos >= out_buf.len) break;
            out_buf[pos] = ',';
            pos += 1;
        }
        first = false;
        const author = db_mod.findUserById(db, row.actor_id) orelse continue;
        var a_iso_buf: [32]u8 = undefined;
        const a_iso = serialize.formatIsoTimestamp(author.created_at, &a_iso_buf) catch "1970-01-01T00:00:00Z";
        var s_iso_buf: [32]u8 = undefined;
        const s_iso = serialize.formatIsoTimestamp(row.published, &s_iso_buf) catch "1970-01-01T00:00:00Z";
        const written = serialize.writeStatus(.{
            .id = row.id,
            .created_at_iso = s_iso,
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
                .created_at_iso = a_iso,
            },
        }, out_buf[pos..]) catch return http_util.writeError(hc, .internal, "buf");
        pos += written.len;
    }
    if (pos >= out_buf.len) return http_util.writeError(hc, .internal, "buf full");
    out_buf[pos] = ']';
    pos += 1;
    try http_util.writeJsonBody(hc, .ok, out_buf[0..pos]);
}
