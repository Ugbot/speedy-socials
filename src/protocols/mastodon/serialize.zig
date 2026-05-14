//! Mastodon JSON serializers. Every function writes into a caller-
//! supplied buffer and returns the slice written. No allocator is used
//! on the hot path.
//!
//! These shapes mirror the Mastodon API v1 documentation. Fields not yet
//! supported by the speedy-socials data model are emitted with safe
//! defaults (empty strings, zero counts) so clients accept the response.

const std = @import("std");

pub const Account = struct {
    id: i64,
    username: []const u8,
    acct: []const u8,
    display_name: []const u8,
    note: []const u8,
    hostname: []const u8,
    created_at_iso: []const u8,
    followers_count: i64 = 0,
    following_count: i64 = 0,
    statuses_count: i64 = 0,
    locked: bool = false,
    bot: bool = false,
    discoverable: bool = true,
};

pub fn writeAccount(a: Account, out: []u8) ![]const u8 {
    return std.fmt.bufPrint(out,
        "{{\"id\":\"{d}\",\"username\":\"{s}\",\"acct\":\"{s}\"," ++
        "\"display_name\":\"{s}\",\"locked\":{s},\"bot\":{s},\"discoverable\":{s},\"group\":false," ++
        "\"created_at\":\"{s}\",\"note\":\"{s}\"," ++
        "\"url\":\"https://{s}/@{s}\",\"avatar\":\"\",\"avatar_static\":\"\"," ++
        "\"header\":\"\",\"header_static\":\"\"," ++
        "\"followers_count\":{d},\"following_count\":{d},\"statuses_count\":{d}," ++
        "\"last_status_at\":null,\"emojis\":[],\"fields\":[]}}",
        .{
            a.id, a.username, a.acct, a.display_name,
            boolJson(a.locked), boolJson(a.bot), boolJson(a.discoverable),
            a.created_at_iso, a.note,
            a.hostname, a.username,
            a.followers_count, a.following_count, a.statuses_count,
        },
    );
}

pub const Status = struct {
    id: i64,
    created_at_iso: []const u8,
    content_html: []const u8,
    account: Account,
    favourites_count: i64 = 0,
    reblogs_count: i64 = 0,
    replies_count: i64 = 0,
    favourited: bool = false,
    reblogged: bool = false,
    visibility: []const u8 = "public",
    in_reply_to_id: i64 = 0, // 0 means null
    spoiler_text: []const u8 = "",
};

pub fn writeStatus(s: Status, out: []u8) ![]const u8 {
    // Build the embedded account JSON first into a scratch buffer.
    var acct_buf: [2048]u8 = undefined;
    const acct_json = try writeAccount(s.account, &acct_buf);

    if (s.in_reply_to_id == 0) {
        return std.fmt.bufPrint(out,
            "{{\"id\":\"{d}\",\"created_at\":\"{s}\",\"in_reply_to_id\":null," ++
            "\"in_reply_to_account_id\":null,\"sensitive\":false,\"spoiler_text\":\"{s}\"," ++
            "\"visibility\":\"{s}\",\"language\":\"en\",\"uri\":\"https://{s}/@{s}/{d}\"," ++
            "\"url\":\"https://{s}/@{s}/{d}\",\"replies_count\":{d}," ++
            "\"reblogs_count\":{d},\"favourites_count\":{d},\"favourited\":{s},\"reblogged\":{s}," ++
            "\"muted\":false,\"bookmarked\":false,\"pinned\":false,\"content\":\"{s}\"," ++
            "\"reblog\":null,\"application\":null,\"media_attachments\":[],\"mentions\":[]," ++
            "\"tags\":[],\"emojis\":[],\"card\":null,\"poll\":null,\"account\":{s}}}",
            .{
                s.id, s.created_at_iso, s.spoiler_text, s.visibility,
                s.account.hostname, s.account.username, s.id,
                s.account.hostname, s.account.username, s.id,
                s.replies_count, s.reblogs_count, s.favourites_count,
                boolJson(s.favourited), boolJson(s.reblogged),
                s.content_html, acct_json,
            },
        );
    } else {
        return std.fmt.bufPrint(out,
            "{{\"id\":\"{d}\",\"created_at\":\"{s}\",\"in_reply_to_id\":\"{d}\"," ++
            "\"in_reply_to_account_id\":null,\"sensitive\":false,\"spoiler_text\":\"{s}\"," ++
            "\"visibility\":\"{s}\",\"language\":\"en\",\"uri\":\"https://{s}/@{s}/{d}\"," ++
            "\"url\":\"https://{s}/@{s}/{d}\",\"replies_count\":{d}," ++
            "\"reblogs_count\":{d},\"favourites_count\":{d},\"favourited\":{s},\"reblogged\":{s}," ++
            "\"muted\":false,\"bookmarked\":false,\"pinned\":false,\"content\":\"{s}\"," ++
            "\"reblog\":null,\"application\":null,\"media_attachments\":[],\"mentions\":[]," ++
            "\"tags\":[],\"emojis\":[],\"card\":null,\"poll\":null,\"account\":{s}}}",
            .{
                s.id, s.created_at_iso, s.in_reply_to_id, s.spoiler_text, s.visibility,
                s.account.hostname, s.account.username, s.id,
                s.account.hostname, s.account.username, s.id,
                s.replies_count, s.reblogs_count, s.favourites_count,
                boolJson(s.favourited), boolJson(s.reblogged),
                s.content_html, acct_json,
            },
        );
    }
}

pub const Application = struct {
    name: []const u8,
    website: []const u8,
    client_id: []const u8,
    client_secret: []const u8,
    redirect_uri: []const u8,
    vapid_key: []const u8,
};

pub fn writeApplication(app: Application, out: []u8) ![]const u8 {
    return std.fmt.bufPrint(out,
        "{{\"id\":\"0\",\"name\":\"{s}\",\"website\":\"{s}\"," ++
        "\"redirect_uri\":\"{s}\",\"client_id\":\"{s}\",\"client_secret\":\"{s}\"," ++
        "\"vapid_key\":\"{s}\"}}",
        .{ app.name, app.website, app.redirect_uri, app.client_id, app.client_secret, app.vapid_key },
    );
}

pub const Notification = struct {
    id: i64,
    type: []const u8,
    created_at_iso: []const u8,
    account_acct: []const u8, // already-formatted acct uri or handle
    hostname: []const u8,
    status_id: i64 = 0, // 0 = none
};

pub fn writeNotification(n: Notification, out: []u8) ![]const u8 {
    // We embed a stripped-down account for the `account` field. Real
    // accounts can be fetched separately by clients that need full info.
    var acct_buf: [512]u8 = undefined;
    const acct_json = try std.fmt.bufPrint(&acct_buf,
        "{{\"id\":\"0\",\"username\":\"{s}\",\"acct\":\"{s}\",\"display_name\":\"{s}\"," ++
        "\"url\":\"https://{s}/@{s}\",\"avatar\":\"\",\"avatar_static\":\"\"," ++
        "\"header\":\"\",\"header_static\":\"\",\"locked\":false,\"bot\":false," ++
        "\"created_at\":\"1970-01-01T00:00:00Z\",\"note\":\"\"," ++
        "\"followers_count\":0,\"following_count\":0,\"statuses_count\":0,\"emojis\":[],\"fields\":[]}}",
        .{ n.account_acct, n.account_acct, n.account_acct, n.hostname, n.account_acct },
    );
    if (n.status_id == 0) {
        return std.fmt.bufPrint(out,
            "{{\"id\":\"{d}\",\"type\":\"{s}\",\"created_at\":\"{s}\",\"account\":{s},\"status\":null}}",
            .{ n.id, n.type, n.created_at_iso, acct_json },
        );
    }
    return std.fmt.bufPrint(out,
        "{{\"id\":\"{d}\",\"type\":\"{s}\",\"created_at\":\"{s}\",\"account\":{s},\"status\":{{\"id\":\"{d}\"}}}}",
        .{ n.id, n.type, n.created_at_iso, acct_json, n.status_id },
    );
}

pub const InstanceMeta = struct {
    hostname: []const u8,
    user_count: i64,
    status_count: i64,
    domain_count: i64,
};

pub fn writeInstance(m: InstanceMeta, out: []u8) ![]const u8 {
    return std.fmt.bufPrint(out,
        "{{\"uri\":\"{s}\",\"title\":\"speedy-socials\"," ++
        "\"short_description\":\"A high-performance social server in Zig\"," ++
        "\"description\":\"speedy-socials federates over both ActivityPub and AT Protocol.\"," ++
        "\"email\":\"admin@{s}\",\"version\":\"4.0.0 (compatible; speedy-socials)\"," ++
        "\"urls\":{{\"streaming_api\":\"wss://{s}\"}}," ++
        "\"stats\":{{\"user_count\":{d},\"status_count\":{d},\"domain_count\":{d}}}," ++
        "\"thumbnail\":null,\"languages\":[\"en\"]," ++
        "\"registrations\":true,\"approval_required\":false,\"invites_enabled\":false," ++
        "\"configuration\":{{\"statuses\":{{\"max_characters\":5000,\"max_media_attachments\":4,\"characters_reserved_per_url\":23}}," ++
        "\"media_attachments\":{{\"supported_mime_types\":[\"image/jpeg\",\"image/png\",\"image/gif\"]," ++
        "\"image_size_limit\":10485760,\"video_size_limit\":41943040}}}}," ++
        "\"contact_account\":null,\"rules\":[]}}",
        .{ m.hostname, m.hostname, m.hostname, m.user_count, m.status_count, m.domain_count },
    );
}

fn boolJson(v: bool) []const u8 {
    return if (v) "true" else "false";
}

/// Render a unix-seconds timestamp as an RFC 3339 string with second
/// precision. Bounded — guaranteed ≤ 20 bytes.
pub fn formatIsoTimestamp(unix_seconds: i64, out: []u8) ![]const u8 {
    if (out.len < 20) return error.BufferTooSmall;
    const es = std.time.epoch.EpochSeconds{ .secs = @intCast(@max(unix_seconds, 0)) };
    const ed = es.getEpochDay();
    const ymd = ed.calculateYearDay();
    const md = ymd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return std.fmt.bufPrint(out,
        "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z",
        .{
            @as(u32, ymd.year), @as(u32, md.month.numeric()), @as(u32, md.day_index + 1),
            ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
        },
    );
}

const testing = std.testing;

test "writeAccount basic" {
    var buf: [2048]u8 = undefined;
    const out = try writeAccount(.{
        .id = 1,
        .username = "alice",
        .acct = "alice",
        .display_name = "Alice",
        .note = "hello",
        .hostname = "speedy.local",
        .created_at_iso = "2025-01-01T00:00:00Z",
        .followers_count = 3,
        .following_count = 7,
        .statuses_count = 12,
    }, &buf);
    try testing.expect(std.mem.indexOf(u8, out, "\"id\":\"1\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"username\":\"alice\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"followers_count\":3") != null);
}

test "writeStatus embeds account" {
    var buf: [4096]u8 = undefined;
    const out = try writeStatus(.{
        .id = 42,
        .created_at_iso = "2025-01-02T00:00:00Z",
        .content_html = "hello",
        .account = .{
            .id = 1,
            .username = "alice",
            .acct = "alice",
            .display_name = "Alice",
            .note = "",
            .hostname = "speedy.local",
            .created_at_iso = "2025-01-01T00:00:00Z",
        },
        .favourites_count = 2,
    }, &buf);
    try testing.expect(std.mem.indexOf(u8, out, "\"id\":\"42\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"favourites_count\":2") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"username\":\"alice\"") != null);
}

test "writeInstance shape" {
    var buf: [4096]u8 = undefined;
    const out = try writeInstance(.{
        .hostname = "speedy.local",
        .user_count = 5,
        .status_count = 10,
        .domain_count = 1,
    }, &buf);
    try testing.expect(std.mem.indexOf(u8, out, "\"uri\":\"speedy.local\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"user_count\":5") != null);
}

test "writeApplication shape" {
    var buf: [1024]u8 = undefined;
    const out = try writeApplication(.{
        .name = "test app",
        .website = "https://test/",
        .client_id = "cid",
        .client_secret = "csec",
        .redirect_uri = "urn:ietf:wg:oauth:2.0:oob",
        .vapid_key = "",
    }, &buf);
    try testing.expect(std.mem.indexOf(u8, out, "\"client_id\":\"cid\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"client_secret\":\"csec\"") != null);
}

test "writeNotification with status" {
    var buf: [2048]u8 = undefined;
    const out = try writeNotification(.{
        .id = 7,
        .type = "follow",
        .created_at_iso = "2025-01-01T00:00:00Z",
        .account_acct = "bob",
        .hostname = "speedy.local",
        .status_id = 0,
    }, &buf);
    try testing.expect(std.mem.indexOf(u8, out, "\"type\":\"follow\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"status\":null") != null);
}

test "formatIsoTimestamp produces zero-padded output" {
    var buf: [32]u8 = undefined;
    const out = try formatIsoTimestamp(0, &buf);
    try testing.expectEqualStrings("1970-01-01T00:00:00Z", out);
    const out2 = try formatIsoTimestamp(1_700_000_000, &buf);
    try testing.expect(out2.len == 20);
}
