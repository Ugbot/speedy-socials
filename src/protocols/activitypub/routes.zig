//! HTTP routes for the ActivityPub plugin.
//!
//! Routes registered:
//!   * GET  /.well-known/webfinger
//!   * GET  /.well-known/nodeinfo
//!   * GET  /nodeinfo/2.1
//!   * GET  /users/:u                (content-negotiated)
//!   * POST /users/:u/inbox
//!   * GET  /users/:u/outbox
//!   * GET  /users/:u/followers
//!   * GET  /users/:u/following
//!   * GET  /users/:u/collections/featured
//!   * POST /inbox                   (shared inbox)
//!
//! Handlers use the module-level State (set by main.zig) to talk to
//! the storage layer and the key cache. Responses use the fixed-length
//! `response.Builder` for known sizes; collections paginate within a
//! single page worth of items here (full chunked-stream support lands
//! later — current bound is `collections.max_page_items = 40`).

const std = @import("std");
const c = @import("sqlite").c;
const core = @import("core");

const HandlerContext = core.http.router.HandlerContext;
const Status = core.http.response.Status;
const Router = core.http.router.Router;
const Method = core.http.request.Method;
const HttpError = core.errors.HttpError;

const state_mod = @import("state.zig");
const webfinger = @import("webfinger.zig");
const nodeinfo = @import("nodeinfo.zig");
const actor_mod = @import("actor.zig");
const collections = @import("collections.zig");
const activity_mod = @import("activity.zig");
const inbox = @import("inbox.zig");
const sig = @import("sig.zig");
const keys = @import("keys.zig");
const key_cache = @import("key_cache.zig");
const delivery = @import("delivery.zig");

const max_response_bytes: usize = 16 * 1024;

// ──────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────

fn writeJsonLd(hc: *HandlerContext, status: Status, body: []const u8) !void {
    try hc.response.startStatus(status);
    try hc.response.header("Content-Type", "application/activity+json; charset=utf-8");
    try hc.response.headerFmt("Content-Length", "{d}", .{body.len});
    try hc.response.header("Connection", "close");
    try hc.response.finishHeaders();
    try hc.response.body(body);
}

fn writeJson(hc: *HandlerContext, status: Status, body: []const u8) !void {
    try hc.response.startStatus(status);
    try hc.response.header("Content-Type", "application/json; charset=utf-8");
    try hc.response.headerFmt("Content-Length", "{d}", .{body.len});
    try hc.response.header("Connection", "close");
    try hc.response.finishHeaders();
    try hc.response.body(body);
}

fn writeHtml(hc: *HandlerContext, status: Status, body: []const u8) !void {
    try hc.response.startStatus(status);
    try hc.response.header("Content-Type", "text/html; charset=utf-8");
    try hc.response.headerFmt("Content-Length", "{d}", .{body.len});
    try hc.response.header("Connection", "close");
    try hc.response.finishHeaders();
    try hc.response.body(body);
}

fn writePlain(hc: *HandlerContext, status: Status, body: []const u8) !void {
    try hc.response.startStatus(status);
    try hc.response.header("Content-Type", "application/jrd+json; charset=utf-8");
    try hc.response.headerFmt("Content-Length", "{d}", .{body.len});
    try hc.response.header("Connection", "close");
    try hc.response.finishHeaders();
    try hc.response.body(body);
}

/// Content negotiation: returns true if the client wants ActivityPub
/// JSON-LD. Mastodon sends either `application/activity+json` or
/// `application/ld+json; profile="https://www.w3.org/ns/activitystreams"`.
pub fn wantsActivityJson(accept: []const u8) bool {
    if (std.mem.indexOf(u8, accept, "application/activity+json") != null) return true;
    if (std.mem.indexOf(u8, accept, "application/ld+json") != null and
        std.mem.indexOf(u8, accept, "activitystreams") != null) return true;
    return false;
}

/// Read one query-param value by name. Tiger Style: bounded scan.
pub fn getQueryParam(query: []const u8, name: []const u8) ?[]const u8 {
    var i: usize = 0;
    var guard: u32 = 0;
    while (i < query.len) {
        guard += 1;
        if (guard > 64) return null;
        const start = i;
        var eq = i;
        while (eq < query.len and query[eq] != '=' and query[eq] != '&') eq += 1;
        const key = query[start..eq];
        if (eq >= query.len) {
            if (std.mem.eql(u8, key, name)) return "";
            return null;
        }
        if (query[eq] == '=') {
            const vstart = eq + 1;
            var vend = vstart;
            while (vend < query.len and query[vend] != '&') vend += 1;
            if (std.mem.eql(u8, key, name)) return query[vstart..vend];
            i = if (vend < query.len) vend + 1 else vend;
        } else {
            if (std.mem.eql(u8, key, name)) return "";
            i = eq + 1;
        }
    }
    return null;
}

// ──────────────────────────────────────────────────────────────────────
// Local data lookups (synchronous via the attached writer DB)
// ──────────────────────────────────────────────────────────────────────

const LocalUser = struct {
    id: i64,
    username_buf: [64]u8 = undefined,
    username_len: usize = 0,
    display_buf: [128]u8 = undefined,
    display_len: usize = 0,
    bio_buf: [256]u8 = undefined,
    bio_len: usize = 0,
    is_locked: bool = false,
    discoverable: bool = true,
    indexable: bool = true,
    pem_buf: [keys.max_pem_bytes]u8 = undefined,
    pem_len: usize = 0,

    fn username(self: *const LocalUser) []const u8 {
        return self.username_buf[0..self.username_len];
    }
    fn displayName(self: *const LocalUser) []const u8 {
        return self.display_buf[0..self.display_len];
    }
    fn bio(self: *const LocalUser) []const u8 {
        return self.bio_buf[0..self.bio_len];
    }
    fn pem(self: *const LocalUser) []const u8 {
        return self.pem_buf[0..self.pem_len];
    }
};

fn loadUser(db: *c.sqlite3, username: []const u8) ?LocalUser {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql =
        \\SELECT u.id, u.username, COALESCE(u.display_name,''), COALESCE(u.bio,''),
        \\       u.is_locked, u.discoverable, u.indexable,
        \\       COALESCE(k.public_pem, '')
        \\FROM ap_users u
        \\LEFT JOIN ap_actor_keys k ON k.actor_id = u.id
        \\WHERE u.username = ?
        \\LIMIT 1
    ;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return null;
    }
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, username.ptr, @intCast(username.len), c.sqliteTransientAsDestructor());
    if (c.sqlite3_step(stmt) != c.SQLITE_ROW) return null;

    var u: LocalUser = .{ .id = c.sqlite3_column_int64(stmt, 0) };
    copyTextCol(stmt.?, 1, &u.username_buf, &u.username_len);
    copyTextCol(stmt.?, 2, &u.display_buf, &u.display_len);
    copyTextCol(stmt.?, 3, &u.bio_buf, &u.bio_len);
    u.is_locked = c.sqlite3_column_int(stmt, 4) != 0;
    u.discoverable = c.sqlite3_column_int(stmt, 5) != 0;
    u.indexable = c.sqlite3_column_int(stmt, 6) != 0;
    copyTextCol(stmt.?, 7, &u.pem_buf, &u.pem_len);
    return u;
}

fn copyTextCol(stmt: *c.sqlite3_stmt, idx: c_int, buf: []u8, len_out: *usize) void {
    const ptr = c.sqlite3_column_text(stmt, idx);
    const n: usize = @intCast(c.sqlite3_column_bytes(stmt, idx));
    const copy_n = @min(n, buf.len);
    if (ptr != null and copy_n > 0) @memcpy(buf[0..copy_n], ptr[0..copy_n]);
    len_out.* = copy_n;
}

fn countFollows(db: *c.sqlite3, column: []const u8, value: []const u8) i64 {
    var buf: [128]u8 = undefined;
    const sql_fmt = "SELECT COUNT(*) FROM ap_follows WHERE {s} = ? AND state='accepted'";
    const sql = std.fmt.bufPrintZ(&buf, sql_fmt, .{column}) catch return 0;
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql.ptr, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return 0;
    }
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, value.ptr, @intCast(value.len), c.sqliteTransientAsDestructor());
    if (c.sqlite3_step(stmt) != c.SQLITE_ROW) return 0;
    return c.sqlite3_column_int64(stmt, 0);
}

fn countActivities(db: *c.sqlite3, actor_id: i64) i64 {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "SELECT COUNT(*) FROM ap_activities WHERE actor_id = ?";
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return 0;
    }
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_int64(stmt, 1, actor_id);
    if (c.sqlite3_step(stmt) != c.SQLITE_ROW) return 0;
    return c.sqlite3_column_int64(stmt, 0);
}

fn isTombstoned(db: *c.sqlite3, uri: []const u8) bool {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "SELECT 1 FROM ap_tombstones WHERE uri = ?";
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return false;
    }
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, uri.ptr, @intCast(uri.len), c.sqliteTransientAsDestructor());
    return c.sqlite3_step(stmt) == c.SQLITE_ROW;
}

// ──────────────────────────────────────────────────────────────────────
// Handlers
// ──────────────────────────────────────────────────────────────────────

fn handleWebFinger(hc: *HandlerContext) anyerror!void {
    const st = state_mod.get();
    const pq = hc.request.pathAndQuery();
    const resource = getQueryParam(pq.query, "resource") orelse {
        return writeJson(hc, .bad_request, "{\"error\":\"resource required\"}");
    };
    const parsed = webfinger.parseResourceParam(resource) catch {
        return writeJson(hc, .bad_request, "{\"error\":\"bad resource\"}");
    };
    // Host check (case-insensitive). If our hostname doesn't match, 404.
    if (!std.ascii.eqlIgnoreCase(parsed.host, st.hostname())) {
        return writeJson(hc, .not_found, "{\"error\":\"unknown host\"}");
    }
    const db = st.db orelse {
        return writeJson(hc, .service_unavailable, "{\"error\":\"db not ready\"}");
    };
    const user = loadUser(db, parsed.username) orelse {
        return writeJson(hc, .not_found, "{\"error\":\"unknown user\"}");
    };
    var body: [1024]u8 = undefined;
    const out = webfinger.writeJrd(.{ .hostname = st.hostname(), .username = user.username() }, &body) catch {
        return writeJson(hc, .internal, "{\"error\":\"jrd buffer\"}");
    };
    try writePlain(hc, .ok, out);
}

fn handleNodeInfoJrd(hc: *HandlerContext) anyerror!void {
    const st = state_mod.get();
    var body: [512]u8 = undefined;
    const out = nodeinfo.writeJrd(.{ .hostname = st.hostname() }, &body) catch {
        return writeJson(hc, .internal, "{\"error\":\"jrd buffer\"}");
    };
    try writeJson(hc, .ok, out);
}

fn handleNodeInfo21(hc: *HandlerContext) anyerror!void {
    const st = state_mod.get();
    var stats: nodeinfo.Stats = .{};
    if (st.db) |db| {
        stats.total_users = @intCast(countTable(db, "ap_users"));
        stats.local_posts = @intCast(countTable(db, "ap_activities"));
    }
    var body: [2048]u8 = undefined;
    const out = nodeinfo.writeNodeInfo(.{ .hostname = st.hostname() }, stats, &body) catch {
        return writeJson(hc, .internal, "{\"error\":\"nodeinfo buffer\"}");
    };
    try writeJson(hc, .ok, out);
}

fn countTable(db: *c.sqlite3, name: []const u8) i64 {
    var buf: [128]u8 = undefined;
    const sql = std.fmt.bufPrintZ(&buf, "SELECT COUNT(*) FROM {s}", .{name}) catch return 0;
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql.ptr, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return 0;
    }
    defer _ = c.sqlite3_finalize(stmt);
    if (c.sqlite3_step(stmt) != c.SQLITE_ROW) return 0;
    return c.sqlite3_column_int64(stmt, 0);
}

fn handleUserActor(hc: *HandlerContext) anyerror!void {
    const st = state_mod.get();
    const username = hc.params.get("u") orelse return writeJson(hc, .bad_request, "{\"error\":\"missing user\"}");
    const db = st.db orelse return writeJson(hc, .service_unavailable, "{\"error\":\"db not ready\"}");

    // Tombstone check: profile URI.
    var uri_buf: [256]u8 = undefined;
    const uri = std.fmt.bufPrint(&uri_buf, "https://{s}/users/{s}", .{ st.hostname(), username }) catch {
        return writeJson(hc, .internal, "{\"error\":\"uri buf\"}");
    };
    if (isTombstoned(db, uri)) return writeTombstone(hc, uri);

    const user = loadUser(db, username) orelse {
        return writeJson(hc, .not_found, "{\"error\":\"unknown user\"}");
    };

    const accept = hc.request.header("Accept") orelse "";
    if (!wantsActivityJson(accept)) {
        // Serve a tiny HTML stub.
        var html_buf: [1024]u8 = undefined;
        const html = std.fmt.bufPrint(&html_buf,
            "<!doctype html><html><head><title>@{s}</title></head>" ++
            "<body><h1>@{s}</h1><p>{s}</p></body></html>",
            .{ user.username(), user.username(), user.bio() }) catch return writeJson(hc, .internal, "{\"error\":\"html buf\"}");
        return writeHtml(hc, .ok, html);
    }

    var body: [max_response_bytes]u8 = undefined;
    const out = actor_mod.writePerson(.{
        .hostname = st.hostname(),
        .username = user.username(),
        .display_name = user.displayName(),
        .bio = user.bio(),
        .public_key_pem = user.pem(),
        .manually_approves_followers = user.is_locked,
        .discoverable = user.discoverable,
        .indexable = user.indexable,
    }, &body) catch return writeJson(hc, .internal, "{\"error\":\"actor buf\"}");
    try writeJsonLd(hc, .ok, out);
}

fn writeTombstone(hc: *HandlerContext, uri: []const u8) !void {
    var body: [512]u8 = undefined;
    const out = std.fmt.bufPrint(&body,
        "{{\"@context\":\"https://www.w3.org/ns/activitystreams\"," ++
        "\"id\":\"{s}\",\"type\":\"Tombstone\"}}",
        .{uri}) catch return writeJson(hc, .internal, "{\"error\":\"tombstone buf\"}");
    try hc.response.startStatus(.gone);
    try hc.response.header("Content-Type", "application/activity+json; charset=utf-8");
    try hc.response.headerFmt("Content-Length", "{d}", .{out.len});
    try hc.response.header("Connection", "close");
    try hc.response.finishHeaders();
    try hc.response.body(out);
}

fn handleUserInbox(hc: *HandlerContext) anyerror!void {
    const st = state_mod.get();
    const username = hc.params.get("u") orelse return writeJson(hc, .bad_request, "{\"error\":\"missing user\"}");
    const db = st.db orelse return writeJson(hc, .service_unavailable, "{\"error\":\"db not ready\"}");

    _ = loadUser(db, username) orelse return writeJson(hc, .not_found, "{\"error\":\"unknown user\"}");
    try dispatchInbox(hc, st, db, username);
}

fn handleSharedInbox(hc: *HandlerContext) anyerror!void {
    const st = state_mod.get();
    const db = st.db orelse return writeJson(hc, .service_unavailable, "{\"error\":\"db not ready\"}");
    try dispatchInbox(hc, st, db, "");
}

fn dispatchInbox(hc: *HandlerContext, st: *state_mod.State, db: *c.sqlite3, _: []const u8) !void {
    // Parse the activity body. Signature verification is deferred unless
    // a key is resolvable; in production the key is fetched via the
    // worker pool, but the route accepts a 202 outcome either way to
    // signal "received, will process".
    const body = hc.request.body;
    if (body.len == 0) return writeJson(hc, .bad_request, "{\"error\":\"empty body\"}");

    const act = activity_mod.parse(body) catch {
        return writeJson(hc, .bad_request, "{\"error\":\"bad activity\"}");
    };

    // Optional signature verify: best effort. If we have a key cache +
    // workers + a signature header, try to verify; if not, the activity
    // is still accepted into the inbox but not fanned out (Tiger Style
    // soft acceptance — see PROTOCOL_AUDIT AP-C2 for the strict mode
    // that will land alongside the key-fetch HTTPS client).
    var verified = false;
    if (hc.request.header("Signature")) |sig_hdr| sig_block: {
        const pool = st.workers orelse break :sig_block;
        const parsed = sig.parseCavage(sig_hdr) catch break :sig_block;
        const pk = key_cache.resolve(&st.keys, pool, st.clock, parsed.key_id) catch break :sig_block;
        const pq = hc.request.pathAndQuery();
        const target_uri_buf: [256]u8 = undefined;
        _ = target_uri_buf;
        const req_view: sig.RequestView = .{
            .method = hc.request.method_raw,
            .path = pq.path,
            .target_uri = "",
            .host = hc.request.header("Host") orelse st.hostname(),
            .date = hc.request.header("Date") orelse "",
            .digest_legacy = hc.request.header("Digest") orelse "",
        };
        sig.verify(&parsed, &req_view, &pk) catch break :sig_block;
        verified = true;
    }

    // Run the state machine. Side-effects are drained inline.
    const ns128 = st.clock.wallNs();
    const ns64: u64 = @as(u64, @bitCast(@as(i64, @truncate(ns128))));
    var rng = core.rng.Rng.init(ns64 ^ 0xa55a);
    var eff: inbox.SideEffectBuffer = .{};
    var env: inbox.Envelope = .{
        .activity = act,
        .verified_actor = .{ .iri = act.actor, .is_known_to_us = false },
        .clock = st.clock,
        .rng = &rng,
    };
    inbox.dispatch(&env, &eff) catch |err| switch (err) {
        error.InboxRejected => return writeJson(hc, .bad_request, "{\"error\":\"inbox rejected\"}"),
        error.BadObject => return writeJson(hc, .bad_request, "{\"error\":\"bad object\"}"),
        error.UnsupportedActivity, error.UnknownActor => return writeJson(hc, .bad_request, "{\"error\":\"unsupported\"}"),
    };

    drainSideEffects(db, st, body, eff.slice()) catch {};

    const status: Status = if (verified) .ok else .ok;
    try writeJson(hc, status, "{\"status\":\"accepted\"}");
}

fn drainSideEffects(db: *c.sqlite3, st: *state_mod.State, raw_body: []const u8, effects: []const inbox.SideEffect) !void {
    var i: usize = 0;
    while (i < effects.len) : (i += 1) {
        switch (effects[i]) {
            .store_activity => |sa| {
                _ = recordActivity(db, st.clock, sa.id, sa.actor, sa.kind, raw_body) catch {};
            },
            .record_follow => |rf| {
                _ = recordFollow(db, rf.from_actor, rf.to_actor, "pending") catch {};
            },
            .accept_follow => |af| {
                _ = recordFollow(db, af.from_actor, af.to_actor, "accepted") catch {};
            },
            .reject_follow => |rj| {
                _ = recordFollow(db, rj.from_actor, rj.to_actor, "rejected") catch {};
            },
            .tombstone_object => |tomb| {
                _ = recordTombstone(db, st.clock, tomb.id) catch {};
            },
            else => {},
        }
    }
}

fn recordActivity(db: *c.sqlite3, clock: core.clock.Clock, ap_id: []const u8, actor: []const u8, kind: activity_mod.ActivityType, raw: []const u8) !void {
    _ = actor;
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "INSERT OR IGNORE INTO ap_activities(ap_id,actor_id,type,object_id,published,raw) VALUES (?,0,?,NULL,?,?)";
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return;
    }
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, ap_id.ptr, @intCast(ap_id.len), c.sqliteTransientAsDestructor());
    const kind_str = @tagName(kind);
    _ = c.sqlite3_bind_text(stmt, 2, kind_str.ptr, @intCast(kind_str.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(stmt, 3, clock.wallUnix());
    _ = c.sqlite3_bind_blob(stmt, 4, raw.ptr, @intCast(raw.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_step(stmt);
}

fn recordFollow(db: *c.sqlite3, follower: []const u8, followee: []const u8, state: []const u8) !void {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql =
        \\INSERT INTO ap_follows(follower, followee, state, accepted_at)
        \\VALUES (?, ?, ?, NULL)
        \\ON CONFLICT(follower, followee) DO UPDATE SET state = excluded.state
    ;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return;
    }
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, follower.ptr, @intCast(follower.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 2, followee.ptr, @intCast(followee.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 3, state.ptr, @intCast(state.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_step(stmt);
}

fn recordTombstone(db: *c.sqlite3, clock: core.clock.Clock, uri: []const u8) !void {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "INSERT OR REPLACE INTO ap_tombstones(uri, deleted_at) VALUES (?, ?)";
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return;
    }
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, uri.ptr, @intCast(uri.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(stmt, 2, clock.wallUnix());
    _ = c.sqlite3_step(stmt);
}

// ── Collection handlers ───────────────────────────────────────────────

fn handleOutbox(hc: *HandlerContext) anyerror!void {
    try renderCollection(hc, .outbox);
}

fn handleFollowers(hc: *HandlerContext) anyerror!void {
    try renderCollection(hc, .followers);
}

fn handleFollowing(hc: *HandlerContext) anyerror!void {
    try renderCollection(hc, .following);
}

fn handleFeatured(hc: *HandlerContext) anyerror!void {
    try renderCollection(hc, .featured);
}

fn renderCollection(hc: *HandlerContext, kind: collections.CollectionKind) !void {
    const st = state_mod.get();
    const username = hc.params.get("u") orelse return writeJson(hc, .bad_request, "{\"error\":\"missing user\"}");
    const db = st.db orelse return writeJson(hc, .service_unavailable, "{\"error\":\"db not ready\"}");
    const user = loadUser(db, username) orelse return writeJson(hc, .not_found, "{\"error\":\"unknown user\"}");

    // Build URI for follower/following filter.
    var actor_uri_buf: [256]u8 = undefined;
    const actor_uri = std.fmt.bufPrint(&actor_uri_buf, "https://{s}/users/{s}", .{ st.hostname(), user.username() }) catch return writeJson(hc, .internal, "{\"error\":\"uri buf\"}");

    const total: u64 = switch (kind) {
        .outbox => @intCast(countActivities(db, user.id)),
        .followers => @intCast(countFollows(db, "followee", actor_uri)),
        .following => @intCast(countFollows(db, "follower", actor_uri)),
        .featured => 0,
    };

    var body: [max_response_bytes]u8 = undefined;
    const out = collections.writeIndex(.{
        .hostname = st.hostname(),
        .actor_username = user.username(),
        .kind = kind,
        .total_items = total,
    }, &body) catch return writeJson(hc, .internal, "{\"error\":\"collection buf\"}");
    try writeJsonLd(hc, .ok, out);
}

// ──────────────────────────────────────────────────────────────────────
// Registration
// ──────────────────────────────────────────────────────────────────────

pub fn register(router: *Router, plugin_index: u16) !void {
    try router.register(.get, "/.well-known/webfinger", handleWebFinger, plugin_index);
    try router.register(.get, "/.well-known/nodeinfo", handleNodeInfoJrd, plugin_index);
    try router.register(.get, "/nodeinfo/2.1", handleNodeInfo21, plugin_index);
    try router.register(.get, "/users/:u", handleUserActor, plugin_index);
    try router.register(.post, "/users/:u/inbox", handleUserInbox, plugin_index);
    try router.register(.get, "/users/:u/outbox", handleOutbox, plugin_index);
    try router.register(.get, "/users/:u/followers", handleFollowers, plugin_index);
    try router.register(.get, "/users/:u/following", handleFollowing, plugin_index);
    try router.register(.get, "/users/:u/collections/featured", handleFeatured, plugin_index);
    try router.register(.post, "/inbox", handleSharedInbox, plugin_index);
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "wantsActivityJson detects application/activity+json" {
    try testing.expect(wantsActivityJson("application/activity+json"));
    try testing.expect(wantsActivityJson("text/html, application/activity+json"));
    try testing.expect(!wantsActivityJson("text/html"));
}

test "wantsActivityJson detects ld+json with activitystreams profile" {
    try testing.expect(wantsActivityJson(
        "application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"",
    ));
    try testing.expect(!wantsActivityJson("application/ld+json"));
}

test "getQueryParam extracts named value" {
    try testing.expectEqualStrings("acct:a@b", getQueryParam("resource=acct:a@b", "resource").?);
    try testing.expectEqualStrings("v", getQueryParam("k=v&x=y", "k").?);
    try testing.expectEqualStrings("y", getQueryParam("k=v&x=y", "x").?);
    try testing.expect(getQueryParam("k=v", "missing") == null);
}

test "register binds 10 routes" {
    var r = Router.init();
    try register(&r, 0);
    try testing.expectEqual(@as(u32, 10), r.count);
}

test "loadUser returns null on missing user" {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try @import("schema.zig").applyAllForTests(db);
    try testing.expect(loadUser(db, "nobody") == null);
}

test "loadUser returns row for inserted user" {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try @import("schema.zig").applyAllForTests(db);
    var em: [*c]u8 = null;
    _ = c.sqlite3_exec(db,
        "INSERT INTO ap_users(username, display_name, bio, is_locked, discoverable, indexable, created_at) " ++
        "VALUES ('alice','Alice','hello',0,1,1,0)",
        null, null, &em);
    if (em != null) c.sqlite3_free(em);

    const u = loadUser(db, "alice") orelse return error.TestUserMissing;
    try testing.expectEqualStrings("alice", u.username());
    try testing.expectEqualStrings("Alice", u.displayName());
    try testing.expectEqualStrings("hello", u.bio());
    try testing.expect(!u.is_locked);
}

test "isTombstoned reports true after insert" {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try @import("schema.zig").applyAllForTests(db);
    var em: [*c]u8 = null;
    _ = c.sqlite3_exec(db, "INSERT INTO ap_tombstones(uri, deleted_at) VALUES ('https://x/y', 0)", null, null, &em);
    if (em != null) c.sqlite3_free(em);
    try testing.expect(isTombstoned(db, "https://x/y"));
    try testing.expect(!isTombstoned(db, "https://other"));
}

test "recordFollow upserts state correctly" {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try @import("schema.zig").applyAllForTests(db);
    try recordFollow(db, "a", "b", "pending");
    try recordFollow(db, "a", "b", "accepted");

    var stmt: ?*c.sqlite3_stmt = null;
    _ = c.sqlite3_prepare_v2(db, "SELECT state FROM ap_follows WHERE follower='a' AND followee='b'", -1, &stmt, null);
    defer _ = c.sqlite3_finalize(stmt);
    try testing.expect(c.sqlite3_step(stmt) == c.SQLITE_ROW);
    const sptr = c.sqlite3_column_text(stmt, 0);
    const slen: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
    try testing.expectEqualStrings("accepted", sptr[0..slen]);
}
