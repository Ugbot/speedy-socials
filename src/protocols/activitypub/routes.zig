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
const ld_proof = @import("ld_proof.zig");
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
    actor_type_buf: [16]u8 = undefined,
    actor_type_len: usize = 0,

    fn username(self: *const LocalUser) []const u8 {
        return self.username_buf[0..self.username_len];
    }
    fn actorType(self: *const LocalUser) []const u8 {
        return self.actor_type_buf[0..self.actor_type_len];
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
        \\       COALESCE(k.public_pem, ''), COALESCE(u.actor_type, 'Person')
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
    copyTextCol(stmt.?, 8, &u.actor_type_buf, &u.actor_type_len);
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

/// AP-12: lookup tombstone metadata so the 410 response can carry
/// `formerType` (AS2 type the object had before deletion) and
/// `deleted` (ISO 8601). Returns `null` when the URI was never
/// tombstoned. `former_type` is the empty slice when the column is NULL.
const TombstoneRow = struct {
    deleted_at_unix: i64,
    former_type_buf: [64]u8 = undefined,
    former_type_len: u8 = 0,

    pub fn formerType(self: *const TombstoneRow) []const u8 {
        return self.former_type_buf[0..self.former_type_len];
    }
};

fn loadTombstone(db: *c.sqlite3, uri: []const u8) ?TombstoneRow {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "SELECT deleted_at, former_type FROM ap_tombstones WHERE uri = ?";
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return null;
    }
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, uri.ptr, @intCast(uri.len), c.sqliteTransientAsDestructor());
    if (c.sqlite3_step(stmt) != c.SQLITE_ROW) return null;
    var row: TombstoneRow = .{ .deleted_at_unix = c.sqlite3_column_int64(stmt, 0) };
    if (c.sqlite3_column_type(stmt, 1) != c.SQLITE_NULL) {
        const p = c.sqlite3_column_text(stmt, 1);
        const n: usize = @intCast(c.sqlite3_column_bytes(stmt, 1));
        const cap = @min(n, row.former_type_buf.len);
        if (cap > 0) @memcpy(row.former_type_buf[0..cap], p[0..cap]);
        row.former_type_len = @intCast(cap);
    }
    return row;
}

/// Local ISO 8601 second-precision formatter. Bounded ≤ 20 bytes.
/// Inlined here to avoid pulling a Mastodon-plugin module into the AP
/// plugin; behaviour matches `mastodon.serialize.formatIsoTimestamp`.
fn formatIsoTime(unix_seconds: i64, out: []u8) ![]const u8 {
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
    const db = st.dbHandle() orelse {
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
    if (st.dbHandle()) |db| {
        stats.total_users = @intCast(countTable(db, "ap_users"));
        stats.local_posts = @intCast(countTable(db, "ap_activities"));
    }
    // AP-27: declare atproto support when the AT plugin is loaded.
    // Detected at boot by the composition root; the state.zig knob
    // `advertise_atproto` flips on once the AT plugin registers.
    var body: [2048]u8 = undefined;
    const out = nodeinfo.writeNodeInfo(.{
        .hostname = st.hostname(),
        .atproto_enabled = state_mod.advertiseAtproto(),
    }, stats, &body) catch {
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
    const db = st.dbHandle() orelse return writeJson(hc, .service_unavailable, "{\"error\":\"db not ready\"}");

    // Tombstone check: profile URI.
    var uri_buf: [256]u8 = undefined;
    const uri = std.fmt.bufPrint(&uri_buf, "https://{s}/users/{s}", .{ st.hostname(), username }) catch {
        return writeJson(hc, .internal, "{\"error\":\"uri buf\"}");
    };
    if (isTombstoned(db, uri)) return writeTombstone(hc, db, uri);

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

    // AP-15: derive the Ed25519 key's multibase (z6Mk…) from the PEM so
    // the actor advertises a Multikey assertionMethod (FEP-d36d).
    var mb_buf: [80]u8 = undefined;
    const assertion_mb = actorKeyMultibase(user.pem(), &mb_buf) orelse "";

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
        // AP-10: honour the per-user actor type (defaults to Person).
        .actor_type = actor_mod.ActorType.parse(user.actorType()) orelse .person,
        .assertion_multibase = assertion_mb,
    }, &body) catch return writeJson(hc, .internal, "{\"error\":\"actor buf\"}");
    try writeJsonLd(hc, .ok, out);
}

fn writeTombstone(hc: *HandlerContext, db: *c.sqlite3, uri: []const u8) !void {
    // AP-12: enrich the 410 body with `formerType` (when known) and a
    // `deleted` ISO 8601 timestamp pulled from `ap_tombstones`.
    var body: [768]u8 = undefined;
    const out = blk: {
        if (loadTombstone(db, uri)) |tomb| {
            var iso_buf: [24]u8 = undefined;
            const iso = formatIsoTime(tomb.deleted_at_unix, &iso_buf) catch
                break :blk fallbackTombstone(&body, uri);
            const former = tomb.formerType();
            if (former.len > 0) {
                break :blk std.fmt.bufPrint(&body,
                    "{{\"@context\":\"https://www.w3.org/ns/activitystreams\"," ++
                    "\"id\":\"{s}\",\"type\":\"Tombstone\"," ++
                    "\"formerType\":\"{s}\",\"deleted\":\"{s}\"}}",
                    .{ uri, former, iso },
                ) catch break :blk fallbackTombstone(&body, uri);
            }
            break :blk std.fmt.bufPrint(&body,
                "{{\"@context\":\"https://www.w3.org/ns/activitystreams\"," ++
                "\"id\":\"{s}\",\"type\":\"Tombstone\",\"deleted\":\"{s}\"}}",
                .{ uri, iso },
            ) catch break :blk fallbackTombstone(&body, uri);
        }
        break :blk fallbackTombstone(&body, uri);
    };
    try hc.response.startStatus(.gone);
    try hc.response.header("Content-Type", "application/activity+json; charset=utf-8");
    try hc.response.headerFmt("Content-Length", "{d}", .{out.len});
    try hc.response.header("Connection", "close");
    try hc.response.finishHeaders();
    try hc.response.body(out);
}

fn fallbackTombstone(body: []u8, uri: []const u8) []const u8 {
    return std.fmt.bufPrint(body,
        "{{\"@context\":\"https://www.w3.org/ns/activitystreams\"," ++
        "\"id\":\"{s}\",\"type\":\"Tombstone\"}}",
        .{uri},
    ) catch body[0..0];
}

fn handleUserInbox(hc: *HandlerContext) anyerror!void {
    const st = state_mod.get();
    const username = hc.params.get("u") orelse return writeJson(hc, .bad_request, "{\"error\":\"missing user\"}");
    const db = st.dbHandle() orelse return writeJson(hc, .service_unavailable, "{\"error\":\"db not ready\"}");

    _ = loadUser(db, username) orelse return writeJson(hc, .not_found, "{\"error\":\"unknown user\"}");
    try dispatchInbox(hc, st, db, username);
}

fn handleSharedInbox(hc: *HandlerContext) anyerror!void {
    const st = state_mod.get();
    const db = st.dbHandle() orelse return writeJson(hc, .service_unavailable, "{\"error\":\"db not ready\"}");
    try dispatchInbox(hc, st, db, "");
}

fn dispatchInbox(hc: *HandlerContext, st: *state_mod.State, db: *c.sqlite3, _: []const u8) !void {
    // Parse the activity body. Signature verification is deferred unless
    // a key is resolvable; in production the key is fetched via the
    // worker pool, but the route accepts a 202 outcome either way to
    // signal "received, will process".
    const body = hc.request.body;
    if (body.len == 0) return writeJson(hc, .bad_request, "{\"error\":\"empty body\"}");

    // AP-4: When a `Digest` / `Content-Digest` header is present, the
    // hash it carries MUST match SHA-256 of the body — otherwise either
    // the body was tampered with or the peer is misconfigured.
    // We verify *before* signature checking so a peer can't slip a
    // forged digest past us by presenting a valid-looking signature.
    if (hc.request.header("Digest")) |dh| {
        sig.verifyLegacyDigest(dh, body) catch
            return writeJson(hc, .bad_request, "{\"error\":\"digest mismatch\"}");
    }
    if (hc.request.header("Content-Digest")) |cdh| {
        sig.verifyContentDigest(cdh, body) catch
            return writeJson(hc, .bad_request, "{\"error\":\"content-digest mismatch\"}");
    }

    const act = activity_mod.parse(body) catch {
        return writeJson(hc, .bad_request, "{\"error\":\"bad activity\"}");
    };

    // AP-25: refuse activities from a blocked actor. The check uses
    // the local recipient (if any) as the "target" side of the
    // block.
    if (isBlocked(db, act.actor)) {
        return writeJson(hc, .forbidden, "{\"error\":\"blocked\"}");
    }

    // Optional signature verify: best effort. If we have a key cache +
    // workers + a signature header, try to verify; if not, the activity
    // is still accepted into the inbox but not fanned out (Tiger Style
    // soft acceptance — see PROTOCOL_AUDIT AP-C2 for the strict mode
    // that will land alongside the key-fetch HTTPS client).
    var verified = false;
    if (hc.request.header("Signature")) |sig_hdr| sig_block: {
        const pool = st.workers orelse break :sig_block;
        const parsed = sig.parseCavage(sig_hdr) catch break :sig_block;
        // AP-5: enforce signature freshness if the params carry it.
        // Default policy: ±300 s skew, 12 h max age. Soft mode logs +
        // skips fanout; strict mode below rejects with 401.
        sig.checkFreshness(&parsed, st.clock.wallUnix(), .{}) catch break :sig_block;
        // AP-20: replay window. Re-presenting the same signature within
        // the window (default 600 s) is a replay attempt — reject hard.
        const replay = state_mod.replayCache();
        const now_unix = st.clock.wallUnix();
        if (replay.seenBefore(parsed.key_id, parsed.signature_b64, now_unix)) {
            return writeJson(hc, .unauthorized, "{\"error\":\"signature replay\"}");
        }
        const pq = hc.request.pathAndQuery();
        const req_view: sig.RequestView = .{
            .method = hc.request.method_raw,
            .path = pq.path,
            .target_uri = "",
            .host = hc.request.header("Host") orelse st.hostname(),
            .date = hc.request.header("Date") orelse "",
            .digest_legacy = hc.request.header("Digest") orelse "",
            .content_digest = hc.request.header("Content-Digest") orelse "",
        };
        // AP-15: verify against the resolved main key; on failure, try
        // any published extra keys (FEP-d36d Multikey rotation) whose
        // keyId matches — "tries each key in turn".
        var ok = false;
        if (key_cache.resolve(&st.keys, pool, st.clock, parsed.key_id)) |pk| {
            if (sig.verify(&parsed, &req_view, &pk)) |_| ok = true else |_| {}
        } else |_| {}
        if (!ok) {
            if (st.dbHandle()) |xdb| ok = verifyWithExtraKey(xdb, &parsed, &req_view);
        }
        if (!ok) break :sig_block;
        replay.record(parsed.key_id, parsed.signature_b64, now_unix);
        verified = true;
    }

    // AP-21: optional Data Integrity (LD-proof) verification. Strictly
    // additive — it can only raise confidence, never bypass. Off unless
    // AP_LD_PROOF=1; resolves the proof's did:key verificationMethod and
    // verifies the eddsa-jcs-2022 signature over the raw body.
    if (!verified and ld_proof.enabled() and hc.request.body.len > 0) {
        var ld_scratch: [32 * 1024]u8 = undefined;
        if (ld_proof.verifyDocument(hc.request.body, &ld_scratch)) verified = true;
    }

    // G4: strict signature mode rejects unverified activities.
    if (state_mod.isStrictHttpSig() and !verified) {
        return writeJson(hc, .unauthorized, "{\"error\":\"signature required\"}");
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
        .local_host = st.hostname(),
        .raw_body = body,
    };
    inbox.dispatch(&env, &eff) catch |err| switch (err) {
        error.InboxRejected => return writeJson(hc, .bad_request, "{\"error\":\"inbox rejected\"}"),
        error.BadObject => return writeJson(hc, .bad_request, "{\"error\":\"bad object\"}"),
        error.UnsupportedActivity, error.UnknownActor => return writeJson(hc, .bad_request, "{\"error\":\"unsupported\"}"),
    };

    drainSideEffects(db, st, body, eff.slice()) catch {};

    // W5.2: notify the protocol-relay hook (if registered) so the
    // activity is mirrored into the AT side of the bridge. The hook
    // is a no-op when no relay is running; failures inside are
    // swallowed at the relay — they do not affect the inbox
    // response.
    if (inbox.currentRelayInboxHook()) |hook| hook(&act, body, db, st.clock);

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
                _ = recordFollow(db, rf.from_actor, rf.to_actor, "pending", rf.follow_iri) catch {};
            },
            .accept_follow => |af| {
                _ = recordFollow(db, af.from_actor, af.to_actor, "accepted", "") catch {};
            },
            .reject_follow => |rj| {
                _ = recordFollow(db, rj.from_actor, rj.to_actor, "rejected", "") catch {};
            },
            .tombstone_object => |tomb| {
                _ = recordTombstone(db, st.clock, tomb.id, tomb.former_type) catch {};
            },
            .undo_by_iri => |un| {
                _ = applyUndoByIri(db, un.iri) catch {};
            },
            .collection_add => |ca| {
                _ = collectionAdd(db, st.clock, ca.collection, ca.object_iri, ca.actor) catch {};
            },
            .collection_remove => |cr| {
                _ = collectionRemove(db, cr.collection, cr.object_iri) catch {};
            },
            .forward_to_followers => |fwd| {
                _ = forwardToLocalFollowers(db, st, fwd.collection_url, fwd.raw_body) catch {};
            },
            .record_block => |b| {
                _ = recordBlock(db, st.clock, b.actor, b.target, b.activity_id) catch {};
            },
            .record_move => |m| {
                _ = recordMove(db, st.clock, m.old_actor, m.new_actor) catch {};
            },
            .record_tag => |t| {
                _ = recordTag(db, t.activity_iri, t.kind, t.name, t.href) catch {};
            },
            .record_poll_vote => |v| {
                _ = recordPollVote(db, st.clock, v.activity_iri, v.question_iri, v.actor, v.option_name) catch {};
            },
            .record_attachment => |a| {
                _ = recordAttachment(db, a.object_iri, a.url, a.media_type, a.name) catch {};
            },
            else => {},
        }
    }
}

// AP-16: record a poll vote (idempotent on (question, actor, option)).
fn recordPollVote(db: *c.sqlite3, clock: core.clock.Clock, activity_iri: []const u8, question_iri: []const u8, actor: []const u8, option_name: []const u8) !void {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "INSERT OR IGNORE INTO ap_poll_votes (activity_iri, question_iri, actor, option_name, created_at) VALUES (?,?,?,?,?)";
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, activity_iri.ptr, @intCast(activity_iri.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 2, question_iri.ptr, @intCast(question_iri.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 3, actor.ptr, @intCast(actor.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 4, option_name.ptr, @intCast(option_name.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(stmt, 5, clock.wallUnix());
    _ = c.sqlite3_step(stmt.?);
}

// AP-23: record a media attachment for an inbound object (idempotent on
// (object_iri, url)).
fn recordAttachment(db: *c.sqlite3, object_iri: []const u8, url: []const u8, media_type: []const u8, name: []const u8) !void {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "INSERT OR IGNORE INTO ap_attachments (object_iri, url, media_type, name) VALUES (?,?,?,?)";
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, object_iri.ptr, @intCast(object_iri.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 2, url.ptr, @intCast(url.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 3, media_type.ptr, @intCast(media_type.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 4, name.ptr, @intCast(name.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_step(stmt.?);
}

// AP-15: try every published extra key whose `key_id` matches the
// signature's keyId (FEP-d36d Multikey rotation). Returns true on the
// first key that verifies.
fn verifyWithExtraKey(db: *c.sqlite3, parsed: *const sig.Parsed, req_view: *const sig.RequestView) bool {
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "SELECT public_pem FROM ap_actor_extra_keys WHERE key_id = ?", -1, &stmt, null) != c.SQLITE_OK) return false;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, parsed.key_id.ptr, @intCast(parsed.key_id.len), c.sqliteTransientAsDestructor());
    const kid = keys.KeyId.fromSlice(parsed.key_id) catch return false;
    var guard: u32 = 0;
    while (c.sqlite3_step(stmt.?) == c.SQLITE_ROW and guard < 16) : (guard += 1) {
        const p = c.sqlite3_column_text(stmt, 0);
        const n: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
        if (p == null or n == 0) continue;
        const pem = p[0..n];
        const pk = keys.parsePublicKeyPem(pem, kid) catch continue;
        if (sig.verify(parsed, req_view, &pk)) |_| return true else |_| {}
    }
    return false;
}

// AP-25: check whether any local actor has blocked `actor`. Used by
// the inbox handler to reject activities from blocked peers.
fn isBlocked(db: *c.sqlite3, actor: []const u8) bool {
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "SELECT 1 FROM ap_blocks WHERE target = ? LIMIT 1", -1, &stmt, null) != c.SQLITE_OK) return false;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, actor.ptr, @intCast(actor.len), c.sqliteTransientAsDestructor());
    return c.sqlite3_step(stmt) == c.SQLITE_ROW;
}

fn recordBlock(db: *c.sqlite3, clock: core.clock.Clock, actor: []const u8, target: []const u8, activity_id: []const u8) !void {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql =
        \\INSERT INTO ap_blocks (actor, target, activity_id, created_at)
        \\VALUES (?,?,?,?)
        \\ON CONFLICT (actor, target) DO NOTHING
    ;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, actor.ptr, @intCast(actor.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 2, target.ptr, @intCast(target.len), c.sqliteTransientAsDestructor());
    if (activity_id.len > 0) {
        _ = c.sqlite3_bind_text(stmt, 3, activity_id.ptr, @intCast(activity_id.len), c.sqliteTransientAsDestructor());
    } else {
        _ = c.sqlite3_bind_null(stmt, 3);
    }
    _ = c.sqlite3_bind_int64(stmt, 4, clock.wallUnix());
    _ = c.sqlite3_step(stmt);
}

fn recordMove(db: *c.sqlite3, clock: core.clock.Clock, old_actor: []const u8, new_actor: []const u8) !void {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql =
        \\INSERT INTO ap_actor_moves (old_actor, new_actor, moved_at)
        \\VALUES (?,?,?)
        \\ON CONFLICT (old_actor) DO UPDATE SET new_actor = excluded.new_actor, moved_at = excluded.moved_at
    ;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, old_actor.ptr, @intCast(old_actor.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 2, new_actor.ptr, @intCast(new_actor.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(stmt, 3, clock.wallUnix());
    _ = c.sqlite3_step(stmt);
}

fn recordTag(db: *c.sqlite3, activity_iri: []const u8, kind: []const u8, name: []const u8, href: []const u8) !void {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql =
        \\INSERT INTO ap_tags (activity_iri, kind, name, href)
        \\VALUES (?,?,?,?)
        \\ON CONFLICT (activity_iri, kind, name) DO NOTHING
    ;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, activity_iri.ptr, @intCast(activity_iri.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 2, kind.ptr, @intCast(kind.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 3, name.ptr, @intCast(name.len), c.sqliteTransientAsDestructor());
    if (href.len > 0) {
        _ = c.sqlite3_bind_text(stmt, 4, href.ptr, @intCast(href.len), c.sqliteTransientAsDestructor());
    } else {
        _ = c.sqlite3_bind_null(stmt, 4);
    }
    _ = c.sqlite3_step(stmt);
}

// AP-3: forward the supplied raw activity body to each follower's
// inbox. Resolves the local actor from the collection URL and
// enqueues one outbox row per follower row in `ap_follows` whose
// `followee` matches the actor.
fn forwardToLocalFollowers(db: *c.sqlite3, st: *state_mod.State, collection_url: []const u8, raw: []const u8) !void {
    // collection_url ends with `/followers`; the part before is the
    // actor's IRI.
    const suffix = "/followers";
    if (!std.mem.endsWith(u8, collection_url, suffix)) return;
    const actor_uri = collection_url[0 .. collection_url.len - suffix.len];

    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "SELECT follower FROM ap_follows WHERE followee = ? AND state = 'accepted'";
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, actor_uri.ptr, @intCast(actor_uri.len), c.sqliteTransientAsDestructor());

    var enq: ?*c.sqlite3_stmt = null;
    const enq_sql =
        \\INSERT INTO ap_federation_outbox
        \\  (target_inbox, shared_inbox, payload, key_id, attempts, next_attempt_at, state, inserted_at)
        \\VALUES (?, NULL, ?, ?, 0, ?, 'pending', ?)
    ;
    if (c.sqlite3_prepare_v2(db, enq_sql, -1, &enq, null) != c.SQLITE_OK) return;
    defer _ = c.sqlite3_finalize(enq);

    const now = st.clock.wallUnix();
    // Build the local actor's keyId for signing the forwarded post.
    var keyid_buf: [320]u8 = undefined;
    const keyid = std.fmt.bufPrint(&keyid_buf, "{s}#main-key", .{actor_uri}) catch return;

    var inbox_buf: [320]u8 = undefined;
    var n: u32 = 0;
    while (n < 64) : (n += 1) {
        const rc = c.sqlite3_step(stmt.?);
        if (rc == c.SQLITE_DONE) break;
        if (rc != c.SQLITE_ROW) break;
        const f_ptr = c.sqlite3_column_text(stmt, 0);
        const f_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
        if (f_len == 0 or f_ptr == null) continue;
        const inbox_target = std.fmt.bufPrint(&inbox_buf, "{s}/inbox", .{f_ptr[0..f_len]}) catch continue;

        _ = c.sqlite3_reset(enq);
        _ = c.sqlite3_clear_bindings(enq);
        _ = c.sqlite3_bind_text(enq, 1, inbox_target.ptr, @intCast(inbox_target.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_blob(enq, 2, raw.ptr, @intCast(raw.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_text(enq, 3, keyid.ptr, @intCast(keyid.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_int64(enq, 4, now);
        _ = c.sqlite3_bind_int64(enq, 5, now);
        _ = c.sqlite3_step(enq);
    }
}

// AP-8: collection membership helpers. Keyed on (collection, object)
// so re-Add is a no-op; Remove deletes the row. Featured / liked /
// bookmarks all share this table by collection IRI.
fn collectionAdd(db: *c.sqlite3, clock: core.clock.Clock, collection: []const u8, object: []const u8, actor: []const u8) !void {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql =
        \\INSERT INTO ap_collection_items (collection, object_iri, actor, added_at)
        \\VALUES (?,?,?,?)
        \\ON CONFLICT (collection, object_iri) DO NOTHING
    ;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, collection.ptr, @intCast(collection.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 2, object.ptr, @intCast(object.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 3, actor.ptr, @intCast(actor.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(stmt, 4, clock.wallUnix());
    _ = c.sqlite3_step(stmt);
}

// AP-14: count Like activities authored by the actor. Used by
// `/users/:u/liked` (FEP-c648).
fn countLikedByActor(db: *c.sqlite3, actor_iri: []const u8) i64 {
    // `ap_activities` stores `type` as a tag string; we recorded
    // `'like'` via `@tagName(.like)`. Filter on that + the actor IRI.
    _ = actor_iri; // current schema doesn't index activities by actor IRI directly
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM ap_activities WHERE type = 'like'", -1, &stmt, null) != c.SQLITE_OK) return 0;
    defer _ = c.sqlite3_finalize(stmt);
    if (c.sqlite3_step(stmt) != c.SQLITE_ROW) return 0;
    return c.sqlite3_column_int64(stmt, 0);
}

fn countCollectionItems(db: *c.sqlite3, collection: []const u8) i64 {
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM ap_collection_items WHERE collection = ?", -1, &stmt, null) != c.SQLITE_OK) return 0;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, collection.ptr, @intCast(collection.len), c.sqliteTransientAsDestructor());
    if (c.sqlite3_step(stmt) != c.SQLITE_ROW) return 0;
    return c.sqlite3_column_int64(stmt, 0);
}

fn collectionRemove(db: *c.sqlite3, collection: []const u8, object: []const u8) !void {
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "DELETE FROM ap_collection_items WHERE collection = ? AND object_iri = ?", -1, &stmt, null) != c.SQLITE_OK) return;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, collection.ptr, @intCast(collection.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 2, object.ptr, @intCast(object.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_step(stmt);
}

// AP-6: drainer half of the Undo flow. Look up the original activity
// row by its `ap_id`; on the type, fan out to:
//   * Follow → delete from `ap_follows` by `follow_iri` (which the
//     Follow path persisted).
//   * Like / Announce → delete the row from `ap_activities` so it no
//     longer appears in counters / timelines.
// Unknown / missing → no-op (we still recorded the Undo itself via
// `recordActivity`, so peers can audit the receipt).
fn applyUndoByIri(db: *c.sqlite3, iri: []const u8) !void {
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "SELECT type FROM ap_activities WHERE ap_id = ?", -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return;
    }
    _ = c.sqlite3_bind_text(stmt, 1, iri.ptr, @intCast(iri.len), c.sqliteTransientAsDestructor());
    const rc = c.sqlite3_step(stmt.?);
    var kind_buf: [32]u8 = undefined;
    var kind_len: usize = 0;
    if (rc == c.SQLITE_ROW) {
        const p = c.sqlite3_column_text(stmt, 0);
        const n: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
        const cap = @min(n, kind_buf.len);
        if (cap > 0) @memcpy(kind_buf[0..cap], p[0..cap]);
        kind_len = cap;
    }
    _ = c.sqlite3_finalize(stmt);
    if (kind_len == 0) return; // no record of the original — nothing to undo

    const kind = kind_buf[0..kind_len];
    if (std.mem.eql(u8, kind, "follow")) {
        var d: ?*c.sqlite3_stmt = null;
        _ = c.sqlite3_prepare_v2(db, "DELETE FROM ap_follows WHERE follow_iri = ?", -1, &d, null);
        defer _ = c.sqlite3_finalize(d);
        _ = c.sqlite3_bind_text(d, 1, iri.ptr, @intCast(iri.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_step(d.?);
    } else if (std.mem.eql(u8, kind, "like") or std.mem.eql(u8, kind, "announce")) {
        var d: ?*c.sqlite3_stmt = null;
        _ = c.sqlite3_prepare_v2(db, "DELETE FROM ap_activities WHERE ap_id = ?", -1, &d, null);
        defer _ = c.sqlite3_finalize(d);
        _ = c.sqlite3_bind_text(d, 1, iri.ptr, @intCast(iri.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_step(d.?);
    }
    // Other types (create/update/delete/accept/reject/undo) are not
    // reversible via Undo per spec; we silently drop.
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

fn recordFollow(
    db: *c.sqlite3,
    follower: []const u8,
    followee: []const u8,
    state: []const u8,
    follow_iri: []const u8,
) !void {
    var stmt: ?*c.sqlite3_stmt = null;
    // AP-6: also persist the Follow activity IRI so a later
    // `Undo{Follow}` can locate this row. On state transitions
    // (pending → accepted etc.) keep the original IRI.
    const sql =
        \\INSERT INTO ap_follows(follower, followee, state, accepted_at, follow_iri)
        \\VALUES (?, ?, ?, NULL, ?)
        \\ON CONFLICT(follower, followee) DO UPDATE
        \\  SET state = excluded.state,
        \\      follow_iri = COALESCE(NULLIF(excluded.follow_iri, ''), ap_follows.follow_iri)
    ;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return;
    }
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, follower.ptr, @intCast(follower.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 2, followee.ptr, @intCast(followee.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 3, state.ptr, @intCast(state.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 4, follow_iri.ptr, @intCast(follow_iri.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_step(stmt);
}

fn recordTombstone(db: *c.sqlite3, clock: core.clock.Clock, uri: []const u8, former_type: []const u8) !void {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "INSERT OR REPLACE INTO ap_tombstones(uri, deleted_at, former_type) VALUES (?, ?, ?)";
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return;
    }
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, uri.ptr, @intCast(uri.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(stmt, 2, clock.wallUnix());
    if (former_type.len > 0) {
        _ = c.sqlite3_bind_text(stmt, 3, former_type.ptr, @intCast(former_type.len), c.sqliteTransientAsDestructor());
    } else {
        _ = c.sqlite3_bind_null(stmt, 3);
    }
    _ = c.sqlite3_step(stmt);
}

// ── Collection handlers ───────────────────────────────────────────────

fn handleOutbox(hc: *HandlerContext) anyerror!void {
    try renderCollection(hc, .outbox);
}

// AP-1: C2S outbox POST. Accepts an activity from an authenticated
// local user and records it in `ap_activities`. The Mastodon API +
// the AP signing path then federate it out.
//
// Authentication: a Bearer JWT issued by the Mastodon OAuth server.
// We accept any token shaped as `Bearer <opaque>` and look the
// owning user up by token via the Mastodon plugin's auth path. For
// now we require the request to carry an `X-Local-User: <username>`
// header that the API gateway sets after auth — keeping AP-1
// decoupled from the Mastodon plugin's internals. Operators who
// don't run a gateway can wire OAuth verification directly.
fn handleOutboxPost(hc: *HandlerContext) anyerror!void {
    const st = state_mod.get();
    const db = st.dbHandle() orelse return writeJson(hc, .service_unavailable, "{\"error\":\"db not ready\"}");
    const username = hc.params.get("u") orelse return writeJson(hc, .bad_request, "{\"error\":\"missing user\"}");
    const owner = loadUser(db, username) orelse return writeJson(hc, .not_found, "{\"error\":\"unknown user\"}");

    // Caller must prove they are the owner. The simplest contract:
    // `X-Local-User: <username>` injected by a trusted gateway. When
    // the header is absent we deny; production deployments wire OAuth
    // bearer verification here.
    const auth_user = hc.request.header("X-Local-User") orelse
        return writeJson(hc, .unauthorized, "{\"error\":\"auth required\"}");
    if (!std.mem.eql(u8, auth_user, owner.username())) {
        return writeJson(hc, .forbidden, "{\"error\":\"not your outbox\"}");
    }

    const body = hc.request.body;
    if (body.len == 0) return writeJson(hc, .bad_request, "{\"error\":\"empty body\"}");

    const act = activity_mod.parse(body) catch {
        return writeJson(hc, .bad_request, "{\"error\":\"bad activity\"}");
    };
    // The actor on the activity must match the local user.
    var actor_buf: [320]u8 = undefined;
    const expected_actor = std.fmt.bufPrint(&actor_buf, "https://{s}/users/{s}", .{ st.hostname(), owner.username() }) catch
        return writeJson(hc, .internal, "{\"error\":\"actor fmt\"}");
    if (!std.mem.eql(u8, act.actor, expected_actor)) {
        return writeJson(hc, .forbidden, "{\"error\":\"actor mismatch\"}");
    }

    // Record the activity. Recipient resolution + delivery rides on
    // the existing outbox worker via `enqueueDeliveries` when the
    // activity carries explicit `to`/`cc` addressing.
    _ = recordActivity(db, st.clock, act.id, act.actor, act.activity_type, body) catch {};

    // Return 201 + a `Location` pointing at the (synthetic) activity
    // IRI. Production would mint a fresh per-activity URI; for now
    // we echo `act.id` if it was supplied, else a generated one.
    const activity_iri = if (act.id.len > 0) act.id else expected_actor;
    var loc_buf: [320]u8 = undefined;
    const loc_value = std.fmt.bufPrint(&loc_buf, "{s}", .{activity_iri}) catch
        return writeJson(hc, .internal, "{\"error\":\"loc\"}");
    try hc.response.startStatus(.created);
    try hc.response.header("Content-Type", "application/activity+json; charset=utf-8");
    try hc.response.header("Location", loc_value);
    const body_response = "{\"status\":\"accepted\"}";
    try hc.response.headerFmt("Content-Length", "{d}", .{body_response.len});
    try hc.response.header("Connection", "close");
    try hc.response.finishHeaders();
    try hc.response.body(body_response);
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

fn handleLiked(hc: *HandlerContext) anyerror!void {
    try renderCollection(hc, .liked);
}

/// Minimal query-param lookup (no URL-decoding needed for `page`).
/// Local to avoid a cross-plugin import of `atproto.xrpc`.
fn queryParam(query: []const u8, name: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i < query.len) {
        const seg_end = std.mem.indexOfScalarPos(u8, query, i, '&') orelse query.len;
        const seg = query[i..seg_end];
        if (std.mem.indexOfScalar(u8, seg, '=')) |eq| {
            if (std.mem.eql(u8, seg[0..eq], name)) return seg[eq + 1 ..];
        } else if (std.mem.eql(u8, seg, name)) {
            return "";
        }
        i = seg_end + 1;
    }
    return null;
}

/// AP-7: type-erased iterator over a bound page query. Each `next`
/// steps the statement and emits the column-0 IRI as a quoted JSON
/// string; null/empty cells (e.g. a Like with no object) are skipped.
const PageIter = struct {
    stmt: ?*c.sqlite3_stmt,
    /// Latch: once the statement reaches a non-row result we must NOT
    /// step again. `prepare_v2` auto-resets a DONE statement on the
    /// next `step`, which would silently re-run the query from row 1 —
    /// breaking `writePage`'s has-more probe.
    done: bool = false,

    fn next(state: ?*anyopaque, out: []u8) ?[]const u8 {
        const self: *PageIter = @ptrCast(@alignCast(state.?));
        if (self.done) return null;
        while (true) {
            if (c.sqlite3_step(self.stmt) != c.SQLITE_ROW) {
                self.done = true;
                return null;
            }
            const p = c.sqlite3_column_text(self.stmt, 0);
            const n: usize = @intCast(c.sqlite3_column_bytes(self.stmt, 0));
            if (n == 0 or p == null) continue; // skip null/empty cells
            if (out.len < n + 2) return null;
            out[0] = '"';
            @memcpy(out[1 .. 1 + n], p[0..n]);
            out[1 + n] = '"';
            return out[0 .. n + 2];
        }
    }
};

/// Prepare + bind the page query for `kind`. Binds `limit`
/// (`max_page_items + 1`, so `writePage` can probe for a `next` link)
/// and `offset`. Returns null on prepare failure.
fn preparePageStmt(
    db: *c.sqlite3,
    kind: collections.CollectionKind,
    actor_id: i64,
    actor_uri: []const u8,
    featured_uri: []const u8,
    limit: i64,
    offset: i64,
) ?*c.sqlite3_stmt {
    var stmt: ?*c.sqlite3_stmt = null;
    const transient = c.sqliteTransientAsDestructor();
    switch (kind) {
        .outbox => {
            const sql = "SELECT ap_id FROM ap_activities WHERE actor_id = ? ORDER BY published DESC, id DESC LIMIT ? OFFSET ?";
            if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return null;
            _ = c.sqlite3_bind_int64(stmt, 1, actor_id);
            _ = c.sqlite3_bind_int64(stmt, 2, limit);
            _ = c.sqlite3_bind_int64(stmt, 3, offset);
        },
        .followers => {
            const sql = "SELECT follower FROM ap_follows WHERE followee = ? AND state='accepted' ORDER BY id LIMIT ? OFFSET ?";
            if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return null;
            _ = c.sqlite3_bind_text(stmt, 1, actor_uri.ptr, @intCast(actor_uri.len), transient);
            _ = c.sqlite3_bind_int64(stmt, 2, limit);
            _ = c.sqlite3_bind_int64(stmt, 3, offset);
        },
        .following => {
            const sql = "SELECT followee FROM ap_follows WHERE follower = ? AND state='accepted' ORDER BY id LIMIT ? OFFSET ?";
            if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return null;
            _ = c.sqlite3_bind_text(stmt, 1, actor_uri.ptr, @intCast(actor_uri.len), transient);
            _ = c.sqlite3_bind_int64(stmt, 2, limit);
            _ = c.sqlite3_bind_int64(stmt, 3, offset);
        },
        .featured => {
            const sql = "SELECT object_iri FROM ap_collection_items WHERE collection = ? ORDER BY added_at DESC LIMIT ? OFFSET ?";
            if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return null;
            _ = c.sqlite3_bind_text(stmt, 1, featured_uri.ptr, @intCast(featured_uri.len), transient);
            _ = c.sqlite3_bind_int64(stmt, 2, limit);
            _ = c.sqlite3_bind_int64(stmt, 3, offset);
        },
        .liked => {
            // Mirrors `countLikedByActor`'s current schema limitation
            // (Like activities aren't indexed by actor IRI yet).
            const sql = "SELECT object_id FROM ap_activities WHERE type = 'like' AND object_id IS NOT NULL ORDER BY published DESC, id DESC LIMIT ? OFFSET ?";
            if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return null;
            _ = c.sqlite3_bind_int64(stmt, 1, limit);
            _ = c.sqlite3_bind_int64(stmt, 2, offset);
        },
    }
    return stmt;
}

/// AP-15: encode an Ed25519 public-key PEM as a `publicKeyMultibase`
/// string (`z` + base58btc(multicodec-0xed01 ‖ raw32)). Returns null for
/// a missing / non-Ed25519 / unparseable key.
fn actorKeyMultibase(pem: []const u8, out: []u8) ?[]const u8 {
    if (pem.len == 0) return null;
    const kid = keys.KeyId.fromSlice("k") catch return null;
    const pk = keys.parsePublicKeyPem(pem, kid) catch return null;
    if (pk.algo != .ed25519) return null;
    var mc: [34]u8 = undefined;
    mc[0] = 0xed;
    mc[1] = 0x01;
    mc[2..34].* = pk.ed25519Bytes();
    if (out.len < 1) return null;
    out[0] = 'z';
    const n = core.crypto.multibase.base58btcEncode(&mc, out[1..]) catch return null;
    return out[0 .. 1 + n];
}

fn renderCollection(hc: *HandlerContext, kind: collections.CollectionKind) !void {
    const st = state_mod.get();
    const username = hc.params.get("u") orelse return writeJson(hc, .bad_request, "{\"error\":\"missing user\"}");
    const db = st.dbHandle() orelse return writeJson(hc, .service_unavailable, "{\"error\":\"db not ready\"}");
    const user = loadUser(db, username) orelse return writeJson(hc, .not_found, "{\"error\":\"unknown user\"}");

    // Build URI for follower/following filter.
    var actor_uri_buf: [256]u8 = undefined;
    const actor_uri = std.fmt.bufPrint(&actor_uri_buf, "https://{s}/users/{s}", .{ st.hostname(), user.username() }) catch return writeJson(hc, .internal, "{\"error\":\"uri buf\"}");

    // AP-11: featured collection counts entries in `ap_collection_items`
    // for the actor's `/collections/featured` URL.
    var featured_uri_buf: [320]u8 = undefined;
    const featured_uri = std.fmt.bufPrint(&featured_uri_buf,
        "https://{s}/users/{s}/collections/featured",
        .{ st.hostname(), user.username() },
    ) catch return writeJson(hc, .internal, "{\"error\":\"uri buf\"}");

    // AP-7: `?page=N` serves an OrderedCollectionPage of up to
    // `max_page_items` real items with next/prev links; absent `page`
    // serves the index document pointing at `?page=1`.
    if (queryParam(hc.request.pathAndQuery().query, "page")) |page_str| {
        const parsed = std.fmt.parseInt(u32, page_str, 10) catch 1;
        const page: u32 = if (parsed == 0) 1 else parsed;
        const offset: i64 = @intCast((page - 1) * collections.max_page_items);
        const limit: i64 = collections.max_page_items + 1;
        const stmt = preparePageStmt(db, kind, user.id, actor_uri, featured_uri, limit, offset) orelse
            return writeJson(hc, .internal, "{\"error\":\"page query\"}");
        defer _ = c.sqlite3_finalize(stmt);
        var iter = PageIter{ .stmt = stmt };
        var page_body: [max_response_bytes]u8 = undefined;
        const page_out = collections.writePage(.{
            .hostname = st.hostname(),
            .actor_username = user.username(),
            .kind = kind,
            .total_items = 0, // page docs don't emit totalItems
        }, page, @ptrCast(&iter), PageIter.next, &page_body) catch return writeJson(hc, .internal, "{\"error\":\"collection buf\"}");
        return writeJsonLd(hc, .ok, page_out);
    }

    const total: u64 = switch (kind) {
        .outbox => @intCast(countActivities(db, user.id)),
        .followers => @intCast(countFollows(db, "followee", actor_uri)),
        .following => @intCast(countFollows(db, "follower", actor_uri)),
        .featured => @intCast(countCollectionItems(db, featured_uri)),
        // AP-14: count Like activities issued by this actor.
        .liked => @intCast(countLikedByActor(db, actor_uri)),
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

// AP-30: serve `410 Gone` + Tombstone for any URL we've recorded a
// tombstone against. Mounts at `/users/:u/statuses/:id/activity`
// (Mastodon's canonical activity IRI shape) and at
// `/users/:u/statuses/:id` (the object IRI).
fn handleUserStatus(hc: *HandlerContext) anyerror!void {
    const st = state_mod.get();
    const db = st.dbHandle() orelse return writeJson(hc, .service_unavailable, "{\"error\":\"db not ready\"}");
    const username = hc.params.get("u") orelse return writeJson(hc, .bad_request, "{\"error\":\"missing user\"}");
    const id = hc.params.get("id") orelse return writeJson(hc, .bad_request, "{\"error\":\"missing id\"}");
    var uri_buf: [320]u8 = undefined;
    const uri = std.fmt.bufPrint(&uri_buf, "https://{s}/users/{s}/statuses/{s}", .{ st.hostname(), username, id }) catch
        return writeJson(hc, .internal, "{\"error\":\"uri buf\"}");
    if (isTombstoned(db, uri)) return writeTombstone(hc, db, uri);
    // Today we don't render local statuses via AP — the Mastodon API
    // handles object responses. Surface a 404 here rather than 410.
    return writeJson(hc, .not_found, "{\"error\":\"unknown\"}");
}

fn handleUserActivity(hc: *HandlerContext) anyerror!void {
    const st = state_mod.get();
    const db = st.dbHandle() orelse return writeJson(hc, .service_unavailable, "{\"error\":\"db not ready\"}");
    const username = hc.params.get("u") orelse return writeJson(hc, .bad_request, "{\"error\":\"missing user\"}");
    const id = hc.params.get("id") orelse return writeJson(hc, .bad_request, "{\"error\":\"missing id\"}");
    var uri_buf: [320]u8 = undefined;
    const uri = std.fmt.bufPrint(&uri_buf, "https://{s}/users/{s}/statuses/{s}/activity", .{ st.hostname(), username, id }) catch
        return writeJson(hc, .internal, "{\"error\":\"uri buf\"}");
    if (isTombstoned(db, uri)) return writeTombstone(hc, db, uri);
    return writeJson(hc, .not_found, "{\"error\":\"unknown\"}");
}

pub fn register(router: *Router, plugin_index: u16) !void {
    try router.register(.get, "/.well-known/webfinger", handleWebFinger, plugin_index);
    try router.register(.get, "/.well-known/nodeinfo", handleNodeInfoJrd, plugin_index);
    try router.register(.get, "/nodeinfo/2.1", handleNodeInfo21, plugin_index);
    try router.register(.get, "/users/:u", handleUserActor, plugin_index);
    try router.register(.post, "/users/:u/inbox", handleUserInbox, plugin_index);
    try router.register(.get, "/users/:u/outbox", handleOutbox, plugin_index);
    try router.register(.post, "/users/:u/outbox", handleOutboxPost, plugin_index); // AP-1
    try router.register(.get, "/users/:u/followers", handleFollowers, plugin_index);
    try router.register(.get, "/users/:u/following", handleFollowing, plugin_index);
    try router.register(.get, "/users/:u/collections/featured", handleFeatured, plugin_index);
    try router.register(.get, "/users/:u/liked", handleLiked, plugin_index); // AP-14
    try router.register(.get, "/users/:u/statuses/:id", handleUserStatus, plugin_index); // AP-30
    try router.register(.get, "/users/:u/statuses/:id/activity", handleUserActivity, plugin_index); // AP-30
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

test "register binds the expected route count" {
    var r = Router.init();
    try register(&r, 0);
    // 10 base + AP-30 (×2 status/activity) + AP-14 (liked) + AP-1 outbox POST.
    try testing.expectEqual(@as(u32, 14), r.count);
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

test "AP-12: loadTombstone returns former_type + deleted timestamp" {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try @import("schema.zig").applyAllForTests(db);

    var sc = core.clock.SimClock.init(1_700_000_000);
    const clock = sc.clock();
    try recordTombstone(db, clock, "https://x/notes/1", "Note");

    const row = loadTombstone(db, "https://x/notes/1").?;
    try testing.expectEqualStrings("Note", row.formerType());
    try testing.expectEqual(@as(i64, 1_700_000_000), row.deleted_at_unix);
}

test "AP-12: formatIsoTime produces RFC 3339 second precision" {
    var buf: [24]u8 = undefined;
    const out = try formatIsoTime(1_700_000_000, &buf);
    try testing.expect(out.len >= 20);
    try testing.expect(std.mem.endsWith(u8, out, "Z"));
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
    try recordFollow(db, "a", "b", "pending", "https://a/activities/follow1");
    try recordFollow(db, "a", "b", "accepted", "");

    var stmt: ?*c.sqlite3_stmt = null;
    _ = c.sqlite3_prepare_v2(db, "SELECT state, follow_iri FROM ap_follows WHERE follower='a' AND followee='b'", -1, &stmt, null);
    defer _ = c.sqlite3_finalize(stmt);
    try testing.expect(c.sqlite3_step(stmt) == c.SQLITE_ROW);
    const sptr = c.sqlite3_column_text(stmt, 0);
    const slen: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
    try testing.expectEqualStrings("accepted", sptr[0..slen]);
    // AP-6: the original Follow IRI persists across state transitions.
    const iri_ptr = c.sqlite3_column_text(stmt, 1);
    const iri_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 1));
    try testing.expectEqualStrings("https://a/activities/follow1", iri_ptr[0..iri_len]);
}

test "AP-7: collection pagination walks followers across pages" {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try @import("schema.zig").applyAllForTests(db);

    const actor = "https://h/users/alice";
    const total = collections.max_page_items + 1; // 41 → spills to a 2nd page
    var i: u32 = 0;
    var fbuf: [64]u8 = undefined;
    while (i < total) : (i += 1) {
        const follower = try std.fmt.bufPrint(&fbuf, "https://peer/u{d}", .{i});
        try recordFollow(db, follower, actor, "accepted", "");
    }

    const limit: i64 = collections.max_page_items + 1;

    // Page 1: full page, a `next` link, no `prev`.
    {
        const stmt = preparePageStmt(db, .followers, 0, actor, "", limit, 0).?;
        defer _ = c.sqlite3_finalize(stmt);
        var iter = PageIter{ .stmt = stmt };
        var buf: [max_response_bytes]u8 = undefined;
        const out = try collections.writePage(.{
            .hostname = "h",
            .actor_username = "alice",
            .kind = .followers,
            .total_items = 0,
        }, 1, @ptrCast(&iter), PageIter.next, &buf);
        try testing.expect(std.mem.indexOf(u8, out, "\"OrderedCollectionPage\"") != null);
        try testing.expect(std.mem.indexOf(u8, out, "\"next\":\"https://h/users/alice/followers?page=2\"") != null);
        try testing.expect(std.mem.indexOf(u8, out, "\"prev\"") == null);
        try testing.expect(std.mem.indexOf(u8, out, "\"https://peer/u0\"") != null);
    }

    // Page 2: the remainder, a `prev` link, no `next`.
    {
        const stmt = preparePageStmt(db, .followers, 0, actor, "", limit, collections.max_page_items).?;
        defer _ = c.sqlite3_finalize(stmt);
        var iter = PageIter{ .stmt = stmt };
        var buf: [max_response_bytes]u8 = undefined;
        const out = try collections.writePage(.{
            .hostname = "h",
            .actor_username = "alice",
            .kind = .followers,
            .total_items = 0,
        }, 2, @ptrCast(&iter), PageIter.next, &buf);
        try testing.expect(std.mem.indexOf(u8, out, "\"prev\":\"https://h/users/alice/followers?page=1\"") != null);
        try testing.expect(std.mem.indexOf(u8, out, "\"next\"") == null);
    }
}

test "AP-6: applyUndoByIri removes Follow row by follow_iri" {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try @import("schema.zig").applyAllForTests(db);

    var sc = core.clock.SimClock.init(0);
    const clock = sc.clock();

    try recordFollow(db, "https://a", "https://b", "accepted", "https://a/acts/follow-xyz");
    try recordActivity(db, clock, "https://a/acts/follow-xyz", "https://a", .follow, "{}");

    try applyUndoByIri(db, "https://a/acts/follow-xyz");

    var stmt: ?*c.sqlite3_stmt = null;
    _ = c.sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM ap_follows WHERE follower='https://a'", -1, &stmt, null);
    defer _ = c.sqlite3_finalize(stmt);
    try testing.expect(c.sqlite3_step(stmt) == c.SQLITE_ROW);
    try testing.expectEqual(@as(i64, 0), c.sqlite3_column_int64(stmt, 0));
}

test "AP-6: applyUndoByIri removes Like activity row by ap_id" {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try @import("schema.zig").applyAllForTests(db);

    var sc = core.clock.SimClock.init(0);
    const clock = sc.clock();
    try recordActivity(db, clock, "https://a/acts/like1", "https://a", .like, "{}");

    try applyUndoByIri(db, "https://a/acts/like1");

    var stmt: ?*c.sqlite3_stmt = null;
    _ = c.sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM ap_activities WHERE ap_id='https://a/acts/like1'", -1, &stmt, null);
    defer _ = c.sqlite3_finalize(stmt);
    try testing.expect(c.sqlite3_step(stmt) == c.SQLITE_ROW);
    try testing.expectEqual(@as(i64, 0), c.sqlite3_column_int64(stmt, 0));
}

test "AP-6: applyUndoByIri on unknown IRI is a no-op" {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try @import("schema.zig").applyAllForTests(db);
    try applyUndoByIri(db, "https://nowhere/x");
}

test "AP-10: actor_type persists and renders" {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try @import("schema.zig").applyAllForTests(db);
    var em: [*c]u8 = null;
    _ = c.sqlite3_exec(db,
        "INSERT INTO ap_users(username, display_name, bio, is_locked, discoverable, indexable, created_at, actor_type) " ++
        "VALUES ('svc','Service Bot','',0,1,1,0,'Service')",
        null, null, &em);
    if (em != null) c.sqlite3_free(em);

    const u = loadUser(db, "svc") orelse return error.TestUserMissing;
    try testing.expectEqualStrings("Service", u.actorType());

    var body: [4096]u8 = undefined;
    const out = try actor_mod.writePerson(.{
        .hostname = "example.com",
        .username = u.username(),
        .public_key_pem = "",
        .actor_type = actor_mod.ActorType.parse(u.actorType()) orelse .person,
    }, &body);
    try testing.expect(std.mem.indexOf(u8, out, "\"type\":\"Service\"") != null);
}

test "AP-15: actor advertises a Multikey assertionMethod (FEP-d36d)" {
    const kid = try keys.KeyId.fromSlice("https://h/users/alice#main-key");
    const pair = try keys.generateEd25519FromSeed(kid, keys.testSeed(1));
    var pem_buf: [256]u8 = undefined;
    const pem_len = try keys.writeEd25519PublicPem(pair.public.ed25519Bytes(), &pem_buf);
    const pem = pem_buf[0..pem_len];

    var mb_buf: [80]u8 = undefined;
    const mb = actorKeyMultibase(pem, &mb_buf) orelse return error.NoMultibase;
    try testing.expect(mb[0] == 'z');

    var body: [max_response_bytes]u8 = undefined;
    const out = try actor_mod.writePerson(.{
        .hostname = "h",
        .username = "alice",
        .public_key_pem = pem,
        .assertion_multibase = mb,
    }, &body);
    try testing.expect(std.mem.indexOf(u8, out, "\"assertionMethod\":[") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"type\":\"Multikey\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"publicKeyMultibase\":\"z") != null);
}

test "AP-15: verifyWithExtraKey accepts a signature from a published rotation key" {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try @import("schema.zig").applyAllForTests(db);

    const kid = try keys.KeyId.fromSlice("kid");
    const pair = try keys.generateEd25519FromSeed(kid, keys.testSeed(2));
    var pem_buf: [256]u8 = undefined;
    const pem_len = try keys.writeEd25519PublicPem(pair.public.ed25519Bytes(), &pem_buf);
    const pem = pem_buf[0..pem_len];

    // Publish the key as an extra key keyed on "kid".
    {
        var stmt: ?*c.sqlite3_stmt = null;
        try testing.expect(c.sqlite3_prepare_v2(db, "INSERT INTO ap_actor_extra_keys(username, key_id, key_type, public_pem, created_at) VALUES ('alice','kid','ed25519',?,0)", -1, &stmt, null) == c.SQLITE_OK);
        defer _ = c.sqlite3_finalize(stmt);
        _ = c.sqlite3_bind_text(stmt, 1, pem.ptr, @intCast(pem.len), c.sqliteTransientAsDestructor());
        try testing.expect(c.sqlite3_step(stmt.?) == c.SQLITE_DONE);
    }

    // Sign a request with that key and confirm the extra-key path verifies it.
    const hdr = "keyId=\"kid\",algorithm=\"ed25519\",headers=\"(request-target) host date\",signature=\"AAAA\"";
    var p = try sig.parseCavage(hdr);
    p.algorithm = .ed25519;
    const req: sig.RequestView = .{
        .method = "POST",
        .path = "/inbox",
        .target_uri = "https://example.com/inbox",
        .host = "example.com",
        .date = "Thu, 19 Mar 2026 12:00:00 GMT",
    };
    var sig_buf: [128]u8 = undefined;
    p.signature_b64 = try sig.signEd25519(&p, &req, pair.private.ed25519SecretBytes(), &sig_buf);

    try testing.expect(verifyWithExtraKey(db, &p, &req));
    // A different keyId finds no extra key → false.
    var p2 = p;
    p2.key_id = "other";
    try testing.expect(!verifyWithExtraKey(db, &p2, &req));
}
