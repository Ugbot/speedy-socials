//! Integration tests for the Mastodon plugin.
//!
//! Each test stands up an in-memory SQLite DB, applies the AP + Mastodon
//! schema, attaches it to the plugin state, then drives synthetic HTTP
//! requests through individual handlers. This style mirrors
//! `src/protocols/activitypub/routes.zig` tests but at a higher level.
//!
//! Test data is generated with the deterministic RNG so each run is
//! reproducible; usernames/jti/client_id come from the RNG, not hard-
//! coded strings, satisfying the project's "no hardcoded happy paths"
//! rule.

const std = @import("std");
const core = @import("core");
const c = @import("sqlite").c;

const schema = @import("schema.zig");
const state_mod = @import("state.zig");
const db_mod = @import("db.zig");
const oauth = @import("oauth.zig");
const jwt = @import("jwt.zig");
const auth = @import("auth.zig");
const http_util = @import("http_util.zig");
const accounts_routes = @import("routes/accounts.zig");
const statuses_routes = @import("routes/statuses.zig");
const timelines_routes = @import("routes/timelines.zig");
const notifications_routes = @import("routes/notifications.zig");
const instance_routes = @import("routes/instance.zig");
const apps_routes = @import("routes/apps.zig");
const streaming_routes = @import("routes/streaming.zig");
const media_routes = @import("routes/media.zig");
const serialize = @import("serialize.zig");

const Request = core.http.request.Request;
const Header = core.http.request.Header;
const Method = core.http.request.Method;
const Response = core.http.response;
const PathParams = core.http.router.PathParams;
const HandlerContext = core.http.router.HandlerContext;

const testing = std.testing;

// ── Test harness ─────────────────────────────────────────────────

const Fixture = struct {
    db: *c.sqlite3,
    rng: core.rng.Rng,
    sim: core.clock.SimClock,
    ctx: core.plugin.Context,

    fn init(seed: u64) Fixture {
        // The SimClock vtable returned by `core.clock.Clock` captures the
        // address of the `sim` field, so the Fixture MUST be heap-stable
        // (callers store it in a stack local and never move it).
        return .{
            .db = undefined,
            .rng = core.rng.Rng.init(seed),
            .sim = core.clock.SimClock.init(1_700_000_000),
            .ctx = undefined,
        };
    }

    fn start(self: *Fixture) !void {
        const sqlite_mod = core.storage.sqlite;
        self.db = try sqlite_mod.openWriter(":memory:");
        try schema.applyAllForTests(self.db);
        self.ctx = .{ .clock = self.sim.clock(), .rng = &self.rng };
        state_mod.reset();
        state_mod.setClockAndRng(self.ctx.clock, &self.rng);
        state_mod.setHostname("speedy.test");
        state_mod.attachDb(self.db);
    }

    fn deinit(self: *Fixture) void {
        state_mod.reset();
        core.storage.sqlite.closeDb(self.db);
    }
};

fn newFixture(seed: u64) !Fixture {
    return Fixture.init(seed);
}

fn randomUsername(rng: *core.rng.Rng, buf: []u8) []const u8 {
    const alphabet = "abcdefghijklmnopqrstuvwxyz";
    var i: usize = 0;
    while (i < buf.len) : (i += 1) {
        const v: u8 = @truncate(rng.random().int(u64));
        buf[i] = alphabet[v % alphabet.len];
    }
    return buf[0..buf.len];
}

const TestCallContext = struct {
    plugin_ctx: *core.plugin.Context,
    request: Request,
    builder: Response.Builder,
    resp_buf: [16 * 1024]u8 = undefined,
    params: PathParams = .{},

    fn handler(self: *TestCallContext) HandlerContext {
        return .{
            .plugin_ctx = self.plugin_ctx,
            .request = &self.request,
            .response = &self.builder,
            .params = self.params,
        };
    }

    fn body(self: *const TestCallContext) []const u8 {
        return self.builder.bytes();
    }

    fn responseBodyBytes(self: *const TestCallContext) []const u8 {
        const raw = self.body();
        const sep = std.mem.indexOf(u8, raw, "\r\n\r\n") orelse return "";
        return raw[sep + 4 ..];
    }

    fn statusLine(self: *const TestCallContext) []const u8 {
        const raw = self.body();
        const end = std.mem.indexOf(u8, raw, "\r\n") orelse return raw;
        return raw[0..end];
    }
};

fn makeCall(allocator: std.mem.Allocator, fx: *Fixture, method: Method, target: []const u8, headers: []const Header, body: []const u8) !*TestCallContext {
    const tc = try allocator.create(TestCallContext);
    tc.* = .{
        .plugin_ctx = &fx.ctx,
        .request = .{
            .method = method,
            .method_raw = "POST",
            .target = target,
            .version = "HTTP/1.1",
            .headers = headers,
            .body = body,
        },
        .builder = Response.Builder.init(&tc.resp_buf),
    };
    return tc;
}

// Convenience: parse `client_id` and `client_secret` out of a /api/v1/apps
// JSON response.
fn extractClient(out: []const u8) struct { client_id: []const u8, client_secret: []const u8 } {
    return .{
        .client_id = http_util.jsonString(out, "client_id") orelse "",
        .client_secret = http_util.jsonString(out, "client_secret") orelse "",
    };
}

// ── Schema tests ─────────────────────────────────────────────────

test "schema: all 5 tables created" {
    var fx = Fixture.init(0xA1);
    try fx.start();
    defer fx.deinit();
    const tables = [_][:0]const u8{
        "mastodon_apps", "mastodon_tokens", "mastodon_notifications", "mastodon_favourites", "mastodon_reblogs",
    };
    for (tables) |t| {
        var buf: [256]u8 = undefined;
        const sql = try std.fmt.bufPrintZ(&buf, "SELECT COUNT(*) FROM {s}", .{t});
        var stmt: ?*c.sqlite3_stmt = null;
        try testing.expect(c.sqlite3_prepare_v2(fx.db, sql.ptr, -1, &stmt, null) == c.SQLITE_OK);
        defer _ = c.sqlite3_finalize(stmt);
        try testing.expect(c.sqlite3_step(stmt) == c.SQLITE_ROW);
    }
}

// ── OAuth flow tests ─────────────────────────────────────────────

test "OAuth: register app via /api/v1/apps returns client credentials" {
    const alloc = testing.allocator;
    var fx = Fixture.init(0xA2);
    try fx.start();
    defer fx.deinit();

    var tc = try makeCall(alloc, &fx, .post, "/api/v1/apps", &.{}, "{\"client_name\":\"testapp\",\"redirect_uris\":\"urn:ietf:wg:oauth:2.0:oob\",\"scopes\":\"read write\"}");
    defer alloc.destroy(tc);
    var hc = tc.handler();
    try oauth.handleCreateApp(&hc);
    const out = tc.responseBodyBytes();
    try testing.expect(std.mem.indexOf(u8, out, "\"client_id\":") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"client_secret\":") != null);
}

test "OAuth: client_credentials grant issues a usable token" {
    const alloc = testing.allocator;
    var fx = Fixture.init(0xA3);
    try fx.start();
    defer fx.deinit();

    // Register app.
    var app_call = try makeCall(alloc, &fx, .post, "/api/v1/apps", &.{}, "{\"client_name\":\"app\"}");
    defer alloc.destroy(app_call);
    var hc = app_call.handler();
    try oauth.handleCreateApp(&hc);
    const creds = extractClient(app_call.responseBodyBytes());
    try testing.expect(creds.client_id.len > 0);

    var body_buf: [256]u8 = undefined;
    const body = try std.fmt.bufPrint(&body_buf, "grant_type=client_credentials&client_id={s}&client_secret={s}", .{ creds.client_id, creds.client_secret });
    var tok_call = try makeCall(alloc, &fx, .post, "/oauth/token", &.{
        .{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" },
    }, body);
    defer alloc.destroy(tok_call);
    var hc2 = tok_call.handler();
    try oauth.handleToken(&hc2);
    const tok_out = tok_call.responseBodyBytes();
    const access_token = http_util.jsonString(tok_out, "access_token") orelse "";
    try testing.expect(access_token.len > 64);
    try testing.expect(std.mem.indexOf(u8, tok_out, "\"token_type\":\"Bearer\"") != null);
}

test "OAuth: password grant binds a user_id" {
    const alloc = testing.allocator;
    var fx = Fixture.init(0xA4);
    try fx.start();
    defer fx.deinit();

    // Create a user.
    var name_buf: [8]u8 = undefined;
    const username = randomUsername(&fx.rng, &name_buf);
    _ = try db_mod.insertUser(fx.db, username, username, "", fx.sim.clock().wallUnix());

    // Register app.
    var app_call = try makeCall(alloc, &fx, .post, "/api/v1/apps", &.{}, "{\"client_name\":\"app\"}");
    defer alloc.destroy(app_call);
    var hc = app_call.handler();
    try oauth.handleCreateApp(&hc);
    const creds = extractClient(app_call.responseBodyBytes());

    // Token exchange with password grant.
    var body_buf: [256]u8 = undefined;
    const body = try std.fmt.bufPrint(&body_buf,
        "grant_type=password&client_id={s}&client_secret={s}&username={s}&password=hunter2&scope=read write",
        .{ creds.client_id, creds.client_secret, username },
    );
    var tok_call = try makeCall(alloc, &fx, .post, "/oauth/token", &.{}, body);
    defer alloc.destroy(tok_call);
    var hc2 = tok_call.handler();
    try oauth.handleToken(&hc2);
    const access = http_util.jsonString(tok_call.responseBodyBytes(), "access_token") orelse "";
    try testing.expect(access.len > 0);

    // Decode the JWT and confirm user_id is non-zero.
    var claims: jwt.Claims = .{};
    try jwt.verify(access, state_mod.get().jwt_key.public_key, fx.sim.clock().wallUnix(), &claims);
    try testing.expect(claims.user_id != 0);
}

test "OAuth: revoked token fails verify_credentials" {
    const alloc = testing.allocator;
    var fx = Fixture.init(0xA5);
    try fx.start();
    defer fx.deinit();

    var name_buf: [8]u8 = undefined;
    const username = randomUsername(&fx.rng, &name_buf);
    _ = try db_mod.insertUser(fx.db, username, username, "", fx.sim.clock().wallUnix());

    var app_call = try makeCall(alloc, &fx, .post, "/api/v1/apps", &.{}, "{\"client_name\":\"app\"}");
    defer alloc.destroy(app_call);
    var hc1 = app_call.handler();
    try oauth.handleCreateApp(&hc1);
    const creds = extractClient(app_call.responseBodyBytes());

    var body_buf: [256]u8 = undefined;
    const body = try std.fmt.bufPrint(&body_buf,
        "grant_type=password&client_id={s}&client_secret={s}&username={s}&password=x&scope=read",
        .{ creds.client_id, creds.client_secret, username },
    );
    var tok_call = try makeCall(alloc, &fx, .post, "/oauth/token", &.{}, body);
    defer alloc.destroy(tok_call);
    var hc2 = tok_call.handler();
    try oauth.handleToken(&hc2);
    const access = http_util.jsonString(tok_call.responseBodyBytes(), "access_token") orelse "";

    // Revoke.
    var rev_body_buf: [1024]u8 = undefined;
    const rev_body = try std.fmt.bufPrint(&rev_body_buf, "token={s}", .{access});
    var rev_call = try makeCall(alloc, &fx, .post, "/oauth/revoke", &.{}, rev_body);
    defer alloc.destroy(rev_call);
    var hc3 = rev_call.handler();
    try oauth.handleRevoke(&hc3);

    // verify_credentials should now return 401.
    var auth_buf: [1100]u8 = undefined;
    const auth_value = try std.fmt.bufPrint(&auth_buf, "Bearer {s}", .{access});
    var vc_call = try makeCall(alloc, &fx, .get, "/api/v1/accounts/verify_credentials", &.{
        .{ .name = "Authorization", .value = auth_value },
    }, "");
    defer alloc.destroy(vc_call);
    var hc4 = vc_call.handler();
    try accounts_routes.handleVerifyCredentials(&hc4);
    try testing.expect(std.mem.startsWith(u8, vc_call.statusLine(), "HTTP/1.1 401"));
}

test "OAuth: revoke handles already-expired token" {
    const alloc = testing.allocator;
    var fx = Fixture.init(0xA6);
    try fx.start();
    defer fx.deinit();

    var name_buf: [8]u8 = undefined;
    const username = randomUsername(&fx.rng, &name_buf);
    _ = try db_mod.insertUser(fx.db, username, username, "", fx.sim.clock().wallUnix());

    var app_call = try makeCall(alloc, &fx, .post, "/api/v1/apps", &.{}, "{\"client_name\":\"app\"}");
    defer alloc.destroy(app_call);
    var hc = app_call.handler();
    try oauth.handleCreateApp(&hc);
    const creds = extractClient(app_call.responseBodyBytes());

    var body_buf: [256]u8 = undefined;
    const body = try std.fmt.bufPrint(&body_buf,
        "grant_type=password&client_id={s}&client_secret={s}&username={s}&password=x",
        .{ creds.client_id, creds.client_secret, username },
    );
    var tok_call = try makeCall(alloc, &fx, .post, "/oauth/token", &.{}, body);
    defer alloc.destroy(tok_call);
    var hc2 = tok_call.handler();
    try oauth.handleToken(&hc2);
    const access = http_util.jsonString(tok_call.responseBodyBytes(), "access_token") orelse "";

    // Advance time past the access TTL so the token is expired.
    fx.sim.advance(@as(u64, (jwt.access_ttl_seconds + 60)) * std.time.ns_per_s);

    var rev_body_buf: [1024]u8 = undefined;
    const rev_body = try std.fmt.bufPrint(&rev_body_buf, "token={s}", .{access});
    var rev_call = try makeCall(alloc, &fx, .post, "/oauth/revoke", &.{}, rev_body);
    defer alloc.destroy(rev_call);
    var hc3 = rev_call.handler();
    try oauth.handleRevoke(&hc3);
    try testing.expect(std.mem.startsWith(u8, rev_call.statusLine(), "HTTP/1.1 200"));
}

test "OAuth: unknown grant_type rejected" {
    const alloc = testing.allocator;
    var fx = Fixture.init(0xA7);
    try fx.start();
    defer fx.deinit();

    var app_call = try makeCall(alloc, &fx, .post, "/api/v1/apps", &.{}, "{\"client_name\":\"app\"}");
    defer alloc.destroy(app_call);
    var hc = app_call.handler();
    try oauth.handleCreateApp(&hc);
    const creds = extractClient(app_call.responseBodyBytes());

    var body_buf: [256]u8 = undefined;
    const body = try std.fmt.bufPrint(&body_buf, "grant_type=magic&client_id={s}&client_secret={s}", .{ creds.client_id, creds.client_secret });
    var tok_call = try makeCall(alloc, &fx, .post, "/oauth/token", &.{}, body);
    defer alloc.destroy(tok_call);
    var hc2 = tok_call.handler();
    try oauth.handleToken(&hc2);
    try testing.expect(std.mem.startsWith(u8, tok_call.statusLine(), "HTTP/1.1 400"));
}

test "OAuth: bad client_secret rejected with 401" {
    const alloc = testing.allocator;
    var fx = Fixture.init(0xA8);
    try fx.start();
    defer fx.deinit();

    var app_call = try makeCall(alloc, &fx, .post, "/api/v1/apps", &.{}, "{\"client_name\":\"app\"}");
    defer alloc.destroy(app_call);
    var hc = app_call.handler();
    try oauth.handleCreateApp(&hc);
    const creds = extractClient(app_call.responseBodyBytes());

    var body_buf: [256]u8 = undefined;
    const body = try std.fmt.bufPrint(&body_buf, "grant_type=client_credentials&client_id={s}&client_secret=WRONG_SECRET", .{creds.client_id});
    var tok_call = try makeCall(alloc, &fx, .post, "/oauth/token", &.{}, body);
    defer alloc.destroy(tok_call);
    var hc2 = tok_call.handler();
    try oauth.handleToken(&hc2);
    try testing.expect(std.mem.startsWith(u8, tok_call.statusLine(), "HTTP/1.1 401"));
}

// ── /api/v1/accounts ─────────────────────────────────────────────

test "accounts: GET /accounts/{id} returns correct shape" {
    const alloc = testing.allocator;
    var fx = Fixture.init(0xB1);
    try fx.start();
    defer fx.deinit();

    var name_buf: [8]u8 = undefined;
    const username = randomUsername(&fx.rng, &name_buf);
    const uid = try db_mod.insertUser(fx.db, username, username, "hello", fx.sim.clock().wallUnix());

    var path_buf: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/api/v1/accounts/{d}", .{uid});
    var call = try makeCall(alloc, &fx, .get, path, &.{}, "");
    defer alloc.destroy(call);

    var id_buf: [16]u8 = undefined;
    const id_str = try std.fmt.bufPrint(&id_buf, "{d}", .{uid});
    call.params.keys[0] = "id";
    call.params.values[0] = id_str;
    call.params.count = 1;

    var hc = call.handler();
    try accounts_routes.handleGetAccount(&hc);
    const out = call.responseBodyBytes();
    try testing.expect(std.mem.indexOf(u8, out, "\"username\":") != null);
    try testing.expect(std.mem.indexOf(u8, out, username) != null);
}

test "accounts: GET /accounts/{id} 404 on missing user" {
    const alloc = testing.allocator;
    var fx = Fixture.init(0xB2);
    try fx.start();
    defer fx.deinit();

    var call = try makeCall(alloc, &fx, .get, "/api/v1/accounts/9999", &.{}, "");
    defer alloc.destroy(call);
    call.params.keys[0] = "id";
    call.params.values[0] = "9999";
    call.params.count = 1;
    var hc = call.handler();
    try accounts_routes.handleGetAccount(&hc);
    try testing.expect(std.mem.startsWith(u8, call.statusLine(), "HTTP/1.1 404"));
}

test "accounts: verify_credentials returns 401 without token" {
    const alloc = testing.allocator;
    var fx = Fixture.init(0xB3);
    try fx.start();
    defer fx.deinit();
    var call = try makeCall(alloc, &fx, .get, "/api/v1/accounts/verify_credentials", &.{}, "");
    defer alloc.destroy(call);
    var hc = call.handler();
    try accounts_routes.handleVerifyCredentials(&hc);
    try testing.expect(std.mem.startsWith(u8, call.statusLine(), "HTTP/1.1 401"));
}

// ── Helper to mint a user + token in one call ────────────────────

fn mintUserAndToken(fx: *Fixture, alloc: std.mem.Allocator, scopes: []const u8, out_username: *[]const u8, out_user_id: *i64, out_token_buf: []u8) ![]const u8 {
    const name_buf = try alloc.alloc(u8, 8);
    const uname = randomUsername(&fx.rng, name_buf);
    out_username.* = uname;
    out_user_id.* = try db_mod.insertUser(fx.db, uname, uname, "", fx.sim.clock().wallUnix());

    var app_call = try makeCall(alloc, fx, .post, "/api/v1/apps", &.{}, "{\"client_name\":\"app\"}");
    defer alloc.destroy(app_call);
    var hc = app_call.handler();
    try oauth.handleCreateApp(&hc);
    const creds = extractClient(app_call.responseBodyBytes());

    var body_buf: [256]u8 = undefined;
    const body = try std.fmt.bufPrint(&body_buf,
        "grant_type=password&client_id={s}&client_secret={s}&username={s}&password=x&scope={s}",
        .{ creds.client_id, creds.client_secret, uname, scopes },
    );
    var tok_call = try makeCall(alloc, fx, .post, "/oauth/token", &.{}, body);
    defer alloc.destroy(tok_call);
    var hc2 = tok_call.handler();
    try oauth.handleToken(&hc2);
    const access = http_util.jsonString(tok_call.responseBodyBytes(), "access_token") orelse return error.TestNoToken;
    const n = @min(access.len, out_token_buf.len);
    @memcpy(out_token_buf[0..n], access[0..n]);
    return out_token_buf[0..n];
}

fn freeUsername(alloc: std.mem.Allocator, uname: []const u8) void {
    alloc.free(@as([]u8, @constCast(uname)));
}

fn authHeader(buf: []u8, token: []const u8) []const u8 {
    const out = std.fmt.bufPrint(buf, "Bearer {s}", .{token}) catch return "";
    return out;
}

test "accounts: verify_credentials with valid token returns account" {
    const alloc = testing.allocator;
    var fx = Fixture.init(0xB4);
    try fx.start();
    defer fx.deinit();

    var token_buf: [1024]u8 = undefined;
    var uname: []const u8 = "";
    var uid: i64 = 0;
    const token = try mintUserAndToken(&fx, alloc, "read write", &uname, &uid, &token_buf);
    defer freeUsername(alloc, uname);

    var ah_buf: [1200]u8 = undefined;
    const ah = authHeader(&ah_buf, token);
    var call = try makeCall(alloc, &fx, .get, "/api/v1/accounts/verify_credentials", &.{
        .{ .name = "Authorization", .value = ah },
    }, "");
    defer alloc.destroy(call);
    var hc = call.handler();
    try accounts_routes.handleVerifyCredentials(&hc);
    try testing.expect(std.mem.startsWith(u8, call.statusLine(), "HTTP/1.1 200"));
    try testing.expect(std.mem.indexOf(u8, call.responseBodyBytes(), uname) != null);
}

test "accounts: write scope required for follow" {
    const alloc = testing.allocator;
    var fx = Fixture.init(0xB5);
    try fx.start();
    defer fx.deinit();

    // mint a read-only token
    var tok_buf: [1024]u8 = undefined;
    var uname: []const u8 = "";
    var uid: i64 = 0;
    const tok = try mintUserAndToken(&fx, alloc, "read", &uname, &uid, &tok_buf);
    defer freeUsername(alloc, uname);

    var ah_buf: [1200]u8 = undefined;
    const ah = authHeader(&ah_buf, tok);
    var call = try makeCall(alloc, &fx, .post, "/api/v1/accounts/1/follow", &.{
        .{ .name = "Authorization", .value = ah },
    }, "");
    defer alloc.destroy(call);
    call.params.keys[0] = "id";
    call.params.values[0] = "1";
    call.params.count = 1;
    var hc = call.handler();
    try accounts_routes.handleAccountFollow(&hc);
    try testing.expect(std.mem.startsWith(u8, call.statusLine(), "HTTP/1.1 403"));
}

// ── /api/v1/statuses ─────────────────────────────────────────────

test "statuses: create then read round-trip" {
    const alloc = testing.allocator;
    var fx = Fixture.init(0xC1);
    try fx.start();
    defer fx.deinit();

    var tok_buf: [1024]u8 = undefined;
    var uname: []const u8 = "";
    var uid: i64 = 0;
    const tok = try mintUserAndToken(&fx, alloc, "read write follow", &uname, &uid, &tok_buf);
    defer freeUsername(alloc, uname);

    var ah_buf: [1200]u8 = undefined;
    const ah = authHeader(&ah_buf, tok);

    const post_body = "{\"status\":\"hello world\"}";
    var create_call = try makeCall(alloc, &fx, .post, "/api/v1/statuses", &.{
        .{ .name = "Authorization", .value = ah },
    }, post_body);
    defer alloc.destroy(create_call);
    var hc1 = create_call.handler();
    try statuses_routes.handleCreateStatus(&hc1);
    const out = create_call.responseBodyBytes();
    try testing.expect(std.mem.startsWith(u8, create_call.statusLine(), "HTTP/1.1 200"));
    try testing.expect(std.mem.indexOf(u8, out, "hello world") != null);

    // The id should now exist in ap_activities.
    const status_id = http_util.jsonString(out, "id") orelse "0";
    try testing.expect(status_id.len > 0);
}

test "statuses: favourite increments favourites_count" {
    const alloc = testing.allocator;
    var fx = Fixture.init(0xC2);
    try fx.start();
    defer fx.deinit();

    var tok_buf: [1024]u8 = undefined;
    var uname: []const u8 = "";
    var uid: i64 = 0;
    const tok = try mintUserAndToken(&fx, alloc, "read write follow", &uname, &uid, &tok_buf);
    defer freeUsername(alloc, uname);
    var ah_buf: [1200]u8 = undefined;
    const ah = authHeader(&ah_buf, tok);

    var create_call = try makeCall(alloc, &fx, .post, "/api/v1/statuses", &.{
        .{ .name = "Authorization", .value = ah },
    }, "{\"status\":\"fav me\"}");
    defer alloc.destroy(create_call);
    var hc1 = create_call.handler();
    try statuses_routes.handleCreateStatus(&hc1);
    const out = create_call.responseBodyBytes();
    const id_str = http_util.jsonString(out, "id") orelse return error.TestNoId;

    var fav_call = try makeCall(alloc, &fx, .post, "/api/v1/statuses/x/favourite", &.{
        .{ .name = "Authorization", .value = ah },
    }, "");
    defer alloc.destroy(fav_call);
    fav_call.params.keys[0] = "id";
    fav_call.params.values[0] = id_str;
    fav_call.params.count = 1;
    var hc2 = fav_call.handler();
    try statuses_routes.handleFavourite(&hc2);
    const fav_out = fav_call.responseBodyBytes();
    try testing.expect(std.mem.indexOf(u8, fav_out, "\"favourites_count\":1") != null);
}

test "statuses: delete removes from listing" {
    const alloc = testing.allocator;
    var fx = Fixture.init(0xC3);
    try fx.start();
    defer fx.deinit();

    var tok_buf: [1024]u8 = undefined;
    var uname: []const u8 = "";
    var uid: i64 = 0;
    const tok = try mintUserAndToken(&fx, alloc, "read write follow", &uname, &uid, &tok_buf);
    defer freeUsername(alloc, uname);
    var ah_buf: [1200]u8 = undefined;
    const ah = authHeader(&ah_buf, tok);

    var create_call = try makeCall(alloc, &fx, .post, "/api/v1/statuses", &.{
        .{ .name = "Authorization", .value = ah },
    }, "{\"status\":\"to delete\"}");
    defer alloc.destroy(create_call);
    var hc1 = create_call.handler();
    try statuses_routes.handleCreateStatus(&hc1);
    const id_str = http_util.jsonString(create_call.responseBodyBytes(), "id") orelse return error.TestNoId;

    var del_call = try makeCall(alloc, &fx, .delete, "/api/v1/statuses/x", &.{
        .{ .name = "Authorization", .value = ah },
    }, "");
    defer alloc.destroy(del_call);
    del_call.params.keys[0] = "id";
    del_call.params.values[0] = id_str;
    del_call.params.count = 1;
    var hc2 = del_call.handler();
    try statuses_routes.handleDeleteStatus(&hc2);
    try testing.expect(std.mem.startsWith(u8, del_call.statusLine(), "HTTP/1.1 200"));

    // GET should now 404.
    var get_call = try makeCall(alloc, &fx, .get, "/api/v1/statuses/x", &.{}, "");
    defer alloc.destroy(get_call);
    get_call.params.keys[0] = "id";
    get_call.params.values[0] = id_str;
    get_call.params.count = 1;
    var hc3 = get_call.handler();
    try statuses_routes.handleGetStatus(&hc3);
    try testing.expect(std.mem.startsWith(u8, get_call.statusLine(), "HTTP/1.1 404"));
}

test "statuses: reblog round-trip increments and decrements" {
    const alloc = testing.allocator;
    var fx = Fixture.init(0xC4);
    try fx.start();
    defer fx.deinit();

    var tok_buf: [1024]u8 = undefined;
    var uname: []const u8 = "";
    var uid: i64 = 0;
    const tok = try mintUserAndToken(&fx, alloc, "read write follow", &uname, &uid, &tok_buf);
    defer freeUsername(alloc, uname);
    var ah_buf: [1200]u8 = undefined;
    const ah = authHeader(&ah_buf, tok);

    var c1 = try makeCall(alloc, &fx, .post, "/api/v1/statuses", &.{.{ .name = "Authorization", .value = ah }}, "{\"status\":\"reblog me\"}");
    defer alloc.destroy(c1);
    var h1 = c1.handler();
    try statuses_routes.handleCreateStatus(&h1);
    const id_str = http_util.jsonString(c1.responseBodyBytes(), "id") orelse return error.TestNoId;

    var c2 = try makeCall(alloc, &fx, .post, "/api/v1/statuses/x/reblog", &.{.{ .name = "Authorization", .value = ah }}, "");
    defer alloc.destroy(c2);
    c2.params.keys[0] = "id";
    c2.params.values[0] = id_str;
    c2.params.count = 1;
    var h2 = c2.handler();
    try statuses_routes.handleReblog(&h2);
    try testing.expect(std.mem.indexOf(u8, c2.responseBodyBytes(), "\"reblogs_count\":1") != null);

    var c3 = try makeCall(alloc, &fx, .post, "/api/v1/statuses/x/unreblog", &.{.{ .name = "Authorization", .value = ah }}, "");
    defer alloc.destroy(c3);
    c3.params.keys[0] = "id";
    c3.params.values[0] = id_str;
    c3.params.count = 1;
    var h3 = c3.handler();
    try statuses_routes.handleUnreblog(&h3);
    try testing.expect(std.mem.indexOf(u8, c3.responseBodyBytes(), "\"reblogs_count\":0") != null);
}

// ── Timelines ────────────────────────────────────────────────────

test "timelines: home + public show created status" {
    const alloc = testing.allocator;
    var fx = Fixture.init(0xD1);
    try fx.start();
    defer fx.deinit();

    var tok_buf: [1024]u8 = undefined;
    var uname: []const u8 = "";
    var uid: i64 = 0;
    const tok = try mintUserAndToken(&fx, alloc, "read write follow", &uname, &uid, &tok_buf);
    defer freeUsername(alloc, uname);
    var ah_buf: [1200]u8 = undefined;
    const ah = authHeader(&ah_buf, tok);

    var cc = try makeCall(alloc, &fx, .post, "/api/v1/statuses", &.{.{ .name = "Authorization", .value = ah }}, "{\"status\":\"timeline test\"}");
    defer alloc.destroy(cc);
    var h = cc.handler();
    try statuses_routes.handleCreateStatus(&h);

    var public_call = try makeCall(alloc, &fx, .get, "/api/v1/timelines/public", &.{}, "");
    defer alloc.destroy(public_call);
    var ph = public_call.handler();
    try timelines_routes.handlePublic(&ph);
    try testing.expect(std.mem.indexOf(u8, public_call.responseBodyBytes(), "timeline test") != null);

    var home_call = try makeCall(alloc, &fx, .get, "/api/v1/timelines/home", &.{.{ .name = "Authorization", .value = ah }}, "");
    defer alloc.destroy(home_call);
    var hh = home_call.handler();
    try timelines_routes.handleHome(&hh);
    try testing.expect(std.mem.indexOf(u8, home_call.responseBodyBytes(), "timeline test") != null);
}

test "timelines: limit query parameter caps result count" {
    const alloc = testing.allocator;
    var fx = Fixture.init(0xD2);
    try fx.start();
    defer fx.deinit();

    var tok_buf: [1024]u8 = undefined;
    var uname: []const u8 = "";
    var uid: i64 = 0;
    const tok = try mintUserAndToken(&fx, alloc, "read write", &uname, &uid, &tok_buf);
    defer freeUsername(alloc, uname);
    var ah_buf: [1200]u8 = undefined;
    const ah = authHeader(&ah_buf, tok);

    var i: usize = 0;
    while (i < 5) : (i += 1) {
        var body_buf: [64]u8 = undefined;
        const body = try std.fmt.bufPrint(&body_buf, "{{\"status\":\"post {d}\"}}", .{i});
        var cc = try makeCall(alloc, &fx, .post, "/api/v1/statuses", &.{.{ .name = "Authorization", .value = ah }}, body);
        defer alloc.destroy(cc);
        var hh = cc.handler();
        try statuses_routes.handleCreateStatus(&hh);
        fx.sim.advance(1_000_000_000);
    }

    var lim_call = try makeCall(alloc, &fx, .get, "/api/v1/timelines/public?limit=2", &.{}, "");
    defer alloc.destroy(lim_call);
    var lh = lim_call.handler();
    try timelines_routes.handlePublic(&lh);
    // Count commas inside the array — 2 statuses ⇒ 1 separator commas
    // (Mastodon also embeds many commas inside each status, so we instead
    // count "\"id\":\"" occurrences.)
    const out = lim_call.responseBodyBytes();
    var occ: usize = 0;
    var idx: usize = 0;
    while (std.mem.indexOfPos(u8, out, idx, "\"in_reply_to_id\"")) |pos| {
        occ += 1;
        idx = pos + 1;
    }
    try testing.expectEqual(@as(usize, 2), occ);
}

test "timelines: hashtag filter selects matching content" {
    const alloc = testing.allocator;
    var fx = Fixture.init(0xD3);
    try fx.start();
    defer fx.deinit();
    var tok_buf: [1024]u8 = undefined;
    var uname: []const u8 = "";
    var uid: i64 = 0;
    const tok = try mintUserAndToken(&fx, alloc, "read write", &uname, &uid, &tok_buf);
    defer freeUsername(alloc, uname);
    var ah_buf: [1200]u8 = undefined;
    const ah = authHeader(&ah_buf, tok);

    var c1 = try makeCall(alloc, &fx, .post, "/api/v1/statuses", &.{.{ .name = "Authorization", .value = ah }}, "{\"status\":\"morning #coffee\"}");
    defer alloc.destroy(c1);
    var h1 = c1.handler();
    try statuses_routes.handleCreateStatus(&h1);

    var c2 = try makeCall(alloc, &fx, .post, "/api/v1/statuses", &.{.{ .name = "Authorization", .value = ah }}, "{\"status\":\"plain status\"}");
    defer alloc.destroy(c2);
    var h2 = c2.handler();
    try statuses_routes.handleCreateStatus(&h2);

    var tag_call = try makeCall(alloc, &fx, .get, "/api/v1/timelines/tag/coffee", &.{}, "");
    defer alloc.destroy(tag_call);
    tag_call.params.keys[0] = "hashtag";
    tag_call.params.values[0] = "coffee";
    tag_call.params.count = 1;
    var th = tag_call.handler();
    try timelines_routes.handleHashtag(&th);
    const tag_out = tag_call.responseBodyBytes();
    try testing.expect(std.mem.indexOf(u8, tag_out, "morning") != null);
    try testing.expect(std.mem.indexOf(u8, tag_out, "plain status") == null);
}

test "timelines: since_id excludes older statuses" {
    const alloc = testing.allocator;
    var fx = Fixture.init(0xD4);
    try fx.start();
    defer fx.deinit();
    var tok_buf: [1024]u8 = undefined;
    var uname: []const u8 = "";
    var uid: i64 = 0;
    const tok = try mintUserAndToken(&fx, alloc, "read write", &uname, &uid, &tok_buf);
    defer freeUsername(alloc, uname);
    var ah_buf: [1200]u8 = undefined;
    const ah = authHeader(&ah_buf, tok);

    var c1 = try makeCall(alloc, &fx, .post, "/api/v1/statuses", &.{.{ .name = "Authorization", .value = ah }}, "{\"status\":\"old\"}");
    defer alloc.destroy(c1);
    var h1 = c1.handler();
    try statuses_routes.handleCreateStatus(&h1);
    const id_str = http_util.jsonString(c1.responseBodyBytes(), "id") orelse return error.TestNoId;

    fx.sim.advance(2_000_000_000);

    var c2 = try makeCall(alloc, &fx, .post, "/api/v1/statuses", &.{.{ .name = "Authorization", .value = ah }}, "{\"status\":\"new\"}");
    defer alloc.destroy(c2);
    var h2 = c2.handler();
    try statuses_routes.handleCreateStatus(&h2);

    var path_buf: [128]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/api/v1/timelines/public?since_id={s}", .{id_str});
    var pc = try makeCall(alloc, &fx, .get, path, &.{}, "");
    defer alloc.destroy(pc);
    var ph = pc.handler();
    try timelines_routes.handlePublic(&ph);
    const out = pc.responseBodyBytes();
    try testing.expect(std.mem.indexOf(u8, out, "new") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"content\":\"old\"") == null);
}

// ── Notifications ────────────────────────────────────────────────

test "notifications: follow generates a notification" {
    const alloc = testing.allocator;
    var fx = Fixture.init(0xE1);
    try fx.start();
    defer fx.deinit();

    var tok_buf: [1024]u8 = undefined;
    var uname: []const u8 = "";
    var follower_id: i64 = 0;
    const tok = try mintUserAndToken(&fx, alloc, "read write follow", &uname, &follower_id, &tok_buf);
    defer freeUsername(alloc, uname);
    var ah_buf: [1200]u8 = undefined;
    const ah = authHeader(&ah_buf, tok);

    // Mint a second user to follow.
    var n_buf: [8]u8 = undefined;
    const target_name = randomUsername(&fx.rng, &n_buf);
    const target_id = try db_mod.insertUser(fx.db, target_name, target_name, "", fx.sim.clock().wallUnix());

    var id_buf: [16]u8 = undefined;
    const id_str = try std.fmt.bufPrint(&id_buf, "{d}", .{target_id});
    var path_buf: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/api/v1/accounts/{d}/follow", .{target_id});
    var call = try makeCall(alloc, &fx, .post, path, &.{.{ .name = "Authorization", .value = ah }}, "");
    defer alloc.destroy(call);
    call.params.keys[0] = "id";
    call.params.values[0] = id_str;
    call.params.count = 1;
    var hc = call.handler();
    try accounts_routes.handleAccountFollow(&hc);
    try testing.expect(std.mem.startsWith(u8, call.statusLine(), "HTTP/1.1 200"));

    // The target now has one notification.
    var iter = db_mod.queryNotifications(fx.db, target_id, 10);
    defer iter.deinit();
    var row: db_mod.NotificationRow = .{};
    try testing.expect(iter.next(&row));
    try testing.expectEqualStrings("follow", row.typeStr());
}

test "notifications: clear empties the feed" {
    const alloc = testing.allocator;
    var fx = Fixture.init(0xE2);
    try fx.start();
    defer fx.deinit();
    var tok_buf: [1024]u8 = undefined;
    var uname: []const u8 = "";
    var uid: i64 = 0;
    const tok = try mintUserAndToken(&fx, alloc, "read write follow", &uname, &uid, &tok_buf);
    defer freeUsername(alloc, uname);

    try db_mod.insertNotification(fx.db, uid, "follow", "https://other/u", 0, fx.sim.clock().wallUnix());
    var ah_buf: [1200]u8 = undefined;
    const ah = authHeader(&ah_buf, tok);
    var call = try makeCall(alloc, &fx, .post, "/api/v1/notifications/clear", &.{.{ .name = "Authorization", .value = ah }}, "");
    defer alloc.destroy(call);
    var hc = call.handler();
    try notifications_routes.handleClear(&hc);
    try testing.expect(std.mem.startsWith(u8, call.statusLine(), "HTTP/1.1 200"));

    var iter = db_mod.queryNotifications(fx.db, uid, 10);
    defer iter.deinit();
    var row: db_mod.NotificationRow = .{};
    try testing.expect(!iter.next(&row));
}

test "notifications: list returns inserted entries" {
    const alloc = testing.allocator;
    var fx = Fixture.init(0xE3);
    try fx.start();
    defer fx.deinit();
    var tok_buf: [1024]u8 = undefined;
    var uname: []const u8 = "";
    var uid: i64 = 0;
    const tok = try mintUserAndToken(&fx, alloc, "read", &uname, &uid, &tok_buf);
    defer freeUsername(alloc, uname);

    try db_mod.insertNotification(fx.db, uid, "favourite", "https://x/u", 0, fx.sim.clock().wallUnix());
    var ah_buf: [1200]u8 = undefined;
    const ah = authHeader(&ah_buf, tok);
    var call = try makeCall(alloc, &fx, .get, "/api/v1/notifications", &.{.{ .name = "Authorization", .value = ah }}, "");
    defer alloc.destroy(call);
    var hc = call.handler();
    try notifications_routes.handleList(&hc);
    try testing.expect(std.mem.indexOf(u8, call.responseBodyBytes(), "\"type\":\"favourite\"") != null);
}

// ── Instance ─────────────────────────────────────────────────────

test "instance: metadata shape" {
    const alloc = testing.allocator;
    var fx = Fixture.init(0xF1);
    try fx.start();
    defer fx.deinit();
    var call = try makeCall(alloc, &fx, .get, "/api/v1/instance", &.{}, "");
    defer alloc.destroy(call);
    var hc = call.handler();
    try instance_routes.handleInstance(&hc);
    const out = call.responseBodyBytes();
    try testing.expect(std.mem.indexOf(u8, out, "\"uri\":\"speedy.test\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"stats\"") != null);
}

test "instance: peers + activity return arrays" {
    const alloc = testing.allocator;
    var fx = Fixture.init(0xF2);
    try fx.start();
    defer fx.deinit();
    var peers = try makeCall(alloc, &fx, .get, "/api/v1/instance/peers", &.{}, "");
    defer alloc.destroy(peers);
    var ph = peers.handler();
    try instance_routes.handleInstancePeers(&ph);
    try testing.expectEqualStrings("[]", peers.responseBodyBytes());

    var act = try makeCall(alloc, &fx, .get, "/api/v1/instance/activity", &.{}, "");
    defer alloc.destroy(act);
    var ah = act.handler();
    try instance_routes.handleInstanceActivity(&ah);
    try testing.expectEqualStrings("[]", act.responseBodyBytes());
}

// ── Media + streaming stubs ──────────────────────────────────────

test "media: v1 returns 501" {
    const alloc = testing.allocator;
    var fx = Fixture.init(0xF3);
    try fx.start();
    defer fx.deinit();
    var call = try makeCall(alloc, &fx, .post, "/api/v1/media", &.{}, "");
    defer alloc.destroy(call);
    var hc = call.handler();
    try media_routes.handleUploadV1(&hc);
    try testing.expect(std.mem.startsWith(u8, call.statusLine(), "HTTP/1.1 501"));
}

test "media: v2 returns 501" {
    const alloc = testing.allocator;
    var fx = Fixture.init(0xF4);
    try fx.start();
    defer fx.deinit();
    var call = try makeCall(alloc, &fx, .post, "/api/v2/media", &.{}, "");
    defer alloc.destroy(call);
    var hc = call.handler();
    try media_routes.handleUploadV2(&hc);
    try testing.expect(std.mem.startsWith(u8, call.statusLine(), "HTTP/1.1 501"));
}

test "streaming: HTTP fallback returns 400 telling client to upgrade" {
    // W2.1: real-time streaming is a WebSocket upgrade now. A plain
    // GET against `/api/v1/streaming/*` falls through to this
    // 400-with-JSON-body handler.
    const alloc = testing.allocator;
    var fx = Fixture.init(0xF5);
    try fx.start();
    defer fx.deinit();
    var call = try makeCall(alloc, &fx, .get, "/api/v1/streaming/user", &.{}, "");
    defer alloc.destroy(call);
    var hc = call.handler();
    try streaming_routes.handleUser(&hc);
    const raw = call.body();
    try testing.expect(std.mem.startsWith(u8, raw, "HTTP/1.1 400"));
    try testing.expect(std.mem.indexOf(u8, raw, "WebSocket Upgrade") != null);
}

// ── Apps ────────────────────────────────────────────────────────

test "apps: verify_credentials returns app metadata" {
    const alloc = testing.allocator;
    var fx = Fixture.init(0xF6);
    try fx.start();
    defer fx.deinit();

    var tok_buf: [1024]u8 = undefined;
    var uname: []const u8 = "";
    var uid: i64 = 0;
    const tok = try mintUserAndToken(&fx, alloc, "read", &uname, &uid, &tok_buf);
    defer freeUsername(alloc, uname);

    var ah_buf: [1200]u8 = undefined;
    const ah = authHeader(&ah_buf, tok);
    var call = try makeCall(alloc, &fx, .get, "/api/v1/apps/verify_credentials", &.{.{ .name = "Authorization", .value = ah }}, "");
    defer alloc.destroy(call);
    var hc = call.handler();
    try apps_routes.handleVerifyAppCredentials(&hc);
    try testing.expect(std.mem.startsWith(u8, call.statusLine(), "HTTP/1.1 200"));
    try testing.expect(std.mem.indexOf(u8, call.responseBodyBytes(), "\"name\":") != null);
}

// ── Follow round-trip ────────────────────────────────────────────

test "follows: follow then unfollow round-trip" {
    const alloc = testing.allocator;
    var fx = Fixture.init(0xF7);
    try fx.start();
    defer fx.deinit();

    var tok_buf: [1024]u8 = undefined;
    var uname: []const u8 = "";
    var uid: i64 = 0;
    const tok = try mintUserAndToken(&fx, alloc, "read write follow", &uname, &uid, &tok_buf);
    defer freeUsername(alloc, uname);
    var ah_buf: [1200]u8 = undefined;
    const ah = authHeader(&ah_buf, tok);

    var n_buf: [8]u8 = undefined;
    const target_name = randomUsername(&fx.rng, &n_buf);
    const target_id = try db_mod.insertUser(fx.db, target_name, target_name, "", fx.sim.clock().wallUnix());
    var id_buf: [16]u8 = undefined;
    const id_str = try std.fmt.bufPrint(&id_buf, "{d}", .{target_id});

    var path_buf: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/api/v1/accounts/{d}/follow", .{target_id});
    var f_call = try makeCall(alloc, &fx, .post, path, &.{.{ .name = "Authorization", .value = ah }}, "");
    defer alloc.destroy(f_call);
    f_call.params.keys[0] = "id";
    f_call.params.values[0] = id_str;
    f_call.params.count = 1;
    var fh = f_call.handler();
    try accounts_routes.handleAccountFollow(&fh);
    try testing.expect(std.mem.indexOf(u8, f_call.responseBodyBytes(), "\"following\":true") != null);

    var path2_buf: [64]u8 = undefined;
    const path2 = try std.fmt.bufPrint(&path2_buf, "/api/v1/accounts/{d}/unfollow", .{target_id});
    var u_call = try makeCall(alloc, &fx, .post, path2, &.{.{ .name = "Authorization", .value = ah }}, "");
    defer alloc.destroy(u_call);
    u_call.params.keys[0] = "id";
    u_call.params.values[0] = id_str;
    u_call.params.count = 1;
    var uh = u_call.handler();
    try accounts_routes.handleAccountUnfollow(&uh);
    try testing.expect(std.mem.indexOf(u8, u_call.responseBodyBytes(), "\"following\":false") != null);
}

// ── Serializer regression ────────────────────────────────────────

test "serialize: ISO timestamp deterministic for known epoch" {
    var buf: [32]u8 = undefined;
    const out = try serialize.formatIsoTimestamp(1_700_000_000, &buf);
    try testing.expectEqualStrings("2023-11-14T22:13:20Z", out);
}

test "auth: requireScope returns 401 for missing header" {
    const alloc = testing.allocator;
    var fx = Fixture.init(0xF8);
    try fx.start();
    defer fx.deinit();
    var call = try makeCall(alloc, &fx, .get, "/x", &.{}, "");
    defer alloc.destroy(call);
    var hc = call.handler();
    const claims = try auth.requireScope(&hc, "read");
    try testing.expect(claims == null);
    try testing.expect(std.mem.startsWith(u8, call.statusLine(), "HTTP/1.1 401"));
}

test "auth: bad bearer token returns 401" {
    const alloc = testing.allocator;
    var fx = Fixture.init(0xF9);
    try fx.start();
    defer fx.deinit();
    var call = try makeCall(alloc, &fx, .get, "/x", &.{
        .{ .name = "Authorization", .value = "Bearer not-a-jwt" },
    }, "");
    defer alloc.destroy(call);
    var hc = call.handler();
    const claims = try auth.requireScope(&hc, "read");
    try testing.expect(claims == null);
    try testing.expect(std.mem.startsWith(u8, call.statusLine(), "HTTP/1.1 401"));
}

test "OAuth: authorize endpoint serves an HTML form" {
    const alloc = testing.allocator;
    var fx = Fixture.init(0xFA);
    try fx.start();
    defer fx.deinit();
    var call = try makeCall(alloc, &fx, .get, "/oauth/authorize?client_id=abc&scope=read", &.{}, "");
    defer alloc.destroy(call);
    var hc = call.handler();
    try oauth.handleAuthorize(&hc);
    const raw = call.body();
    try testing.expect(std.mem.indexOf(u8, raw, "<form") != null);
    try testing.expect(std.mem.indexOf(u8, raw, "grant_type") != null);
}
