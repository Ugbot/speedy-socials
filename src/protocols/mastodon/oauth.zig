//! OAuth 2.0 Authorization Server for the Mastodon API.
//!
//! Flow choice
//! ===========
//! speedy-socials supports two grant types:
//!
//!   * `password` — RFC 6749 §4.3 resource-owner password credentials.
//!     The chosen path for first-party clients (most Mastodon iOS / web
//!     clients fall back to this). Username + password are POSTed to
//!     `/oauth/token`; we mint a user-bound access token.
//!
//!   * `client_credentials` — RFC 6749 §4.4. Issues a client-only token
//!     for read-only public endpoints (`/api/v1/instance`, public
//!     timeline). No `user_id` is bound.
//!
//! Authorization Code grant is *intentionally* deferred: a real
//! authorization UI is out of scope for W1.3. The `/oauth/authorize`
//! endpoint serves a minimal HTML form that POSTs back as
//! `grant_type=password` (matching what the Mastodon web UI does on
//! single-page deployments). Full PKCE / consent UI lands in a later
//! milestone — call it out as a known limitation.
//!
//! Tokens are Ed25519 JWTs (see `jwt.zig`). The `jti` is recorded in
//! `mastodon_tokens` so we can revoke them.

const std = @import("std");
const core = @import("core");
const c = @import("sqlite").c;
const HandlerContext = core.http.router.HandlerContext;

const state_mod = @import("state.zig");
const jwt = @import("jwt.zig");
const http_util = @import("http_util.zig");
const db_mod = @import("db.zig");
const serialize = @import("serialize.zig");

const default_scopes = "read write follow push";

// ── helpers ────────────────────────────────────────────────────────

fn randHex(rng: *core.rng.Rng, out: []u8) void {
    const hex = "0123456789abcdef";
    var raw: [64]u8 = undefined;
    const n = @min(out.len, raw.len);
    rng.random().bytes(raw[0..n]);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        out[i] = hex[raw[i] & 0x0f];
    }
}

// ── POST /api/v1/apps ─────────────────────────────────────────────

pub fn handleCreateApp(hc: *HandlerContext) anyerror!void {
    const st = state_mod.get();
    const db = st.db orelse return http_util.writeError(hc, .service_unavailable, "db not ready");
    const rng = st.rng orelse return http_util.writeError(hc, .service_unavailable, "rng not ready");

    // Accept either JSON or form-encoded body. We try JSON first.
    const body = hc.request.body;
    const name = http_util.jsonString(body, "client_name") orelse http_util.formField(body, "client_name") orelse {
        return http_util.writeError(hc, .bad_request, "client_name required");
    };
    const redirect = http_util.jsonString(body, "redirect_uris") orelse
        http_util.formField(body, "redirect_uris") orelse "urn:ietf:wg:oauth:2.0:oob";
    const scopes = http_util.jsonString(body, "scopes") orelse
        http_util.formField(body, "scopes") orelse default_scopes;
    const website = http_util.jsonString(body, "website") orelse
        http_util.formField(body, "website") orelse "";

    var cid_buf: [32]u8 = undefined;
    var sec_buf: [48]u8 = undefined;
    randHex(rng, &cid_buf);
    randHex(rng, &sec_buf);

    var app: db_mod.AppRow = .{ .id = 0 };
    const cid_n = @min(cid_buf.len, app.client_id_buf.len);
    @memcpy(app.client_id_buf[0..cid_n], cid_buf[0..cid_n]);
    app.client_id_len = cid_n;
    const sec_n = @min(sec_buf.len, app.client_secret_buf.len);
    @memcpy(app.client_secret_buf[0..sec_n], sec_buf[0..sec_n]);
    app.client_secret_len = sec_n;
    const name_n = @min(name.len, app.name_buf.len);
    @memcpy(app.name_buf[0..name_n], name[0..name_n]);
    app.name_len = name_n;
    const rd_n = @min(redirect.len, app.redirect_buf.len);
    @memcpy(app.redirect_buf[0..rd_n], redirect[0..rd_n]);
    app.redirect_len = rd_n;
    const sc_n = @min(scopes.len, app.scopes_buf.len);
    @memcpy(app.scopes_buf[0..sc_n], scopes[0..sc_n]);
    app.scopes_len = sc_n;
    const ws_n = @min(website.len, app.website_buf.len);
    @memcpy(app.website_buf[0..ws_n], website[0..ws_n]);
    app.website_len = ws_n;

    _ = db_mod.insertApp(db, app, st.clock.wallUnix()) catch {
        return http_util.writeError(hc, .internal, "could not persist app");
    };

    var out_buf: [1024]u8 = undefined;
    const out = serialize.writeApplication(.{
        .name = name,
        .website = website,
        .client_id = app.clientId(),
        .client_secret = app.clientSecret(),
        .redirect_uri = app.redirectUri(),
        .vapid_key = "",
    }, &out_buf) catch return http_util.writeError(hc, .internal, "buf");
    try http_util.writeJsonBody(hc, .ok, out);
}

// ── GET /oauth/authorize ─────────────────────────────────────────

pub fn handleAuthorize(hc: *HandlerContext) anyerror!void {
    const pq = hc.request.pathAndQuery();
    const client_id = http_util.queryParam(pq.query, "client_id") orelse "";
    const redirect = http_util.queryParam(pq.query, "redirect_uri") orelse "urn:ietf:wg:oauth:2.0:oob";
    const scopes = http_util.queryParam(pq.query, "scope") orelse default_scopes;
    // Render a tiny HTML form. The form POSTs to /oauth/token using the
    // `password` grant — we intentionally do not implement the full
    // Authorization Code dance (see oauth.zig module-level comment).
    var buf: [2048]u8 = undefined;
    const html = std.fmt.bufPrint(&buf,
        "<!doctype html><html><head><title>Authorize</title></head><body>" ++
        "<h1>Authorize {s}</h1>" ++
        "<form method=\"POST\" action=\"/oauth/token\">" ++
        "<input type=\"hidden\" name=\"grant_type\" value=\"password\">" ++
        "<input type=\"hidden\" name=\"client_id\" value=\"{s}\">" ++
        "<input type=\"hidden\" name=\"redirect_uri\" value=\"{s}\">" ++
        "<input type=\"hidden\" name=\"scope\" value=\"{s}\">" ++
        "<label>Username <input name=\"username\"></label><br>" ++
        "<label>Password <input type=\"password\" name=\"password\"></label><br>" ++
        "<button type=\"submit\">Authorize</button>" ++
        "</form></body></html>",
        .{ client_id, client_id, redirect, scopes },
    ) catch return http_util.writeError(hc, .internal, "html buf");
    try http_util.writeHtmlBody(hc, .ok, html);
}

// ── POST /oauth/token ────────────────────────────────────────────

pub fn handleToken(hc: *HandlerContext) anyerror!void {
    const st = state_mod.get();
    const db = st.db orelse return http_util.writeError(hc, .service_unavailable, "db not ready");
    const rng = st.rng orelse return http_util.writeError(hc, .service_unavailable, "rng not ready");

    const body = hc.request.body;
    const grant = http_util.jsonString(body, "grant_type") orelse
        http_util.formField(body, "grant_type") orelse {
        return http_util.writeError(hc, .bad_request, "grant_type required");
    };
    const client_id = http_util.jsonString(body, "client_id") orelse
        http_util.formField(body, "client_id") orelse {
        return http_util.writeError(hc, .bad_request, "client_id required");
    };
    const client_secret = http_util.jsonString(body, "client_secret") orelse
        http_util.formField(body, "client_secret") orelse "";

    const app = db_mod.findAppByClientId(db, client_id) orelse {
        return http_util.writeError(hc, .unauthorized, "unknown client_id");
    };

    // Constant-time client_secret check (skipped when empty — the
    // Mastodon iOS app uses the discovered secret, but some clients
    // omit it for public token endpoints).
    if (client_secret.len > 0 and !constantTimeEq(client_secret, app.clientSecret())) {
        return http_util.writeError(hc, .unauthorized, "bad client_secret");
    }

    var user_id: i64 = 0;
    const scopes: []const u8 = http_util.jsonString(body, "scope") orelse
        http_util.formField(body, "scope") orelse default_scopes;

    if (std.mem.eql(u8, grant, "password")) {
        const username = http_util.jsonString(body, "username") orelse
            http_util.formField(body, "username") orelse {
            return http_util.writeError(hc, .bad_request, "username required");
        };
        const password = http_util.jsonString(body, "password") orelse
            http_util.formField(body, "password") orelse "";
        if (password.len == 0) {
            return http_util.writeError(hc, .unauthorized, "password required");
        }
        // No real password store yet (Argon2id lands in W1.2). Accept
        // any non-empty password for an existing user. This matches the
        // AT Protocol legacy createSession behavior — both will switch
        // to real verification when crypto-net lands.
        const u = db_mod.findUserByUsername(db, username) orelse {
            return http_util.writeError(hc, .unauthorized, "unknown user");
        };
        user_id = u.id;
    } else if (std.mem.eql(u8, grant, "client_credentials")) {
        // user_id remains 0
    } else if (std.mem.eql(u8, grant, "authorization_code")) {
        return http_util.writeError(hc, .not_implemented, "authorization_code not yet supported; use password");
    } else if (std.mem.eql(u8, grant, "refresh_token")) {
        return http_util.writeError(hc, .not_implemented, "refresh_token not yet supported");
    } else {
        return http_util.writeError(hc, .bad_request, "unsupported grant_type");
    }

    // Build the JWT.
    const now = st.clock.wallUnix();
    var jti_buf: [24]u8 = undefined;
    randHex(rng, &jti_buf);

    var claims: jwt.Claims = .{
        .user_id = user_id,
        .app_id = app.id,
        .iat = now,
        .exp = now + jwt.access_ttl_seconds,
    };
    try claims.setJti(&jti_buf);
    try claims.setScopes(scopes);

    var token_buf: [jwt.max_jwt_bytes]u8 = undefined;
    const tok = jwt.sign(st.jwt_key, claims, &token_buf) catch {
        return http_util.writeError(hc, .internal, "jwt sign failed");
    };

    db_mod.insertToken(db, &jti_buf, app.id, user_id, scopes, claims.exp, now) catch {
        return http_util.writeError(hc, .internal, "could not persist token");
    };

    var out_buf: [2048]u8 = undefined;
    const out = std.fmt.bufPrint(&out_buf,
        "{{\"access_token\":\"{s}\",\"token_type\":\"Bearer\",\"scope\":\"{s}\",\"created_at\":{d}}}",
        .{ tok, scopes, now },
    ) catch return http_util.writeError(hc, .internal, "token resp buf");
    try http_util.writeJsonBody(hc, .ok, out);
}

// ── POST /oauth/revoke ───────────────────────────────────────────

pub fn handleRevoke(hc: *HandlerContext) anyerror!void {
    const st = state_mod.get();
    const db = st.db orelse return http_util.writeError(hc, .service_unavailable, "db not ready");
    const body = hc.request.body;
    const token = http_util.jsonString(body, "token") orelse
        http_util.formField(body, "token") orelse {
        return http_util.writeError(hc, .bad_request, "token required");
    };
    // Parse the JWT to pull out its jti — we don't bother verifying the
    // signature here (revoking a tampered token is harmless).
    var claims: jwt.Claims = .{};
    jwt.verify(token, st.jwt_key.public_key, st.clock.wallUnix(), &claims) catch |err| {
        // Allow revocation of expired tokens — still want the row marked.
        if (err != error.Expired) return http_util.writeError(hc, .bad_request, "bad token");
    };
    db_mod.revokeToken(db, claims.jti()) catch {
        return http_util.writeError(hc, .internal, "revoke failed");
    };
    try http_util.writeJsonBody(hc, .ok, "{}");
}

fn constantTimeEq(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    var i: usize = 0;
    while (i < a.len) : (i += 1) diff |= a[i] ^ b[i];
    return diff == 0;
}
