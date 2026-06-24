//! AT-1: OAuth 2.1 + DPoP authorization server.
//!
//! This module implements the atproto OAuth profile:
//!   * `/.well-known/oauth-authorization-server` — AS metadata
//!   * `/.well-known/oauth-protected-resource` — resource server metadata
//!   * `/oauth/par` — pushed authorization request
//!   * `/oauth/authorize` — authorization endpoint (consent + code grant)
//!   * `/oauth/token` — token endpoint with DPoP-bound access tokens
//!   * `/oauth/jwks` — JWKS for the AS public key
//!
//! Constraints (atproto profile):
//!   * PAR is mandatory.
//!   * PKCE S256 is mandatory.
//!   * DPoP is mandatory on the token endpoint.
//!   * Client metadata is fetched from the `client_id` URL — we
//!     accept any client_id today; client-metadata verification is
//!     a future hardening.
//!
//! Storage: PAR requests and authorization codes live in
//! `atp_oauth_par` and `atp_oauth_codes` tables (migrations below).
//! Issued tokens are bound to the DPoP-key thumbprint via the JWT
//! `cnf` claim; the same path as `core.account.Backend` issues a
//! JWT, but with `cnf` extended.

const std = @import("std");
const c = @import("sqlite").c;
const core = @import("core");
const HandlerContext = core.http.router.HandlerContext;
const Router = core.http.router.Router;

const State = @import("state.zig");
const xrpc = @import("xrpc.zig");
const auth_mod = @import("auth.zig");
const oauth_dpop = @import("oauth_dpop.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const base64url = std.base64.url_safe_no_pad;

/// AT-1: process-wide DPoP proof verifier. Holds the replay (`jti`)
/// window across token requests. Single PDS instance per process.
var dpop_verifier: oauth_dpop.Verifier = oauth_dpop.Verifier.init();

/// AT-3: DPoP-Nonce (RFC 9449 §8) lifetime. A nonce remains acceptable
/// for this window; presented later it is treated as stale and a fresh
/// one is issued. Kept short — DPoP proofs are themselves short-lived.
const dpop_nonce_ttl_seconds: i64 = 300;
/// Random byte count for an issued nonce (hex-encoded → 64 chars).
const dpop_nonce_bytes: usize = 32;

/// AT-3: mint a fresh DPoP nonce, persist it in `atp_dpop_nonces`, and
/// write the hex value into `out` (must hold `dpop_nonce_bytes * 2`).
/// Returns the slice written. Nonces are seeded from the atproto state
/// clock (the same entropy source the PAR/code minters use).
fn issueDpopNonce(db: *c.sqlite3, st: *State.State, out: []u8) ?[]const u8 {
    if (out.len < dpop_nonce_bytes * 2) return null;
    var rng_bytes: [dpop_nonce_bytes]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(@bitCast(@as(i64, @truncate(st.clock.wallNs() ^ 0xD9_0F_AC_E5))));
    prng.random().bytes(&rng_bytes);
    const hex_chars = "0123456789abcdef";
    for (rng_bytes, 0..) |b, i| {
        out[i * 2] = hex_chars[b >> 4];
        out[i * 2 + 1] = hex_chars[b & 0xF];
    }
    const nonce = out[0 .. dpop_nonce_bytes * 2];

    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO atp_dpop_nonces (nonce, issued_at, expires_at) VALUES (?,?,?)", -1, &stmt, null) != c.SQLITE_OK) {
        return null;
    }
    defer _ = c.sqlite3_finalize(stmt);
    const now = st.clock.wallUnix();
    _ = c.sqlite3_bind_text(stmt, 1, nonce.ptr, @intCast(nonce.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(stmt, 2, now);
    _ = c.sqlite3_bind_int64(stmt, 3, now + dpop_nonce_ttl_seconds);
    if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return null;
    return nonce;
}

/// AT-3 (FIXNONCE): validate + consume a DPoP nonce atomically. RFC 9449
/// §8 requires a server-issued nonce MUST NOT be accepted more than once;
/// the previous SELECT-then-DELETE left a window where two concurrent
/// requests carrying the SAME nonce could both pass the expiry check
/// before either deleted, enabling replay.
///
/// This is now a single `DELETE … WHERE nonce = ? AND expires_at >= ?
/// RETURNING nonce`. The delete + expiry test happen in one statement
/// under SQLite's row-level write lock, so exactly one concurrent caller
/// removes the row. The nonce is validly consumed ONLY when the statement
/// yields a row (`SQLITE_ROW`): that proves *this* call performed the
/// delete and the row was still live. An expired nonce fails the
/// `expires_at >= ?` predicate, so it is rejected — and, because DELETE
/// also removes any row matching only `nonce = ?`, we reap stale rows in a
/// second pass when the live delete found nothing.
///
/// Requires SQLite ≥ 3.35 for DELETE…RETURNING; the bundled amalgamation
/// is 3.49.2 (see `third_party/zig-sqlite` → sqlite-amalgamation-3490200),
/// so RETURNING is available.
fn consumeDpopNonce(db: *c.sqlite3, st: *State.State, nonce: []const u8) bool {
    if (nonce.len == 0 or nonce.len > 256) return false;
    const now = st.clock.wallUnix();

    // Atomic consume: delete iff still live, returning the deleted nonce.
    var del: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(
        db,
        "DELETE FROM atp_dpop_nonces WHERE nonce = ? AND expires_at >= ? RETURNING nonce",
        -1,
        &del,
        null,
    ) != c.SQLITE_OK) {
        return false;
    }
    defer _ = c.sqlite3_finalize(del);
    _ = c.sqlite3_bind_text(del, 1, nonce.ptr, @intCast(nonce.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(del, 2, now);
    const consumed = c.sqlite3_step(del.?) == c.SQLITE_ROW;
    if (consumed) return true;

    // Not consumed: either the nonce was unknown/already-consumed, or it
    // was present but expired. In the expired case the live-delete above
    // matched nothing (the `expires_at >= ?` guard failed), so reap the
    // stale row now so it cannot linger. Rejection stands either way.
    var reap: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "DELETE FROM atp_dpop_nonces WHERE nonce = ?", -1, &reap, null) == c.SQLITE_OK) {
        _ = c.sqlite3_bind_text(reap, 1, nonce.ptr, @intCast(nonce.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_step(reap.?);
        _ = c.sqlite3_finalize(reap);
    }
    return false;
}

/// AT-3: respond with a fresh `DPoP-Nonce` header and the RFC 9449
/// `use_dpop_nonce` error so the client retries with the nonce echoed
/// into its proof. Written directly via the response builder because
/// the shared `xrpc.writeJsonBody` finalizes headers before we could
/// add `DPoP-Nonce`.
fn writeUseDpopNonce(hc: *HandlerContext, nonce: []const u8) !void {
    const body =
        "{\"error\":\"use_dpop_nonce\",\"error_description\":\"Authorization server requires nonce in DPoP proof\"}";
    try hc.response.startStatus(.bad_request);
    try hc.response.header("Content-Type", "application/json");
    try hc.response.header("DPoP-Nonce", nonce);
    try hc.response.headerFmt("Content-Length", "{d}", .{body.len});
    try hc.response.header("Connection", "close");
    try hc.response.finishHeaders();
    try hc.response.body(body);
}

// ──────────────────────────────────────────────────────────────────────
// AS / RS metadata
// ──────────────────────────────────────────────────────────────────────

fn wellKnownAuthServer(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    var body_buf: [4 * 1024]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf,
        "{{" ++
            "\"issuer\":\"https://{s}\"," ++
            "\"authorization_endpoint\":\"https://{s}/oauth/authorize\"," ++
            "\"token_endpoint\":\"https://{s}/oauth/token\"," ++
            "\"pushed_authorization_request_endpoint\":\"https://{s}/oauth/par\"," ++
            "\"jwks_uri\":\"https://{s}/oauth/jwks\"," ++
            "\"response_types_supported\":[\"code\"]," ++
            "\"grant_types_supported\":[\"authorization_code\",\"refresh_token\"]," ++
            "\"code_challenge_methods_supported\":[\"S256\"]," ++
            "\"token_endpoint_auth_methods_supported\":[\"none\"]," ++
            "\"dpop_signing_alg_values_supported\":[\"ES256\",\"EdDSA\"]," ++
            "\"require_pushed_authorization_requests\":true," ++
            "\"scopes_supported\":[\"atproto\"]" ++
        "}}",
        .{ st.host, st.host, st.host, st.host, st.host },
    ) catch return xrpc.writeError(hc, .internal, "InternalError", "fmt");
    try xrpc.writeJsonBody(hc, .ok, body);
}

fn wellKnownProtectedResource(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    var body_buf: [1024]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf,
        "{{\"resource\":\"https://{s}\",\"authorization_servers\":[\"https://{s}\"]}}",
        .{ st.host, st.host },
    ) catch return xrpc.writeError(hc, .internal, "InternalError", "fmt");
    try xrpc.writeJsonBody(hc, .ok, body);
}

// ──────────────────────────────────────────────────────────────────────
// Pushed Authorization Request (PAR)
// ──────────────────────────────────────────────────────────────────────

fn parRequest(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const db = st.dbHandle() orelse return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "db not ready");

    // PAR accepts the same parameters as `authorize` but inline. We
    // require client_id, response_type=code, redirect_uri, code_challenge,
    // code_challenge_method=S256, scope.
    const client_id = xrpc.jsonStringField(hc.request.body, "client_id") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing client_id");
    const redirect_uri = xrpc.jsonStringField(hc.request.body, "redirect_uri") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing redirect_uri");
    const code_challenge = xrpc.jsonStringField(hc.request.body, "code_challenge") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing code_challenge");
    const code_method = xrpc.jsonStringField(hc.request.body, "code_challenge_method") orelse "S256";
    if (!std.mem.eql(u8, code_method, "S256")) {
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "code_challenge_method must be S256");
    }
    const scope = xrpc.jsonStringField(hc.request.body, "scope") orelse "atproto";

    // Mint a request_uri: `urn:ietf:params:oauth:request_uri:<random>`
    var rng_bytes: [16]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(@bitCast(@as(i64, @truncate(st.clock.wallNs()))));
    prng.random().bytes(&rng_bytes);
    var hex: [32]u8 = undefined;
    const hex_chars = "0123456789abcdef";
    for (rng_bytes, 0..) |b, i| {
        hex[i * 2] = hex_chars[b >> 4];
        hex[i * 2 + 1] = hex_chars[b & 0xF];
    }
    var request_uri_buf: [128]u8 = undefined;
    const request_uri = std.fmt.bufPrint(&request_uri_buf,
        "urn:ietf:params:oauth:request_uri:{s}",
        .{hex[0..]},
    ) catch return xrpc.writeError(hc, .internal, "InternalError", "fmt");

    var stmt: ?*c.sqlite3_stmt = null;
    const sql =
        \\INSERT INTO atp_oauth_par
        \\  (request_uri, client_id, redirect_uri, code_challenge, scope, expires_at)
        \\VALUES (?,?,?,?,?,?)
    ;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        return xrpc.writeError(hc, .internal, "InternalError", "prepare");
    }
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, request_uri.ptr, @intCast(request_uri.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 2, client_id.ptr, @intCast(client_id.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 3, redirect_uri.ptr, @intCast(redirect_uri.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 4, code_challenge.ptr, @intCast(code_challenge.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 5, scope.ptr, @intCast(scope.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(stmt, 6, st.clock.wallUnix() + 90); // 90s TTL
    if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return xrpc.writeError(hc, .internal, "InternalError", "step");

    var resp_buf: [256]u8 = undefined;
    const resp = std.fmt.bufPrint(&resp_buf,
        "{{\"request_uri\":\"{s}\",\"expires_in\":90}}",
        .{request_uri},
    ) catch return xrpc.writeError(hc, .internal, "InternalError", "fmt");
    try xrpc.writeJsonBody(hc, .ok, resp);
}

// ──────────────────────────────────────────────────────────────────────
// Authorization endpoint
//
// Real production: render a consent UI, prompt for the user's
// password, then on success issue an authorization code. The
// minimum-viable shape here is a JSON endpoint: the caller posts
// `{request_uri, did, password}`; on valid credentials we mint a
// code and respond with `{code}`. The caller (or a follow-up UI)
// then redirects.
// ──────────────────────────────────────────────────────────────────────

fn authorize(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const db = st.dbHandle() orelse return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "db not ready");
    const backend = core.account.global() orelse return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "account backend not configured");

    const request_uri = xrpc.jsonStringField(hc.request.body, "request_uri") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing request_uri");
    const did = xrpc.jsonStringField(hc.request.body, "did") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing did");
    const password = xrpc.jsonStringField(hc.request.body, "password") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing password");

    // Verify the credentials.
    const ok = backend.verifyPassword(did, password) catch
        return xrpc.writeError(hc, .internal, "InternalError", "verify");
    if (!ok) return xrpc.writeError(hc, .unauthorized, "AuthenticationRequired", "bad credentials");

    // Confirm the PAR exists + not expired.
    var sel: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "SELECT client_id, redirect_uri, code_challenge, scope, expires_at FROM atp_oauth_par WHERE request_uri = ?", -1, &sel, null) != c.SQLITE_OK) {
        return xrpc.writeError(hc, .internal, "InternalError", "prepare");
    }
    defer _ = c.sqlite3_finalize(sel);
    _ = c.sqlite3_bind_text(sel, 1, request_uri.ptr, @intCast(request_uri.len), c.sqliteTransientAsDestructor());
    if (c.sqlite3_step(sel.?) != c.SQLITE_ROW) return xrpc.writeError(hc, .bad_request, "InvalidRequest", "unknown request_uri");
    const exp = c.sqlite3_column_int64(sel, 4);
    if (exp < st.clock.wallUnix()) return xrpc.writeError(hc, .bad_request, "InvalidRequest", "request_uri expired");

    // Mint an authorization code.
    var rng_bytes: [24]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(@bitCast(@as(i64, @truncate(st.clock.wallNs() ^ 0x42))));
    prng.random().bytes(&rng_bytes);
    var hex: [48]u8 = undefined;
    const hex_chars = "0123456789abcdef";
    for (rng_bytes, 0..) |b, i| {
        hex[i * 2] = hex_chars[b >> 4];
        hex[i * 2 + 1] = hex_chars[b & 0xF];
    }
    const code = hex[0..];

    var ins: ?*c.sqlite3_stmt = null;
    const ins_sql =
        \\INSERT INTO atp_oauth_codes
        \\  (code, did, request_uri, expires_at)
        \\VALUES (?,?,?,?)
    ;
    if (c.sqlite3_prepare_v2(db, ins_sql, -1, &ins, null) != c.SQLITE_OK) {
        return xrpc.writeError(hc, .internal, "InternalError", "prepare");
    }
    defer _ = c.sqlite3_finalize(ins);
    _ = c.sqlite3_bind_text(ins, 1, code.ptr, @intCast(code.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(ins, 2, did.ptr, @intCast(did.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(ins, 3, request_uri.ptr, @intCast(request_uri.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(ins, 4, st.clock.wallUnix() + 60); // 60s TTL
    if (c.sqlite3_step(ins.?) != c.SQLITE_DONE) return xrpc.writeError(hc, .internal, "InternalError", "step");

    var resp_buf: [256]u8 = undefined;
    const resp = std.fmt.bufPrint(&resp_buf, "{{\"code\":\"{s}\"}}", .{code}) catch
        return xrpc.writeError(hc, .internal, "InternalError", "fmt");
    try xrpc.writeJsonBody(hc, .ok, resp);
}

// ──────────────────────────────────────────────────────────────────────
// Token endpoint
//
// Requires DPoP proof in the `DPoP` header. Exchanges the
// authorization code (with PKCE) for a DPoP-bound access token +
// refresh token. The `cnf` claim is the thumbprint of the DPoP key.
// ──────────────────────────────────────────────────────────────────────

fn token(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const db = st.dbHandle() orelse return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "db not ready");

    const grant_type = xrpc.jsonStringField(hc.request.body, "grant_type") orelse
        return xrpc.writeError(hc, .bad_request, "invalid_request", "missing grant_type");
    if (!std.mem.eql(u8, grant_type, "authorization_code")) {
        return xrpc.writeError(hc, .bad_request, "unsupported_grant_type", "only authorization_code is wired");
    }
    const code = xrpc.jsonStringField(hc.request.body, "code") orelse
        return xrpc.writeError(hc, .bad_request, "invalid_request", "missing code");
    const code_verifier = xrpc.jsonStringField(hc.request.body, "code_verifier") orelse
        return xrpc.writeError(hc, .bad_request, "invalid_request", "missing code_verifier");

    // AT-1: DPoP proof. The `DPoP` header carries a JWT signed by the
    // client's key, with that key embedded in the proof header `jwk`.
    // Verify the signature (EdDSA or ES256) + htm/htu/iat/replay, and
    // derive the RFC 7638 `jkt` thumbprint for the token's `cnf` claim.
    const dpop_header = hc.request.header("DPoP") orelse
        return xrpc.writeError(hc, .bad_request, "invalid_dpop_proof", "missing DPoP header");
    if (std.mem.count(u8, dpop_header, ".") != 2) {
        return xrpc.writeError(hc, .bad_request, "invalid_dpop_proof", "DPoP must be a 3-segment JWT");
    }
    var htu_buf: [320]u8 = undefined;
    const htu = std.fmt.bufPrint(&htu_buf, "https://{s}/oauth/token", .{st.host}) catch
        return xrpc.writeError(hc, .internal, "InternalError", "htu");
    var jkt_buf: [64]u8 = undefined;
    const jkt = dpop_verifier.verifyDpopHeader(dpop_header, "POST", htu, st.clock.wallUnix(), &jkt_buf) catch
        return xrpc.writeError(hc, .bad_request, "invalid_dpop_proof", "DPoP proof verification failed");

    // AT-3: DPoP-Nonce (RFC 9449 §8). The proof must carry a server-
    // issued `nonce`. If absent or stale, issue a fresh nonce via the
    // `DPoP-Nonce` header + `use_dpop_nonce` error so the client retries.
    var nonce_scratch: [256]u8 = undefined;
    const proof_nonce = oauth_dpop.extractNonce(dpop_header, &nonce_scratch);
    const nonce_ok = if (proof_nonce) |n| consumeDpopNonce(db, st, n) else false;
    if (!nonce_ok) {
        var issued_buf: [dpop_nonce_bytes * 2]u8 = undefined;
        const fresh = issueDpopNonce(db, st, &issued_buf) orelse
            return xrpc.writeError(hc, .internal, "InternalError", "nonce");
        return writeUseDpopNonce(hc, fresh);
    }

    // Look up + consume the auth code.
    var sel: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "SELECT did, request_uri, expires_at FROM atp_oauth_codes WHERE code = ?", -1, &sel, null) != c.SQLITE_OK) {
        return xrpc.writeError(hc, .internal, "InternalError", "prepare");
    }
    defer _ = c.sqlite3_finalize(sel);
    _ = c.sqlite3_bind_text(sel, 1, code.ptr, @intCast(code.len), c.sqliteTransientAsDestructor());
    if (c.sqlite3_step(sel.?) != c.SQLITE_ROW) return xrpc.writeError(hc, .bad_request, "invalid_grant", "unknown code");

    const did_ptr = c.sqlite3_column_text(sel, 0);
    const did_len: usize = @intCast(c.sqlite3_column_bytes(sel, 0));
    const request_uri_ptr = c.sqlite3_column_text(sel, 1);
    const request_uri_len: usize = @intCast(c.sqlite3_column_bytes(sel, 1));
    const code_exp = c.sqlite3_column_int64(sel, 2);
    if (code_exp < st.clock.wallUnix()) return xrpc.writeError(hc, .bad_request, "invalid_grant", "code expired");

    var did_buf: [256]u8 = undefined;
    const did_cap = @min(did_len, did_buf.len);
    @memcpy(did_buf[0..did_cap], did_ptr[0..did_cap]);
    const did = did_buf[0..did_cap];

    var ru_buf: [256]u8 = undefined;
    const ru_cap = @min(request_uri_len, ru_buf.len);
    @memcpy(ru_buf[0..ru_cap], request_uri_ptr[0..ru_cap]);
    const request_uri = ru_buf[0..ru_cap];

    // Look up the PAR row's code_challenge and verify PKCE.
    var par: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "SELECT code_challenge FROM atp_oauth_par WHERE request_uri = ?", -1, &par, null) != c.SQLITE_OK) {
        return xrpc.writeError(hc, .internal, "InternalError", "prepare");
    }
    defer _ = c.sqlite3_finalize(par);
    _ = c.sqlite3_bind_text(par, 1, request_uri.ptr, @intCast(request_uri.len), c.sqliteTransientAsDestructor());
    if (c.sqlite3_step(par.?) != c.SQLITE_ROW) return xrpc.writeError(hc, .bad_request, "invalid_grant", "request_uri gone");
    const challenge_ptr = c.sqlite3_column_text(par, 0);
    const challenge_len: usize = @intCast(c.sqlite3_column_bytes(par, 0));
    var challenge_buf: [256]u8 = undefined;
    const ch_cap = @min(challenge_len, challenge_buf.len);
    @memcpy(challenge_buf[0..ch_cap], challenge_ptr[0..ch_cap]);
    const expected_challenge = challenge_buf[0..ch_cap];

    // PKCE S256: challenge = base64url(sha256(verifier)).
    var verifier_hash: [32]u8 = undefined;
    Sha256.hash(code_verifier, &verifier_hash, .{});
    var computed_b64: [44]u8 = undefined;
    const computed_len = base64url.Encoder.calcSize(32);
    _ = base64url.Encoder.encode(computed_b64[0..computed_len], &verifier_hash);
    if (!std.mem.eql(u8, computed_b64[0..computed_len], expected_challenge)) {
        return xrpc.writeError(hc, .bad_request, "invalid_grant", "PKCE mismatch");
    }

    // Burn the code so it can't be re-used.
    var del: ?*c.sqlite3_stmt = null;
    _ = c.sqlite3_prepare_v2(db, "DELETE FROM atp_oauth_codes WHERE code = ?", -1, &del, null);
    _ = c.sqlite3_bind_text(del, 1, code.ptr, @intCast(code.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_step(del.?);
    _ = c.sqlite3_finalize(del);

    // Mint access + refresh tokens, both DPoP-bound via `cnf.jkt`
    // (the real RFC 7638 thumbprint derived from the verified proof).
    const now = st.clock.wallUnix();
    var access_jti: [16]u8 = undefined;
    fillJti(&access_jti, now, 5);

    var ac: auth_mod.Claims = .{ .scope = .access, .iat = now, .exp = now + auth_mod.access_ttl_seconds };
    try ac.setSub(did);
    try ac.setJti(&access_jti);
    try ac.setCnfJkt(jkt);

    var ab: [auth_mod.max_jwt_bytes]u8 = undefined;
    const access = try auth_mod.sign(st.jwt_key, ac, &ab);

    var rj: [16]u8 = undefined;
    fillJti(&rj, now, 6);
    var rc: auth_mod.Claims = .{ .scope = .refresh, .iat = now, .exp = now + auth_mod.refresh_ttl_seconds };
    try rc.setSub(did);
    try rc.setJti(&rj);
    try rc.setCnfJkt(jkt);
    var rb: [auth_mod.max_jwt_bytes]u8 = undefined;
    const refresh = try auth_mod.sign(st.jwt_key, rc, &rb);

    var resp_buf: [2 * auth_mod.max_jwt_bytes + 256]u8 = undefined;
    const resp = std.fmt.bufPrint(&resp_buf,
        "{{\"access_token\":\"{s}\",\"token_type\":\"DPoP\",\"expires_in\":{d},\"refresh_token\":\"{s}\",\"scope\":\"atproto\"}}",
        .{ access, auth_mod.access_ttl_seconds, refresh },
    ) catch return xrpc.writeError(hc, .internal, "InternalError", "fmt");
    try xrpc.writeJsonBody(hc, .ok, resp);
}

fn fillJti(out: []u8, seed: i64, salt: u8) void {
    var i: usize = 0;
    var v: u64 = @as(u64, @bitCast(seed)) ^ (@as(u64, salt) << 56);
    while (i < out.len) : (i += 1) {
        out[i] = "0123456789abcdef"[@as(usize, @intCast(v & 0xf))];
        v >>= 4;
        if (v == 0) v = @as(u64, @bitCast(seed)) +% (@as(u64, salt) * (@as(u64, i) + 1));
    }
}

// ──────────────────────────────────────────────────────────────────────
// JWKS (public key of the AS).
// ──────────────────────────────────────────────────────────────────────

fn jwks(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    var pk_b64: [44]u8 = undefined;
    const n = base64url.Encoder.calcSize(32);
    _ = base64url.Encoder.encode(pk_b64[0..n], &st.jwt_key.public_key);
    var body_buf: [512]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf,
        "{{\"keys\":[{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"{s}\",\"use\":\"sig\",\"alg\":\"EdDSA\",\"kid\":\"pds-as\"}}]}}",
        .{pk_b64[0..n]},
    ) catch return xrpc.writeError(hc, .internal, "InternalError", "fmt");
    try xrpc.writeJsonBody(hc, .ok, body);
}

// ──────────────────────────────────────────────────────────────────────
// Registration
// ──────────────────────────────────────────────────────────────────────

pub fn register(router: *Router, plugin_index: u16) !void {
    try router.register(.get, "/.well-known/oauth-authorization-server", wellKnownAuthServer, plugin_index);
    try router.register(.get, "/.well-known/oauth-protected-resource", wellKnownProtectedResource, plugin_index);
    try router.register(.post, "/oauth/par", parRequest, plugin_index);
    try router.register(.post, "/oauth/authorize", authorize, plugin_index);
    try router.register(.post, "/oauth/token", token, plugin_index);
    try router.register(.get, "/oauth/jwks", jwks, plugin_index);
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "AT-1: oauth routes register" {
    var r = Router.init();
    try register(&r, 0);
    try testing.expectEqual(@as(u32, 6), r.count);
}

test "AT-1: PKCE S256 matches reference verifier/challenge" {
    // Reference vector from RFC 7636 §B.
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    var h: [32]u8 = undefined;
    Sha256.hash(verifier, &h, .{});
    var b64: [44]u8 = undefined;
    const n = base64url.Encoder.calcSize(32);
    _ = base64url.Encoder.encode(b64[0..n], &h);
    try testing.expectEqualStrings("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", b64[0..n]);
}

// ── AT-3: DPoP-Nonce store ─────────────────────────────────────────

const schema_mod = @import("schema.zig");

fn setupOAuthDb() !*c.sqlite3 {
    const db = try core.storage.sqlite.openWriter(":memory:");
    for (schema_mod.all_migrations) |m| {
        const sql_z = try testing.allocator.dupeZ(u8, m.up);
        defer testing.allocator.free(sql_z);
        var em: [*c]u8 = null;
        _ = c.sqlite3_exec(db, sql_z.ptr, null, null, &em);
        if (em != null) c.sqlite3_free(em);
    }
    return db;
}

test "AT-3: dpop nonce issue -> consume -> reject reuse" {
    const db = try setupOAuthDb();
    defer core.storage.sqlite.closeDb(db);

    State.reset();
    var rng = core.rng.Rng.init(0xA73);
    var sc = core.clock.SimClock.init(1_000);
    State.init(sc.clock(), &rng, "pds.example");
    defer State.reset();
    const st = State.get();

    var buf: [dpop_nonce_bytes * 2]u8 = undefined;
    const nonce = issueDpopNonce(db, st, &buf) orelse return error.IssueFailed;
    try testing.expectEqual(@as(usize, dpop_nonce_bytes * 2), nonce.len);

    // First consume succeeds.
    try testing.expect(consumeDpopNonce(db, st, nonce));
    // Replay (already consumed) is rejected.
    try testing.expect(!consumeDpopNonce(db, st, nonce));
    // Unknown nonce is rejected.
    try testing.expect(!consumeDpopNonce(db, st, "deadbeef"));
}

test "FIXNONCE: double consume of one nonce -> exactly one succeeds" {
    const db = try setupOAuthDb();
    defer core.storage.sqlite.closeDb(db);

    State.reset();
    var rng = core.rng.Rng.init(0xC0FFEE);
    var sc = core.clock.SimClock.init(2_000);
    State.init(sc.clock(), &rng, "pds.example");
    defer State.reset();
    const st = State.get();

    var buf: [dpop_nonce_bytes * 2]u8 = undefined;
    const nonce = issueDpopNonce(db, st, &buf) orelse return error.IssueFailed;

    // Two requests presenting the SAME live nonce. The atomic
    // DELETE…RETURNING means exactly one removes the row and succeeds;
    // the other finds nothing to delete and is rejected — RFC 9449 §8
    // "MUST NOT be accepted more than once".
    const first = consumeDpopNonce(db, st, nonce);
    const second = consumeDpopNonce(db, st, nonce);
    var wins: u8 = 0;
    if (first) wins += 1;
    if (second) wins += 1;
    try testing.expectEqual(@as(u8, 1), wins);
    try testing.expect(first); // serial order: first wins, second loses
    try testing.expect(!second);
}

test "FIXNONCE: expired nonce rejected AND atomically reaped" {
    const db = try setupOAuthDb();
    defer core.storage.sqlite.closeDb(db);

    State.reset();
    var rng = core.rng.Rng.init(0xDEAD);
    var sc = core.clock.SimClock.init(7_000);
    State.init(sc.clock(), &rng, "pds.example");
    defer State.reset();
    const st = State.get();

    var buf: [dpop_nonce_bytes * 2]u8 = undefined;
    const nonce = issueDpopNonce(db, st, &buf) orelse return error.IssueFailed;
    var saved: [dpop_nonce_bytes * 2]u8 = undefined;
    @memcpy(&saved, nonce);

    // Advance past TTL: the row is present but stale.
    sc.advance(@as(u64, @intCast(dpop_nonce_ttl_seconds + 1)) * std.time.ns_per_s);
    // Rejected (expired)…
    try testing.expect(!consumeDpopNonce(db, st, saved[0..]));

    // …and reaped: the row is gone, so a direct count is zero.
    var cnt: ?*c.sqlite3_stmt = null;
    try testing.expectEqual(c.SQLITE_OK, c.sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM atp_dpop_nonces WHERE nonce = ?", -1, &cnt, null));
    defer _ = c.sqlite3_finalize(cnt);
    _ = c.sqlite3_bind_text(cnt, 1, saved[0..].ptr, @intCast(saved.len), c.sqliteTransientAsDestructor());
    try testing.expectEqual(c.SQLITE_ROW, c.sqlite3_step(cnt.?));
    try testing.expectEqual(@as(i64, 0), c.sqlite3_column_int64(cnt, 0));
}

test "AT-3: dpop nonce rejected once past its TTL window" {
    const db = try setupOAuthDb();
    defer core.storage.sqlite.closeDb(db);

    State.reset();
    var rng = core.rng.Rng.init(0xB91);
    var sc = core.clock.SimClock.init(5_000);
    State.init(sc.clock(), &rng, "pds.example");
    defer State.reset();
    const st = State.get();

    var buf: [dpop_nonce_bytes * 2]u8 = undefined;
    const nonce = issueDpopNonce(db, st, &buf) orelse return error.IssueFailed;
    // Copy: the consume path deletes the row, so re-insert a stale row by
    // advancing the clock beyond the TTL before consuming the original.
    var stale_buf: [dpop_nonce_bytes * 2]u8 = undefined;
    @memcpy(&stale_buf, nonce);

    // Advance the simulated wall clock past the nonce TTL.
    sc.advance(@as(u64, @intCast(dpop_nonce_ttl_seconds + 1)) * std.time.ns_per_s);
    // The row exists but is now expired → consume returns false.
    try testing.expect(!consumeDpopNonce(db, st, stale_buf[0..]));
}

test "AT-3: extractNonce recovers the nonce claim from a signed proof" {
    const oauth_dpop_mod = @import("oauth_dpop.zig");
    const keypair_mod = @import("keypair.zig");
    const auth_max = @import("auth.zig").max_jwt_bytes;

    var seed: [32]u8 = undefined;
    @memset(&seed, 0x77);
    const kp = keypair_mod.Ed25519KeyPair.fromSeed(seed);

    var pbuf: [auth_max]u8 = undefined;
    const proof = try oauth_dpop_mod.signProofWithNonce(
        kp,
        "POST",
        "https://pds.example/oauth/token",
        9000,
        "nonce-jti-1",
        "server-issued-nonce-abc123",
        &pbuf,
    );

    var nbuf: [256]u8 = undefined;
    const got = oauth_dpop_mod.extractNonce(proof, &nbuf) orelse return error.NoNonce;
    try testing.expectEqualStrings("server-issued-nonce-abc123", got);

    // A proof without a nonce claim yields null.
    var pbuf2: [auth_max]u8 = undefined;
    const proof2 = try oauth_dpop_mod.signProof(kp, "POST", "https://pds.example/oauth/token", 9000, "no-nonce", &pbuf2);
    try testing.expect(oauth_dpop_mod.extractNonce(proof2, &nbuf) == null);
}
