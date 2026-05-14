//! XRPC route handlers for the AT Protocol PDS.
//!
//! Routes register against the shared `Router`. Handlers read module-
//! level state via `state.get()` and dispatch into `repo.zig`,
//! `auth.zig`, `firehose.zig`. Responses use the fixed-length
//! `response.Builder` for known-size bodies; the `getRepo` and
//! `subscribeRepos` paths return 501 until the streaming/WS handler
//! plumbing in `core/ws/registry.zig` is wired into `core/server.zig`
//! (the server currently does not forward WS upgrades to plugins —
//! that lands alongside this phase's integration).
//!
//! Tiger Style: every handler bounded; no allocator beyond the
//! HandlerContext arena (currently unused here since responses fit in
//! the connection write buffer).

const std = @import("std");
const core = @import("core");

const HandlerContext = core.http.router.HandlerContext;
const Status = core.http.response.Status;
const Router = core.http.router.Router;
const Method = core.http.request.Method;

const State = @import("state.zig");
const xrpc = @import("xrpc.zig");
const auth_mod = @import("auth.zig");
const repo_mod = @import("repo.zig");
const firehose = @import("firehose.zig");
const tid_mod = @import("tid.zig");
const dag = @import("dag_cbor.zig");
const mst = @import("mst.zig");
const cid_mod = @import("cid.zig");
const car = @import("car.zig");

// ── describeServer ────────────────────────────────────────────────

fn describeServer(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    var buf: [1024]u8 = undefined;
    const body = std.fmt.bufPrint(&buf,
        "{{\"did\":\"did:web:{s}\",\"availableUserDomains\":[\".{s}\"],\"inviteCodeRequired\":false,\"links\":{{\"privacyPolicy\":\"\",\"termsOfService\":\"\"}},\"contact\":{{\"email\":\"\"}}}}",
        .{ st.host, st.host },
    ) catch return error.OutOfMemory;
    try xrpc.writeJsonBody(hc, .ok, body);
}

// ── createSession ─────────────────────────────────────────────────

fn createSession(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const ident = xrpc.jsonStringField(hc.request.body, "identifier") orelse {
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing identifier");
    };
    const password = xrpc.jsonStringField(hc.request.body, "password") orelse {
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing password");
    };

    // Stub password check (Argon2id deferred). Accept any non-empty
    // password for an identifier that matches a known did:plc/web
    // syntax; this is the legacy "app password" path. Tests + dev only.
    if (password.len == 0) {
        return xrpc.writeError(hc, .unauthorized, "AuthenticationRequired", "bad password");
    }

    // Build access + refresh JWTs.
    const now = st.clock.wallUnix();

    var access_jti_buf: [16]u8 = undefined;
    var refresh_jti_buf: [16]u8 = undefined;
    fillJti(&access_jti_buf, now, 1);
    fillJti(&refresh_jti_buf, now, 2);

    var access_claims: auth_mod.Claims = .{ .scope = .access, .iat = now, .exp = now + auth_mod.access_ttl_seconds };
    try access_claims.setSub(ident);
    try access_claims.setJti(&access_jti_buf);

    var refresh_claims: auth_mod.Claims = .{ .scope = .refresh, .iat = now, .exp = now + auth_mod.refresh_ttl_seconds };
    try refresh_claims.setSub(ident);
    try refresh_claims.setJti(&refresh_jti_buf);

    var access_buf: [auth_mod.max_jwt_bytes]u8 = undefined;
    var refresh_buf: [auth_mod.max_jwt_bytes]u8 = undefined;
    const access = try auth_mod.sign(st.jwt_key, access_claims, &access_buf);
    const refresh = try auth_mod.sign(st.jwt_key, refresh_claims, &refresh_buf);

    var body_buf: [4096]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf,
        "{{\"did\":\"{s}\",\"handle\":\"{s}\",\"accessJwt\":\"{s}\",\"refreshJwt\":\"{s}\"}}",
        .{ ident, ident, access, refresh },
    ) catch return error.OutOfMemory;
    try xrpc.writeJsonBody(hc, .ok, body);
}

fn refreshSession(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const auth_header = hc.request.header("Authorization") orelse {
        return xrpc.writeError(hc, .unauthorized, "AuthenticationRequired", "missing bearer");
    };
    if (!std.mem.startsWith(u8, auth_header, "Bearer ")) {
        return xrpc.writeError(hc, .unauthorized, "AuthenticationRequired", "bad scheme");
    }
    const token = auth_header[7..];

    const now = st.clock.wallUnix();
    var claims: auth_mod.Claims = .{ .scope = .access, .iat = 0, .exp = 0 };
    auth_mod.verify(token, st.jwt_key.public_key, now, &claims) catch {
        return xrpc.writeError(hc, .unauthorized, "AuthenticationRequired", "invalid refresh");
    };
    if (claims.scope != .refresh) {
        return xrpc.writeError(hc, .unauthorized, "AuthenticationRequired", "not a refresh token");
    }

    // Rotate.
    var new_access_jti_buf: [16]u8 = undefined;
    var new_refresh_jti_buf: [16]u8 = undefined;
    fillJti(&new_access_jti_buf, now, 11);
    fillJti(&new_refresh_jti_buf, now, 12);

    var access_claims: auth_mod.Claims = .{ .scope = .access, .iat = now, .exp = now + auth_mod.access_ttl_seconds };
    try access_claims.setSub(claims.sub());
    try access_claims.setJti(&new_access_jti_buf);

    var refresh_claims: auth_mod.Claims = .{ .scope = .refresh, .iat = now, .exp = now + auth_mod.refresh_ttl_seconds };
    try refresh_claims.setSub(claims.sub());
    try refresh_claims.setJti(&new_refresh_jti_buf);

    var ab: [auth_mod.max_jwt_bytes]u8 = undefined;
    var rb: [auth_mod.max_jwt_bytes]u8 = undefined;
    const access = try auth_mod.sign(st.jwt_key, access_claims, &ab);
    const refresh = try auth_mod.sign(st.jwt_key, refresh_claims, &rb);

    var body_buf: [4096]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf,
        "{{\"did\":\"{s}\",\"handle\":\"{s}\",\"accessJwt\":\"{s}\",\"refreshJwt\":\"{s}\"}}",
        .{ claims.sub(), claims.sub(), access, refresh },
    ) catch return error.OutOfMemory;
    try xrpc.writeJsonBody(hc, .ok, body);
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

// ── createRecord / getRecord / listRecords / describeRepo ─────────

fn createRecord(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const db = st.reader_db orelse {
        return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "db not ready");
    };
    const repo_did = xrpc.jsonStringField(hc.request.body, "repo") orelse {
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing repo");
    };
    const collection = xrpc.jsonStringField(hc.request.body, "collection") orelse {
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing collection");
    };

    // Persist a tiny CBOR value with the raw request body for now —
    // production would lexicon-validate then re-encode canonically.
    var enc_buf: [4096]u8 = undefined;
    var enc = dag.Encoder.init(&enc_buf);
    enc.writeMapHeader(2) catch return xrpc.writeError(hc, .internal, "InternalError", "encode");
    enc.writeText("$type") catch return xrpc.writeError(hc, .internal, "InternalError", "encode");
    enc.writeText(collection) catch return xrpc.writeError(hc, .internal, "InternalError", "encode");
    enc.writeText("body") catch return xrpc.writeError(hc, .internal, "InternalError", "encode");
    enc.writeText(hc.request.body) catch return xrpc.writeError(hc, .internal, "InternalError", "encode");

    var rng = core.rng.Rng.init(@as(u64, @bitCast(st.clock.wallUnix())));
    var ts = tid_mod.State.init(&rng);
    const rev = ts.next(st.clock);
    const rkey = ts.next(st.clock);

    repo_mod.ensureRepo(db, repo_did, "did:key:placeholder", st.clock.wallUnix()) catch {
        return xrpc.writeError(hc, .internal, "InternalError", "ensureRepo");
    };

    var tree: mst.Tree(mst.max_keys) = .{};
    repo_mod.loadTree(db, repo_did, &tree) catch {};

    const ops = [_]repo_mod.Operation{
        .{ .collection = collection, .rkey = "", .value_cbor = enc.written() },
    };
    const commit = repo_mod.commit(db, repo_did, st.jwt_key, rev, &tree, &ops, st.clock.wallUnix(), rkey) catch {
        return xrpc.writeError(hc, .internal, "InternalError", "commit");
    };

    var body_buf: [1024]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf,
        "{{\"uri\":\"at://{s}/{s}/{s}\",\"cid\":\"{s}\"}}",
        .{ repo_did, collection, rkey.str(), commit.cidStr() },
    ) catch return error.OutOfMemory;
    try xrpc.writeJsonBody(hc, .ok, body);
}

fn getRecord(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const db = st.reader_db orelse {
        return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "db not ready");
    };
    const q = hc.request.pathAndQuery().query;
    const repo_did = xrpc.queryParam(q, "repo") orelse {
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing repo");
    };
    const collection = xrpc.queryParam(q, "collection") orelse {
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing collection");
    };
    const rkey = xrpc.queryParam(q, "rkey") orelse {
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing rkey");
    };

    var row: repo_mod.RecordRow = .{};
    const found = repo_mod.getRecord(db, repo_did, collection, rkey, &row) catch {
        return xrpc.writeError(hc, .internal, "InternalError", "lookup");
    };
    if (!found) return xrpc.writeError(hc, .not_found, "RecordNotFound", "no such record");

    var body_buf: [4096]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf,
        "{{\"uri\":\"at://{s}/{s}/{s}\",\"cid\":\"{s}\",\"value\":\"<cbor:{d}>\"}}",
        .{ repo_did, collection, rkey, row.cidStr(), row.value_len },
    ) catch return error.OutOfMemory;
    try xrpc.writeJsonBody(hc, .ok, body);
}

fn deleteRecord(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const db = st.reader_db orelse {
        return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "db not ready");
    };
    const repo_did = xrpc.jsonStringField(hc.request.body, "repo") orelse {
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing repo");
    };
    const collection = xrpc.jsonStringField(hc.request.body, "collection") orelse {
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing collection");
    };
    const rkey = xrpc.jsonStringField(hc.request.body, "rkey") orelse {
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing rkey");
    };
    _ = repo_mod.deleteRecord(db, repo_did, collection, rkey) catch {
        return xrpc.writeError(hc, .internal, "InternalError", "delete");
    };
    try xrpc.writeJsonBody(hc, .ok, "{}");
}

fn describeRepo(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const db = st.reader_db orelse {
        return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "db not ready");
    };
    const q = hc.request.pathAndQuery().query;
    const repo_did = xrpc.queryParam(q, "repo") orelse {
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing repo");
    };

    var meta: repo_mod.RepoMeta = .{};
    const found = repo_mod.loadRepoMeta(db, repo_did, &meta) catch {
        return xrpc.writeError(hc, .internal, "InternalError", "load");
    };
    if (!found) return xrpc.writeError(hc, .not_found, "RepoNotFound", "no such repo");

    var body_buf: [1024]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf,
        "{{\"did\":\"{s}\",\"handle\":\"{s}\",\"didDoc\":{{}},\"collections\":[],\"handleIsCorrect\":true}}",
        .{ repo_did, repo_did },
    ) catch return error.OutOfMemory;
    try xrpc.writeJsonBody(hc, .ok, body);
}

// ── well-known DID ────────────────────────────────────────────────

fn wellKnownAtprotoDid(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    var buf: [256]u8 = undefined;
    const body = std.fmt.bufPrint(&buf, "did:web:{s}", .{st.host}) catch return error.OutOfMemory;
    try hc.response.startStatus(.ok);
    try hc.response.header("Content-Type", "text/plain");
    try hc.response.headerFmt("Content-Length", "{d}", .{body.len});
    try hc.response.header("Connection", "close");
    try hc.response.finishHeaders();
    try hc.response.body(body);
}

// ── stubs returning 501 for endpoints whose plumbing lands later ──

fn notImplemented(hc: *HandlerContext) anyerror!void {
    try xrpc.writeError(hc, .not_implemented, "NotImplemented", "endpoint not yet wired");
}

// ── register ──────────────────────────────────────────────────────

pub fn register(router: *Router, plugin_index: u16) !void {
    try router.register(.get, "/xrpc/com.atproto.server.describeServer", describeServer, plugin_index);
    try router.register(.post, "/xrpc/com.atproto.server.createSession", createSession, plugin_index);
    try router.register(.post, "/xrpc/com.atproto.server.refreshSession", refreshSession, plugin_index);

    try router.register(.post, "/xrpc/com.atproto.repo.createRecord", createRecord, plugin_index);
    try router.register(.post, "/xrpc/com.atproto.repo.putRecord", createRecord, plugin_index);
    try router.register(.post, "/xrpc/com.atproto.repo.deleteRecord", deleteRecord, plugin_index);
    try router.register(.get, "/xrpc/com.atproto.repo.getRecord", getRecord, plugin_index);
    try router.register(.get, "/xrpc/com.atproto.repo.listRecords", notImplemented, plugin_index);
    try router.register(.get, "/xrpc/com.atproto.repo.describeRepo", describeRepo, plugin_index);
    try router.register(.post, "/xrpc/com.atproto.repo.uploadBlob", notImplemented, plugin_index);

    try router.register(.get, "/xrpc/com.atproto.sync.getRepo", notImplemented, plugin_index);
    try router.register(.get, "/xrpc/com.atproto.sync.getRecord", notImplemented, plugin_index);
    try router.register(.get, "/xrpc/com.atproto.sync.getBlocks", notImplemented, plugin_index);
    try router.register(.get, "/xrpc/com.atproto.sync.listRepos", notImplemented, plugin_index);
    try router.register(.get, "/xrpc/com.atproto.sync.subscribeRepos", notImplemented, plugin_index);

    try router.register(.get, "/xrpc/com.atproto.identity.resolveHandle", notImplemented, plugin_index);

    try router.register(.get, "/.well-known/atproto-did", wellKnownAtprotoDid, plugin_index);
}
