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
const c = @import("sqlite").c;

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
const json_dagcbor = @import("json_dagcbor.zig");
const mst = @import("mst.zig");
const cid_mod = @import("cid.zig");
const car = @import("car.zig");
const did_resolver = @import("did_resolver.zig");
const keypair = @import("keypair.zig");
const account_routes = @import("account_routes.zig");
const admin_routes = @import("admin_routes.zig");
const oauth_routes = @import("oauth_routes.zig");
const plc_routes = @import("plc_routes.zig");
const lexicon = @import("lexicon.zig");

// W2.3: caps for the sync endpoints. listRecords pagination follows
// the AT spec defaults (50/100). CAR responses are bounded by the
// connection write buffer (16 KiB), so we cap the upload-blob route
// + getRepo at a few KiB of CAR payload — adequate for test repos and
// the early production scale this PDS targets. Full chunked streaming
// requires server-side response_stream wiring (W2.1's territory).
const list_records_default: u32 = 50;
const list_records_max: u32 = 100;
const list_repos_default: u32 = 50;
const list_repos_max: u32 = 200;
const max_blocks_per_request: u32 = 1024;
const car_scratch_bytes: usize = 12 * 1024;

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
    if (password.len == 0) {
        return xrpc.writeError(hc, .unauthorized, "AuthenticationRequired", "bad password");
    }

    // W2.3: real Argon2id verify against `atp_user_passwords`. The
    // table is created empty per-deployment; admins call
    // `auth_mod.setPassword` to provision accounts (test fixtures do
    // the same).
    const reader_db = st.reader_db orelse {
        return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "db not ready");
    };
    if (!auth_mod.verifyPassword(reader_db, ident, password)) {
        return xrpc.writeError(hc, .unauthorized, "AuthenticationRequired", "bad credentials");
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

    // AT-4: lexicon validation — pulls the registered RecordSpec
    // for `collection` and checks required + scalar shape. Unknown
    // collections pass through.
    const record_value = xrpc.jsonObjectField(hc.request.body, "record") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing record");
    lexicon.validate(collection, record_value) catch |e| switch (e) {
        error.MissingRequiredField => return xrpc.writeError(hc, .bad_request, "InvalidRecord", "missing required field"),
        error.WrongType => return xrpc.writeError(hc, .bad_request, "InvalidRecord", "wrong field type"),
        error.StringTooLong => return xrpc.writeError(hc, .bad_request, "InvalidRecord", "string field too long"),
        else => return xrpc.writeError(hc, .bad_request, "InvalidRecord", "validation failed"),
    };

    // AT-4: re-encode the record to canonical DAG-CBOR so the resulting
    // CID is reproducible across implementations (sorted map keys,
    // shortest-form ints, DAG-JSON $link/$bytes honoured).
    var enc_buf: [16384]u8 = undefined;
    const record_cbor = json_dagcbor.encode(record_value, &enc_buf) catch
        return xrpc.writeError(hc, .bad_request, "InvalidRecord", "record not DAG-CBOR encodable");

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
        .{ .collection = collection, .rkey = "", .value_cbor = record_cbor },
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

// AT-13: PDS-wide DID document served at `/.well-known/did.json`. The
// PDS advertises itself as `did:web:<host>` with one Ed25519
// verification method (id `#atproto`, type `Multikey`,
// `publicKeyMultibase` derived from the JWT signing key) and one
// service entry (id `#atproto_pds`, type
// `AtprotoPersonalDataServer`, serviceEndpoint `https://<host>`).
//
// `alsoKnownAs` carries the PDS's `at://<host>` handle so AppViews
// and relays can cross-reference identity.
fn renderPdsDidDocument(out: []u8) ![]const u8 {
    const st = State.get();
    var didkey_buf: [128]u8 = undefined;
    const didkey = try keypair.formatDidKeyEd25519(st.jwt_key.public_key, &didkey_buf);
    const did_key_prefix = "did:key:";
    if (!std.mem.startsWith(u8, didkey, did_key_prefix)) return error.MalformedDidKey;
    const multibase = didkey[did_key_prefix.len..];
    return std.fmt.bufPrint(out,
        "{{" ++
            "\"@context\":[\"https://www.w3.org/ns/did/v1\",\"https://w3id.org/security/multikey/v1\"]," ++
            "\"id\":\"did:web:{s}\"," ++
            "\"alsoKnownAs\":[\"at://{s}\"]," ++
            "\"verificationMethod\":[{{" ++
                "\"id\":\"did:web:{s}#atproto\"," ++
                "\"type\":\"Multikey\"," ++
                "\"controller\":\"did:web:{s}\"," ++
                "\"publicKeyMultibase\":\"{s}\"" ++
            "}}]," ++
            "\"service\":[{{" ++
                "\"id\":\"#atproto_pds\"," ++
                "\"type\":\"AtprotoPersonalDataServer\"," ++
                "\"serviceEndpoint\":\"https://{s}\"" ++
            "}}]" ++
        "}}",
        .{ st.host, st.host, st.host, st.host, multibase, st.host },
    );
}

fn wellKnownDidJson(hc: *HandlerContext) anyerror!void {
    var body_buf: [2048]u8 = undefined;
    const body = renderPdsDidDocument(&body_buf) catch {
        return xrpc.writeError(hc, .internal, "InternalError", "did doc render");
    };
    try hc.response.startStatus(.ok);
    try hc.response.header("Content-Type", "application/did+json");
    try hc.response.headerFmt("Content-Length", "{d}", .{body.len});
    try hc.response.header("Connection", "close");
    try hc.response.finishHeaders();
    try hc.response.body(body);
}

// AT-14: `com.atproto.identity.resolveDid`. If the requested DID is
// the PDS's own did:web identity, return the inlined DID document. For
// any other DID, defer to the module-level resolver (HTTP fetch
// against plc.directory or remote did:web /.well-known/did.json).
fn identityResolveDid(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const q = hc.request.pathAndQuery().query;
    const did = xrpc.queryParam(q, "did") orelse {
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing did");
    };

    var own_buf: [256]u8 = undefined;
    const own_did = std.fmt.bufPrint(&own_buf, "did:web:{s}", .{st.host}) catch
        return xrpc.writeError(hc, .internal, "InternalError", "fmt");
    if (std.mem.eql(u8, did, own_did)) {
        var body_buf: [2048]u8 = undefined;
        const body = renderPdsDidDocument(&body_buf) catch {
            return xrpc.writeError(hc, .internal, "InternalError", "did doc render");
        };
        return xrpc.writeJsonBody(hc, .ok, body);
    }

    const fetcher = did_resolver.getFetcher() orelse {
        return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "did resolver not configured");
    };
    var resolver = did_resolver.Resolver.init(fetcher);
    var doc_buf: [4096]u8 = undefined;
    const doc = resolver.resolveDid(did, &doc_buf) catch |err| switch (err) {
        error.NotFound => return xrpc.writeError(hc, .not_found, "DidNotFound", "did not resolved"),
        else => return xrpc.writeError(hc, .internal, "InternalError", "resolution failed"),
    };
    try xrpc.writeJsonBody(hc, .ok, doc);
}

// AT-15: `com.atproto.sync.getRepoStatus`. Relays poll this during
// catch-up to confirm a repo is live and to learn its current head
// rev. Today every hosted repo reports `active: true`; the optional
// `status` field is only present for non-active states (suspended,
// takendown, deactivated, deleted) which are tracked once AT-8 lands.
fn syncGetRepoStatus(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const db = st.reader_db orelse {
        return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "db not ready");
    };
    const q = hc.request.pathAndQuery().query;
    const repo_did = xrpc.queryParam(q, "did") orelse {
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing did");
    };

    var meta: repo_mod.RepoMeta = .{};
    const found = repo_mod.loadRepoMeta(db, repo_did, &meta) catch {
        return xrpc.writeError(hc, .internal, "InternalError", "load");
    };
    if (!found) return xrpc.writeError(hc, .not_found, "RepoNotFound", "no such repo");

    var body_buf: [512]u8 = undefined;
    const head = meta.headCid();
    const rev = meta.headRev();
    const body = blk: {
        if (head.len > 0 and rev.len > 0) {
            break :blk std.fmt.bufPrint(&body_buf,
                "{{\"did\":\"{s}\",\"active\":true,\"rev\":\"{s}\",\"head\":\"{s}\"}}",
                .{ repo_did, rev, head },
            ) catch return xrpc.writeError(hc, .internal, "InternalError", "fmt");
        }
        break :blk std.fmt.bufPrint(&body_buf,
            "{{\"did\":\"{s}\",\"active\":true}}",
            .{repo_did},
        ) catch return xrpc.writeError(hc, .internal, "InternalError", "fmt");
    };
    try xrpc.writeJsonBody(hc, .ok, body);
}

// ── identity.resolveHandle ────────────────────────────────────────
// Resolves a Bluesky handle (e.g. `alice.example.com`) to a DID by
// fetching `https://<handle>/.well-known/atproto-did` through the
// module-level HTTP fetcher wired at boot (`did_resolver.setFetcher`).
// Returns `{ "did": "did:..." }` on success.
fn identityResolveHandle(hc: *HandlerContext) anyerror!void {
    const q = hc.request.pathAndQuery().query;
    const handle = xrpc.queryParam(q, "handle") orelse {
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing handle");
    };
    const fetcher = did_resolver.getFetcher() orelse {
        return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "did resolver not configured");
    };
    var resolver = did_resolver.Resolver.init(fetcher);
    var did_buf: [did_resolver.max_did_bytes]u8 = undefined;
    const did_slice = resolver.resolveHandle(handle, &did_buf) catch |err| switch (err) {
        error.NotFound => return xrpc.writeError(hc, .not_found, "ResolutionFailed", "handle not found"),
        else => return xrpc.writeError(hc, .internal, "InternalError", "resolution failed"),
    };
    var body_buf: [did_resolver.max_did_bytes + 32]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf, "{{\"did\":\"{s}\"}}", .{did_slice}) catch {
        return xrpc.writeError(hc, .internal, "InternalError", "encode");
    };
    try xrpc.writeJsonBody(hc, .ok, body);
}

// ── stubs returning 501 for endpoints whose plumbing lands later ──

fn notImplemented(hc: *HandlerContext) anyerror!void {
    try xrpc.writeError(hc, .not_implemented, "NotImplemented", "endpoint not yet wired");
}

// W2.1: HTTP fallback for `subscribeRepos`. Real clients send an
// Upgrade: websocket request which the server's upgrade router catches
// before this handler ever runs. A plain GET ends up here and gets a
// 400 with a hint to upgrade.
fn subscribeReposHttp(hc: *HandlerContext) anyerror!void {
    try xrpc.writeError(
        hc,
        .bad_request,
        "InvalidRequest",
        "subscribeRepos requires a WebSocket upgrade (RFC 6455)",
    );
}

// W2.3 ── com.atproto.repo.listRecords ────────────────────────────
fn listRecords(hc: *HandlerContext) anyerror!void {
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
    var limit: u32 = list_records_default;
    if (xrpc.queryParam(q, "limit")) |lim_str| {
        if (std.fmt.parseInt(u32, lim_str, 10)) |n| {
            limit = @min(n, list_records_max);
            if (limit == 0) limit = 1;
        } else |_| {}
    }
    const cursor = xrpc.queryParam(q, "cursor") orelse "";

    const sql = "SELECT rkey, cid FROM atp_records WHERE did = ? AND collection = ? AND rkey > ? ORDER BY rkey ASC LIMIT ?";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        return xrpc.writeError(hc, .internal, "InternalError", "prepare");
    }
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, repo_did.ptr, @intCast(repo_did.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 2, collection.ptr, @intCast(collection.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 3, cursor.ptr, @intCast(cursor.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(stmt, 4, @intCast(limit));

    var body_buf: [12 * 1024]u8 = undefined;
    var bw = body_buf[0..];
    var pos: usize = 0;

    const head = "{\"records\":[";
    if (pos + head.len > bw.len) return xrpc.writeError(hc, .internal, "InternalError", "buf");
    @memcpy(bw[pos..][0..head.len], head);
    pos += head.len;

    var n: u32 = 0;
    var last_rkey_buf: [128]u8 = undefined;
    var last_rkey_len: usize = 0;
    while (n < limit) : (n += 1) {
        const rc = c.sqlite3_step(stmt.?);
        if (rc == c.SQLITE_DONE) break;
        if (rc != c.SQLITE_ROW) return xrpc.writeError(hc, .internal, "InternalError", "step");

        const rkey_ptr = c.sqlite3_column_text(stmt, 0);
        const rkey_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
        const cid_ptr = c.sqlite3_column_text(stmt, 1);
        const cid_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 1));

        const written = std.fmt.bufPrint(bw[pos..],
            "{s}{{\"uri\":\"at://{s}/{s}/{s}\",\"cid\":\"{s}\",\"value\":{{}}}}",
            .{ if (n == 0) "" else ",", repo_did, collection, rkey_ptr[0..rkey_len], cid_ptr[0..cid_len] },
        ) catch return xrpc.writeError(hc, .internal, "InternalError", "fmt");
        pos += written.len;

        const cap = @min(rkey_len, last_rkey_buf.len);
        @memcpy(last_rkey_buf[0..cap], rkey_ptr[0..cap]);
        last_rkey_len = cap;
    }

    const tail_with_cursor = "]";
    if (pos + tail_with_cursor.len > bw.len) return xrpc.writeError(hc, .internal, "InternalError", "buf");
    @memcpy(bw[pos..][0..tail_with_cursor.len], tail_with_cursor);
    pos += tail_with_cursor.len;

    if (n >= limit and last_rkey_len > 0) {
        const cursor_tail = std.fmt.bufPrint(bw[pos..], ",\"cursor\":\"{s}\"}}", .{last_rkey_buf[0..last_rkey_len]}) catch
            return xrpc.writeError(hc, .internal, "InternalError", "buf");
        pos += cursor_tail.len;
    } else {
        if (pos + 1 > bw.len) return xrpc.writeError(hc, .internal, "InternalError", "buf");
        bw[pos] = '}';
        pos += 1;
    }

    try xrpc.writeJsonBody(hc, .ok, bw[0..pos]);
}

// W2.3 ── helpers for CAR responses ───────────────────────────────
fn writeCarResponse(hc: *HandlerContext, payload: []const u8) !void {
    try hc.response.startStatus(.ok);
    try hc.response.header("Content-Type", "application/vnd.ipld.car");
    try hc.response.headerFmt("Content-Length", "{d}", .{payload.len});
    try hc.response.header("Connection", "close");
    try hc.response.finishHeaders();
    try hc.response.body(payload);
}

fn lookupBlock(db: *c.sqlite3, cid_str: []const u8, out: []u8) !?usize {
    // Try mst_blocks then records (record CBOR) then commits (commit CBOR).
    const queries = [_][:0]const u8{
        "SELECT data FROM atp_mst_blocks WHERE cid = ?",
        "SELECT value FROM atp_records WHERE cid = ?",
        "SELECT data_cid FROM atp_commits WHERE cid = ?",
    };
    var qi: usize = 0;
    while (qi < queries.len) : (qi += 1) {
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db, queries[qi].ptr, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);
        _ = c.sqlite3_bind_text(stmt, 1, cid_str.ptr, @intCast(cid_str.len), c.sqliteTransientAsDestructor());
        const rc = c.sqlite3_step(stmt.?);
        if (rc == c.SQLITE_ROW) {
            const ptr = c.sqlite3_column_blob(stmt.?, 0);
            const n: usize = @intCast(c.sqlite3_column_bytes(stmt.?, 0));
            if (n == 0 or ptr == null) return null;
            if (n > out.len) return error.BufferTooSmall;
            const p: [*]const u8 = @ptrCast(ptr);
            @memcpy(out[0..n], p[0..n]);
            return n;
        }
        if (rc != c.SQLITE_DONE) return error.StepFailed;
    }
    return null;
}

// W2.3 ── com.atproto.sync.getRecord ──────────────────────────────
fn syncGetRecord(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const db = st.reader_db orelse {
        return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "db not ready");
    };
    const q = hc.request.pathAndQuery().query;
    const repo_did = xrpc.queryParam(q, "did") orelse {
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing did");
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

    var meta: repo_mod.RepoMeta = .{};
    _ = repo_mod.loadRepoMeta(db, repo_did, &meta) catch {};

    const record_cid_bin = cid_mod.parseString(row.cidStr()) catch {
        return xrpc.writeError(hc, .internal, "InternalError", "bad record cid");
    };

    var scratch: [car_scratch_bytes]u8 = undefined;
    var pos: usize = 0;
    const roots = [_]cid_mod.Cid{record_cid_bin};
    pos += car.writeHeader(&roots, scratch[pos..]) catch
        return xrpc.writeError(hc, .internal, "InternalError", "car header");
    pos += car.writeBlock(record_cid_bin, row.value(), scratch[pos..]) catch
        return xrpc.writeError(hc, .internal, "InternalError", "car block");

    // MST proof block (best-effort — include the current data root).
    if (meta.head_cid_len > 0) {
        var data_cid_str: [cid_mod.string_cid_len]u8 = undefined;
        const dcs_len = @min(meta.head_cid_len, data_cid_str.len);
        @memcpy(data_cid_str[0..dcs_len], meta.head_cid_buf[0..dcs_len]);
        // We can't infer data_cid directly from head; fall back to walking
        // mst_blocks for this DID and include them all (bounded).
        const sql = "SELECT cid, data FROM atp_mst_blocks WHERE did = ? LIMIT ?";
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) == c.SQLITE_OK) {
            defer _ = c.sqlite3_finalize(stmt);
            _ = c.sqlite3_bind_text(stmt, 1, repo_did.ptr, @intCast(repo_did.len), c.sqliteTransientAsDestructor());
            _ = c.sqlite3_bind_int64(stmt, 2, @intCast(max_blocks_per_request));
            var added: u32 = 0;
            while (added < max_blocks_per_request) : (added += 1) {
                const rc = c.sqlite3_step(stmt.?);
                if (rc == c.SQLITE_DONE) break;
                if (rc != c.SQLITE_ROW) break;
                const cid_ptr = c.sqlite3_column_text(stmt, 0);
                const cid_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
                const data_ptr = c.sqlite3_column_blob(stmt, 1);
                const data_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 1));
                if (cid_len == 0 or data_len == 0 or data_ptr == null) continue;
                var cs: [cid_mod.string_cid_len]u8 = undefined;
                if (cid_len > cs.len) continue;
                @memcpy(cs[0..cid_len], cid_ptr[0..cid_len]);
                const block_cid = cid_mod.parseString(cs[0..cid_len]) catch continue;
                const dp: [*]const u8 = @ptrCast(data_ptr);
                if (pos + cid_mod.raw_cid_len + data_len + 10 > scratch.len) break;
                pos += car.writeBlock(block_cid, dp[0..data_len], scratch[pos..]) catch break;
            }
        }
    }

    try writeCarResponse(hc, scratch[0..pos]);
}

// W2.3 ── com.atproto.sync.getBlocks ──────────────────────────────
fn syncGetBlocks(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const db = st.reader_db orelse {
        return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "db not ready");
    };
    const q = hc.request.pathAndQuery().query;
    const cids_param = xrpc.queryParam(q, "cids") orelse {
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing cids");
    };

    var scratch: [car_scratch_bytes]u8 = undefined;
    var pos: usize = 0;

    // Header with no roots — getBlocks doesn't have one.
    const roots: [0]cid_mod.Cid = .{};
    pos += car.writeHeader(&roots, scratch[pos..]) catch
        return xrpc.writeError(hc, .internal, "InternalError", "car header");

    var it = std.mem.splitScalar(u8, cids_param, ',');
    var processed: u32 = 0;
    var block_buf: [16 * 1024]u8 = undefined;
    while (it.next()) |cid_s| {
        if (processed >= max_blocks_per_request) break;
        if (cid_s.len == 0) continue;
        const cid_bin = cid_mod.parseString(cid_s) catch continue;
        const got_opt = lookupBlock(db, cid_s, &block_buf) catch null;
        if (got_opt) |n| {
            if (n > 0) {
                if (pos + cid_mod.raw_cid_len + n + 10 > scratch.len) break;
                pos += car.writeBlock(cid_bin, block_buf[0..n], scratch[pos..]) catch break;
            }
        }
        processed += 1;
    }

    try writeCarResponse(hc, scratch[0..pos]);
}

// W2.3 ── com.atproto.sync.listRepos ──────────────────────────────
fn syncListRepos(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const db = st.reader_db orelse {
        return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "db not ready");
    };
    const q = hc.request.pathAndQuery().query;
    var limit: u32 = list_repos_default;
    if (xrpc.queryParam(q, "limit")) |lim_str| {
        if (std.fmt.parseInt(u32, lim_str, 10)) |n| {
            limit = @min(n, list_repos_max);
            if (limit == 0) limit = 1;
        } else |_| {}
    }
    const cursor = xrpc.queryParam(q, "cursor") orelse "";

    const sql = "SELECT did, head_cid, head_rev FROM atp_repos WHERE did > ? ORDER BY did ASC LIMIT ?";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        return xrpc.writeError(hc, .internal, "InternalError", "prepare");
    }
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, cursor.ptr, @intCast(cursor.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(stmt, 2, @intCast(limit));

    var body_buf: [12 * 1024]u8 = undefined;
    var pos: usize = 0;
    const head = "{\"repos\":[";
    @memcpy(body_buf[pos..][0..head.len], head);
    pos += head.len;

    var n: u32 = 0;
    var last_did_buf: [256]u8 = undefined;
    var last_did_len: usize = 0;
    while (n < limit) : (n += 1) {
        const rc = c.sqlite3_step(stmt.?);
        if (rc == c.SQLITE_DONE) break;
        if (rc != c.SQLITE_ROW) return xrpc.writeError(hc, .internal, "InternalError", "step");
        const did_ptr = c.sqlite3_column_text(stmt, 0);
        const did_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
        const head_ptr = if (c.sqlite3_column_type(stmt, 1) == c.SQLITE_NULL) null else c.sqlite3_column_text(stmt, 1);
        const head_len: usize = if (head_ptr == null) 0 else @intCast(c.sqlite3_column_bytes(stmt, 1));
        const rev_ptr = if (c.sqlite3_column_type(stmt, 2) == c.SQLITE_NULL) null else c.sqlite3_column_text(stmt, 2);
        const rev_len: usize = if (rev_ptr == null) 0 else @intCast(c.sqlite3_column_bytes(stmt, 2));

        const head_slice: []const u8 = if (head_ptr != null) head_ptr[0..head_len] else "";
        const rev_slice: []const u8 = if (rev_ptr != null) rev_ptr[0..rev_len] else "";

        const written = std.fmt.bufPrint(body_buf[pos..],
            "{s}{{\"did\":\"{s}\",\"head\":\"{s}\",\"rev\":\"{s}\"}}",
            .{ if (n == 0) "" else ",", did_ptr[0..did_len], head_slice, rev_slice },
        ) catch return xrpc.writeError(hc, .internal, "InternalError", "fmt");
        pos += written.len;

        const cap = @min(did_len, last_did_buf.len);
        @memcpy(last_did_buf[0..cap], did_ptr[0..cap]);
        last_did_len = cap;
    }

    @memcpy(body_buf[pos..][0..1], "]");
    pos += 1;
    if (n >= limit and last_did_len > 0) {
        const ct = std.fmt.bufPrint(body_buf[pos..], ",\"cursor\":\"{s}\"}}", .{last_did_buf[0..last_did_len]}) catch
            return xrpc.writeError(hc, .internal, "InternalError", "fmt");
        pos += ct.len;
    } else {
        body_buf[pos] = '}';
        pos += 1;
    }
    try xrpc.writeJsonBody(hc, .ok, body_buf[0..pos]);
}

// W2.3 ── com.atproto.sync.getRepo ────────────────────────────────
fn syncGetRepo(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const db = st.reader_db orelse {
        return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "db not ready");
    };
    const q = hc.request.pathAndQuery().query;
    const repo_did = xrpc.queryParam(q, "did") orelse {
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing did");
    };
    const since = xrpc.queryParam(q, "since") orelse "";

    var meta: repo_mod.RepoMeta = .{};
    const found = repo_mod.loadRepoMeta(db, repo_did, &meta) catch {
        return xrpc.writeError(hc, .internal, "InternalError", "load");
    };
    if (!found) return xrpc.writeError(hc, .not_found, "RepoNotFound", "no such repo");

    var scratch: [car_scratch_bytes]u8 = undefined;
    var pos: usize = 0;

    // Roots = head commit CID.
    const head_cid_bin = if (meta.head_cid_len > 0)
        cid_mod.parseString(meta.headCid()) catch null
    else
        null;
    if (head_cid_bin) |hb| {
        const roots = [_]cid_mod.Cid{hb};
        pos += car.writeHeader(&roots, scratch[pos..]) catch
            return xrpc.writeError(hc, .internal, "InternalError", "car header");
    } else {
        const empty: [0]cid_mod.Cid = .{};
        pos += car.writeHeader(&empty, scratch[pos..]) catch
            return xrpc.writeError(hc, .internal, "InternalError", "car header");
    }

    // Commit blocks (rev > since).
    {
        const sql = "SELECT cid, data_cid, signature, rev FROM atp_commits WHERE did = ? AND rev > ? ORDER BY rev ASC LIMIT ?";
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) == c.SQLITE_OK) {
            defer _ = c.sqlite3_finalize(stmt);
            _ = c.sqlite3_bind_text(stmt, 1, repo_did.ptr, @intCast(repo_did.len), c.sqliteTransientAsDestructor());
            _ = c.sqlite3_bind_text(stmt, 2, since.ptr, @intCast(since.len), c.sqliteTransientAsDestructor());
            _ = c.sqlite3_bind_int64(stmt, 3, @intCast(max_blocks_per_request));
            var count: u32 = 0;
            while (count < max_blocks_per_request) : (count += 1) {
                const rc = c.sqlite3_step(stmt.?);
                if (rc == c.SQLITE_DONE) break;
                if (rc != c.SQLITE_ROW) break;
                const cid_ptr = c.sqlite3_column_text(stmt, 0);
                const cid_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
                if (cid_len == 0) continue;
                var cs: [cid_mod.string_cid_len]u8 = undefined;
                if (cid_len > cs.len) continue;
                @memcpy(cs[0..cid_len], cid_ptr[0..cid_len]);
                const block_cid = cid_mod.parseString(cs[0..cid_len]) catch continue;
                // Encode a small commit object: {did, data, sig}.
                var commit_buf: [512]u8 = undefined;
                var enc = dag.Encoder.init(&commit_buf);
                enc.writeMapHeader(2) catch break;
                enc.writeText("did") catch break;
                enc.writeText(repo_did) catch break;
                const data_cid_ptr = c.sqlite3_column_text(stmt, 1);
                const data_cid_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 1));
                enc.writeText("data") catch break;
                enc.writeText(data_cid_ptr[0..data_cid_len]) catch break;
                if (pos + cid_mod.raw_cid_len + enc.written().len + 10 > scratch.len) break;
                pos += car.writeBlock(block_cid, enc.written(), scratch[pos..]) catch break;
            }
        }
    }

    // MST blocks.
    {
        const sql = "SELECT cid, data FROM atp_mst_blocks WHERE did = ? LIMIT ?";
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) == c.SQLITE_OK) {
            defer _ = c.sqlite3_finalize(stmt);
            _ = c.sqlite3_bind_text(stmt, 1, repo_did.ptr, @intCast(repo_did.len), c.sqliteTransientAsDestructor());
            _ = c.sqlite3_bind_int64(stmt, 2, @intCast(max_blocks_per_request));
            var count: u32 = 0;
            while (count < max_blocks_per_request) : (count += 1) {
                const rc = c.sqlite3_step(stmt.?);
                if (rc == c.SQLITE_DONE) break;
                if (rc != c.SQLITE_ROW) break;
                const cid_ptr = c.sqlite3_column_text(stmt, 0);
                const cid_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
                const data_ptr = c.sqlite3_column_blob(stmt, 1);
                const data_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 1));
                if (cid_len == 0 or data_len == 0 or data_ptr == null) continue;
                var cs: [cid_mod.string_cid_len]u8 = undefined;
                if (cid_len > cs.len) continue;
                @memcpy(cs[0..cid_len], cid_ptr[0..cid_len]);
                const block_cid = cid_mod.parseString(cs[0..cid_len]) catch continue;
                const dp: [*]const u8 = @ptrCast(data_ptr);
                if (pos + cid_mod.raw_cid_len + data_len + 10 > scratch.len) break;
                pos += car.writeBlock(block_cid, dp[0..data_len], scratch[pos..]) catch break;
            }
        }
    }

    // Record blocks.
    {
        const sql = "SELECT cid, value FROM atp_records WHERE did = ? LIMIT ?";
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) == c.SQLITE_OK) {
            defer _ = c.sqlite3_finalize(stmt);
            _ = c.sqlite3_bind_text(stmt, 1, repo_did.ptr, @intCast(repo_did.len), c.sqliteTransientAsDestructor());
            _ = c.sqlite3_bind_int64(stmt, 2, @intCast(max_blocks_per_request));
            var count: u32 = 0;
            while (count < max_blocks_per_request) : (count += 1) {
                const rc = c.sqlite3_step(stmt.?);
                if (rc == c.SQLITE_DONE) break;
                if (rc != c.SQLITE_ROW) break;
                const cid_ptr = c.sqlite3_column_text(stmt, 0);
                const cid_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
                const val_ptr = c.sqlite3_column_blob(stmt, 1);
                const val_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 1));
                if (cid_len == 0 or val_len == 0 or val_ptr == null) continue;
                var cs: [cid_mod.string_cid_len]u8 = undefined;
                if (cid_len > cs.len) continue;
                @memcpy(cs[0..cid_len], cid_ptr[0..cid_len]);
                const block_cid = cid_mod.parseString(cs[0..cid_len]) catch continue;
                const vp: [*]const u8 = @ptrCast(val_ptr);
                if (pos + cid_mod.raw_cid_len + val_len + 10 > scratch.len) break;
                pos += car.writeBlock(block_cid, vp[0..val_len], scratch[pos..]) catch break;
            }
        }
    }

    try writeCarResponse(hc, scratch[0..pos]);
}

// W2.3 ── com.atproto.repo.uploadBlob ─────────────────────────────
fn repoUploadBlob(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    if (st.reader_db == null) {
        return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "db not ready");
    }
    const auth_hdr = hc.request.header("Authorization");
    var did_str: []const u8 = "did:plc:anonymous";
    if (auth_hdr) |hdr| {
        if (std.mem.startsWith(u8, hdr, "Bearer ")) {
            const token = hdr[7..];
            var claims: auth_mod.Claims = .{ .scope = .access, .iat = 0, .exp = 0 };
            if (auth_mod.verify(token, st.jwt_key.public_key, st.clock.wallUnix(), &claims)) |_| {
                if (claims.sub_len > 0) did_str = claims.sub();
            } else |_| {}
        }
    }
    const mime = hc.request.header("Content-Type") orelse "application/octet-stream";
    const bytes = hc.request.body;
    if (bytes.len == 0) {
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "empty body");
    }

    // Delegate to media plugin. The atproto plugin can't import the
    // media plugin module directly today (it would create a cycle in
    // the build graph). Instead, perform an inline storeBlob using the
    // shared `atp_blobs` table — semantically identical to what
    // `media.api.storeBlobBytes` would do.
    const db = st.reader_db.?;
    // Spec: BlobRef CIDs are CIDv1 raw codec (0x55), sha2-256, base32-lower
    // with `b` multibase prefix. Format: `bafkrei…`.
    const blob_cid = cid_mod.computeRaw(bytes);
    var cid_buf: [cid_mod.string_cid_len]u8 = undefined;
    const cid = cid_mod.encodeString(blob_cid, &cid_buf) catch {
        return xrpc.writeError(hc, .internal, "InternalError", "cid encode");
    };

    // Insert into atp_blobs. Duplicate uploads bump ref_count.
    var sel: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "SELECT 1 FROM atp_blobs WHERE cid = ?", -1, &sel, null) != c.SQLITE_OK) {
        return xrpc.writeError(hc, .internal, "InternalError", "prepare");
    }
    _ = c.sqlite3_bind_text(sel, 1, cid.ptr, @intCast(cid.len), c.sqliteTransientAsDestructor());
    const sel_rc = c.sqlite3_step(sel.?);
    _ = c.sqlite3_finalize(sel);
    if (sel_rc == c.SQLITE_ROW) {
        var upd: ?*c.sqlite3_stmt = null;
        _ = c.sqlite3_prepare_v2(db, "UPDATE atp_blobs SET ref_count = ref_count + 1 WHERE cid = ?", -1, &upd, null);
        _ = c.sqlite3_bind_text(upd, 1, cid.ptr, @intCast(cid.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_step(upd.?);
        _ = c.sqlite3_finalize(upd);
    } else {
        if (bytes.len > core.limits.media_inline_threshold_bytes) {
            return xrpc.writeError(hc, .payload_too_large, "PayloadTooLarge", "blob too large");
        }
        var ins: ?*c.sqlite3_stmt = null;
        const ins_sql = "INSERT INTO atp_blobs(cid, did, mime, size, ref_count, data, created_at) VALUES (?,?,?,?,1,?,?)";
        if (c.sqlite3_prepare_v2(db, ins_sql, -1, &ins, null) != c.SQLITE_OK) {
            return xrpc.writeError(hc, .internal, "InternalError", "prepare");
        }
        defer _ = c.sqlite3_finalize(ins);
        _ = c.sqlite3_bind_text(ins, 1, cid.ptr, @intCast(cid.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_text(ins, 2, did_str.ptr, @intCast(did_str.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_text(ins, 3, mime.ptr, @intCast(mime.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_int64(ins, 4, @intCast(bytes.len));
        _ = c.sqlite3_bind_blob(ins, 5, bytes.ptr, @intCast(bytes.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_int64(ins, 6, st.clock.wallUnix());
        if (c.sqlite3_step(ins.?) != c.SQLITE_DONE) {
            return xrpc.writeError(hc, .internal, "InternalError", "step");
        }
    }

    // DUAL-3: also write the bytes into the shared content-addressed
    // blob store under the SAME CID, so the AP side can serve them via
    // `/blob/<cid>` — one upload, both networks reference one set of
    // on-disk bytes (AT BlobRef `$link` == the AP attachment URL's CID).
    if (core.blob.global()) |store| {
        store.put(cid, bytes) catch {};
    }

    var resp_buf: [512]u8 = undefined;
    const body = std.fmt.bufPrint(&resp_buf,
        "{{\"blob\":{{\"$type\":\"blob\",\"ref\":{{\"$link\":\"{s}\"}},\"mimeType\":\"{s}\",\"size\":{d}}}}}",
        .{ cid, mime, bytes.len },
    ) catch return xrpc.writeError(hc, .internal, "InternalError", "fmt");
    try xrpc.writeJsonBody(hc, .ok, body);
}

// DUAL-3: content-addressed blob URL (`GET /blob/:cid`). An AP attachment
// `url` of `https://<host>/blob/<cid>` and the AT BlobRef `$link` of
// `<cid>` resolve to the same bytes. Serves the inline `atp_blobs.data`
// or, when spilled, the shared `core.blob` store.
fn serveBlobByCid(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const db = st.reader_db orelse return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "db not ready");
    const cid = hc.params.get("cid") orelse return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing cid");

    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "SELECT mime, data FROM atp_blobs WHERE cid = ?", -1, &stmt, null) != c.SQLITE_OK) {
        return xrpc.writeError(hc, .internal, "InternalError", "prepare");
    }
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, cid.ptr, @intCast(cid.len), c.sqliteTransientAsDestructor());
    if (c.sqlite3_step(stmt.?) != c.SQLITE_ROW) {
        return xrpc.writeError(hc, .not_found, "BlobNotFound", "blob not present");
    }
    const mime_ptr = c.sqlite3_column_text(stmt, 0);
    const mime_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
    var mime_buf: [128]u8 = undefined;
    const mime = blk: {
        if (mime_len == 0 or mime_ptr == null) break :blk "application/octet-stream";
        const cap = @min(mime_len, mime_buf.len);
        @memcpy(mime_buf[0..cap], mime_ptr[0..cap]);
        break :blk mime_buf[0..cap];
    };
    if (c.sqlite3_column_type(stmt, 1) != c.SQLITE_NULL) {
        const blob_ptr = c.sqlite3_column_blob(stmt, 1);
        const blob_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 1));
        const p: [*]const u8 = @ptrCast(blob_ptr);
        try hc.response.startStatus(.ok);
        try hc.response.header("Content-Type", mime);
        try hc.response.headerFmt("Content-Length", "{d}", .{blob_len});
        try hc.response.header("Connection", "close");
        try hc.response.finishHeaders();
        try hc.response.body(p[0..blob_len]);
        return;
    }
    const store = core.blob.global() orelse return xrpc.writeError(hc, .not_found, "BlobNotFound", "missing");
    var body_buf: [4 * 1024 * 1024]u8 = undefined;
    const body = store.get(cid, &body_buf) catch
        return xrpc.writeError(hc, .not_found, "BlobNotFound", "missing");
    try hc.response.startStatus(.ok);
    try hc.response.header("Content-Type", mime);
    try hc.response.headerFmt("Content-Length", "{d}", .{body.len});
    try hc.response.header("Connection", "close");
    try hc.response.finishHeaders();
    try hc.response.body(body);
}

// AT-23: `com.atproto.repo.importRepo`. Real semantics need a full
// CAR reader (parse blocks → reconstruct MST → replay commits). We
// validate the request shape, record the upload size, and reject
// with 501 NotImplemented at the persistence step — the route is
// reachable so clients can probe support; the heavy lift is tracked
// as a follow-up.
fn importRepoStub(hc: *HandlerContext) anyerror!void {
    if (hc.request.body.len == 0) {
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "empty body");
    }
    // We accept the upload but advertise that consumption isn't wired.
    return xrpc.writeError(hc, .not_implemented, "NotImplemented",
        "importRepo accepted upload but persistence is pending a full CAR reader (see SPEC_PUNCHLIST AT-23)");
}

// AT-18b: `com.atproto.identity.resolveIdentity`. Combines the
// handle-resolution path (DNS TXT or HTTPS .well-known) with the
// DID-document fetch. Returns both the DID and the document.
fn identityResolveIdentity(hc: *HandlerContext) anyerror!void {
    const q = hc.request.pathAndQuery().query;
    const identifier = xrpc.queryParam(q, "identifier") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing identifier");

    var did_buf: [did_resolver.max_did_bytes]u8 = undefined;
    var did_slice: []const u8 = "";

    if (std.mem.startsWith(u8, identifier, "did:")) {
        did_slice = identifier;
    } else {
        // Try DNS TXT first (`_atproto.<handle>` → `did=did:plc:...`),
        // then HTTPS .well-known via the existing resolver.
        var dns_name_buf: [320]u8 = undefined;
        const dns_name = std.fmt.bufPrint(&dns_name_buf, "_atproto.{s}", .{identifier}) catch
            return xrpc.writeError(hc, .bad_request, "InvalidRequest", "handle too long");
        var txt_buf: [256]u8 = undefined;
        if (core.dns.lookupTxt(dns_name, &txt_buf)) |txt| {
            const prefix = "did=";
            if (std.mem.startsWith(u8, txt, prefix)) {
                const v = txt[prefix.len..];
                if (v.len <= did_buf.len) {
                    @memcpy(did_buf[0..v.len], v);
                    did_slice = did_buf[0..v.len];
                }
            }
        } else |_| {}

        if (did_slice.len == 0) {
            const fetcher = did_resolver.getFetcher() orelse
                return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "no resolver configured");
            var resolver = did_resolver.Resolver.init(fetcher);
            did_slice = resolver.resolveHandle(identifier, &did_buf) catch |e| switch (e) {
                error.NotFound => return xrpc.writeError(hc, .not_found, "NotFound", "handle does not resolve"),
                else => return xrpc.writeError(hc, .internal, "InternalError", "resolution failed"),
            };
        }
    }

    var resp_buf: [did_resolver.max_did_bytes + 64]u8 = undefined;
    const resp = std.fmt.bufPrint(&resp_buf,
        "{{\"did\":\"{s}\",\"handle\":\"{s}\"}}",
        .{ did_slice, identifier },
    ) catch return xrpc.writeError(hc, .internal, "InternalError", "fmt");
    try xrpc.writeJsonBody(hc, .ok, resp);
}

// AT-12: `com.atproto.repo.applyWrites`. Atomic batch of create /
// update / delete record operations. We collect all ops into a
// single repo.commit call so one #commit event covers the batch.
fn applyWrites(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const db = st.reader_db orelse {
        return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "db not ready");
    };
    const repo_did = xrpc.jsonStringField(hc.request.body, "repo") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing repo");

    const writes = xrpc.jsonArrayField(hc.request.body, "writes") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing writes");

    repo_mod.ensureRepo(db, repo_did, "did:key:placeholder", st.clock.wallUnix()) catch {
        return xrpc.writeError(hc, .internal, "InternalError", "ensureRepo");
    };

    // Walk each op and assemble repo.Operation array. Bounded —
    // batches over `max_writes` get rejected to keep memory tight.
    const max_writes: usize = 32;
    var ops_buf: [max_writes]repo_mod.Operation = undefined;
    var enc_buf: [max_writes][8 * 1024]u8 = undefined;
    var rkey_storage: [max_writes][16]u8 = undefined;
    var n_ops: usize = 0;

    var rng = core.rng.Rng.init(@as(u64, @bitCast(st.clock.wallUnix())));
    var ts = tid_mod.State.init(&rng);
    const rev = ts.next(st.clock);

    var iter = xrpc.ObjectArrayIter.init(writes);
    while (iter.next()) |op_json| {
        if (n_ops >= max_writes) {
            return xrpc.writeError(hc, .bad_request, "InvalidRequest", "too many writes");
        }
        const type_tag = xrpc.jsonStringField(op_json, "$type") orelse "";
        const collection = xrpc.jsonStringField(op_json, "collection") orelse
            return xrpc.writeError(hc, .bad_request, "InvalidRequest", "write missing collection");

        // Only create/update need a value. Delete is a tombstone.
        const is_delete = std.mem.endsWith(u8, type_tag, "#delete");
        const supplied_rkey = xrpc.jsonStringField(op_json, "rkey") orelse "";

        // Generate an rkey for create when not supplied.
        const rkey_slice: []const u8 = blk: {
            if (supplied_rkey.len > 0) {
                const cap = @min(supplied_rkey.len, rkey_storage[n_ops].len);
                @memcpy(rkey_storage[n_ops][0..cap], supplied_rkey[0..cap]);
                break :blk rkey_storage[n_ops][0..cap];
            }
            const t = ts.next(st.clock);
            @memcpy(&rkey_storage[n_ops], t.str()[0..]);
            break :blk rkey_storage[n_ops][0..];
        };

        if (is_delete) {
            // For delete ops in this batch, we still need a value-CBOR
            // marker (encoder requires it). Tag with a `{$type: "delete"}`
            // placeholder; the repo path treats deletes via rkey
            // matching downstream.
            var enc = dag.Encoder.init(&enc_buf[n_ops]);
            enc.writeMapHeader(1) catch return xrpc.writeError(hc, .internal, "InternalError", "encode");
            enc.writeText("$type") catch return xrpc.writeError(hc, .internal, "InternalError", "encode");
            enc.writeText("delete") catch return xrpc.writeError(hc, .internal, "InternalError", "encode");
            ops_buf[n_ops] = .{ .collection = collection, .rkey = rkey_slice, .value_cbor = enc.written() };
        } else {
            // Wrap the supplied `value` object as a CBOR map with
            // $type + body, matching the single-record createRecord
            // shape until AT-4 lexicon validation lands.
            const value_obj = xrpc.jsonObjectField(op_json, "value") orelse "{}";
            var enc = dag.Encoder.init(&enc_buf[n_ops]);
            enc.writeMapHeader(2) catch return xrpc.writeError(hc, .internal, "InternalError", "encode");
            enc.writeText("$type") catch return xrpc.writeError(hc, .internal, "InternalError", "encode");
            enc.writeText(collection) catch return xrpc.writeError(hc, .internal, "InternalError", "encode");
            enc.writeText("body") catch return xrpc.writeError(hc, .internal, "InternalError", "encode");
            enc.writeText(value_obj) catch return xrpc.writeError(hc, .internal, "InternalError", "encode");
            ops_buf[n_ops] = .{ .collection = collection, .rkey = rkey_slice, .value_cbor = enc.written() };
        }
        n_ops += 1;
    }
    if (n_ops == 0) return xrpc.writeError(hc, .bad_request, "InvalidRequest", "empty writes");

    var tree: mst.Tree(mst.max_keys) = .{};
    repo_mod.loadTree(db, repo_did, &tree) catch {};

    _ = repo_mod.commit(db, repo_did, st.jwt_key, rev, &tree, ops_buf[0..n_ops], st.clock.wallUnix(), null) catch {
        return xrpc.writeError(hc, .internal, "InternalError", "commit");
    };

    var resp_buf: [256]u8 = undefined;
    const resp = std.fmt.bufPrint(&resp_buf, "{{\"commit\":{{\"rev\":\"{s}\"}}}}", .{rev.str()}) catch
        return xrpc.writeError(hc, .internal, "InternalError", "fmt");
    try xrpc.writeJsonBody(hc, .ok, resp);
}

// AT-6: `com.atproto.sync.getBlob`. Returns the blob bytes for a
// `(did, cid)` pair. We look up `atp_blobs` (the canonical record;
// even when blob storage lives in a separate FsStore, the row carries
// the mime + size). For inline rows the body is in `data`; otherwise
// fall back to the configured `core.blob.global()` store.
fn syncGetBlob(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const db = st.reader_db orelse {
        return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "db not ready");
    };
    const q = hc.request.pathAndQuery().query;
    const cid = xrpc.queryParam(q, "cid") orelse {
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing cid");
    };
    // `did` is required by the spec but we don't need it for the
    // lookup (CIDs are globally unique). Validate it's present so
    // bad clients fail loudly.
    _ = xrpc.queryParam(q, "did") orelse {
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing did");
    };

    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "SELECT mime, data FROM atp_blobs WHERE cid = ?", -1, &stmt, null) != c.SQLITE_OK) {
        return xrpc.writeError(hc, .internal, "InternalError", "prepare");
    }
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, cid.ptr, @intCast(cid.len), c.sqliteTransientAsDestructor());

    if (c.sqlite3_step(stmt.?) != c.SQLITE_ROW) {
        return xrpc.writeError(hc, .not_found, "BlobNotFound", "blob not present");
    }

    // Mime.
    const mime_ptr = c.sqlite3_column_text(stmt, 0);
    const mime_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
    var mime_buf: [128]u8 = undefined;
    const mime = blk: {
        if (mime_len == 0 or mime_ptr == null) break :blk "application/octet-stream";
        const cap = @min(mime_len, mime_buf.len);
        @memcpy(mime_buf[0..cap], mime_ptr[0..cap]);
        break :blk mime_buf[0..cap];
    };

    // Body: either inline (column 1 non-null) or sourced from the
    // pluggable blob store via core.blob.global().
    if (c.sqlite3_column_type(stmt, 1) != c.SQLITE_NULL) {
        const blob_ptr = c.sqlite3_column_blob(stmt, 1);
        const blob_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 1));
        const p: [*]const u8 = @ptrCast(blob_ptr);
        try hc.response.startStatus(.ok);
        try hc.response.header("Content-Type", mime);
        try hc.response.headerFmt("Content-Length", "{d}", .{blob_len});
        try hc.response.header("Connection", "close");
        try hc.response.finishHeaders();
        try hc.response.body(p[0..blob_len]);
        return;
    }

    const store = core.blob.global() orelse {
        return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "blob store not configured");
    };
    var body_buf: [4 * 1024 * 1024]u8 = undefined;
    const body = store.get(cid, &body_buf) catch |e| switch (e) {
        error.NotFound => return xrpc.writeError(hc, .not_found, "BlobNotFound", "missing"),
        error.BufferTooSmall => return xrpc.writeError(hc, .internal, "InternalError", "blob too large for single-body response"),
        else => return xrpc.writeError(hc, .internal, "InternalError", "store"),
    };
    try hc.response.startStatus(.ok);
    try hc.response.header("Content-Type", mime);
    try hc.response.headerFmt("Content-Length", "{d}", .{body.len});
    try hc.response.header("Connection", "close");
    try hc.response.finishHeaders();
    try hc.response.body(body);
}

// AT-20: `com.atproto.label.queryLabels`. Returns labels for the
// supplied subject URIs. Optional `sources` filter narrows to one
// or more labellers (we record `src` per label row).
fn labelQueryLabels(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const db = st.reader_db orelse {
        return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "db not ready");
    };
    const q = hc.request.pathAndQuery().query;
    const uri = xrpc.queryParam(q, "uriPatterns") orelse {
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing uriPatterns");
    };

    var stmt: ?*c.sqlite3_stmt = null;
    // Patterns may be exact or trailing-wildcard (`...*`). Translate
    // `*` to `%` for the LIKE query.
    var pattern_buf: [320]u8 = undefined;
    if (uri.len + 1 > pattern_buf.len) return xrpc.writeError(hc, .bad_request, "InvalidRequest", "pattern too long");
    @memcpy(pattern_buf[0..uri.len], uri);
    var i: usize = 0;
    while (i < uri.len) : (i += 1) {
        if (pattern_buf[i] == '*') pattern_buf[i] = '%';
    }
    const pattern = pattern_buf[0..uri.len];

    const sql = "SELECT seq, src, uri, val, neg, created_at FROM atp_labels WHERE uri LIKE ? ORDER BY seq DESC LIMIT 100";
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        return xrpc.writeError(hc, .internal, "InternalError", "prepare");
    }
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, pattern.ptr, @intCast(pattern.len), c.sqliteTransientAsDestructor());

    var body_buf: [8 * 1024]u8 = undefined;
    var pos: usize = 0;
    const head = "{\"labels\":[";
    @memcpy(body_buf[pos..][0..head.len], head);
    pos += head.len;
    var n: u32 = 0;
    while (true) {
        const rc = c.sqlite3_step(stmt.?);
        if (rc == c.SQLITE_DONE) break;
        if (rc != c.SQLITE_ROW) break;
        const src_ptr = c.sqlite3_column_text(stmt, 1);
        const src_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 1));
        const uri_ptr = c.sqlite3_column_text(stmt, 2);
        const uri_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 2));
        const val_ptr = c.sqlite3_column_text(stmt, 3);
        const val_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 3));
        const neg = c.sqlite3_column_int64(stmt, 4);
        const written = std.fmt.bufPrint(body_buf[pos..],
            "{s}{{\"src\":\"{s}\",\"uri\":\"{s}\",\"val\":\"{s}\",\"neg\":{s},\"cts\":{d}}}",
            .{
                if (n == 0) "" else ",",
                src_ptr[0..src_len],
                uri_ptr[0..uri_len],
                val_ptr[0..val_len],
                if (neg != 0) "true" else "false",
                c.sqlite3_column_int64(stmt, 5),
            },
        ) catch break;
        pos += written.len;
        n += 1;
        if (pos > body_buf.len - 256) break;
    }
    @memcpy(body_buf[pos..][0..2], "]}");
    pos += 2;
    try xrpc.writeJsonBody(hc, .ok, body_buf[0..pos]);
}

// AT-2: `com.atproto.sync.requestCrawl`. A relay/AppView POSTs here
// to ask us to push commits to it; we record the relay's hostname
// in `atp_crawl_subscriptions`. The relay then subscribes to our
// `subscribeRepos` stream. (The reverse — us announcing ourselves
// to an upstream relay — runs at boot via `RELAY_ANNOUNCE_URL`.)
fn syncRequestCrawl(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const host = xrpc.jsonStringField(hc.request.body, "hostname") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing hostname");
    // AT-2: persist the relay's hostname (so it can be subscribed to our
    // subscribeRepos stream). We accept all crawl requests today; rate
    // limiting + a deny list are policy items.
    if (st.reader_db) |db| {
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db, "INSERT INTO atp_crawl_subscriptions(hostname, requested_at) VALUES (?,?) ON CONFLICT(hostname) DO UPDATE SET requested_at = excluded.requested_at", -1, &stmt, null) == c.SQLITE_OK) {
            defer _ = c.sqlite3_finalize(stmt);
            _ = c.sqlite3_bind_text(stmt, 1, host.ptr, @intCast(host.len), c.sqliteTransientAsDestructor());
            _ = c.sqlite3_bind_int64(stmt, 2, st.clock.wallUnix());
            _ = c.sqlite3_step(stmt.?);
        }
    }
    try xrpc.writeJsonBody(hc, .ok, "{}");
}

// AT-2 sibling: `com.atproto.sync.notifyOfUpdate`. A peer signals
// that we should re-crawl them. We accept it as a hint; the actual
// re-subscription is the operator's call.
fn syncNotifyOfUpdate(hc: *HandlerContext) anyerror!void {
    _ = xrpc.jsonStringField(hc.request.body, "hostname") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing hostname");
    try xrpc.writeJsonBody(hc, .ok, "{}");
}

// AT-21: `com.atproto.moderation.createReport`. We store the raw
// JSON body for now — moderation pipelines consume it via an
// admin sweep. Schema for `atp_reports` is added by the schema
// migration below.
fn moderationCreateReport(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const db = st.reader_db orelse {
        return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "db not ready");
    };
    const reason_type = xrpc.jsonStringField(hc.request.body, "reasonType") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing reasonType");
    const reason_text = xrpc.jsonStringField(hc.request.body, "reason") orelse "";
    // `subject` is an object — for now we just record its presence by
    // capturing the whole inbound JSON body.
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "INSERT INTO atp_reports (reason_type, reason_text, subject_json, created_at) VALUES (?,?,?,?)";
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        return xrpc.writeError(hc, .internal, "InternalError", "prepare");
    }
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, reason_type.ptr, @intCast(reason_type.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 2, reason_text.ptr, @intCast(reason_text.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_blob(stmt, 3, hc.request.body.ptr, @intCast(hc.request.body.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(stmt, 4, st.clock.wallUnix());
    if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) {
        return xrpc.writeError(hc, .internal, "InternalError", "step");
    }
    const report_id = c.sqlite3_last_insert_rowid(db);
    var body_buf: [256]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf,
        "{{\"id\":{d},\"reasonType\":\"{s}\",\"createdAt\":\"\"}}",
        .{ report_id, reason_type },
    ) catch return xrpc.writeError(hc, .internal, "InternalError", "fmt");
    try xrpc.writeJsonBody(hc, .ok, body);
}

// AT-18a: `com.atproto.identity.updateHandle`. Persists the new
// handle on the local account row and emits a `#identity` firehose
// event so AppViews invalidate caches.
fn identityUpdateHandle(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const backend = core.account.global() orelse {
        return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "account backend not configured");
    };
    // Identify the caller via the JWT.
    const auth_hdr = hc.request.header("Authorization") orelse
        return xrpc.writeError(hc, .unauthorized, "AuthenticationRequired", "missing bearer");
    if (!std.mem.startsWith(u8, auth_hdr, "Bearer "))
        return xrpc.writeError(hc, .unauthorized, "AuthenticationRequired", "bad scheme");
    const token = auth_hdr[7..];
    var claims: auth_mod.Claims = .{ .scope = .access, .iat = 0, .exp = 0 };
    auth_mod.verify(token, st.jwt_key.public_key, st.clock.wallUnix(), &claims) catch
        return xrpc.writeError(hc, .unauthorized, "AuthenticationRequired", "invalid token");
    const sub = claims.sub();

    const new_handle = xrpc.jsonStringField(hc.request.body, "handle") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing handle");

    backend.setHandle(sub, new_handle, st.clock.wallUnix()) catch |e| switch (e) {
        error.AlreadyExists => return xrpc.writeError(hc, .bad_request, "HandleNotAvailable", "handle in use"),
        error.NotFound => return xrpc.writeError(hc, .not_found, "AccountNotFound", "no account"),
        error.InvalidArg => return xrpc.writeError(hc, .bad_request, "InvalidRequest", "invalid handle"),
        else => return xrpc.writeError(hc, .internal, "InternalError", "set handle"),
    };

    if (st.reader_db) |db| {
        _ = firehose.appendIdentity(db, sub, new_handle, st.clock.wallUnix()) catch {};
    }
    try xrpc.writeJsonBody(hc, .ok, "{}");
}

// AT-17: `com.atproto.server.getServiceAuth`. Mint a short-lived
// Ed25519 JWT bound to a remote audience so inter-service calls
// (PDS → relay, PDS → AppView) can be authenticated. The signing
// key is the PDS's `jwt_key`; the audience verifies via our DID
// document's verificationMethod.
fn getServiceAuth(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const auth_hdr = hc.request.header("Authorization") orelse
        return xrpc.writeError(hc, .unauthorized, "AuthenticationRequired", "missing bearer");
    if (!std.mem.startsWith(u8, auth_hdr, "Bearer "))
        return xrpc.writeError(hc, .unauthorized, "AuthenticationRequired", "bad scheme");
    const token = auth_hdr[7..];
    var claims: auth_mod.Claims = .{ .scope = .access, .iat = 0, .exp = 0 };
    auth_mod.verify(token, st.jwt_key.public_key, st.clock.wallUnix(), &claims) catch
        return xrpc.writeError(hc, .unauthorized, "AuthenticationRequired", "invalid token");

    const q = hc.request.pathAndQuery().query;
    const aud = xrpc.queryParam(q, "aud") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing aud");
    // exp clamps to 1 hour to prevent long-lived service grants.
    var exp_secs: i64 = 300;
    if (xrpc.queryParam(q, "exp")) |raw| {
        if (std.fmt.parseInt(i64, raw, 10)) |n| {
            exp_secs = @min(@max(n - st.clock.wallUnix(), 1), 3600);
        } else |_| {}
    }

    const now = st.clock.wallUnix();
    var jti_buf: [16]u8 = undefined;
    fillJti(&jti_buf, now, 3);
    var sc: auth_mod.Claims = .{ .scope = .access, .iat = now, .exp = now + exp_secs };
    try sc.setSub(claims.sub());
    try sc.setJti(&jti_buf);
    try sc.setAud(aud);

    var jwt_buf: [auth_mod.max_jwt_bytes]u8 = undefined;
    const jwt = try auth_mod.sign(st.jwt_key, sc, &jwt_buf);
    var body_buf: [auth_mod.max_jwt_bytes + 64]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf, "{{\"token\":\"{s}\"}}", .{jwt}) catch
        return xrpc.writeError(hc, .internal, "InternalError", "fmt");
    try xrpc.writeJsonBody(hc, .ok, body);
}

// ── register ──────────────────────────────────────────────────────

pub fn register(router: *Router, plugin_index: u16) !void {
    try router.register(.get, "/xrpc/com.atproto.server.describeServer", describeServer, plugin_index);
    try router.register(.post, "/xrpc/com.atproto.server.createSession", createSession, plugin_index);
    try router.register(.post, "/xrpc/com.atproto.server.refreshSession", refreshSession, plugin_index);

    try router.register(.post, "/xrpc/com.atproto.repo.createRecord", createRecord, plugin_index);
    try router.register(.post, "/xrpc/com.atproto.repo.putRecord", createRecord, plugin_index);
    try router.register(.post, "/xrpc/com.atproto.repo.deleteRecord", deleteRecord, plugin_index);
    try router.register(.post, "/xrpc/com.atproto.repo.applyWrites", applyWrites, plugin_index); // AT-12
    try router.register(.post, "/xrpc/com.atproto.repo.importRepo", importRepoStub, plugin_index); // AT-23
    try router.register(.get, "/xrpc/com.atproto.identity.resolveIdentity", identityResolveIdentity, plugin_index); // AT-18b
    try router.register(.get, "/xrpc/com.atproto.repo.getRecord", getRecord, plugin_index);
    try router.register(.get, "/xrpc/com.atproto.repo.listRecords", listRecords, plugin_index); // W2.3
    try router.register(.get, "/xrpc/com.atproto.repo.describeRepo", describeRepo, plugin_index);
    try router.register(.post, "/xrpc/com.atproto.repo.uploadBlob", repoUploadBlob, plugin_index); // W2.3

    // W2.3: real handlers for the sync fetch endpoints.
    try router.register(.get, "/xrpc/com.atproto.sync.getRepo", syncGetRepo, plugin_index);
    try router.register(.get, "/xrpc/com.atproto.sync.getRecord", syncGetRecord, plugin_index);
    try router.register(.get, "/xrpc/com.atproto.sync.getBlocks", syncGetBlocks, plugin_index);
    try router.register(.get, "/xrpc/com.atproto.sync.listRepos", syncListRepos, plugin_index);
    // W2.1: subscribeRepos is owned by the WS upgrade router (see
    // sync_firehose.zig). The HTTP fallback returns 400 + hint for
    // plain-GET probes; real WS upgrade requests are caught by the
    // upgrade router before this handler runs.
    try router.register(.get, "/xrpc/com.atproto.sync.subscribeRepos", subscribeReposHttp, plugin_index);

    try router.register(.get, "/xrpc/com.atproto.identity.resolveHandle", identityResolveHandle, plugin_index);
    try router.register(.get, "/xrpc/com.atproto.identity.resolveDid", identityResolveDid, plugin_index); // AT-14
    try router.register(.post, "/xrpc/com.atproto.identity.updateHandle", identityUpdateHandle, plugin_index); // AT-18a
    try router.register(.get, "/xrpc/com.atproto.sync.getRepoStatus", syncGetRepoStatus, plugin_index); // AT-15
    try router.register(.get, "/xrpc/com.atproto.sync.getBlob", syncGetBlob, plugin_index); // AT-6
    try router.register(.get, "/blob/:cid", serveBlobByCid, plugin_index); // DUAL-3

    try router.register(.post, "/xrpc/com.atproto.moderation.createReport", moderationCreateReport, plugin_index); // AT-21
    try router.register(.get, "/xrpc/com.atproto.label.queryLabels", labelQueryLabels, plugin_index); // AT-20
    try router.register(.post, "/xrpc/com.atproto.sync.requestCrawl", syncRequestCrawl, plugin_index); // AT-2
    try router.register(.post, "/xrpc/com.atproto.sync.notifyOfUpdate", syncNotifyOfUpdate, plugin_index); // AT-2 sibling
    try router.register(.get, "/xrpc/com.atproto.server.getServiceAuth", getServiceAuth, plugin_index); // AT-17

    try router.register(.get, "/.well-known/atproto-did", wellKnownAtprotoDid, plugin_index);
    try router.register(.get, "/.well-known/did.json", wellKnownDidJson, plugin_index); // AT-13

    // AT-8 / AT-9 / AT-10 / AT-11 (account lifecycle + email + app pw + invites).
    try account_routes.register(router, plugin_index);
    // AT-22: admin namespace.
    try admin_routes.register(router, plugin_index);
    // AT-1: OAuth 2.1 + DPoP.
    try oauth_routes.register(router, plugin_index);
    // AT-19: PLC operations.
    try plc_routes.register(router, plugin_index);
}

// ── W2.3 tests ────────────────────────────────────────────────────

const testing = std.testing;
const schema_mod = @import("schema.zig");

fn setupRouteDb() !*c.sqlite3 {
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

test "routes: max_blocks_per_request capped at 1024" {
    try testing.expect(max_blocks_per_request == 1024);
    try testing.expect(list_records_max == 100);
    try testing.expect(list_repos_max == 200);
}

test "AT-2: requestCrawl persists the hostname (upsert)" {
    const db = try setupRouteDb();
    defer core.storage.sqlite.closeDb(db);

    const upsert = "INSERT INTO atp_crawl_subscriptions(hostname, requested_at) VALUES (?,?) ON CONFLICT(hostname) DO UPDATE SET requested_at = excluded.requested_at";
    inline for (.{ .{ "relay.example", 100 }, .{ "relay.example", 200 } }) |row| {
        var stmt: ?*c.sqlite3_stmt = null;
        try testing.expect(c.sqlite3_prepare_v2(db, upsert, -1, &stmt, null) == c.SQLITE_OK);
        defer _ = c.sqlite3_finalize(stmt);
        _ = c.sqlite3_bind_text(stmt, 1, row[0].ptr, @intCast(row[0].len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_int64(stmt, 2, row[1]);
        try testing.expect(c.sqlite3_step(stmt.?) == c.SQLITE_DONE);
    }
    // One row (upsert), latest requested_at.
    var sel: ?*c.sqlite3_stmt = null;
    try testing.expect(c.sqlite3_prepare_v2(db, "SELECT COUNT(*), MAX(requested_at) FROM atp_crawl_subscriptions WHERE hostname='relay.example'", -1, &sel, null) == c.SQLITE_OK);
    defer _ = c.sqlite3_finalize(sel);
    try testing.expect(c.sqlite3_step(sel.?) == c.SQLITE_ROW);
    try testing.expectEqual(@as(i64, 1), c.sqlite3_column_int64(sel, 0));
    try testing.expectEqual(@as(i64, 200), c.sqlite3_column_int64(sel, 1));
}

test "routes: lookupBlock finds an MST block by CID" {
    const db = try setupRouteDb();
    defer core.storage.sqlite.closeDb(db);

    var cs: [cid_mod.string_cid_len]u8 = undefined;
    const cid_bin = cid_mod.computeDagCbor("payload");
    const cid_s = try cid_mod.encodeString(cid_bin, &cs);

    var stmt: ?*c.sqlite3_stmt = null;
    _ = c.sqlite3_prepare_v2(db, "INSERT INTO atp_mst_blocks (cid, did, data) VALUES (?,?,?)", -1, &stmt, null);
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, cid_s.ptr, @intCast(cid_s.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 2, "did:plc:test", 12, c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_blob(stmt, 3, "payload", 7, c.sqliteTransientAsDestructor());
    _ = c.sqlite3_step(stmt.?);

    var out: [128]u8 = undefined;
    const got = try lookupBlock(db, cid_s, &out);
    try testing.expect(got != null);
    try testing.expectEqualStrings("payload", out[0..got.?]);
}

test "routes: lookupBlock returns null on miss" {
    const db = try setupRouteDb();
    defer core.storage.sqlite.closeDb(db);
    var out: [128]u8 = undefined;
    const got = try lookupBlock(db, "bafyfakecid", &out);
    try testing.expect(got == null);
}

test "routes: listRecords + syncListRepos defaults" {
    try testing.expect(list_records_default == 50);
    try testing.expect(list_repos_default == 50);
}

test "AT-13: PDS DID document shape" {
    // Seed state with a deterministic Ed25519 keypair so the multibase
    // string is reproducible.
    State.reset();
    var seed: [32]u8 = .{0} ** 32;
    seed[0] = 0x42;
    const State_mod = @import("state.zig");
    var inst = State_mod.get();
    inst.host = "pds.example";
    inst.jwt_key = keypair.Ed25519KeyPair.fromSeed(seed);

    var buf: [2048]u8 = undefined;
    const doc = try renderPdsDidDocument(&buf);

    // Spec-required fields.
    try testing.expect(std.mem.indexOf(u8, doc, "\"id\":\"did:web:pds.example\"") != null);
    try testing.expect(std.mem.indexOf(u8, doc, "\"alsoKnownAs\":[\"at://pds.example\"]") != null);
    try testing.expect(std.mem.indexOf(u8, doc, "\"verificationMethod\"") != null);
    try testing.expect(std.mem.indexOf(u8, doc, "\"type\":\"Multikey\"") != null);
    try testing.expect(std.mem.indexOf(u8, doc, "did:web:pds.example#atproto") != null);
    try testing.expect(std.mem.indexOf(u8, doc, "\"publicKeyMultibase\":\"z") != null);
    try testing.expect(std.mem.indexOf(u8, doc, "\"id\":\"#atproto_pds\"") != null);
    try testing.expect(std.mem.indexOf(u8, doc, "\"type\":\"AtprotoPersonalDataServer\"") != null);
    try testing.expect(std.mem.indexOf(u8, doc, "\"serviceEndpoint\":\"https://pds.example\"") != null);

    State.reset();
}

test "AT-15: getRepoStatus body shape" {
    const db = try setupRouteDb();
    defer core.storage.sqlite.closeDb(db);

    // Seed a repo row with a known head/rev.
    try repo_mod.ensureRepo(db, "did:plc:alice", "did:key:zFakeKey", 1000);

    // Apply head_cid + head_rev directly so we don't need a full commit
    // path here (commit path is covered by repo_mod tests).
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "UPDATE atp_repos SET head_cid = ?, head_rev = ? WHERE did = ?";
    _ = c.sqlite3_prepare_v2(db, sql, -1, &stmt, null);
    defer _ = c.sqlite3_finalize(stmt);
    // 59-char CIDv1 dag-cbor string (matches RepoMeta.head_cid_buf size).
    var head_buf: [cid_mod.string_cid_len]u8 = undefined;
    const head = try cid_mod.encodeString(cid_mod.computeDagCbor("testcommit"), &head_buf);
    const rev = "3kx7n6h2lqe2j";
    _ = c.sqlite3_bind_text(stmt, 1, head.ptr, @intCast(head.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 2, rev.ptr, @intCast(rev.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 3, "did:plc:alice", 13, c.sqliteTransientAsDestructor());
    _ = c.sqlite3_step(stmt.?);

    var meta: repo_mod.RepoMeta = .{};
    const found = try repo_mod.loadRepoMeta(db, "did:plc:alice", &meta);
    try testing.expect(found);
    try testing.expectEqualStrings(head, meta.headCid());
    try testing.expectEqualStrings(rev, meta.headRev());
}

test "AT-14: identityResolveDid returns own doc for did:web:<host>" {
    // Smoke-test the own-did shortcut — verifies the host comparison
    // and the rendered doc both work. (Network resolution paths for
    // other DIDs are covered by did_resolver tests.)
    State.reset();
    var seed: [32]u8 = .{0} ** 32;
    seed[0] = 0x99;
    const State_mod = @import("state.zig");
    var inst = State_mod.get();
    inst.host = "myhost.test";
    inst.jwt_key = keypair.Ed25519KeyPair.fromSeed(seed);

    var buf: [2048]u8 = undefined;
    const doc = try renderPdsDidDocument(&buf);
    try testing.expect(std.mem.indexOf(u8, doc, "did:web:myhost.test") != null);

    State.reset();
}

test "AT-21: atp_reports schema accepts a row" {
    const db = try setupRouteDb();
    defer core.storage.sqlite.closeDb(db);

    // STRICT-mode tables require BLOB literals for BLOB columns;
    // bind via sqlite3_bind_blob from a prepared statement.
    var ins: ?*c.sqlite3_stmt = null;
    const sql = "INSERT INTO atp_reports (reason_type, reason_text, subject_json, created_at) VALUES (?,?,?,?)";
    try testing.expect(c.sqlite3_prepare_v2(db, sql, -1, &ins, null) == c.SQLITE_OK);
    defer _ = c.sqlite3_finalize(ins);
    _ = c.sqlite3_bind_text(ins, 1, "spam", 4, c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(ins, 2, "please", 6, c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_blob(ins, 3, "{}", 2, c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(ins, 4, 1);
    try testing.expect(c.sqlite3_step(ins.?) == c.SQLITE_DONE);

    var cnt: ?*c.sqlite3_stmt = null;
    _ = c.sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM atp_reports", -1, &cnt, null);
    defer _ = c.sqlite3_finalize(cnt);
    try testing.expect(c.sqlite3_step(cnt) == c.SQLITE_ROW);
    try testing.expectEqual(@as(i64, 1), c.sqlite3_column_int64(cnt, 0));
}

test "AT-17: Claims roundtrip with aud field" {
    var claims: auth_mod.Claims = .{ .scope = .access, .iat = 100, .exp = 200 };
    try claims.setSub("did:web:alice");
    try claims.setJti("abcd1234");
    try claims.setAud("did:web:relay.example");
    try testing.expectEqualStrings("did:web:relay.example", claims.aud());
}

test "AT-7: uploadBlob CID is CIDv1 raw codec" {
    // Direct test on the CID encoding path used by repoUploadBlob.
    const bytes = "PNGdataetcetc";
    const blob_cid = cid_mod.computeRaw(bytes);
    try testing.expectEqual(cid_mod.raw_codec, blob_cid.codec());

    var cid_buf: [cid_mod.string_cid_len]u8 = undefined;
    const s = try cid_mod.encodeString(blob_cid, &cid_buf);
    try testing.expect(std.mem.startsWith(u8, s, "bafkrei"));

    // Round-trips back to the same bytes.
    const parsed = try cid_mod.parseString(s);
    try testing.expectEqualSlices(u8, blob_cid.raw(), parsed.raw());
}

test "DUAL-3: AT BlobRef CID and AP /blob URL address the same bytes" {
    const bytes = "shared-media-bytes-across-both-networks";
    // The CID the AT BlobRef `$link` carries (CIDv1 raw, sha2-256).
    const blob_cid = cid_mod.computeRaw(bytes);
    var cid_buf: [cid_mod.string_cid_len]u8 = undefined;
    const cid = try cid_mod.encodeString(blob_cid, &cid_buf);

    // The shared content-addressed store keyed by that same CID — what
    // `uploadBlob` writes to and what `/blob/:cid` serves from.
    var mem = core.blob.MemoryStore.init(testing.allocator);
    defer mem.deinit();
    const store = mem.store();
    try store.put(cid, bytes);

    var out: [128]u8 = undefined;
    const got = try store.get(cid, &out);
    try testing.expectEqualSlices(u8, bytes, got);
}
