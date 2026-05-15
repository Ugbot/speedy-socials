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
const mst = @import("mst.zig");
const cid_mod = @import("cid.zig");
const car = @import("car.zig");

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
    var cid_buf: [64]u8 = undefined;
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &hash, .{});
    const hex = "0123456789abcdef";
    for (hash, 0..) |b, i| {
        cid_buf[i * 2] = hex[b >> 4];
        cid_buf[i * 2 + 1] = hex[b & 0x0F];
    }
    const cid = cid_buf[0..64];

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

    var resp_buf: [512]u8 = undefined;
    const body = std.fmt.bufPrint(&resp_buf,
        "{{\"blob\":{{\"$type\":\"blob\",\"ref\":{{\"$link\":\"{s}\"}},\"mimeType\":\"{s}\",\"size\":{d}}}}}",
        .{ cid, mime, bytes.len },
    ) catch return xrpc.writeError(hc, .internal, "InternalError", "fmt");
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

    try router.register(.get, "/xrpc/com.atproto.identity.resolveHandle", notImplemented, plugin_index);

    try router.register(.get, "/.well-known/atproto-did", wellKnownAtprotoDid, plugin_index);
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
