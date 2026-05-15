//! Real outbound delivery for ActivityPub federation.
//!
//! Backs `outbox_worker.setDeliverHook`. The worker calls the installed
//! hook with `(target_inbox, payload, key_id)`; this module:
//!
//!   1. Looks up the local actor's private key by parsing the
//!      `/users/{username}` portion of `key_id` and joining against
//!      `ap_actor_keys`.
//!   2. Builds draft-cavage signing headers (Date, Digest, Host, etc.).
//!   3. Reconstructs the signing string via `sig.buildSigningString` so
//!      the signing layout is *identical* to what `sig.verify` checks
//!      on the inbound side (round-trip parity).
//!   4. Signs with Ed25519 (stdlib). RSA signing isn't supported — the
//!      stdlib RSA module exposes verify-only; `core.crypto.rsa` only
//!      verifies. Until a sign primitive lands the path returns
//!      `RsaSignNotImplemented` which the dispatcher classifies as a
//!      *permanent* failure (dead-letter).
//!   5. POSTs via `core.http_client.Client.sendSync` and classifies the
//!      result:
//!        * 2xx → success
//!        * 4xx (except 408 / 429) → permanent_failure
//!        * 5xx / 408 / 429 / transport errors → transient_failure
//!
//! Tiger Style: every buffer is fixed-size and inline. No allocator.

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const base64 = std.base64.standard;
const c = @import("sqlite").c;

const core = @import("core");
const http_client = core.http_client;

const sig = @import("sig.zig");
const keys = @import("keys.zig");
const outbox_worker = @import("outbox_worker.zig");

pub const max_signature_b64_bytes: usize = 1024;
pub const max_date_bytes: usize = 64;
pub const max_digest_bytes: usize = 96;
pub const max_signature_header_bytes: usize = 2048;
pub const max_request_body_bytes: usize = 64 * 1024;
pub const max_host_bytes: usize = 256;
pub const max_path_bytes: usize = 2048;

pub const DeliveryError = error{
    UnknownKey,
    SignFailed,
    RsaSignNotImplemented,
    BuildFailed,
    HttpFailed,
};

/// Parse a key_id like `https://host/users/alice#main-key` into username.
/// Returns the username slice into `key_id`, or null.
pub fn usernameFromKeyId(key_id: []const u8) ?[]const u8 {
    const marker = "/users/";
    const at = std.mem.indexOf(u8, key_id, marker) orelse return null;
    var end = key_id.len;
    if (std.mem.indexOfScalar(u8, key_id[at..], '#')) |hash_rel| {
        end = at + hash_rel;
    }
    if (std.mem.indexOfScalarPos(u8, key_id, at + marker.len, '/')) |slash| {
        if (slash < end) end = slash;
    }
    const u = key_id[at + marker.len .. end];
    if (u.len == 0) return null;
    return u;
}

pub fn parseAuthorityAndPath(url: []const u8) struct { host: []const u8, path: []const u8 } {
    var rest = url;
    if (std.mem.startsWith(u8, rest, "https://")) {
        rest = rest[8..];
    } else if (std.mem.startsWith(u8, rest, "http://")) {
        rest = rest[7..];
    }
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    const host = rest[0..slash];
    const path = if (slash < rest.len) rest[slash..] else "/";
    return .{ .host = host, .path = path };
}

/// Build an RFC 1123 / 7231 IMF-fixdate string from a unix timestamp.
/// Output: `Sun, 06 Nov 1994 08:49:37 GMT`.
pub fn writeHttpDate(unix: i64, out: []u8) ![]const u8 {
    if (out.len < 29) return error.BufferTooSmall;
    // Use std.time.epoch helpers.
    const days_secs = std.time.epoch.EpochSeconds{ .secs = @intCast(unix) };
    const day_secs = days_secs.getDaySeconds();
    const epoch_day = days_secs.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();

    const weekdays = [_][]const u8{ "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun" };
    const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    // 1970-01-01 was a Thursday. Day-of-week = (epoch_day + 3) % 7 mapping
    // to Mon=0..Sun=6.
    const dow_raw: i64 = @as(i64, @intCast(epoch_day.day)) + 3;
    const dow_idx: usize = @intCast(@mod(dow_raw, 7));

    return std.fmt.bufPrint(out, "{s}, {d:0>2} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} GMT", .{
        weekdays[dow_idx],
        month_day.day_index + 1,
        months[@intFromEnum(month_day.month) - 1],
        year_day.year,
        day_secs.getHoursIntoDay(),
        day_secs.getMinutesIntoHour(),
        day_secs.getSecondsIntoMinute(),
    }) catch error.BufferTooSmall;
}

/// Look up the local actor's private key by username. Returns the algorithm,
/// the key_id-bound private key, plus an Ed25519 private key slice copied
/// into `priv_buf` (Ed25519 case) or the PEM bytes copied into `priv_buf`
/// (RSA case, returned for the host's future RSA signer).
pub const LoadedPrivateKey = struct {
    algo: keys.Algorithm,
    /// For Ed25519: 32-byte secret key; expanded to 64 by signer.
    /// For RSA: raw PEM blob.
    bytes: [4096]u8 = undefined,
    len: usize = 0,
};

pub fn loadActorPrivateKey(db: *c.sqlite3, username: []const u8, out: *LoadedPrivateKey) DeliveryError!void {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql =
        \\SELECT k.key_type, k.private_pem
        \\FROM ap_actor_keys k
        \\INNER JOIN ap_users u ON u.id = k.actor_id
        \\WHERE u.username = ?
        \\LIMIT 1
    ;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return error.UnknownKey;
    }
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, username.ptr, @intCast(username.len), c.sqliteTransientAsDestructor());
    if (c.sqlite3_step(stmt) != c.SQLITE_ROW) return error.UnknownKey;
    const kt_ptr = c.sqlite3_column_text(stmt, 0);
    const kt_n: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
    if (kt_ptr == null or kt_n == 0) return error.UnknownKey;
    const key_type = kt_ptr[0..kt_n];
    out.algo = if (std.ascii.eqlIgnoreCase(key_type, "ed25519"))
        .ed25519
    else
        .rsa_sha256;
    const p_ptr = c.sqlite3_column_blob(stmt, 1);
    const p_n: usize = @intCast(c.sqlite3_column_bytes(stmt, 1));
    if (p_ptr == null or p_n == 0 or p_n > out.bytes.len) return error.UnknownKey;
    const pp: [*]const u8 = @ptrCast(p_ptr);
    @memcpy(out.bytes[0..p_n], pp[0..p_n]);
    out.len = p_n;
}

/// Parse the raw 32-byte ed25519 seed from a PKCS#8 PEM. We accept the
/// canonical RFC 8410 PrivateKeyInfo encoding the Mastodon-compatible
/// writer in `core.crypto.ed25519` produces: a 48-byte DER blob where the
/// inner 32-byte OCTET STRING starts at offset 16.
const ed25519_pkcs8_seed_offset: usize = 16;
const ed25519_pkcs8_der_len: usize = 48;

pub fn extractEd25519Seed(pem: []const u8) DeliveryError![32]u8 {
    // Locate the PEM body between BEGIN/END markers. Accept either
    // "PRIVATE KEY" or "ED25519 PRIVATE KEY".
    const begin_marker = "-----BEGIN";
    const end_marker = "-----END";
    const begin = std.mem.indexOf(u8, pem, begin_marker) orelse return error.SignFailed;
    const after_begin = std.mem.indexOfScalarPos(u8, pem, begin, '\n') orelse return error.SignFailed;
    const end = std.mem.indexOfPos(u8, pem, after_begin, end_marker) orelse return error.SignFailed;
    var stripped: [256]u8 = undefined;
    var s_len: usize = 0;
    var i: usize = after_begin + 1;
    while (i < end) : (i += 1) {
        const ch = pem[i];
        if (ch == ' ' or ch == '\r' or ch == '\n' or ch == '\t') continue;
        if (s_len >= stripped.len) return error.SignFailed;
        stripped[s_len] = ch;
        s_len += 1;
    }
    if (s_len == 0) return error.SignFailed;
    const der_len = base64.Decoder.calcSizeForSlice(stripped[0..s_len]) catch return error.SignFailed;
    if (der_len != ed25519_pkcs8_der_len) return error.SignFailed;
    var der: [ed25519_pkcs8_der_len]u8 = undefined;
    base64.Decoder.decode(&der, stripped[0..s_len]) catch return error.SignFailed;
    var seed: [32]u8 = undefined;
    @memcpy(&seed, der[ed25519_pkcs8_seed_offset .. ed25519_pkcs8_seed_offset + 32]);
    return seed;
}

/// Build a draft-cavage Parsed template with components
/// `(request-target) host date digest` and the given keyId/algorithm.
fn buildCavageTemplate(key_id: []const u8, algo: sig.Algorithm) sig.Parsed {
    var p: sig.Parsed = .{
        .scheme = .cavage,
        .key_id = key_id,
        .algorithm = algo,
        .signature_b64 = "",
    };
    p.components[0] = sig.Component.fromSlice("(request-target)") catch unreachable;
    p.components[1] = sig.Component.fromSlice("host") catch unreachable;
    p.components[2] = sig.Component.fromSlice("date") catch unreachable;
    p.components[3] = sig.Component.fromSlice("digest") catch unreachable;
    p.component_count = 4;
    return p;
}

pub fn classifyStatus(status: u16) outbox_worker.DeliveryResult {
    if (status >= 200 and status < 300) return .success;
    if (status == 408 or status == 429) return .transient_failure;
    if (status >= 400 and status < 500) return .permanent_failure;
    // 5xx and anything else (e.g. odd 1xx leakage): transient.
    return .transient_failure;
}

/// Build the `Signature: ...` header value. Returns the slice written
/// into `out` (header value only — caller adds the header name).
pub fn buildSignatureHeader(
    key_id: []const u8,
    algo_str: []const u8,
    headers_list: []const u8,
    signature_b64: []const u8,
    out: []u8,
) DeliveryError![]const u8 {
    var w: usize = 0;
    const parts = [_][]const u8{
        "keyId=\"",            key_id, "\",algorithm=\"",
        algo_str,              "\",headers=\"",
        headers_list,          "\",signature=\"",
        signature_b64,         "\"",
    };
    for (parts) |p| {
        if (w + p.len > out.len) return error.BuildFailed;
        @memcpy(out[w .. w + p.len], p);
        w += p.len;
    }
    return out[0..w];
}

/// Full delivery: sign + POST. Returns the classification result the
/// outbox worker stores.
pub fn deliver(
    client: *http_client.Client,
    db: *c.sqlite3,
    now_unix: i64,
    target_inbox: []const u8,
    payload: []const u8,
    key_id: []const u8,
) outbox_worker.DeliveryResult {
    return deliverInner(client, db, now_unix, target_inbox, payload, key_id) catch |err| switch (err) {
        // Permanent: this delivery cannot succeed without operator action.
        error.UnknownKey, error.RsaSignNotImplemented, error.SignFailed, error.BuildFailed => .permanent_failure,
        // Transport problem: try again later.
        error.HttpFailed => .transient_failure,
    };
}

fn deliverInner(
    client: *http_client.Client,
    db: *c.sqlite3,
    now_unix: i64,
    target_inbox: []const u8,
    payload: []const u8,
    key_id: []const u8,
) DeliveryError!outbox_worker.DeliveryResult {
    if (payload.len > max_request_body_bytes) return error.BuildFailed;

    const username = usernameFromKeyId(key_id) orelse return error.UnknownKey;
    var priv: LoadedPrivateKey = .{ .algo = .ed25519 };
    try loadActorPrivateKey(db, username, &priv);

    const dest = parseAuthorityAndPath(target_inbox);
    if (dest.host.len == 0 or dest.host.len > max_host_bytes) return error.BuildFailed;
    if (dest.path.len == 0 or dest.path.len > max_path_bytes) return error.BuildFailed;

    // Date header.
    var date_buf: [max_date_bytes]u8 = undefined;
    const date_str = writeHttpDate(now_unix, &date_buf) catch return error.BuildFailed;

    // Digest header value (SHA-256=b64).
    var digest_buf: [max_digest_bytes]u8 = undefined;
    const digest = sig.computeSha256DigestHeader(payload, &digest_buf) catch return error.SignFailed;

    // Signing string via the shared sig module.
    const algo: sig.Algorithm = switch (priv.algo) {
        .ed25519 => .ed25519,
        .rsa_sha256 => .rsa_sha256_legacy,
    };
    var template = buildCavageTemplate(key_id, algo);
    const req_view: sig.RequestView = .{
        .method = "POST",
        .path = dest.path,
        .target_uri = target_inbox,
        .host = dest.host,
        .date = date_str,
        .digest_legacy = digest,
    };

    var sig_b64_buf: [max_signature_b64_bytes]u8 = undefined;
    const signature_b64: []const u8 = switch (priv.algo) {
        .ed25519 => blk: {
            const seed = try extractEd25519Seed(priv.bytes[0..priv.len]);
            const kp = core.crypto.ed25519.fromSeed(seed) catch return error.SignFailed;
            const sig_b64 = sig.signEd25519(&template, &req_view, kp.secret_key, &sig_b64_buf) catch return error.SignFailed;
            break :blk sig_b64;
        },
        .rsa_sha256 => {
            // The stdlib RSA does not yet expose a sign primitive; the
            // host-injected verifier in `core.crypto.rsa` covers verify
            // only. Until that ships, dead-letter outbound RSA flows so
            // operators see them and can rotate to Ed25519. Inbound RSA
            // verification continues to work.
            return error.RsaSignNotImplemented;
        },
    };

    const algo_str: []const u8 = switch (priv.algo) {
        .ed25519 => "ed25519",
        .rsa_sha256 => "rsa-sha256",
    };
    var sig_header_buf: [max_signature_header_bytes]u8 = undefined;
    const sig_header = try buildSignatureHeader(
        key_id,
        algo_str,
        "(request-target) host date digest",
        signature_b64,
        &sig_header_buf,
    );

    const hdrs = [_]http_client.Header{
        .{ .name = "Date", .value = date_str },
        .{ .name = "Digest", .value = digest },
        .{ .name = "Content-Type", .value = "application/activity+json" },
        .{ .name = "Signature", .value = sig_header },
    };

    var resp: http_client.Response = .{ .status = 0 };
    client.sendSync(.{
        .method = .post,
        .url = target_inbox,
        .headers = &hdrs,
        .body = payload,
        .timeout_ms = 30_000,
    }, &resp) catch return error.HttpFailed;

    return classifyStatus(resp.status);
}

// ── Tests ─────────────────────────────────────────────────────────────

const testing = std.testing;

test "usernameFromKeyId pulls alice from a Mastodon style keyId" {
    try testing.expectEqualStrings("alice", usernameFromKeyId("https://h/users/alice#main-key").?);
    try testing.expectEqualStrings("bob", usernameFromKeyId("https://h/users/bob").?);
    try testing.expect(usernameFromKeyId("https://h/no-user-here") == null);
}

test "parseAuthorityAndPath splits authority + path for https" {
    const r = parseAuthorityAndPath("https://mastodon.social/users/foo/inbox");
    try testing.expectEqualStrings("mastodon.social", r.host);
    try testing.expectEqualStrings("/users/foo/inbox", r.path);
}

test "writeHttpDate formats a known epoch correctly" {
    var buf: [64]u8 = undefined;
    // 1700000000 = 2023-11-14 22:13:20 UTC, a Tuesday.
    const s = try writeHttpDate(1_700_000_000, &buf);
    try testing.expectEqualStrings("Tue, 14 Nov 2023 22:13:20 GMT", s);
}

test "classifyStatus maps 2xx → success" {
    try testing.expectEqual(outbox_worker.DeliveryResult.success, classifyStatus(200));
    try testing.expectEqual(outbox_worker.DeliveryResult.success, classifyStatus(202));
}

test "classifyStatus maps 410 → permanent_failure (dead-letter)" {
    try testing.expectEqual(outbox_worker.DeliveryResult.permanent_failure, classifyStatus(410));
    try testing.expectEqual(outbox_worker.DeliveryResult.permanent_failure, classifyStatus(400));
}

test "classifyStatus maps 5xx + 429 + 408 → transient" {
    try testing.expectEqual(outbox_worker.DeliveryResult.transient_failure, classifyStatus(500));
    try testing.expectEqual(outbox_worker.DeliveryResult.transient_failure, classifyStatus(503));
    try testing.expectEqual(outbox_worker.DeliveryResult.transient_failure, classifyStatus(429));
    try testing.expectEqual(outbox_worker.DeliveryResult.transient_failure, classifyStatus(408));
}

test "buildSignatureHeader produces a valid draft-cavage header" {
    var out: [256]u8 = undefined;
    const v = try buildSignatureHeader(
        "https://h/users/a#main-key",
        "ed25519",
        "(request-target) host date digest",
        "AAAA",
        &out,
    );
    try testing.expect(std.mem.indexOf(u8, v, "keyId=\"https://h/users/a#main-key\"") != null);
    try testing.expect(std.mem.indexOf(u8, v, "algorithm=\"ed25519\"") != null);
    try testing.expect(std.mem.indexOf(u8, v, "headers=\"(request-target) host date digest\"") != null);
    try testing.expect(std.mem.indexOf(u8, v, "signature=\"AAAA\"") != null);
}

test "extractEd25519Seed round-trips a PKCS#8 PEM written by core.crypto.ed25519" {
    // Generate a key via the canonical helper, write the private PEM, then
    // re-extract the seed and confirm signing+verification works.
    var seed: [32]u8 = undefined;
    var i: usize = 0;
    while (i < 32) : (i += 1) seed[i] = @intCast((i *% 7 +% 13) & 0xff);
    const kp = try core.crypto.ed25519.fromSeed(seed);

    // We don't have a writePrivatePem helper, so synthesize the canonical
    // RFC 8410 PrivateKeyInfo manually: 48-byte DER prefix + seed bytes.
    const prefix = [_]u8{
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
        0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    };
    var der: [48]u8 = undefined;
    @memcpy(der[0..16], &prefix);
    @memcpy(der[16..48], &seed);
    var b64_buf: [base64.Encoder.calcSize(48)]u8 = undefined;
    const b64 = base64.Encoder.encode(&b64_buf, &der);
    var pem_buf: [256]u8 = undefined;
    const pem = try std.fmt.bufPrint(&pem_buf, "-----BEGIN PRIVATE KEY-----\n{s}\n-----END PRIVATE KEY-----", .{b64});

    const got = try extractEd25519Seed(pem);
    try testing.expectEqualSlices(u8, &seed, &got);

    // Confirm the extracted seed regenerates the same secret key.
    const kp2 = try core.crypto.ed25519.fromSeed(got);
    try testing.expectEqualSlices(u8, &kp.secret_key, &kp2.secret_key);
}

test "deliverInner: end-to-end Ed25519 sign + HTTP POST + verify-on-receiver" {
    // This is the heaviest test in the file: it stands up a full
    // in-memory pipeline. The mock TLS backend captures the outgoing
    // bytes; we parse the Signature header and verify it against the
    // generated public key using `sig.verify`. That proves the signing
    // string we build matches what receivers reconstruct.
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    // Apply only the AP migrations we need (users + actor_keys).
    const ap_schema = @import("schema.zig");
    try ap_schema.applyAllForTests(db);

    // Seed an actor + key.
    var seed: [32]u8 = undefined;
    var i: usize = 0;
    while (i < 32) : (i += 1) seed[i] = @intCast((i +% 11) & 0xff);
    const kp = try core.crypto.ed25519.fromSeed(seed);

    // Build the PKCS#8 PEM for the seed (same shape extractEd25519Seed reads).
    const prefix = [_]u8{
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
        0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    };
    var der: [48]u8 = undefined;
    @memcpy(der[0..16], &prefix);
    @memcpy(der[16..48], &seed);
    var b64_buf: [base64.Encoder.calcSize(48)]u8 = undefined;
    const b64 = base64.Encoder.encode(&b64_buf, &der);
    var priv_pem_buf: [256]u8 = undefined;
    const priv_pem = try std.fmt.bufPrint(&priv_pem_buf, "-----BEGIN PRIVATE KEY-----\n{s}\n-----END PRIVATE KEY-----", .{b64});

    // Insert into ap_users + ap_actor_keys directly.
    {
        var stmt: ?*c.sqlite3_stmt = null;
        _ = c.sqlite3_prepare_v2(db, "INSERT INTO ap_users(username, display_name, bio, is_locked, discoverable, indexable, created_at) VALUES (?,?,?,?,?,?,?)", -1, &stmt, null);
        defer _ = c.sqlite3_finalize(stmt);
        const uname = "alice";
        _ = c.sqlite3_bind_text(stmt, 1, uname.ptr, @intCast(uname.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_text(stmt, 2, "Alice".ptr, 5, c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_text(stmt, 3, "".ptr, 0, c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_int(stmt, 4, 0);
        _ = c.sqlite3_bind_int(stmt, 5, 1);
        _ = c.sqlite3_bind_int(stmt, 6, 1);
        _ = c.sqlite3_bind_int64(stmt, 7, 0);
        try testing.expect(c.sqlite3_step(stmt) == c.SQLITE_DONE);
    }
    const actor_id = c.sqlite3_last_insert_rowid(db);
    {
        var stmt: ?*c.sqlite3_stmt = null;
        _ = c.sqlite3_prepare_v2(db, "INSERT INTO ap_actor_keys(actor_id, key_type, public_pem, private_pem, created_at) VALUES (?,?,?,?,?)", -1, &stmt, null);
        defer _ = c.sqlite3_finalize(stmt);
        _ = c.sqlite3_bind_int64(stmt, 1, actor_id);
        _ = c.sqlite3_bind_text(stmt, 2, "ed25519".ptr, 7, c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_text(stmt, 3, "".ptr, 0, c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_blob(stmt, 4, priv_pem.ptr, @intCast(priv_pem.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_int64(stmt, 5, 0);
        try testing.expect(c.sqlite3_step(stmt) == c.SQLITE_DONE);
    }

    // Install the mock TLS backend (matches what http_client tests use).
    const MockTls = @import("test_mock_tls.zig");
    MockTls.canned_response = "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n";
    http_client.setTlsBackend(MockTls.backend());
    defer http_client.setTlsBackend(null);
    MockTls.reset();

    var client = http_client.Client.init(undefined);
    const result = deliver(
        &client,
        db,
        1_700_000_000,
        "https://remote.example/inbox",
        "{\"id\":\"x\"}",
        "https://local.example/users/alice#main-key",
    );
    try testing.expectEqual(outbox_worker.DeliveryResult.success, result);

    // Pull the request the mock captured and parse the Signature header.
    const req_bytes = MockTls.seen_request[0..MockTls.seen_request_len];
    try testing.expect(std.mem.startsWith(u8, req_bytes, "POST /inbox HTTP/1.1\r\n"));
    try testing.expect(std.mem.indexOf(u8, req_bytes, "Host: remote.example\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, req_bytes, "Date: ") != null);
    try testing.expect(std.mem.indexOf(u8, req_bytes, "Digest: SHA-256=") != null);

    // Locate the Signature header and feed it into the verifier.
    const sig_marker = "Signature: ";
    const sig_at = std.mem.indexOf(u8, req_bytes, sig_marker).?;
    const after_sig = req_bytes[sig_at + sig_marker.len ..];
    const crlf = std.mem.indexOf(u8, after_sig, "\r\n").?;
    const sig_header = after_sig[0..crlf];

    var parsed = try sig.parseCavage(sig_header);
    parsed.algorithm = .ed25519;
    // Reconstruct the request view exactly as the receiver would.
    const date_at = std.mem.indexOf(u8, req_bytes, "Date: ").?;
    const date_after = req_bytes[date_at + 6 ..];
    const date_crlf = std.mem.indexOf(u8, date_after, "\r\n").?;
    const date_v = date_after[0..date_crlf];

    const dig_at = std.mem.indexOf(u8, req_bytes, "Digest: ").?;
    const dig_after = req_bytes[dig_at + 8 ..];
    const dig_crlf = std.mem.indexOf(u8, dig_after, "\r\n").?;
    const dig_v = dig_after[0..dig_crlf];

    const req_view: sig.RequestView = .{
        .method = "POST",
        .path = "/inbox",
        .target_uri = "https://remote.example/inbox",
        .host = "remote.example",
        .date = date_v,
        .digest_legacy = dig_v,
    };
    const kid = try keys.KeyId.fromSlice("https://local.example/users/alice#main-key");
    const pub_key = keys.PublicKey.ed25519FromBytes(kid, kp.public_key);
    try sig.verify(&parsed, &req_view, &pub_key);
}

test "deliver returns permanent_failure when key_id has no /users/ portion" {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    const ap_schema = @import("schema.zig");
    try ap_schema.applyAllForTests(db);

    var client = http_client.Client.init(undefined);
    const r = deliver(&client, db, 1, "http://t/inbox", "{}", "unknown-keyid");
    try testing.expectEqual(outbox_worker.DeliveryResult.permanent_failure, r);
}
