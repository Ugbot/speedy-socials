//! RFC 6455 §4 — opening handshake.
//!
//! Given a parsed HTTP/1.1 request, validate that it is a well-formed
//! WebSocket upgrade and write the 101 Switching Protocols response
//! into a `response.Builder`.
//!
//! No allocations — the hash buffers are stack-local and the response
//! is written directly into the connection's outbound write buffer.

const std = @import("std");
const http_request = @import("../http/request.zig");
const response = @import("../http/response.zig");
const errors = @import("../errors.zig");
const HttpError = errors.HttpError;
const WsError = errors.WsError;
const assert_mod = @import("../assert.zig");
const assert = assert_mod.assert;
const assertLe = assert_mod.assertLe;
const limits = @import("../limits.zig");

/// RFC 6455 magic GUID for the Sec-WebSocket-Accept hash.
pub const websocket_magic_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// Maximum subprotocol token length we will echo back. Sized for the
/// short identifiers used in practice (e.g. `chat`, `xmpp`,
/// `com.atproto.sync`). Anything longer is rejected silently — the
/// header is simply omitted and the negotiation proceeds without a
/// subprotocol, mirroring browser behavior on unrecognized tokens.
pub const max_subprotocol_bytes: usize = 64;

/// Result of `validate` — captures the data needed by the response
/// writer. All slices alias the request's header buffer (lifetime
/// equal to the connection's read buffer).
pub const Accepted = struct {
    /// The verbatim `Sec-WebSocket-Key` header value.
    key: []const u8,
    /// Negotiated subprotocol from the caller-provided allowlist, or
    /// empty string if none matched.
    subprotocol: []const u8,
};

/// Validate the inbound HTTP request as an RFC 6455 §4.1 upgrade.
///
/// `allowed_subprotocols`: ordered list of subprotocols the server
/// supports. The first client-offered protocol that appears in this
/// list is selected; if none match (or the client didn't offer any),
/// `subprotocol` is "".
pub fn validate(
    req: *const http_request.Request,
    allowed_subprotocols: []const []const u8,
) WsError!Accepted {
    if (req.method != .get) return error.HandshakeBadMethod;

    const upgrade = req.header("Upgrade") orelse return error.HandshakeMissingUpgrade;
    if (!containsTokenCi(upgrade, "websocket")) return error.HandshakeMissingUpgrade;

    const connection = req.header("Connection") orelse return error.HandshakeMissingConnection;
    if (!containsTokenCi(connection, "Upgrade")) return error.HandshakeMissingConnection;

    const version = req.header("Sec-WebSocket-Version") orelse return error.HandshakeBadVersion;
    if (!std.mem.eql(u8, std.mem.trim(u8, version, " \t"), "13")) return error.HandshakeBadVersion;

    const key = req.header("Sec-WebSocket-Key") orelse return error.HandshakeMissingKey;
    const trimmed_key = std.mem.trim(u8, key, " \t");
    if (trimmed_key.len == 0) return error.HandshakeMissingKey;

    const subprotocol = selectSubprotocol(
        req.header("Sec-WebSocket-Protocol") orelse "",
        allowed_subprotocols,
    );

    return .{ .key = trimmed_key, .subprotocol = subprotocol };
}

/// Compute the Sec-WebSocket-Accept value: base64(sha1(key + magic)).
/// The accept value is exactly 28 base64 characters.
pub fn computeAccept(key: []const u8, out: *[28]u8) void {
    var hasher = std.crypto.hash.Sha1.init(.{});
    hasher.update(key);
    hasher.update(websocket_magic_guid);
    var digest: [20]u8 = undefined;
    hasher.final(&digest);
    const enc = std.base64.standard.Encoder;
    const written = enc.encode(out, &digest);
    // Sha1 -> 20 bytes -> base64 -> 28 chars, no padding fiddling needed.
    assert(written.len == 28);
}

/// Write the 101 Switching Protocols response into `builder`.
/// `accepted.subprotocol` empty → header omitted.
pub fn writeResponse(builder: *response.Builder, accepted: Accepted) (HttpError || WsError)!void {
    var accept: [28]u8 = undefined;
    computeAccept(accepted.key, &accept);

    try builder.body("HTTP/1.1 101 Switching Protocols\r\n");
    try builder.body("Upgrade: websocket\r\n");
    try builder.body("Connection: Upgrade\r\n");
    try builder.body("Sec-WebSocket-Accept: ");
    try builder.body(&accept);
    try builder.body("\r\n");
    if (accepted.subprotocol.len > 0) {
        assertLe(accepted.subprotocol.len, max_subprotocol_bytes);
        try builder.body("Sec-WebSocket-Protocol: ");
        try builder.body(accepted.subprotocol);
        try builder.body("\r\n");
    }
    try builder.body("\r\n");
}

// ── helpers ────────────────────────────────────────────────────

/// Case-insensitive token containment for HTTP header lists like
/// "keep-alive, Upgrade". Splits on comma, trims whitespace, compares
/// case-insensitively. No allocations.
fn containsTokenCi(haystack: []const u8, needle: []const u8) bool {
    var cursor: usize = 0;
    var iters: usize = 0;
    // Bounded: at most one iteration per byte in haystack.
    while (cursor <= haystack.len) : (iters += 1) {
        assertLe(iters, haystack.len + 1);
        const end = std.mem.indexOfScalarPos(u8, haystack, cursor, ',') orelse haystack.len;
        const tok = std.mem.trim(u8, haystack[cursor..end], " \t");
        if (std.ascii.eqlIgnoreCase(tok, needle)) return true;
        if (end == haystack.len) return false;
        cursor = end + 1;
    }
    return false;
}

/// Pick the first subprotocol offered by the client that matches the
/// server allowlist. Returns "" if no overlap. Comparison is exact
/// (subprotocol tokens are case-sensitive per RFC 6455).
fn selectSubprotocol(offered: []const u8, allowed: []const []const u8) []const u8 {
    if (offered.len == 0 or allowed.len == 0) return "";
    var cursor: usize = 0;
    var iters: usize = 0;
    while (cursor <= offered.len) : (iters += 1) {
        assertLe(iters, offered.len + 1);
        const end = std.mem.indexOfScalarPos(u8, offered, cursor, ',') orelse offered.len;
        const tok = std.mem.trim(u8, offered[cursor..end], " \t");
        if (tok.len > 0 and tok.len <= max_subprotocol_bytes) {
            for (allowed) |candidate| {
                if (std.mem.eql(u8, tok, candidate)) return candidate;
            }
        }
        if (end == offered.len) return "";
        cursor = end + 1;
    }
    return "";
}

// ── tests ──────────────────────────────────────────────────────

const testing = std.testing;

test "RFC 6455 example Sec-WebSocket-Accept" {
    // Canonical example from RFC 6455 §1.3.
    var out: [28]u8 = undefined;
    computeAccept("dGhlIHNhbXBsZSBub25jZQ==", &out);
    try testing.expectEqualSlices(u8, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", &out);
}

test "validate happy path" {
    const headers = [_]http_request.Header{
        .{ .name = "Host", .value = "example.com" },
        .{ .name = "Upgrade", .value = "websocket" },
        .{ .name = "Connection", .value = "keep-alive, Upgrade" },
        .{ .name = "Sec-WebSocket-Version", .value = "13" },
        .{ .name = "Sec-WebSocket-Key", .value = "dGhlIHNhbXBsZSBub25jZQ==" },
    };
    const req = http_request.Request{
        .method = .get,
        .method_raw = "GET",
        .target = "/chat",
        .version = "HTTP/1.1",
        .headers = &headers,
        .body = "",
    };
    const acc = try validate(&req, &.{});
    try testing.expectEqualSlices(u8, "dGhlIHNhbXBsZSBub25jZQ==", acc.key);
    try testing.expectEqual(@as(usize, 0), acc.subprotocol.len);
}

test "validate rejects non-GET" {
    const req = http_request.Request{
        .method = .post,
        .method_raw = "POST",
        .target = "/chat",
        .version = "HTTP/1.1",
        .headers = &.{},
        .body = "",
    };
    try testing.expectError(error.HandshakeBadMethod, validate(&req, &.{}));
}

test "validate rejects bad version" {
    const headers = [_]http_request.Header{
        .{ .name = "Upgrade", .value = "websocket" },
        .{ .name = "Connection", .value = "Upgrade" },
        .{ .name = "Sec-WebSocket-Version", .value = "8" },
        .{ .name = "Sec-WebSocket-Key", .value = "abc" },
    };
    const req = http_request.Request{
        .method = .get,
        .method_raw = "GET",
        .target = "/",
        .version = "HTTP/1.1",
        .headers = &headers,
        .body = "",
    };
    try testing.expectError(error.HandshakeBadVersion, validate(&req, &.{}));
}

test "validate rejects missing upgrade" {
    const headers = [_]http_request.Header{
        .{ .name = "Connection", .value = "Upgrade" },
        .{ .name = "Sec-WebSocket-Version", .value = "13" },
        .{ .name = "Sec-WebSocket-Key", .value = "abc" },
    };
    const req = http_request.Request{
        .method = .get,
        .method_raw = "GET",
        .target = "/",
        .version = "HTTP/1.1",
        .headers = &headers,
        .body = "",
    };
    try testing.expectError(error.HandshakeMissingUpgrade, validate(&req, &.{}));
}

test "subprotocol selection picks first allowed" {
    const headers = [_]http_request.Header{
        .{ .name = "Upgrade", .value = "websocket" },
        .{ .name = "Connection", .value = "Upgrade" },
        .{ .name = "Sec-WebSocket-Version", .value = "13" },
        .{ .name = "Sec-WebSocket-Key", .value = "ZZZ" },
        .{ .name = "Sec-WebSocket-Protocol", .value = "v1.unknown, chat, xmpp" },
    };
    const req = http_request.Request{
        .method = .get,
        .method_raw = "GET",
        .target = "/",
        .version = "HTTP/1.1",
        .headers = &headers,
        .body = "",
    };
    const allowed = [_][]const u8{ "chat", "xmpp" };
    const acc = try validate(&req, &allowed);
    try testing.expectEqualSlices(u8, "chat", acc.subprotocol);
}

test "subprotocol selection none match => empty" {
    const headers = [_]http_request.Header{
        .{ .name = "Upgrade", .value = "websocket" },
        .{ .name = "Connection", .value = "Upgrade" },
        .{ .name = "Sec-WebSocket-Version", .value = "13" },
        .{ .name = "Sec-WebSocket-Key", .value = "ZZZ" },
        .{ .name = "Sec-WebSocket-Protocol", .value = "foo, bar" },
    };
    const req = http_request.Request{
        .method = .get,
        .method_raw = "GET",
        .target = "/",
        .version = "HTTP/1.1",
        .headers = &headers,
        .body = "",
    };
    const allowed = [_][]const u8{ "chat", "xmpp" };
    const acc = try validate(&req, &allowed);
    try testing.expectEqual(@as(usize, 0), acc.subprotocol.len);
}

test "writeResponse produces 101 with accept header" {
    var buf: [256]u8 = undefined;
    var b = response.Builder.init(&buf);
    try writeResponse(&b, .{ .key = "dGhlIHNhbXBsZSBub25jZQ==", .subprotocol = "" });
    const out = b.bytes();
    try testing.expect(std.mem.startsWith(u8, out, "HTTP/1.1 101 Switching Protocols\r\n"));
    try testing.expect(std.mem.indexOf(u8, out, "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, out, "\r\n\r\n"));
    try testing.expect(std.mem.indexOf(u8, out, "Sec-WebSocket-Protocol") == null);
}

test "writeResponse emits subprotocol when present" {
    var buf: [256]u8 = undefined;
    var b = response.Builder.init(&buf);
    try writeResponse(&b, .{ .key = "dGhlIHNhbXBsZSBub25jZQ==", .subprotocol = "chat" });
    const out = b.bytes();
    try testing.expect(std.mem.indexOf(u8, out, "Sec-WebSocket-Protocol: chat\r\n") != null);
}
