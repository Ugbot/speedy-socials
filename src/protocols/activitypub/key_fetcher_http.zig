//! Real HTTP fetcher for ActivityPub actor public keys.
//!
//! This is the production backing for `key_cache.setFetchHook`. The hook
//! itself is a function-pointer with shape `(key_id, out_pem) FedError!usize`
//! — it does not carry a `*Client` argument, so the composition root binds
//! a process-wide pointer at boot and the hook trampoline delegates to
//! `httpFetch(client, key_id, out_pem)`.
//!
//! Flow:
//!   1. Strip any trailing `#fragment` from the keyId to obtain the actor
//!      URL (Mastodon publishes `https://h/users/x#main-key`).
//!   2. GET that URL with `Accept: application/activity+json`.
//!   3. Scan the JSON body for `"publicKey"` → `"publicKeyPem"` and copy
//!      its (de-escaped) value into the caller's PEM buffer.
//!
//! Tiger Style: no allocator, fixed scratch buffers, response copy bounded
//! by `keys.max_pem_bytes`.

const std = @import("std");
const core = @import("core");

const FedError = core.errors.FedError;
const http_client = core.http_client;

const keys = @import("keys.zig");

/// Strip a `#fragment` suffix from a keyId/URL. Returns the prefix.
pub fn stripFragment(url: []const u8) []const u8 {
    if (std.mem.indexOfScalar(u8, url, '#')) |i| return url[0..i];
    return url;
}

/// Scan a JSON document for a `"publicKeyPem"` field and return the
/// (raw, possibly escaped) value bytes. The returned slice references
/// `body`. Returns `KeyFetchFailed` if not found.
pub fn findPublicKeyPemField(body: []const u8) FedError![]const u8 {
    const needle = "\"publicKeyPem\"";
    const at = std.mem.indexOf(u8, body, needle) orelse return error.KeyFetchFailed;
    var i: usize = at + needle.len;
    // Skip whitespace + colon.
    var guard: u32 = 0;
    while (i < body.len) : (i += 1) {
        guard += 1;
        if (guard > 64) return error.KeyFetchFailed;
        const ch = body[i];
        if (ch == ' ' or ch == '\t' or ch == '\n' or ch == '\r' or ch == ':') continue;
        break;
    }
    if (i >= body.len or body[i] != '"') return error.KeyFetchFailed;
    i += 1;
    const start = i;
    var g2: u32 = 0;
    while (i < body.len) : (i += 1) {
        g2 += 1;
        if (g2 > keys.max_pem_bytes * 2) return error.KeyFetchFailed;
        const ch = body[i];
        if (ch == '\\') {
            // Skip the escape char; bounded.
            if (i + 1 >= body.len) return error.KeyFetchFailed;
            i += 1;
            continue;
        }
        if (ch == '"') {
            return body[start..i];
        }
    }
    return error.KeyFetchFailed;
}

/// Decode a JSON string value (already stripped of the surrounding quotes)
/// into `out`. Supports the escape sequences PEM payloads actually emit:
/// `\n`, `\r`, `\t`, `\\`, `\"`, `\/`. Returns bytes written.
pub fn decodeJsonString(escaped: []const u8, out: []u8) FedError!usize {
    var w: usize = 0;
    var i: usize = 0;
    while (i < escaped.len) {
        const ch = escaped[i];
        if (ch != '\\') {
            if (w >= out.len) return error.KeyFetchFailed;
            out[w] = ch;
            w += 1;
            i += 1;
            continue;
        }
        if (i + 1 >= escaped.len) return error.KeyFetchFailed;
        const esc = escaped[i + 1];
        const decoded: u8 = switch (esc) {
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            '\\' => '\\',
            '"' => '"',
            '/' => '/',
            'b' => 8,
            'f' => 12,
            // \uXXXX — only ASCII subset; bail on non-ASCII for simplicity.
            'u' => {
                if (i + 5 >= escaped.len) return error.KeyFetchFailed;
                const hex = escaped[i + 2 .. i + 6];
                const cp = std.fmt.parseInt(u16, hex, 16) catch return error.KeyFetchFailed;
                if (cp > 0x7f) return error.KeyFetchFailed;
                if (w >= out.len) return error.KeyFetchFailed;
                out[w] = @intCast(cp);
                w += 1;
                i += 6;
                continue;
            },
            else => return error.KeyFetchFailed,
        };
        if (w >= out.len) return error.KeyFetchFailed;
        out[w] = decoded;
        w += 1;
        i += 2;
    }
    return w;
}

/// Fetch the actor doc at `key_id` (stripping the `#fragment`), find
/// `publicKeyPem`, write the *decoded* PEM into `out_pem`. Returns bytes
/// written. The output is the canonical PEM string (with literal newlines)
/// suitable for `keys.parsePublicKeyPem`.
pub fn httpFetch(
    client: *http_client.Client,
    key_id: []const u8,
    out_pem: []u8,
) FedError!usize {
    const actor_url = stripFragment(key_id);
    if (actor_url.len == 0) return error.KeyFetchFailed;

    const req: http_client.Request = .{
        .method = .get,
        .url = actor_url,
        .headers = &[_]http_client.Header{
            .{ .name = "Accept", .value = "application/activity+json" },
        },
        .body = "",
        .timeout_ms = 15_000,
    };
    var resp: http_client.Response = .{ .status = 0 };
    client.sendSync(req, &resp) catch return error.KeyFetchFailed;
    if (resp.status < 200 or resp.status >= 300) return error.KeyFetchFailed;
    const escaped = try findPublicKeyPemField(resp.body());
    return decodeJsonString(escaped, out_pem);
}

// ── Tests ─────────────────────────────────────────────────────────────

const testing = std.testing;

test "stripFragment removes trailing #main-key" {
    try testing.expectEqualStrings(
        "https://h/users/a",
        stripFragment("https://h/users/a#main-key"),
    );
    try testing.expectEqualStrings(
        "https://h/users/a",
        stripFragment("https://h/users/a"),
    );
}

test "findPublicKeyPemField locates the value in a typical actor JSON" {
    const body =
        "{\"type\":\"Person\",\"publicKey\":{\"id\":\"https://h/u/a#main-key\"," ++
        "\"owner\":\"https://h/u/a\",\"publicKeyPem\":\"-----BEGIN PUBLIC KEY-----\\nABC\\n-----END PUBLIC KEY-----\"}}";
    const v = try findPublicKeyPemField(body);
    try testing.expectEqualStrings(
        "-----BEGIN PUBLIC KEY-----\\nABC\\n-----END PUBLIC KEY-----",
        v,
    );
}

test "findPublicKeyPemField errors when field missing" {
    try testing.expectError(error.KeyFetchFailed, findPublicKeyPemField("{\"type\":\"Person\"}"));
}

test "decodeJsonString unescapes \\n and \\\"" {
    const in = "a\\nb\\\"c";
    var out: [16]u8 = undefined;
    const n = try decodeJsonString(in, &out);
    try testing.expectEqualStrings("a\nb\"c", out[0..n]);
}

test "decodeJsonString rejects truncated escape" {
    const in = "abc\\";
    var out: [16]u8 = undefined;
    try testing.expectError(error.KeyFetchFailed, decodeJsonString(in, &out));
}

test "decodeJsonString respects buffer cap" {
    const in = "abcdef";
    var out: [3]u8 = undefined;
    try testing.expectError(error.KeyFetchFailed, decodeJsonString(in, &out));
}
