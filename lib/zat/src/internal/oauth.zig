//! OAuth client primitives for AT Protocol
//!
//! PKCE, DPoP proofs, client assertions, and related helpers
//! for implementing AT Protocol OAuth flows (based on OAuth 2.1).
//!
//! see: https://atproto.com/specs/oauth

const std = @import("std");
const crypto = std.crypto;
const Allocator = std.mem.Allocator;
const Keypair = @import("crypto/keypair.zig").Keypair;
const jwt = @import("crypto/jwt.zig");

/// create a signed JWT from header and payload JSON strings.
/// caller owns returned slice.
pub fn createJwt(allocator: Allocator, header_json: []const u8, payload_json: []const u8, keypair: *const Keypair) ![]u8 {
    const header_b64 = try jwt.base64UrlEncode(allocator, header_json);
    defer allocator.free(header_b64);

    const payload_b64 = try jwt.base64UrlEncode(allocator, payload_json);
    defer allocator.free(payload_b64);

    const signing_input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ header_b64, payload_b64 });
    defer allocator.free(signing_input);

    const sig = try keypair.sign(signing_input);
    const sig_b64 = try jwt.base64UrlEncode(allocator, &sig.bytes);
    defer allocator.free(sig_b64);

    return std.fmt.allocPrint(allocator, "{s}.{s}", .{ signing_input, sig_b64 });
}

/// create a DPoP proof JWT per RFC 9449.
/// htm: HTTP method, htu: target URI, nonce: server-provided DPoP-Nonce,
/// ath: optional access token hash (base64url-encoded SHA-256).
pub fn createDpopProof(
    allocator: Allocator,
    keypair: *const Keypair,
    htm: []const u8,
    htu: []const u8,
    nonce: ?[]const u8,
    ath: ?[]const u8,
) ![]u8 {
    const jwk_json = try keypair.jwk(allocator);
    defer allocator.free(jwk_json);

    const jti = try generateJti(allocator);
    defer allocator.free(jti);

    const alg = @tagName(keypair.algorithm());
    const now = std.time.timestamp();

    // header: {"typ":"dpop+jwt","alg":"...","jwk":{...}}
    const header = try std.fmt.allocPrint(allocator,
        \\{{"typ":"dpop+jwt","alg":"{s}","jwk":{s}}}
    , .{ alg, jwk_json });
    defer allocator.free(header);

    // payload — build with writer for optional fields
    var payload_buf: std.ArrayList(u8) = .{};
    defer payload_buf.deinit(allocator);
    const writer = payload_buf.writer(allocator);

    try writer.print(
        \\{{"jti":"{s}","htm":"{s}","htu":"{s}","iat":{d}
    , .{ jti, htm, htu, now });

    if (nonce) |n| {
        try writer.print(",\"nonce\":\"{s}\"", .{n});
    }
    if (ath) |a| {
        try writer.print(",\"ath\":\"{s}\"", .{a});
    }

    try writer.writeAll("}");

    return createJwt(allocator, header, payload_buf.items, keypair);
}

/// create a private_key_jwt client assertion for token endpoint auth.
/// client_id: the OAuth client ID, aud: the token endpoint URL.
pub fn createClientAssertion(
    allocator: Allocator,
    keypair: *const Keypair,
    client_id: []const u8,
    aud: []const u8,
) ![]u8 {
    const jti = try generateJti(allocator);
    defer allocator.free(jti);

    const kid = try keypair.jwkThumbprint(allocator);
    defer allocator.free(kid);

    const alg = @tagName(keypair.algorithm());
    const now = std.time.timestamp();

    const header = try std.fmt.allocPrint(allocator,
        \\{{"typ":"JWT","alg":"{s}","kid":"{s}"}}
    , .{ alg, kid });
    defer allocator.free(header);

    const payload = try std.fmt.allocPrint(allocator,
        \\{{"iss":"{s}","sub":"{s}","aud":"{s}","jti":"{s}","iat":{d},"exp":{d}}}
    , .{ client_id, client_id, aud, jti, now, now + 120 });
    defer allocator.free(payload);

    return createJwt(allocator, header, payload, keypair);
}

/// generate a random PKCE code verifier (43 chars, base64url-encoded 32 random bytes).
/// caller owns returned slice.
pub fn generatePkceVerifier(allocator: Allocator) ![]u8 {
    var random_bytes: [32]u8 = undefined;
    crypto.random.bytes(&random_bytes);
    return jwt.base64UrlEncode(allocator, &random_bytes);
}

/// generate a PKCE S256 challenge from a verifier.
/// caller owns returned slice.
pub fn generatePkceChallenge(allocator: Allocator, verifier: []const u8) ![]u8 {
    var hash: [32]u8 = undefined;
    crypto.hash.sha2.Sha256.hash(verifier, &hash, .{});
    return jwt.base64UrlEncode(allocator, &hash);
}

/// generate a random state parameter (CSRF token).
/// caller owns returned slice.
pub fn generateState(allocator: Allocator) ![]u8 {
    var random_bytes: [16]u8 = undefined;
    crypto.random.bytes(&random_bytes);
    return jwt.base64UrlEncode(allocator, &random_bytes);
}

/// compute access token hash for DPoP ath claim: base64url(SHA-256(access_token)).
/// caller owns returned slice.
pub fn accessTokenHash(allocator: Allocator, access_token: []const u8) ![]u8 {
    var hash: [32]u8 = undefined;
    crypto.hash.sha2.Sha256.hash(access_token, &hash, .{});
    return jwt.base64UrlEncode(allocator, &hash);
}

/// encode key-value pairs as application/x-www-form-urlencoded.
/// caller owns returned slice.
pub fn formEncode(allocator: Allocator, params: []const [2][]const u8) ![]u8 {
    var buf: std.ArrayList(u8) = .{};
    errdefer buf.deinit(allocator);
    const writer = buf.writer(allocator);

    for (params, 0..) |kv, i| {
        if (i > 0) try writer.writeAll("&");
        try percentEncode(writer, kv[0]);
        try writer.writeAll("=");
        try percentEncode(writer, kv[1]);
    }

    return buf.toOwnedSlice(allocator);
}

/// format a JWKS JSON containing a single public key.
/// caller owns returned slice.
pub fn jwksJson(allocator: Allocator, keypair: *const Keypair) ![]u8 {
    const jwk_json = try keypair.jwk(allocator);
    defer allocator.free(jwk_json);

    return std.fmt.allocPrint(allocator,
        \\{{"keys":[{s}]}}
    , .{jwk_json});
}

// --- helpers ---

fn generateJti(allocator: Allocator) ![]u8 {
    var random_bytes: [16]u8 = undefined;
    crypto.random.bytes(&random_bytes);
    return jwt.base64UrlEncode(allocator, &random_bytes);
}

fn percentEncode(writer: anytype, input: []const u8) !void {
    for (input) |c| {
        if (isUnreserved(c)) {
            try writer.writeByte(c);
        } else {
            try writer.print("%{X:0>2}", .{c});
        }
    }
}

fn isUnreserved(c: u8) bool {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '_', '.', '~' => true,
        else => false,
    };
}

// === tests ===

test "PKCE S256 challenge - RFC 7636 test vector" {
    const allocator = std.testing.allocator;
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const challenge = try generatePkceChallenge(allocator, verifier);
    defer allocator.free(challenge);
    try std.testing.expectEqualStrings("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", challenge);
}

test "PKCE verifier is 43 chars" {
    const allocator = std.testing.allocator;
    const verifier = try generatePkceVerifier(allocator);
    defer allocator.free(verifier);
    try std.testing.expectEqual(@as(usize, 43), verifier.len);
}

test "form URL encoding" {
    const allocator = std.testing.allocator;

    const params = [_][2][]const u8{
        .{ "grant_type", "authorization_code" },
        .{ "code", "abc123" },
        .{ "redirect_uri", "https://example.com/callback" },
    };

    const encoded = try formEncode(allocator, &params);
    defer allocator.free(encoded);

    try std.testing.expectEqualStrings(
        "grant_type=authorization_code&code=abc123&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback",
        encoded,
    );
}

test "access token hash" {
    const allocator = std.testing.allocator;
    const ath = try accessTokenHash(allocator, "test-access-token");
    defer allocator.free(ath);
    // base64url(SHA-256) is always 43 chars
    try std.testing.expectEqual(@as(usize, 43), ath.len);
}

test "createJwt sign and verify round-trip" {
    const allocator = std.testing.allocator;
    const multibase = @import("crypto/multibase.zig");
    const multicodec = @import("crypto/multicodec.zig");

    const keypair = try Keypair.fromSecretKey(.p256, .{
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
    });

    const header =
        \\{"alg":"ES256","typ":"JWT"}
    ;
    const payload =
        \\{"iss":"did:example:test","aud":"did:example:aud","exp":9999999999}
    ;

    const token = try createJwt(allocator, header, payload, &keypair);
    defer allocator.free(token);

    // parse and verify with existing JWT infrastructure
    var parsed_jwt = try jwt.Jwt.parse(allocator, token);
    defer parsed_jwt.deinit();

    try std.testing.expectEqual(jwt.Algorithm.ES256, parsed_jwt.header.alg);
    try std.testing.expectEqualStrings("did:example:test", parsed_jwt.payload.iss);

    // verify signature via multibase key
    const pk = try keypair.publicKey();
    const mc_bytes = try multicodec.encodePublicKey(allocator, .p256, &pk);
    defer allocator.free(mc_bytes);
    const multibase_key = try multibase.encode(allocator, .base58btc, mc_bytes);
    defer allocator.free(multibase_key);

    try parsed_jwt.verify(multibase_key);
}

test "DPoP proof structure" {
    const allocator = std.testing.allocator;

    const keypair = try Keypair.fromSecretKey(.p256, .{
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
    });

    const proof = try createDpopProof(allocator, &keypair, "POST", "https://auth.example.com/token", "server-nonce", null);
    defer allocator.free(proof);

    // decode header
    var iter = std.mem.splitScalar(u8, proof, '.');
    const header_b64 = iter.next().?;
    const payload_b64 = iter.next().?;

    const header_json = try jwt.base64UrlDecode(allocator, header_b64);
    defer allocator.free(header_json);

    const header_parsed = try std.json.parseFromSlice(std.json.Value, allocator, header_json, .{});
    defer header_parsed.deinit();

    try std.testing.expectEqualStrings("dpop+jwt", header_parsed.value.object.get("typ").?.string);
    try std.testing.expectEqualStrings("ES256", header_parsed.value.object.get("alg").?.string);
    try std.testing.expect(header_parsed.value.object.get("jwk") != null);

    // decode payload
    const payload_json = try jwt.base64UrlDecode(allocator, payload_b64);
    defer allocator.free(payload_json);

    const payload_parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload_json, .{});
    defer payload_parsed.deinit();

    const obj = payload_parsed.value.object;
    try std.testing.expect(obj.get("jti") != null);
    try std.testing.expectEqualStrings("POST", obj.get("htm").?.string);
    try std.testing.expectEqualStrings("https://auth.example.com/token", obj.get("htu").?.string);
    try std.testing.expect(obj.get("iat") != null);
    try std.testing.expectEqualStrings("server-nonce", obj.get("nonce").?.string);
}

test "client assertion structure" {
    const allocator = std.testing.allocator;

    const keypair = try Keypair.fromSecretKey(.p256, .{
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
    });

    const assertion = try createClientAssertion(allocator, &keypair, "https://app.example.com/client-metadata", "https://bsky.social/oauth/token");
    defer allocator.free(assertion);

    // decode header
    var iter = std.mem.splitScalar(u8, assertion, '.');
    const header_b64 = iter.next().?;
    const payload_b64 = iter.next().?;

    const header_json = try jwt.base64UrlDecode(allocator, header_b64);
    defer allocator.free(header_json);

    const header_parsed = try std.json.parseFromSlice(std.json.Value, allocator, header_json, .{});
    defer header_parsed.deinit();

    try std.testing.expectEqualStrings("JWT", header_parsed.value.object.get("typ").?.string);
    try std.testing.expectEqualStrings("ES256", header_parsed.value.object.get("alg").?.string);
    try std.testing.expect(header_parsed.value.object.get("kid") != null);

    // decode payload
    const payload_json = try jwt.base64UrlDecode(allocator, payload_b64);
    defer allocator.free(payload_json);

    const payload_parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload_json, .{});
    defer payload_parsed.deinit();

    const obj = payload_parsed.value.object;
    try std.testing.expectEqualStrings("https://app.example.com/client-metadata", obj.get("iss").?.string);
    try std.testing.expectEqualStrings("https://app.example.com/client-metadata", obj.get("sub").?.string);
    try std.testing.expectEqualStrings("https://bsky.social/oauth/token", obj.get("aud").?.string);
    try std.testing.expect(obj.get("jti") != null);
    try std.testing.expect(obj.get("iat") != null);
    try std.testing.expect(obj.get("exp") != null);
}

test "JWKS JSON wraps JWK" {
    const allocator = std.testing.allocator;

    const keypair = try Keypair.fromSecretKey(.p256, .{
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
    });

    const jwks = try jwksJson(allocator, &keypair);
    defer allocator.free(jwks);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, jwks, .{});
    defer parsed.deinit();

    const keys = parsed.value.object.get("keys").?.array;
    try std.testing.expectEqual(@as(usize, 1), keys.items.len);
    try std.testing.expectEqualStrings("EC", keys.items[0].object.get("kty").?.string);
}
