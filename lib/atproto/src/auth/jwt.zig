const std = @import("std");

/// JWT claims for AT Protocol session tokens.
pub const Claims = struct {
    /// Issuer (server DID).
    iss: []const u8,
    /// Subject (user DID).
    sub: []const u8,
    /// Audience.
    aud: []const u8,
    /// Expiration time (unix timestamp).
    exp: i64,
    /// Issued at (unix timestamp).
    iat: i64,
    /// Scope: "com.atproto.access" or "com.atproto.refresh".
    scope: []const u8,
};

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const base64url = std.base64.url_safe_no_pad;

/// Create an HS256 JWT token.
pub fn createToken(allocator: std.mem.Allocator, claims: Claims, secret: []const u8) ![]const u8 {
    // Header: {"alg":"HS256","typ":"JWT"}
    const header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";

    // Encode claims as JSON, then base64url
    var claims_aw: std.io.Writer.Allocating = .init(allocator);
    defer claims_aw.deinit();
    try std.json.Stringify.value(claims, .{}, &claims_aw.writer);
    const claims_bytes = claims_aw.written();

    const claims_b64 = try allocator.alloc(u8, base64url.Encoder.calcSize(claims_bytes.len));
    defer allocator.free(claims_b64);
    _ = base64url.Encoder.encode(claims_b64, claims_bytes);

    // Build signing input: header.payload
    const signing_input = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ header, claims_b64 });
    defer allocator.free(signing_input);

    // HMAC-SHA256 signature
    var sig: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&sig, signing_input, secret);

    const sig_b64 = try allocator.alloc(u8, base64url.Encoder.calcSize(sig.len));
    defer allocator.free(sig_b64);
    _ = base64url.Encoder.encode(sig_b64, &sig);

    // Assemble: header.payload.signature
    return std.fmt.allocPrint(allocator, "{s}.{s}.{s}", .{ header, claims_b64, sig_b64 });
}

/// Verify an HS256 JWT token and return the claims.
pub fn verifyToken(allocator: std.mem.Allocator, token: []const u8, secret: []const u8) !Claims {
    // Split into header.payload.signature
    var parts = std.mem.splitScalar(u8, token, '.');
    const header_part = parts.next() orelse return error.InvalidToken;
    const payload_part = parts.next() orelse return error.InvalidToken;
    const sig_part = parts.next() orelse return error.InvalidToken;
    _ = header_part;

    // Verify signature
    const signing_input_len = @as(usize, @intCast(@intFromPtr(sig_part.ptr) - @intFromPtr(token.ptr) - 1));
    const signing_input = token[0..signing_input_len];

    var expected_sig: [HmacSha256.mac_length]u8 = undefined;
    HmacSha256.create(&expected_sig, signing_input, secret);

    const expected_b64 = try allocator.alloc(u8, base64url.Encoder.calcSize(expected_sig.len));
    defer allocator.free(expected_b64);
    _ = base64url.Encoder.encode(expected_b64, &expected_sig);

    if (!std.mem.eql(u8, sig_part, expected_b64)) {
        return error.InvalidToken;
    }

    // Decode payload
    const payload_decoded = try allocator.alloc(u8, base64url.Decoder.calcSizeForSlice(payload_part) catch return error.InvalidToken);
    defer allocator.free(payload_decoded);
    base64url.Decoder.decode(payload_decoded, payload_part) catch return error.InvalidToken;

    // Parse JSON claims
    const parsed = std.json.parseFromSlice(Claims, allocator, payload_decoded, .{ .ignore_unknown_fields = true }) catch return error.InvalidToken;
    defer parsed.deinit();

    // Check expiration
    if (parsed.value.exp < std.time.timestamp()) {
        return error.ExpiredToken;
    }

    return Claims{
        .iss = try allocator.dupe(u8, parsed.value.iss),
        .sub = try allocator.dupe(u8, parsed.value.sub),
        .aud = try allocator.dupe(u8, parsed.value.aud),
        .exp = parsed.value.exp,
        .iat = parsed.value.iat,
        .scope = try allocator.dupe(u8, parsed.value.scope),
    };
}

/// Free claims strings allocated by verifyToken.
pub fn freeClaims(allocator: std.mem.Allocator, claims: Claims) void {
    allocator.free(claims.iss);
    allocator.free(claims.sub);
    allocator.free(claims.aud);
    allocator.free(claims.scope);
}

test "create and verify JWT" {
    const allocator = std.testing.allocator;
    const secret = "test-secret-key-for-hmac-256!!";
    const now = std.time.timestamp();

    const token = try createToken(allocator, .{
        .iss = "did:web:test",
        .sub = "did:web:user",
        .aud = "did:web:test",
        .exp = now + 3600,
        .iat = now,
        .scope = "com.atproto.access",
    }, secret);
    defer allocator.free(token);

    try std.testing.expect(std.mem.indexOf(u8, token, ".") != null);

    const claims = try verifyToken(allocator, token, secret);
    defer freeClaims(allocator, claims);

    try std.testing.expectEqualStrings("did:web:test", claims.iss);
    try std.testing.expectEqualStrings("did:web:user", claims.sub);
    try std.testing.expectEqualStrings("com.atproto.access", claims.scope);
}
