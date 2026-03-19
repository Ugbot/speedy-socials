const std = @import("std");
const crypto = std.crypto;
const Ed25519 = crypto.sign.Ed25519;
const Sha256 = crypto.hash.sha2.Sha256;
const base64 = std.base64.standard;

pub const KeyPair = struct {
    secret_key: [64]u8,
    public_key: [32]u8,
};

/// SPKI OID prefix for Ed25519: SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING }
/// Fixed 12-byte DER prefix before the 32-byte public key.
const spki_prefix = [12]u8{
    0x30, 0x2a, // SEQUENCE, 42 bytes total
    0x30, 0x05, // SEQUENCE, 5 bytes (algorithm identifier)
    0x06, 0x03, // OID, 3 bytes
    0x2b, 0x65, 0x70, // 1.3.101.112 (Ed25519)
    0x03, 0x21, 0x00, // BIT STRING, 33 bytes, 0 unused bits
};

const pem_header = "-----BEGIN PUBLIC KEY-----";
const pem_footer = "-----END PUBLIC KEY-----";

pub fn generateKeyPair() KeyPair {
    const kp = Ed25519.KeyPair.generate();
    return KeyPair{
        .secret_key = kp.secret_key.toBytes(),
        .public_key = kp.public_key.toBytes(),
    };
}

pub fn publicKeyToPem(allocator: std.mem.Allocator, public_key: [32]u8) ![]u8 {
    // Build the 44-byte DER encoding
    var der: [44]u8 = undefined;
    @memcpy(der[0..12], &spki_prefix);
    @memcpy(der[12..44], &public_key);

    // Base64 encode the DER
    const encoded_len = base64.Encoder.calcSize(44);
    var encoded_buf: [base64.Encoder.calcSize(44)]u8 = undefined;
    _ = base64.Encoder.encode(&encoded_buf, &der);

    // Build PEM: header + newline + base64 + newline + footer
    const pem_len = pem_header.len + 1 + encoded_len + 1 + pem_footer.len;
    const pem = try allocator.alloc(u8, pem_len);
    var offset: usize = 0;

    @memcpy(pem[offset .. offset + pem_header.len], pem_header);
    offset += pem_header.len;
    pem[offset] = '\n';
    offset += 1;
    @memcpy(pem[offset .. offset + encoded_len], &encoded_buf);
    offset += encoded_len;
    pem[offset] = '\n';
    offset += 1;
    @memcpy(pem[offset .. offset + pem_footer.len], pem_footer);

    return pem;
}

pub fn pemToPublicKey(pem: []const u8) ![32]u8 {
    // Find the base64 content between header and footer
    const header_end = std.mem.indexOf(u8, pem, "\n") orelse return error.InvalidPem;
    const footer_start = std.mem.lastIndexOf(u8, pem, "\n") orelse return error.InvalidPem;

    if (header_end >= footer_start) return error.InvalidPem;

    const b64_data = std.mem.trim(u8, pem[header_end + 1 .. footer_start], " \t\r\n");

    // Decode base64 to get the 44-byte DER
    var der: [44]u8 = undefined;
    const decoded_len = base64.Decoder.calcSizeForSlice(b64_data) catch return error.InvalidBase64;
    if (decoded_len != 44) return error.InvalidDerLength;
    base64.Decoder.decode(&der, b64_data) catch return error.InvalidBase64;

    // Verify the SPKI prefix
    if (!std.mem.eql(u8, der[0..12], &spki_prefix)) return error.InvalidSpkiPrefix;

    // Extract the 32-byte public key
    var public_key: [32]u8 = undefined;
    @memcpy(&public_key, der[12..44]);
    return public_key;
}

pub fn generateDigest(allocator: std.mem.Allocator, body: []const u8) ![]u8 {
    var hasher = Sha256.init(.{});
    hasher.update(body);
    const hash = hasher.finalResult();

    const b64_len = base64.Encoder.calcSize(32);
    const prefix = "SHA-256=";
    const result = try allocator.alloc(u8, prefix.len + b64_len);
    @memcpy(result[0..prefix.len], prefix);

    var b64_buf: [base64.Encoder.calcSize(32)]u8 = undefined;
    _ = base64.Encoder.encode(&b64_buf, &hash);
    @memcpy(result[prefix.len..], &b64_buf);

    return result;
}

pub fn buildSigningString(
    allocator: std.mem.Allocator,
    method: []const u8,
    path: []const u8,
    host: []const u8,
    date: []const u8,
    digest: ?[]const u8,
) ![]u8 {
    // Lowercase the method for (request-target)
    const lower_method = try allocator.alloc(u8, method.len);
    defer allocator.free(lower_method);
    for (method, 0..) |c, i| {
        lower_method[i] = std.ascii.toLower(c);
    }

    if (digest) |d| {
        return std.fmt.allocPrint(allocator,
            "(request-target): {s} {s}\nhost: {s}\ndate: {s}\ndigest: {s}",
            .{ lower_method, path, host, date, d },
        );
    } else {
        return std.fmt.allocPrint(allocator,
            "(request-target): {s} {s}\nhost: {s}\ndate: {s}",
            .{ lower_method, path, host, date },
        );
    }
}

pub fn signRequest(
    allocator: std.mem.Allocator,
    secret_key: [64]u8,
    key_id: []const u8,
    method: []const u8,
    path: []const u8,
    host: []const u8,
    date: []const u8,
    digest: ?[]const u8,
) ![]u8 {
    const signing_string = try buildSigningString(allocator, method, path, host, date, digest);
    defer allocator.free(signing_string);

    const sk = try Ed25519.SecretKey.fromBytes(secret_key);
    const pk = Ed25519.PublicKey.fromBytes(sk.publicKeyBytes()) catch return error.InvalidPublicKey;
    const kp = Ed25519.KeyPair{ .public_key = pk, .secret_key = sk };
    const sig = try kp.sign(signing_string, null);
    const sig_bytes = sig.toBytes();

    var sig_b64: [base64.Encoder.calcSize(64)]u8 = undefined;
    _ = base64.Encoder.encode(&sig_b64, &sig_bytes);

    const headers_list = if (digest != null)
        "(request-target) host date digest"
    else
        "(request-target) host date";

    return std.fmt.allocPrint(allocator,
        "keyId=\"{s}\",algorithm=\"hs2019\",headers=\"{s}\",signature=\"{s}\"",
        .{ key_id, headers_list, sig_b64 },
    );
}

pub const ParsedSignature = struct {
    key_id: []const u8,
    algorithm: []const u8,
    headers: []const u8,
    signature: []const u8,
};

pub fn parseSignatureHeader(header: []const u8) !ParsedSignature {
    var result: ParsedSignature = .{
        .key_id = &.{},
        .algorithm = &.{},
        .headers = &.{},
        .signature = &.{},
    };

    var found_key_id = false;
    var found_algorithm = false;
    var found_headers = false;
    var found_signature = false;

    // Parse comma-separated key="value" pairs
    var remaining = header;
    while (remaining.len > 0) {
        // Skip leading whitespace and commas
        remaining = std.mem.trimLeft(u8, remaining, " ,");
        if (remaining.len == 0) break;

        // Find the '=' separator
        const eq_pos = std.mem.indexOf(u8, remaining, "=") orelse return error.InvalidSignatureHeader;
        const key = std.mem.trim(u8, remaining[0..eq_pos], " ");
        remaining = remaining[eq_pos + 1 ..];

        // Expect a quoted value
        if (remaining.len == 0 or remaining[0] != '"') return error.InvalidSignatureHeader;
        remaining = remaining[1..]; // skip opening quote

        const close_quote = std.mem.indexOf(u8, remaining, "\"") orelse return error.InvalidSignatureHeader;
        const value = remaining[0..close_quote];
        remaining = if (close_quote + 1 < remaining.len) remaining[close_quote + 1 ..] else &.{};

        if (std.mem.eql(u8, key, "keyId")) {
            result.key_id = value;
            found_key_id = true;
        } else if (std.mem.eql(u8, key, "algorithm")) {
            result.algorithm = value;
            found_algorithm = true;
        } else if (std.mem.eql(u8, key, "headers")) {
            result.headers = value;
            found_headers = true;
        } else if (std.mem.eql(u8, key, "signature")) {
            result.signature = value;
            found_signature = true;
        }
    }

    if (!found_key_id or !found_algorithm or !found_headers or !found_signature) {
        return error.InvalidSignatureHeader;
    }

    return result;
}

pub fn verifyRequest(
    allocator: std.mem.Allocator,
    public_key: [32]u8,
    parsed_sig: ParsedSignature,
    method: []const u8,
    path: []const u8,
    host: []const u8,
    date: []const u8,
    digest: ?[]const u8,
) !bool {
    const signing_string = try buildSigningString(allocator, method, path, host, date, digest);
    defer allocator.free(signing_string);

    // Decode the base64 signature
    var sig_bytes: [64]u8 = undefined;
    const expected_len = base64.Decoder.calcSizeForSlice(parsed_sig.signature) catch return false;
    if (expected_len != 64) return false;
    base64.Decoder.decode(&sig_bytes, parsed_sig.signature) catch return false;

    const pk = Ed25519.PublicKey.fromBytes(public_key) catch return false;
    const sig = Ed25519.Signature.fromBytes(sig_bytes);

    sig.verify(signing_string, pk) catch return false;
    return true;
}

// =============================================================================
// Tests
// =============================================================================

test "generate key pair" {
    const kp = generateKeyPair();
    // Verify the keys are non-zero (very unlikely to be all zeros from random generation)
    var all_zero_secret = true;
    for (kp.secret_key) |b| {
        if (b != 0) {
            all_zero_secret = false;
            break;
        }
    }
    try std.testing.expect(!all_zero_secret);

    var all_zero_public = true;
    for (kp.public_key) |b| {
        if (b != 0) {
            all_zero_public = false;
            break;
        }
    }
    try std.testing.expect(!all_zero_public);

    // Verify sizes are correct
    try std.testing.expectEqual(@as(usize, 64), kp.secret_key.len);
    try std.testing.expectEqual(@as(usize, 32), kp.public_key.len);

    // Generate a second pair and ensure they differ
    const kp2 = generateKeyPair();
    try std.testing.expect(!std.mem.eql(u8, &kp.public_key, &kp2.public_key));
}

test "PEM round-trip" {
    const kp = generateKeyPair();
    const pem = try publicKeyToPem(std.testing.allocator, kp.public_key);
    defer std.testing.allocator.free(pem);

    // Verify PEM structure
    try std.testing.expect(std.mem.startsWith(u8, pem, pem_header));
    try std.testing.expect(std.mem.endsWith(u8, pem, pem_footer));

    // Round-trip: decode back and compare
    const decoded_key = try pemToPublicKey(pem);
    try std.testing.expectEqualSlices(u8, &kp.public_key, &decoded_key);
}

test "sign and verify" {
    const kp = generateKeyPair();
    const key_id = "https://example.com/users/alice#main-key";
    const method = "POST";
    const path = "/inbox";
    const host = "remote.example.com";
    const date = "Thu, 19 Mar 2026 12:00:00 GMT";

    const digest = try generateDigest(std.testing.allocator, "{\"type\":\"Create\"}");
    defer std.testing.allocator.free(digest);

    const sig_header = try signRequest(
        std.testing.allocator,
        kp.secret_key,
        key_id,
        method,
        path,
        host,
        date,
        digest,
    );
    defer std.testing.allocator.free(sig_header);

    // Parse the generated signature header
    const parsed = try parseSignatureHeader(sig_header);
    try std.testing.expectEqualStrings("hs2019", parsed.algorithm);
    try std.testing.expectEqualStrings(key_id, parsed.key_id);
    try std.testing.expectEqualStrings("(request-target) host date digest", parsed.headers);

    // Verify the signature
    const valid = try verifyRequest(
        std.testing.allocator,
        kp.public_key,
        parsed,
        method,
        path,
        host,
        date,
        digest,
    );
    try std.testing.expect(valid);
}

test "verify fails with wrong key" {
    const kp = generateKeyPair();
    const kp2 = generateKeyPair();

    const digest = try generateDigest(std.testing.allocator, "{\"type\":\"Follow\"}");
    defer std.testing.allocator.free(digest);

    const sig_header = try signRequest(
        std.testing.allocator,
        kp.secret_key,
        "https://example.com/users/alice#main-key",
        "POST",
        "/inbox",
        "remote.example.com",
        "Thu, 19 Mar 2026 12:00:00 GMT",
        digest,
    );
    defer std.testing.allocator.free(sig_header);

    const parsed = try parseSignatureHeader(sig_header);

    // Verify with the WRONG public key — should fail
    const valid = try verifyRequest(
        std.testing.allocator,
        kp2.public_key,
        parsed,
        "POST",
        "/inbox",
        "remote.example.com",
        "Thu, 19 Mar 2026 12:00:00 GMT",
        digest,
    );
    try std.testing.expect(!valid);
}

test "verify fails with tampered body" {
    const kp = generateKeyPair();

    const original_digest = try generateDigest(std.testing.allocator, "{\"type\":\"Create\",\"id\":\"1\"}");
    defer std.testing.allocator.free(original_digest);

    const sig_header = try signRequest(
        std.testing.allocator,
        kp.secret_key,
        "https://example.com/users/alice#main-key",
        "POST",
        "/inbox",
        "remote.example.com",
        "Thu, 19 Mar 2026 12:00:00 GMT",
        original_digest,
    );
    defer std.testing.allocator.free(sig_header);

    const parsed = try parseSignatureHeader(sig_header);

    // Create a digest from a DIFFERENT body
    const tampered_digest = try generateDigest(std.testing.allocator, "{\"type\":\"Delete\",\"id\":\"666\"}");
    defer std.testing.allocator.free(tampered_digest);

    // Verify with the tampered digest — should fail
    const valid = try verifyRequest(
        std.testing.allocator,
        kp.public_key,
        parsed,
        "POST",
        "/inbox",
        "remote.example.com",
        "Thu, 19 Mar 2026 12:00:00 GMT",
        tampered_digest,
    );
    try std.testing.expect(!valid);
}

test "parse signature header" {
    const header =
        \\keyId="https://example.com/users/bob#main-key",algorithm="hs2019",headers="(request-target) host date digest",signature="dGVzdHNpZw=="
    ;

    const parsed = try parseSignatureHeader(header);
    try std.testing.expectEqualStrings("https://example.com/users/bob#main-key", parsed.key_id);
    try std.testing.expectEqualStrings("hs2019", parsed.algorithm);
    try std.testing.expectEqualStrings("(request-target) host date digest", parsed.headers);
    try std.testing.expectEqualStrings("dGVzdHNpZw==", parsed.signature);
}

test "digest generation" {
    const body = "hello world";
    const digest = try generateDigest(std.testing.allocator, body);
    defer std.testing.allocator.free(digest);

    // SHA-256 of "hello world" is known:
    // b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
    // Base64 of those bytes: uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=
    try std.testing.expectEqualStrings("SHA-256=uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=", digest);
}
