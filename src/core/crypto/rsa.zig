//! RSA-PKCS1-v1.5 over SHA-256 — verify (and bounded-rare sign).
//!
//! Implementation choice: pure-Zig, layered on `std.crypto.Certificate.rsa`
//! which provides RSA-{2048,3072,4096} modular exponentiation + the
//! EMSA-PKCS1-v1.5 encoding via `std.crypto.ff.Modulus`. The standard
//! library has the primitives we need without vendoring BoringSSL —
//! verification is the hot path for ActivityPub HTTP signatures, and the
//! stdlib's `ff` integer is constant-time enough for our use (legacy
//! draft-cavage signatures we only verify, not sign).
//!
//! See `src/core/crypto/README.md` for the BoringSSL discussion.
//!
//! Surface:
//!   * `verifyPkcs1v15Sha256(spki_der, message, signature) bool`
//!     The host wires this as the ActivityPub RSA verify hook.
//!   * `parseSpkiDer(der) PublicKey` for diagnostics / metadata.
//!
//! Tiger Style: bounded buffers, no allocator on the verify path. The
//! stdlib's `ff.Modulus` stack-allocates a 4096-bit integer; sign-path
//! is not implemented (we generate Ed25519 keys, not RSA).

const std = @import("std");
const cert = std.crypto.Certificate;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Error = error{
    /// SPKI DER did not parse as an RSA public key.
    BadSpki,
    /// Modulus length is not a supported size (2048/3072/4096 bits).
    UnsupportedKeySize,
    /// Signature length does not match the modulus length.
    BadSignatureLength,
};

pub const max_modulus_bytes: usize = 512; // 4096 bits

pub const PublicKey = struct {
    /// Big-endian modulus bytes (no leading zeros).
    n: [max_modulus_bytes]u8 = undefined,
    n_len: usize = 0,
    /// Big-endian public exponent bytes.
    e: [16]u8 = undefined,
    e_len: usize = 0,
};

/// Parse an RSA SPKI DER blob (the body of an `-----BEGIN PUBLIC KEY-----`
/// block once the PEM wrapping is stripped). The stdlib's
/// `Certificate.rsa.PublicKey.parseDer` does the heavy lifting.
pub fn parseSpkiDer(spki_der: []const u8) Error!PublicKey {
    // The stdlib accepts the *inner* SubjectPublicKey BIT STRING contents
    // (the raw PKCS#1 RSAPublicKey SEQUENCE), not the outer SPKI. We
    // walk the outer wrapper once: SPKI = SEQUENCE { algId, BIT STRING }.
    const inner = stripSpkiWrapper(spki_der) catch return error.BadSpki;
    const components = cert.rsa.PublicKey.parseDer(inner) catch return error.BadSpki;
    if (components.modulus.len > max_modulus_bytes) return error.UnsupportedKeySize;
    if (components.exponent.len > 16) return error.BadSpki;
    var pk: PublicKey = .{};
    @memcpy(pk.n[0..components.modulus.len], components.modulus);
    pk.n_len = components.modulus.len;
    @memcpy(pk.e[0..components.exponent.len], components.exponent);
    pk.e_len = components.exponent.len;
    return pk;
}

/// Strip the outer SPKI wrapper to expose the inner RSAPublicKey
/// SEQUENCE. Tiger Style: hand-rolled DER walker, no recursion.
fn stripSpkiWrapper(der: []const u8) error{Malformed}![]const u8 {
    // Expect: 0x30 LEN SEQUENCE { 0x30 LEN AlgorithmIdentifier
    //   { 0x06 LEN OID(rsaEncryption) 0x05 0x00 NULL },
    //   0x03 LEN BIT STRING { 0x00 RSAPublicKey } }
    var p: usize = 0;
    if (der.len < 4) return error.Malformed;
    if (der[p] != 0x30) return error.Malformed;
    p += 1;
    p += try derSkipLen(der, p);

    // Inside outer SEQUENCE. First child: AlgorithmIdentifier SEQUENCE.
    if (der.len <= p or der[p] != 0x30) return error.Malformed;
    p += 1;
    const algo_len = try derReadLen(der, &p);
    p += algo_len;

    // Second child: BIT STRING.
    if (der.len <= p or der[p] != 0x03) return error.Malformed;
    p += 1;
    const bs_len = try derReadLen(der, &p);
    if (der.len < p + bs_len) return error.Malformed;
    if (bs_len < 1) return error.Malformed;
    // First byte of BIT STRING is the "unused bits" count; must be 0.
    if (der[p] != 0x00) return error.Malformed;
    return der[p + 1 .. p + bs_len];
}

fn derReadLen(der: []const u8, p: *usize) error{Malformed}!usize {
    if (p.* >= der.len) return error.Malformed;
    const b0 = der[p.*];
    p.* += 1;
    if ((b0 & 0x80) == 0) return b0;
    const n = b0 & 0x7f;
    if (n > 4 or p.* + n > der.len) return error.Malformed;
    var v: usize = 0;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        v = (v << 8) | der[p.* + i];
    }
    p.* += n;
    return v;
}

fn derSkipLen(der: []const u8, start: usize) error{Malformed}!usize {
    var p = start;
    _ = try derReadLen(der, &p);
    return p - start;
}

/// PKCS1-v1.5 / SHA-256 verify. The hot path for ActivityPub
/// HTTP-signature verification.
pub fn verifyPkcs1v15Sha256(spki_der: []const u8, message: []const u8, signature: []const u8) bool {
    const pk = parseSpkiDer(spki_der) catch return false;
    return verifyParsed(pk, message, signature);
}

pub fn verifyParsed(pk: PublicKey, message: []const u8, signature: []const u8) bool {
    if (signature.len != pk.n_len) return false;
    const stdpk = cert.rsa.PublicKey.fromBytes(pk.e[0..pk.e_len], pk.n[0..pk.n_len]) catch return false;
    switch (pk.n_len) {
        inline 256, 384, 512 => |mod_len| {
            var sig_arr: [mod_len]u8 = undefined;
            @memcpy(&sig_arr, signature[0..mod_len]);
            cert.rsa.PKCS1v1_5Signature.verify(mod_len, sig_arr, message, stdpk, Sha256) catch return false;
            return true;
        },
        else => return false,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

const testing = std.testing;

// 2048-bit RSA public key (PEM body) generated with OpenSSL:
//   openssl genrsa -out k.pem 2048
//   openssl rsa -in k.pem -pubout -outform DER | base64
//
// We embed the DER bytes inline rather than re-deriving them at test
// time. The matching private key was used to produce `test_sig_b64`.
//
// Generated test vector (deterministic per the embedded key):
//   message = "speedy-socials rsa test vector v1"
const test_spki_der_b64 =
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt05wQCVTwSL36r6nJE9a" ++
    "60PhB1CyIiOUTZ6BkT1BY7+vGPq2ygDsRH6XanVi8nhHH9dvuHhTYNiJmsqIMhAL" ++
    "ZN+PtwjroUtvf4PSFdkt3jH2Zqb0FdMiPFmzAj7eVAGHbACbO0sSikexZcVIJ/t3" ++
    "bHAVcj9QxDT7nnFNny8Mc5uQizLjDw1f9rvkKQKlXXMEJoPMD/3WLkvT7ZMYjPAA" ++
    "9pxxoVPxGnm1o/8PhfKe63QLdNRaFBxu6nqb2lG6HXyQrWeBM/bMei/yElIPveg6" ++
    "dljUZdc9MHTMEILdfGnrS3pHpJ8fWPQ98dMgrALS884tK0KWBuc8WnyiUZ1GUyyQ" ++
    "gQIDAQAB";

const test_message = "speedy-socials rsa test vector v1";
const test_sig_b64 =
    "IH3uffF6OhqRgeMjwlgH+TJybJc/a39kJBcOmPoqZM6morKguFQQ4IZmPbmnybd8" ++
    "4yzyhHEUCOFFNWLwbKKLPgTdwuegy8YwsjkcVaW4YMVtdCGvB8LaE4xqUEOlasK1" ++
    "KabGbkYBx5rqAMBXy38LbB/k27HoleNOYCPyz2E3ny7AeRblx/mHVzkDGNKC2A4c" ++
    "s+cT6jcMnQvSh9DByS26GcqHyfU4flR61Bnzffs9wN7UXAwlYOZATmzpc19isGmt" ++
    "f60L/u91Ko5E28+E/63KyPdcY+a8G3gINBnA+gBrUsAWU7V1FuxZ2fDgS/y6zX6F" ++
    "a1xgtY2lblcvdqSCySdfnQ==";

test "rsa: parseSpkiDer succeeds for a real 2048-bit key" {
    // base64-decode the SPKI DER.
    var der: [512]u8 = undefined;
    const der_len = std.base64.standard.Decoder.calcSizeForSlice(test_spki_der_b64) catch unreachable;
    try std.base64.standard.Decoder.decode(der[0..der_len], test_spki_der_b64);
    const pk = parseSpkiDer(der[0..der_len]) catch |e| {
        std.debug.print("parse err: {s}\n", .{@errorName(e)});
        return e;
    };
    try testing.expectEqual(@as(usize, 256), pk.n_len);
    // Public exponent 65537 = 0x010001
    try testing.expectEqual(@as(usize, 3), pk.e_len);
    try testing.expectEqual(@as(u8, 0x01), pk.e[0]);
    try testing.expectEqual(@as(u8, 0x00), pk.e[1]);
    try testing.expectEqual(@as(u8, 0x01), pk.e[2]);
}

test "rsa: verifyPkcs1v15Sha256 accepts a real OpenSSL signature" {
    var der: [512]u8 = undefined;
    const der_len = std.base64.standard.Decoder.calcSizeForSlice(test_spki_der_b64) catch unreachable;
    try std.base64.standard.Decoder.decode(der[0..der_len], test_spki_der_b64);
    var sig: [256]u8 = undefined;
    const sig_len = std.base64.standard.Decoder.calcSizeForSlice(test_sig_b64) catch unreachable;
    try testing.expectEqual(@as(usize, 256), sig_len);
    try std.base64.standard.Decoder.decode(sig[0..sig_len], test_sig_b64);
    try testing.expect(verifyPkcs1v15Sha256(der[0..der_len], test_message, sig[0..sig_len]));
}

test "rsa: verifyPkcs1v15Sha256 rejects flipped message bit" {
    var der: [512]u8 = undefined;
    const der_len = std.base64.standard.Decoder.calcSizeForSlice(test_spki_der_b64) catch unreachable;
    try std.base64.standard.Decoder.decode(der[0..der_len], test_spki_der_b64);
    var sig: [256]u8 = undefined;
    try std.base64.standard.Decoder.decode(&sig, test_sig_b64);
    var msg_buf: [test_message.len]u8 = undefined;
    @memcpy(&msg_buf, test_message);
    msg_buf[0] ^= 0x01;
    try testing.expect(!verifyPkcs1v15Sha256(der[0..der_len], &msg_buf, &sig));
}

test "rsa: verifyPkcs1v15Sha256 rejects forged signature" {
    var der: [512]u8 = undefined;
    const der_len = std.base64.standard.Decoder.calcSizeForSlice(test_spki_der_b64) catch unreachable;
    try std.base64.standard.Decoder.decode(der[0..der_len], test_spki_der_b64);
    var bogus_sig: [256]u8 = undefined;
    @memset(&bogus_sig, 0xAA);
    try testing.expect(!verifyPkcs1v15Sha256(der[0..der_len], "anything", &bogus_sig));
}

test "rsa: verifyPkcs1v15Sha256 fails on wrong signature length" {
    var der: [512]u8 = undefined;
    const der_len = std.base64.standard.Decoder.calcSizeForSlice(test_spki_der_b64) catch unreachable;
    try std.base64.standard.Decoder.decode(der[0..der_len], test_spki_der_b64);
    var short_sig: [200]u8 = undefined;
    @memset(&short_sig, 0);
    try testing.expect(!verifyPkcs1v15Sha256(der[0..der_len], "x", &short_sig));
}

test "rsa: parseSpkiDer rejects garbage" {
    var garbage: [64]u8 = undefined;
    @memset(&garbage, 0xFF);
    try testing.expectError(error.BadSpki, parseSpkiDer(&garbage));
}
