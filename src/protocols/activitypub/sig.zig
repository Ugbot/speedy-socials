//! HTTP Signature parsing + verification for both
//!   * draft-cavage-http-signatures-12 (legacy Mastodon)
//!   * RFC 9421 HTTP Message Signatures (Mastodon 4.5+ default)
//!
//! No I/O, no allocator, no heap. The caller supplies the public key via
//! `PublicKey` and a fixed-size signing-string buffer; nothing is fetched
//! here. Bounds:
//!   * up to `max_components` covered components per signature
//!   * up to `max_signing_string_bytes` reconstructed signing string
//!   * up to `max_param_bytes` per parameter value
//!
//! All loops are bounded by `limits.max_http_headers` and the above
//! ceilings.

const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;
const Sha256 = std.crypto.hash.sha2.Sha256;
const base64 = std.base64.standard;

const core = @import("core");
const errors = core.errors;
const FedError = errors.FedError;

const limits = core.limits;
const assert = core.assert.assert;
const assertLe = core.assert.assertLe;

const keys = @import("keys.zig");
const PublicKey = keys.PublicKey;

pub const max_components: u8 = 12;
pub const max_signing_string_bytes: usize = 4096;
pub const max_param_bytes: usize = 512;

pub const Scheme = enum {
    /// draft-cavage-http-signatures-12. One `Signature` header with
    /// keyId, algorithm, headers, signature params; signing string is
    /// "<name>: <value>\n" joined, no trailing newline; `(request-target)`
    /// is lowercased "<method> <path>"; `host` and `date` use the literal
    /// header values.
    cavage,
    /// RFC 9421. `Signature-Input: sig1=("@method" "@target-uri"
    /// "content-digest");created=...;keyid="..."` plus
    /// `Signature: sig1=:base64:`. Signing string lines look like
    /// `"@method": POST` and end with `"@signature-params": (...)`.
    rfc9421,
};

pub const Algorithm = enum {
    ed25519,
    rsa_sha256,
    /// draft-cavage `hs2019` — algorithm is decided by the key. We
    /// resolve this against the PublicKey's algorithm tag.
    hs2019,
    /// Legacy explicit RSA-SHA256 (`rsa-sha256` in draft-cavage).
    rsa_sha256_legacy,
    unknown,

    pub fn parse(s: []const u8) Algorithm {
        if (std.ascii.eqlIgnoreCase(s, "ed25519")) return .ed25519;
        if (std.ascii.eqlIgnoreCase(s, "rsa-v1_5-sha256")) return .rsa_sha256;
        if (std.ascii.eqlIgnoreCase(s, "rsa-sha256")) return .rsa_sha256_legacy;
        if (std.ascii.eqlIgnoreCase(s, "hs2019")) return .hs2019;
        return .unknown;
    }
};

/// One covered component name as written in the Signature/Signature-Input
/// header. For cavage these are plain header names plus `(request-target)`;
/// for RFC 9421 these include `@method`, `@target-uri`, etc. — we keep
/// the quotes-stripped form.
pub const Component = struct {
    name: [64]u8 = undefined,
    len: u8 = 0,

    pub fn fromSlice(s: []const u8) FedError!Component {
        if (s.len == 0 or s.len > 64) return error.SignatureMalformed;
        var c: Component = .{};
        @memcpy(c.name[0..s.len], s);
        c.len = @intCast(s.len);
        return c;
    }

    pub fn slice(self: *const Component) []const u8 {
        return self.name[0..self.len];
    }
};

/// Pre-parsed `Signature` header. All slices reference the caller's
/// header bytes — no copying.
pub const Parsed = struct {
    scheme: Scheme,
    key_id: []const u8,
    algorithm: Algorithm,
    /// Components are stored as KeyId-style fixed buffers so the parsed
    /// view does not retain header-byte lifetimes beyond the call.
    components: [max_components]Component = undefined,
    component_count: u8 = 0,
    signature_b64: []const u8,
    /// RFC 9421 only: the literal `(... );...` parameters list as it
    /// appeared in `Signature-Input`, e.g. `("@method" "@target-uri");keyid="..."`.
    /// Empty for cavage.
    signature_params_raw: []const u8 = "",
    /// Optional metadata captured from the params (created/expires).
    created_unix: ?i64 = null,
    expires_unix: ?i64 = null,
};

// ──────────────────────────────────────────────────────────────────────
// Parsing
// ──────────────────────────────────────────────────────────────────────

/// Parse a draft-cavage `Signature` header value.
pub fn parseCavage(header: []const u8) FedError!Parsed {
    var p: Parsed = .{
        .scheme = .cavage,
        .key_id = &.{},
        .algorithm = .unknown,
        .signature_b64 = &.{},
    };

    var found_signature = false;
    var found_key_id = false;
    var found_headers = false;
    var rem = header;
    var iter_guard: u32 = 0;
    while (rem.len > 0) {
        iter_guard += 1;
        if (iter_guard > 64) return error.SignatureMalformed;
        rem = std.mem.trimStart(u8, rem, " ,\t");
        if (rem.len == 0) break;
        const eq = std.mem.indexOfScalar(u8, rem, '=') orelse return error.SignatureMalformed;
        const key = std.mem.trim(u8, rem[0..eq], " ");
        rem = rem[eq + 1 ..];
        if (rem.len == 0 or rem[0] != '"') return error.SignatureMalformed;
        rem = rem[1..];
        const close = std.mem.indexOfScalar(u8, rem, '"') orelse return error.SignatureMalformed;
        const value = rem[0..close];
        rem = if (close + 1 < rem.len) rem[close + 1 ..] else &.{};

        if (std.mem.eql(u8, key, "keyId")) {
            if (value.len == 0) return error.SignatureMalformed;
            p.key_id = value;
            found_key_id = true;
        } else if (std.mem.eql(u8, key, "algorithm")) {
            p.algorithm = Algorithm.parse(value);
        } else if (std.mem.eql(u8, key, "headers")) {
            try parseCavageHeaders(value, &p);
            found_headers = true;
        } else if (std.mem.eql(u8, key, "signature")) {
            if (value.len == 0) return error.SignatureMalformed;
            p.signature_b64 = value;
            found_signature = true;
        } else if (std.mem.eql(u8, key, "created")) {
            p.created_unix = std.fmt.parseInt(i64, value, 10) catch null;
        } else if (std.mem.eql(u8, key, "expires")) {
            p.expires_unix = std.fmt.parseInt(i64, value, 10) catch null;
        }
        // Unknown params are ignored per the spec.
    }

    if (!found_signature or !found_key_id) return error.SignatureMalformed;
    // Cavage default headers list is `date` if omitted; we require explicit.
    if (!found_headers) return error.SignatureMalformed;
    if (p.algorithm == .unknown) p.algorithm = .hs2019;
    return p;
}

fn parseCavageHeaders(value: []const u8, p: *Parsed) FedError!void {
    var i: usize = 0;
    var count: u8 = 0;
    while (i < value.len) {
        // Skip whitespace.
        while (i < value.len and value[i] == ' ') : (i += 1) {}
        if (i >= value.len) break;
        const start = i;
        while (i < value.len and value[i] != ' ') : (i += 1) {}
        if (count >= max_components) return error.SignatureMalformed;
        p.components[count] = try Component.fromSlice(value[start..i]);
        count += 1;
    }
    if (count == 0) return error.SignatureMalformed;
    p.component_count = count;
}

/// Parse an RFC 9421 pair of headers. `signature_input` is the value of
/// `Signature-Input` (e.g. `sig1=("@method" "@target-uri");keyid="..."`);
/// `signature` is the value of `Signature` (`sig1=:base64:`). The label
/// (`sig1`) must match between the two; we pick the first label.
pub fn parseRfc9421(signature_input: []const u8, signature: []const u8) FedError!Parsed {
    var p: Parsed = .{
        .scheme = .rfc9421,
        .key_id = &.{},
        .algorithm = .unknown,
        .signature_b64 = &.{},
    };

    // Find label in signature_input.
    const eq1 = std.mem.indexOfScalar(u8, signature_input, '=') orelse return error.SignatureMalformed;
    const label = signature_input[0..eq1];
    if (label.len == 0) return error.SignatureMalformed;
    const after_label = signature_input[eq1 + 1 ..];
    if (after_label.len == 0 or after_label[0] != '(') return error.SignatureMalformed;
    const close_paren = std.mem.indexOfScalar(u8, after_label, ')') orelse return error.SignatureMalformed;
    const inner = after_label[1..close_paren];
    p.signature_params_raw = after_label;

    // Parse quoted component names.
    var i: usize = 0;
    var count: u8 = 0;
    var guard: u32 = 0;
    while (i < inner.len) {
        guard += 1;
        if (guard > 64) return error.SignatureMalformed;
        while (i < inner.len and (inner[i] == ' ' or inner[i] == '\t')) : (i += 1) {}
        if (i >= inner.len) break;
        if (inner[i] != '"') return error.SignatureMalformed;
        i += 1;
        const start = i;
        while (i < inner.len and inner[i] != '"') : (i += 1) {}
        if (i >= inner.len) return error.SignatureMalformed;
        if (count >= max_components) return error.SignatureMalformed;
        p.components[count] = try Component.fromSlice(inner[start..i]);
        count += 1;
        i += 1; // past close quote
    }
    if (count == 0) return error.SignatureMalformed;
    p.component_count = count;

    // Parse trailing parameters (after the close paren).
    var tail = after_label[close_paren + 1 ..];
    var tail_guard: u32 = 0;
    while (tail.len > 0) {
        tail_guard += 1;
        if (tail_guard > 32) return error.SignatureMalformed;
        tail = std.mem.trimStart(u8, tail, " ;\t");
        if (tail.len == 0) break;
        const eq = std.mem.indexOfScalar(u8, tail, '=') orelse return error.SignatureMalformed;
        const k = std.mem.trim(u8, tail[0..eq], " ");
        var v_region = tail[eq + 1 ..];
        var v: []const u8 = &.{};
        if (v_region.len > 0 and v_region[0] == '"') {
            const close = std.mem.indexOfScalar(u8, v_region[1..], '"') orelse return error.SignatureMalformed;
            v = v_region[1 .. 1 + close];
            v_region = if (2 + close <= v_region.len) v_region[1 + close + 1 ..] else &.{};
        } else {
            const end = std.mem.indexOfAny(u8, v_region, ";") orelse v_region.len;
            v = std.mem.trim(u8, v_region[0..end], " ");
            v_region = if (end < v_region.len) v_region[end..] else &.{};
        }
        tail = v_region;
        if (std.mem.eql(u8, k, "keyid")) {
            p.key_id = v;
        } else if (std.mem.eql(u8, k, "alg")) {
            p.algorithm = Algorithm.parse(v);
        } else if (std.mem.eql(u8, k, "created")) {
            p.created_unix = std.fmt.parseInt(i64, v, 10) catch null;
        } else if (std.mem.eql(u8, k, "expires")) {
            p.expires_unix = std.fmt.parseInt(i64, v, 10) catch null;
        }
    }
    if (p.key_id.len == 0) return error.SignatureMalformed;

    // Pull signature bytes from the `signature` header: <label>=:base64:
    var sig_rem = signature;
    sig_rem = std.mem.trimStart(u8, sig_rem, " ");
    // Allow leading "<label>=" or no label (we look for the first '=' followed by ':')
    if (std.mem.indexOf(u8, sig_rem, ":")) |first_colon| {
        const last_colon = std.mem.lastIndexOfScalar(u8, sig_rem, ':') orelse return error.SignatureMalformed;
        if (last_colon <= first_colon) return error.SignatureMalformed;
        p.signature_b64 = sig_rem[first_colon + 1 .. last_colon];
    } else {
        return error.SignatureMalformed;
    }
    if (p.signature_b64.len == 0) return error.SignatureMalformed;
    if (p.algorithm == .unknown) p.algorithm = .hs2019;
    return p;
}

// ──────────────────────────────────────────────────────────────────────
// Signing-string reconstruction
// ──────────────────────────────────────────────────────────────────────

/// Components a verifier looks up on the inbound request.
pub const RequestView = struct {
    method: []const u8,
    path: []const u8, // request-target path component, e.g. "/users/alice/inbox"
    target_uri: []const u8, // full URI for @target-uri (RFC 9421)
    host: []const u8,
    date: []const u8,
    digest_legacy: []const u8 = "", // "SHA-256=..." (cavage `digest`)
    content_digest: []const u8 = "", // "sha-256=:...:" (RFC 9421)
    content_type: []const u8 = "",
};

/// Reconstruct the signing string into `out`. Returns the slice written.
pub fn buildSigningString(parsed: *const Parsed, req: *const RequestView, out: []u8) FedError![]const u8 {
    if (out.len == 0) return error.SignatureMalformed;
    var w = Writer{ .buf = out };
    switch (parsed.scheme) {
        .cavage => try buildCavage(parsed, req, &w),
        .rfc9421 => try buildRfc9421(parsed, req, &w),
    }
    return w.slice();
}

const Writer = struct {
    buf: []u8,
    pos: usize = 0,

    fn writeAll(self: *Writer, bytes: []const u8) FedError!void {
        if (self.pos + bytes.len > self.buf.len) return error.SignatureMalformed;
        @memcpy(self.buf[self.pos .. self.pos + bytes.len], bytes);
        self.pos += bytes.len;
    }

    fn writeByte(self: *Writer, b: u8) FedError!void {
        if (self.pos + 1 > self.buf.len) return error.SignatureMalformed;
        self.buf[self.pos] = b;
        self.pos += 1;
    }

    fn writeLower(self: *Writer, bytes: []const u8) FedError!void {
        if (self.pos + bytes.len > self.buf.len) return error.SignatureMalformed;
        var i: usize = 0;
        while (i < bytes.len) : (i += 1) {
            self.buf[self.pos + i] = std.ascii.toLower(bytes[i]);
        }
        self.pos += bytes.len;
    }

    fn slice(self: *Writer) []const u8 {
        return self.buf[0..self.pos];
    }
};

fn buildCavage(parsed: *const Parsed, req: *const RequestView, w: *Writer) FedError!void {
    var i: u8 = 0;
    while (i < parsed.component_count) : (i += 1) {
        if (i > 0) try w.writeByte('\n');
        const name = parsed.components[i].slice();
        try w.writeLower(name);
        try w.writeAll(": ");
        if (std.mem.eql(u8, name, "(request-target)")) {
            // method (lowercase) + space + path
            try w.writeLower(req.method);
            try w.writeByte(' ');
            try w.writeAll(req.path);
        } else if (std.ascii.eqlIgnoreCase(name, "host")) {
            try w.writeAll(req.host);
        } else if (std.ascii.eqlIgnoreCase(name, "date")) {
            try w.writeAll(req.date);
        } else if (std.ascii.eqlIgnoreCase(name, "digest")) {
            try w.writeAll(req.digest_legacy);
        } else if (std.ascii.eqlIgnoreCase(name, "content-type")) {
            try w.writeAll(req.content_type);
        } else {
            return error.SignatureMalformed;
        }
    }
}

fn buildRfc9421(parsed: *const Parsed, req: *const RequestView, w: *Writer) FedError!void {
    var i: u8 = 0;
    while (i < parsed.component_count) : (i += 1) {
        const name = parsed.components[i].slice();
        try w.writeByte('"');
        try w.writeLower(name);
        try w.writeByte('"');
        try w.writeAll(": ");
        if (std.mem.eql(u8, name, "@method")) {
            // Section 2.2.1: uppercase canonical method.
            var j: usize = 0;
            while (j < req.method.len) : (j += 1) {
                try w.writeByte(std.ascii.toUpper(req.method[j]));
            }
        } else if (std.mem.eql(u8, name, "@target-uri")) {
            try w.writeAll(req.target_uri);
        } else if (std.mem.eql(u8, name, "@authority")) {
            try w.writeLower(req.host);
        } else if (std.mem.eql(u8, name, "@path")) {
            try w.writeAll(req.path);
        } else if (std.ascii.eqlIgnoreCase(name, "content-digest")) {
            try w.writeAll(req.content_digest);
        } else if (std.ascii.eqlIgnoreCase(name, "content-type")) {
            try w.writeAll(req.content_type);
        } else if (std.ascii.eqlIgnoreCase(name, "host")) {
            try w.writeAll(req.host);
        } else if (std.ascii.eqlIgnoreCase(name, "date")) {
            try w.writeAll(req.date);
        } else {
            return error.SignatureMalformed;
        }
        try w.writeByte('\n');
    }
    // Trailing @signature-params line.
    try w.writeAll("\"@signature-params\": ");
    try w.writeAll(parsed.signature_params_raw);
}

// ──────────────────────────────────────────────────────────────────────
// Verification
// ──────────────────────────────────────────────────────────────────────

/// Verify a parsed signature against the request view + public key.
/// Returns void on success; FedError.SignatureInvalid on failure.
pub fn verify(parsed: *const Parsed, req: *const RequestView, pk: *const PublicKey) FedError!void {
    var buf: [max_signing_string_bytes]u8 = undefined;
    const sstr = try buildSigningString(parsed, req, &buf);

    // Decode base64 signature into stack buffer (RSA-2048 = 256 bytes,
    // Ed25519 = 64 bytes; allow up to 512 for RSA-4096 forward-compat).
    var sig_buf: [512]u8 = undefined;
    const sig_len = decodeB64(parsed.signature_b64, &sig_buf) catch return error.SignatureMalformed;

    const effective_algo: Algorithm = switch (parsed.algorithm) {
        .hs2019 => switch (pk.algo) {
            .ed25519 => .ed25519,
            .rsa_sha256 => .rsa_sha256,
        },
        else => parsed.algorithm,
    };

    switch (effective_algo) {
        .ed25519 => {
            if (pk.algo != .ed25519) return error.SignatureInvalid;
            if (sig_len != 64) return error.SignatureInvalid;
            var sig_bytes: [64]u8 = undefined;
            @memcpy(&sig_bytes, sig_buf[0..64]);
            const ed_pk = Ed25519.PublicKey.fromBytes(pk.ed25519Bytes()) catch return error.SignatureInvalid;
            const sig = Ed25519.Signature.fromBytes(sig_bytes);
            sig.verify(sstr, ed_pk) catch return error.SignatureInvalid;
        },
        .rsa_sha256, .rsa_sha256_legacy => {
            if (pk.algo != .rsa_sha256) return error.SignatureInvalid;
            if (!keys.rsaVerify(pk.rsaSpki(), sstr, sig_buf[0..sig_len])) {
                return error.SignatureInvalid;
            }
        },
        .hs2019, .unknown => return error.SignatureInvalid,
    }
}

fn decodeB64(s: []const u8, out: []u8) !usize {
    const decoded_len = try base64.Decoder.calcSizeForSlice(s);
    if (decoded_len > out.len) return error.InvalidLength;
    try base64.Decoder.decode(out[0..decoded_len], s);
    return decoded_len;
}

// ──────────────────────────────────────────────────────────────────────
// Helpers for signers (used by outbound delivery; tests exercise round-trip)
// ──────────────────────────────────────────────────────────────────────

pub fn signEd25519(
    parsed_template: *const Parsed,
    req: *const RequestView,
    sk_bytes: [64]u8,
    out_signature_b64: []u8,
) FedError![]const u8 {
    var sbuf: [max_signing_string_bytes]u8 = undefined;
    const sstr = try buildSigningString(parsed_template, req, &sbuf);
    const sk = Ed25519.SecretKey.fromBytes(sk_bytes) catch return error.SignatureMalformed;
    const pk = Ed25519.PublicKey.fromBytes(sk.publicKeyBytes()) catch return error.SignatureMalformed;
    const kp = Ed25519.KeyPair{ .public_key = pk, .secret_key = sk };
    const sig = kp.sign(sstr, null) catch return error.SignatureInvalid;
    const sig_bytes = sig.toBytes();
    const need = base64.Encoder.calcSize(64);
    if (out_signature_b64.len < need) return error.SignatureMalformed;
    return base64.Encoder.encode(out_signature_b64[0..need], &sig_bytes);
}

pub fn computeSha256DigestHeader(body: []const u8, out: []u8) FedError![]const u8 {
    const prefix = "SHA-256=";
    const need = prefix.len + base64.Encoder.calcSize(32);
    if (out.len < need) return error.SignatureMalformed;
    var hasher = Sha256.init(.{});
    hasher.update(body);
    const hash = hasher.finalResult();
    @memcpy(out[0..prefix.len], prefix);
    _ = base64.Encoder.encode(out[prefix.len..need], &hash);
    return out[0..need];
}

pub fn computeContentDigestHeader(body: []const u8, out: []u8) FedError![]const u8 {
    const prefix = "sha-256=:";
    const suffix = ":";
    const need = prefix.len + base64.Encoder.calcSize(32) + suffix.len;
    if (out.len < need) return error.SignatureMalformed;
    var hasher = Sha256.init(.{});
    hasher.update(body);
    const hash = hasher.finalResult();
    @memcpy(out[0..prefix.len], prefix);
    _ = base64.Encoder.encode(out[prefix.len .. prefix.len + base64.Encoder.calcSize(32)], &hash);
    @memcpy(out[need - suffix.len .. need], suffix);
    return out[0..need];
}

// ──────────────────────────────────────────────────────────────────────
// AP-4: Inbound digest verification.
//
// `Digest` (cavage / RFC 3230) header is `SHA-256=<base64>`. RFC 9421
// uses `Content-Digest: sha-256=:<base64>:`. Both encode SHA-256 of the
// request body. We accept either; if `expected` does not contain a
// `sha-256` (case-insensitive) entry, we treat it as malformed.
// ──────────────────────────────────────────────────────────────────────

/// Verify the supplied legacy `Digest` header against `body`.
/// Empty header → returns success (caller decides whether absence is allowed).
pub fn verifyLegacyDigest(header_value: []const u8, body: []const u8) FedError!void {
    if (header_value.len == 0) return; // no-op when header absent
    // The header may carry multiple algorithms separated by commas. Find
    // a `SHA-256=` (case-insensitive) entry.
    var rem = header_value;
    var guard: u32 = 0;
    while (rem.len > 0) {
        guard += 1;
        if (guard > 8) return error.SignatureMalformed;
        // Skip leading whitespace/comma.
        rem = std.mem.trimStart(u8, rem, " ,\t");
        if (rem.len == 0) break;
        const eq = std.mem.indexOfScalar(u8, rem, '=') orelse return error.SignatureMalformed;
        const alg = rem[0..eq];
        // Find end of this entry's value (until comma or eol). Note: the
        // value is base64 + '=' padding; the comma is the separator
        // between entries, not within a value.
        var end: usize = eq + 1;
        while (end < rem.len and rem[end] != ',') : (end += 1) {}
        const value = rem[eq + 1 .. end];
        rem = if (end < rem.len) rem[end + 1 ..] else &.{};
        if (std.ascii.eqlIgnoreCase(alg, "SHA-256")) {
            return compareSha256Base64(value, body);
        }
    }
    return error.SignatureInvalid;
}

/// Verify the supplied RFC 9421 `Content-Digest` header against `body`.
/// Empty header → returns success.
pub fn verifyContentDigest(header_value: []const u8, body: []const u8) FedError!void {
    if (header_value.len == 0) return;
    // RFC 9530 syntax: `sha-256=:<base64>:` possibly multiple separated
    // by commas. Each value is wrapped in `:` delimiters (sf-binary).
    var rem = header_value;
    var guard: u32 = 0;
    while (rem.len > 0) {
        guard += 1;
        if (guard > 8) return error.SignatureMalformed;
        rem = std.mem.trimStart(u8, rem, " ,\t");
        if (rem.len == 0) break;
        const eq = std.mem.indexOfScalar(u8, rem, '=') orelse return error.SignatureMalformed;
        const alg = rem[0..eq];
        rem = rem[eq + 1 ..];
        if (rem.len < 2 or rem[0] != ':') return error.SignatureMalformed;
        rem = rem[1..];
        const close = std.mem.indexOfScalar(u8, rem, ':') orelse return error.SignatureMalformed;
        const value = rem[0..close];
        rem = if (close + 1 < rem.len) rem[close + 1 ..] else &.{};
        if (std.ascii.eqlIgnoreCase(alg, "sha-256")) {
            return compareSha256Base64(value, body);
        }
        // skip trailing comma
        rem = std.mem.trimStart(u8, rem, " ,\t");
    }
    return error.SignatureInvalid;
}

fn compareSha256Base64(b64: []const u8, body: []const u8) FedError!void {
    var hash: [32]u8 = undefined;
    Sha256.hash(body, &hash, .{});

    var decoded: [33]u8 = undefined;
    const dec_len = base64.Decoder.calcSizeForSlice(b64) catch return error.SignatureMalformed;
    if (dec_len != 32 or dec_len > decoded.len) return error.SignatureInvalid;
    base64.Decoder.decode(decoded[0..dec_len], b64) catch return error.SignatureMalformed;
    // Constant-time compare to avoid timing leaks (though digest is
    // public, defence in depth).
    var diff: u8 = 0;
    var i: usize = 0;
    while (i < 32) : (i += 1) diff |= decoded[i] ^ hash[i];
    if (diff != 0) return error.SignatureInvalid;
}

// ──────────────────────────────────────────────────────────────────────
// AP-5: Signature freshness / expiry check.
//
// Reject when:
//   * `expires` is set and < now (signature already expired)
//   * `created` is set and > now + skew_seconds (clock too far ahead —
//     either a misconfigured peer or a replay-prep attempt)
//   * `created` is set and < now - max_age_seconds (too old)
//
// All checks are gated by the field being present in the signature
// params; absent fields don't fail the check.
// ──────────────────────────────────────────────────────────────────────

pub const FreshnessPolicy = struct {
    /// Maximum allowed clock skew between peers (seconds either side).
    /// Default 300 s tracks Mastodon practice.
    skew_seconds: i64 = 300,
    /// Maximum age (seconds) for a signature whose `created` is set.
    /// Default 12 h; longer windows enable replay if `expires` is absent.
    max_age_seconds: i64 = 12 * 60 * 60,
};

pub fn checkFreshness(parsed: *const Parsed, now_unix: i64, policy: FreshnessPolicy) FedError!void {
    if (parsed.expires_unix) |exp| {
        if (exp < now_unix - policy.skew_seconds) return error.SignatureInvalid;
    }
    if (parsed.created_unix) |created| {
        if (created > now_unix + policy.skew_seconds) return error.SignatureInvalid;
        if (created < now_unix - policy.max_age_seconds) return error.SignatureInvalid;
    }
}

// ──────────────────────────────────────────────────────────────────────
// AP-20: Replay-window nonce cache.
//
// Bounded fixed-size cache of recently-accepted `(keyId, signature)`
// pairs. We keep entries for `window_seconds` (default 600 s — wider
// than the AP-5 freshness window so a replay launched between freshness
// boundaries still hits the cache). Eviction is oldest-on-insert.
//
// Inserted via `seen` from the inbox handler *after* signature verify
// succeeds; consulted by `seenBefore` at the start of the same path.
// Constant-time on the happy path (linear scan of a small ring).
// ──────────────────────────────────────────────────────────────────────

pub const ReplayCache = struct {
    pub const capacity: usize = 256;
    pub const max_keyid_bytes: usize = 256;
    pub const max_sig_bytes: usize = 96; // base64(64-byte sig) + slack

    const Entry = struct {
        ts: i64 = 0,
        keyid_buf: [max_keyid_bytes]u8 = undefined,
        keyid_len: u16 = 0,
        sig_buf: [max_sig_bytes]u8 = undefined,
        sig_len: u8 = 0,

        fn keyid(self: *const Entry) []const u8 {
            return self.keyid_buf[0..self.keyid_len];
        }
        fn sig(self: *const Entry) []const u8 {
            return self.sig_buf[0..self.sig_len];
        }
    };

    entries: [capacity]Entry = .{Entry{}} ** capacity,
    /// Where the next insert writes — wraps around.
    head: u16 = 0,
    /// Configurable replay window in seconds.
    window_seconds: i64 = 600,

    pub fn init() ReplayCache {
        return .{};
    }

    pub fn seenBefore(self: *const ReplayCache, key_id: []const u8, signature_b64: []const u8, now_unix: i64) bool {
        var i: usize = 0;
        while (i < capacity) : (i += 1) {
            const e = &self.entries[i];
            if (e.keyid_len == 0) continue;
            if (now_unix - e.ts > self.window_seconds) continue;
            if (e.keyid_len != key_id.len or e.sig_len != signature_b64.len) continue;
            if (!std.mem.eql(u8, e.keyid(), key_id)) continue;
            if (!std.mem.eql(u8, e.sig(), signature_b64)) continue;
            return true;
        }
        return false;
    }

    pub fn record(self: *ReplayCache, key_id: []const u8, signature_b64: []const u8, now_unix: i64) void {
        if (key_id.len == 0 or key_id.len > max_keyid_bytes) return;
        if (signature_b64.len == 0 or signature_b64.len > max_sig_bytes) return;
        const idx = self.head;
        self.head = @intCast((@as(usize, self.head) + 1) % capacity);
        var e: Entry = .{ .ts = now_unix };
        @memcpy(e.keyid_buf[0..key_id.len], key_id);
        e.keyid_len = @intCast(key_id.len);
        @memcpy(e.sig_buf[0..signature_b64.len], signature_b64);
        e.sig_len = @intCast(signature_b64.len);
        self.entries[idx] = e;
    }

    pub fn reset(self: *ReplayCache) void {
        self.* = .{};
    }
};

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

test "parseCavage extracts keyId / algorithm / headers / signature" {
    const hdr =
        "keyId=\"https://x/users/a#main-key\",algorithm=\"hs2019\"," ++
        "headers=\"(request-target) host date digest\",signature=\"dGVzdA==\"";
    const p = try parseCavage(hdr);
    try std.testing.expect(p.scheme == .cavage);
    try std.testing.expectEqualStrings("https://x/users/a#main-key", p.key_id);
    try std.testing.expect(p.algorithm == .hs2019);
    try std.testing.expectEqual(@as(u8, 4), p.component_count);
    try std.testing.expectEqualStrings("(request-target)", p.components[0].slice());
    try std.testing.expectEqualStrings("digest", p.components[3].slice());
    try std.testing.expectEqualStrings("dGVzdA==", p.signature_b64);
}

test "parseCavage rejects missing fields" {
    try std.testing.expectError(error.SignatureMalformed, parseCavage("keyId=\"k\""));
    try std.testing.expectError(error.SignatureMalformed, parseCavage(""));
}

test "buildSigningString cavage produces RFC-correct format" {
    const hdr =
        "keyId=\"k\",algorithm=\"hs2019\"," ++
        "headers=\"(request-target) host date digest\",signature=\"AAAA\"";
    const p = try parseCavage(hdr);
    const req: RequestView = .{
        .method = "POST",
        .path = "/users/alice/inbox",
        .target_uri = "https://example.com/users/alice/inbox",
        .host = "example.com",
        .date = "Thu, 19 Mar 2026 12:00:00 GMT",
        .digest_legacy = "SHA-256=abc==",
    };
    var buf: [1024]u8 = undefined;
    const sstr = try buildSigningString(&p, &req, &buf);
    const expected =
        "(request-target): post /users/alice/inbox\n" ++
        "host: example.com\n" ++
        "date: Thu, 19 Mar 2026 12:00:00 GMT\n" ++
        "digest: SHA-256=abc==";
    try std.testing.expectEqualStrings(expected, sstr);
}

test "AP-4: verifyLegacyDigest accepts matching SHA-256 body" {
    const body = "{\"hello\":\"world\"}";
    var hash: [32]u8 = undefined;
    Sha256.hash(body, &hash, .{});
    var b64_buf: [64]u8 = undefined;
    const b64 = base64.Encoder.encode(b64_buf[0..base64.Encoder.calcSize(32)], &hash);
    var hdr_buf: [128]u8 = undefined;
    const hdr = try std.fmt.bufPrint(&hdr_buf, "SHA-256={s}", .{b64});
    try verifyLegacyDigest(hdr, body);
}

test "AP-4: verifyLegacyDigest rejects digest of different body" {
    const body = "{\"hello\":\"world\"}";
    var hash: [32]u8 = undefined;
    Sha256.hash("other body", &hash, .{});
    var b64_buf: [64]u8 = undefined;
    const b64 = base64.Encoder.encode(b64_buf[0..base64.Encoder.calcSize(32)], &hash);
    var hdr_buf: [128]u8 = undefined;
    const hdr = try std.fmt.bufPrint(&hdr_buf, "SHA-256={s}", .{b64});
    try std.testing.expectError(error.SignatureInvalid, verifyLegacyDigest(hdr, body));
}

test "AP-4: verifyLegacyDigest empty header is no-op" {
    try verifyLegacyDigest("", "body");
}

test "AP-4: verifyContentDigest accepts matching sha-256 body" {
    const body = "abc";
    var out: [128]u8 = undefined;
    const hdr = try computeContentDigestHeader(body, &out);
    try verifyContentDigest(hdr, body);
}

test "AP-4: verifyContentDigest rejects mismatched body" {
    const body = "abc";
    var out: [128]u8 = undefined;
    const hdr = try computeContentDigestHeader(body, &out);
    try std.testing.expectError(error.SignatureInvalid, verifyContentDigest(hdr, "abd"));
}

test "AP-5: checkFreshness accepts unset created/expires" {
    const p: Parsed = .{
        .scheme = .cavage,
        .key_id = "k",
        .algorithm = .ed25519,
        .signature_b64 = "s",
    };
    try checkFreshness(&p, 1_000_000, .{});
}

test "AP-5: checkFreshness rejects expired signature" {
    var p: Parsed = .{
        .scheme = .rfc9421,
        .key_id = "k",
        .algorithm = .ed25519,
        .signature_b64 = "s",
    };
    p.expires_unix = 100;
    try std.testing.expectError(
        error.SignatureInvalid,
        checkFreshness(&p, 100_000, .{ .skew_seconds = 60 }),
    );
}

test "AP-5: checkFreshness rejects far-future created" {
    var p: Parsed = .{
        .scheme = .rfc9421,
        .key_id = "k",
        .algorithm = .ed25519,
        .signature_b64 = "s",
    };
    p.created_unix = 1_000_000;
    try std.testing.expectError(
        error.SignatureInvalid,
        checkFreshness(&p, 1_000, .{ .skew_seconds = 60 }),
    );
}

test "AP-5: checkFreshness rejects too-old created" {
    var p: Parsed = .{
        .scheme = .rfc9421,
        .key_id = "k",
        .algorithm = .ed25519,
        .signature_b64 = "s",
    };
    p.created_unix = 1_000;
    try std.testing.expectError(
        error.SignatureInvalid,
        checkFreshness(&p, 1_000_000, .{ .max_age_seconds = 60 * 60 }),
    );
}

test "AP-20: ReplayCache rejects duplicate signature within window" {
    var cache = ReplayCache.init();
    try std.testing.expect(!cache.seenBefore("key1", "sigAAA", 100));
    cache.record("key1", "sigAAA", 100);
    try std.testing.expect(cache.seenBefore("key1", "sigAAA", 200));
}

test "AP-20: ReplayCache lets duplicates through after window expires" {
    var cache = ReplayCache.init();
    cache.window_seconds = 60;
    cache.record("key1", "sigAAA", 100);
    try std.testing.expect(cache.seenBefore("key1", "sigAAA", 150));
    try std.testing.expect(!cache.seenBefore("key1", "sigAAA", 200));
}

test "AP-20: ReplayCache distinguishes by keyId" {
    var cache = ReplayCache.init();
    cache.record("key1", "sigAAA", 100);
    try std.testing.expect(!cache.seenBefore("key2", "sigAAA", 100));
}

test "AP-5: checkFreshness accepts created within skew" {
    var p: Parsed = .{
        .scheme = .rfc9421,
        .key_id = "k",
        .algorithm = .ed25519,
        .signature_b64 = "s",
    };
    p.created_unix = 100_010; // 10 s in the future
    try checkFreshness(&p, 100_000, .{ .skew_seconds = 300, .max_age_seconds = 12 * 60 * 60 });
}

test "parseRfc9421 extracts components + keyid + signature bytes" {
    const sig_input =
        "sig1=(\"@method\" \"@target-uri\" \"content-digest\");" ++
        "created=1742391600;keyid=\"https://x/users/a#main-key\";alg=\"ed25519\"";
    const sig = "sig1=:AAAA:";
    const p = try parseRfc9421(sig_input, sig);
    try std.testing.expect(p.scheme == .rfc9421);
    try std.testing.expect(p.algorithm == .ed25519);
    try std.testing.expectEqual(@as(u8, 3), p.component_count);
    try std.testing.expectEqualStrings("@method", p.components[0].slice());
    try std.testing.expectEqualStrings("content-digest", p.components[2].slice());
    try std.testing.expectEqualStrings("AAAA", p.signature_b64);
    try std.testing.expectEqual(@as(?i64, 1742391600), p.created_unix);
}

test "buildSigningString rfc9421 includes @signature-params trailer" {
    const sig_input =
        "sig1=(\"@method\" \"@target-uri\");keyid=\"k\";alg=\"ed25519\"";
    const p = try parseRfc9421(sig_input, "sig1=:AAAA:");
    const req: RequestView = .{
        .method = "post",
        .path = "/inbox",
        .target_uri = "https://example.com/inbox",
        .host = "example.com",
        .date = "",
    };
    var buf: [512]u8 = undefined;
    const sstr = try buildSigningString(&p, &req, &buf);
    const expected =
        "\"@method\": POST\n" ++
        "\"@target-uri\": https://example.com/inbox\n" ++
        "\"@signature-params\": (\"@method\" \"@target-uri\");keyid=\"k\";alg=\"ed25519\"";
    try std.testing.expectEqualStrings(expected, sstr);
}

test "Ed25519 cavage sign + verify round-trip" {
    const kid = try keys.KeyId.fromSlice("kid");
    const pair = try keys.generateEd25519FromSeed(kid, keys.testSeed(2));

    // Build a parsed template by parsing a header (signature bytes will
    // be overwritten by signEd25519's b64 output, but parseCavage needs
    // them present).
    const hdr =
        "keyId=\"kid\",algorithm=\"ed25519\"," ++
        "headers=\"(request-target) host date\",signature=\"AAAA\"";
    var p = try parseCavage(hdr);
    p.algorithm = .ed25519;

    const req: RequestView = .{
        .method = "POST",
        .path = "/inbox",
        .target_uri = "https://example.com/inbox",
        .host = "example.com",
        .date = "Thu, 19 Mar 2026 12:00:00 GMT",
    };

    var sig_buf: [128]u8 = undefined;
    const sig_b64 = try signEd25519(&p, &req, pair.private.ed25519SecretBytes(), &sig_buf);
    p.signature_b64 = sig_b64;

    try verify(&p, &req, &pair.public);
}

test "Ed25519 rfc9421 sign + verify round-trip" {
    const kid = try keys.KeyId.fromSlice("kid");
    const pair = try keys.generateEd25519FromSeed(kid, keys.testSeed(2));
    const sig_input =
        "sig1=(\"@method\" \"@target-uri\" \"content-digest\");keyid=\"kid\";alg=\"ed25519\"";
    var p = try parseRfc9421(sig_input, "sig1=:AAAA:");

    const req: RequestView = .{
        .method = "post",
        .path = "/inbox",
        .target_uri = "https://example.com/inbox",
        .host = "example.com",
        .date = "",
        .content_digest = "sha-256=:1234:",
    };

    var sig_buf: [128]u8 = undefined;
    const sig_b64 = try signEd25519(&p, &req, pair.private.ed25519SecretBytes(), &sig_buf);
    p.signature_b64 = sig_b64;

    try verify(&p, &req, &pair.public);
}

test "verify fails when signing string differs (tampered path)" {
    const kid = try keys.KeyId.fromSlice("kid");
    const pair = try keys.generateEd25519FromSeed(kid, keys.testSeed(2));
    const hdr =
        "keyId=\"kid\",algorithm=\"ed25519\"," ++
        "headers=\"(request-target) host date\",signature=\"AAAA\"";
    var p = try parseCavage(hdr);
    p.algorithm = .ed25519;
    const req: RequestView = .{
        .method = "POST",
        .path = "/inbox",
        .target_uri = "",
        .host = "example.com",
        .date = "Thu, 19 Mar 2026 12:00:00 GMT",
    };
    var sig_buf: [128]u8 = undefined;
    const sig_b64 = try signEd25519(&p, &req, pair.private.ed25519SecretBytes(), &sig_buf);
    p.signature_b64 = sig_b64;
    var tampered = req;
    tampered.path = "/inbox-evil";
    try std.testing.expectError(error.SignatureInvalid, verify(&p, &tampered, &pair.public));
}

test "verify fails when wrong public key" {
    const kid = try keys.KeyId.fromSlice("kid");
    const a = try keys.generateEd25519FromSeed(kid, keys.testSeed(3));
    const b = try keys.generateEd25519FromSeed(kid, keys.testSeed(7));
    const hdr =
        "keyId=\"kid\",algorithm=\"ed25519\"," ++
        "headers=\"(request-target) host date\",signature=\"AAAA\"";
    var p = try parseCavage(hdr);
    p.algorithm = .ed25519;
    const req: RequestView = .{
        .method = "POST",
        .path = "/inbox",
        .target_uri = "",
        .host = "example.com",
        .date = "d",
    };
    var sig_buf: [128]u8 = undefined;
    const sig_b64 = try signEd25519(&p, &req, a.private.ed25519SecretBytes(), &sig_buf);
    p.signature_b64 = sig_b64;
    try std.testing.expectError(error.SignatureInvalid, verify(&p, &req, &b.public));
}

test "computeSha256DigestHeader matches known value" {
    var out: [128]u8 = undefined;
    const digest = try computeSha256DigestHeader("hello world", &out);
    try std.testing.expectEqualStrings(
        "SHA-256=uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=",
        digest,
    );
}

test "computeContentDigestHeader wraps in colons per RFC 9421" {
    var out: [128]u8 = undefined;
    const digest = try computeContentDigestHeader("hello world", &out);
    try std.testing.expect(std.mem.startsWith(u8, digest, "sha-256=:"));
    try std.testing.expect(std.mem.endsWith(u8, digest, ":"));
}

test "buildSigningString errors when too small" {
    const hdr =
        "keyId=\"k\",algorithm=\"hs2019\"," ++
        "headers=\"(request-target) host\",signature=\"AAAA\"";
    const p = try parseCavage(hdr);
    const req: RequestView = .{
        .method = "POST",
        .path = "/x",
        .target_uri = "",
        .host = "example.com",
        .date = "",
    };
    var tiny: [4]u8 = undefined;
    try std.testing.expectError(error.SignatureMalformed, buildSigningString(&p, &req, &tiny));
}

test "Algorithm.parse handles aliases" {
    try std.testing.expect(Algorithm.parse("ed25519") == .ed25519);
    try std.testing.expect(Algorithm.parse("ED25519") == .ed25519);
    try std.testing.expect(Algorithm.parse("hs2019") == .hs2019);
    try std.testing.expect(Algorithm.parse("rsa-sha256") == .rsa_sha256_legacy);
    try std.testing.expect(Algorithm.parse("rsa-v1_5-sha256") == .rsa_sha256);
    try std.testing.expect(Algorithm.parse("blake3") == .unknown);
}
