//! AP-21: Data Integrity Proofs (FEP-8b32 / W3C VC `eddsa-jcs-2022`).
//!
//! Verifies an inbound activity's `proof` block:
//!   1. canonicalise the document minus `proof`  → SHA-256 → docHash
//!   2. canonicalise the proof minus `proofValue` → SHA-256 → cfgHash
//!   3. hashData = cfgHash ‖ docHash
//!   4. Ed25519-verify(proofValue, hashData, key)
//!
//! Canonicalisation is a deterministic compact JSON re-serialisation with
//! lexicographically-sorted object keys (JCS-style; exact RFC 8785
//! string/number normalisation is a follow-up gated on real-peer interop
//! testing — see the env flag below). Determinism is what the
//! sign↔verify round-trip relies on, and the tests prove it.
//!
//! **Disabled by default.** Inbound LD-proof verification only runs when
//! `AP_LD_PROOF=1`; otherwise the proof block is parsed/recognised but not
//! cryptographically enforced (matching the historical soft behaviour).
//! Default-off means a canonicalisation mismatch can never turn into a
//! signature bypass on the default path.

const std = @import("std");
const core = @import("core");
const ed25519 = core.crypto.ed25519;
const multibase = core.crypto.multibase;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const max_depth: u32 = 32;
pub const max_object_keys: u32 = 256;

pub const Error = error{ Malformed, BufferTooSmall, TooDeep };

/// True iff inbound LD-proof verification is enabled (`AP_LD_PROOF=1`).
pub fn enabled() bool {
    const p = std.c.getenv("AP_LD_PROOF") orelse return false;
    const s = std.mem.sliceTo(p, 0);
    return s.len > 0 and (s[0] == '1' or s[0] == 't' or s[0] == 'T');
}

// ── Canonical JSON ─────────────────────────────────────────────────────

const Entry = struct { key_start: u32, key_len: u32, val_start: u32 };

const Canon = struct {
    src: []const u8,
    cur: usize = 0,
    out: []u8,
    olen: usize = 0,

    fn emit(self: *Canon, s: []const u8) Error!void {
        if (self.olen + s.len > self.out.len) return error.BufferTooSmall;
        @memcpy(self.out[self.olen..][0..s.len], s);
        self.olen += s.len;
    }
    fn emitByte(self: *Canon, b: u8) Error!void {
        if (self.olen + 1 > self.out.len) return error.BufferTooSmall;
        self.out[self.olen] = b;
        self.olen += 1;
    }
    fn skipWs(self: *Canon) void {
        while (self.cur < self.src.len) : (self.cur += 1) switch (self.src[self.cur]) {
            ' ', '\t', '\n', '\r' => {},
            else => return,
        };
    }
    fn peek(self: *Canon) ?u8 {
        return if (self.cur < self.src.len) self.src[self.cur] else null;
    }

    fn value(self: *Canon, depth: u32, exclude: []const u8) Error!void {
        if (depth > max_depth) return error.TooDeep;
        self.skipWs();
        const ch = self.peek() orelse return error.Malformed;
        switch (ch) {
            '{' => try self.object(depth, exclude),
            '[' => try self.array(depth),
            '"' => try self.string(),
            else => try self.scalar(),
        }
    }

    fn object(self: *Canon, depth: u32, exclude: []const u8) Error!void {
        self.cur += 1; // {
        var entries: [max_object_keys]Entry = undefined;
        var n: u32 = 0;
        self.skipWs();
        if (self.peek() == '}') {
            self.cur += 1;
            return self.emit("{}");
        }
        while (true) {
            self.skipWs();
            if (self.peek() != '"') return error.Malformed;
            const ks = self.cur + 1;
            try self.skipString();
            const ke = self.cur - 1;
            self.skipWs();
            if (self.peek() != ':') return error.Malformed;
            self.cur += 1;
            self.skipWs();
            if (n >= max_object_keys) return error.Malformed;
            entries[n] = .{ .key_start = @intCast(ks), .key_len = @intCast(ke - ks), .val_start = @intCast(self.cur) };
            n += 1;
            try self.skipValue();
            self.skipWs();
            const d = self.peek() orelse return error.Malformed;
            if (d == ',') {
                self.cur += 1;
                continue;
            }
            if (d == '}') {
                self.cur += 1;
                break;
            }
            return error.Malformed;
        }
        std.sort.pdq(Entry, entries[0..n], self.src, lessKey);
        try self.emitByte('{');
        var first = true;
        var i: u32 = 0;
        while (i < n) : (i += 1) {
            const key = self.src[entries[i].key_start..][0..entries[i].key_len];
            if (exclude.len > 0 and std.mem.eql(u8, key, exclude)) continue;
            if (!first) try self.emitByte(',');
            first = false;
            try self.emitByte('"');
            try self.emit(key);
            try self.emit("\":");
            self.cur = entries[i].val_start;
            try self.value(depth + 1, ""); // exclude only applies at this level
        }
        try self.emitByte('}');
    }

    fn array(self: *Canon, depth: u32) Error!void {
        self.cur += 1; // [
        try self.emitByte('[');
        self.skipWs();
        if (self.peek() == ']') {
            self.cur += 1;
            return self.emitByte(']');
        }
        var first = true;
        while (true) {
            self.skipWs();
            if (!first) try self.emitByte(',');
            first = false;
            try self.value(depth + 1, "");
            self.skipWs();
            const d = self.peek() orelse return error.Malformed;
            if (d == ',') {
                self.cur += 1;
                continue;
            }
            if (d == ']') {
                self.cur += 1;
                break;
            }
            return error.Malformed;
        }
        try self.emitByte(']');
    }

    fn string(self: *Canon) Error!void {
        // Emit the source string token verbatim (deterministic).
        const start = self.cur;
        try self.skipString();
        try self.emit(self.src[start..self.cur]);
    }

    fn scalar(self: *Canon) Error!void {
        const start = self.cur;
        while (self.cur < self.src.len) : (self.cur += 1) switch (self.src[self.cur]) {
            ',', '}', ']', ' ', '\t', '\n', '\r' => break,
            else => {},
        };
        if (self.cur == start) return error.Malformed;
        try self.emit(self.src[start..self.cur]);
    }

    fn skipString(self: *Canon) Error!void {
        self.cur += 1; // opening quote
        while (self.cur < self.src.len) : (self.cur += 1) {
            const ch = self.src[self.cur];
            if (ch == '\\') {
                self.cur += 1;
                continue;
            }
            if (ch == '"') {
                self.cur += 1;
                return;
            }
        }
        return error.Malformed;
    }

    fn skipValue(self: *Canon) Error!void {
        self.skipWs();
        const ch = self.peek() orelse return error.Malformed;
        switch (ch) {
            '"' => try self.skipString(),
            '{', '[' => {
                var depth: u32 = 0;
                while (self.cur < self.src.len) {
                    const cc = self.src[self.cur];
                    if (cc == '"') {
                        try self.skipString();
                        continue;
                    }
                    if (cc == '{' or cc == '[') depth += 1;
                    if (cc == '}' or cc == ']') {
                        depth -= 1;
                        self.cur += 1;
                        if (depth == 0) return;
                        continue;
                    }
                    self.cur += 1;
                }
                return error.Malformed;
            },
            else => while (self.cur < self.src.len) : (self.cur += 1) switch (self.src[self.cur]) {
                ',', '}', ']', ' ', '\t', '\n', '\r' => return,
                else => {},
            },
        }
    }
};

fn lessKey(src: []const u8, a: Entry, b: Entry) bool {
    return std.mem.order(u8, src[a.key_start..][0..a.key_len], src[b.key_start..][0..b.key_len]) == .lt;
}

/// Canonicalise a JSON object, optionally omitting one top-level key.
pub fn canonicalize(json: []const u8, out: []u8, exclude_top_key: []const u8) Error![]const u8 {
    var canon = Canon{ .src = json, .out = out };
    try canon.value(0, exclude_top_key);
    return canon.out[0..canon.olen];
}

// ── Field extraction (minimal, no nesting beyond what proofs use) ────────

/// Return the `{...}` span of a top-level object field, or null.
fn objectFieldSpan(doc: []const u8, key: []const u8) ?[]const u8 {
    var needle_buf: [64]u8 = undefined;
    if (key.len + 3 > needle_buf.len) return null;
    needle_buf[0] = '"';
    @memcpy(needle_buf[1..][0..key.len], key);
    needle_buf[1 + key.len] = '"';
    const needle = needle_buf[0 .. key.len + 2];
    const at = std.mem.indexOf(u8, doc, needle) orelse return null;
    var i = at + needle.len;
    while (i < doc.len and (doc[i] == ' ' or doc[i] == ':' or doc[i] == '\t')) : (i += 1) {}
    if (i >= doc.len or doc[i] != '{') return null;
    const start = i;
    var depth: u32 = 0;
    while (i < doc.len) : (i += 1) {
        const ch = doc[i];
        if (ch == '"') {
            // skip string
            i += 1;
            while (i < doc.len) : (i += 1) {
                if (doc[i] == '\\') {
                    i += 1;
                    continue;
                }
                if (doc[i] == '"') break;
            }
            continue;
        }
        if (ch == '{') depth += 1;
        if (ch == '}') {
            depth -= 1;
            if (depth == 0) return doc[start .. i + 1];
        }
    }
    return null;
}

/// Return a top-level string field's value (no escapes), or null.
fn stringFieldValue(obj: []const u8, key: []const u8) ?[]const u8 {
    var needle_buf: [64]u8 = undefined;
    if (key.len + 4 > needle_buf.len) return null;
    needle_buf[0] = '"';
    @memcpy(needle_buf[1..][0..key.len], key);
    needle_buf[1 + key.len] = '"';
    needle_buf[2 + key.len] = ':';
    needle_buf[3 + key.len] = '"';
    const needle = needle_buf[0 .. key.len + 4];
    const at = std.mem.indexOf(u8, obj, needle) orelse return null;
    const vs = at + needle.len;
    const end = std.mem.indexOfScalarPos(u8, obj, vs, '"') orelse return null;
    return obj[vs..end];
}

// ── Verify / sign ────────────────────────────────────────────────────────

/// Compute the `eddsa-jcs-2022` signing input (cfgHash ‖ docHash) for
/// `document` (whose `proof` block is `proof_obj`). `scratch` must hold
/// two canonicalisations.
fn hashData(document: []const u8, proof_obj: []const u8, scratch: []u8) Error![64]u8 {
    const half = scratch.len / 2;
    const cdoc = try canonicalize(document, scratch[0..half], "proof");
    var doc_hash: [32]u8 = undefined;
    Sha256.hash(cdoc, &doc_hash, .{});
    const ccfg = try canonicalize(proof_obj, scratch[half..], "proofValue");
    var cfg_hash: [32]u8 = undefined;
    Sha256.hash(ccfg, &cfg_hash, .{});
    var hd: [64]u8 = undefined;
    @memcpy(hd[0..32], &cfg_hash);
    @memcpy(hd[32..64], &doc_hash);
    return hd;
}

/// Verify a Data Integrity proof on `document` against `public_key`.
/// Returns false on any malformation (never throws into the inbox path).
pub fn verify(document: []const u8, public_key: [32]u8, scratch: []u8) bool {
    const proof = objectFieldSpan(document, "proof") orelse return false;
    const pv = stringFieldValue(proof, "proofValue") orelse return false;
    if (pv.len < 2 or pv[0] != 'z') return false; // multibase base58btc
    var sig: [64]u8 = undefined;
    const n = multibase.base58btcDecode(pv[1..], &sig) catch return false;
    if (n != 64) return false;
    const hd = hashData(document, proof, scratch) catch return false;
    return ed25519.verify(public_key, &hd, sig);
}

/// Decode a `did:key:z6Mk…` verification method to its 32-byte Ed25519
/// key (FEP-8b32's common embedded-key form). Returns null for non-Ed25519
/// or non-did:key methods (which would need a fetch — a follow-up).
fn didKeyToEd25519(vm: []const u8) ?[32]u8 {
    const prefix = "did:key:z";
    if (!std.mem.startsWith(u8, vm, prefix)) return null;
    var b58 = vm[prefix.len..]; // base58 payload (after the 'z' multibase tag)
    if (std.mem.indexOfScalar(u8, b58, '#')) |h| b58 = b58[0..h];
    var raw: [40]u8 = undefined;
    const n = multibase.base58btcDecode(b58, &raw) catch return null;
    // multicodec 0xed01 prefix + 32-byte key.
    if (n != 34 or raw[0] != 0xed or raw[1] != 0x01) return null;
    var key: [32]u8 = undefined;
    @memcpy(&key, raw[2..34]);
    return key;
}

/// Verify a document's Data Integrity proof, resolving the key from the
/// proof's `verificationMethod` when it is an embedded `did:key`. Returns
/// false when the proof is absent, the VM isn't a did:key, or verification
/// fails. Used by the inbox under the `AP_LD_PROOF` flag.
pub fn verifyDocument(document: []const u8, scratch: []u8) bool {
    const proof = objectFieldSpan(document, "proof") orelse return false;
    const vm = stringFieldValue(proof, "verificationMethod") orelse return false;
    const key = didKeyToEd25519(vm) orelse return false;
    return verify(document, key, scratch);
}

/// Test/util: produce the `proofValue` (multibase base58btc) for a
/// document whose `proof` block is `proof_obj`, signing with `secret_key`.
pub fn signProofValue(document: []const u8, proof_obj: []const u8, secret_key: [64]u8, scratch: []u8, out: []u8) Error![]const u8 {
    const hd = try hashData(document, proof_obj, scratch);
    const sig = ed25519.sign(secret_key, &hd);
    if (out.len < 1) return error.BufferTooSmall;
    out[0] = 'z';
    const n = multibase.base58btcEncode(&sig, out[1..]) catch return error.BufferTooSmall;
    return out[0 .. 1 + n];
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

test "AP-21: canonicalize sorts object keys + strips whitespace" {
    var buf: [256]u8 = undefined;
    const out = try canonicalize(
        \\{ "b": 1, "a": [true, "x"], "c": {"z":1,"y":2} }
    , &buf, "");
    try testing.expectEqualStrings("{\"a\":[true,\"x\"],\"b\":1,\"c\":{\"y\":2,\"z\":1}}", out);
}

test "AP-21: canonicalize can omit a top-level key" {
    var buf: [128]u8 = undefined;
    const out = try canonicalize("{\"keep\":1,\"drop\":2}", &buf, "drop");
    try testing.expectEqualStrings("{\"keep\":1}", out);
}

test "AP-21: eddsa-jcs-2022 sign + verify round-trip" {
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x21);
    const kp = try ed25519.fromSeed(seed);

    // The document body (without proof) + a proof config (without proofValue).
    const doc_no_proof =
        \\{"@context":["https://www.w3.org/ns/activitystreams"],"id":"https://a/x/1","type":"Create","actor":"https://a/u"}
    ;
    const proof_cfg =
        \\{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","created":"2026-06-16T00:00:00Z","verificationMethod":"https://a/u#key","proofPurpose":"assertionMethod"}
    ;
    var scratch: [4096]u8 = undefined;
    var pv_buf: [128]u8 = undefined;
    const proof_value = try signProofValue(doc_no_proof, proof_cfg, kp.secret_key, &scratch, &pv_buf);

    // Assemble the signed document: insert proofValue into the proof and
    // attach the proof to the document.
    var doc_buf: [1024]u8 = undefined;
    const signed = try std.fmt.bufPrint(&doc_buf,
        "{{\"@context\":[\"https://www.w3.org/ns/activitystreams\"],\"id\":\"https://a/x/1\",\"type\":\"Create\",\"actor\":\"https://a/u\"," ++
        "\"proof\":{{\"type\":\"DataIntegrityProof\",\"cryptosuite\":\"eddsa-jcs-2022\",\"created\":\"2026-06-16T00:00:00Z\",\"verificationMethod\":\"https://a/u#key\",\"proofPurpose\":\"assertionMethod\",\"proofValue\":\"{s}\"}}}}",
        .{proof_value},
    );

    var vscratch: [4096]u8 = undefined;
    try testing.expect(verify(signed, kp.public_key, &vscratch));

    // Tamper the body → verification fails.
    var tampered_buf: [1024]u8 = undefined;
    const tampered = try std.mem.replaceOwned(u8, testing.allocator, signed, "https://a/u", "https://evil/u");
    defer testing.allocator.free(tampered);
    @memcpy(tampered_buf[0..tampered.len], tampered);
    try testing.expect(!verify(tampered_buf[0..tampered.len], kp.public_key, &vscratch));

    // Wrong key → fails.
    var seed2: [32]u8 = undefined;
    @memset(&seed2, 0x99);
    const kp2 = try ed25519.fromSeed(seed2);
    try testing.expect(!verify(signed, kp2.public_key, &vscratch));
}

test "AP-21: verifyDocument resolves a did:key verificationMethod" {
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x33);
    const kp = try ed25519.fromSeed(seed);

    // Build the did:key for this key (z + base58btc(0xed01 ‖ pubkey)).
    var mc: [34]u8 = undefined;
    mc[0] = 0xed;
    mc[1] = 0x01;
    @memcpy(mc[2..34], &kp.public_key);
    var b58: [64]u8 = undefined;
    const bn = try multibase.base58btcEncode(&mc, &b58);
    var vm_buf: [128]u8 = undefined;
    const vm = try std.fmt.bufPrint(&vm_buf, "did:key:z{s}", .{b58[0..bn]});

    const doc_no_proof = "{\"id\":\"https://a/1\",\"type\":\"Create\"}";
    var pcfg_buf: [256]u8 = undefined;
    const proof_cfg = try std.fmt.bufPrint(&pcfg_buf, "{{\"type\":\"DataIntegrityProof\",\"cryptosuite\":\"eddsa-jcs-2022\",\"verificationMethod\":\"{s}\",\"proofPurpose\":\"assertionMethod\"}}", .{vm});
    var scratch: [4096]u8 = undefined;
    var pv_buf: [128]u8 = undefined;
    const pv = try signProofValue(doc_no_proof, proof_cfg, kp.secret_key, &scratch, &pv_buf);

    var doc_buf: [1024]u8 = undefined;
    const signed = try std.fmt.bufPrint(&doc_buf, "{{\"id\":\"https://a/1\",\"type\":\"Create\",\"proof\":{{\"type\":\"DataIntegrityProof\",\"cryptosuite\":\"eddsa-jcs-2022\",\"verificationMethod\":\"{s}\",\"proofPurpose\":\"assertionMethod\",\"proofValue\":\"{s}\"}}}}", .{ vm, pv });

    var vscratch: [4096]u8 = undefined;
    try testing.expect(verifyDocument(signed, &vscratch));
}

test "AP-21: disabled by default" {
    // Without AP_LD_PROOF set, enforcement is off.
    try testing.expect(!enabled());
}
