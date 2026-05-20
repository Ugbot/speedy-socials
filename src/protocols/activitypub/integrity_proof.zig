//! AP-21: Data Integrity Proofs (FEP-8b32 / W3C VC Data Integrity).
//!
//! Some peers (especially Fediverse-adjacent VC tooling) sign
//! activities with a `proof` block carrying a `DataIntegrityProof` /
//! `Multikey` proof. HTTP signatures stay the primary federation
//! signing method; this module recognises the `proof` shape so we
//! can log incoming activities that use it and choose to honour or
//! ignore the proof later.
//!
//! Recognition only — verifying the proof requires JSON-LD
//! canonicalisation (URDNA2015) which is a future tranche. We
//! return the parsed proof metadata so the inbox can audit it.

const std = @import("std");

pub const Proof = struct {
    type_buf: [64]u8 = undefined,
    type_len: u8 = 0,
    proof_purpose_buf: [64]u8 = undefined,
    proof_purpose_len: u8 = 0,
    verification_method_buf: [256]u8 = undefined,
    verification_method_len: u16 = 0,
    proof_value_buf: [256]u8 = undefined,
    proof_value_len: u16 = 0,
    created_buf: [32]u8 = undefined,
    created_len: u8 = 0,

    pub fn proofType(self: *const Proof) []const u8 {
        return self.type_buf[0..self.type_len];
    }
    pub fn proofPurpose(self: *const Proof) []const u8 {
        return self.proof_purpose_buf[0..self.proof_purpose_len];
    }
    pub fn verificationMethod(self: *const Proof) []const u8 {
        return self.verification_method_buf[0..self.verification_method_len];
    }
    pub fn proofValue(self: *const Proof) []const u8 {
        return self.proof_value_buf[0..self.proof_value_len];
    }
    pub fn created(self: *const Proof) []const u8 {
        return self.created_buf[0..self.created_len];
    }
};

pub fn extract(body: []const u8) ?Proof {
    // Locate a top-level `"proof":{...}` block.
    const needle = "\"proof\":{";
    const start = std.mem.indexOf(u8, body, needle) orelse return null;
    var p: Proof = .{};
    const obj_start = start + needle.len - 1; // include `{`
    // Find balanced end.
    var end = obj_start + 1;
    var depth: u32 = 1;
    var in_string = false;
    var escape = false;
    while (end < body.len) : (end += 1) {
        const ch = body[end];
        if (escape) {
            escape = false;
            continue;
        }
        if (in_string) {
            if (ch == '\\') escape = true;
            if (ch == '"') in_string = false;
            continue;
        }
        switch (ch) {
            '"' => in_string = true,
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if (depth == 0) break;
            },
            else => {},
        }
    }
    if (end >= body.len) return null;
    const obj = body[obj_start .. end + 1];

    copyStringField(obj, "type", &p.type_buf, &p.type_len);
    copyStringField(obj, "proofPurpose", &p.proof_purpose_buf, &p.proof_purpose_len);
    copyStringFieldU16(obj, "verificationMethod", &p.verification_method_buf, &p.verification_method_len);
    copyStringFieldU16(obj, "proofValue", &p.proof_value_buf, &p.proof_value_len);
    copyStringField(obj, "created", &p.created_buf, &p.created_len);
    return p;
}

fn copyStringField(body: []const u8, name: []const u8, buf: []u8, len_out: *u8) void {
    if (findString(body, name)) |s| {
        const cap = @min(s.len, buf.len);
        @memcpy(buf[0..cap], s[0..cap]);
        len_out.* = @intCast(cap);
    }
}

fn copyStringFieldU16(body: []const u8, name: []const u8, buf: []u8, len_out: *u16) void {
    if (findString(body, name)) |s| {
        const cap = @min(s.len, buf.len);
        @memcpy(buf[0..cap], s[0..cap]);
        len_out.* = @intCast(cap);
    }
}

fn findString(body: []const u8, name: []const u8) ?[]const u8 {
    var needle_buf: [64]u8 = undefined;
    if (name.len + 4 > needle_buf.len) return null;
    needle_buf[0] = '"';
    @memcpy(needle_buf[1..][0..name.len], name);
    needle_buf[1 + name.len] = '"';
    needle_buf[2 + name.len] = ':';
    needle_buf[3 + name.len] = '"';
    const needle = needle_buf[0 .. 4 + name.len];
    const start = std.mem.indexOf(u8, body, needle) orelse return null;
    const v_start = start + needle.len;
    const end_rel = std.mem.indexOfScalar(u8, body[v_start..], '"') orelse return null;
    return body[v_start .. v_start + end_rel];
}

const testing = std.testing;

test "AP-21: extract parses a DataIntegrityProof block" {
    const body =
        \\{"type":"Create","actor":"https://a/u","object":{},"proof":{"type":"DataIntegrityProof","proofPurpose":"assertionMethod","verificationMethod":"did:key:zABC#k1","proofValue":"z123","created":"2026-05-20T00:00:00Z"}}
    ;
    const p = extract(body).?;
    try testing.expectEqualStrings("DataIntegrityProof", p.proofType());
    try testing.expectEqualStrings("assertionMethod", p.proofPurpose());
    try testing.expectEqualStrings("did:key:zABC#k1", p.verificationMethod());
    try testing.expectEqualStrings("z123", p.proofValue());
    try testing.expectEqualStrings("2026-05-20T00:00:00Z", p.created());
}

test "AP-21: extract returns null when no proof block" {
    try testing.expect(extract("{\"type\":\"Create\"}") == null);
}
