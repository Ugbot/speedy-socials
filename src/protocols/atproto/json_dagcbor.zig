//! AT-4: JSON → canonical DAG-CBOR.
//!
//! `com.atproto.repo.createRecord` / `putRecord` receive the record as a
//! JSON object. To produce CIDs that are reproducible across AT Protocol
//! implementations, the record must be stored as *canonical* DAG-CBOR:
//!   * map keys sorted by (length, then bytewise)
//!   * shortest-form integer encoding (handled by `dag.Encoder`)
//!   * no map/array indefinite-length forms
//!
//! This module is a bounded, allocator-free recursive-descent JSON parser
//! that emits canonical CBOR through `dag.Encoder`. It also honours the
//! AT Protocol DAG-JSON extensions: `{"$link":"<cid>"}` → a CBOR tag-42
//! CID link, and `{"$bytes":"<base64>"}` → a CBOR byte string.
//!
//! Tiger Style: fixed recursion depth, fixed per-level entry/element
//! caps, fixed scratch buffers. Object record keys are assumed
//! escape-free (lexicon field names); a backslash in a key is rejected.

const std = @import("std");
const core = @import("core");
const AtpError = core.errors.AtpError;
const dag = @import("dag_cbor.zig");
const cid_mod = @import("cid.zig");

pub const max_depth: u32 = 24;
pub const max_object_entries: u32 = 64;
pub const max_array_items: u32 = 256;
pub const max_string_bytes: usize = 8192;

/// Encode a single JSON value (typically the record object) into
/// canonical DAG-CBOR written to `out`. Returns the encoded slice.
pub fn encode(json: []const u8, out: []u8) AtpError![]const u8 {
    var enc = dag.Encoder.init(out);
    var p = Parser{ .src = json };
    try p.value(&enc, 0);
    return enc.written();
}

const Entry = struct { key_start: u32, key_len: u32, val_start: u32 };

const Parser = struct {
    src: []const u8,
    cur: usize = 0,

    fn skipWs(self: *Parser) void {
        while (self.cur < self.src.len) : (self.cur += 1) {
            switch (self.src[self.cur]) {
                ' ', '\t', '\n', '\r' => {},
                else => return,
            }
        }
    }

    fn peek(self: *Parser) ?u8 {
        if (self.cur >= self.src.len) return null;
        return self.src[self.cur];
    }

    fn value(self: *Parser, enc: *dag.Encoder, depth: u32) AtpError!void {
        if (depth > max_depth) return error.BadCbor;
        self.skipWs();
        const c = self.peek() orelse return error.BadCbor;
        switch (c) {
            '{' => try self.object(enc, depth),
            '[' => try self.array(enc, depth),
            '"' => try self.emitString(enc),
            't', 'f' => try self.boolean(enc),
            'n' => {
                try self.literalNull();
                try enc.writeNull();
            },
            else => try self.number(enc),
        }
    }

    fn emitString(self: *Parser, enc: *dag.Encoder) AtpError!void {
        var sbuf: [max_string_bytes]u8 = undefined;
        const s = try self.parseString(&sbuf);
        try enc.writeText(s);
    }

    fn object(self: *Parser, enc: *dag.Encoder, depth: u32) AtpError!void {
        if (depth >= max_depth) return error.BadCbor;
        self.cur += 1; // consume '{'
        var entries: [max_object_entries]Entry = undefined;
        var n: u32 = 0;
        self.skipWs();
        if (self.peek() == '}') {
            self.cur += 1;
            return enc.writeMapHeader(0);
        }
        while (true) {
            self.skipWs();
            if (self.peek() != '"') return error.BadCbor;
            const ks = self.cur + 1;
            try self.skipString();
            const ke = self.cur - 1; // index of the closing quote
            const key = self.src[ks..ke];
            if (std.mem.indexOfScalar(u8, key, '\\') != null) return error.BadCbor;
            self.skipWs();
            if (self.peek() != ':') return error.BadCbor;
            self.cur += 1;
            self.skipWs();
            if (n >= max_object_entries) return error.BadCbor;
            entries[n] = .{ .key_start = @intCast(ks), .key_len = @intCast(ke - ks), .val_start = @intCast(self.cur) };
            n += 1;
            try self.skipValue();
            self.skipWs();
            const d = self.peek() orelse return error.BadCbor;
            if (d == ',') {
                self.cur += 1;
                continue;
            }
            if (d == '}') {
                self.cur += 1;
                break;
            }
            return error.BadCbor;
        }

        // DAG-JSON single-key extensions.
        if (n == 1) {
            const k = self.src[entries[0].key_start..][0..entries[0].key_len];
            if (std.mem.eql(u8, k, "$link")) return self.emitLink(enc, entries[0].val_start);
            if (std.mem.eql(u8, k, "$bytes")) return self.emitBytes(enc, entries[0].val_start);
        }

        std.sort.pdq(Entry, entries[0..n], self.src, lessKey);
        try enc.writeMapHeader(n);
        var i: u32 = 0;
        while (i < n) : (i += 1) {
            const k = self.src[entries[i].key_start..][0..entries[i].key_len];
            try enc.writeText(k);
            self.cur = entries[i].val_start;
            try self.value(enc, depth + 1);
        }
    }

    fn array(self: *Parser, enc: *dag.Encoder, depth: u32) AtpError!void {
        if (depth >= max_depth) return error.BadCbor;
        self.cur += 1; // consume '['
        var starts: [max_array_items]u32 = undefined;
        var n: u32 = 0;
        self.skipWs();
        if (self.peek() == ']') {
            self.cur += 1;
            return enc.writeArrayHeader(0);
        }
        while (true) {
            self.skipWs();
            if (n >= max_array_items) return error.BadCbor;
            starts[n] = @intCast(self.cur);
            n += 1;
            try self.skipValue();
            self.skipWs();
            const d = self.peek() orelse return error.BadCbor;
            if (d == ',') {
                self.cur += 1;
                continue;
            }
            if (d == ']') {
                self.cur += 1;
                break;
            }
            return error.BadCbor;
        }
        try enc.writeArrayHeader(n);
        var i: u32 = 0;
        while (i < n) : (i += 1) {
            self.cur = starts[i];
            try self.value(enc, depth + 1);
        }
    }

    fn emitLink(self: *Parser, enc: *dag.Encoder, val_start: u32) AtpError!void {
        self.cur = val_start;
        var sbuf: [256]u8 = undefined;
        const s = try self.parseString(&sbuf);
        const cid = try cid_mod.parseString(s);
        try enc.writeCidLink(cid.raw());
    }

    fn emitBytes(self: *Parser, enc: *dag.Encoder, val_start: u32) AtpError!void {
        self.cur = val_start;
        var sbuf: [max_string_bytes]u8 = undefined;
        const s = try self.parseString(&sbuf);
        const dec = std.base64.standard_no_pad.Decoder;
        const out_len = dec.calcSizeForSlice(s) catch return error.BadCbor;
        var out: [max_string_bytes]u8 = undefined;
        if (out_len > out.len) return error.BufferTooSmall;
        dec.decode(out[0..out_len], s) catch return error.BadCbor;
        try enc.writeBytesValue(out[0..out_len]);
    }

    fn number(self: *Parser, enc: *dag.Encoder) AtpError!void {
        const start = self.cur;
        var is_float = false;
        while (self.cur < self.src.len) : (self.cur += 1) {
            switch (self.src[self.cur]) {
                '0'...'9', '-', '+' => {},
                '.', 'e', 'E' => is_float = true,
                else => break,
            }
        }
        const tok = self.src[start..self.cur];
        if (tok.len == 0) return error.BadCbor;
        if (is_float) {
            const f = std.fmt.parseFloat(f64, tok) catch return error.BadCbor;
            try enc.writeFloat64(f);
        } else {
            const v = std.fmt.parseInt(i64, tok, 10) catch return error.BadCbor;
            try enc.writeInt(v);
        }
    }

    fn boolean(self: *Parser, enc: *dag.Encoder) AtpError!void {
        if (std.mem.startsWith(u8, self.src[self.cur..], "true")) {
            self.cur += 4;
            return enc.writeBool(true);
        }
        if (std.mem.startsWith(u8, self.src[self.cur..], "false")) {
            self.cur += 5;
            return enc.writeBool(false);
        }
        return error.BadCbor;
    }

    fn literalNull(self: *Parser) AtpError!void {
        if (!std.mem.startsWith(u8, self.src[self.cur..], "null")) return error.BadCbor;
        self.cur += 4;
    }

    /// Advance `cur` past one JSON value without decoding it.
    fn skipValue(self: *Parser) AtpError!void {
        self.skipWs();
        const c = self.peek() orelse return error.BadCbor;
        switch (c) {
            '"' => try self.skipString(),
            '{', '[' => {
                var depth: u32 = 0;
                while (self.cur < self.src.len) {
                    const ch = self.src[self.cur];
                    if (ch == '"') {
                        try self.skipString();
                        continue;
                    }
                    if (ch == '{' or ch == '[') depth += 1;
                    if (ch == '}' or ch == ']') {
                        depth -= 1;
                        self.cur += 1;
                        if (depth == 0) return;
                        continue;
                    }
                    self.cur += 1;
                }
                return error.BadCbor;
            },
            else => {
                while (self.cur < self.src.len) : (self.cur += 1) {
                    switch (self.src[self.cur]) {
                        ',', '}', ']', ' ', '\t', '\n', '\r' => return,
                        else => {},
                    }
                }
            },
        }
    }

    /// Skip a JSON string (cur at opening quote → just past closing quote).
    fn skipString(self: *Parser) AtpError!void {
        self.cur += 1;
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
        return error.BadCbor;
    }

    /// Parse + unescape a JSON string into `out` (cur at opening quote).
    fn parseString(self: *Parser, out: []u8) AtpError![]const u8 {
        if (self.peek() != '"') return error.BadCbor;
        self.cur += 1;
        var o: usize = 0;
        while (self.cur < self.src.len) {
            const ch = self.src[self.cur];
            if (ch == '"') {
                self.cur += 1;
                return out[0..o];
            }
            if (ch == '\\') {
                self.cur += 1;
                if (self.cur >= self.src.len) return error.BadCbor;
                const e = self.src[self.cur];
                self.cur += 1;
                if (e == 'u') {
                    const cp = try self.readUnicodeEscape();
                    var tmp: [4]u8 = undefined;
                    const len = std.unicode.utf8Encode(cp, &tmp) catch return error.BadCbor;
                    if (o + len > out.len) return error.BufferTooSmall;
                    @memcpy(out[o..][0..len], tmp[0..len]);
                    o += len;
                    continue;
                }
                const decoded: u8 = switch (e) {
                    '"' => '"',
                    '\\' => '\\',
                    '/' => '/',
                    'b' => 0x08,
                    'f' => 0x0C,
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    else => return error.BadCbor,
                };
                if (o >= out.len) return error.BufferTooSmall;
                out[o] = decoded;
                o += 1;
                continue;
            }
            if (o >= out.len) return error.BufferTooSmall;
            out[o] = ch;
            o += 1;
            self.cur += 1;
        }
        return error.BadCbor;
    }

    fn readUnicodeEscape(self: *Parser) AtpError!u21 {
        const hi = try self.read4Hex();
        if (hi >= 0xD800 and hi <= 0xDBFF) {
            if (self.cur + 2 > self.src.len or self.src[self.cur] != '\\' or self.src[self.cur + 1] != 'u') return error.BadCbor;
            self.cur += 2;
            const lo = try self.read4Hex();
            if (lo < 0xDC00 or lo > 0xDFFF) return error.BadCbor;
            const cp: u21 = 0x10000 + (@as(u21, hi - 0xD800) << 10) + @as(u21, lo - 0xDC00);
            return cp;
        }
        return @intCast(hi);
    }

    fn read4Hex(self: *Parser) AtpError!u16 {
        if (self.cur + 4 > self.src.len) return error.BadCbor;
        var v: u16 = 0;
        var i: usize = 0;
        while (i < 4) : (i += 1) {
            const c = self.src[self.cur];
            self.cur += 1;
            const d: u16 = switch (c) {
                '0'...'9' => c - '0',
                'a'...'f' => @as(u16, c - 'a') + 10,
                'A'...'F' => @as(u16, c - 'A') + 10,
                else => return error.BadCbor,
            };
            v = v * 16 + d;
        }
        return v;
    }
};

fn lessKey(src: []const u8, a: Entry, b: Entry) bool {
    const ka = src[a.key_start..][0..a.key_len];
    const kb = src[b.key_start..][0..b.key_len];
    if (ka.len != kb.len) return ka.len < kb.len;
    return std.mem.order(u8, ka, kb) == .lt;
}

// ── Tests ──────────────────────────────────────────────────────────

const testing = std.testing;

test "AT-4: encodes scalars + nested object with sorted keys" {
    var buf: [512]u8 = undefined;
    // Keys deliberately out of canonical order in the JSON.
    const out = try encode(
        \\{"text":"hi","createdAt":"2026-06-15T00:00:00Z","$type":"app.bsky.feed.post"}
    , &buf);
    // First byte: map header with 3 pairs → major type 5 (0xA0 | 3) = 0xA3.
    try testing.expectEqual(@as(u8, 0xA3), out[0]);
    // Canonical key order is length-then-lex: "text"(4) < "$type"(5) < "createdAt"(9).
    const i_text = std.mem.indexOf(u8, out, "text").?;
    const i_type = std.mem.indexOf(u8, out, "$type").?;
    const i_created = std.mem.indexOf(u8, out, "createdAt").?;
    try testing.expect(i_text < i_type);
    try testing.expect(i_type < i_created);
}

test "AT-4: reproducible CID regardless of JSON key order / whitespace" {
    var b1: [512]u8 = undefined;
    var b2: [512]u8 = undefined;
    const a = try encode(
        \\{"a":1,"b":[true,false,null],"c":{"x":"y"}}
    , &b1);
    const b = try encode(
        \\{  "c" : { "x" : "y" } , "b":[true,  false, null], "a": 1 }
    , &b2);
    // Structurally-equal records must produce byte-identical canonical
    // CBOR → identical CIDs.
    const cid_a = cid_mod.computeDagCbor(a);
    const cid_b = cid_mod.computeDagCbor(b);
    try testing.expectEqualSlices(u8, cid_a.raw(), cid_b.raw());
}

test "AT-4: integers use canonical shortest form" {
    var buf: [64]u8 = undefined;
    const out = try encode("{\"n\":23}", &buf);
    // map(1): 0xA1, key "n": 0x61 'n', value 23 → single byte 0x17.
    try testing.expectEqual(@as(u8, 0xA1), out[0]);
    try testing.expectEqual(@as(u8, 0x17), out[out.len - 1]);
}

test "AT-4: rejects malformed json" {
    var buf: [64]u8 = undefined;
    try testing.expectError(error.BadCbor, encode("{\"a\":}", &buf));
    try testing.expectError(error.BadCbor, encode("{unquoted:1}", &buf));
}

test "AT-4: unicode escape is decoded to utf-8" {
    var buf: [64]u8 = undefined;
    const out = try encode("{\"e\":\"\\u00e9\"}", &buf); // é
    // The UTF-8 bytes 0xC3 0xA9 must appear in the encoded text value.
    try testing.expect(std.mem.indexOf(u8, out, &[_]u8{ 0xC3, 0xA9 }) != null);
}
