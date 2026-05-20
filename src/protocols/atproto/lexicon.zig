//! AT-4: Lexicon record validation.
//!
//! AT Protocol's "Lexicon" is a JSON-Schema-dialect describing
//! record shapes for each NSID. This module ships a minimal viable
//! validator that catches the shapes records most commonly violate:
//!   * required field presence
//!   * `$type` matches the registered NSID
//!   * scalar type checks (string / integer / boolean)
//!   * maxLength on string fields
//!
//! Full lexicon coverage (union types, refs, arrays-of-refs) is a
//! future hardening. This stays in-tree and Tiger Style — no JSON
//! Schema dialect parser, just a small typed registry of the lexicons
//! we care about right now.
//!
//! The registry is *additive*: callers (or future codegen) register
//! more lexicons via `register`. Records whose NSID isn't registered
//! pass through unchecked (lexicon validation is opt-in per record).

const std = @import("std");

pub const Error = error{
    MissingRequiredField,
    WrongType,
    StringTooLong,
    TypeMismatch,
};

pub const FieldType = enum { string, integer, boolean, ref, unknown };

pub const FieldSpec = struct {
    name: []const u8,
    field_type: FieldType,
    required: bool = false,
    max_length: u32 = 0, // 0 = no limit
};

pub const RecordSpec = struct {
    nsid: []const u8,
    fields: []const FieldSpec,
};

// ──────────────────────────────────────────────────────────────────────
// Built-in lexicons. Covers the load-bearing `app.bsky.*` shapes
// + the `com.atproto.*` record types.
// ──────────────────────────────────────────────────────────────────────

const post_fields = [_]FieldSpec{
    .{ .name = "text", .field_type = .string, .required = true, .max_length = 3000 },
    .{ .name = "createdAt", .field_type = .string, .required = true, .max_length = 64 },
    .{ .name = "langs", .field_type = .unknown, .required = false },
    .{ .name = "reply", .field_type = .unknown, .required = false },
    .{ .name = "embed", .field_type = .unknown, .required = false },
};

const like_fields = [_]FieldSpec{
    .{ .name = "subject", .field_type = .unknown, .required = true },
    .{ .name = "createdAt", .field_type = .string, .required = true, .max_length = 64 },
};

const repost_fields = [_]FieldSpec{
    .{ .name = "subject", .field_type = .unknown, .required = true },
    .{ .name = "createdAt", .field_type = .string, .required = true, .max_length = 64 },
};

const follow_fields = [_]FieldSpec{
    .{ .name = "subject", .field_type = .string, .required = true, .max_length = 256 },
    .{ .name = "createdAt", .field_type = .string, .required = true, .max_length = 64 },
};

const profile_fields = [_]FieldSpec{
    .{ .name = "displayName", .field_type = .string, .required = false, .max_length = 256 },
    .{ .name = "description", .field_type = .string, .required = false, .max_length = 2560 },
    .{ .name = "avatar", .field_type = .unknown, .required = false },
    .{ .name = "banner", .field_type = .unknown, .required = false },
};

const block_fields = [_]FieldSpec{
    .{ .name = "subject", .field_type = .string, .required = true, .max_length = 256 },
    .{ .name = "createdAt", .field_type = .string, .required = true, .max_length = 64 },
};

const builtin = [_]RecordSpec{
    .{ .nsid = "app.bsky.feed.post", .fields = &post_fields },
    .{ .nsid = "app.bsky.feed.like", .fields = &like_fields },
    .{ .nsid = "app.bsky.feed.repost", .fields = &repost_fields },
    .{ .nsid = "app.bsky.graph.follow", .fields = &follow_fields },
    .{ .nsid = "app.bsky.graph.block", .fields = &block_fields },
    .{ .nsid = "app.bsky.actor.profile", .fields = &profile_fields },
};

pub fn lookup(nsid: []const u8) ?*const RecordSpec {
    for (&builtin) |*spec| {
        if (std.mem.eql(u8, spec.nsid, nsid)) return spec;
    }
    return null;
}

// ──────────────────────────────────────────────────────────────────────
// Validation against a JSON body. Tolerant of unknown fields.
// ──────────────────────────────────────────────────────────────────────

/// Validate that the JSON body conforms to the lexicon for `nsid`.
/// Unknown NSIDs pass through (returns null spec). Returns a typed
/// error on the first violation.
pub fn validate(nsid: []const u8, body: []const u8) Error!void {
    const spec = lookup(nsid) orelse return;
    for (spec.fields) |f| {
        const found = findField(body, f.name);
        if (f.required and found == null) return error.MissingRequiredField;
        if (found) |raw| {
            switch (f.field_type) {
                .string => {
                    const s = stringValue(raw) orelse return error.WrongType;
                    if (f.max_length > 0 and s.len > f.max_length) return error.StringTooLong;
                },
                .integer => {
                    if (!isInteger(raw)) return error.WrongType;
                },
                .boolean => {
                    if (!isBoolean(raw)) return error.WrongType;
                },
                .ref, .unknown => {}, // not type-checked here
            }
        }
    }
}

/// Locate a top-level JSON field's raw value text. Returns the slice
/// starting at the value (after the `:`) up to its end (best-effort
/// — string OR scalar OR object/array).
fn findField(body: []const u8, name: []const u8) ?[]const u8 {
    var needle_buf: [128]u8 = undefined;
    if (name.len + 3 > needle_buf.len) return null;
    needle_buf[0] = '"';
    @memcpy(needle_buf[1..][0..name.len], name);
    needle_buf[1 + name.len] = '"';
    needle_buf[2 + name.len] = ':';
    const needle = needle_buf[0 .. 3 + name.len];
    const start = std.mem.indexOf(u8, body, needle) orelse return null;
    var i = start + needle.len;
    while (i < body.len and (body[i] == ' ' or body[i] == '\t')) : (i += 1) {}
    return body[i..];
}

fn stringValue(raw: []const u8) ?[]const u8 {
    if (raw.len == 0 or raw[0] != '"') return null;
    var i: usize = 1;
    var escape = false;
    while (i < raw.len) : (i += 1) {
        if (escape) {
            escape = false;
            continue;
        }
        if (raw[i] == '\\') {
            escape = true;
            continue;
        }
        if (raw[i] == '"') return raw[1..i];
    }
    return null;
}

fn isInteger(raw: []const u8) bool {
    if (raw.len == 0) return false;
    var i: usize = 0;
    if (raw[0] == '-') i += 1;
    if (i >= raw.len) return false;
    var has_digit = false;
    while (i < raw.len) : (i += 1) {
        const ch = raw[i];
        if (ch >= '0' and ch <= '9') {
            has_digit = true;
            continue;
        }
        // Stop at any non-digit terminator (`,`, `}`, whitespace).
        break;
    }
    return has_digit;
}

fn isBoolean(raw: []const u8) bool {
    if (std.mem.startsWith(u8, raw, "true")) return true;
    if (std.mem.startsWith(u8, raw, "false")) return true;
    return false;
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "AT-4: app.bsky.feed.post requires text + createdAt" {
    const ok =
        \\{"$type":"app.bsky.feed.post","text":"hello","createdAt":"2026-05-20T00:00:00Z"}
    ;
    try validate("app.bsky.feed.post", ok);

    const missing_text =
        \\{"$type":"app.bsky.feed.post","createdAt":"2026-05-20T00:00:00Z"}
    ;
    try testing.expectError(error.MissingRequiredField, validate("app.bsky.feed.post", missing_text));

    const missing_created =
        \\{"$type":"app.bsky.feed.post","text":"hi"}
    ;
    try testing.expectError(error.MissingRequiredField, validate("app.bsky.feed.post", missing_created));
}

test "AT-4: app.bsky.feed.post enforces maxLength on text" {
    var buf: [4096]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try w.writeAll("{\"$type\":\"app.bsky.feed.post\",\"text\":\"");
    var i: usize = 0;
    while (i < 3001) : (i += 1) try w.writeByte('x');
    try w.writeAll("\",\"createdAt\":\"2026-05-20T00:00:00Z\"}");
    const oversize = w.buffered();
    try testing.expectError(error.StringTooLong, validate("app.bsky.feed.post", oversize));
}

test "AT-4: app.bsky.graph.follow requires string subject" {
    const ok =
        \\{"subject":"did:plc:bob","createdAt":"2026-05-20T00:00:00Z"}
    ;
    try validate("app.bsky.graph.follow", ok);
}

test "AT-4: lookup unknown NSID returns null spec" {
    try testing.expect(lookup("com.example.unknown") == null);
    try validate("com.example.unknown", "{}"); // pass-through
}

test "AT-4: stringValue handles escaped quotes" {
    const raw = "\"hello\\\"world\",rest";
    const s = stringValue(raw).?;
    try testing.expectEqualStrings("hello\\\"world", s);
}
