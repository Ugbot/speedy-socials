//! RESP2/RESP3 reply object model — the typed result of parsing one Redis
//! reply off the wire. This is the *data* half of the in-tree, from-scratch
//! hiredis-equivalent client: `resp.zig` owns the byte-level codec and
//! produces values of the `Reply` union defined here.
//!
//! Lifetime / ownership (READ THIS before holding a `Reply`):
//!   - Inline scalar payloads — `status`, `err`, `int`, `bulk`, `double`,
//!     `boolean`, `big_number`, `verbatim.data`, `blob_err` — borrow the
//!     SLICE THEY WERE PARSED FROM, i.e. the caller's input buffer passed to
//!     `resp.parseReply`. They are valid only as long as that input buffer
//!     is alive and unmodified. Copy them out if you need them to outlive
//!     the read buffer.
//!   - Aggregate backing arrays — `array`, `map`, `set`, `push` — are
//!     allocated from the `arena` allocator the caller hands to
//!     `resp.parseReply`. Their *elements* are themselves `Reply`s whose
//!     inline payloads still borrow the input buffer (the arena holds only
//!     the spine, never copies of string bytes). Freeing/resetting the
//!     arena frees every aggregate spine produced by that parse.
//!
//! Tiger Style: this file declares no functions that allocate, recurse
//! unbounded, or perform I/O. The accessors are total functions over the
//! union and never fail.

const std = @import("std");

/// One key/value pair inside a RESP3 map (`%`). Both halves are full
/// replies because Redis permits arbitrary types as map keys and values.
pub const KV = struct {
    key: Reply,
    value: Reply,
};

/// A single decoded Redis reply.
///
/// RESP2 reachable variants: `status` (`+`), `err` (`-`), `int` (`:`),
/// `bulk` (`$`, with `null` for the `$-1` null bulk), `array` (`*`, with a
/// zero-length slice for `*0` and the distinct `nil` variant for the `*-1`
/// null array — see `resp.zig`).
///
/// RESP3 adds: `nil` (`_`), `double` (`,`), `boolean` (`#`), `big_number`
/// (`(`), `verbatim` (`=`), `blob_err` (`!`), `map` (`%`), `set` (`~`) and
/// `push` (`>`). The `|` attribute frame is parsed and discarded by the
/// codec (documented in `resp.zig`), so it never surfaces as a variant.
pub const Reply = union(enum) {
    /// RESP3 `_\r\n`, and the canonical decode of the RESP2 `$-1`/`*-1`
    /// null forms.
    nil,
    /// `+OK\r\n` style simple string. Borrows the input buffer.
    status: []const u8,
    /// `-ERR ...\r\n` simple error. Borrows the input buffer.
    err: []const u8,
    /// `:123\r\n` signed 64-bit integer.
    int: i64,
    /// `$<len>\r\n<bytes>\r\n` bulk string, or `null` for the `$-1` null
    /// bulk. The non-null slice borrows the input buffer.
    bulk: ?[]const u8,
    /// `,3.14\r\n` double. `inf`/`-inf`/`nan` decode to the matching f64.
    double: f64,
    /// `#t\r\n` / `#f\r\n` boolean.
    boolean: bool,
    /// `(<digits>\r\n` arbitrary-precision integer kept as its textual
    /// digits (with optional leading `-`). Borrows the input buffer.
    big_number: []const u8,
    /// `=<len>\r\n<3-char-format>:<bytes>\r\n` verbatim string. `format`
    /// is the 3-byte type tag (e.g. `txt`, `mkd`); `data` is the body
    /// AFTER the `:` separator and borrows the input buffer.
    verbatim: struct { format: [3]u8, data: []const u8 },
    /// `!<len>\r\n<bytes>\r\n` bulk error. Borrows the input buffer.
    blob_err: []const u8,
    /// `*<n>\r\n<elem>...` array. Spine from the arena; elements borrow
    /// the input buffer for their inline payloads.
    array: []Reply,
    /// `%<n>\r\n<key><val>...` map (n pairs). Spine from the arena.
    map: []KV,
    /// `~<n>\r\n<elem>...` set. Spine from the arena.
    set: []Reply,
    /// `><n>\r\n<elem>...` out-of-band push message. Spine from the arena.
    push: []Reply,

    // ── Ergonomic accessors (total, allocation-free) ──────────────────────

    /// The integer value when this reply is an `:` integer, else null.
    /// Note: does NOT coerce a numeric bulk string — that is a deliberate
    /// choice so callers can distinguish wire types.
    pub fn asInt(self: Reply) ?i64 {
        return switch (self) {
            .int => |v| v,
            else => null,
        };
    }

    /// The string bytes when this reply carries text the caller would treat
    /// as a value: a simple string (`status`) or a non-null bulk string.
    /// Returns null for every other variant (including a null bulk).
    pub fn asString(self: Reply) ?[]const u8 {
        return switch (self) {
            .status => |s| s,
            .bulk => |b| b,
            else => null,
        };
    }

    /// The error text when this reply is an error frame — either a RESP2
    /// `-` simple error or a RESP3 `!` blob error — else null. Lets callers
    /// branch on "did the server return an error?" in one check.
    pub fn isError(self: Reply) ?[]const u8 {
        return switch (self) {
            .err => |e| e,
            .blob_err => |e| e,
            else => null,
        };
    }

    /// True when this reply is the null sentinel: the RESP3 `_` null, the
    /// RESP2 `$-1` null bulk, or the RESP2 `*-1` null array (all of which
    /// the codec normalises so callers get one predicate).
    pub fn isNil(self: Reply) bool {
        return switch (self) {
            .nil => true,
            .bulk => |b| b == null,
            else => false,
        };
    }
};

// ──────────────────────────────────────────────────────────────────────
// Tests — accessor semantics over hand-built replies. The wire-level
// round-trip / incremental tests live in `resp.zig`; here we pin only the
// `Reply` accessor contract so callers can rely on it.
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "asInt: only the integer variant yields a value" {
    var prng = std.Random.DefaultPrng.init(testing.random_seed);
    const rand = prng.random();
    var i: usize = 0;
    while (i < 64) : (i += 1) {
        const v = rand.int(i64);
        const r: Reply = .{ .int = v };
        try testing.expectEqual(v, r.asInt().?);
    }
    // A bulk string that happens to look numeric is NOT coerced.
    const b: Reply = .{ .bulk = "123" };
    try testing.expect(b.asInt() == null);
    try testing.expect((Reply{ .status = "OK" }).asInt() == null);
    try testing.expect((@as(Reply, .nil)).asInt() == null);
}

test "asString: status and non-null bulk only" {
    try testing.expectEqualStrings("OK", (Reply{ .status = "OK" }).asString().?);
    try testing.expectEqualStrings("hello", (Reply{ .bulk = "hello" }).asString().?);
    // Null bulk and unrelated variants return null.
    try testing.expect((Reply{ .bulk = null }).asString() == null);
    try testing.expect((Reply{ .int = 7 }).asString() == null);
    try testing.expect((Reply{ .err = "boom" }).asString() == null);
}

test "isError: simple and blob errors" {
    try testing.expectEqualStrings("ERR x", (Reply{ .err = "ERR x" }).isError().?);
    try testing.expectEqualStrings("WRONGTYPE", (Reply{ .blob_err = "WRONGTYPE" }).isError().?);
    try testing.expect((Reply{ .status = "OK" }).isError() == null);
    try testing.expect((Reply{ .bulk = "ERR not really" }).isError() == null);
}

test "isNil: explicit nil and the null-bulk normalisation" {
    try testing.expect((@as(Reply, .nil)).isNil());
    try testing.expect((Reply{ .bulk = null }).isNil());
    try testing.expect(!(Reply{ .bulk = "" }).isNil()); // empty bulk is NOT nil
    try testing.expect(!(Reply{ .int = 0 }).isNil());
    try testing.expect(!(Reply{ .status = "" }).isNil());
}
