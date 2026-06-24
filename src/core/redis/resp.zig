//! Pure-Zig RESP2/RESP3 wire codec — the byte-level half of the in-tree,
//! from-scratch hiredis-equivalent Redis/Valkey client. NO sockets, NO
//! connection, NO pool: every function here is a total function over byte
//! slices with no I/O and no global state, exactly like the MySQL codec in
//! `../storage/mysql/protocol.zig`.
//!
//! Two responsibilities:
//!
//!   1. `encodeCommand` — serialise a command as the canonical RESP request
//!      (an array of bulk strings: `*<argc>\r\n` then `$<len>\r\n<bytes>\r\n`
//!      per argument). Zero allocation; writes into a caller buffer.
//!
//!   2. `parseReply` — the hiredis *reader model*. Given a buffer that may
//!      hold a partial OR complete reply, it parses EXACTLY ONE complete
//!      reply or reports `.incomplete` (NOT an error) when more bytes are
//!      needed. On a complete parse it returns the decoded `Reply` plus the
//!      exact `consumed` byte count so the caller can advance its read
//!      buffer and re-enter for the next reply.
//!
//! Incomplete vs error:
//!   - `.incomplete` means the bytes so far are a valid PREFIX of some
//!     reply but the reply is not yet whole (truncated header, a header
//!     line missing its trailing CRLF, a bulk/verbatim body shorter than
//!     its declared length, or an aggregate whose children are not all
//!     present). The stream is still byte-aligned; the caller reads more.
//!   - A real `Error` (`Protocol`, `TooDeep`, `TooLarge`, `BadLength`)
//!     means the bytes are malformed or exceed a configured limit. Use
//!     `isResumable` to learn whether the connection is still usable.
//!
//! Tiger Style: the encoder and the scalar decode path allocate nothing and
//! recurse not at all. Aggregate (array/map/set/push) decoding uses the
//! CALLER-PROVIDED `arena` allocator for the element spine only — never for
//! string bytes, which always borrow `input`. Aggregates are bounded by an
//! explicit `Limits` struct (max nesting depth, max element count, max bulk
//! length) with `std.debug.assert` on invariants and explicit
//! `error.TooDeep` / `error.TooLarge` on violation. Recursion depth is
//! hard-capped by `Limits.max_depth` (≤ `max_depth_ceiling`) and asserted
//! on every descent, so the call stack is bounded by a compile-time-ish
//! constant rather than attacker-controlled input.

const std = @import("std");
const reply = @import("reply.zig");

pub const Reply = reply.Reply;
pub const KV = reply.KV;

// ──────────────────────────────────────────────────────────────────────
// Errors.
// ──────────────────────────────────────────────────────────────────────

pub const Error = error{
    /// A malformed frame: bad type byte, a header line that is not a valid
    /// integer/float where one is required, a missing/!= CRLF terminator on
    /// a body of known length, or a structurally impossible value. After
    /// this the byte stream can no longer be re-synchronised → NOT resumable.
    Protocol,
    /// Aggregate nesting exceeded `Limits.max_depth`. The framing is intact
    /// but we refuse to descend further → NOT resumable (we stopped mid-frame).
    TooDeep,
    /// An aggregate declared more elements than `Limits.max_elements`, or a
    /// bulk/verbatim declared more bytes than `Limits.max_bulk_bytes`. The
    /// declared length itself parsed fine but is over budget → NOT resumable.
    TooLarge,
    /// A length/count header carried a negative value the spec does not
    /// allow for that type, or a non-canonical null marker → NOT resumable.
    BadLength,
    /// `encodeCommand`: more arguments than `max_args`.
    TooManyArgs,
    /// `encodeCommand`: the destination buffer cannot hold the request.
    BufferTooSmall,
};

/// Returns true when, after `err`, the protocol byte stream is still known
/// to be byte-aligned so a connection could be reused. Mirrors the
/// resumable/fatal split the MySQL + Redis drivers use elsewhere. Every
/// decode error here happens MID-frame (we stop without knowing the frame's
/// true length), so none of them leave the stream re-synchronisable: the
/// honest answer is `false` for all of them. The `encodeCommand`-only
/// errors never touch a live stream, so they are reported `false` too (a
/// caller should never ask `isResumable` about them).
pub fn isResumable(err: Error) bool {
    return switch (err) {
        // No decode error leaves the stream aligned: once we hit a bad or
        // over-limit frame we no longer know where the next reply starts.
        error.Protocol, error.TooDeep, error.TooLarge, error.BadLength => false,
        // Encoder errors are not stream errors at all.
        error.TooManyArgs, error.BufferTooSmall => false,
    };
}

// ──────────────────────────────────────────────────────────────────────
// Encoder — `*argc\r\n` then `$len\r\n<bytes>\r\n` per arg. Zero alloc.
// ──────────────────────────────────────────────────────────────────────

/// Upper bound on the number of arguments a single command may carry. A
/// Redis command is `command-name` + its operands; 256 is comfortably above
/// any real command while keeping the count a small, bounded value.
pub const max_args: usize = 256;

/// Encode `args` (argv[0] is the command name) as a RESP request into `buf`
/// and return the written prefix slice. Zero allocation; never reads past
/// `args.len`. Fails with `TooManyArgs` above `max_args` and
/// `BufferTooSmall` if `buf` cannot hold the full request.
pub fn encodeCommand(buf: []u8, args: []const []const u8) Error![]const u8 {
    if (args.len > max_args) return error.TooManyArgs;
    var w = Cursor{ .buf = buf };
    // Header: array-of-bulk-strings count.
    try w.byte('*');
    try w.uint(args.len);
    try w.crlf();
    for (args) |a| {
        try w.byte('$');
        try w.uint(a.len);
        try w.crlf();
        try w.bytes(a);
        try w.crlf();
    }
    return w.written();
}

/// A bounds-checked forward write cursor into a caller-owned buffer. All
/// failures are `BufferTooSmall`; it never writes out of bounds.
const Cursor = struct {
    buf: []u8,
    pos: usize = 0,

    fn written(self: *const Cursor) []const u8 {
        return self.buf[0..self.pos];
    }

    fn byte(self: *Cursor, b: u8) Error!void {
        if (self.pos >= self.buf.len) return error.BufferTooSmall;
        self.buf[self.pos] = b;
        self.pos += 1;
    }

    fn bytes(self: *Cursor, s: []const u8) Error!void {
        if (self.pos + s.len > self.buf.len) return error.BufferTooSmall;
        @memcpy(self.buf[self.pos .. self.pos + s.len], s);
        self.pos += s.len;
    }

    fn crlf(self: *Cursor) Error!void {
        try self.byte('\r');
        try self.byte('\n');
    }

    /// Write `v` in decimal (no allocation; a fixed 20-byte scratch covers
    /// the full u64 range). `usize` ≤ u64 on every target we build for.
    fn uint(self: *Cursor, v: usize) Error!void {
        var tmp: [20]u8 = undefined;
        var n: usize = 0;
        var x = v;
        if (x == 0) {
            try self.byte('0');
            return;
        }
        // Emit least-significant digit first into `tmp`, then reverse.
        while (x != 0) {
            tmp[n] = @intCast('0' + (x % 10));
            x /= 10;
            n += 1;
        }
        std.debug.assert(n <= tmp.len);
        var i: usize = n;
        while (i > 0) {
            i -= 1;
            try self.byte(tmp[i]);
        }
    }
};

// ──────────────────────────────────────────────────────────────────────
// Decoder — the hiredis incremental reader model.
// ──────────────────────────────────────────────────────────────────────

/// Decode budget. Aggregates are bounded on three independent axes so a
/// hostile or buggy server cannot drive unbounded recursion, allocation, or
/// memory pinning. Defaults mirror the task spec.
pub const Limits = struct {
    /// Maximum aggregate nesting depth (an array-of-arrays is depth 2…).
    /// Hard-capped at `max_depth_ceiling`; values above it are clamped by
    /// the assert so the C stack stays bounded.
    max_depth: u8 = 16,
    /// Maximum element count across a SINGLE aggregate header (for a map,
    /// the child count is 2× the pair count, and the 2× is what is bounded).
    max_elements: u32 = 1 << 20,
    /// Maximum byte length of a single bulk string / verbatim / blob error.
    max_bulk_bytes: usize = 512 * 1024 * 1024,
};

/// Absolute ceiling on `Limits.max_depth`, independent of caller config.
/// The recursive decoder asserts `depth <= max_depth_ceiling` on entry so
/// the native call stack is bounded by a compile-time constant regardless
/// of what a caller (or a bug) puts in `Limits.max_depth`.
pub const max_depth_ceiling: u8 = 64;

/// The outcome of attempting to parse ONE reply from a byte buffer.
pub const ParseResult = union(enum) {
    /// The buffer is a valid prefix but does not yet hold a whole reply.
    /// The caller should read more bytes and call again with the (grown)
    /// buffer. NOT an error — the stream is still aligned.
    incomplete,
    /// Exactly one reply was decoded. `consumed` is the number of leading
    /// bytes of `input` the reply occupied; the caller advances its buffer
    /// by that many bytes before parsing the next reply.
    complete: struct {
        reply: Reply,
        consumed: usize,
    },
};

/// Parse exactly one RESP2/RESP3 reply from the front of `input`.
///
/// Returns `.incomplete` when more bytes are needed (see module docs),
/// `.complete` with the decoded reply + consumed byte count on success, or
/// an `Error` on malformed / over-limit data.
///
/// `arena` backs ONLY aggregate element spines (array/map/set/push). Inline
/// scalar payloads always borrow `input`; see `reply.zig` for the full
/// lifetime contract. Pass a per-reply arena so a single `reset` reclaims
/// everything an aggregate allocated.
pub fn parseReply(arena: std.mem.Allocator, input: []const u8, opts: Limits) Error!ParseResult {
    std.debug.assert(opts.max_depth <= max_depth_ceiling);
    var d = Decoder{ .arena = arena, .input = input, .opts = opts };
    const r = (try d.parseOne(0)) orelse return .incomplete;
    std.debug.assert(d.pos <= input.len);
    return .{ .complete = .{ .reply = r, .consumed = d.pos } };
}

/// Internal decode state: a forward cursor over `input` plus the budget.
const Decoder = struct {
    arena: std.mem.Allocator,
    input: []const u8,
    pos: usize = 0,
    opts: Limits,

    /// Bytes still unread.
    fn remaining(self: *const Decoder) usize {
        return self.input.len - self.pos;
    }

    /// Parse one reply starting at the cursor. Returns null (and leaves
    /// `self.pos` unchanged from the caller's perspective — see callers)
    /// when the buffer does not yet hold a whole reply. `depth` is the
    /// current nesting level; 0 at the top.
    fn parseOne(self: *Decoder, depth: u8) Error!?Reply {
        // Tiger Style: hard depth cap, asserted, independent of caller cfg.
        std.debug.assert(depth <= max_depth_ceiling);
        if (depth > self.opts.max_depth) return error.TooDeep;

        if (self.remaining() == 0) return null; // need the type byte
        const type_byte = self.input[self.pos];

        return switch (type_byte) {
            '+' => self.parseLineString(.status),
            '-' => self.parseLineString(.err),
            ':' => self.parseInteger(),
            '$' => self.parseBulk(.normal),
            '*' => self.parseAggregate(.array, depth),
            // RESP3 additions.
            '_' => self.parseNull(),
            ',' => self.parseDouble(),
            '#' => self.parseBoolean(),
            '(' => self.parseBigNumber(),
            '=' => self.parseBulk(.verbatim),
            '!' => self.parseBulk(.blob_err),
            '%' => self.parseAggregate(.map, depth),
            '~' => self.parseAggregate(.set, depth),
            '>' => self.parseAggregate(.push, depth),
            // RESP3 attribute frame: `|<n>\r\n` map-shaped metadata that
            // PRECEDES the real reply. We parse and DISCARD it (attributes
            // are advisory; surfacing them is out of scope for this codec),
            // then return the following real reply. Documented behaviour.
            '|' => self.parseAttributeThenValue(depth),
            else => error.Protocol, // unknown type byte → cannot resync
        };
    }

    /// `+...\r\n` / `-...\r\n`: the line content (minus CRLF) borrowed from
    /// `input`. `which` selects the resulting `Reply` variant.
    fn parseLineString(self: *Decoder, comptime which: enum { status, err }) Error!?Reply {
        // Skip the type byte only after we know the whole line is present.
        const body = (try self.takeLineAfterPrefix()) orelse return null;
        return switch (which) {
            .status => .{ .status = body },
            .err => .{ .err = body },
        };
    }

    /// `:<int>\r\n` → `Reply.int`.
    fn parseInteger(self: *Decoder) Error!?Reply {
        const body = (try self.takeLineAfterPrefix()) orelse return null;
        const v = parseI64(body) orelse return error.Protocol;
        return .{ .int = v };
    }

    /// `_\r\n` → `Reply.nil`. The line body MUST be empty.
    fn parseNull(self: *Decoder) Error!?Reply {
        const body = (try self.takeLineAfterPrefix()) orelse return null;
        if (body.len != 0) return error.Protocol;
        return .nil;
    }

    /// `,<double>\r\n` → `Reply.double`. Accepts `inf`, `-inf`, `nan`
    /// (case-insensitively) per RESP3, plus standard decimal/exponent forms.
    fn parseDouble(self: *Decoder) Error!?Reply {
        const body = (try self.takeLineAfterPrefix()) orelse return null;
        const v = parseDoubleBody(body) orelse return error.Protocol;
        return .{ .double = v };
    }

    /// `#t\r\n` / `#f\r\n` → `Reply.boolean`.
    fn parseBoolean(self: *Decoder) Error!?Reply {
        const body = (try self.takeLineAfterPrefix()) orelse return null;
        if (body.len != 1) return error.Protocol;
        return switch (body[0]) {
            't' => .{ .boolean = true },
            'f' => .{ .boolean = false },
            else => error.Protocol,
        };
    }

    /// `(<digits>\r\n` → `Reply.big_number`. We keep the textual digits
    /// (validated to be an optional sign followed by ≥1 decimal digits)
    /// rather than trying to fit an arbitrary-precision value into i64.
    fn parseBigNumber(self: *Decoder) Error!?Reply {
        const body = (try self.takeLineAfterPrefix()) orelse return null;
        if (!isBigNumberText(body)) return error.Protocol;
        return .{ .big_number = body };
    }

    const BulkKind = enum { normal, verbatim, blob_err };

    /// Length-prefixed bodies: `$`, `=`, `!`. Shape is
    /// `<prefix><len>\r\n<len bytes>\r\n`. `$-1\r\n` is the null bulk
    /// (`normal` only). Verbatim bodies additionally carry a leading
    /// `xxx:` 3-char format tag inside the counted bytes.
    fn parseBulk(self: *Decoder, comptime kind: BulkKind) Error!?Reply {
        const save = self.pos;
        const body = (try self.takeLineAfterPrefix()) orelse return null;

        // Null bulk: only `$-1` is canonical. RESP3 prefers `_` for null,
        // but `$-1` remains valid on a RESP2 connection.
        if (kind == .normal and isMinusOne(body)) {
            return .{ .bulk = null };
        }

        const len = parseLen(body) orelse {
            self.pos = save; // restore for caller hygiene on error
            return error.BadLength;
        };
        if (len > self.opts.max_bulk_bytes) return error.TooLarge;

        // Need `len` body bytes plus the trailing CRLF.
        if (self.remaining() < len + 2) {
            self.pos = save; // rewind: we have NOT consumed a whole frame
            return null; // incomplete
        }
        const data = self.input[self.pos .. self.pos + len];
        // Trailing CRLF is mandatory and must match exactly.
        if (self.input[self.pos + len] != '\r' or self.input[self.pos + len + 1] != '\n') {
            return error.Protocol;
        }
        self.pos += len + 2;

        return switch (kind) {
            .normal => .{ .bulk = data },
            .blob_err => .{ .blob_err = data },
            .verbatim => blk: {
                // RESP3 verbatim: first 3 bytes are the format tag, byte 3
                // is a ':' separator, the rest is the payload.
                if (data.len < 4 or data[3] != ':') return error.Protocol;
                const fmt: [3]u8 = .{ data[0], data[1], data[2] };
                break :blk .{ .verbatim = .{ .format = fmt, .data = data[4..] } };
            },
        };
    }

    const AggKind = enum { array, map, set, push };

    /// Aggregate headers: `*`, `%`, `~`, `>`. Shape is `<prefix><n>\r\n`
    /// followed by the child elements. For a map `n` is the PAIR count and
    /// the child count is `2*n`. `*-1\r\n` is the null array → `Reply.nil`.
    ///
    /// Decoding is recursive but bounded: `depth+1` is asserted against the
    /// hard ceiling and checked against `opts.max_depth` on entry to each
    /// child via `parseOne`. The element count is checked against
    /// `opts.max_elements` BEFORE any allocation.
    fn parseAggregate(self: *Decoder, comptime kind: AggKind, depth: u8) Error!?Reply {
        const save = self.pos;
        const body = (try self.takeLineAfterPrefix()) orelse return null;

        // Null array (`*-1`) — RESP2 form, normalised to nil.
        if (kind == .array and isMinusOne(body)) {
            return .nil;
        }

        const declared = parseLen(body) orelse {
            self.pos = save;
            return error.BadLength;
        };

        // Child element count: maps carry 2 children per declared pair.
        const child_count: usize = switch (kind) {
            .map => blk: {
                // Guard the 2× against overflow before comparing the budget.
                if (declared > self.opts.max_elements) return error.TooLarge;
                break :blk declared * 2;
            },
            else => declared,
        };
        if (child_count > self.opts.max_elements) return error.TooLarge;

        // Parse children into a temporary arena-backed buffer. If ANY child
        // is incomplete we must report the WHOLE aggregate incomplete and
        // rewind to `save` so the caller retries the entire frame once more
        // bytes arrive (the reader model is restart-from-frame-start).
        switch (kind) {
            .map => {
                const pairs = self.arena.alloc(KV, declared) catch return error.TooLarge;
                var i: usize = 0;
                while (i < declared) : (i += 1) {
                    const k = (try self.parseOne(depth + 1)) orelse {
                        self.pos = save;
                        return null;
                    };
                    const v = (try self.parseOne(depth + 1)) orelse {
                        self.pos = save;
                        return null;
                    };
                    pairs[i] = .{ .key = k, .value = v };
                }
                return .{ .map = pairs };
            },
            else => {
                const elems = self.arena.alloc(Reply, declared) catch return error.TooLarge;
                var i: usize = 0;
                while (i < declared) : (i += 1) {
                    const e = (try self.parseOne(depth + 1)) orelse {
                        self.pos = save;
                        return null;
                    };
                    elems[i] = e;
                }
                return switch (kind) {
                    .array => .{ .array = elems },
                    .set => .{ .set = elems },
                    .push => .{ .push = elems },
                    .map => unreachable,
                };
            },
        }
    }

    /// `|<n>\r\n <2n entries>` attribute frame, then the actual reply. We
    /// decode the attribute map purely to advance the cursor past it, then
    /// return the following value. If either the attribute frame or the
    /// trailing value is incomplete we rewind to the frame start and report
    /// incomplete (the whole `|…value` is one logical frame to the caller).
    fn parseAttributeThenValue(self: *Decoder, depth: u8) Error!?Reply {
        const save = self.pos;
        // Reuse the map machinery to consume `|<n>\r\n` + 2n entries. The
        // returned map value is discarded; only the cursor advance matters.
        const attr = (try self.parseAggregate(.map, depth)) orelse {
            self.pos = save;
            return null;
        };
        std.debug.assert(attr == .map); // `|` always decodes map-shaped
        // The real reply follows immediately at the SAME depth.
        const value = (try self.parseOne(depth)) orelse {
            self.pos = save;
            return null;
        };
        return value;
    }

    /// Consume the type-byte-prefixed line starting at `self.pos`: returns
    /// the body between the prefix and the CRLF (borrowing `input`) and
    /// advances `self.pos` past the CRLF. Returns null (cursor unchanged)
    /// when the whole line is not yet present. Used by every line-shaped
    /// type (`+ - : _ , # ( $ = ! * % ~ > |` headers).
    fn takeLineAfterPrefix(self: *Decoder) Error!?[]const u8 {
        std.debug.assert(self.remaining() >= 1); // type byte present
        // Look for the CRLF that ends the line, starting AFTER the prefix.
        const content_start = self.pos + 1;
        var i = content_start;
        while (i < self.input.len) : (i += 1) {
            const c = self.input[i];
            if (c == '\r') {
                if (i + 1 >= self.input.len) return null; // need '\n'
                if (self.input[i + 1] != '\n') return error.Protocol;
                const body = self.input[content_start..i];
                self.pos = i + 2; // past CRLF
                return body;
            }
            if (c == '\n') return error.Protocol; // bare LF illegal
        }
        return null; // no terminator yet
    }
};

// ──────────────────────────────────────────────────────────────────────
// Scalar text parsers — total functions over a line body, no allocation.
// ──────────────────────────────────────────────────────────────────────

/// True iff `s` is exactly "-1" (the canonical null length marker).
fn isMinusOne(s: []const u8) bool {
    return s.len == 2 and s[0] == '-' and s[1] == '1';
}

/// Parse a non-negative length header (`$`, `=`, `!`, `*`, `%`, `~`, `>`).
/// Rejects empty, signs, and non-digits. Returns null on any of those so
/// the caller maps it to `error.BadLength`. Overflow of usize also → null.
fn parseLen(s: []const u8) ?usize {
    if (s.len == 0) return null;
    var v: usize = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        const digit: usize = c - '0';
        // Bounded multiply/add with explicit overflow check.
        const mul = std.math.mul(usize, v, 10) catch return null;
        v = std.math.add(usize, mul, digit) catch return null;
    }
    return v;
}

/// Parse a signed 64-bit integer (`:` body). Accepts an optional leading
/// `-`/`+`, requires ≥1 digit, rejects overflow. Returns null on malformed.
fn parseI64(s: []const u8) ?i64 {
    if (s.len == 0) return null;
    var i: usize = 0;
    var neg = false;
    if (s[0] == '-' or s[0] == '+') {
        neg = s[0] == '-';
        i = 1;
        if (s.len == 1) return null; // sign with no digits
    }
    var v: i64 = 0;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (c < '0' or c > '9') return null;
        const digit: i64 = c - '0';
        v = std.math.mul(i64, v, 10) catch return null;
        // Accumulate in the correct sign to use the full i64 range
        // (including the most-negative value).
        v = if (neg)
            (std.math.sub(i64, v, digit) catch return null)
        else
            (std.math.add(i64, v, digit) catch return null);
    }
    return v;
}

/// True iff `s` is a valid RESP3 big-number literal: an optional `-`/`+`
/// sign followed by ≥1 decimal digits. We keep the text, so we only
/// validate the shape (no overflow concern — it is arbitrary precision).
fn isBigNumberText(s: []const u8) bool {
    if (s.len == 0) return false;
    var i: usize = 0;
    if (s[0] == '-' or s[0] == '+') {
        i = 1;
        if (s.len == 1) return false;
    }
    while (i < s.len) : (i += 1) {
        if (s[i] < '0' or s[i] > '9') return false;
    }
    return true;
}

/// Parse a RESP3 double body. Handles the special tokens `inf`, `-inf`,
/// `+inf`, `nan` (any case) per spec, otherwise defers to the std float
/// parser for decimal / exponent forms. Returns null on malformed.
fn parseDoubleBody(s: []const u8) ?f64 {
    if (s.len == 0) return null;
    if (eqIgnoreCase(s, "inf") or eqIgnoreCase(s, "+inf")) return std.math.inf(f64);
    if (eqIgnoreCase(s, "-inf")) return -std.math.inf(f64);
    if (eqIgnoreCase(s, "nan") or eqIgnoreCase(s, "-nan") or eqIgnoreCase(s, "+nan")) {
        return std.math.nan(f64);
    }
    return std.fmt.parseFloat(f64, s) catch null;
}

fn eqIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (std.ascii.toLower(x) != std.ascii.toLower(y)) return false;
    }
    return true;
}

// ──────────────────────────────────────────────────────────────────────
// Tests — randomized round-trips, full type coverage, the incremental
// reader-model property, and malformed/over-limit rejection. No live
// server; everything is pure byte slices. `std.testing.allocator` is used
// as the arena so aggregate-spine leaks are caught.
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;

// Pull the reply-model tests into this file's build unit too, so building
// resp.zig in isolation exercises both files.
test {
    _ = reply;
}

test "encodeCommand: round-trips by independent re-derivation, random argv" {
    var prng = std.Random.DefaultPrng.init(testing.random_seed);
    const rand = prng.random();

    var iter: usize = 0;
    while (iter < 200) : (iter += 1) {
        const argc = rand.intRangeAtMost(usize, 1, 8);
        var args_storage: [8][]const u8 = undefined;
        // Each arg gets random bytes INCLUDING \r \n NUL and zero-length.
        var arg_bufs: [8][32]u8 = undefined;
        for (0..argc) |i| {
            const len = rand.intRangeAtMost(usize, 0, 32);
            for (0..len) |j| arg_bufs[i][j] = rand.int(u8);
            args_storage[i] = arg_bufs[i][0..len];
        }
        const args = args_storage[0..argc];

        var buf: [4096]u8 = undefined;
        const out = try encodeCommand(&buf, args);

        // Re-derive the expected bytes independently with std.fmt.
        var expected: std.ArrayListUnmanaged(u8) = .empty;
        defer expected.deinit(testing.allocator);
        try expected.print(testing.allocator, "*{d}\r\n", .{argc});
        for (args) |a| {
            try expected.print(testing.allocator, "${d}\r\n", .{a.len});
            try expected.appendSlice(testing.allocator, a);
            try expected.appendSlice(testing.allocator, "\r\n");
        }
        try testing.expectEqualSlices(u8, expected.items, out);

        // And the encoded request must parse back as an array of bulk
        // strings whose contents match argv exactly.
        const res = try parseReply(testing.allocator, out, .{});
        const r = res.complete.reply;
        defer testing.allocator.free(r.array);
        try testing.expectEqual(argc, r.array.len);
        try testing.expectEqual(out.len, res.complete.consumed);
        for (args, r.array) |a, elem| {
            try testing.expectEqualSlices(u8, a, elem.bulk.?);
        }
    }
}

test "encodeCommand: bounds — TooManyArgs and BufferTooSmall" {
    var big: [max_args + 1][]const u8 = undefined;
    for (&big) |*a| a.* = "x";
    var buf: [8192]u8 = undefined;
    try testing.expectError(error.TooManyArgs, encodeCommand(&buf, &big));

    var tiny: [3]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, encodeCommand(&tiny, &.{ "GET", "key" }));
}

test "decode: simple string, error, integer (RESP2 scalars)" {
    {
        const res = try parseReply(testing.allocator, "+OK\r\n", .{});
        try testing.expectEqualStrings("OK", res.complete.reply.status);
        try testing.expectEqual(@as(usize, 5), res.complete.consumed);
        try testing.expectEqualStrings("OK", res.complete.reply.asString().?);
    }
    {
        const res = try parseReply(testing.allocator, "-ERR boom\r\n", .{});
        try testing.expectEqualStrings("ERR boom", res.complete.reply.err);
        try testing.expectEqualStrings("ERR boom", res.complete.reply.isError().?);
    }
    // Random integers incl. negative + the i64 extremes.
    var prng = std.Random.DefaultPrng.init(testing.random_seed);
    const rand = prng.random();
    const fixed = [_]i64{ 0, 1, -1, std.math.maxInt(i64), std.math.minInt(i64) };
    for (fixed) |v| try expectIntRoundTrip(v);
    var i: usize = 0;
    while (i < 256) : (i += 1) try expectIntRoundTrip(rand.int(i64));
}

fn expectIntRoundTrip(v: i64) !void {
    var buf: [32]u8 = undefined;
    const line = try std.fmt.bufPrint(&buf, ":{d}\r\n", .{v});
    const res = try parseReply(testing.allocator, line, .{});
    try testing.expectEqual(v, res.complete.reply.int);
    try testing.expectEqual(v, res.complete.reply.asInt().?);
    try testing.expectEqual(line.len, res.complete.consumed);
}

test "decode: bulk string incl. binary, empty, and null" {
    var prng = std.Random.DefaultPrng.init(testing.random_seed);
    const rand = prng.random();

    var iter: usize = 0;
    while (iter < 200) : (iter += 1) {
        const len = rand.intRangeAtMost(usize, 0, 64);
        var payload: [64]u8 = undefined;
        for (0..len) |j| payload[j] = rand.int(u8); // includes \r \n NUL
        var buf: [256]u8 = undefined;
        var w = Cursor{ .buf = &buf };
        try w.byte('$');
        try w.uint(len);
        try w.crlf();
        try w.bytes(payload[0..len]);
        try w.crlf();
        const wire = w.written();

        const res = try parseReply(testing.allocator, wire, .{});
        try testing.expectEqualSlices(u8, payload[0..len], res.complete.reply.bulk.?);
        try testing.expectEqual(wire.len, res.complete.consumed);
    }

    // Null bulk `$-1\r\n` → bulk == null, and isNil() true.
    {
        const res = try parseReply(testing.allocator, "$-1\r\n", .{});
        try testing.expect(res.complete.reply.bulk == null);
        try testing.expect(res.complete.reply.isNil());
        try testing.expectEqual(@as(usize, 5), res.complete.consumed);
    }
    // Empty bulk `$0\r\n\r\n` is an empty (non-null) string.
    {
        const res = try parseReply(testing.allocator, "$0\r\n\r\n", .{});
        try testing.expectEqualStrings("", res.complete.reply.bulk.?);
        try testing.expect(!res.complete.reply.isNil());
    }
}

test "decode: RESP3 scalars — null, double (incl inf/nan), boolean, big number, verbatim, blob error" {
    // Null `_`.
    {
        const res = try parseReply(testing.allocator, "_\r\n", .{});
        try testing.expect(res.complete.reply == .nil);
        try testing.expect(res.complete.reply.isNil());
    }
    // Doubles: random finite values round-trip, plus the special tokens.
    var prng = std.Random.DefaultPrng.init(testing.random_seed);
    const rand = prng.random();
    var i: usize = 0;
    while (i < 128) : (i += 1) {
        const v = (rand.float(f64) - 0.5) * 1e6;
        var buf: [64]u8 = undefined;
        const line = try std.fmt.bufPrint(&buf, ",{d}\r\n", .{v});
        const res = try parseReply(testing.allocator, line, .{});
        try testing.expectApproxEqRel(v, res.complete.reply.double, 1e-9);
    }
    try testing.expect(std.math.isPositiveInf((try parseReply(testing.allocator, ",inf\r\n", .{})).complete.reply.double));
    try testing.expect(std.math.isNegativeInf((try parseReply(testing.allocator, ",-inf\r\n", .{})).complete.reply.double));
    try testing.expect(std.math.isNan((try parseReply(testing.allocator, ",nan\r\n", .{})).complete.reply.double));

    // Booleans.
    try testing.expectEqual(true, (try parseReply(testing.allocator, "#t\r\n", .{})).complete.reply.boolean);
    try testing.expectEqual(false, (try parseReply(testing.allocator, "#f\r\n", .{})).complete.reply.boolean);

    // Big number keeps its text.
    {
        const res = try parseReply(testing.allocator, "(3492890328409238509324850943850943825024385\r\n", .{});
        try testing.expectEqualStrings("3492890328409238509324850943850943825024385", res.complete.reply.big_number);
    }
    // Verbatim string: 3-char format + ':' + payload.
    {
        const res = try parseReply(testing.allocator, "=15\r\ntxt:Some string\r\n", .{});
        try testing.expectEqualSlices(u8, "txt", &res.complete.reply.verbatim.format);
        try testing.expectEqualStrings("Some string", res.complete.reply.verbatim.data);
    }
    // Blob error.
    {
        const res = try parseReply(testing.allocator, "!21\r\nSYNTAX invalid syntax\r\n", .{});
        try testing.expectEqualStrings("SYNTAX invalid syntax", res.complete.reply.blob_err);
        try testing.expectEqualStrings("SYNTAX invalid syntax", res.complete.reply.isError().?);
    }
}

test "decode: arrays — empty, null, nested to random depth" {
    // Empty array `*0`.
    {
        const res = try parseReply(testing.allocator, "*0\r\n", .{});
        try testing.expectEqual(@as(usize, 0), res.complete.reply.array.len);
        // Zero-length alloc need not be freed, but free is safe + leak-checked.
        testing.allocator.free(res.complete.reply.array);
    }
    // Null array `*-1` → nil.
    {
        const res = try parseReply(testing.allocator, "*-1\r\n", .{});
        try testing.expect(res.complete.reply == .nil);
    }
    // A small flat array of mixed scalars.
    {
        const wire = "*3\r\n:1\r\n$5\r\nhello\r\n+world\r\n";
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const res = try parseReply(arena.allocator(), wire, .{});
        const a = res.complete.reply.array;
        try testing.expectEqual(@as(usize, 3), a.len);
        try testing.expectEqual(@as(i64, 1), a[0].int);
        try testing.expectEqualStrings("hello", a[1].bulk.?);
        try testing.expectEqualStrings("world", a[2].status);
        try testing.expectEqual(wire.len, res.complete.consumed);
    }
    // Randomly-nested arrays, each level holding 0..3 children, depth ≤ 6.
    var prng = std.Random.DefaultPrng.init(testing.random_seed);
    const rand = prng.random();
    var iter: usize = 0;
    while (iter < 64) : (iter += 1) {
        var wire: std.ArrayListUnmanaged(u8) = .empty;
        defer wire.deinit(testing.allocator);
        var leaves: usize = 0;
        try buildRandomNested(testing.allocator, &wire, rand, 6, &leaves);

        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const res = try parseReply(arena.allocator(), wire.items, .{});
        try testing.expectEqual(wire.items.len, res.complete.consumed);
        // Independently count the integer leaves in the decoded tree.
        try testing.expectEqual(leaves, countIntLeaves(res.complete.reply));
    }
}

/// Build a random nested array/leaf structure into `out`, counting the
/// integer leaves it contains. Bounded by `budget` (remaining depth).
fn buildRandomNested(
    alloc: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    rand: std.Random,
    budget: u8,
    leaves: *usize,
) !void {
    // At depth budget 0, or with some probability, emit an integer leaf.
    if (budget == 0 or rand.boolean()) {
        const v = rand.int(i32);
        try out.print(alloc, ":{d}\r\n", .{v});
        leaves.* += 1;
        return;
    }
    const n = rand.intRangeAtMost(usize, 0, 3);
    try out.print(alloc, "*{d}\r\n", .{n});
    var i: usize = 0;
    while (i < n) : (i += 1) {
        try buildRandomNested(alloc, out, rand, budget - 1, leaves);
    }
}

fn countIntLeaves(r: Reply) usize {
    return switch (r) {
        .int => 1,
        .array, .set, .push => |elems| blk: {
            var total: usize = 0;
            for (elems) |e| total += countIntLeaves(e);
            break :blk total;
        },
        .map => |pairs| blk: {
            var total: usize = 0;
            for (pairs) |kv| total += countIntLeaves(kv.key) + countIntLeaves(kv.value);
            break :blk total;
        },
        else => 0,
    };
}

test "decode: map and set (RESP3 aggregates)" {
    // Map of 2 pairs: {key1: 1, key2: 2}.
    {
        const wire = "%2\r\n$4\r\nkey1\r\n:1\r\n$4\r\nkey2\r\n:2\r\n";
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const res = try parseReply(arena.allocator(), wire, .{});
        const m = res.complete.reply.map;
        try testing.expectEqual(@as(usize, 2), m.len);
        try testing.expectEqualStrings("key1", m[0].key.bulk.?);
        try testing.expectEqual(@as(i64, 1), m[0].value.int);
        try testing.expectEqualStrings("key2", m[1].key.bulk.?);
        try testing.expectEqual(@as(i64, 2), m[1].value.int);
        try testing.expectEqual(wire.len, res.complete.consumed);
    }
    // Set of 3 integers.
    {
        const wire = "~3\r\n:10\r\n:20\r\n:30\r\n";
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const res = try parseReply(arena.allocator(), wire, .{});
        const s = res.complete.reply.set;
        try testing.expectEqual(@as(usize, 3), s.len);
        try testing.expectEqual(@as(i64, 30), s[2].int);
    }
    // Push frame.
    {
        const wire = ">2\r\n+message\r\n$2\r\nhi\r\n";
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const res = try parseReply(arena.allocator(), wire, .{});
        const p = res.complete.reply.push;
        try testing.expectEqual(@as(usize, 2), p.len);
        try testing.expectEqualStrings("message", p[0].status);
    }
}

test "decode: RESP3 attribute frame is parsed and skipped, value surfaces" {
    // `|1\r\n` attr map {key-popularity: ...} then the real reply :42.
    const wire = "|1\r\n$3\r\nkey\r\n+meta\r\n:42\r\n";
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const res = try parseReply(arena.allocator(), wire, .{});
    try testing.expectEqual(@as(i64, 42), res.complete.reply.int);
    try testing.expectEqual(wire.len, res.complete.consumed);
}

test "incremental: feeding one byte at a time yields .incomplete until the final byte" {
    var prng = std.Random.DefaultPrng.init(testing.random_seed);
    const rand = prng.random();

    var iter: usize = 0;
    while (iter < 64) : (iter += 1) {
        // Build a random nested reply so we exercise the aggregate path too.
        var wire: std.ArrayListUnmanaged(u8) = .empty;
        defer wire.deinit(testing.allocator);
        var leaves: usize = 0;
        try buildRandomNested(testing.allocator, &wire, rand, 5, &leaves);
        const total = wire.items.len;
        try testing.expect(total >= 1);

        // Every strict prefix must be .incomplete (never an error), and the
        // full buffer must be .complete consuming exactly `total` bytes.
        var prefix: usize = 1;
        while (prefix < total) : (prefix += 1) {
            var arena = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena.deinit();
            const res = try parseReply(arena.allocator(), wire.items[0..prefix], .{});
            try testing.expect(res == .incomplete);
        }
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        const full = try parseReply(arena.allocator(), wire.items, .{});
        try testing.expect(full == .complete);
        try testing.expectEqual(total, full.complete.consumed);
    }
}

test "incremental: scalar prefixes are incomplete, not errors" {
    // Cover one of each scalar type byte-by-byte.
    const cases = [_][]const u8{
        "+hello world\r\n",
        "-ERR something\r\n",
        ":-1234567\r\n",
        "$5\r\nhello\r\n",
        "_\r\n",
        ",3.14159\r\n",
        "#t\r\n",
        "(123456789012345678901234567890\r\n",
        "=12\r\ntxt:hi there\r\n",
        "!10\r\nERR badcmd\r\n"[0..],
    };
    for (cases) |wire| {
        var p: usize = 1;
        while (p < wire.len) : (p += 1) {
            const res = parseReply(testing.allocator, wire[0..p], .{}) catch |e| {
                std.debug.print("unexpected error {} at prefix {d} of {s}\n", .{ e, p, wire });
                return e;
            };
            try testing.expect(res == .incomplete);
        }
        const full = try parseReply(testing.allocator, wire, .{});
        try testing.expect(full == .complete);
    }
}

test "consumed: a buffer with TWO replies decodes the first and reports its exact length" {
    const wire = "+FIRST\r\n:99\r\n";
    const first = try parseReply(testing.allocator, wire, .{});
    try testing.expectEqualStrings("FIRST", first.complete.reply.status);
    try testing.expectEqual(@as(usize, 8), first.complete.consumed); // "+FIRST\r\n"
    // Advancing the buffer parses the second.
    const second = try parseReply(testing.allocator, wire[first.complete.consumed..], .{});
    try testing.expectEqual(@as(i64, 99), second.complete.reply.int);
    try testing.expectEqual(@as(usize, 5), second.complete.consumed);
}

test "malformed: garbage type byte, bad lengths, bad integers → Protocol/BadLength; not resumable" {
    // Unknown leading byte.
    try testing.expectError(error.Protocol, parseReply(testing.allocator, "?nope\r\n", .{}));
    try testing.expect(!isResumable(error.Protocol));
    // Bad bulk length header (non-numeric).
    try testing.expectError(error.BadLength, parseReply(testing.allocator, "$abc\r\n", .{}));
    try testing.expect(!isResumable(error.BadLength));
    // Bad integer body.
    try testing.expectError(error.Protocol, parseReply(testing.allocator, ":12x4\r\n", .{}));
    // Boolean with an illegal token.
    try testing.expectError(error.Protocol, parseReply(testing.allocator, "#x\r\n", .{}));
    // Bare LF (no CR) is illegal framing.
    try testing.expectError(error.Protocol, parseReply(testing.allocator, "+oops\n", .{}));
    // Bulk body whose trailing CRLF is wrong.
    try testing.expectError(error.Protocol, parseReply(testing.allocator, "$2\r\nhiXX", .{}));
    // Verbatim missing the `xxx:` prefix.
    try testing.expectError(error.Protocol, parseReply(testing.allocator, "=3\r\nabc\r\n", .{}));
    // Bad aggregate count header.
    try testing.expectError(error.BadLength, parseReply(testing.allocator, "*xx\r\n", .{}));
}

test "over-limit: depth > max_depth → TooDeep; elements > max_elements → TooLarge; bulk > max_bulk_bytes → TooLarge" {
    // Aggregates that allocate spine bytes before erroring rely on the
    // caller's per-reply arena to reclaim them (the documented contract);
    // a single deinit frees everything even on the error path.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Build a nested array deeper than max_depth=2: *1 -> *1 -> *1 -> :0
    const deep = "*1\r\n*1\r\n*1\r\n:0\r\n";
    try testing.expectError(error.TooDeep, parseReply(a, deep, .{ .max_depth = 2 }));
    try testing.expect(!isResumable(error.TooDeep));

    // Element count over budget: header says 5 but max_elements=4. We reject
    // BEFORE allocating, so no children bytes are needed.
    try testing.expectError(error.TooLarge, parseReply(a, "*5\r\n", .{ .max_elements = 4 }));
    // Map child-count doubling is also bounded: 3 pairs → 6 children > 4.
    try testing.expectError(error.TooLarge, parseReply(a, "%3\r\n", .{ .max_elements = 4 }));

    // Bulk longer than the byte budget is rejected on the header alone.
    try testing.expectError(error.TooLarge, parseReply(a, "$100\r\n", .{ .max_bulk_bytes = 10 }));
    try testing.expect(!isResumable(error.TooLarge));
}

test "over-limit: a deep-but-incomplete buffer still reports TooDeep, not incomplete" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    // Depth check fires on descent regardless of whether children are present.
    try testing.expectError(error.TooDeep, parseReply(arena.allocator(), "*1\r\n*1\r\n*1\r\n", .{ .max_depth = 2 }));
}

test "scalar parsers: parseLen / parseI64 / parseDoubleBody edge cases" {
    try testing.expectEqual(@as(?usize, 0), parseLen("0"));
    try testing.expectEqual(@as(?usize, 123), parseLen("123"));
    try testing.expect(parseLen("") == null);
    try testing.expect(parseLen("-1") == null); // sign not allowed in a length
    try testing.expect(parseLen("1a") == null);

    try testing.expectEqual(@as(?i64, std.math.minInt(i64)), parseI64("-9223372036854775808"));
    try testing.expectEqual(@as(?i64, std.math.maxInt(i64)), parseI64("9223372036854775807"));
    try testing.expect(parseI64("9223372036854775808") == null); // overflow
    try testing.expect(parseI64("-") == null);
    try testing.expect(parseI64("") == null);

    try testing.expectEqual(@as(?f64, 1.5), parseDoubleBody("1.5"));
    try testing.expect(std.math.isPositiveInf(parseDoubleBody("INF").?));
    try testing.expect(std.math.isNan(parseDoubleBody("NaN").?));
    try testing.expect(parseDoubleBody("not-a-number") == null);
}
