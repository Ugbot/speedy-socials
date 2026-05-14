//! TID — Timestamp Identifier.
//!
//! 13-char base32-sortable identifier encoding a 53-bit microsecond
//! timestamp plus a 10-bit clock id. Sorts lexicographically by time.
//!
//! Tiger Style: stateful generation is held by a `State` struct so callers
//! own the storage. The clock id is sampled once from a `*Rng` at `init`
//! and persists for the process lifetime, matching the spec's
//! "clock-id stable per writer" requirement. `next` guarantees strict
//! monotonic ordering — if wall time hasn't advanced, the encoded
//! timestamp is bumped by 1 µs.
//!
//! Spec: https://atproto.com/specs/record-key#record-key-type-tid

const std = @import("std");
const core = @import("core");
const AtpError = core.errors.AtpError;
const Clock = core.clock.Clock;
const Rng = core.rng.Rng;
const assert = core.assert.assert;
const assertLe = core.assert.assertLe;

pub const tid_len: usize = 13;

const alphabet = "234567abcdefghijklmnopqrstuvwxyz";

pub const Tid = struct {
    raw: [tid_len]u8,

    pub fn str(self: *const Tid) []const u8 {
        return self.raw[0..];
    }

    pub fn timestampMicros(self: Tid) u64 {
        var ts: u64 = 0;
        var i: usize = 0;
        while (i < 11) : (i += 1) {
            assertLe(i, tid_len);
            const v = charToValue(self.raw[i]) orelse unreachable;
            ts = (ts << 5) | v;
        }
        return ts;
    }

    pub fn clockId(self: Tid) u10 {
        var id: u10 = 0;
        var i: usize = 11;
        while (i < 13) : (i += 1) {
            assertLe(i, tid_len);
            const v: u10 = @intCast(charToValue(self.raw[i]) orelse unreachable);
            id = (id << 5) | v;
        }
        return id;
    }
};

pub fn parse(s: []const u8) AtpError!Tid {
    if (s.len != tid_len) return error.BadTid;
    // First char: high bit (0x40) must be 0 — only '2'-'7' allowed.
    if (s[0] & 0x40 != 0) return error.BadTid;
    var out: Tid = .{ .raw = undefined };
    var i: usize = 0;
    while (i < tid_len) : (i += 1) {
        assertLe(i, tid_len);
        if (charToValue(s[i]) == null) return error.BadTid;
        out.raw[i] = s[i];
    }
    return out;
}

pub fn fromTimestamp(ts_micros: u64, clock_id: u10) Tid {
    var result: Tid = .{ .raw = undefined };

    // 53-bit timestamp → first 11 chars, big-endian.
    var t = ts_micros & ((@as(u64, 1) << 53) - 1);
    var i: usize = 11;
    while (i > 0) {
        i -= 1;
        result.raw[i] = alphabet[@as(usize, @intCast(t & 0x1f))];
        t >>= 5;
    }

    // 10-bit clock id → last 2 chars.
    var c: u10 = clock_id;
    var j: usize = 13;
    while (j > 11) {
        j -= 1;
        result.raw[j] = alphabet[@as(usize, c & 0x1f)];
        c >>= 5;
    }
    return result;
}

fn charToValue(c: u8) ?u5 {
    return switch (c) {
        '2'...'7' => @intCast(c - '2'),
        'a'...'z' => @intCast(c - 'a' + 6),
        else => null,
    };
}

/// Per-process state for monotonic TID generation. `init` samples the
/// clock id once from `rng`; thereafter `next` is pure given clock.
pub const State = struct {
    clock_id: u10,
    last_micros: u64 = 0,

    pub fn init(rng: *Rng) State {
        // Use raw `random().int` to avoid the std.crypto.random path that
        // no longer exists in Zig 0.16.
        const r = rng.random().int(u16);
        return .{ .clock_id = @intCast(r & 0x3ff) };
    }

    /// Returns a new TID guaranteed strictly greater than every TID this
    /// State has issued previously. `clock.wallNs()` provides the
    /// monotonic epoch base.
    pub fn next(self: *State, clock: Clock) Tid {
        const wall_ns = clock.wallNs();
        // Convert ns → µs. Negative wall times pre-1970 collapse to 0;
        // a single instance shouldn't see those but be safe.
        const wall_us_signed = @divTrunc(wall_ns, std.time.ns_per_us);
        const wall_us: u64 = if (wall_us_signed < 0) 0 else @intCast(wall_us_signed);

        var t = wall_us;
        if (t <= self.last_micros) t = self.last_micros + 1;
        assert(t > self.last_micros);
        self.last_micros = t;
        return fromTimestamp(t, self.clock_id);
    }
};

// ── Tests ──────────────────────────────────────────────────────────

test "tid: encode then parse roundtrip" {
    const t = fromTimestamp(1_704_067_200_000_000, 42);
    const parsed = try parse(t.str());
    try std.testing.expectEqual(@as(u64, 1_704_067_200_000_000), parsed.timestampMicros());
    try std.testing.expectEqual(@as(u10, 42), parsed.clockId());
}

test "tid: parser rejects bad inputs" {
    try std.testing.expectError(error.BadTid, parse("short"));
    try std.testing.expectError(error.BadTid, parse(""));
    try std.testing.expectError(error.BadTid, parse("0000000000000"));
    try std.testing.expectError(error.BadTid, parse("aaaaaaaaaaaaa"));
    try std.testing.expectError(error.BadTid, parse("2AAAAAAAAAAAA"));
}

test "tid: monotonic State.next" {
    var sc = core.clock.SimClock.init(1_700_000_000);
    var rng = Rng.init(0xC0FFEE);
    var state = State.init(&rng);

    var prev: Tid = state.next(sc.clock());
    var i: u32 = 0;
    while (i < 32) : (i += 1) {
        const cur = state.next(sc.clock());
        // Strict monotonic at the string level: cur > prev lexicographically.
        try std.testing.expect(std.mem.lessThan(u8, prev.str(), cur.str()));
        prev = cur;
        sc.advance(std.time.ns_per_us); // 1 µs per iteration
    }
}

test "tid: ordering with time gap" {
    var sc = core.clock.SimClock.init(1_700_000_000);
    var rng = Rng.init(0xDEAD);
    var state = State.init(&rng);
    const a = state.next(sc.clock());
    sc.advance(1_000 * std.time.ns_per_us); // 1 ms
    const b = state.next(sc.clock());
    try std.testing.expect(std.mem.lessThan(u8, a.str(), b.str()));
    try std.testing.expect(b.timestampMicros() > a.timestampMicros());
}
