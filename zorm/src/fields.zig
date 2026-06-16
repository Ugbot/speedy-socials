//! zorm field types — the bounded, Tiger-Style building blocks an entity
//! is declared with. Each carries a comptime `zorm_kind` marker so the
//! reflection layer can map it to a column without runtime cost. Strings
//! and blobs are fixed-capacity (no heap, no per-row allocation); scalars
//! (`i64`/`u32`/`bool`/`f64`), Zig enums (stored as text by name), and
//! `?T` optionals are used directly with no wrapper.
//!
//! Example entity:
//!   const User = struct {
//!       pub const zorm_table = "users";
//!       id: zorm.AutoPk = .{},
//!       handle: zorm.Text(64) = .{},
//!       avatar: zorm.Bytes(4096) = .{},
//!       created_at: zorm.Timestamp = .{},
//!       role: Role = .member,        // enum -> TEXT
//!       bio: ?zorm.Text(256) = null,  // nullable column
//!   };

const std = @import("std");

/// What a field maps to at the storage layer. Detected via the comptime
/// `zorm_kind` decl on the field's type (or `@typeInfo` for native types).
pub const Kind = enum { text, bytes, pk_text, pk_auto, timestamp };

/// Fixed-capacity UTF-8/text column. Stored as TEXT. `N` ≤ 1024 (the
/// backend's inline-column limit; enforced at comptime by `reflect`).
pub fn Text(comptime N: usize) type {
    return struct {
        const Self = @This();
        pub const zorm_kind: Kind = .text;
        pub const capacity: usize = N;

        buf: [N]u8 = undefined,
        len: std.math.IntFittingRange(0, N) = 0,

        pub fn set(self: *Self, s: []const u8) void {
            const n = @min(N, s.len);
            @memcpy(self.buf[0..n], s[0..n]);
            self.len = @intCast(n);
        }
        pub fn slice(self: *const Self) []const u8 {
            return self.buf[0..self.len];
        }
        pub fn from(s: []const u8) Self {
            var x: Self = .{};
            x.set(s);
            return x;
        }
        pub fn eql(self: *const Self, other: *const Self) bool {
            return std.mem.eql(u8, self.slice(), other.slice());
        }
    };
}

/// Fixed-capacity binary column. Stored as BLOB. Same shape as `Text`.
pub fn Bytes(comptime N: usize) type {
    return struct {
        const Self = @This();
        pub const zorm_kind: Kind = .bytes;
        pub const capacity: usize = N;

        buf: [N]u8 = undefined,
        len: std.math.IntFittingRange(0, N) = 0,

        pub fn set(self: *Self, s: []const u8) void {
            const n = @min(N, s.len);
            @memcpy(self.buf[0..n], s[0..n]);
            self.len = @intCast(n);
        }
        pub fn slice(self: *const Self) []const u8 {
            return self.buf[0..self.len];
        }
        pub fn from(s: []const u8) Self {
            var x: Self = .{};
            x.set(s);
            return x;
        }
        pub fn eql(self: *const Self, other: *const Self) bool {
            return std.mem.eql(u8, self.slice(), other.slice());
        }
    };
}

/// Text PRIMARY KEY (e.g. a DID or UUID). Stored as TEXT PRIMARY KEY.
pub fn Pk(comptime N: usize) type {
    return struct {
        const Self = @This();
        pub const zorm_kind: Kind = .pk_text;
        pub const capacity: usize = N;

        buf: [N]u8 = undefined,
        len: std.math.IntFittingRange(0, N) = 0,

        pub fn set(self: *Self, s: []const u8) void {
            const n = @min(N, s.len);
            @memcpy(self.buf[0..n], s[0..n]);
            self.len = @intCast(n);
        }
        pub fn slice(self: *const Self) []const u8 {
            return self.buf[0..self.len];
        }
        pub fn from(s: []const u8) Self {
            var x: Self = .{};
            x.set(s);
            return x;
        }
        pub fn eql(self: *const Self, other: *const Self) bool {
            return std.mem.eql(u8, self.slice(), other.slice());
        }
    };
}

/// Auto-incrementing integer PRIMARY KEY. A zero `value` means "unsaved"
/// (the row id is assigned by the DB on insert: `RETURNING id` on
/// Postgres, `lastInsertId()` on SQLite).
pub const AutoPk = struct {
    pub const zorm_kind: Kind = .pk_auto;
    value: i64 = 0,
};

/// Unix-seconds timestamp. Stored as INTEGER.
pub const Timestamp = struct {
    pub const zorm_kind: Kind = .timestamp;
    unix: i64 = 0,
};

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

test "Text: set/slice/from/eql + truncation at capacity" {
    var t = Text(8).from("hello");
    try testing.expectEqualStrings("hello", t.slice());
    t.set("worldwide"); // 9 chars into cap 8 → truncates
    try testing.expectEqual(@as(usize, 8), t.slice().len);
    try testing.expectEqualStrings("worldwid", t.slice());

    const a = Text(8).from("x");
    const b = Text(8).from("x");
    try testing.expect(a.eql(&b));
    try testing.expect(!a.eql(&Text(8).from("y")));
}

test "field kind markers are visible at comptime" {
    try testing.expectEqual(Kind.text, Text(4).zorm_kind);
    try testing.expectEqual(Kind.bytes, Bytes(4).zorm_kind);
    try testing.expectEqual(Kind.pk_text, Pk(4).zorm_kind);
    try testing.expectEqual(Kind.pk_auto, AutoPk.zorm_kind);
    try testing.expectEqual(Kind.timestamp, Timestamp.zorm_kind);
}

test "AutoPk zero means unsaved" {
    const k: AutoPk = .{};
    try testing.expectEqual(@as(i64, 0), k.value);
}
