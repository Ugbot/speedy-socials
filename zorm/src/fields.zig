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
pub const Kind = enum {
    text,
    bytes,
    pk_text,
    pk_auto,
    /// Caller-supplied integer PRIMARY KEY (NOT auto-assigned). Stored as
    /// INTEGER. Used as a single PK or — more commonly — as one part of a
    /// COMPOSITE key (e.g. `(tenant TEXT, seq INTEGER)`).
    pk_int,
    timestamp,
    /// Fixed-point numeric (money). Stored losslessly as text.
    decimal,
    /// 16-byte UUID. Stored as its canonical 36-char string.
    uuid,
    /// Bounded JSON document. Stored as text.
    json,
    /// Calendar date (no time). Stored as an ISO-8601 `YYYY-MM-DD` string.
    date,
    /// Date + time. Stored as an ISO-8601 `YYYY-MM-DDTHH:MM:SS[.fff]` string.
    datetime,
};

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

/// Caller-supplied integer PRIMARY KEY (the value is NOT DB-assigned — the
/// caller sets it). The natural integer member of a composite key. Stored as
/// INTEGER PRIMARY KEY (single) or as one column of a table-level composite
/// PRIMARY KEY.
pub const PkInt = struct {
    pub const zorm_kind: Kind = .pk_int;
    value: i64 = 0,
};

/// Unix-seconds timestamp. Stored as INTEGER.
pub const Timestamp = struct {
    pub const zorm_kind: Kind = .timestamp;
    unix: i64 = 0,
};

/// Fixed-point decimal column (money/exact numeric) with `precision` total
/// significant digits and `scale` digits after the point. DDL emits
/// `NUMERIC(precision, scale)` / `DECIMAL(precision, scale)` per dialect.
///
/// Representation: TEXT. The decimal is held as its exact decimal string
/// (e.g. `"-1234.56"`), so it round-trips losslessly through every backend
/// — no binary-float rounding, no engine-specific scaled-int packing. The
/// inline buffer is sized `precision + 2` (one byte for a leading sign, one
/// for the decimal point), which is the longest canonical form.
pub fn Decimal(comptime precision: usize, comptime scale: usize) type {
    if (precision == 0) @compileError("zorm: Decimal precision must be ≥ 1");
    if (scale > precision) @compileError("zorm: Decimal scale must be ≤ precision");
    return struct {
        const Self = @This();
        pub const zorm_kind: Kind = .decimal;
        pub const sql_precision: usize = precision;
        pub const sql_scale: usize = scale;
        /// Text capacity: all `precision` digits + sign + decimal point.
        pub const capacity: usize = precision + 2;

        buf: [capacity]u8 = undefined,
        len: std.math.IntFittingRange(0, capacity) = 0,

        pub fn set(self: *Self, s: []const u8) void {
            const n = @min(capacity, s.len);
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

/// 16-byte UUID column. DDL emits a native UUID type where one exists
/// (Postgres `UUID`, SQL Server `UNIQUEIDENTIFIER`), `CHAR(36)` on MySQL,
/// `TEXT` on SQLite.
///
/// Representation: the value is bound/read as its canonical lowercase
/// 36-char string (`8-4-4-4-12` hex), which round-trips through every
/// dialect's text/UUID type. The raw 16 bytes are also available via
/// `bytes()` / `setBytes()` for callers that hold a binary UUID.
pub const Uuid = struct {
    const Self = @This();
    pub const zorm_kind: Kind = .uuid;
    /// Canonical string length (8-4-4-4-12 + 4 hyphens).
    pub const capacity: usize = 36;

    /// Source of truth: the canonical lowercase 36-char string. Kept inline
    /// so `canonical()`/`slice()` return a borrow into the field — which the
    /// bind layer requires (the `BindValue` outlives the call). Raw bytes are
    /// derived on demand via `bytes()`. Default is the all-zero (nil) UUID.
    buf: [capacity]u8 = ("00000000-0000-0000-0000-000000000000").*,
    len: std.math.IntFittingRange(0, capacity) = capacity,

    fn nibble(c: u8) ?u8 {
        return switch (c) {
            '0'...'9' => c - '0',
            'a'...'f' => c - 'a' + 10,
            'A'...'F' => c - 'A' + 10,
            else => null,
        };
    }

    fn hexDigit(v: u8) u8 {
        return "0123456789abcdef"[v & 0x0f];
    }

    /// The canonical 36-char string (borrow into the field). Used by bind.
    pub fn canonical(self: *const Self) []const u8 {
        return self.buf[0..self.len];
    }

    /// Set from a canonical (or hyphen-free, any-case) UUID string. The
    /// value is normalized to canonical lowercase `8-4-4-4-12` form so the
    /// stored bytes are stable regardless of input formatting.
    pub fn set(self: *Self, s: []const u8) void {
        var raw: [16]u8 = [_]u8{0} ** 16;
        var byte_idx: usize = 0;
        var hi: ?u8 = null;
        for (s) |c| {
            const v = nibble(c) orelse continue;
            if (hi) |h| {
                if (byte_idx >= 16) break;
                raw[byte_idx] = (h << 4) | v;
                byte_idx += 1;
                hi = null;
            } else {
                hi = v;
            }
        }
        self.setBytes(&raw);
    }

    /// Set from raw 16 bytes (zero-padded if fewer). Stores the canonical
    /// lowercase string form.
    pub fn setBytes(self: *Self, b: []const u8) void {
        var raw: [16]u8 = [_]u8{0} ** 16;
        const n = @min(16, b.len);
        @memcpy(raw[0..n], b[0..n]);
        var j: usize = 0;
        for (raw, 0..) |byte, i| {
            if (i == 4 or i == 6 or i == 8 or i == 10) {
                self.buf[j] = '-';
                j += 1;
            }
            self.buf[j] = hexDigit(byte >> 4);
            self.buf[j + 1] = hexDigit(byte & 0x0f);
            j += 2;
        }
        self.len = capacity;
    }

    /// Decode the canonical string back to raw 16 bytes.
    pub fn bytes(self: *const Self) [16]u8 {
        var raw: [16]u8 = [_]u8{0} ** 16;
        var byte_idx: usize = 0;
        var hi: ?u8 = null;
        for (self.buf[0..self.len]) |c| {
            const v = nibble(c) orelse continue;
            if (hi) |h| {
                if (byte_idx >= 16) break;
                raw[byte_idx] = (h << 4) | v;
                byte_idx += 1;
                hi = null;
            } else {
                hi = v;
            }
        }
        return raw;
    }

    /// Alias for `canonical()` — the canonical string (borrow into the field).
    pub fn slice(self: *const Self) []const u8 {
        return self.canonical();
    }

    pub fn from(s: []const u8) Self {
        var x: Self = .{};
        x.set(s);
        return x;
    }
    pub fn fromBytes(b: []const u8) Self {
        var x: Self = .{};
        x.setBytes(b);
        return x;
    }
    pub fn eql(self: *const Self, other: *const Self) bool {
        return std.mem.eql(u8, self.canonical(), other.canonical());
    }
};

/// Bounded JSON document column (`N` bytes of UTF-8 JSON text). DDL emits a
/// native JSON type where one exists (Postgres `JSONB`, MySQL `JSON`),
/// `NVARCHAR(N)` on SQL Server, `TEXT` on SQLite.
///
/// Representation: TEXT. zorm stores the JSON exactly as given (it does not
/// parse or canonicalize it); `N` ≤ 1024 (the inline-column limit).
pub fn Json(comptime N: usize) type {
    return struct {
        const Self = @This();
        pub const zorm_kind: Kind = .json;
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

/// Calendar date (no time-of-day). DDL emits `DATE` on every dialect.
///
/// Representation: an ISO-8601 `YYYY-MM-DD` string (TEXT-bound). 10 chars;
/// the buffer is sized 10. Stored as a string so it round-trips identically
/// across engines (DATE columns accept and return this canonical form).
pub const Date = struct {
    const Self = @This();
    pub const zorm_kind: Kind = .date;
    /// `YYYY-MM-DD`.
    pub const capacity: usize = 10;

    buf: [capacity]u8 = undefined,
    len: std.math.IntFittingRange(0, capacity) = 0,

    pub fn set(self: *Self, s: []const u8) void {
        const n = @min(capacity, s.len);
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

/// Date + time. DDL emits a high-resolution datetime per dialect (Postgres
/// `TIMESTAMP`, MySQL `DATETIME`, SQL Server `DATETIME2`, SQLite `TEXT`).
/// Distinct from `Timestamp`, which is a unix-seconds INTEGER.
///
/// Representation: an ISO-8601 `YYYY-MM-DDTHH:MM:SS[.fff]` string
/// (TEXT-bound). Buffer sized 32 to admit fractional seconds + offset. A
/// string round-trips losslessly across engines without timezone surprises.
pub const DateTime = struct {
    const Self = @This();
    pub const zorm_kind: Kind = .datetime;
    /// `YYYY-MM-DDTHH:MM:SS.ffffff+HH:MM` fits in 32.
    pub const capacity: usize = 32;

    buf: [capacity]u8 = undefined,
    len: std.math.IntFittingRange(0, capacity) = 0,

    pub fn set(self: *Self, s: []const u8) void {
        const n = @min(capacity, s.len);
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
    try testing.expectEqual(Kind.decimal, Decimal(10, 2).zorm_kind);
    try testing.expectEqual(Kind.uuid, Uuid.zorm_kind);
    try testing.expectEqual(Kind.json, Json(64).zorm_kind);
    try testing.expectEqual(Kind.date, Date.zorm_kind);
    try testing.expectEqual(Kind.datetime, DateTime.zorm_kind);
}

test "Decimal: precision/scale + lossless text round-trip" {
    const Money = Decimal(12, 2);
    try testing.expectEqual(@as(usize, 12), Money.sql_precision);
    try testing.expectEqual(@as(usize, 2), Money.sql_scale);
    try testing.expectEqual(@as(usize, 14), Money.capacity); // 12 + sign + dot

    var m = Money.from("-1234567890.99");
    try testing.expectEqualStrings("-1234567890.99", m.slice());
    m.set("0.01");
    try testing.expectEqualStrings("0.01", m.slice());
    try testing.expect(Money.from("3.14").eql(&Money.from("3.14")));
    try testing.expect(!Money.from("3.14").eql(&Money.from("3.15")));
}

test "Uuid: canonical string + raw byte round-trip" {
    const canon = "550e8400-e29b-41d4-a716-446655440000";
    const u = Uuid.from(canon);

    try testing.expectEqualStrings(canon, u.slice());
    try testing.expectEqualStrings(canon, u.canonical());

    // Raw bytes: first byte 0x55, fifth 0xe2, last 0x00.
    const raw = u.bytes();
    try testing.expectEqual(@as(u8, 0x55), raw[0]);
    try testing.expectEqual(@as(u8, 0xe2), raw[4]);
    try testing.expectEqual(@as(u8, 0x00), raw[15]);

    // Round-trip via raw bytes reproduces the same canonical string.
    const back = Uuid.fromBytes(&raw);
    try testing.expect(u.eql(&back));
    try testing.expectEqualStrings(canon, back.slice());

    // Uppercase / hyphen-free input normalizes to the same canonical value.
    try testing.expect(Uuid.from("550E8400E29B41D4A716446655440000").eql(&u));
    try testing.expectEqualStrings(canon, Uuid.from("550E8400E29B41D4A716446655440000").canonical());
}

test "Json: bounded text round-trip" {
    const J = Json(64);
    try testing.expectEqual(@as(usize, 64), J.capacity);
    var j = J.from("{\"a\":1,\"b\":[2,3]}");
    try testing.expectEqualStrings("{\"a\":1,\"b\":[2,3]}", j.slice());
    j.set("null");
    try testing.expectEqualStrings("null", j.slice());
}

test "Date/DateTime: ISO-8601 text round-trip" {
    var d = Date.from("2026-06-23");
    try testing.expectEqualStrings("2026-06-23", d.slice());
    try testing.expectEqual(@as(usize, 10), Date.capacity);

    var dt = DateTime.from("2026-06-23T14:05:09.250");
    try testing.expectEqualStrings("2026-06-23T14:05:09.250", dt.slice());
    try testing.expectEqual(@as(usize, 32), DateTime.capacity);
}

test "AutoPk zero means unsaved" {
    const k: AutoPk = .{};
    try testing.expectEqual(@as(i64, 0), k.value);
}
