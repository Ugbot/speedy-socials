//! Storage channel — bounded MPSC queue of `Query` items the writer thread
//! drains. No allocator on the hot path: every query carries its bind args
//! in a fixed-size array of `Value` variants.

const std = @import("std");
const limits = @import("../limits.zig");
const static = @import("../static.zig");
const assert_mod = @import("../assert.zig");
const assert = assert_mod.assert;
const assertLe = assert_mod.assertLe;

/// Maximum number of bind parameters in a single query. Anything larger is
/// a hard error at registration time. Tiger Style: bounded.
pub const max_bind_args: u8 = 16;

/// Maximum length of a textual bind value carried inline. Bind text larger
/// than this must be referenced via a `text_borrowed` slice the caller
/// keeps alive for the duration of the query.
pub const inline_text_bytes: u16 = 256;

/// Maximum length of an inline blob bind value.
pub const inline_blob_bytes: u16 = 256;

/// One bind parameter. Variant fixes the SQLite type; the writer thread
/// performs the corresponding `sqlite3_bind_*` call.
pub const Value = union(enum) {
    null_,
    int: i64,
    real: f64,
    /// Inline NUL-terminated text. `len` is the byte length (excluding NUL).
    text_inline: struct { bytes: [inline_text_bytes]u8 = undefined, len: u16 = 0 },
    /// Borrowed text — the caller must keep the slice alive until completion.
    text_borrowed: []const u8,
    blob_inline: struct { bytes: [inline_blob_bytes]u8 = undefined, len: u16 = 0 },
    blob_borrowed: []const u8,

    pub fn int64(v: i64) Value {
        return .{ .int = v };
    }
    pub fn real_(v: f64) Value {
        return .{ .real = v };
    }
    pub fn nul() Value {
        return .null_;
    }
    pub fn textInline(s: []const u8) Value {
        assertLe(s.len, inline_text_bytes);
        var out: Value = .{ .text_inline = .{} };
        @memcpy(out.text_inline.bytes[0..s.len], s);
        out.text_inline.len = @intCast(s.len);
        return out;
    }
    pub fn textBorrowed(s: []const u8) Value {
        return .{ .text_borrowed = s };
    }
    pub fn blobInline(s: []const u8) Value {
        assertLe(s.len, inline_blob_bytes);
        var out: Value = .{ .blob_inline = .{} };
        @memcpy(out.blob_inline.bytes[0..s.len], s);
        out.blob_inline.len = @intCast(s.len);
        return out;
    }
    pub fn blobBorrowed(s: []const u8) Value {
        return .{ .blob_borrowed = s };
    }
};

/// Fixed-size bind args buffer.
pub const BindArgs = struct {
    items: [max_bind_args]Value = [_]Value{.null_} ** max_bind_args,
    count: u8 = 0,

    pub fn init() BindArgs {
        return .{};
    }

    pub fn push(self: *BindArgs, v: Value) void {
        assert(self.count < max_bind_args);
        self.items[self.count] = v;
        self.count += 1;
    }

    pub fn slice(self: *const BindArgs) []const Value {
        return self.items[0..self.count];
    }
};

/// Status reported to the completion callback.
pub const QueryStatus = enum(u8) {
    ok,
    not_found,
    prepare_failed,
    bind_failed,
    step_failed,
    closed,
};

/// A single result row delivered to the completion callback for `query_one`
/// or `query_many`. The writer thread copies up to `max_result_columns`
/// column values into the fixed buffer. Text/blob results are copied into
/// the inline buffer (truncated to `inline_text_bytes` if larger).
pub const max_result_columns: u8 = 16;

pub const ResultValue = union(enum) {
    null_,
    int: i64,
    real: f64,
    /// Inline copy of text. `len` is the byte length (excluding any NUL).
    text: struct { bytes: [inline_text_bytes]u8 = undefined, len: u16 = 0, truncated: bool = false },
    blob: struct { bytes: [inline_blob_bytes]u8 = undefined, len: u16 = 0, truncated: bool = false },
};

pub const Row = struct {
    cols: [max_result_columns]ResultValue = [_]ResultValue{.null_} ** max_result_columns,
    col_count: u8 = 0,
};

/// Tagged kind of a Query.
pub const QueryKind = enum(u8) { exec, query_one, query_many };

/// A completion callback. Called on the writer thread once the query has
/// finished. `rows` is the slice of rows produced (empty for `exec` and
/// `query_one` when not found).
pub const CompletionFn = *const fn (
    user_data: ?*anyopaque,
    status: QueryStatus,
    rows: []const Row,
    rows_affected: i64,
) void;

/// Maximum rows captured by a single `query_many`. Anything larger
/// truncates and the status remains `.ok`. Tiger Style: bounded.
pub const max_captured_rows: u16 = 64;

pub const Query = struct {
    kind: QueryKind,
    /// Index into the prepared statement table.
    stmt: u32,
    args: BindArgs,
    /// Caller user data passed back through the completion callback.
    user_data: ?*anyopaque,
    /// Required completion callback. Always invoked exactly once.
    completion: CompletionFn,
    /// Optional row buffer for query_many. The caller owns it; the writer
    /// thread fills up to `cap` rows then calls completion.
    rows_buf: ?[*]Row = null,
    rows_cap: u16 = 0,
};

/// Bounded MPSC channel feeding the writer thread.
pub const Channel = static.BoundedMpsc(Query, limits.max_inflight_queries);

test "Value text_inline round-trip" {
    const v = Value.textInline("hello");
    switch (v) {
        .text_inline => |t| {
            try std.testing.expectEqualStrings("hello", t.bytes[0..t.len]);
        },
        else => return error.TestUnexpectedTag,
    }
}

test "Value variants" {
    try std.testing.expect(Value.int64(7) == .int);
    try std.testing.expect(Value.real_(1.5) == .real);
    try std.testing.expect(Value.nul() == .null_);
    try std.testing.expect(Value.textBorrowed("x") == .text_borrowed);
    try std.testing.expect(Value.blobInline("a") == .blob_inline);
    try std.testing.expect(Value.blobBorrowed("b") == .blob_borrowed);
}

test "BindArgs push under capacity" {
    var a = BindArgs.init();
    a.push(Value.int64(1));
    a.push(Value.int64(2));
    a.push(Value.textInline("ok"));
    try std.testing.expectEqual(@as(u8, 3), a.count);
    try std.testing.expectEqual(@as(i64, 2), a.items[1].int);
}

test "Value blob_inline round-trip" {
    const v = Value.blobInline("\x00\x01\x02");
    switch (v) {
        .blob_inline => |b| {
            try std.testing.expectEqual(@as(u16, 3), b.len);
            try std.testing.expectEqual(@as(u8, 2), b.bytes[2]);
        },
        else => return error.TestUnexpectedTag,
    }
}

test "Channel MPSC contention from two producer threads" {
    var ch = Channel.init();
    const dummy = struct {
        fn run(_: ?*anyopaque, _: QueryStatus, _: []const Row, _: i64) void {}
    }.run;

    const producer = struct {
        fn run(ctx: *Channel, n: u32) void {
            var i: u32 = 0;
            while (i < n) : (i += 1) {
                while (true) {
                    ctx.push(.{
                        .kind = .exec,
                        .stmt = i % 4,
                        .args = .{},
                        .user_data = null,
                        .completion = dummy,
                    }) catch |err| switch (err) {
                        error.Full => continue, // spin
                        error.Closed => return,
                    };
                    break;
                }
            }
        }
    };

    const t1 = try std.Thread.spawn(.{}, producer.run, .{ &ch, @as(u32, 64) });
    const t2 = try std.Thread.spawn(.{}, producer.run, .{ &ch, @as(u32, 64) });

    var drained: u32 = 0;
    while (drained < 128) {
        if (ch.tryPop()) |_| drained += 1;
    }
    t1.join();
    t2.join();
    try std.testing.expectEqual(@as(u32, 128), drained);
}

test "Channel basic push/pop" {
    var ch = Channel.init();
    const dummy_completion = struct {
        fn run(_: ?*anyopaque, _: QueryStatus, _: []const Row, _: i64) void {}
    }.run;
    try ch.push(.{
        .kind = .exec,
        .stmt = 0,
        .args = .{},
        .user_data = null,
        .completion = dummy_completion,
    });
    const q = ch.tryPop() orelse return error.TestExpectedItem;
    try std.testing.expectEqual(@as(u32, 0), q.stmt);
}
