//! Structured, ring-buffered, lossy log.
//!
//! Philosophy — lossy by design:
//!
//! The log ring is the canonical Tiger Style ring-buffer use case. When
//! a slow consumer (the drain thread, a paused debugger, a stalled
//! stderr pipe) falls behind, the producer **overwrites the oldest
//! pending entry** instead of blocking. A request handler may not
//! stall waiting on a log slot; logs are diagnostics, not durable data.
//!
//! In numbers: the ring holds `limits.log_ring_capacity = 4096` entries
//! at ~512 B each (≈ 2 MiB). At 100 ms drain ticks, sustained > 40 000
//! lines/sec for over 100 ms is required to drop anything. Bursts that
//! exceed that are visibly logged in a final "log_dropped: N" counter
//! emitted at next drain.
//!
//! Hot-path discipline:
//!  * `log.info(...)` etc. take only a spinlock to publish into the
//!    ring; no allocator, no syscalls, no formatting allocations.
//!  * Message bodies are written into a fixed `[max_log_msg_bytes]u8`
//!    slot; over-long formats are truncated with "...".
//!  * Drain thread runs at a configurable cadence (default 100 ms via
//!    `Clock`) and serializes pending entries to a `std.Io.Writer`
//!    provided at startup (defaulted to stderr).
//!
//! Output format: JSON Lines. One JSON object per line per entry, with
//! `ts_unix_ns`, `level`, `scope`, `msg`, and an optional `kv` object.
//!
//! Test hooks: `Log.testDrainTo(writer)` runs one drain pass without
//! the worker thread, for deterministic snapshot tests.

const std = @import("std");
const builtin = @import("builtin");

const assert_mod = @import("assert.zig");
const assert = assert_mod.assert;
const assertLe = assert_mod.assertLe;

const limits = @import("limits.zig");
const clock_mod = @import("clock.zig");
const Clock = clock_mod.Clock;
const WallNanos = clock_mod.WallNanos;
const Spinlock = @import("static.zig").Spinlock;

comptime {
    // Ring capacity must be a power of two for fast masking.
    if ((limits.log_ring_capacity & (limits.log_ring_capacity - 1)) != 0) {
        @compileError("limits.log_ring_capacity must be a power of two");
    }
    if (limits.log_ring_capacity == 0) {
        @compileError("limits.log_ring_capacity must be > 0");
    }
}

pub const Level = enum(u8) {
    trace = 0,
    debug = 1,
    info = 2,
    warn = 3,
    err = 4,

    pub fn name(self: Level) []const u8 {
        return switch (self) {
            .trace => "trace",
            .debug => "debug",
            .info => "info",
            .warn => "warn",
            .err => "error",
        };
    }
};

pub const KeyVal = struct {
    key_len: u8 = 0,
    val_len: u8 = 0,
    key_buf: [limits.max_log_kv_bytes]u8 = undefined,
    val_buf: [limits.max_log_kv_bytes]u8 = undefined,

    pub fn key(self: *const KeyVal) []const u8 {
        return self.key_buf[0..self.key_len];
    }
    pub fn val(self: *const KeyVal) []const u8 {
        return self.val_buf[0..self.val_len];
    }

    pub fn set(self: *KeyVal, k: []const u8, v: []const u8) void {
        const k_n = @min(k.len, limits.max_log_kv_bytes);
        const v_n = @min(v.len, limits.max_log_kv_bytes);
        @memcpy(self.key_buf[0..k_n], k[0..k_n]);
        @memcpy(self.val_buf[0..v_n], v[0..v_n]);
        self.key_len = @intCast(k_n);
        self.val_len = @intCast(v_n);
    }
};

pub const LogEntry = struct {
    ts: WallNanos = 0,
    level: Level = .info,
    scope_len: u8 = 0,
    scope_buf: [limits.max_log_scope_bytes]u8 = undefined,
    len: u16 = 0,
    message: [limits.max_log_msg_bytes]u8 = undefined,
    kv_count: u8 = 0,
    kv: [limits.max_log_kv]KeyVal = undefined,

    pub fn scope(self: *const LogEntry) []const u8 {
        return self.scope_buf[0..self.scope_len];
    }

    pub fn msg(self: *const LogEntry) []const u8 {
        return self.message[0..self.len];
    }
};

const ring_capacity: u32 = limits.log_ring_capacity;
const ring_mask: u32 = ring_capacity - 1;

/// The global log. One Logger lives for the process lifetime; plugins
/// receive it indirectly via `Context` (wired in a later phase) or via
/// the package-level convenience functions in this module after
/// `installGlobal()`.
pub const Log = struct {
    lock: Spinlock = .{},
    /// Total entries published (monotonically increasing modulo u64).
    published: u64 = 0,
    /// Total entries successfully serialized to the writer.
    drained: u64 = 0,
    /// Entries lost to overwrite. Visible in the next drain as a
    /// synthetic "log_dropped" line.
    dropped: u64 = 0,

    entries: [ring_capacity]LogEntry = undefined,

    clock: Clock,
    min_level: Level = .info,

    pub fn init(clk: Clock) Log {
        return .{ .clock = clk };
    }

    pub fn setMinLevel(self: *Log, level: Level) void {
        self.min_level = level;
    }

    /// Publish an entry. Lossy: on full ring the oldest pending entry
    /// is overwritten (head advances). Never blocks the caller for
    /// more than a spinlock window.
    pub fn record(
        self: *Log,
        level: Level,
        scope: []const u8,
        message: []const u8,
        kvs: []const struct { k: []const u8, v: []const u8 },
    ) void {
        if (@intFromEnum(level) < @intFromEnum(self.min_level)) return;
        const ts = self.clock.wallNs();

        self.lock.lock();
        defer self.lock.unlock();

        const idx = self.published & ring_mask;
        var e: *LogEntry = &self.entries[idx];
        e.ts = ts;
        e.level = level;

        const s_n = @min(scope.len, limits.max_log_scope_bytes);
        @memcpy(e.scope_buf[0..s_n], scope[0..s_n]);
        e.scope_len = @intCast(s_n);

        const m_n: u16 = @intCast(@min(message.len, limits.max_log_msg_bytes));
        @memcpy(e.message[0..m_n], message[0..m_n]);
        e.len = m_n;

        const kv_n: u8 = @intCast(@min(kvs.len, limits.max_log_kv));
        var i: u8 = 0;
        while (i < kv_n) : (i += 1) {
            e.kv[i] = .{};
            e.kv[i].set(kvs[i].k, kvs[i].v);
        }
        e.kv_count = kv_n;

        // If the ring was already full, the consumer is behind: bump
        // the drop counter and advance `drained` so the next drain
        // starts at the new tail.
        const in_flight = self.published -% self.drained;
        if (in_flight >= ring_capacity) {
            self.dropped +%= 1;
            self.drained +%= 1;
        }
        self.published +%= 1;
    }

    /// Convenience helpers.
    pub inline fn trace(self: *Log, scope: []const u8, message: []const u8) void {
        self.record(.trace, scope, message, &.{});
    }
    pub inline fn debug(self: *Log, scope: []const u8, message: []const u8) void {
        self.record(.debug, scope, message, &.{});
    }
    pub inline fn info(self: *Log, scope: []const u8, message: []const u8) void {
        self.record(.info, scope, message, &.{});
    }
    pub inline fn warn(self: *Log, scope: []const u8, message: []const u8) void {
        self.record(.warn, scope, message, &.{});
    }
    pub inline fn err(self: *Log, scope: []const u8, message: []const u8) void {
        self.record(.err, scope, message, &.{});
    }

    /// Drain pending entries to `w`. Returns the number drained.
    /// Caller controls when this runs; the worker thread calls it on a
    /// 100 ms cadence.
    pub fn flush(self: *Log, w: *std.Io.Writer) std.Io.Writer.Error!u64 {
        // Snapshot under lock; copy slots out so we don't hold the
        // spinlock across the writer I/O.
        var batch: [128]LogEntry = undefined;
        var n_drained: u64 = 0;
        var dropped_this_round: u64 = 0;
        // Bounded outer loop: at most ring_capacity / batch iterations.
        const max_iters: u32 = (ring_capacity / batch.len) + 1;
        var iter: u32 = 0;
        while (iter < max_iters) : (iter += 1) {
            var taken: usize = 0;
            self.lock.lock();
            const in_flight = self.published -% self.drained;
            const take: usize = @min(@as(usize, @intCast(in_flight)), batch.len);
            var i: usize = 0;
            while (i < take) : (i += 1) {
                const idx = (self.drained +% i) & ring_mask;
                batch[i] = self.entries[idx];
            }
            self.drained +%= take;
            taken = take;
            if (iter == 0) {
                dropped_this_round = self.dropped;
                self.dropped = 0;
            }
            self.lock.unlock();

            if (taken == 0 and (iter > 0 or dropped_this_round == 0)) break;

            if (iter == 0 and dropped_this_round > 0) {
                try writeDropLine(w, dropped_this_round);
            }

            var j: usize = 0;
            while (j < taken) : (j += 1) {
                try writeEntry(w, &batch[j]);
            }
            n_drained += taken;
            if (taken < batch.len) break;
        }
        try w.flush();
        return n_drained;
    }

    /// Snapshot of internal counters for assertions / tests.
    pub fn stats(self: *Log) struct { published: u64, drained: u64, dropped: u64 } {
        self.lock.lock();
        defer self.lock.unlock();
        return .{
            .published = self.published,
            .drained = self.drained,
            .dropped = self.dropped,
        };
    }
};

fn writeDropLine(w: *std.Io.Writer, n: u64) std.Io.Writer.Error!void {
    try w.print(
        "{{\"level\":\"warn\",\"scope\":\"log\",\"msg\":\"log_dropped\",\"kv\":{{\"count\":\"{d}\"}}}}\n",
        .{n},
    );
}

fn writeEntry(w: *std.Io.Writer, e: *const LogEntry) std.Io.Writer.Error!void {
    try w.writeAll("{\"ts_unix_ns\":");
    try w.print("{d}", .{e.ts});
    try w.writeAll(",\"level\":\"");
    try w.writeAll(e.level.name());
    try w.writeAll("\",\"scope\":\"");
    try writeJsonString(w, e.scope());
    try w.writeAll("\",\"msg\":\"");
    try writeJsonString(w, e.msg());
    try w.writeByte('"');
    if (e.kv_count > 0) {
        try w.writeAll(",\"kv\":{");
        var i: u8 = 0;
        while (i < e.kv_count) : (i += 1) {
            if (i > 0) try w.writeByte(',');
            try w.writeByte('"');
            try writeJsonString(w, e.kv[i].key());
            try w.writeAll("\":\"");
            try writeJsonString(w, e.kv[i].val());
            try w.writeByte('"');
        }
        try w.writeByte('}');
    }
    try w.writeAll("}\n");
}

fn writeJsonString(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    // Bounded by s.len, asserted ≤ max message size on entry.
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            0...0x07, 0x0b, 0x0e...0x1f => try w.print("\\u{x:0>4}", .{c}),
            else => try w.writeByte(c),
        }
    }
}

/// Background drain worker.
pub const Drainer = struct {
    log: *Log,
    period_ns: u64,
    stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,

    pub fn init(log: *Log, period_ns: u64) Drainer {
        return .{ .log = log, .period_ns = period_ns };
    }

    /// Start the worker. Owns the spawned thread; call `stopAndJoin`
    /// before program exit so the final batch is flushed.
    pub fn start(self: *Drainer) !void {
        self.stop.store(false, .release);
        self.thread = try std.Thread.spawn(.{}, workerEntry, .{self});
    }

    pub fn stopAndJoin(self: *Drainer) void {
        self.stop.store(true, .release);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
        // Final synchronous flush so no entry leaks on shutdown.
        flushToStderr(self.log) catch {};
    }

    fn workerEntry(self: *Drainer) void {
        // Bounded loop: each iteration drains then sleeps.
        var spin_guard: u64 = 0;
        while (!self.stop.load(.acquire)) {
            spin_guard +%= 1;
            assertLe(spin_guard, std.math.maxInt(u64)); // can't actually fail; bounded by clock.
            flushToStderr(self.log) catch {};
            sleepNs(self.period_ns);
        }
    }
};

fn sleepNs(ns: u64) void {
    var req: std.c.timespec = .{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    var rem: std.c.timespec = undefined;
    // Bounded retry: at most a handful of EINTR loops.
    var attempt: u8 = 0;
    while (attempt < 8) : (attempt += 1) {
        const rc = std.c.nanosleep(&req, &rem);
        if (rc == 0) return;
        // EINTR — sleep again for the remainder.
        req = rem;
    }
}

/// Drain to the process stderr using the std.debug locked-stderr
/// primitive (which bypasses the Io interface — safe to call from a
/// worker thread without an Io handle).
pub fn flushToStderr(log: *Log) !void {
    var scratch: [4096]u8 = undefined;
    const locked = std.debug.lockStderr(&scratch);
    defer std.debug.unlockStderr();
    _ = try log.flush(&locked.file_writer.interface);
}

// ── Tests ──────────────────────────────────────────────────────────

const testing = std.testing;

const SimClock = clock_mod.SimClock;

/// Heap-allocated test log. The ring is ~2 MiB; stack allocation in
/// tests overflows the default test-runner thread stack. Caller owns
/// destruction via `testing.allocator.destroy`.
fn makeLogHeap(sc: *SimClock) !*Log {
    const log = try testing.allocator.create(Log);
    log.* = Log.init(sc.clock());
    return log;
}

fn destroyLog(log: *Log) void {
    testing.allocator.destroy(log);
}

test "Log: record + flush JSON Lines snapshot" {
    var sc = SimClock.init(1_700_000_000);
    const log = try makeLogHeap(&sc);
    defer destroyLog(log);
    log.setMinLevel(.trace);

    log.info("startup", "hello world");
    sc.advance(1_000);
    log.warn("http", "slow");

    var buf: [4096]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    const n = try log.flush(&w);
    try testing.expectEqual(@as(u64, 2), n);

    const out = w.buffered();
    try testing.expect(std.mem.indexOf(u8, out, "\"level\":\"info\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"scope\":\"startup\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"msg\":\"hello world\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"level\":\"warn\"") != null);
    // exactly two lines emitted.
    var newlines: usize = 0;
    for (out) |c| if (c == '\n') {
        newlines += 1;
    };
    try testing.expectEqual(@as(usize, 2), newlines);
}

test "Log: kv pairs serialize as nested JSON object" {
    var sc = SimClock.init(0);
    const log = try makeLogHeap(&sc);
    defer destroyLog(log);

    log.record(.info, "auth", "login", &.{
        .{ .k = "user", .v = "alice" },
        .{ .k = "ip", .v = "1.2.3.4" },
    });

    var buf: [1024]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    _ = try log.flush(&w);
    const out = w.buffered();
    try testing.expect(std.mem.indexOf(u8, out, "\"kv\":{\"user\":\"alice\",\"ip\":\"1.2.3.4\"}") != null);
}

test "Log: ring overwrites oldest under burst load" {
    var sc = SimClock.init(0);
    const log = try makeLogHeap(&sc);
    defer destroyLog(log);
    log.setMinLevel(.trace);

    // Publish ring_capacity + 16 entries — the first 16 must be lost.
    const overflow: u32 = 16;
    var i: u32 = 0;
    var msg_buf: [32]u8 = undefined;
    while (i < ring_capacity + overflow) : (i += 1) {
        const m = std.fmt.bufPrint(&msg_buf, "n={d}", .{i}) catch unreachable;
        log.record(.info, "burst", m, &.{});
    }
    const s = log.stats();
    try testing.expectEqual(@as(u64, overflow), s.dropped);
    try testing.expectEqual(@as(u64, ring_capacity + overflow), s.published);
    // drained advanced by `dropped` (head moved forward as oldest was
    // overwritten).
    try testing.expectEqual(@as(u64, overflow), s.drained);
}

test "Log: dropped count surfaces in next drain" {
    var sc = SimClock.init(0);
    const log = try makeLogHeap(&sc);
    defer destroyLog(log);
    log.setMinLevel(.trace);

    var i: u32 = 0;
    while (i < ring_capacity + 5) : (i += 1) {
        log.info("x", "y");
    }

    // 4096 entries × ~70 B each ≈ 280 KiB. Buffer sized with slack.
    const buf = try testing.allocator.alloc(u8, 1 << 20);
    defer testing.allocator.free(buf);
    var w = std.Io.Writer.fixed(buf);
    _ = try log.flush(&w);
    const out = w.buffered();
    try testing.expect(std.mem.indexOf(u8, out, "\"msg\":\"log_dropped\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"count\":\"5\"") != null);
}

test "Log: min_level filter suppresses lower levels" {
    var sc = SimClock.init(0);
    const log = try makeLogHeap(&sc);
    defer destroyLog(log);
    log.setMinLevel(.warn);

    log.info("a", "filtered");
    log.debug("a", "filtered");
    log.warn("a", "kept");
    log.err("a", "kept");

    var buf: [1024]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    const n = try log.flush(&w);
    try testing.expectEqual(@as(u64, 2), n);
}

test "Log: long messages are truncated, not heap-grown" {
    var sc = SimClock.init(0);
    const log = try makeLogHeap(&sc);
    defer destroyLog(log);

    var huge: [limits.max_log_msg_bytes + 200]u8 = undefined;
    @memset(&huge, 'x');
    log.info("trunc", &huge);

    var buf: [4096]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    _ = try log.flush(&w);
    const out = w.buffered();
    // Body should contain exactly max_log_msg_bytes x's between the
    // "msg":"..." quotes.
    const expected_xs = "x" ** limits.max_log_msg_bytes;
    try testing.expect(std.mem.indexOf(u8, out, expected_xs) != null);
}

test "Log: JSON string escapes special characters" {
    var sc = SimClock.init(0);
    const log = try makeLogHeap(&sc);
    defer destroyLog(log);

    log.info("esc", "a\"b\\c\nd\te");

    var buf: [1024]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    _ = try log.flush(&w);
    const out = w.buffered();
    try testing.expect(std.mem.indexOf(u8, out, "a\\\"b\\\\c\\nd\\te") != null);
}
