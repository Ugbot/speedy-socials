//! Op-D / E3: Chrome-format tracing.
//!
//! When enabled, every span emits a JSON line to a configured file
//! that opens in `chrome://tracing` (or Perfetto) — useful for
//! visualising request-handler latency, firehose append → consumer
//! translate → outbox enqueue, and other multi-stage pipelines.
//!
//! Three integration points:
//!   * `begin(name, category)` returns a `SpanHandle` that records
//!     the open timestamp.
//!   * `end(handle)` writes a "complete" event (`ph: "X"`) covering
//!     the elapsed wall-clock window.
//!   * `flushTo(writer)` drains accumulated events to a fixed
//!     `std.Io.Writer`. Operators invoke from a debug route or a
//!     shutdown hook.
//!
//! Tiger Style: fixed-size ring buffer of completed spans; older
//! events overwrite oldest on burst. No allocator on the hot path.
//! Tracing is off by default; set `TRACE_ENABLE=1` at boot to turn
//! it on.

const std = @import("std");

pub const max_name_bytes: usize = 64;
pub const max_category_bytes: usize = 32;
pub const ring_capacity: usize = 4096;

pub const SpanEvent = struct {
    name_buf: [max_name_bytes]u8 = undefined,
    name_len: u8 = 0,
    category_buf: [max_category_bytes]u8 = undefined,
    category_len: u8 = 0,
    start_us: i64 = 0,
    duration_us: i64 = 0,
    pid: u32 = 0,
    tid: u32 = 0,

    pub fn name(self: *const SpanEvent) []const u8 {
        return self.name_buf[0..self.name_len];
    }
    pub fn category(self: *const SpanEvent) []const u8 {
        return self.category_buf[0..self.category_len];
    }
};

pub const SpanHandle = struct {
    name_buf: [max_name_bytes]u8 = undefined,
    name_len: u8 = 0,
    category_buf: [max_category_bytes]u8 = undefined,
    category_len: u8 = 0,
    start_us: i64 = 0,
};

var enabled: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var ring: [ring_capacity]SpanEvent = undefined;
var write_idx: std.atomic.Value(u64) = std.atomic.Value(u64).init(0);

pub fn setEnabled(on: bool) void {
    enabled.store(on, .release);
}

pub fn isEnabled() bool {
    return enabled.load(.acquire);
}

pub fn begin(name: []const u8, category: []const u8) SpanHandle {
    var h: SpanHandle = .{};
    const nc = @min(name.len, h.name_buf.len);
    @memcpy(h.name_buf[0..nc], name[0..nc]);
    h.name_len = @intCast(nc);
    const cc = @min(category.len, h.category_buf.len);
    @memcpy(h.category_buf[0..cc], category[0..cc]);
    h.category_len = @intCast(cc);
    h.start_us = nowMicros();
    return h;
}

pub fn end(handle: SpanHandle) void {
    if (!isEnabled()) return;
    const elapsed = nowMicros() - handle.start_us;
    var ev: SpanEvent = .{
        .start_us = handle.start_us,
        .duration_us = elapsed,
        .pid = 1,
        .tid = 1,
    };
    @memcpy(ev.name_buf[0..handle.name_len], handle.name_buf[0..handle.name_len]);
    ev.name_len = handle.name_len;
    @memcpy(ev.category_buf[0..handle.category_len], handle.category_buf[0..handle.category_len]);
    ev.category_len = handle.category_len;

    const idx = write_idx.fetchAdd(1, .monotonic);
    const slot: usize = @intCast(idx % ring_capacity);
    ring[slot] = ev;
}

fn nowMicros() i64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(std.c.CLOCK.REALTIME, &ts);
    return @as(i64, ts.sec) * 1_000_000 + @divTrunc(@as(i64, ts.nsec), 1_000);
}

pub fn flushTo(writer: *std.Io.Writer) !void {
    try writer.writeAll("[");
    const write = write_idx.load(.acquire);
    const start = if (write > ring_capacity) write - ring_capacity else 0;
    var i: u64 = start;
    var first = true;
    while (i < write) : (i += 1) {
        const slot: usize = @intCast(i % ring_capacity);
        const ev = &ring[slot];
        if (!first) try writer.writeAll(",\n");
        first = false;
        // Chrome trace "complete" event.
        try writer.print(
            "{{\"name\":\"{s}\",\"cat\":\"{s}\",\"ph\":\"X\",\"ts\":{d},\"dur\":{d},\"pid\":{d},\"tid\":{d}}}",
            .{ ev.name(), ev.category(), ev.start_us, ev.duration_us, ev.pid, ev.tid },
        );
    }
    try writer.writeAll("]\n");
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "E3: begin/end records a span when enabled" {
    write_idx.store(0, .release);
    setEnabled(true);
    defer setEnabled(false);
    const h = begin("test-span", "test");
    end(h);
    try testing.expectEqual(@as(u64, 1), write_idx.load(.acquire));
}

test "E3: end is a no-op when disabled" {
    write_idx.store(0, .release);
    setEnabled(false);
    const h = begin("ignored", "cat");
    end(h);
    try testing.expectEqual(@as(u64, 0), write_idx.load(.acquire));
}

test "E3: flushTo emits valid JSON envelope" {
    write_idx.store(0, .release);
    setEnabled(true);
    defer setEnabled(false);
    const h = begin("span-a", "io");
    end(h);

    var buf: [4096]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try flushTo(&w);
    const out = w.buffered();
    try testing.expect(std.mem.startsWith(u8, out, "["));
    try testing.expect(std.mem.endsWith(u8, std.mem.trimEnd(u8, out, "\n"), "]"));
    try testing.expect(std.mem.indexOf(u8, out, "\"name\":\"span-a\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"ph\":\"X\"") != null);
}
