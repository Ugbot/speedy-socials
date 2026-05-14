//! Counters + gauges + histograms with a fixed-capacity static registry
//! and Prometheus text exposition output.
//!
//! Tiger Style: no allocator on hot paths. Each metric is identified by
//! a stable `MetricId` (the index into the registry) returned at
//! registration time. `inc(id)`, `add(id, n)`, `set(id, v)`, and
//! `observe(id, v)` are O(1) atomic ops.
//!
//! Histograms are fixed-bucket. The caller supplies LE bucket bounds
//! (`max_histogram_buckets`) at registration; observations are counted
//! into the smallest bucket whose upper bound ≥ value, plus a `+Inf`
//! bucket and a separate `_sum` aggregate.
//!
//! Output: Prometheus text exposition format
//! (https://prometheus.io/docs/instrumenting/exposition_formats/). The
//! `export` method writes to a caller-provided `std.Io.Writer`.

const std = @import("std");
const limits = @import("limits.zig");
const errors = @import("errors.zig");
const ObsError = errors.ObsError;
const assert_mod = @import("assert.zig");
const assert = assert_mod.assert;
const assertLe = assert_mod.assertLe;

pub const Kind = enum(u8) { counter, gauge, histogram };

pub const MetricId = u16;

pub const Histogram = struct {
    bucket_count: u32 = 0,
    bounds: [limits.max_histogram_buckets]f64 = [_]f64{0.0} ** limits.max_histogram_buckets,
    /// One atomic counter per bucket. Index N is "≤ bounds[N]". The
    /// extra slot at `bucket_count` represents +Inf.
    counts: [limits.max_histogram_buckets + 1]std.atomic.Value(u64) = blk: {
        var arr: [limits.max_histogram_buckets + 1]std.atomic.Value(u64) = undefined;
        var i: usize = 0;
        while (i < arr.len) : (i += 1) arr[i] = std.atomic.Value(u64).init(0);
        break :blk arr;
    },
    /// Sum of observed values, stored as raw u64 bits of f64.
    sum_bits: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// Total observation count.
    observed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
};

pub const Metric = struct {
    name_len: u8 = 0,
    name_buf: [limits.max_metric_name_bytes]u8 = undefined,
    help_len: u8 = 0,
    help_buf: [limits.max_metric_help_bytes]u8 = undefined,
    kind: Kind = .counter,

    /// Counter/gauge state. For counters: monotonic u64 add. For
    /// gauges: signed semantics encoded as i64 stored in atomic u64.
    value: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    histogram: Histogram = .{},

    pub fn name(self: *const Metric) []const u8 {
        return self.name_buf[0..self.name_len];
    }

    pub fn help(self: *const Metric) []const u8 {
        return self.help_buf[0..self.help_len];
    }
};

pub const Registry = struct {
    items: [limits.max_metrics]Metric = undefined,
    count: u16 = 0,

    pub fn init() Registry {
        return .{};
    }

    fn registerCommon(
        self: *Registry,
        kind: Kind,
        name: []const u8,
        help: []const u8,
    ) ObsError!MetricId {
        if (self.count >= limits.max_metrics) return error.TooManyMetrics;
        if (name.len == 0 or name.len > limits.max_metric_name_bytes) return error.MetricNameTooLong;
        if (help.len > limits.max_metric_help_bytes) return error.MetricHelpTooLong;

        var i: u16 = 0;
        while (i < self.count) : (i += 1) {
            const m = &self.items[i];
            if (std.mem.eql(u8, m.name(), name)) return error.DuplicateMetric;
        }

        const id: MetricId = self.count;
        var m: *Metric = &self.items[id];
        m.* = .{};
        m.kind = kind;
        @memcpy(m.name_buf[0..name.len], name);
        m.name_len = @intCast(name.len);
        @memcpy(m.help_buf[0..help.len], help);
        m.help_len = @intCast(help.len);
        self.count += 1;
        assertLe(@as(u32, self.count), limits.max_metrics);
        return id;
    }

    pub fn registerCounter(self: *Registry, name: []const u8, help: []const u8) ObsError!MetricId {
        return self.registerCommon(.counter, name, help);
    }

    pub fn registerGauge(self: *Registry, name: []const u8, help: []const u8) ObsError!MetricId {
        return self.registerCommon(.gauge, name, help);
    }

    pub fn registerHistogram(
        self: *Registry,
        name: []const u8,
        help: []const u8,
        bucket_bounds: []const f64,
    ) ObsError!MetricId {
        if (bucket_bounds.len == 0 or bucket_bounds.len > limits.max_histogram_buckets) {
            return error.TooManyBuckets;
        }
        var i: usize = 1;
        while (i < bucket_bounds.len) : (i += 1) {
            if (!(bucket_bounds[i] > bucket_bounds[i - 1])) return error.BucketsNotMonotonic;
        }

        const id = try self.registerCommon(.histogram, name, help);
        var m: *Metric = &self.items[id];
        m.histogram.bucket_count = @intCast(bucket_bounds.len);
        var k: usize = 0;
        while (k < bucket_bounds.len) : (k += 1) {
            m.histogram.bounds[k] = bucket_bounds[k];
        }
        return id;
    }

    fn checkKind(self: *Registry, id: MetricId, kind: Kind) ObsError!*Metric {
        if (id >= self.count) return error.UnknownMetric;
        const m: *Metric = &self.items[id];
        if (m.kind != kind) return error.WrongMetricKind;
        return m;
    }

    pub fn inc(self: *Registry, id: MetricId) ObsError!void {
        return self.add(id, 1);
    }

    pub fn add(self: *Registry, id: MetricId, delta: u64) ObsError!void {
        const m = try self.checkKind(id, .counter);
        _ = m.value.fetchAdd(delta, .monotonic);
    }

    pub fn setGauge(self: *Registry, id: MetricId, v: i64) ObsError!void {
        const m = try self.checkKind(id, .gauge);
        m.value.store(@bitCast(v), .monotonic);
    }

    pub fn addGauge(self: *Registry, id: MetricId, delta: i64) ObsError!void {
        const m = try self.checkKind(id, .gauge);
        // Read-modify-write with CAS; bounded retry loop.
        var attempt: u32 = 0;
        const max_attempts: u32 = 1024;
        while (attempt < max_attempts) : (attempt += 1) {
            const cur_u = m.value.load(.monotonic);
            const cur_i: i64 = @bitCast(cur_u);
            const next_i: i64 = cur_i +% delta;
            const next_u: u64 = @bitCast(next_i);
            if (m.value.cmpxchgWeak(cur_u, next_u, .monotonic, .monotonic) == null) return;
        }
        // CAS contention this severe is a Tiger invariant violation;
        // crash so we don't silently lose updates.
        unreachable;
    }

    pub fn observe(self: *Registry, id: MetricId, v: f64) ObsError!void {
        const m = try self.checkKind(id, .histogram);
        _ = m.histogram.observed.fetchAdd(1, .monotonic);

        // Bounded bucket search.
        const bc = m.histogram.bucket_count;
        var i: u32 = 0;
        var landed: u32 = bc; // default to +Inf
        while (i < bc) : (i += 1) {
            if (v <= m.histogram.bounds[i]) {
                landed = i;
                break;
            }
        }
        _ = m.histogram.counts[landed].fetchAdd(1, .monotonic);

        // Atomic add to sum (CAS loop).
        var attempt: u32 = 0;
        const max_attempts: u32 = 1024;
        while (attempt < max_attempts) : (attempt += 1) {
            const cur_bits = m.histogram.sum_bits.load(.monotonic);
            const cur: f64 = @bitCast(cur_bits);
            const next: f64 = cur + v;
            const next_bits: u64 = @bitCast(next);
            if (m.histogram.sum_bits.cmpxchgWeak(cur_bits, next_bits, .monotonic, .monotonic) == null) return;
        }
        unreachable;
    }

    /// Counter value (for tests/internal inspection).
    pub fn counterValue(self: *Registry, id: MetricId) ObsError!u64 {
        const m = try self.checkKind(id, .counter);
        return m.value.load(.monotonic);
    }

    pub fn gaugeValue(self: *Registry, id: MetricId) ObsError!i64 {
        const m = try self.checkKind(id, .gauge);
        return @bitCast(m.value.load(.monotonic));
    }

    pub fn histogramSum(self: *Registry, id: MetricId) ObsError!f64 {
        const m = try self.checkKind(id, .histogram);
        return @bitCast(m.histogram.sum_bits.load(.monotonic));
    }

    pub fn histogramCount(self: *Registry, id: MetricId) ObsError!u64 {
        const m = try self.checkKind(id, .histogram);
        return m.histogram.observed.load(.monotonic);
    }

    /// Emit the entire registry as Prometheus text exposition format.
    pub fn export_(self: *const Registry, w: *std.Io.Writer) std.Io.Writer.Error!void {
        var i: u16 = 0;
        while (i < self.count) : (i += 1) {
            const m = &self.items[i];
            if (m.help_len > 0) {
                try w.writeAll("# HELP ");
                try w.writeAll(m.name());
                try w.writeByte(' ');
                try w.writeAll(m.help());
                try w.writeByte('\n');
            }
            try w.writeAll("# TYPE ");
            try w.writeAll(m.name());
            try w.writeByte(' ');
            switch (m.kind) {
                .counter => try w.writeAll("counter"),
                .gauge => try w.writeAll("gauge"),
                .histogram => try w.writeAll("histogram"),
            }
            try w.writeByte('\n');

            switch (m.kind) {
                .counter => {
                    try w.writeAll(m.name());
                    try w.print(" {d}\n", .{m.value.load(.monotonic)});
                },
                .gauge => {
                    const v: i64 = @bitCast(m.value.load(.monotonic));
                    try w.writeAll(m.name());
                    try w.print(" {d}\n", .{v});
                },
                .histogram => try writeHistogram(w, m),
            }
        }
        try w.flush();
    }
};

fn writeHistogram(w: *std.Io.Writer, m: *const Metric) std.Io.Writer.Error!void {
    const h = &m.histogram;
    var cum: u64 = 0;
    var i: u32 = 0;
    while (i < h.bucket_count) : (i += 1) {
        cum += h.counts[i].load(.monotonic);
        try w.writeAll(m.name());
        try w.print("_bucket{{le=\"{d}\"}} {d}\n", .{ h.bounds[i], cum });
    }
    cum += h.counts[h.bucket_count].load(.monotonic);
    try w.writeAll(m.name());
    try w.print("_bucket{{le=\"+Inf\"}} {d}\n", .{cum});

    const sum: f64 = @bitCast(h.sum_bits.load(.monotonic));
    try w.writeAll(m.name());
    try w.print("_sum {d}\n", .{sum});

    try w.writeAll(m.name());
    try w.print("_count {d}\n", .{h.observed.load(.monotonic)});
}

// ── Tests ──────────────────────────────────────────────────────────

const testing = std.testing;

test "Registry: counter register/inc/add" {
    var r = Registry.init();
    const c = try r.registerCounter("http_requests_total", "Total HTTP requests.");
    try r.inc(c);
    try r.inc(c);
    try r.add(c, 5);
    try testing.expectEqual(@as(u64, 7), try r.counterValue(c));
}

test "Registry: duplicate name rejected" {
    var r = Registry.init();
    _ = try r.registerCounter("x", "y");
    try testing.expectError(error.DuplicateMetric, r.registerCounter("x", "z"));
}

test "Registry: wrong-kind operation rejected" {
    var r = Registry.init();
    const g = try r.registerGauge("memory_bytes", "process RSS bytes");
    try testing.expectError(error.WrongMetricKind, r.inc(g));
    try r.setGauge(g, -42);
    try testing.expectEqual(@as(i64, -42), try r.gaugeValue(g));
    try r.addGauge(g, 100);
    try testing.expectEqual(@as(i64, 58), try r.gaugeValue(g));
}

test "Registry: histogram observe + sum + count" {
    var r = Registry.init();
    const buckets = [_]f64{ 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0 };
    const h = try r.registerHistogram("http_request_seconds", "Request duration", &buckets);
    try r.observe(h, 0.003);
    try r.observe(h, 0.04);
    try r.observe(h, 0.7);
    try r.observe(h, 2.0); // +Inf
    try testing.expectEqual(@as(u64, 4), try r.histogramCount(h));
    const sum = try r.histogramSum(h);
    try testing.expect(@abs(sum - (0.003 + 0.04 + 0.7 + 2.0)) < 1e-9);
}

test "Registry: histogram rejects non-monotonic buckets" {
    var r = Registry.init();
    const bad = [_]f64{ 0.1, 0.05, 0.2 };
    try testing.expectError(error.BucketsNotMonotonic, r.registerHistogram("x", "y", &bad));
}

test "Registry: histogram rejects too many buckets" {
    var r = Registry.init();
    var bounds: [limits.max_histogram_buckets + 1]f64 = undefined;
    var i: usize = 0;
    while (i < bounds.len) : (i += 1) bounds[i] = @as(f64, @floatFromInt(i + 1));
    try testing.expectError(error.TooManyBuckets, r.registerHistogram("x", "y", &bounds));
}

test "Registry: export_ Prometheus text format snapshot" {
    var r = Registry.init();
    const c = try r.registerCounter("requests_total", "Total requests handled.");
    try r.add(c, 42);
    const g = try r.registerGauge("inflight", "Inflight requests right now.");
    try r.setGauge(g, 3);
    const buckets = [_]f64{ 0.01, 0.1, 1.0 };
    const h = try r.registerHistogram("latency_seconds", "Latency.", &buckets);
    try r.observe(h, 0.005);
    try r.observe(h, 0.5);
    try r.observe(h, 5.0);

    var buf: [4096]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try r.export_(&w);
    const out = w.buffered();

    try testing.expect(std.mem.indexOf(u8, out, "# HELP requests_total Total requests handled.") != null);
    try testing.expect(std.mem.indexOf(u8, out, "# TYPE requests_total counter") != null);
    try testing.expect(std.mem.indexOf(u8, out, "requests_total 42") != null);
    try testing.expect(std.mem.indexOf(u8, out, "# TYPE inflight gauge") != null);
    try testing.expect(std.mem.indexOf(u8, out, "inflight 3") != null);
    try testing.expect(std.mem.indexOf(u8, out, "# TYPE latency_seconds histogram") != null);
    try testing.expect(std.mem.indexOf(u8, out, "latency_seconds_bucket{le=\"0.01\"} 1") != null);
    try testing.expect(std.mem.indexOf(u8, out, "latency_seconds_bucket{le=\"+Inf\"} 3") != null);
    try testing.expect(std.mem.indexOf(u8, out, "latency_seconds_count 3") != null);
}

test "Registry: unknown id rejected" {
    var r = Registry.init();
    try testing.expectError(error.UnknownMetric, r.inc(99));
}
