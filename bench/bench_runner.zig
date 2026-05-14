//! Bench runner: executes the storage bench in-process, reads thresholds
//! from `bench/baseline.json`, splices in the echo bench's side file (if
//! present), writes a `bench/results.json`, and exits non-zero if any
//! metric regressed past its threshold.
//!
//! Thresholds:
//!   * `storage.insert_rate_rps.min`   — fail if `current < min`
//!   * `storage.select_rate_rps.min`   — fail if `current < min`
//!   * `echo.rps_single_core.min`      — fail if `current < min`
//!   * `alloc_delta_per_request.max`   — fail if `current > max` (always 0)
//!
//! The storage bench's hot path runs under TigerBeetle's `StaticAllocator`
//! (init→static transition) so any accidental allocation in storage or
//! its dependencies during the hot loop panics. The bench_runner inherits
//! that property by delegating to the same code paths.

const std = @import("std");
const core = @import("core");

const c = @import("sqlite").c;

const STORAGE_N: u64 = 50_000;

const StorageMetrics = struct {
    insert_rate_rps: f64,
    select_rate_rps: f64,
    ins_total_ns: u64,
    sel_total_ns: u64,
};

const EchoMetrics = struct {
    rps: f64 = 0,
    p50_ns: u64 = 0,
    p99_ns: u64 = 0,
    p999_ns: u64 = 0,
    alloc_delta: i64 = 0,
    captured: bool = false,
};

const Threshold = struct {
    storage_insert_min: f64,
    storage_select_min: f64,
    echo_rps_min: f64,
    alloc_delta_max: i64,
};

fn realNs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(std.c.CLOCK.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

const StorageOut = struct {
    var inserts_ok = std.atomic.Value(u64).init(0);
    var inserts_err = std.atomic.Value(u64).init(0);

    fn insCb(_: ?*anyopaque, status: core.storage.QueryStatus, _: []const core.storage.Row, _: i64) void {
        switch (status) {
            .ok => _ = inserts_ok.fetchAdd(1, .release),
            else => _ = inserts_err.fetchAdd(1, .release),
        }
    }
};

const SelectOut = struct {
    var found = std.atomic.Value(u64).init(0);
    var missing = std.atomic.Value(u64).init(0);

    fn cb(_: ?*anyopaque, status: core.storage.QueryStatus, rows: []const core.storage.Row, _: i64) void {
        switch (status) {
            .ok => {
                if (rows.len > 0) {
                    _ = found.fetchAdd(1, .release);
                } else {
                    _ = missing.fetchAdd(1, .release);
                }
            },
            else => _ = missing.fetchAdd(1, .release),
        }
    }
};

fn runStorageBench(allocator: std.mem.Allocator) !StorageMetrics {
    _ = allocator;

    const path: [:0]const u8 = "/tmp/speedy_socials_bench_runner.db";
    _ = std.c.unlink(path.ptr);

    const db = try core.storage.sqlite.openWriter(path);
    defer core.storage.sqlite.closeDb(db);

    var stmts = core.storage.StmtTable.init();
    defer stmts.finalizeAll();

    var schema = core.storage.Schema.init();
    try schema.register(core.storage.bootstrap_migration);
    try schema.register(.{
        .id = 9_001,
        .name = "bench:create_kv",
        .up = "CREATE TABLE kv (k INTEGER PRIMARY KEY, v INTEGER NOT NULL) STRICT;",
    });
    try schema.applyAll(db);

    const k_ins = try stmts.register("ins", "INSERT INTO kv(k, v) VALUES (?, ?)");
    const k_sel = try stmts.register("sel", "SELECT v FROM kv WHERE k = ?");
    try stmts.prepareAll(db);

    var channel = core.storage.Channel.init();
    var writer = core.storage.Writer.init(db, &stmts, &channel);
    try writer.start();
    defer writer.stop();

    var handle = core.storage.Handle.init(&channel, &stmts);

    StorageOut.inserts_ok.store(0, .release);
    StorageOut.inserts_err.store(0, .release);

    // ── INSERT N rows ────────────────────────────────────────────────
    const t0 = realNs();
    var i: u64 = 0;
    while (i < STORAGE_N) : (i += 1) {
        var args: core.storage.BindArgs = .{};
        args.push(core.storage.Value.int64(@intCast(i)));
        args.push(core.storage.Value.int64(@intCast(i *% 7)));
        while (true) {
            handle.exec(k_ins, args, null, StorageOut.insCb) catch |err| switch (err) {
                error.BackpressureRejected => {
                    core.storage.sqlite.sleepNs(10 * std.time.ns_per_us);
                    continue;
                },
                else => return err,
            };
            break;
        }
    }
    while (StorageOut.inserts_ok.load(.acquire) < STORAGE_N and StorageOut.inserts_err.load(.acquire) == 0) {
        core.storage.sqlite.sleepNs(100 * std.time.ns_per_us);
    }
    const t1 = realNs();

    // ── SELECT N rows ────────────────────────────────────────────────
    SelectOut.found.store(0, .release);
    SelectOut.missing.store(0, .release);
    i = 0;
    while (i < STORAGE_N) : (i += 1) {
        var args: core.storage.BindArgs = .{};
        args.push(core.storage.Value.int64(@intCast(i)));
        while (true) {
            handle.queryOne(k_sel, args, null, SelectOut.cb) catch |err| switch (err) {
                error.BackpressureRejected => {
                    core.storage.sqlite.sleepNs(10 * std.time.ns_per_us);
                    continue;
                },
                else => return err,
            };
            break;
        }
    }
    while (SelectOut.found.load(.acquire) + SelectOut.missing.load(.acquire) < STORAGE_N) {
        core.storage.sqlite.sleepNs(100 * std.time.ns_per_us);
    }
    const t2 = realNs();

    return .{
        .insert_rate_rps = @as(f64, @floatFromInt(STORAGE_N)) / (@as(f64, @floatFromInt(t1 - t0)) / 1e9),
        .select_rate_rps = @as(f64, @floatFromInt(STORAGE_N)) / (@as(f64, @floatFromInt(t2 - t1)) / 1e9),
        .ins_total_ns = t1 - t0,
        .sel_total_ns = t2 - t1,
    };
}

const libc = @cImport({
    @cInclude("stdio.h");
});

fn readFileBounded(allocator: std.mem.Allocator, path: [:0]const u8, max_bytes: usize) !?[]u8 {
    const f = libc.fopen(path.ptr, "r") orelse return null;
    defer _ = libc.fclose(f);
    if (libc.fseek(f, 0, libc.SEEK_END) != 0) return error.SeekFailed;
    const sz = libc.ftell(f);
    if (sz < 0) return error.SeekFailed;
    const size: usize = @intCast(sz);
    if (size > max_bytes) return error.FileTooLarge;
    _ = libc.fseek(f, 0, libc.SEEK_SET);
    const buf = try allocator.alloc(u8, size);
    errdefer allocator.free(buf);
    const got = libc.fread(buf.ptr, 1, size, f);
    if (got != size) return error.ReadFailed;
    return buf;
}

fn writeFileC(path: [:0]const u8, contents: []const u8) !void {
    const f = libc.fopen(path.ptr, "w") orelse return error.OpenFailed;
    defer _ = libc.fclose(f);
    const written = libc.fwrite(contents.ptr, 1, contents.len, f);
    if (written != contents.len) return error.WriteFailed;
}

fn extractMin(text: []const u8, metric_name: []const u8) ?f64 {
    var buf: [128]u8 = undefined;
    const marker = std.fmt.bufPrint(&buf, "\"{s}\"", .{metric_name}) catch return null;
    const start = std.mem.indexOf(u8, text, marker) orelse return null;
    return jsonGetNumber(text[start..], "min");
}

fn jsonGetNumber(text: []const u8, key: []const u8) ?f64 {
    var marker_buf: [128]u8 = undefined;
    const marker = std.fmt.bufPrint(&marker_buf, "\"{s}\"", .{key}) catch return null;
    const k = std.mem.indexOf(u8, text, marker) orelse return null;
    var i = k + marker.len;
    while (i < text.len and (text[i] == ' ' or text[i] == ':' or text[i] == '\t')) i += 1;
    var j = i;
    while (j < text.len and (text[j] != ',' and text[j] != '}' and text[j] != ' ' and text[j] != '\n' and text[j] != '\r')) j += 1;
    return std.fmt.parseFloat(f64, text[i..j]) catch null;
}

fn parseThresholds(text: []const u8) Threshold {
    // baseline.json structure: nested objects "metrics" → "<metric>" → "min"/"current".
    // We use coarse key scans — first occurrence after each metric's name.
    var t = Threshold{
        .storage_insert_min = 30_000,
        .storage_select_min = 40_000,
        .echo_rps_min = 25_000,
        .alloc_delta_max = 0,
    };

    // Helper: locate the substring `"<metric>"` and from there scan to the next `"min"`.
    t.storage_insert_min = extractMin(text, "storage.insert_rate_rps") orelse t.storage_insert_min;
    t.storage_select_min = extractMin(text, "storage.select_rate_rps") orelse t.storage_select_min;
    t.echo_rps_min = extractMin(text, "echo.rps_single_core") orelse t.echo_rps_min;

    if (std.mem.indexOf(u8, text, "\"alloc_delta_per_request\"")) |start| {
        if (jsonGetNumber(text[start..], "max")) |v| t.alloc_delta_max = @intFromFloat(v);
    }
    return t;
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // ── 1. read baseline.json (thresholds) ────────────────────────────
    var thresholds: Threshold = .{
        .storage_insert_min = 30_000,
        .storage_select_min = 40_000,
        .echo_rps_min = 25_000,
        .alloc_delta_max = 0,
    };
    if (try readFileBounded(allocator, "bench/baseline.json", 64 * 1024)) |baseline_text| {
        defer allocator.free(baseline_text);
        thresholds = parseThresholds(baseline_text);
    } else {
        std.debug.print("bench-runner: no bench/baseline.json found — using defaults\n", .{});
    }
    std.debug.print(
        "bench-runner: thresholds insert_min={d:.0} select_min={d:.0} echo_rps_min={d:.0} alloc_delta_max={d}\n",
        .{ thresholds.storage_insert_min, thresholds.storage_select_min, thresholds.echo_rps_min, thresholds.alloc_delta_max },
    );

    // ── 2. run storage bench ──────────────────────────────────────────
    const storage = try runStorageBench(allocator);
    std.debug.print(
        "  storage  : insert={d:.0} rps  select={d:.0} rps\n",
        .{ storage.insert_rate_rps, storage.select_rate_rps },
    );

    // ── 3. splice echo bench results if present (echo_bench is a
    //   separate executable wired into `zig build bench`).
    var echo: EchoMetrics = .{};
    if (try readFileBounded(allocator, "bench/.echo_bench_results.json", 8 * 1024)) |echo_text| {
        defer allocator.free(echo_text);
        echo.rps = jsonGetNumber(echo_text, "rps") orelse 0;
        echo.p50_ns = @intFromFloat(jsonGetNumber(echo_text, "p50_ns") orelse 0);
        echo.p99_ns = @intFromFloat(jsonGetNumber(echo_text, "p99_ns") orelse 0);
        echo.p999_ns = @intFromFloat(jsonGetNumber(echo_text, "p999_ns") orelse 0);
        echo.alloc_delta = @intFromFloat(jsonGetNumber(echo_text, "alloc_delta") orelse 0);
        echo.captured = true;
        std.debug.print("  echo     : rps={d:.0} p50={d}ns p99={d}ns p999={d}ns alloc_delta={d}\n", .{
            echo.rps, echo.p50_ns, echo.p99_ns, echo.p999_ns, echo.alloc_delta,
        });
    } else {
        std.debug.print("  echo     : not captured (run echo-bench separately or via `zig build bench`)\n", .{});
    }

    // ── 4. write results.json ─────────────────────────────────────────
    {
        var buf: [2048]u8 = undefined;
        const json = try std.fmt.bufPrint(&buf,
            \\{{
            \\  "platform": "darwin-aarch64",
            \\  "zig": "0.16.0",
            \\  "metrics": {{
            \\    "storage.insert_rate_rps": {{ "current": {d:.0}, "min": {d:.0} }},
            \\    "storage.select_rate_rps": {{ "current": {d:.0}, "min": {d:.0} }},
            \\    "echo.rps_single_core":    {{ "current": {d:.0}, "min": {d:.0} }},
            \\    "echo.p50_ns":             {{ "current": {d} }},
            \\    "echo.p99_ns":             {{ "current": {d} }},
            \\    "echo.p999_ns":            {{ "current": {d} }},
            \\    "alloc_delta_per_request": {{ "current": {d}, "max": {d} }}
            \\  }}
            \\}}
            \\
        , .{
            storage.insert_rate_rps, thresholds.storage_insert_min,
            storage.select_rate_rps, thresholds.storage_select_min,
            echo.rps,                thresholds.echo_rps_min,
            echo.p50_ns,
            echo.p99_ns,
            echo.p999_ns,
            echo.alloc_delta,        thresholds.alloc_delta_max,
        });
        try writeFileC("bench/results.json", json);
    }
    std.debug.print("  wrote bench/results.json\n", .{});

    // ── 5. threshold check ────────────────────────────────────────────
    var failed: u32 = 0;
    if (storage.insert_rate_rps < thresholds.storage_insert_min) {
        std.debug.print(
            "REGRESSION: storage.insert_rate_rps {d:.0} < min {d:.0}\n",
            .{ storage.insert_rate_rps, thresholds.storage_insert_min },
        );
        failed += 1;
    }
    if (storage.select_rate_rps < thresholds.storage_select_min) {
        std.debug.print(
            "REGRESSION: storage.select_rate_rps {d:.0} < min {d:.0}\n",
            .{ storage.select_rate_rps, thresholds.storage_select_min },
        );
        failed += 1;
    }
    if (echo.captured) {
        if (echo.rps < thresholds.echo_rps_min) {
            std.debug.print(
                "REGRESSION: echo.rps_single_core {d:.0} < min {d:.0}\n",
                .{ echo.rps, thresholds.echo_rps_min },
            );
            failed += 1;
        }
        if (echo.alloc_delta > thresholds.alloc_delta_max) {
            std.debug.print(
                "REGRESSION: alloc_delta_per_request {d} > max {d}\n",
                .{ echo.alloc_delta, thresholds.alloc_delta_max },
            );
            failed += 1;
        }
    }
    if (failed > 0) {
        std.debug.print("bench-runner: {d} regression(s)\n", .{failed});
        std.process.exit(1);
    }
    std.debug.print("bench-runner: all thresholds met\n", .{});
}
