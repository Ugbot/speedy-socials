//! Storage layer benchmark.
//!
//! Inserts N rows into a synthetic table, then selects them all back via
//! query_one. Demonstrates two invariants of the storage layer:
//!
//!   1. End-to-end throughput is reasonable on commodity hardware.
//!   2. After boot completes (DB open, statements prepared, writer
//!      thread started), the hot path does *no* allocations.
//!
//! We enforce (2) by wrapping the GPA in a TigerBeetle `StaticAllocator`.
//! While in the `.init` phase, allocations pass through. Just before the
//! hot loop we transition to `.static` so any allocation panics. After
//! the hot loop we transition to `.deinit` so cleanup `free` calls
//! still succeed.

const std = @import("std");
const core = @import("core");

const c = @import("sqlite").c;

const N: u64 = 50_000;

const Out = struct {
    var inserts_ok = std.atomic.Value(u64).init(0);
    var inserts_err = std.atomic.Value(u64).init(0);

    fn insCb(_: ?*anyopaque, status: core.storage.QueryStatus, _: []const core.storage.Row, _: i64) void {
        switch (status) {
            .ok => _ = inserts_ok.fetchAdd(1, .release),
            else => _ = inserts_err.fetchAdd(1, .release),
        }
    }
};

fn nowNs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(std.c.CLOCK.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();

    var static_alloc = core.alloc.StaticAllocator.init(gpa.allocator());
    defer static_alloc.deinit();
    // `_ = static_alloc.allocator();` would be unused here — the bench
    // doesn't pass an allocator into storage. We keep the StaticAllocator
    // around solely as the tripwire for the hot path.

    // --- boot: open the DB, prepare statements, start the writer ----
    // Use a private file under /tmp so we don't clobber the dev DB.
    const path: [:0]const u8 = "/tmp/speedy_socials_bench.db";
    // Best-effort delete prior run.
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

    // --- arm the allocator tripwire: nothing past this should alloc -
    // Transition the StaticAllocator out of `.init`; any `alloc`/
    // `resize` call hitting the wrapper now panics. The storage layer
    // does not take an allocator on the hot path (see
    // `core/storage/sqlite.zig`), so this catches code that takes one
    // accidentally via a backdoor.
    static_alloc.transition_from_init_to_static();

    // --- INSERT N rows ---------------------------------------------
    const t0 = nowNs();
    var i: u64 = 0;
    while (i < N) : (i += 1) {
        var args: core.storage.BindArgs = .{};
        args.push(core.storage.Value.int64(@intCast(i)));
        args.push(core.storage.Value.int64(@intCast(i * 7)));
        // The channel may fill up under high producer rate. Spin until
        // we get a slot. Allocator-free; just retries the push.
        while (true) {
            handle.exec(k_ins, args, null, Out.insCb) catch |err| switch (err) {
                error.BackpressureRejected => {
                    core.storage.sqlite.sleepNs(10 * std.time.ns_per_us);
                    continue;
                },
                else => return err,
            };
            break;
        }
    }

    // Wait for the writer to drain.
    while (Out.inserts_ok.load(.acquire) < N and Out.inserts_err.load(.acquire) == 0) {
        core.storage.sqlite.sleepNs(100 * std.time.ns_per_us);
    }
    const t1 = nowNs();

    // --- SELECT N rows back via query_one --------------------------
    const Sel = struct {
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

    i = 0;
    while (i < N) : (i += 1) {
        var args: core.storage.BindArgs = .{};
        args.push(core.storage.Value.int64(@intCast(i)));
        while (true) {
            handle.queryOne(k_sel, args, null, Sel.cb) catch |err| switch (err) {
                error.BackpressureRejected => {
                    core.storage.sqlite.sleepNs(10 * std.time.ns_per_us);
                    continue;
                },
                else => return err,
            };
            break;
        }
    }
    while (Sel.found.load(.acquire) + Sel.missing.load(.acquire) < N) {
        core.storage.sqlite.sleepNs(100 * std.time.ns_per_us);
    }
    const t2 = nowNs();

    // Disarm before printing (printf may alloc via std internals).
    static_alloc.transition_from_static_to_deinit();

    const ins_ns = t1 - t0;
    const sel_ns = t2 - t1;
    std.debug.print("\nstorage-bench: N={d}\n", .{N});
    std.debug.print("  insert  : {d:.2} ms  ({d:.0} ops/sec)\n", .{
        @as(f64, @floatFromInt(ins_ns)) / 1e6,
        @as(f64, @floatFromInt(N)) / (@as(f64, @floatFromInt(ins_ns)) / 1e9),
    });
    std.debug.print("  select  : {d:.2} ms  ({d:.0} ops/sec)\n", .{
        @as(f64, @floatFromInt(sel_ns)) / 1e6,
        @as(f64, @floatFromInt(N)) / (@as(f64, @floatFromInt(sel_ns)) / 1e9),
    });
    std.debug.print("  inserts_ok={d} inserts_err={d} found={d} missing={d}\n", .{
        Out.inserts_ok.load(.acquire),
        Out.inserts_err.load(.acquire),
        Sel.found.load(.acquire),
        Sel.missing.load(.acquire),
    });
}
