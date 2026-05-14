//! Storage layer benchmark.
//!
//! Inserts N rows into a synthetic table, then selects them all back via
//! query_one. Demonstrates two invariants of the storage layer:
//!
//!   1. End-to-end throughput is reasonable on commodity hardware.
//!   2. After boot completes (DB open, statements prepared, writer
//!      thread started), the hot path does *no* allocations.
//!
//! We enforce (2) by wrapping the GPA in a `PoisonAllocator` whose
//! `alloc` panics. We swap the poison allocator in just before the hot
//! loop and swap it back out after. Any hidden allocation aborts.

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

const PoisonState = struct {
    underlying: std.mem.Allocator,
    poisoned: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

fn poisonAlloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
    const self: *PoisonState = @ptrCast(@alignCast(ctx));
    if (self.poisoned.load(.acquire)) {
        std.debug.print("\nPOISON: allocation of {d} bytes on hot path!\n", .{len});
        @panic("hot-path allocation");
    }
    return self.underlying.rawAlloc(len, alignment, ra);
}
fn poisonResize(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
    const self: *PoisonState = @ptrCast(@alignCast(ctx));
    return self.underlying.rawResize(buf, alignment, new_len, ra);
}
fn poisonRemap(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
    const self: *PoisonState = @ptrCast(@alignCast(ctx));
    return self.underlying.rawRemap(buf, alignment, new_len, ra);
}
fn poisonFree(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, ra: usize) void {
    const self: *PoisonState = @ptrCast(@alignCast(ctx));
    return self.underlying.rawFree(buf, alignment, ra);
}

fn poisonAllocator(state: *PoisonState) std.mem.Allocator {
    return .{
        .ptr = state,
        .vtable = &.{
            .alloc = poisonAlloc,
            .resize = poisonResize,
            .remap = poisonRemap,
            .free = poisonFree,
        },
    };
}

fn nowNs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(std.c.CLOCK.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();

    var poison: PoisonState = .{ .underlying = gpa.allocator() };
    _ = poisonAllocator(&poison);

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

    // --- arm the allocator poison: nothing past this should alloc ---
    poison.poisoned.store(true, .release);
    defer poison.poisoned.store(false, .release);

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

    // Disarm before printing (printf may alloc).
    poison.poisoned.store(false, .release);

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
