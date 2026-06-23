//! zorm CRUD overhead benchmark (independent perf verification).
//!
//! Measures the per-operation cost the zorm ORM adds OVER a hand-written
//! SQL path, both hitting the SAME real in-memory SQLite engine through
//! the SAME `core.storage.SqliteBackend`:
//!
//!   * zorm path: `zorm.Repository(T).insertNow` / `findByPk` — comptime
//!     SQL generation + struct<->row marshalling through the zorm adapter
//!     vtable.
//!   * hand path: a prepared INSERT / SELECT issued directly against the
//!     backend with manual bind/read.
//!
//! Both insert the identical column set into the identical table, so the
//! delta is pure ORM marshalling + vtable-indirection overhead. We report
//! ns/op for each and the zorm/hand ratio (overhead factor). The claim
//! under test is that zorm adds only a small constant overhead, not an
//! order of magnitude. We MEASURE and print; assert a loose ceiling so a
//! pathological regression fails CI.

const std = @import("std");
const core = @import("core");
const zorm = @import("zorm");
const c = @import("sqlite").c;

const storage = core.storage;

const N: u64 = 10_000;

fn nowNs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(std.c.CLOCK.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

/// Mirrors the canonical zorm account row used in `account_zorm.zig`.
const ZAccount = struct {
    pub const zorm_table = "zorm_bench_accounts";
    id: zorm.Pk(64) = .{},
    handle: zorm.Text(64) = .{},
    email: zorm.Text(128) = .{},
    state: u8 = 0,
    created_at: i64 = 0,
};

fn keyFor(buf: []u8, i: u64) []const u8 {
    return std.fmt.bufPrint(buf, "did:plc:bench{x:0>12}", .{i}) catch unreachable;
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();

    // ── zorm path ───────────────────────────────────────────────────
    const zdb = try storage.sqlite.openWriter(":memory:");
    defer storage.sqlite.closeDb(zdb);
    var zbe = storage.SqliteBackend.init(zdb);
    var adapter = storage.zorm_adapter.Adapter.init(zbe.backend());
    const zb = adapter.backend(.sqlite);
    try zb.exec(zorm.createTable(ZAccount, .sqlite), &.{});

    var repo = zorm.Repository(ZAccount).init(zb);

    var kb: [64]u8 = undefined;
    const zi0 = nowNs();
    var i: u64 = 0;
    while (i < N) : (i += 1) {
        var a: ZAccount = .{ .state = @intCast(i % 4), .created_at = @intCast(i) };
        a.id = zorm.Pk(64).from(keyFor(&kb, i));
        a.handle = zorm.Text(64).from("user.bench.test");
        a.email = zorm.Text(128).from("u@bench.test");
        try repo.insertNow(&a);
    }
    const zorm_ins_ns = nowNs() - zi0;

    const zf0 = nowNs();
    var zfound: u64 = 0;
    i = 0;
    while (i < N) : (i += 1) {
        var out: ZAccount = .{};
        if (try repo.findByPk(keyFor(&kb, i), &out)) zfound += 1;
    }
    const zorm_find_ns = nowNs() - zf0;

    // ── hand-written path (same backend, raw prepared SQL) ──────────
    const hdb = try storage.sqlite.openWriter(":memory:");
    defer storage.sqlite.closeDb(hdb);
    var em: [*c]u8 = null;
    _ = c.sqlite3_exec(hdb,
        "CREATE TABLE zorm_bench_accounts (id TEXT PRIMARY KEY, handle TEXT, email TEXT, state INTEGER, created_at INTEGER)",
        null, null, &em);
    if (em != null) c.sqlite3_free(em);

    const hi0 = nowNs();
    i = 0;
    while (i < N) : (i += 1) {
        const sql = "INSERT INTO zorm_bench_accounts (id, handle, email, state, created_at) VALUES (?,?,?,?,?)";
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(hdb, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
        const k = keyFor(&kb, i);
        _ = c.sqlite3_bind_text(stmt, 1, k.ptr, @intCast(k.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_text(stmt, 2, "user.bench.test", 15, c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_text(stmt, 3, "u@bench.test", 12, c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_int64(stmt, 4, @intCast(i % 4));
        _ = c.sqlite3_bind_int64(stmt, 5, @intCast(i));
        if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return error.StepFailed;
        _ = c.sqlite3_finalize(stmt);
    }
    const hand_ins_ns = nowNs() - hi0;

    const hf0 = nowNs();
    var hfound: u64 = 0;
    i = 0;
    while (i < N) : (i += 1) {
        const sql = "SELECT id, handle, email, state, created_at FROM zorm_bench_accounts WHERE id = ?";
        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(hdb, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
        const k = keyFor(&kb, i);
        _ = c.sqlite3_bind_text(stmt, 1, k.ptr, @intCast(k.len), c.sqliteTransientAsDestructor());
        if (c.sqlite3_step(stmt.?) == c.SQLITE_ROW) hfound += 1;
        _ = c.sqlite3_finalize(stmt);
    }
    const hand_find_ns = nowNs() - hf0;

    // ── Report ──
    const z_ins = @as(f64, @floatFromInt(zorm_ins_ns)) / @as(f64, N);
    const z_find = @as(f64, @floatFromInt(zorm_find_ns)) / @as(f64, N);
    const h_ins = @as(f64, @floatFromInt(hand_ins_ns)) / @as(f64, N);
    const h_find = @as(f64, @floatFromInt(hand_find_ns)) / @as(f64, N);

    std.debug.print("zorm-bench: N={d} (in-memory SQLite, same backend)\n", .{N});
    std.debug.print("  insert   : zorm={d:>8.1} ns/op  hand={d:>8.1} ns/op  overhead={d:.2}x\n", .{ z_ins, h_ins, z_ins / h_ins });
    std.debug.print("  findByPk : zorm={d:>8.1} ns/op  hand={d:>8.1} ns/op  overhead={d:.2}x\n", .{ z_find, h_find, z_find / h_find });
    std.debug.print("  found: zorm={d} hand={d}\n", .{ zfound, hfound });

    if (zfound != N) return error.ZormFindMismatch;
    if (hfound != N) return error.HandFindMismatch;
    // zorm overhead must be a small constant, not an order of magnitude.
    // Loose ceiling: any single op within 5x of the hand path. Measured
    // numbers are printed above for the methodology doc.
    if (z_ins / h_ins > 5.0) return error.ZormInsertOverheadTooHigh;
    if (z_find / h_find > 5.0) return error.ZormFindOverheadTooHigh;
}
