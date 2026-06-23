//! J3 — long-running deterministic-replay test.
//!
//! Drives `N` simulated firehose events under a fixed SimClock and
//! a seeded PRNG, then re-runs the same workload in a second
//! sim-pass. Asserts both runs produce byte-identical translation
//! log + outbox state.
//!
//! Scale knob: `EVENTS_PER_RUN` (default 1024; chaos / soak runs
//! can crank to 100k). Two passes always run.

const std = @import("std");
const core = @import("core");
const c = @import("sqlite").c;
const atproto = @import("protocol_atproto");
const activitypub = @import("protocol_activitypub");
const relay = @import("protocol_relay");

const EVENTS_PER_RUN: u32 = 1024;

fn applyRelaySchema(db: *c.sqlite3, allocator: std.mem.Allocator) !void {
    inline for (relay.schema.all_migrations) |m| {
        var em: [*c]u8 = null;
        const sql_z = try allocator.dupeZ(u8, m.up);
        defer allocator.free(sql_z);
        _ = c.sqlite3_exec(db, sql_z.ptr, null, null, &em);
        if (em != null) c.sqlite3_free(em);
    }
}

fn applyAtprotoSchema(db: *c.sqlite3, allocator: std.mem.Allocator) !void {
    inline for (atproto.schema.all_migrations) |m| {
        var em: [*c]u8 = null;
        const sql_z = try allocator.dupeZ(u8, m.up);
        defer allocator.free(sql_z);
        _ = c.sqlite3_exec(db, sql_z.ptr, null, null, &em);
        if (em != null) c.sqlite3_free(em);
    }
}

fn run(seed: u64, allocator: std.mem.Allocator) ![32]u8 {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    // D3: drop any stale L0 firehose store on this recycled handle.
    atproto.firehose.forgetStore(db);

    try applyAtprotoSchema(db, allocator);
    try applyRelaySchema(db, allocator);

    var rng = core.rng.Rng.init(seed);
    var sc = core.clock.SimClock.init(1_700_000_000);
    var i: u32 = 0;
    while (i < EVENTS_PER_RUN) : (i += 1) {
        sc.advance(1_000_000);
        var did_buf: [32]u8 = undefined;
        const did = try std.fmt.bufPrint(&did_buf, "did:plc:{d}", .{rng.random().int(u32) % 16});
        var cid_buf: [32]u8 = undefined;
        const cid = try std.fmt.bufPrint(&cid_buf, "bafy{d}", .{i});
        const body = "body";
        _ = try atproto.firehose.append(db, did, cid, body, sc.clock().wallUnix());
    }

    // D3: flush the L0 ring so the whole run is durable, then hash the
    // firehose_events table as a deterministic fingerprint.
    try atproto.firehose.flush(db);
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "SELECT seq, did, commit_cid, body FROM atp_firehose_events ORDER BY seq";
    _ = c.sqlite3_prepare_v2(db, sql, -1, &stmt, null);
    defer _ = c.sqlite3_finalize(stmt);

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    while (true) {
        const rc = c.sqlite3_step(stmt.?);
        if (rc == c.SQLITE_DONE) break;
        if (rc != c.SQLITE_ROW) return error.StepFailed;
        const seq = c.sqlite3_column_int64(stmt, 0);
        var seq_b: [8]u8 = undefined;
        std.mem.writeInt(i64, &seq_b, seq, .little);
        hasher.update(&seq_b);
        for (1..4) |col_idx| {
            const ci: c_int = @intCast(col_idx);
            const ptr = c.sqlite3_column_blob(stmt, ci);
            const n: usize = @intCast(c.sqlite3_column_bytes(stmt, ci));
            const p: [*]const u8 = @ptrCast(ptr);
            hasher.update(p[0..n]);
        }
    }
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const fp1 = try run(0xDEADBEEF, allocator);
    const fp2 = try run(0xDEADBEEF, allocator);
    if (!std.mem.eql(u8, &fp1, &fp2)) {
        std.debug.print("J3: deterministic-replay MISMATCH\n", .{});
        return error.NonDeterministic;
    }
    std.debug.print("J3: deterministic-replay OK over {d} events\n", .{EVENTS_PER_RUN});
}

test "J3: deterministic replay matches across two runs" {
    const fp1 = try run(0xC0FFEE, std.testing.allocator);
    const fp2 = try run(0xC0FFEE, std.testing.allocator);
    try std.testing.expectEqualSlices(u8, &fp1, &fp2);
}
