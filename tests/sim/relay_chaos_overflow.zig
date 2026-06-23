//! J2 — chaos sim: deliver firehose events faster than the relay
//! consumer can translate them; assert the drop-oldest counter
//! advances; then assert that a "subscriber" replaying from the
//! persistent table recovers every event.
//!
//! This isn't a deterministic byte-for-byte sim — the consumer
//! thread runs at its own pace + we deliberately push faster than
//! it can drain. Instead the assertions are:
//!
//!   * persistent `atp_firehose_events` count equals the producer
//!     append count (durable layer never drops)
//!   * `firehose_consumer_dropped_total` > 0 (the ring overflowed)
//!   * a synchronous replay from `firehose.readSince(0, ...)`
//!     yields every seq

const std = @import("std");
const core = @import("core");
const atproto = @import("protocol_atproto");
const activitypub = @import("protocol_activitypub");
const relay = @import("protocol_relay");
const c = @import("sqlite").c;

const burst_count: u32 = 2000; // far exceeds the consumer ring capacity (512)

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    try run(gpa.allocator());
    std.debug.print("relay_chaos_overflow: completed OK\n", .{});
}

fn run(gpa: std.mem.Allocator) !void {
    // The chaos sim runs the consumer on its own thread + the
    // producer on the main thread. SQLite is opened with
    // SQLITE_OPEN_NOMUTEX so we MUST give each thread its own
    // handle. We use a temp file so both handles see the same
    // database state via WAL.
    const tmp_path = "/tmp/speedy_chaos_sim.db";
    _ = std.c.unlink(tmp_path);
    const tmp_path_z: [:0]const u8 = "/tmp/speedy_chaos_sim.db";
    const db = try core.storage.sqlite.openWriter(tmp_path_z);
    defer core.storage.sqlite.closeDb(db);
    const consumer_db = try core.storage.sqlite.openWriter(tmp_path_z);
    defer core.storage.sqlite.closeDb(consumer_db);
    // D3: clear any stale L0 firehose store on these recycled handles.
    atproto.firehose.forgetStore(db);
    atproto.firehose.forgetStore(consumer_db);
    try applySchema(db);

    var sc = core.clock.SimClock.init(1_900_000_000);

    relay.ap_to_at.setRelayHost("relay.chaos");
    defer relay.ap_to_at.setRelayHost("");

    const consumer = try relay.firehose_consumer.start(gpa, consumer_db, sc.clock(), "relay.chaos");

    // Burst: append events as fast as the producer can without
    // waiting for the consumer to drain.
    var i: u32 = 0;
    var ts: i64 = 1_900_000_000;
    while (i < burst_count) : (i += 1) {
        ts += 1;
        const did = "did:plc:chaos";
        var uri_buf: [256]u8 = undefined;
        const uri = try std.fmt.bufPrint(&uri_buf, "at://did:plc:chaos/app.bsky.feed.post/c{d}", .{i});
        const body = "{\"$type\":\"app.bsky.feed.post\",\"text\":\"chaos\",\"createdAt\":\"x\"}";
        try insertSyntheticRecord(db, uri, did, "app.bsky.feed.post", body, ts);
        _ = try atproto.firehose.append(db, did, "bafychaos", body, ts);
    }

    // Hold the consumer thread for a beat to let it drain some.
    var req: std.c.timespec = .{ .sec = 1, .nsec = 0 };
    _ = std.c.nanosleep(&req, &req);

    // Snapshot the stats BEFORE stop — the stop call frees the
    // consumer struct so the atomic fields would dangle.
    const dropped = consumer.stats.dropped.load(.monotonic);
    const enqueued = consumer.stats.enqueued.load(.monotonic);
    const translated_ok = consumer.stats.translated_ok.load(.monotonic);

    relay.firehose_consumer.stop(gpa);

    // D3: flush the L0 ring so the batched tail is durable before we
    // assert on the table. Persistent count = producer count (the
    // durable layer never drops).
    try atproto.firehose.flush(db);
    const persistent_count = try countAll(db, "SELECT count(*) FROM atp_firehose_events");
    if (persistent_count != @as(i64, @intCast(burst_count))) {
        std.debug.print("FAIL: persistent count {d} != {d}\n", .{ persistent_count, burst_count });
        return error.ChaosPersistentLoss;
    }

    // Ring-overflow drops should have happened (the ring is 512;
    // we shoved 2000 in fast). The consumer stats counter records it.
    if (dropped == 0) {
        std.debug.print("FAIL: expected drop-oldest counter > 0; got 0\n", .{});
        return error.ChaosExpectedDrops;
    }

    // Replay from the persistent table — a recovering subscriber
    // sees every seq from 1..N.
    var rows: [4096]atproto.firehose.Event = undefined;
    const n = try atproto.firehose.readSince(db, 0, &rows);
    if (n != burst_count) {
        std.debug.print("FAIL: replay count {d} != {d}\n", .{ n, burst_count });
        return error.ChaosReplayShort;
    }

    std.debug.print(
        "chaos: persistent={d} dropped={d} enqueued={d} translated_ok={d} replay={d}\n",
        .{ persistent_count, dropped, enqueued, translated_ok, n },
    );
}

fn applySchema(db: *c.sqlite3) !void {
    inline for ([_]type{ atproto.schema, activitypub.schema, relay.schema }) |Module| {
        for (Module.all_migrations) |m| {
            const sql_z = try std.heap.page_allocator.dupeZ(u8, m.up);
            defer std.heap.page_allocator.free(sql_z);
            var errmsg: [*c]u8 = null;
            _ = c.sqlite3_exec(db, sql_z.ptr, null, null, &errmsg);
            if (errmsg != null) c.sqlite3_free(errmsg);
        }
    }
}

fn insertSyntheticRecord(db: *c.sqlite3, uri: []const u8, did: []const u8, collection: []const u8, value: []const u8, indexed_at: i64) !void {
    const sql = "INSERT INTO atp_records (uri, did, collection, rkey, cid, value, indexed_at) VALUES (?,?,?,'rk','bafycid', ?, ?)";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, uri.ptr, @intCast(uri.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 2, did.ptr, @intCast(did.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 3, collection.ptr, @intCast(collection.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_blob(stmt, 4, value.ptr, @intCast(value.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(stmt, 5, indexed_at);
    if (c.sqlite3_step(stmt.?) != c.SQLITE_DONE) return error.StepFailed;
}

fn countAll(db: *c.sqlite3, sql: []const u8) !i64 {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql_z = try std.heap.page_allocator.dupeZ(u8, sql);
    defer std.heap.page_allocator.free(sql_z);
    if (c.sqlite3_prepare_v2(db, sql_z.ptr, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    if (c.sqlite3_step(stmt.?) != c.SQLITE_ROW) return -1;
    return c.sqlite3_column_int64(stmt, 0);
}

test "J2: chaos overflow runs" {
    try run(std.testing.allocator);
}
