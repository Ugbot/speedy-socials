//! W5.3 — relay bridge end-to-end simulation.
//!
//! Drives both directions of the AP↔AT bridge against an in-memory
//! SQLite database under a deterministic SimClock, asserting that
//! the `relay_translation_log` accumulates one row per translated
//! event with the expected direction + source / translated IDs.
//!
//! Scenario A — AT→AP:
//!   1. Insert a synthetic AT record into `atp_records` (collection
//!      = `app.bsky.feed.post`).
//!   2. Append a firehose event for the same did + ts. This fires
//!      the in-process sink the relay's `firehose_consumer` installs.
//!   3. Spin until the consumer drains the ring and writes an
//!      `at_to_ap` log row.
//!
//! Scenario B — AP→AT:
//!   1. Construct an AP `Create{Note}` activity in-memory.
//!   2. Invoke `relay.ap_to_at.onActivityReceived` directly (matches
//!      the production path: the AP inbox handler calls it after the
//!      state machine + side-effect drain).
//!   3. Assert an `ap_to_at` log row landed with the expected
//!      collection in the translated AT URI.
//!
//! Determinism: SimClock + the relay's per-record translator are
//! both pure; the only non-deterministic edge is the consumer's
//! poll-sleep loop, which we paper over with a bounded spin in the
//! producer thread (re-checks counters until they advance).
//!
//! Wired into `zig build sim` alongside `firehose_subscriber.zig`
//! and `federate_with_mastodon.zig`.

const std = @import("std");
const core = @import("core");
const atproto = @import("protocol_atproto");
const activitypub = @import("protocol_activitypub");
const relay = @import("protocol_relay");
const c = @import("sqlite").c;

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    try run(gpa.allocator());
    std.debug.print("relay_bridge_scenario: completed OK\n", .{});
}

fn run(gpa: std.mem.Allocator) !void {
    const db = try openSchemaDb();
    defer core.storage.sqlite.closeDb(db);

    var sc = core.clock.SimClock.init(1_715_000_000);

    relay.ap_to_at.setRelayHost("relay.sim");
    defer relay.ap_to_at.setRelayHost("");

    // W6: configure an AP bridge target so AT→AP enqueues a real
    // ap_federation_outbox row we can assert on later.
    relay.firehose_consumer.setBridgeTargetInbox("https://upstream.bridge/inbox");
    defer relay.firehose_consumer.setBridgeTargetInbox("");

    // ── Scenario A: AT → AP ────────────────────────────────────────
    // Run the consumer thread; assert one translation; then STOP the
    // thread before Scenario B so the AT-side writes there don't
    // race the consumer's atp_records reads on a NOMUTEX sqlite
    // handle. The relay's production race-free path is single-thread
    // per writer; this test mirrors that.
    const consumer = try relay.firehose_consumer.start(gpa, db, sc.clock(), "relay.sim");

    const a_did = "did:plc:scenario_a_actor";
    const a_uri = "at://did:plc:scenario_a_actor/app.bsky.feed.post/aaa111";
    const a_value = "{\"$type\":\"app.bsky.feed.post\",\"text\":\"hello from AT\",\"createdAt\":\"2026-05-16T00:00:00Z\"}";
    const a_ts: i64 = 1_715_000_100;
    try insertSyntheticRecord(db, a_uri, a_did, "app.bsky.feed.post", a_value, a_ts);
    _ = try atproto.firehose.append(db, a_did, "bafyA", a_value, a_ts);

    if (!waitUntil(&consumer.stats.translated_ok, 1, 500)) {
        std.debug.print("FAIL: AT→AP consumer did not translate within budget\n", .{});
        relay.firehose_consumer.stop(gpa);
        return error.ScenarioFailedAtToAp;
    }

    // Joining the consumer makes scenario B's commits exclusive.
    relay.firehose_consumer.stop(gpa);

    // ── Scenario B: AP → AT ────────────────────────────────────────
    const ap_act: activitypub.activity.Activity = .{
        .activity_type = .create,
        .id = "https://mastodon.sim/users/bob/activities/9",
        .actor = "https://mastodon.sim/users/bob",
        .object_id = "https://mastodon.sim/users/bob/notes/9",
        .object_type = "Note",
        .target = "",
        .published = "2026-05-16T00:01:00Z",
        .to_first = "https://www.w3.org/ns/activitystreams#Public",
    };
    relay.ap_to_at.onActivityReceived(&ap_act, "", db, sc.clock());

    // ── Scenario B': Update mutates the same row ──────────────────
    const ap_update: activitypub.activity.Activity = .{
        .activity_type = .update,
        .id = "https://mastodon.sim/users/bob/activities/10",
        .actor = "https://mastodon.sim/users/bob",
        .object_id = "https://mastodon.sim/users/bob/notes/9",
        .object_type = "Note",
        .target = "",
        .published = "2026-05-16T00:02:00Z",
        .to_first = "",
    };
    const update_body =
        "{\"type\":\"Update\",\"actor\":\"https://mastodon.sim/users/bob\"," ++
        "\"object\":{\"id\":\"https://mastodon.sim/users/bob/notes/9\"," ++
        "\"type\":\"Note\",\"content\":\"edited content for the bridge\"}}";
    relay.ap_to_at.onActivityReceived(&ap_update, update_body, db, sc.clock());

    // ── Scenario B'': Follow + Undo lifecycle ─────────────────────
    const ap_follow: activitypub.activity.Activity = .{
        .activity_type = .follow,
        .id = "https://mastodon.sim/follow/1",
        .actor = "https://mastodon.sim/users/alice",
        .object_id = "https://relay.sim/ap/users/at:plc:bridged",
        .object_type = "Person",
        .target = "",
        .published = "",
        .to_first = "",
    };
    relay.ap_to_at.onActivityReceived(&ap_follow, "", db, sc.clock());
    const ap_undo: activitypub.activity.Activity = .{
        .activity_type = .undo,
        .id = "https://mastodon.sim/undo/1",
        .actor = "https://mastodon.sim/users/alice",
        .object_id = "https://mastodon.sim/follow/1",
        .object_type = "",
        .target = "",
        .published = "",
        .to_first = "",
    };
    relay.ap_to_at.onActivityReceived(&ap_undo, "", db, sc.clock());

    // ── Scenario B''': Delete removes the bridged record ──────────
    const ap_delete: activitypub.activity.Activity = .{
        .activity_type = .delete,
        .id = "https://mastodon.sim/users/bob/activities/11",
        .actor = "https://mastodon.sim/users/bob",
        .object_id = "https://mastodon.sim/users/bob/notes/9",
        .object_type = "Tombstone",
        .target = "",
        .published = "",
        .to_first = "",
    };
    relay.ap_to_at.onActivityReceived(&ap_delete, "", db, sc.clock());

    // ── Verify both log rows exist with the expected shapes ────────
    var rows: [16]relay.subscription.LogEntry = undefined;
    const n = try relay.subscription.listLog(db, 0, &rows);
    if (n < 2) {
        std.debug.print("FAIL: expected ≥2 translation log rows, got {d}\n", .{n});
        return error.ScenarioFailedLogCount;
    }

    var saw_at_to_ap = false;
    var saw_ap_to_at = false;
    for (rows[0..n]) |row| {
        switch (row.direction) {
            .at_to_ap => {
                if (std.mem.eql(u8, row.sourceId(), a_uri)) saw_at_to_ap = true;
            },
            .ap_to_at => {
                if (std.mem.indexOf(u8, row.translatedId(), "app.bsky.feed.post") != null) saw_ap_to_at = true;
            },
        }
    }
    if (!saw_at_to_ap) {
        std.debug.print("FAIL: missing at_to_ap entry for {s}\n", .{a_uri});
        return error.ScenarioFailedAtToAp;
    }
    if (!saw_ap_to_at) {
        std.debug.print("FAIL: missing ap_to_at entry for Create{{Note}}\n", .{});
        return error.ScenarioFailedApToAt;
    }

    // W6: the AT→AP path enqueued an AP federation outbox row; the
    // AP→AT path committed a real atp_records row.
    const outbox_count = try countRows(db, "SELECT count(*) FROM ap_federation_outbox WHERE target_inbox = ?", "https://upstream.bridge/inbox");
    if (outbox_count != 1) {
        std.debug.print("FAIL: expected 1 ap_federation_outbox row, got {d}\n", .{outbox_count});
        return error.ScenarioFailedOutbox;
    }
    // After Create → Update → Delete, the post row should be GONE
    // (Delete probed app.bsky.feed.post and removed it). The
    // app.bsky.graph.follow row from Follow is also gone (Undo
    // removed the follower table row but the AT record was just
    // logged, not committed back). Only the seeded scenario-A row
    // remains.
    const atp_records_count = try countRows(db, "SELECT count(*) FROM atp_records WHERE collection = ?", "app.bsky.feed.post");
    if (atp_records_count != 1) {
        std.debug.print("FAIL: expected 1 atp_records row after Create→Update→Delete, got {d}\n", .{atp_records_count});
        return error.ScenarioFailedAtRecords;
    }
    // The full lifecycle produced multiple translation-log entries.
    if (n < 4) {
        std.debug.print("FAIL: expected ≥4 translation log rows after extended lifecycle, got {d}\n", .{n});
        return error.ScenarioFailedLogCount;
    }

    std.debug.print(
        "relay bridge: log rows={d}; ap_federation_outbox enqueued={d}; atp_records (post)={d}\n",
        .{ n, outbox_count, atp_records_count },
    );
}

fn countRows(db: *c.sqlite3, sql: []const u8, param: []const u8) !i64 {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql_z = try std.heap.page_allocator.dupeZ(u8, sql);
    defer std.heap.page_allocator.free(sql_z);
    if (c.sqlite3_prepare_v2(db, sql_z.ptr, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, param.ptr, @intCast(param.len), c.sqliteTransientAsDestructor());
    if (c.sqlite3_step(stmt.?) != c.SQLITE_ROW) return -1;
    return c.sqlite3_column_int64(stmt, 0);
}

// ── Helpers ───────────────────────────────────────────────────────

fn openSchemaDb() !*c.sqlite3 {
    const db = try core.storage.sqlite.openWriter(":memory:");
    inline for ([_]type{
        atproto.schema,
        activitypub.schema,
        relay.schema,
    }) |Module| {
        for (Module.all_migrations) |m| {
            const sql_z = try std.heap.page_allocator.dupeZ(u8, m.up);
            defer std.heap.page_allocator.free(sql_z);
            var errmsg: [*c]u8 = null;
            _ = c.sqlite3_exec(db, sql_z.ptr, null, null, &errmsg);
            if (errmsg != null) c.sqlite3_free(errmsg);
        }
    }
    return db;
}

fn insertSyntheticRecord(
    db: *c.sqlite3,
    uri: []const u8,
    did: []const u8,
    collection: []const u8,
    value: []const u8,
    indexed_at: i64,
) !void {
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

fn waitUntil(counter: *std.atomic.Value(u64), target: u64, max_attempts: u32) bool {
    var i: u32 = 0;
    while (i < max_attempts) : (i += 1) {
        if (counter.load(.monotonic) >= target) return true;
        var req: std.c.timespec = .{ .sec = 0, .nsec = 2 * std.time.ns_per_ms };
        _ = std.c.nanosleep(&req, &req);
    }
    return false;
}

test "relay_bridge_scenario: deterministic AT→AP + AP→AT under SimClock" {
    try run(std.testing.allocator);
}
