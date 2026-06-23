//! J3 — long-running deterministic-replay simulation for the
//! AT→AP relay translate→outbox path.
//!
//! Where `deterministic_replay.zig` fingerprints only the raw
//! firehose-append table, THIS scenario drives the full relay
//! translation pipeline — `relay.handleFirehoseEvent` (the pure
//! translator + identity-map upsert + translation-log write) followed
//! by an `ap_federation_outbox` enqueue, exactly mirroring the
//! synchronous body of `firehose_consumer.processItem` minus the
//! thread + ring (which are timing-dependent and so deliberately
//! excluded from a determinism proof).
//!
//! A seeded `std.Random.DefaultPrng` (via `core.rng.Rng`) generates a
//! large firehose workload of randomized actors + record kinds. A
//! `SimClock` advances virtual time per event so timestamps stamped
//! into the translation log + outbox rows are reproducible without
//! real wall-time — the whole run completes in well under a second
//! while covering thousands of events ("1 hour simulated").
//!
//! Determinism assertion:
//!   1. Run the workload twice under the SAME seed, each against a
//!      fresh in-memory DB.
//!   2. Hash (SHA-256) the ordered `relay_translation_log` AND the
//!      ordered `ap_federation_outbox` into one combined fingerprint.
//!   3. Assert the two fingerprints are byte-identical.
//!   4. Assert a DIFFERENT seed yields a DIFFERENT fingerprint, so the
//!      test cannot pass trivially (e.g. if both runs produced nothing).
//!
//! Bounded; deterministic; no real network or broker.
//!
//! Wired into `zig build sim` and `zig build test` alongside the other
//! tests/sim/*.zig scenarios.

const std = @import("std");
const core = @import("core");
const c = @import("sqlite").c;
const atproto = @import("protocol_atproto");
const activitypub = @import("protocol_activitypub");
const relay = @import("protocol_relay");

const Arena = core.arena.Arena;

/// Number of firehose events driven per run. Large enough that
/// determinism is a meaningful property across thousands of distinct
/// actors / record kinds, small enough to finish in a fraction of a
/// second under an in-memory SQLite.
const EVENTS_PER_RUN: u32 = 4096;

/// Number of distinct synthetic actors the workload draws from. Keeping
/// this well below EVENTS_PER_RUN guarantees heavy identity-map reuse
/// (the same DID is seen many times), exercising the
/// `actorForDid`-hit branch of the translator, not only first-mint.
const DISTINCT_ACTORS: u32 = 64;

const RELAY_HOST = "relay.sim";
const BRIDGE_INBOX = "https://upstream.bridge/inbox";

/// Bridge-supported AT collections. We bias the workload toward `post`
/// (the only kind that produces content_html) but include the other
/// supported kinds so the translate path covers Like / Announce /
/// Follow shapes too. An occasional unsupported kind exercises the
/// `UnsupportedKind` → error-log branch.
const Kind = enum {
    post,
    like,
    repost,
    follow,
    unsupported,

    fn collection(self: Kind) []const u8 {
        return switch (self) {
            .post => "app.bsky.feed.post",
            .like => "app.bsky.feed.like",
            .repost => "app.bsky.feed.repost",
            .follow => "app.bsky.graph.follow",
            .unsupported => "app.bsky.feed.threadgate",
        };
    }
};

fn pickKind(r: std.Random) Kind {
    // Weighted: posts dominate a real firehose.
    const roll = r.intRangeLessThan(u32, 0, 100);
    if (roll < 60) return .post;
    if (roll < 75) return .like;
    if (roll < 88) return .repost;
    if (roll < 97) return .follow;
    return .unsupported;
}

fn applySchema(db: *c.sqlite3, allocator: std.mem.Allocator) !void {
    inline for ([_]type{
        atproto.schema,
        activitypub.schema,
        relay.schema,
    }) |Module| {
        for (Module.all_migrations) |m| {
            const sql_z = try allocator.dupeZ(u8, m.up);
            defer allocator.free(sql_z);
            var errmsg: [*c]u8 = null;
            if (c.sqlite3_exec(db, sql_z.ptr, null, null, &errmsg) != c.SQLITE_OK) {
                if (errmsg != null) c.sqlite3_free(errmsg);
                return error.SchemaFailed;
            }
            if (errmsg != null) c.sqlite3_free(errmsg);
        }
    }
}

fn insertRecord(
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

/// Build a deterministic record body for the kind. `post` carries text
/// (so content_html is non-trivial); `like`/`repost` carry a subject;
/// `follow` carries a subject DID. Bytes are derived from the seed-driven
/// PRNG so the body — and thus everything downstream — is reproducible.
fn buildBody(buf: []u8, kind: Kind, did: []const u8, n: u32, created_at: []const u8) ![]const u8 {
    return switch (kind) {
        .post => std.fmt.bufPrint(buf,
            "{{\"$type\":\"app.bsky.feed.post\",\"text\":\"post {d} from {s}\",\"createdAt\":\"{s}\"}}",
            .{ n, did, created_at }),
        .like => std.fmt.bufPrint(buf,
            "{{\"$type\":\"app.bsky.feed.like\",\"subject\":{{\"uri\":\"at://did:plc:t/app.bsky.feed.post/{d}\"}},\"createdAt\":\"{s}\"}}",
            .{ n, created_at }),
        .repost => std.fmt.bufPrint(buf,
            "{{\"$type\":\"app.bsky.feed.repost\",\"subject\":{{\"uri\":\"at://did:plc:t/app.bsky.feed.post/{d}\"}},\"createdAt\":\"{s}\"}}",
            .{ n, created_at }),
        .follow => std.fmt.bufPrint(buf,
            "{{\"$type\":\"app.bsky.graph.follow\",\"subject\":\"did:plc:followee{d}\",\"createdAt\":\"{s}\"}}",
            .{ n % DISTINCT_ACTORS, created_at }),
        .unsupported => std.fmt.bufPrint(buf, "{{}}", .{}),
    };
}

/// Drive the full AT→AP translate→outbox path once and return a
/// SHA-256 fingerprint of (translation_log ++ federation_outbox).
fn run(seed: u64, allocator: std.mem.Allocator) ![32]u8 {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    atproto.firehose.forgetStore(db); // clear stale L0 store on recycled handle

    try applySchema(db, allocator);

    var rng = core.rng.Rng.init(seed);
    const r = rng.random();
    var sc = core.clock.SimClock.init(1_700_000_000);

    var arena_buf: [64 * 1024]u8 = undefined;
    var did_buf: [64]u8 = undefined;
    var uri_buf: [256]u8 = undefined;
    var cid_buf: [64]u8 = undefined;
    var iso_buf: [32]u8 = undefined;
    var body_buf: [4096]u8 = undefined;

    var i: u32 = 0;
    while (i < EVENTS_PER_RUN) : (i += 1) {
        // Advance virtual time. Variable steps keep timestamps moving
        // forward deterministically; over EVENTS_PER_RUN this spans
        // roughly an hour of simulated firehose activity.
        sc.advance(r.intRangeAtMost(u64, 200, 1500) * std.time.ns_per_ms);
        const ts = sc.clock().wallUnix();

        const actor_idx = r.intRangeLessThan(u32, 0, DISTINCT_ACTORS);
        const kind = pickKind(r);
        const did = try std.fmt.bufPrint(&did_buf, "did:plc:actor{d}", .{actor_idx});
        const collection = kind.collection();
        // Per-record rkey keeps every AT-URI unique (the translation
        // log dedups on source_id, so reused URIs would be skipped).
        const uri = try std.fmt.bufPrint(&uri_buf, "at://{s}/{s}/rk{d}", .{ did, collection, i });
        const cid = try std.fmt.bufPrint(&cid_buf, "bafy{d}", .{i});
        // Deterministic ISO timestamp from the sim clock seconds.
        const iso = try std.fmt.bufPrint(&iso_buf, "2026-01-01T00:00:{d:0>2}Z", .{@as(u64, @intCast(@mod(ts, 60)))});
        const body = try buildBody(&body_buf, kind, did, i, iso);

        // Persist the record + a firehose event, exactly as the AT repo
        // writer would. The firehose append gives us a real seq; the
        // record row is what the consumer re-queries by (did, indexed_at).
        try insertRecord(db, uri, did, collection, body, ts);
        _ = try atproto.firehose.append(db, did, cid, body, ts);

        // ── Synchronous translate→outbox (mirrors processItem) ──────
        // Dedup guard: same as the consumer's hasSuccessfulLog check.
        if (relay.subscription.hasSuccessfulLog(db, .at_to_ap, uri)) continue;

        var arena = Arena.init(&arena_buf);
        const ev: relay.FirehoseEvent = .{
            .at_uri = uri,
            .did = did,
            .collection = collection,
            .record_json = body,
            .fallback_created_at = iso,
        };
        const out = relay.handleFirehoseEvent(db, sc.clock(), RELAY_HOST, ev, &arena) catch |err| switch (err) {
            error.UnsupportedKind => {
                // Mirror the consumer: log the unsupported collection so
                // it shows in the translation log rather than vanishing.
                var reason_buf: [128]u8 = undefined;
                const reason = std.fmt.bufPrint(&reason_buf, "unsupported collection: {s}", .{collection}) catch "unsupported collection";
                _ = relay.subscription.appendLog(db, sc.clock(), .at_to_ap, uri, "", true, reason) catch {};
                continue;
            },
            else => return err,
        };

        // Enqueue one AP delivery into the federation outbox addressed
        // at the bridge inbox (the env-target fallback the consumer uses).
        try enqueueApDelivery(db, sc.clock(), &arena, out, BRIDGE_INBOX);
    }

    // ── Fingerprint: translation log THEN outbox, both id-ordered. ──
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    try hashTranslationLog(db, &hasher);
    try hashOutbox(db, &hasher);
    var out: [32]u8 = undefined;
    hasher.final(&out);
    return out;
}

/// Build the AP activity JSON envelope (matching the consumer's shape)
/// and enqueue a single delivery row.
fn enqueueApDelivery(
    db: *c.sqlite3,
    clock: core.clock.Clock,
    arena: *Arena,
    out: anytype,
    target_inbox: []const u8,
) !void {
    var key_id_buf: [256 + 9]u8 = undefined;
    if (out.actor.len + 9 > key_id_buf.len) return error.OutOfMemory;
    @memcpy(key_id_buf[0..out.actor.len], out.actor);
    @memcpy(key_id_buf[out.actor.len..][0..9], "#main-key");
    const key_id = key_id_buf[0 .. out.actor.len + 9];

    const alloc = arena.allocator();
    const buf = try alloc.alloc(u8, 16 * 1024);
    const type_str: []const u8 = switch (out.activity_type) {
        .create => "Create",
        .like => "Like",
        .announce => "Announce",
        .follow => "Follow",
        else => "Note",
    };
    const payload = switch (out.activity_type) {
        .create => try std.fmt.bufPrint(buf,
            \\{{"@context":"https://www.w3.org/ns/activitystreams","id":"{s}","type":"{s}","actor":"{s}","published":"{s}","to":["{s}"],"object":{{"id":"{s}","type":"Note","content":"{s}","attributedTo":"{s}","published":"{s}"}}}}
        , .{ out.id, type_str, out.actor, out.published, out.to, out.object_id, out.content_html, out.actor, out.published }),
        .like, .announce => try std.fmt.bufPrint(buf,
            \\{{"@context":"https://www.w3.org/ns/activitystreams","id":"{s}","type":"{s}","actor":"{s}","object":"{s}","published":"{s}","to":["{s}"]}}
        , .{ out.id, type_str, out.actor, out.object_id, out.published, out.to }),
        .follow => try std.fmt.bufPrint(buf,
            \\{{"@context":"https://www.w3.org/ns/activitystreams","id":"{s}","type":"Follow","actor":"{s}","object":"{s}","to":["{s}"]}}
        , .{ out.id, out.actor, out.object_id, out.to }),
        else => try std.fmt.bufPrint(buf,
            \\{{"@context":"https://www.w3.org/ns/activitystreams","id":"{s}","type":"{s}","actor":"{s}"}}
        , .{ out.id, type_str, out.actor }),
    };

    const recipients = [_]activitypub.delivery.Recipient{.{ .inbox = target_inbox }};
    _ = try activitypub.delivery.enqueueDeliveries(db, clock, &recipients, payload, key_id);
}

fn hashTranslationLog(db: *c.sqlite3, hasher: *std.crypto.hash.sha2.Sha256) !void {
    const sql = "SELECT id, direction, source_id, translated_id, success, COALESCE(error_msg,''), ts FROM relay_translation_log ORDER BY id ASC";
    try hashRows(db, sql, hasher);
}

fn hashOutbox(db: *c.sqlite3, hasher: *std.crypto.hash.sha2.Sha256) !void {
    const sql = "SELECT id, target_inbox, payload, key_id, attempts, next_attempt_at, state, inserted_at FROM ap_federation_outbox ORDER BY id ASC";
    try hashRows(db, sql, hasher);
}

/// Feed every column of every row into the hasher in a type-stable way:
/// integers as little-endian i64, text/blob as raw bytes, NULL as a
/// single sentinel byte. A per-row separator keeps column boundaries
/// unambiguous.
fn hashRows(db: *c.sqlite3, sql: []const u8, hasher: *std.crypto.hash.sha2.Sha256) !void {
    const sql_z = try std.heap.page_allocator.dupeZ(u8, sql);
    defer std.heap.page_allocator.free(sql_z);
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql_z.ptr, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    const ncol = c.sqlite3_column_count(stmt);
    while (true) {
        const rc = c.sqlite3_step(stmt.?);
        if (rc == c.SQLITE_DONE) break;
        if (rc != c.SQLITE_ROW) return error.StepFailed;
        var col: c_int = 0;
        while (col < ncol) : (col += 1) {
            switch (c.sqlite3_column_type(stmt, col)) {
                c.SQLITE_INTEGER => {
                    var b: [9]u8 = undefined;
                    b[0] = 'i';
                    std.mem.writeInt(i64, b[1..9], c.sqlite3_column_int64(stmt, col), .little);
                    hasher.update(&b);
                },
                c.SQLITE_NULL => hasher.update("n"),
                else => {
                    hasher.update("b");
                    const ptr = c.sqlite3_column_blob(stmt, col);
                    const n: usize = @intCast(c.sqlite3_column_bytes(stmt, col));
                    if (ptr != null and n > 0) {
                        const p: [*]const u8 = @ptrCast(ptr);
                        hasher.update(p[0..n]);
                    }
                    // length-tag the bytes so "ab"+"c" != "a"+"bc"
                    var lb: [8]u8 = undefined;
                    std.mem.writeInt(u64, &lb, n, .little);
                    hasher.update(&lb);
                },
            }
        }
        hasher.update("\x00ROW\x00");
    }
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Two runs, same seed → byte-identical fingerprint.
    const seed_a: u64 = 0x5EED_1_FACE;
    const fp1 = try run(seed_a, allocator);
    const fp2 = try run(seed_a, allocator);
    if (!std.mem.eql(u8, &fp1, &fp2)) {
        std.debug.print("J3 translate-replay: MISMATCH under fixed seed\n", .{});
        return error.NonDeterministic;
    }

    // Different seed → different fingerprint (non-triviality guard).
    const fp3 = try run(0xA11CE_B0B, allocator);
    if (std.mem.eql(u8, &fp1, &fp3)) {
        std.debug.print("J3 translate-replay: distinct seeds collided (trivial pass)\n", .{});
        return error.SeedCollision;
    }

    std.debug.print(
        "J3 translate-replay: OK — {d} events x2 byte-identical (fp={x}), distinct seed differs\n",
        .{ EVENTS_PER_RUN, std.mem.readInt(u64, fp1[0..8], .big) },
    );
}

const testing = std.testing;

test "J3: AT→AP translate→outbox replay is byte-identical under a fixed seed" {
    const seed: u64 = 0xC0FFEE_D00D;
    const fp1 = try run(seed, testing.allocator);
    const fp2 = try run(seed, testing.allocator);
    try testing.expectEqualSlices(u8, &fp1, &fp2);
}

test "J3: a different seed produces a different fingerprint (non-trivial)" {
    const fp_a = try run(0x1111_2222, testing.allocator);
    const fp_b = try run(0x3333_4444, testing.allocator);
    try testing.expect(!std.mem.eql(u8, &fp_a, &fp_b));
}
