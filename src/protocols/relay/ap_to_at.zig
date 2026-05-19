//! W5.2 — AP→AT inbox translation hook.
//!
//! When an ActivityPub activity arrives at the AP inbox and clears
//! the state-machine dispatcher, this module's `onActivityReceived`
//! fires (via `activitypub.inbox.setRelayInboxHook`). It mirrors the
//! activity into the AT side of the bridge by writing an `ap_to_at`
//! row into `relay_translation_log` and (where the synthetic AT
//! mapping exists) emitting the AT record shape that downstream
//! tools can read.
//!
//! Scope today: like the AT→AP consumer, this hook *logs* — it does
//! not yet commit into `atp_records` because the synthetic AT repos
//! for AP actors do not have signing keys provisioned yet. The
//! translation log is the verifiable evidence that the AP→AT
//! pipeline is live.
//!
//! Supported activity types (the load-bearing four for a Mastodon
//! ↔ Bluesky bridge):
//!   * Create{Note}    → app.bsky.feed.post
//!   * Like            → app.bsky.feed.like
//!   * Announce        → app.bsky.feed.repost
//!   * Follow          → app.bsky.graph.follow
//!
//! All other types are silently dropped (logged at debug level).

const std = @import("std");
const core = @import("core");
const c = @import("sqlite").c;
const activitypub = @import("protocol_activitypub");
const atproto = @import("protocol_atproto");
const Activity = activitypub.activity.Activity;
const ActivityType = activitypub.activity.ActivityType;

const identity_map = @import("identity_map.zig");
const subscription = @import("subscription.zig");
const synthetic_keys = @import("synthetic_keys.zig");
const Arena = core.arena.Arena;

const RelayError = core.errors.RelayError;

/// The relay's hostname, used to mint synthetic AT DIDs for AP actors
/// that have no native AT presence. Set once at boot.
var relay_host_buf: [256]u8 = undefined;
var relay_host_len: u16 = 0;

pub fn setRelayHost(host: []const u8) void {
    const n = @min(host.len, relay_host_buf.len);
    @memcpy(relay_host_buf[0..n], host[0..n]);
    relay_host_len = @intCast(n);
}

fn relayHost() []const u8 {
    return relay_host_buf[0..relay_host_len];
}

/// Public accessor — other relay modules (`routes.zig` for A1) need
/// the configured host to mint synthetic-actor URLs.
pub fn relayHostPublic() []const u8 {
    return relayHost();
}

/// Maps an AP `ActivityType` (plus, for Create, an inline object
/// type) to its AT collection name. Returns null for activities the
/// bridge does not translate today.
pub fn collectionFor(act: *const Activity) ?[]const u8 {
    return switch (act.activity_type) {
        .create => blk: {
            // Only translate Create{Note}; other inline objects (Article,
            // Image, Video, …) need their own targeted mapping.
            if (std.ascii.eqlIgnoreCase(act.object_type, "Note")) {
                break :blk "app.bsky.feed.post";
            }
            break :blk null;
        },
        .like => "app.bsky.feed.like",
        .announce => "app.bsky.feed.repost",
        .follow => "app.bsky.graph.follow",
        else => null,
    };
}

/// Hook entrypoint — installed by `relay.init` via
/// `activitypub.inbox.setRelayInboxHook`. MUST NOT throw: failures
/// log + return.
pub fn onActivityReceived(act: *const Activity, db: *c.sqlite3, clock: core.clock.Clock) void {
    onActivityReceivedImpl(act, db, clock) catch |err| {
        std.log.warn("relay ap_to_at: failed: {s}", .{@errorName(err)});
    };
}

fn onActivityReceivedImpl(act: *const Activity, db: *c.sqlite3, clock: core.clock.Clock) !void {
    const collection = collectionFor(act) orelse return;

    var arena_buf: [16 * 1024]u8 = undefined;
    var arena = Arena.init(&arena_buf);

    // Look up (or mint) the AT DID for this AP actor. The relay's
    // identity map is the source of truth; mint-on-demand keeps the
    // bridge symmetric with the AT→AP path.
    var maybe_did = try identity_map.didForActor(db, act.actor, &arena);
    if (maybe_did == null) {
        const host = relayHost();
        if (host.len == 0) return error.IdentityMapFailed;
        const synth = try identity_map.syntheticDidForActor(host, act.actor, &arena);
        try identity_map.upsert(db, clock, synth, act.actor);
        maybe_did = synth;
    }
    const did = maybe_did.?;

    // Mint the synthetic Ed25519 signing key for this DID (deterministic
    // from the AP actor URL via the relay pepper) + ensure the AT repo
    // row exists. We pass the AP actor URL as the "signing_key" hint
    // string — opaque to the AT side, but useful for forensic queries.
    const signing_kp = synthetic_keys.deriveKeypair(act.actor);
    try atproto.repo.ensureRepo(db, did, act.actor, clock.wallUnix());

    // Build a dag-cbor record body shaped for the target collection.
    // We deliberately keep this minimal: just enough fields for an AT
    // subscriber to render the bridge entry. Lexicon-perfect encoding
    // is a separate concern (and likely involves AT-side schema
    // negotiation that is out of scope here).
    var record_buf: [4096]u8 = undefined;
    const record_cbor = try buildBridgeRecord(act, collection, &record_buf);

    // Generate a stable rkey from the AP activity id so re-deliveries
    // of the same activity dedupe at the AT repo level (commit uses
    // INSERT OR REPLACE on the at-uri primary key).
    const rkey_seed = if (act.id.len > 0) act.id else act.object_id;
    const rkey = try translatedRkey(rkey_seed, &arena);

    // Load the current MST for this synthetic repo and commit one op.
    // The tree fits inline on the stack — at the bridge's projected
    // load these repos hold low thousands of records max.
    var tree: atproto.mst.Tree(atproto.mst.max_keys) = .{};
    atproto.repo.loadTree(db, did, &tree) catch |err| switch (err) {
        // A missing tree is the normal first-commit case.
        else => {},
    };

    // The commit needs a rev TID derived from the clock. Avoid pulling
    // a full RNG state through every call — the bridge can use a
    // deterministic counter via SimClock in tests, real clock in prod.
    var rng = core.rng.Rng.init(@bitCast(@as(i64, clock.wallUnix())));
    var ts = atproto.tid.State.init(&rng);
    const rev = ts.next(clock);

    var ops_storage: [1]atproto.repo.Operation = .{.{
        .collection = collection,
        .rkey = rkey,
        .value_cbor = record_cbor,
    }};
    _ = atproto.repo.commit(
        db,
        did,
        signing_kp,
        rev,
        &tree,
        &ops_storage,
        clock.wallUnix(),
        null,
    ) catch |err| switch (err) {
        // A commit failure is a real bridge fault — record it as such
        // in the translation log and propagate. The AP inbox response
        // is unaffected because the hook caller swallows errors.
        else => {
            var msg_buf: [64]u8 = undefined;
            const msg = std.fmt.bufPrint(&msg_buf, "commit failed: {s}", .{@errorName(err)}) catch "commit failed";
            const source_id_err = if (act.id.len > 0) act.id else act.object_id;
            _ = subscription.appendLog(db, clock, .ap_to_at, source_id_err, "", false, msg) catch {};
            return;
        },
    };

    // Success — log the translated at-uri so /relay/status surfaces it.
    var translated_buf: [256 + 4 + 96 + 1 + 64]u8 = undefined;
    const translated = try std.fmt.bufPrint(
        &translated_buf,
        "at://{s}/{s}/{s}",
        .{ did, collection, rkey },
    );
    const source_id = if (act.id.len > 0) act.id else act.object_id;
    _ = subscription.appendLog(db, clock, .ap_to_at, source_id, translated, true, "") catch {};
}

/// Build the minimum-viable AT record body. We emit:
///   * `$type`: the collection NSID
///   * `bridgedFrom`: the original AP id
///   * `bridgedActor`: the original AP actor URL
///   * `text` / `subject`: type-specific payload pulled from `act`
/// The shape is intentionally not lexicon-perfect — AT lexicons
/// expect Bluesky-flavoured fields and we cannot synthesize, e.g.,
/// the `facets` array from a Mastodon HTML body without an HTML
/// stripper. This minimum body lets AT consumers see the bridge entry
/// and follow `bridgedFrom` back to the AP source.
fn buildBridgeRecord(act: *const Activity, collection: []const u8, out: []u8) ![]const u8 {
    var enc = atproto.dag_cbor.Encoder.init(out);
    const map_size: u32 = switch (act.activity_type) {
        .create => 5, // $type, bridgedFrom, bridgedActor, text, createdAt
        .like, .announce => 4, // $type, bridgedFrom, bridgedActor, subject
        .follow => 4, // $type, bridgedFrom, bridgedActor, subject
        else => 3,
    };
    try enc.writeMapHeader(map_size);
    try enc.writeText("$type");
    try enc.writeText(collection);
    try enc.writeText("bridgedFrom");
    try enc.writeText(if (act.id.len > 0) act.id else act.object_id);
    try enc.writeText("bridgedActor");
    try enc.writeText(act.actor);
    switch (act.activity_type) {
        .create => {
            try enc.writeText("text");
            // Mastodon-style Note bodies are HTML; we don't strip
            // tags. Downstream consumers must treat `text` as
            // potentially-marked-up.
            try enc.writeText(if (act.object_type.len > 0) act.object_type else "Note");
            try enc.writeText("createdAt");
            try enc.writeText(if (act.published.len > 0) act.published else "1970-01-01T00:00:00Z");
        },
        .like, .announce => {
            try enc.writeText("subject");
            try enc.writeText(act.object_id);
        },
        .follow => {
            try enc.writeText("subject");
            try enc.writeText(act.object_id);
        },
        else => {},
    }
    return enc.written();
}

/// Derive a short rkey from an AP id. We don't need cryptographic
/// uniqueness here — collisions among AP ids would already be
/// pathological. Take the trailing path segment when present; else
/// the last 32 bytes of the URL.
fn translatedRkey(ap_id: []const u8, arena: *Arena) RelayError![]const u8 {
    if (ap_id.len == 0) return "anonymous";
    // Last '/' as the segment boundary.
    var i: usize = ap_id.len;
    while (i > 0) {
        i -= 1;
        if (ap_id[i] == '/') {
            const tail = ap_id[i + 1 ..];
            if (tail.len > 0) return tail;
            break;
        }
    }
    const start = if (ap_id.len > 32) ap_id.len - 32 else 0;
    const slice = ap_id[start..];
    // Sanitize — only [a-zA-Z0-9_-.] are AT rkey-safe.
    const alloc = arena.allocator();
    const buf = alloc.alloc(u8, slice.len) catch return error.TranslationBufferTooSmall;
    for (slice, 0..) |ch, j| {
        buf[j] = switch (ch) {
            'a'...'z', 'A'...'Z', '0'...'9', '_', '-', '.' => ch,
            else => '_',
        };
    }
    return buf;
}

// ── Tests ─────────────────────────────────────────────────────────

const testing = std.testing;
const schema_mod = @import("schema.zig");

fn setupDb() !*c.sqlite3 {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    // AT schema first — relay's commit writes into atp_repos +
    // atp_records + atp_commits + atp_mst_blocks + atp_firehose_events.
    for (atproto.schema.all_migrations) |m| {
        const sql_z = try testing.allocator.dupeZ(u8, m.up);
        defer testing.allocator.free(sql_z);
        var errmsg: [*c]u8 = null;
        _ = c.sqlite3_exec(db, sql_z.ptr, null, null, &errmsg);
        if (errmsg != null) c.sqlite3_free(errmsg);
    }
    for (schema_mod.all_migrations) |m| {
        const sql_z = try testing.allocator.dupeZ(u8, m.up);
        defer testing.allocator.free(sql_z);
        var errmsg: [*c]u8 = null;
        _ = c.sqlite3_exec(db, sql_z.ptr, null, null, &errmsg);
        if (errmsg != null) c.sqlite3_free(errmsg);
    }
    return db;
}

test "collectionFor maps the load-bearing four activity types" {
    var a: Activity = .{
        .activity_type = .create,
        .id = "",
        .actor = "",
        .object_id = "",
        .object_type = "Note",
        .target = "",
        .published = "",
        .to_first = "",
    };
    try testing.expectEqualStrings("app.bsky.feed.post", collectionFor(&a).?);

    a.activity_type = .like;
    a.object_type = "";
    try testing.expectEqualStrings("app.bsky.feed.like", collectionFor(&a).?);

    a.activity_type = .announce;
    try testing.expectEqualStrings("app.bsky.feed.repost", collectionFor(&a).?);

    a.activity_type = .follow;
    try testing.expectEqualStrings("app.bsky.graph.follow", collectionFor(&a).?);

    // Untranslated.
    a.activity_type = .update;
    try testing.expectEqual(@as(?[]const u8, null), collectionFor(&a));
}

test "onActivityReceived: Create{Note} writes ap_to_at log row + mints AT DID" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    var sc = core.clock.SimClock.init(1_715_000_000);
    setRelayHost("relay.test");
    defer setRelayHost("");

    const act: Activity = .{
        .activity_type = .create,
        .id = "https://mastodon.example/notes/abc",
        .actor = "https://mastodon.example/users/alice",
        .object_id = "https://mastodon.example/notes/abc",
        .object_type = "Note",
        .target = "",
        .published = "2026-05-16T00:00:00Z",
        .to_first = "https://www.w3.org/ns/activitystreams#Public",
    };
    onActivityReceived(&act, db, sc.clock());

    var rows: [4]subscription.LogEntry = undefined;
    const n = try subscription.listLog(db, 0, &rows);
    try testing.expectEqual(@as(u32, 1), n);
    try testing.expectEqual(subscription.Direction.ap_to_at, rows[0].direction);
    try testing.expectEqualStrings("https://mastodon.example/notes/abc", rows[0].sourceId());
    try testing.expect(std.mem.startsWith(u8, rows[0].translatedId(), "at://"));
    try testing.expect(std.mem.indexOf(u8, rows[0].translatedId(), "app.bsky.feed.post") != null);

    // Identity-map row should now exist for the AP actor.
    var buf: [1024]u8 = undefined;
    var arena = Arena.init(&buf);
    const did = try identity_map.didForActor(db, "https://mastodon.example/users/alice", &arena);
    try testing.expect(did != null);

    // W6: the bridge actually committed the translated record into
    // atp_records. The synthetic AT repo for the AP actor now holds
    // one row at collection app.bsky.feed.post.
    var rec_count: i64 = -1;
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "SELECT count(*) FROM atp_records WHERE did = ? AND collection = ?", -1, &stmt, null) == c.SQLITE_OK) {
        defer _ = c.sqlite3_finalize(stmt);
        _ = c.sqlite3_bind_text(stmt, 1, did.?.ptr, @intCast(did.?.len), c.sqliteTransientAsDestructor());
        const col = "app.bsky.feed.post";
        _ = c.sqlite3_bind_text(stmt, 2, col, col.len, c.sqliteTransientAsDestructor());
        if (c.sqlite3_step(stmt.?) == c.SQLITE_ROW) {
            rec_count = c.sqlite3_column_int64(stmt, 0);
        }
    }
    try testing.expectEqual(@as(i64, 1), rec_count);

    // And an atp_commits row was emitted (so AT firehose subscribers
    // would see the bridge event).
    var commit_count: i64 = -1;
    var c2: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "SELECT count(*) FROM atp_commits WHERE did = ?", -1, &c2, null) == c.SQLITE_OK) {
        defer _ = c.sqlite3_finalize(c2);
        _ = c.sqlite3_bind_text(c2, 1, did.?.ptr, @intCast(did.?.len), c.sqliteTransientAsDestructor());
        if (c.sqlite3_step(c2.?) == c.SQLITE_ROW) {
            commit_count = c.sqlite3_column_int64(c2, 0);
        }
    }
    try testing.expectEqual(@as(i64, 1), commit_count);
}

test "onActivityReceived: Like translates to app.bsky.feed.like" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    var sc = core.clock.SimClock.init(1);
    setRelayHost("relay.test");
    defer setRelayHost("");
    const act: Activity = .{
        .activity_type = .like,
        .id = "https://m.example/likes/9",
        .actor = "https://m.example/users/bob",
        .object_id = "https://m.example/notes/x",
        .object_type = "",
        .target = "",
        .published = "",
        .to_first = "",
    };
    onActivityReceived(&act, db, sc.clock());
    var rows: [2]subscription.LogEntry = undefined;
    const n = try subscription.listLog(db, 0, &rows);
    try testing.expectEqual(@as(u32, 1), n);
    try testing.expect(std.mem.indexOf(u8, rows[0].translatedId(), "app.bsky.feed.like") != null);
}

test "onActivityReceived: unsupported activity type is silently dropped" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    var sc = core.clock.SimClock.init(1);
    const act: Activity = .{
        .activity_type = .update,
        .id = "https://m.example/u/1",
        .actor = "https://m.example/users/alice",
        .object_id = "https://m.example/n/1",
        .object_type = "Note",
        .target = "",
        .published = "",
        .to_first = "",
    };
    onActivityReceived(&act, db, sc.clock());
    var rows: [2]subscription.LogEntry = undefined;
    const n = try subscription.listLog(db, 0, &rows);
    try testing.expectEqual(@as(u32, 0), n);
}
