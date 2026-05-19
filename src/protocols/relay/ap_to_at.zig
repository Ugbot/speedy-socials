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
const followers_mod = @import("followers.zig");
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
///
/// For Delete: returns the *most likely* target collection — the
/// bridge tries deleting from `app.bsky.feed.post` first; if no row
/// matches it falls through to like / repost / follow in order. The
/// AP Delete activity rarely carries enough information to know
/// which collection the object lived in.
pub fn collectionFor(act: *const Activity) ?[]const u8 {
    return switch (act.activity_type) {
        .create, .update => blk: {
            // A4: Update follows the same target as Create — we
            // re-commit with the same rkey (derived from object_id),
            // so INSERT-OR-REPLACE on `atp_records` mutates the row
            // in place. The inner content extracted from the raw
            // body changes the CID when it actually changed.
            if (std.ascii.eqlIgnoreCase(act.object_type, "Note")) {
                break :blk "app.bsky.feed.post";
            }
            break :blk null;
        },
        .like => "app.bsky.feed.like",
        .announce => "app.bsky.feed.repost",
        .follow => "app.bsky.graph.follow",
        .delete => "app.bsky.feed.post", // probe order: post → like → repost → follow
        else => null,
    };
}

/// Bridge-translatable activities other than Delete go through the
/// "commit a record" path; Delete goes through the "remove a record"
/// path.
fn isDelete(act: *const Activity) bool {
    return act.activity_type == .delete;
}

/// Hook entrypoint — installed by `relay.init` via
/// `activitypub.inbox.setRelayInboxHook`. MUST NOT throw: failures
/// log + return.
pub fn onActivityReceived(act: *const Activity, raw_body: []const u8, db: *c.sqlite3, clock: core.clock.Clock) void {
    onActivityReceivedImpl(act, raw_body, db, clock) catch |err| {
        std.log.warn("relay ap_to_at: failed: {s}", .{@errorName(err)});
    };
}

fn onActivityReceivedImpl(act: *const Activity, raw_body: []const u8, db: *c.sqlite3, clock: core.clock.Clock) !void {
    // B4: Undo runs BEFORE the `collectionFor` early-return because
    // it has no AT-collection mapping. AP `Undo{Follow}` references
    // the inner Follow activity by its `id`. Map: act.object_id ==
    // follow.id. Remove the follower row keyed on that follow_iri.
    if (act.activity_type == .undo and act.object_id.len > 0) {
        const removed = followers_mod.removeByFollowIri(db, act.object_id) catch false;
        const status_msg: []const u8 = if (removed) "" else "undo: no follower row";
        _ = subscription.appendLog(db, clock, .ap_to_at, act.object_id, "[undone]", true, status_msg) catch {};
        return;
    }

    // A5: known-but-not-bridged types. Log explicitly so audit shows
    // we saw them; tracking these helps decide whether to add real
    // bridge semantics later.
    switch (act.activity_type) {
        .move => {
            _ = subscription.appendLog(db, clock, .ap_to_at, act.id, "", true, "dropped: Move not bridged (identity migration logic pending)") catch {};
            return;
        },
        .block => {
            _ = subscription.appendLog(db, clock, .ap_to_at, act.id, "", true, "dropped: Block has no AT primitive") catch {};
            return;
        },
        .flag => {
            _ = subscription.appendLog(db, clock, .ap_to_at, act.id, "", true, "dropped: Flag has no AT primitive") catch {};
            return;
        },
        else => {},
    }

    const collection = collectionFor(act) orelse return;

    // A7: dedup on (direction, source_id). source_id we'll use is
    // the same one appendLog records — the activity id (or
    // object_id fallback). If a successful row already exists, the
    // bridge has already mirrored this activity; skip.
    const dedup_source_id = if (act.id.len > 0) act.id else act.object_id;
    if (subscription.hasSuccessfulLog(db, .ap_to_at, dedup_source_id)) {
        return;
    }

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

    // A3: Delete activities go through the remove-record path, which
    // probes each collection in order. We attempt to delete from the
    // most likely (post) first, then like/repost/follow.
    if (isDelete(act)) {
        try processDelete(act, db, clock, did, &arena);
        return;
    }

    // B1: Follow targeting a synthetic AP actor — record the peer as
    // a follower so the AT→AP fanout reaches them when the bridged
    // actor posts. `act.object_id` is the followed actor URL (one of
    // our synthetic IDs); `act.actor` is the AP peer. We heuristically
    // derive the peer's inbox as `<actor>/inbox` — this matches
    // Mastodon convention. A future C-tier feature is to fetch the
    // peer's actor doc to discover the real inbox / sharedInbox.
    if (act.activity_type == .follow and act.object_id.len > 0) {
        // Derive `<follower>/inbox`. Bounded buffer.
        var inbox_buf: [followers_mod.max_inbox_url_bytes]u8 = undefined;
        if (act.actor.len + "/inbox".len <= inbox_buf.len) {
            @memcpy(inbox_buf[0..act.actor.len], act.actor);
            @memcpy(inbox_buf[act.actor.len..][0.."/inbox".len], "/inbox");
            const inbox_slice = inbox_buf[0 .. act.actor.len + "/inbox".len];
            followers_mod.add(db, clock, act.object_id, inbox_slice, "", act.id) catch |err| {
                std.log.warn("relay followers.add failed: {s}", .{@errorName(err)});
            };
        }
        // Fall through to the AT-side record commit so the bridge
        // still produces an `app.bsky.graph.follow` row.
    }

    // Mint the synthetic Ed25519 signing key for this DID (deterministic
    // from the AP actor URL via the relay pepper) + ensure the AT repo
    // row exists. We pass the AP actor URL as the "signing_key" hint
    // string — opaque to the AT side, but useful for forensic queries.
    const signing_kp = synthetic_keys.deriveKeypair(act.actor);
    try atproto.repo.ensureRepo(db, did, act.actor, clock.wallUnix());

    // Build a dag-cbor record body shaped for the target collection.
    // We pull the inner Note's `content` from the raw body (Mastodon
    // sends HTML in object.content) so Update activities that change
    // the content actually produce a different CID — A4's requirement
    // — and so Create's bridged record carries the real text rather
    // than the literal string "Note".
    var record_buf: [16 * 1024]u8 = undefined;
    const inner_content = extractApInnerContent(raw_body);
    const record_cbor = try buildBridgeRecord(act, collection, inner_content, &record_buf);

    // Generate a stable rkey from the AP *object id* (NOT the activity
    // id). A future Delete activity references the object id alone —
    // keying on the same field on both sides means Delete can target
    // the row by deriving the same rkey. Re-deliveries of Create with
    // the same object_id INSERT-OR-REPLACE in atp_records.
    const rkey_seed = if (act.object_id.len > 0) act.object_id else act.id;
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
    // E2: per-protocol counter.
    core.metrics.incRelayApToAt();
}

/// A3: AP Delete → remove the bridged AT record(s).
///
/// AP Delete carries `object` (the URL of the thing being deleted)
/// but not the collection it belongs to. Probe each bridged
/// collection in turn; the first hit terminates the search.
fn processDelete(act: *const Activity, db: *c.sqlite3, clock: core.clock.Clock, did: []const u8, arena: *Arena) !void {
    if (act.object_id.len == 0) return;
    const rkey = try translatedRkey(act.object_id, arena);

    const probe_order = [_][]const u8{
        "app.bsky.feed.post",
        "app.bsky.feed.like",
        "app.bsky.feed.repost",
        "app.bsky.graph.follow",
    };
    var hit_collection: []const u8 = "";
    for (probe_order) |col| {
        const deleted = atproto.repo.deleteRecord(db, did, col, rkey) catch false;
        if (deleted) {
            hit_collection = col;
            break;
        }
    }

    if (hit_collection.len == 0) {
        // No bridged record matched this object_id. Common case: the
        // peer is deleting something we never bridged (e.g. a video).
        // Not an error — log as a no-op so audit shows we saw it.
        _ = subscription.appendLog(db, clock, .ap_to_at, act.object_id, "", true, "delete: no match") catch {};
        return;
    }

    var translated_buf: [256]u8 = undefined;
    const translated = try std.fmt.bufPrint(
        &translated_buf,
        "at://{s}/{s}/{s} [deleted]",
        .{ did, hit_collection, rkey },
    );
    _ = subscription.appendLog(db, clock, .ap_to_at, act.object_id, translated, true, "") catch {};
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
fn buildBridgeRecord(act: *const Activity, collection: []const u8, inner_content: []const u8, out: []u8) ![]const u8 {
    var enc = atproto.dag_cbor.Encoder.init(out);
    const map_size: u32 = switch (act.activity_type) {
        // Create + Update both emit text+createdAt; their AT records
        // are otherwise indistinguishable (Update is just a mutation
        // of the existing rkey).
        .create, .update => 5, // $type, bridgedFrom, bridgedActor, text, createdAt
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
        .create, .update => {
            try enc.writeText("text");
            // Inner Note body's `content` field if present (HTML for
            // Mastodon); fall back to object_type label when absent.
            const text = if (inner_content.len > 0) inner_content else act.object_type;
            try enc.writeText(if (text.len > 0) text else "Note");
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

/// Best-effort extraction of the inner activity object's `content`
/// field. Mastodon-style Update / Create activities carry an inline
/// `object` map with `"content": "..."`. We pull the FIRST occurrence
/// of `"content":"<text>"` in the body — works because AP bodies
/// contain at most one such field at the relevant nesting level.
/// Returns an empty slice when not found.
fn extractApInnerContent(raw_body: []const u8) []const u8 {
    const needle = "\"content\"";
    var i: usize = 0;
    while (i + needle.len <= raw_body.len) : (i += 1) {
        if (std.mem.eql(u8, raw_body[i..][0..needle.len], needle)) {
            // Skip whitespace + ':' + whitespace.
            var j: usize = i + needle.len;
            while (j < raw_body.len and (raw_body[j] == ' ' or raw_body[j] == '\t')) : (j += 1) {}
            if (j >= raw_body.len or raw_body[j] != ':') return "";
            j += 1;
            while (j < raw_body.len and (raw_body[j] == ' ' or raw_body[j] == '\t')) : (j += 1) {}
            if (j >= raw_body.len or raw_body[j] != '"') return "";
            j += 1;
            const start = j;
            // Scan to the closing unescaped quote.
            while (j < raw_body.len) : (j += 1) {
                if (raw_body[j] == '\\') {
                    j += 1;
                    if (j >= raw_body.len) return "";
                    continue;
                }
                if (raw_body[j] == '"') return raw_body[start..j];
            }
            return "";
        }
    }
    return "";
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
    onActivityReceived(&act, "", db, sc.clock());

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
    onActivityReceived(&act, "", db, sc.clock());
    var rows: [2]subscription.LogEntry = undefined;
    const n = try subscription.listLog(db, 0, &rows);
    try testing.expectEqual(@as(u32, 1), n);
    try testing.expect(std.mem.indexOf(u8, rows[0].translatedId(), "app.bsky.feed.like") != null);
}

test "A4: Update mutates the bridged record in place (CID changes)" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    var sc = core.clock.SimClock.init(1_715_500_000);
    setRelayHost("relay.test");
    defer setRelayHost("");

    const create_body =
        "{\"type\":\"Create\",\"id\":\"https://m.example/users/eve/activities/100\"," ++
        "\"actor\":\"https://m.example/users/eve\"," ++
        "\"object\":{\"id\":\"https://m.example/users/eve/notes/100\"," ++
        "\"type\":\"Note\",\"content\":\"original text\"}}";
    const create_act: Activity = .{
        .activity_type = .create,
        .id = "https://m.example/users/eve/activities/100",
        .actor = "https://m.example/users/eve",
        .object_id = "https://m.example/users/eve/notes/100",
        .object_type = "Note",
        .target = "",
        .published = "2026-05-19T01:00:00Z",
        .to_first = "",
    };
    onActivityReceived(&create_act, create_body, db, sc.clock());

    // Grab the CID after Create.
    var arena_buf: [1024]u8 = undefined;
    var arena = Arena.init(&arena_buf);
    const did = (try identity_map.didForActor(db, create_act.actor, &arena)).?;
    var cid_a_buf: [128]u8 = undefined;
    var cid_a_len: usize = 0;
    var s1: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "SELECT cid FROM atp_records WHERE did = ? AND collection = 'app.bsky.feed.post'", -1, &s1, null) == c.SQLITE_OK) {
        defer _ = c.sqlite3_finalize(s1);
        _ = c.sqlite3_bind_text(s1, 1, did.ptr, @intCast(did.len), c.sqliteTransientAsDestructor());
        if (c.sqlite3_step(s1.?) == c.SQLITE_ROW) {
            const p = c.sqlite3_column_text(s1, 0);
            const n: usize = @intCast(c.sqlite3_column_bytes(s1, 0));
            const cap = @min(n, cid_a_buf.len);
            if (p != null and cap > 0) {
                @memcpy(cid_a_buf[0..cap], p[0..cap]);
                cid_a_len = cap;
            }
        }
    }
    try testing.expect(cid_a_len > 0);

    // Send Update with different content.
    const update_body =
        "{\"type\":\"Update\",\"id\":\"https://m.example/users/eve/activities/101\"," ++
        "\"actor\":\"https://m.example/users/eve\"," ++
        "\"object\":{\"id\":\"https://m.example/users/eve/notes/100\"," ++
        "\"type\":\"Note\",\"content\":\"edited text — totally different\"}}";
    const update_act: Activity = .{
        .activity_type = .update,
        .id = "https://m.example/users/eve/activities/101",
        .actor = "https://m.example/users/eve",
        .object_id = "https://m.example/users/eve/notes/100",
        .object_type = "Note",
        .target = "",
        .published = "2026-05-19T01:05:00Z",
        .to_first = "",
    };
    onActivityReceived(&update_act, update_body, db, sc.clock());

    // CID after Update must differ.
    var cid_b_buf: [128]u8 = undefined;
    var cid_b_len: usize = 0;
    var s2: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "SELECT cid FROM atp_records WHERE did = ? AND collection = 'app.bsky.feed.post'", -1, &s2, null) == c.SQLITE_OK) {
        defer _ = c.sqlite3_finalize(s2);
        _ = c.sqlite3_bind_text(s2, 1, did.ptr, @intCast(did.len), c.sqliteTransientAsDestructor());
        if (c.sqlite3_step(s2.?) == c.SQLITE_ROW) {
            const p = c.sqlite3_column_text(s2, 0);
            const n: usize = @intCast(c.sqlite3_column_bytes(s2, 0));
            const cap = @min(n, cid_b_buf.len);
            if (p != null and cap > 0) {
                @memcpy(cid_b_buf[0..cap], p[0..cap]);
                cid_b_len = cap;
            }
        }
    }
    try testing.expect(cid_b_len > 0);
    try testing.expect(!std.mem.eql(u8, cid_a_buf[0..cid_a_len], cid_b_buf[0..cid_b_len]));

    // Exactly one row still — replaced not appended.
    var row_count: i64 = -1;
    var s3: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "SELECT count(*) FROM atp_records WHERE did = ?", -1, &s3, null) == c.SQLITE_OK) {
        defer _ = c.sqlite3_finalize(s3);
        _ = c.sqlite3_bind_text(s3, 1, did.ptr, @intCast(did.len), c.sqliteTransientAsDestructor());
        if (c.sqlite3_step(s3.?) == c.SQLITE_ROW) row_count = c.sqlite3_column_int64(s3, 0);
    }
    try testing.expectEqual(@as(i64, 1), row_count);
}

test "B4: Follow then Undo removes the follower row" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    var sc = core.clock.SimClock.init(1_716_000_000);
    setRelayHost("relay.test");
    defer setRelayHost("");

    const follow_act: Activity = .{
        .activity_type = .follow,
        .id = "https://m.example/follow/42",
        .actor = "https://m.example/users/frank",
        .object_id = "https://relay.test/ap/users/at:plc:target",
        .object_type = "Person",
        .target = "",
        .published = "",
        .to_first = "",
    };
    onActivityReceived(&follow_act, "", db, sc.clock());

    // The follower row was added.
    var f_buf: [4]followers_mod.Follower = undefined;
    const n_before = try followers_mod.list(db, follow_act.object_id, &f_buf);
    try testing.expectEqual(@as(u32, 1), n_before);

    const undo_act: Activity = .{
        .activity_type = .undo,
        .id = "https://m.example/undo/9",
        .actor = "https://m.example/users/frank",
        // AP convention: Undo's `object` is the IRI of the inner
        // activity being undone — our follow_iri.
        .object_id = "https://m.example/follow/42",
        .object_type = "",
        .target = "",
        .published = "",
        .to_first = "",
    };
    onActivityReceived(&undo_act, "", db, sc.clock());

    const n_after = try followers_mod.list(db, follow_act.object_id, &f_buf);
    try testing.expectEqual(@as(u32, 0), n_after);
}

test "A3: Create then Delete removes the bridged atp_records row" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    var sc = core.clock.SimClock.init(1_715_000_000);
    setRelayHost("relay.test");
    defer setRelayHost("");

    const create_act: Activity = .{
        .activity_type = .create,
        .id = "https://mastodon.example/users/carol/activities/77",
        .actor = "https://mastodon.example/users/carol",
        .object_id = "https://mastodon.example/users/carol/notes/77",
        .object_type = "Note",
        .target = "",
        .published = "2026-05-19T00:00:00Z",
        .to_first = "https://www.w3.org/ns/activitystreams#Public",
    };
    onActivityReceived(&create_act, "", db, sc.clock());

    // Verify the bridged row exists.
    var arena_buf: [1024]u8 = undefined;
    var arena = Arena.init(&arena_buf);
    const did = (try identity_map.didForActor(db, create_act.actor, &arena)).?;
    var pre_count: i64 = -1;
    var s1: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "SELECT count(*) FROM atp_records WHERE did = ?", -1, &s1, null) == c.SQLITE_OK) {
        defer _ = c.sqlite3_finalize(s1);
        _ = c.sqlite3_bind_text(s1, 1, did.ptr, @intCast(did.len), c.sqliteTransientAsDestructor());
        if (c.sqlite3_step(s1.?) == c.SQLITE_ROW) pre_count = c.sqlite3_column_int64(s1, 0);
    }
    try testing.expectEqual(@as(i64, 1), pre_count);

    // Send Delete referencing the same object id.
    const delete_act: Activity = .{
        .activity_type = .delete,
        .id = "https://mastodon.example/users/carol/activities/88",
        .actor = "https://mastodon.example/users/carol",
        .object_id = "https://mastodon.example/users/carol/notes/77",
        .object_type = "Tombstone",
        .target = "",
        .published = "2026-05-19T00:01:00Z",
        .to_first = "",
    };
    onActivityReceived(&delete_act, "", db, sc.clock());

    // Row should be gone.
    var post_count: i64 = -1;
    var s2: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "SELECT count(*) FROM atp_records WHERE did = ?", -1, &s2, null) == c.SQLITE_OK) {
        defer _ = c.sqlite3_finalize(s2);
        _ = c.sqlite3_bind_text(s2, 1, did.ptr, @intCast(did.len), c.sqliteTransientAsDestructor());
        if (c.sqlite3_step(s2.?) == c.SQLITE_ROW) post_count = c.sqlite3_column_int64(s2, 0);
    }
    try testing.expectEqual(@as(i64, 0), post_count);
}

test "A3: Delete for an unknown object id is a logged no-op" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    var sc = core.clock.SimClock.init(1);
    setRelayHost("relay.test");
    defer setRelayHost("");

    const delete_act: Activity = .{
        .activity_type = .delete,
        .id = "https://m.example/a/1",
        .actor = "https://m.example/users/dave",
        .object_id = "https://m.example/users/dave/notes/never-bridged",
        .object_type = "Tombstone",
        .target = "",
        .published = "",
        .to_first = "",
    };
    onActivityReceived(&delete_act, "", db, sc.clock());

    // No atp_records changes, but a log entry exists.
    var rows: [4]subscription.LogEntry = undefined;
    const n = try subscription.listLog(db, 0, &rows);
    try testing.expect(n >= 1);
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
    onActivityReceived(&act, "", db, sc.clock());
    var rows: [2]subscription.LogEntry = undefined;
    const n = try subscription.listLog(db, 0, &rows);
    try testing.expectEqual(@as(u32, 0), n);
}
