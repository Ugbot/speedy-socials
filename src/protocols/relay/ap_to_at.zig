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

const profile_collection = "app.bsky.actor.profile";

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
            // I3: AP actor profile changes arrive as Update{Person}
            // (Mastodon also sends Update with a Person object on
            // avatar/bio edits). Map to the AT profile collection.
            if (std.ascii.eqlIgnoreCase(act.object_type, "Person") or
                std.ascii.eqlIgnoreCase(act.object_type, "Service") or
                std.ascii.eqlIgnoreCase(act.object_type, "Application"))
            {
                break :blk profile_collection;
            }
            break :blk null;
        },
        .like => "app.bsky.feed.like",
        .announce => "app.bsky.feed.repost",
        .follow => "app.bsky.graph.follow",
        // B: AP `Block` → `app.bsky.graph.block`. The subject is the
        // blocked actor's DID, resolved from `act.object_id`.
        .block => "app.bsky.graph.block",
        .delete => "app.bsky.feed.post", // probe order: post → like → repost → follow → block
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
    // B4 + Undo{Like|Announce|Block}: Undo runs BEFORE the
    // `collectionFor` early-return because it has no AT-collection
    // mapping. AP `Undo{X}` references the inner activity by its `id`
    // (`act.object_id == X.id`).
    //
    //   Undo{Follow}              → remove the follower row (B4) AND
    //                               delete the bridged graph.follow record.
    //   Undo{Like|Announce|Block} → delete the bridged like / repost /
    //                               block record (unlike / unrepost /
    //                               unblock).
    //
    // The bridged AT record's rkey was derived from the inner activity's
    // id (`act.object_id`) when it was first created, so we re-derive the
    // same rkey here and probe each collection to delete it. This mirrors
    // the Delete path but is scoped to the interaction collections.
    if (act.activity_type == .undo and act.object_id.len > 0) {
        try processUndo(act, db, clock, &.{ "app.bsky.feed.like", "app.bsky.feed.repost", "app.bsky.graph.block", "app.bsky.graph.follow" });
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
        .flag => {
            _ = subscription.appendLog(db, clock, .ap_to_at, act.id, "", true, "dropped: Flag has no AT primitive") catch {};
            return;
        },
        // Accept/Reject{Follow}: a remote peer is responding to a follow
        // request we (or a bridged actor) sent. AT has no follow-request
        // lifecycle — follows take effect immediately — so there's no
        // record to commit. We record the accept/reject so follow state
        // is observable + consistent through the translation log, and (on
        // Reject) drop any follower row keyed on the inner Follow's id.
        .accept, .reject => {
            try processFollowResponse(act, db, clock);
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
    const is_profile = std.mem.eql(u8, collection, profile_collection);

    // I3: a profile lives at the fixed rkey `self` (one per repo), so
    // repeated edits INSERT-OR-REPLACE the same row. Feed objects key
    // off the AP object id so Delete can re-derive the same rkey.
    const record_cbor = if (is_profile)
        try buildProfileRecord(raw_body, &record_buf)
    else
        try buildBridgeRecord(act, collection, extractApInnerContent(raw_body), &record_buf);

    const rkey = if (is_profile) "self" else blk: {
        const rkey_seed = if (act.object_id.len > 0) act.object_id else act.id;
        break :blk try translatedRkey(rkey_seed, &arena);
    };

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
        "app.bsky.graph.block",
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

/// Undo{Follow|Like|Announce|Block} → delete the bridged AT record.
///
/// AP `Undo` carries `object` = the IRI of the inner activity being
/// undone (`act.object_id`). The bridged record we created for that
/// inner activity stored it in its `bridgedFrom` field, so we locate
/// the record by matching `bridgedFrom` and delete it. `deleteRecord`
/// fires the change hook, so an AP Delete won't loop back (the synthetic
/// repo has no AP followers of its own interactions).
///
/// Follow undones ALSO drop the follower row (B4 parity) so the AT→AP
/// fanout stops reaching the unfollowing peer.
fn processUndo(act: *const Activity, db: *c.sqlite3, clock: core.clock.Clock, probe_order: []const []const u8) !void {
    const inner_id = act.object_id;

    // B4: drop any follower row keyed on the inner Follow's id. Harmless
    // for non-follow undones (no row matches).
    const removed_follower = followers_mod.removeByFollowIri(db, inner_id) catch false;

    // Resolve the actor's DID. If the AP actor was never bridged there's
    // no synthetic repo and nothing to delete — log + return.
    var arena_buf: [4 * 1024]u8 = undefined;
    var arena = Arena.init(&arena_buf);
    const maybe_did = identity_map.didForActor(db, act.actor, &arena) catch null;
    const did = maybe_did orelse {
        const status_msg: []const u8 = if (removed_follower) "" else "undo: no follower row / no bridged actor";
        _ = subscription.appendLog(db, clock, .ap_to_at, inner_id, "[undone]", true, status_msg) catch {};
        return;
    };

    // Find + delete the bridged record by its `bridgedFrom` == inner_id.
    var hit_collection: []const u8 = "";
    var rkey_buf: [256]u8 = undefined;
    var rkey_len: usize = 0;
    for (probe_order) |col| {
        if (findRkeyByBridgedFrom(db, did, col, inner_id, &rkey_buf, &rkey_len)) {
            const deleted = atproto.repo.deleteRecord(db, did, col, rkey_buf[0..rkey_len]) catch false;
            if (deleted) {
                hit_collection = col;
                break;
            }
        }
    }

    if (hit_collection.len == 0) {
        const status_msg: []const u8 = if (removed_follower) "" else "undo: no bridged record";
        _ = subscription.appendLog(db, clock, .ap_to_at, inner_id, "[undone]", true, status_msg) catch {};
        return;
    }

    var translated_buf: [512]u8 = undefined;
    const translated = std.fmt.bufPrint(
        &translated_buf,
        "at://{s}/{s}/{s} [undone]",
        .{ did, hit_collection, rkey_buf[0..rkey_len] },
    ) catch "[undone]";
    _ = subscription.appendLog(db, clock, .ap_to_at, inner_id, translated, true, "") catch {};
    core.metrics.incRelayApToAt();
}

/// Locate the rkey of a bridged record whose DAG-CBOR `value` carries
/// `bridgedFrom == bridged_from`. The activity id is stored verbatim as
/// a CBOR text value, so a substring match on the blob is exact enough:
/// the id is a full URL, collisions would be pathological. Scoped to a
/// single (did, collection). Returns false when none matches.
fn findRkeyByBridgedFrom(
    db: *c.sqlite3,
    did: []const u8,
    collection: []const u8,
    bridged_from: []const u8,
    rkey_out: []u8,
    rkey_len: *usize,
) bool {
    if (bridged_from.len == 0) return false;
    const sql = "SELECT rkey FROM atp_records WHERE did = ? AND collection = ? AND instr(value, ?) > 0 LIMIT 1";
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return false;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, did.ptr, @intCast(did.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 2, collection.ptr, @intCast(collection.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 3, bridged_from.ptr, @intCast(bridged_from.len), c.sqliteTransientAsDestructor());
    if (c.sqlite3_step(stmt.?) != c.SQLITE_ROW) return false;
    const ptr = c.sqlite3_column_text(stmt, 0);
    const n: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
    const cap = @min(n, rkey_out.len);
    if (cap == 0 or ptr == null) return false;
    @memcpy(rkey_out[0..cap], ptr[0..cap]);
    rkey_len.* = cap;
    return true;
}

/// Accept/Reject{Follow}: a remote peer responded to a follow request.
/// AT follows take effect immediately (no request lifecycle), so there's
/// no AT record to commit. We:
///   * record the accept/reject in the translation log (so follow state
///     is observable);
///   * on Reject, drop any follower row keyed on the inner Follow's id
///     (the peer refused — stop fanning out to them).
/// The inner Follow's id is `act.object_id`.
fn processFollowResponse(act: *const Activity, db: *c.sqlite3, clock: core.clock.Clock) !void {
    const inner_id = if (act.object_id.len > 0) act.object_id else act.id;
    const accepted = act.activity_type == .accept;

    var note_buf: [64]u8 = undefined;
    var removed: bool = false;
    if (!accepted and inner_id.len > 0) {
        removed = followers_mod.removeByFollowIri(db, inner_id) catch false;
    }
    const note = std.fmt.bufPrint(
        &note_buf,
        "follow {s}{s}",
        .{ if (accepted) "accepted" else "rejected", if (removed) " (follower dropped)" else "" },
    ) catch (if (accepted) "follow accepted" else "follow rejected");

    const translated: []const u8 = if (accepted) "[follow-accepted]" else "[follow-rejected]";
    _ = subscription.appendLog(db, clock, .ap_to_at, inner_id, translated, true, note) catch {};
    core.metrics.incRelayApToAt();
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
        .block => 4, // $type, bridgedFrom, bridgedActor, subject
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
        .follow, .block => {
            // Follow: subject = followed actor. Block: subject = blocked
            // actor. Both carry the AP target IRI in `object_id`.
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
    return extractJsonStringField(raw_body, "content");
}

/// I3: build an AT `app.bsky.actor.profile` record from an AP Person
/// object. Maps AP `name` → displayName and `summary` → description
/// (Mastodon's bio). Falls back to `preferredUsername` for displayName
/// when `name` is absent. The fields are read from the raw AP body.
fn buildProfileRecord(raw_body: []const u8, out: []u8) ![]const u8 {
    var display = extractJsonStringField(raw_body, "name");
    if (display.len == 0) display = extractJsonStringField(raw_body, "preferredUsername");
    const summary = extractJsonStringField(raw_body, "summary");

    var enc = atproto.dag_cbor.Encoder.init(out);
    try enc.writeMapHeader(3);
    try enc.writeText("$type");
    try enc.writeText(profile_collection);
    try enc.writeText("displayName");
    try enc.writeText(display);
    try enc.writeText("description");
    try enc.writeText(summary);
    return enc.written();
}

/// First `"<field>":"<value>"` string value in a JSON body, with escape
/// handling on the value. Empty slice when absent. Generalised from the
/// original content-only extractor.
fn extractJsonStringField(raw_body: []const u8, field: []const u8) []const u8 {
    // Build the quoted key needle on a small stack buffer.
    var needle_buf: [64]u8 = undefined;
    if (field.len + 2 > needle_buf.len) return "";
    needle_buf[0] = '"';
    @memcpy(needle_buf[1 .. 1 + field.len], field);
    needle_buf[1 + field.len] = '"';
    const needle = needle_buf[0 .. field.len + 2];
    const raw = raw_body;
    var i: usize = 0;
    while (i + needle.len <= raw.len) : (i += 1) {
        if (std.mem.eql(u8, raw[i..][0..needle.len], needle)) {
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

test "J4: fuzz onActivityReceived against random bodies + types" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    var sc = core.clock.SimClock.init(2_000_000_000);
    setRelayHost("relay.fuzz");
    defer setRelayHost("");

    // Seed PRNG from the testing seed for determinism.
    var prng_state = std.Random.DefaultPrng.init(testing.random_seed);
    const rng = prng_state.random();

    var i: u32 = 0;
    while (i < 200) : (i += 1) {
        // Random activity type + bounded random URLs.
        const types = [_]ActivityType{ .create, .update, .delete, .like, .announce, .follow, .undo, .move, .block, .flag };
        const t = types[rng.uintAtMost(usize, types.len - 1)];
        var id_buf: [64]u8 = undefined;
        const id = std.fmt.bufPrint(&id_buf, "https://fuzz.example/act/{x}", .{rng.int(u64)}) catch unreachable;
        var actor_buf: [64]u8 = undefined;
        const actor = std.fmt.bufPrint(&actor_buf, "https://fuzz.example/users/{d}", .{rng.uintAtMost(u32, 100)}) catch unreachable;
        var obj_buf: [64]u8 = undefined;
        const obj = std.fmt.bufPrint(&obj_buf, "https://fuzz.example/obj/{x}", .{rng.int(u64)}) catch unreachable;

        const obj_type: []const u8 = if (t == .create or t == .update) "Note" else "";
        const act: Activity = .{
            .activity_type = t,
            .id = id,
            .actor = actor,
            .object_id = obj,
            .object_type = obj_type,
            .target = "",
            .published = "",
            .to_first = "",
        };
        // Random body shape — sometimes valid JSON, sometimes garbage,
        // always within bounds.
        var body_buf: [256]u8 = undefined;
        const body_len = rng.uintAtMost(usize, body_buf.len);
        for (body_buf[0..body_len]) |*b| b.* = @intCast(rng.uintAtMost(u8, 127));
        onActivityReceived(&act, body_buf[0..body_len], db, sc.clock());
    }
    // The point of the fuzz isn't to assert specific outputs — it's
    // to assert NO PANICS over 200 random inputs. Reaching here is
    // success.
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

test "I3: Update{Person} commits an app.bsky.actor.profile record at rkey self" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    var sc = core.clock.SimClock.init(1_716_500_000);
    setRelayHost("relay.test");
    defer setRelayHost("");

    const body =
        "{\"type\":\"Update\",\"id\":\"https://m.example/users/gwen#updates/1\"," ++
        "\"actor\":\"https://m.example/users/gwen\"," ++
        "\"object\":{\"id\":\"https://m.example/users/gwen\",\"type\":\"Person\"," ++
        "\"name\":\"Gwen 🌟\",\"preferredUsername\":\"gwen\"," ++
        "\"summary\":\"bridge tester & <b>html</b>\"}}";
    const act: Activity = .{
        .activity_type = .update,
        .id = "https://m.example/users/gwen#updates/1",
        .actor = "https://m.example/users/gwen",
        .object_id = "https://m.example/users/gwen",
        .object_type = "Person",
        .target = "",
        .published = "2026-05-20T00:00:00Z",
        .to_first = "",
    };
    onActivityReceived(&act, body, db, sc.clock());

    var arena_buf: [1024]u8 = undefined;
    var arena = Arena.init(&arena_buf);
    const did = (try identity_map.didForActor(db, act.actor, &arena)).?;

    // Exactly one profile record, at rkey 'self', carrying the name.
    var row: atproto.repo.RecordRow = .{};
    const found = try atproto.repo.getRecord(db, did, "app.bsky.actor.profile", "self", &row);
    try testing.expect(found);
    const value = row.value_buf[0..row.value_len];
    // DAG-CBOR stores text values literally — the displayName + summary
    // bytes appear verbatim in the encoded record.
    try testing.expect(std.mem.indexOf(u8, value, "Gwen 🌟") != null);
    try testing.expect(std.mem.indexOf(u8, value, "bridge tester") != null);

    // The translation log records the at-uri with the profile collection.
    var rows: [4]subscription.LogEntry = undefined;
    const n = try subscription.listLog(db, 0, &rows);
    try testing.expect(n >= 1);
    try testing.expect(std.mem.indexOf(u8, rows[0].translatedId(), "app.bsky.actor.profile/self") != null);
}

test "I3: buildProfileRecord falls back to preferredUsername when name is absent" {
    var out: [512]u8 = undefined;
    const body = "{\"type\":\"Person\",\"preferredUsername\":\"solo\",\"summary\":\"\"}";
    const rec = try buildProfileRecord(body, &out);
    try testing.expect(std.mem.indexOf(u8, rec, "solo") != null);
    try testing.expect(std.mem.indexOf(u8, rec, "app.bsky.actor.profile") != null);
}

fn countRecords(db: *c.sqlite3, did: []const u8, collection: []const u8) i64 {
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "SELECT count(*) FROM atp_records WHERE did = ? AND collection = ?", -1, &stmt, null) != c.SQLITE_OK) return -1;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, did.ptr, @intCast(did.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 2, collection.ptr, @intCast(collection.len), c.sqliteTransientAsDestructor());
    if (c.sqlite3_step(stmt.?) != c.SQLITE_ROW) return -1;
    return c.sqlite3_column_int64(stmt, 0);
}

test "Block: AP Block commits an app.bsky.graph.block record with the subject" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    var sc = core.clock.SimClock.init(1_716_700_000);
    setRelayHost("relay.test");
    defer setRelayHost("");

    const act: Activity = .{
        .activity_type = .block,
        .id = "https://m.example/users/han/blocks/1",
        .actor = "https://m.example/users/han",
        .object_id = "https://m.example/users/greedo",
        .object_type = "Person",
        .target = "",
        .published = "2026-05-21T00:00:00Z",
        .to_first = "",
    };
    onActivityReceived(&act, "", db, sc.clock());

    var arena_buf: [1024]u8 = undefined;
    var arena = Arena.init(&arena_buf);
    const did = (try identity_map.didForActor(db, act.actor, &arena)).?;
    try testing.expectEqual(@as(i64, 1), countRecords(db, did, "app.bsky.graph.block"));

    // The committed record carries the blocked actor as `subject`.
    // The rkey was derived from object_id's trailing segment.
    var row: atproto.repo.RecordRow = .{};
    const found = try atproto.repo.getRecord(db, did, "app.bsky.graph.block", "greedo", &row);
    try testing.expect(found);
    const value = row.value_buf[0..row.value_len];
    try testing.expect(std.mem.indexOf(u8, value, "https://m.example/users/greedo") != null);

    var rows: [4]subscription.LogEntry = undefined;
    const n = try subscription.listLog(db, 0, &rows);
    try testing.expect(n >= 1);
    try testing.expect(std.mem.indexOf(u8, rows[0].translatedId(), "app.bsky.graph.block") != null);
}

test "Undo{Block}: AP Block then Undo deletes the bridged block record" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    var sc = core.clock.SimClock.init(1_716_710_000);
    setRelayHost("relay.test");
    defer setRelayHost("");

    const block_act: Activity = .{
        .activity_type = .block,
        .id = "https://m.example/users/lando/blocks/7",
        .actor = "https://m.example/users/lando",
        .object_id = "https://m.example/users/vader",
        .object_type = "Person",
        .target = "",
        .published = "2026-05-21T00:00:00Z",
        .to_first = "",
    };
    onActivityReceived(&block_act, "", db, sc.clock());

    var arena_buf: [1024]u8 = undefined;
    var arena = Arena.init(&arena_buf);
    const did = (try identity_map.didForActor(db, block_act.actor, &arena)).?;
    try testing.expectEqual(@as(i64, 1), countRecords(db, did, "app.bsky.graph.block"));

    // Undo references the inner Block's id in `object`.
    const undo_act: Activity = .{
        .activity_type = .undo,
        .id = "https://m.example/users/lando/undo/9",
        .actor = "https://m.example/users/lando",
        .object_id = "https://m.example/users/lando/blocks/7",
        .object_type = "",
        .target = "",
        .published = "",
        .to_first = "",
    };
    onActivityReceived(&undo_act, "", db, sc.clock());

    try testing.expectEqual(@as(i64, 0), countRecords(db, did, "app.bsky.graph.block"));
}

test "Undo{Like}: AP Like then Undo deletes the bridged like record" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    var sc = core.clock.SimClock.init(1_716_720_000);
    setRelayHost("relay.test");
    defer setRelayHost("");

    const like_act: Activity = .{
        .activity_type = .like,
        .id = "https://m.example/users/leia/likes/3",
        .actor = "https://m.example/users/leia",
        .object_id = "https://m.example/notes/xyz",
        .object_type = "",
        .target = "",
        .published = "2026-05-21T00:00:00Z",
        .to_first = "",
    };
    onActivityReceived(&like_act, "", db, sc.clock());

    var arena_buf: [1024]u8 = undefined;
    var arena = Arena.init(&arena_buf);
    const did = (try identity_map.didForActor(db, like_act.actor, &arena)).?;
    try testing.expectEqual(@as(i64, 1), countRecords(db, did, "app.bsky.feed.like"));

    const undo_act: Activity = .{
        .activity_type = .undo,
        .id = "https://m.example/users/leia/undo/4",
        .actor = "https://m.example/users/leia",
        .object_id = "https://m.example/users/leia/likes/3",
        .object_type = "",
        .target = "",
        .published = "",
        .to_first = "",
    };
    onActivityReceived(&undo_act, "", db, sc.clock());

    try testing.expectEqual(@as(i64, 0), countRecords(db, did, "app.bsky.feed.like"));
}

test "Accept{Follow}: recorded in the translation log, no record committed" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    var sc = core.clock.SimClock.init(1_716_730_000);
    setRelayHost("relay.test");
    defer setRelayHost("");

    const accept_act: Activity = .{
        .activity_type = .accept,
        .id = "https://m.example/users/yoda/accept/1",
        .actor = "https://m.example/users/yoda",
        .object_id = "https://relay.test/activities/at::did:plc:luke:app.bsky.graph.follow:f1",
        .object_type = "Follow",
        .target = "",
        .published = "2026-05-21T00:00:00Z",
        .to_first = "",
    };
    onActivityReceived(&accept_act, "", db, sc.clock());

    var rows: [4]subscription.LogEntry = undefined;
    const n = try subscription.listLog(db, 0, &rows);
    try testing.expectEqual(@as(u32, 1), n);
    try testing.expectEqualStrings("[follow-accepted]", rows[0].translatedId());
    try testing.expect(std.mem.startsWith(u8, rows[0].errorMsg(), "follow accepted"));
}

test "Reject{Follow}: drops the follower row + logs the rejection" {
    const db = try setupDb();
    defer core.storage.sqlite.closeDb(db);
    var sc = core.clock.SimClock.init(1_716_740_000);
    setRelayHost("relay.test");
    defer setRelayHost("");

    // First a Follow comes in so a follower row exists.
    const follow_act: Activity = .{
        .activity_type = .follow,
        .id = "https://m.example/follow/fr",
        .actor = "https://m.example/users/jabba",
        .object_id = "https://relay.test/ap/users/at:plc:han",
        .object_type = "Person",
        .target = "",
        .published = "",
        .to_first = "",
    };
    onActivityReceived(&follow_act, "", db, sc.clock());
    var f_buf: [4]followers_mod.Follower = undefined;
    try testing.expectEqual(@as(u32, 1), try followers_mod.list(db, follow_act.object_id, &f_buf));

    // Reject referencing the inner Follow's id undoes the pending follow.
    const reject_act: Activity = .{
        .activity_type = .reject,
        .id = "https://m.example/users/han/reject/1",
        .actor = "https://relay.test/ap/users/at:plc:han",
        .object_id = "https://m.example/follow/fr",
        .object_type = "Follow",
        .target = "",
        .published = "",
        .to_first = "",
    };
    onActivityReceived(&reject_act, "", db, sc.clock());

    try testing.expectEqual(@as(u32, 0), try followers_mod.list(db, follow_act.object_id, &f_buf));
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
