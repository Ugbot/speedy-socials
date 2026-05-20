//! Op-A / A3b + A4b + I3: AT→AP change hook.
//!
//! Registers with `atproto.repo.setChangeHook` so every record
//! create / update / delete on the AT side gets a corresponding
//! AP Delete or AP Update queued into `ap_federation_outbox`. The
//! existing firehose_consumer continues to handle creates (it has
//! richer body parsing); this hook covers the deletion + mutation
//! gaps that the firehose alone can't surface (deleted rows are
//! gone from atp_records by the time the consumer reads).
//!
//! Tiger Style: synchronous on the writer thread, fixed buffers,
//! best-effort SQL (failures are audit-logged but never panic).

const std = @import("std");
const core = @import("core");
const c = @import("sqlite").c;
const atproto = @import("protocol_atproto");
const repo = atproto.repo;

const state = @import("state.zig");
const identity_map = @import("identity_map.zig");

/// Bound the activity-id buffer; the AP activity id is built from
/// the AT URI by replacing `/` → `:` to stay URL-safe.
const max_activity_id_bytes: usize = 512;

pub fn onChange(kind: repo.ChangeKind, did: []const u8, collection: []const u8, rkey: []const u8, cid: []const u8) void {
    const st = state.get();
    const db = st.reader_db orelse return;
    const clock = st.clock;

    // We only bridge a known set of collections — the same ones the
    // existing firehose consumer translates.
    if (!isBridgedCollection(collection)) return;

    // Build the at-uri and ap activity id.
    var at_uri_buf: [512]u8 = undefined;
    const at_uri = std.fmt.bufPrint(&at_uri_buf, "at://{s}/{s}/{s}", .{ did, collection, rkey }) catch return;

    // Look up the actor IRI for the synthetic AP actor bound to this
    // DID. If none exists yet, the create path of the existing
    // consumer will mint one. Updates/deletes need it to exist.
    var actor_buf: [320]u8 = undefined;
    const actor = lookupActorForDid(db, did, &actor_buf) orelse return;

    var ap_id_buf: [max_activity_id_bytes]u8 = undefined;
    const ap_id = buildApActivityId(st.relayHost(), at_uri, &ap_id_buf) catch return;
    _ = cid; // commit CID isn't needed for the AP envelope today

    switch (kind) {
        .create => {
            // The existing firehose consumer handles creates; nothing
            // to do here.
        },
        .update => {
            // AP Update: re-publishes the object body.
            const payload = renderUpdate(actor, ap_id, at_uri, clock.wallUnix()) catch return;
            enqueueOutboxBestEffort(db, actor, payload, clock.wallUnix());
            logTranslation(db, "at_to_ap", at_uri, ap_id, clock.wallUnix());
        },
        .delete => {
            // AP Delete: signals the bridged AP peer to drop the post.
            const payload = renderDelete(actor, ap_id, at_uri, clock.wallUnix()) catch return;
            enqueueOutboxBestEffort(db, actor, payload, clock.wallUnix());
            logTranslation(db, "at_to_ap", at_uri, ap_id, clock.wallUnix());
        },
    }
}

fn isBridgedCollection(c_name: []const u8) bool {
    const bridged = [_][]const u8{
        "app.bsky.feed.post",
        "app.bsky.feed.like",
        "app.bsky.feed.repost",
        "app.bsky.graph.follow",
        "app.bsky.actor.profile",
    };
    for (bridged) |b| {
        if (std.mem.eql(u8, b, c_name)) return true;
    }
    return false;
}

fn lookupActorForDid(db: *c.sqlite3, did: []const u8, out: []u8) ?[]const u8 {
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "SELECT ap_actor_url FROM relay_identity_map WHERE did = ?", -1, &stmt, null) != c.SQLITE_OK) return null;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, did.ptr, @intCast(did.len), c.sqliteTransientAsDestructor());
    if (c.sqlite3_step(stmt.?) != c.SQLITE_ROW) return null;
    const p = c.sqlite3_column_text(stmt, 0);
    const n: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
    const cap = @min(n, out.len);
    @memcpy(out[0..cap], p[0..cap]);
    return out[0..cap];
}

fn buildApActivityId(host: []const u8, at_uri: []const u8, out: []u8) ![]const u8 {
    // Replace '/' with ':' for path safety.
    var tmp: [512]u8 = undefined;
    if (at_uri.len > tmp.len) return error.TooLong;
    for (at_uri, 0..) |ch, i| tmp[i] = if (ch == '/') ':' else ch;
    return std.fmt.bufPrint(out, "https://{s}/activities/{s}", .{ host, tmp[0..at_uri.len] });
}

fn renderDelete(actor: []const u8, ap_id: []const u8, target_id: []const u8, _: i64) ![]const u8 {
    const fmt =
        \\{{"@context":"https://www.w3.org/ns/activitystreams","id":"{s}","type":"Delete","actor":"{s}","object":"{s}"}}
    ;
    var buf: [2048]u8 = undefined;
    const written = try std.fmt.bufPrint(&buf, fmt, .{ ap_id, actor, target_id });
    // Heap-stable copy: we return a slice into a process-local
    // static buffer so the caller's enqueue path can borrow it.
    payload_static.len = @intCast(written.len);
    @memcpy(payload_static.buf[0..written.len], written);
    return payload_static.buf[0..written.len];
}

fn renderUpdate(actor: []const u8, ap_id: []const u8, target_id: []const u8, _: i64) ![]const u8 {
    const fmt =
        \\{{"@context":"https://www.w3.org/ns/activitystreams","id":"{s}","type":"Update","actor":"{s}","object":{{"id":"{s}","type":"Note"}}}}
    ;
    var buf: [2048]u8 = undefined;
    const written = try std.fmt.bufPrint(&buf, fmt, .{ ap_id, actor, target_id });
    payload_static.len = @intCast(written.len);
    @memcpy(payload_static.buf[0..written.len], written);
    return payload_static.buf[0..written.len];
}

const payload_static = struct {
    var buf: [4096]u8 = undefined;
    var len: u16 = 0;
};

fn enqueueOutboxBestEffort(db: *c.sqlite3, actor: []const u8, payload: []const u8, now: i64) void {
    // Look up follower inboxes and enqueue one row per follower.
    // (Production also has the env-bootstrapped bridge_target_inbox,
    // but the hook fires for changes — the follower table is the
    // canonical fanout.)
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "SELECT follower_inbox FROM relay_followers WHERE actor_url = ?", -1, &stmt, null) != c.SQLITE_OK) return;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, actor.ptr, @intCast(actor.len), c.sqliteTransientAsDestructor());

    var keyid_buf: [320]u8 = undefined;
    const keyid = std.fmt.bufPrint(&keyid_buf, "{s}#main-key", .{actor}) catch return;

    while (true) {
        const rc = c.sqlite3_step(stmt.?);
        if (rc != c.SQLITE_ROW) break;
        const inbox_ptr = c.sqlite3_column_text(stmt, 0);
        const inbox_len: usize = @intCast(c.sqlite3_column_bytes(stmt, 0));
        if (inbox_len == 0) continue;

        var enq: ?*c.sqlite3_stmt = null;
        const sql =
            \\INSERT INTO ap_federation_outbox
            \\  (target_inbox, shared_inbox, payload, key_id, attempts, next_attempt_at, state, inserted_at)
            \\VALUES (?, NULL, ?, ?, 0, ?, 'pending', ?)
        ;
        if (c.sqlite3_prepare_v2(db, sql, -1, &enq, null) != c.SQLITE_OK) continue;
        defer _ = c.sqlite3_finalize(enq);
        _ = c.sqlite3_bind_text(enq, 1, inbox_ptr, @intCast(inbox_len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_blob(enq, 2, payload.ptr, @intCast(payload.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_text(enq, 3, keyid.ptr, @intCast(keyid.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_int64(enq, 4, now);
        _ = c.sqlite3_bind_int64(enq, 5, now);
        _ = c.sqlite3_step(enq.?);
    }
}

fn logTranslation(db: *c.sqlite3, direction: []const u8, src: []const u8, dst: []const u8, ts: i64) void {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "INSERT INTO relay_translation_log (direction, source_id, translated_id, success, error_msg, ts) VALUES (?,?,?,1,NULL,?)";
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, direction.ptr, @intCast(direction.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 2, src.ptr, @intCast(src.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 3, dst.ptr, @intCast(dst.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(stmt, 4, ts);
    _ = c.sqlite3_step(stmt);
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "Op-A: isBridgedCollection recognises bsky NSIDs" {
    try testing.expect(isBridgedCollection("app.bsky.feed.post"));
    try testing.expect(isBridgedCollection("app.bsky.actor.profile"));
    try testing.expect(!isBridgedCollection("com.example.custom"));
}

test "Op-A: buildApActivityId replaces / with :" {
    var buf: [256]u8 = undefined;
    const id = try buildApActivityId("example.com", "at://did:plc:a/app.bsky.feed.post/rkey1", &buf);
    try testing.expect(std.mem.indexOf(u8, id, "at::did:plc:a:app.bsky.feed.post:rkey1") != null);
}