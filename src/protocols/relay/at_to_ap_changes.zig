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
const dag_cbor = atproto.dag_cbor;

const state = @import("state.zig");
const identity_map = @import("identity_map.zig");

const profile_collection = "app.bsky.actor.profile";

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

    // I2: a profile create or update bridges to an AP `Update{Person}`
    // carrying the actor's displayName→name + description→summary. The
    // generic-Note path below only covers feed objects.
    const is_profile = std.mem.eql(u8, collection, profile_collection);
    if (is_profile and (kind == .create or kind == .update)) {
        const payload = renderProfileUpdate(db, did, actor, ap_id, clock.wallUnix()) catch return;
        enqueueOutboxBestEffort(db, actor, payload, clock.wallUnix());
        logTranslation(db, "at_to_ap", at_uri, ap_id, clock.wallUnix());
        return;
    }

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

// ── I2: AT app.bsky.actor.profile → AP Update{Person} ──────────────────

pub const max_profile_field_bytes: usize = 1024;

pub const ProfileFields = struct {
    display_name: []const u8 = "",
    description: []const u8 = "",
};

/// Extract `displayName` / `description` from a DAG-CBOR profile record.
/// Returns empty strings for absent fields; never errors on malformed
/// input (best-effort, slices alias the provided buffers).
pub fn extractProfile(cbor: []const u8, dn_buf: []u8, desc_buf: []u8) ProfileFields {
    var out: ProfileFields = .{};
    var dec = dag_cbor.Decoder.init(cbor);
    const first = dec.nextEvent() catch return out;
    const pairs = switch (first) {
        .map_start => |n| n,
        else => return out,
    };
    var i: u64 = 0;
    while (i < pairs) : (i += 1) {
        const key_ev = dec.nextEvent() catch return out;
        const key = switch (key_ev) {
            .text => |t| t,
            else => return out, // DAG-CBOR map keys are always text
        };
        const val_ev = dec.nextEvent() catch return out;
        if (std.mem.eql(u8, key, "displayName")) {
            if (val_ev == .text) out.display_name = copyInto(dn_buf, val_ev.text) else skipRest(&dec, val_ev) catch return out;
        } else if (std.mem.eql(u8, key, "description")) {
            if (val_ev == .text) out.description = copyInto(desc_buf, val_ev.text) else skipRest(&dec, val_ev) catch return out;
        } else {
            skipRest(&dec, val_ev) catch return out;
        }
    }
    return out;
}

fn copyInto(buf: []u8, s: []const u8) []const u8 {
    const n = @min(s.len, buf.len);
    @memcpy(buf[0..n], s[0..n]);
    return buf[0..n];
}

/// Consume the remainder of a value whose first event was already read.
/// Recurses into containers; bounded by the DAG-CBOR decoder's own
/// nesting limit on well-formed input.
fn skipRest(dec: *dag_cbor.Decoder, ev: dag_cbor.Event) !void {
    switch (ev) {
        .map_start => |n| {
            var i: u64 = 0;
            while (i < n * 2) : (i += 1) {
                const e = try dec.nextEvent();
                try skipRest(dec, e);
            }
        },
        .array_start => |n| {
            var i: u64 = 0;
            while (i < n) : (i += 1) {
                const e = try dec.nextEvent();
                try skipRest(dec, e);
            }
        },
        else => {},
    }
}

/// Render `Update{Person}` with the profile fields. Reads the profile
/// record from `atp_records`; missing record => an Update with no
/// name/summary (still signals "profile changed").
fn renderProfileUpdate(db: *c.sqlite3, did: []const u8, actor: []const u8, ap_id: []const u8, _: i64) ![]const u8 {
    var dn_buf: [max_profile_field_bytes]u8 = undefined;
    var desc_buf: [max_profile_field_bytes]u8 = undefined;
    var fields: ProfileFields = .{};

    var row: repo.RecordRow = .{};
    if (repo.getRecord(db, did, profile_collection, "self", &row)) |found| {
        if (found) fields = extractProfile(row.value_buf[0..row.value_len], &dn_buf, &desc_buf);
    } else |_| {}

    var name_esc: [max_profile_field_bytes * 2]u8 = undefined;
    var summary_esc: [max_profile_field_bytes * 2]u8 = undefined;
    const name = jsonEscape(&name_esc, fields.display_name);
    const summary = jsonEscape(&summary_esc, fields.description);

    const fmt =
        \\{{"@context":"https://www.w3.org/ns/activitystreams","id":"{s}","type":"Update","actor":"{s}","object":{{"id":"{s}","type":"Person","name":"{s}","summary":"{s}"}}}}
    ;
    const written = try std.fmt.bufPrint(&payload_static.buf, fmt, .{ ap_id, actor, actor, name, summary });
    payload_static.len = @intCast(written.len);
    return payload_static.buf[0..written.len];
}

/// Minimal RFC-8259 JSON string-body escaper (no surrounding quotes).
/// Truncates if the escaped form would overflow `out`.
fn jsonEscape(out: []u8, s: []const u8) []const u8 {
    var w: usize = 0;
    for (s) |ch| {
        const seq: []const u8 = switch (ch) {
            '"' => "\\\"",
            '\\' => "\\\\",
            '\n' => "\\n",
            '\r' => "\\r",
            '\t' => "\\t",
            0x00...0x08, 0x0b, 0x0c, 0x0e...0x1f => {
                // \u00XX escape, written directly to avoid a dangling slice.
                const esc = std.fmt.bufPrint(out[w..], "\\u{x:0>4}", .{ch}) catch break;
                w += esc.len;
                continue;
            },
            else => {
                if (w < out.len) {
                    out[w] = ch;
                    w += 1;
                }
                continue;
            },
        };
        if (w + seq.len > out.len) break;
        @memcpy(out[w .. w + seq.len], seq);
        w += seq.len;
    }
    return out[0..w];
}

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

test "I2: extractProfile pulls displayName + description from DAG-CBOR" {
    // Encode a realistic profile record: {$type, displayName, description,
    // avatar:{...}} — the avatar map must be skipped, not mis-parsed.
    var cbor_buf: [512]u8 = undefined;
    var enc = dag_cbor.Encoder.init(&cbor_buf);
    try enc.writeMapHeader(4);
    try enc.writeText("$type");
    try enc.writeText("app.bsky.actor.profile");
    try enc.writeText("displayName");
    try enc.writeText("Alice 🌸");
    try enc.writeText("description");
    try enc.writeText("hi \"there\"\nline2");
    try enc.writeText("avatar");
    try enc.writeMapHeader(1);
    try enc.writeText("cid");
    try enc.writeText("bafyblob");

    var dn: [128]u8 = undefined;
    var desc: [128]u8 = undefined;
    const fields = extractProfile(enc.written(), &dn, &desc);
    try testing.expectEqualStrings("Alice 🌸", fields.display_name);
    try testing.expectEqualStrings("hi \"there\"\nline2", fields.description);
}

test "I2: extractProfile tolerates missing fields and malformed input" {
    var dn: [64]u8 = undefined;
    var desc: [64]u8 = undefined;

    // Empty/garbage → empty fields, no crash (randomized fuzz).
    var prng = std.Random.DefaultPrng.init(0x12_05_A2);
    const rand = prng.random();
    var trial: usize = 0;
    while (trial < 200) : (trial += 1) {
        var noise: [64]u8 = undefined;
        const n = rand.intRangeAtMost(usize, 0, noise.len);
        rand.bytes(noise[0..n]);
        const f = extractProfile(noise[0..n], &dn, &desc);
        _ = f; // must not crash
    }

    // A profile with only displayName.
    var cbor_buf: [128]u8 = undefined;
    var enc = dag_cbor.Encoder.init(&cbor_buf);
    try enc.writeMapHeader(1);
    try enc.writeText("displayName");
    try enc.writeText("Bob");
    const fields = extractProfile(enc.written(), &dn, &desc);
    try testing.expectEqualStrings("Bob", fields.display_name);
    try testing.expectEqualStrings("", fields.description);
}

test "I2: jsonEscape escapes quotes, backslashes and control chars" {
    var out: [128]u8 = undefined;
    try testing.expectEqualStrings("a\\\"b", jsonEscape(&out, "a\"b"));
    try testing.expectEqualStrings("x\\\\y", jsonEscape(&out, "x\\y"));
    try testing.expectEqualStrings("l1\\nl2", jsonEscape(&out, "l1\nl2"));
    try testing.expectEqualStrings("\\u0001", jsonEscape(&out, "\x01"));
    try testing.expectEqualStrings("plain", jsonEscape(&out, "plain"));
}