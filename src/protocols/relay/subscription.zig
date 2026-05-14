//! Subscription lifecycle + translation log helpers.
//!
//! Production calls these from the admin routes and the (future)
//! firehose / inbox consumer threads. Tests drive them directly against
//! an in-memory SQLite — the helpers take a `*c.sqlite3` so they're
//! easy to exercise without spinning up the writer thread.
//!
//! "Subscription" is the durable bookkeeping for an upstream protocol
//! source: either an AT firehose URL or an AP inbox URL we periodically
//! drain. The relay does not (yet) own the consumer threads; this
//! module is the persistence + admin surface.

const std = @import("std");
const c = @import("sqlite").c;
const core = @import("core");

const RelayError = core.errors.RelayError;
const Arena = core.arena.Arena;
const Clock = core.clock.Clock;
const assertLe = core.assert.assertLe;

pub const Kind = enum {
    atproto_firehose,
    activitypub_inbox,

    pub fn label(self: Kind) []const u8 {
        return switch (self) {
            .atproto_firehose => "atproto_firehose",
            .activitypub_inbox => "activitypub_inbox",
        };
    }

    pub fn parse(s: []const u8) ?Kind {
        if (std.mem.eql(u8, s, "atproto_firehose")) return .atproto_firehose;
        if (std.mem.eql(u8, s, "activitypub_inbox")) return .activitypub_inbox;
        return null;
    }
};

pub const State = enum {
    active,
    paused,
    failed,

    pub fn label(self: State) []const u8 {
        return switch (self) {
            .active => "active",
            .paused => "paused",
            .failed => "failed",
        };
    }
};

pub const Direction = enum {
    at_to_ap,
    ap_to_at,

    pub fn label(self: Direction) []const u8 {
        return switch (self) {
            .at_to_ap => "at_to_ap",
            .ap_to_at => "ap_to_at",
        };
    }
};

/// Maximum length of a subscription source string.
pub const max_source_bytes: usize = 512;
/// Maximum length of an opaque cursor token returned by the upstream.
pub const max_cursor_bytes: usize = 256;
/// Maximum length of a translation-log id field.
pub const max_log_id_bytes: usize = 512;
/// Maximum rows returned by `listSubscriptions` / `listLog`. Anything
/// past this requires a second call with a non-zero offset.
pub const max_list_rows: u32 = 64;

pub const Subscription = struct {
    id: i64,
    kind: Kind,
    source_buf: [max_source_bytes]u8 = undefined,
    source_len: u16 = 0,
    cursor_buf: [max_cursor_bytes]u8 = undefined,
    cursor_len: u16 = 0,
    state: State,
    created_at: i64,

    pub fn source(self: *const Subscription) []const u8 {
        return self.source_buf[0..self.source_len];
    }
    pub fn cursor(self: *const Subscription) []const u8 {
        return self.cursor_buf[0..self.cursor_len];
    }
};

/// Create (or upsert) a subscription. The `(kind, source)` pair is
/// unique; calling `subscribe` twice with the same pair is a no-op that
/// flips state back to `active`.
pub fn subscribe(
    db: *c.sqlite3,
    clock: Clock,
    kind: Kind,
    source: []const u8,
) RelayError!i64 {
    if (source.len == 0 or source.len > max_source_bytes) return error.BadSubscriptionState;
    var stmt: ?*c.sqlite3_stmt = null;
    const sql =
        \\INSERT INTO relay_subscriptions (kind, source, cursor, state, created_at)
        \\VALUES (?, ?, NULL, 'active', ?)
        \\ON CONFLICT(kind, source) DO UPDATE SET state = 'active'
        \\RETURNING id
    ;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return error.BadSubscriptionState;
    }
    defer _ = c.sqlite3_finalize(stmt);
    const now: i64 = @intCast(@divTrunc(clock.wallNs(), std.time.ns_per_s));
    if (c.sqlite3_bind_text(stmt, 1, kind.label().ptr, @intCast(kind.label().len), c.sqliteTransientAsDestructor()) != c.SQLITE_OK) return error.BadSubscriptionState;
    if (c.sqlite3_bind_text(stmt, 2, source.ptr, @intCast(source.len), c.sqliteTransientAsDestructor()) != c.SQLITE_OK) return error.BadSubscriptionState;
    if (c.sqlite3_bind_int64(stmt, 3, now) != c.SQLITE_OK) return error.BadSubscriptionState;
    const step = c.sqlite3_step(stmt);
    if (step != c.SQLITE_ROW) return error.BadSubscriptionState;
    return c.sqlite3_column_int64(stmt, 0);
}

/// Transition a subscription's state. Allowed transitions:
///   active → paused | failed
///   paused → active
///   failed → active
pub fn setState(db: *c.sqlite3, id: i64, new_state: State) RelayError!void {
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "UPDATE relay_subscriptions SET state = ? WHERE id = ?", -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return error.BadSubscriptionState;
    }
    defer _ = c.sqlite3_finalize(stmt);
    if (c.sqlite3_bind_text(stmt, 1, new_state.label().ptr, @intCast(new_state.label().len), c.sqliteTransientAsDestructor()) != c.SQLITE_OK) return error.BadSubscriptionState;
    if (c.sqlite3_bind_int64(stmt, 2, id) != c.SQLITE_OK) return error.BadSubscriptionState;
    if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.BadSubscriptionState;
    if (c.sqlite3_changes(db) == 0) return error.SubscriptionNotFound;
}

/// List subscriptions (bounded; caller paginates).
pub fn listSubscriptions(
    db: *c.sqlite3,
    offset: u32,
    out: []Subscription,
) RelayError!u32 {
    assertLe(out.len, max_list_rows);
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "SELECT id, kind, source, cursor, state, created_at FROM relay_subscriptions ORDER BY id ASC LIMIT ? OFFSET ?";
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return error.BadSubscriptionState;
    }
    defer _ = c.sqlite3_finalize(stmt);
    if (c.sqlite3_bind_int64(stmt, 1, @intCast(out.len)) != c.SQLITE_OK) return error.BadSubscriptionState;
    if (c.sqlite3_bind_int64(stmt, 2, @intCast(offset)) != c.SQLITE_OK) return error.BadSubscriptionState;

    var n: u32 = 0;
    while (n < out.len) {
        const rc = c.sqlite3_step(stmt);
        if (rc == c.SQLITE_DONE) break;
        if (rc != c.SQLITE_ROW) return error.BadSubscriptionState;
        var row: Subscription = .{
            .id = c.sqlite3_column_int64(stmt, 0),
            .kind = .atproto_firehose, // overwritten below
            .state = .active,
            .created_at = c.sqlite3_column_int64(stmt, 5),
        };
        // kind
        const kp = c.sqlite3_column_text(stmt, 1);
        const kn: usize = @intCast(c.sqlite3_column_bytes(stmt, 1));
        if (Kind.parse(kp[0..kn])) |k| row.kind = k else return error.BadSubscriptionState;
        // source
        const sp = c.sqlite3_column_text(stmt, 2);
        const sn: usize = @intCast(c.sqlite3_column_bytes(stmt, 2));
        const copy_s: u16 = @intCast(@min(sn, max_source_bytes));
        if (sn > 0 and sp != null) @memcpy(row.source_buf[0..copy_s], sp[0..copy_s]);
        row.source_len = copy_s;
        // cursor (may be NULL)
        if (c.sqlite3_column_type(stmt, 3) == c.SQLITE_TEXT) {
            const cp = c.sqlite3_column_text(stmt, 3);
            const cn: usize = @intCast(c.sqlite3_column_bytes(stmt, 3));
            const copy_c: u16 = @intCast(@min(cn, max_cursor_bytes));
            if (cn > 0 and cp != null) @memcpy(row.cursor_buf[0..copy_c], cp[0..copy_c]);
            row.cursor_len = copy_c;
        }
        // state
        const stp = c.sqlite3_column_text(stmt, 4);
        const stn: usize = @intCast(c.sqlite3_column_bytes(stmt, 4));
        const state_text = stp[0..stn];
        if (std.mem.eql(u8, state_text, "active")) row.state = .active else if (std.mem.eql(u8, state_text, "paused")) row.state = .paused else if (std.mem.eql(u8, state_text, "failed")) row.state = .failed else return error.BadSubscriptionState;

        out[n] = row;
        n += 1;
    }
    return n;
}

// ── Translation log ───────────────────────────────────────────────────

pub const LogEntry = struct {
    id: i64,
    direction: Direction,
    source_id_buf: [max_log_id_bytes]u8 = undefined,
    source_id_len: u16 = 0,
    translated_id_buf: [max_log_id_bytes]u8 = undefined,
    translated_id_len: u16 = 0,
    success: bool,
    error_msg_buf: [128]u8 = undefined,
    error_msg_len: u8 = 0,
    ts: i64,

    pub fn sourceId(self: *const LogEntry) []const u8 {
        return self.source_id_buf[0..self.source_id_len];
    }
    pub fn translatedId(self: *const LogEntry) []const u8 {
        return self.translated_id_buf[0..self.translated_id_len];
    }
    pub fn errorMsg(self: *const LogEntry) []const u8 {
        return self.error_msg_buf[0..self.error_msg_len];
    }
};

/// Append a translation log entry. Returns the new row id.
pub fn appendLog(
    db: *c.sqlite3,
    clock: Clock,
    direction: Direction,
    source_id: []const u8,
    translated_id: []const u8,
    success: bool,
    error_msg: []const u8,
) RelayError!i64 {
    if (source_id.len == 0 or source_id.len > max_log_id_bytes) return error.BadSubscriptionState;
    if (translated_id.len > max_log_id_bytes) return error.BadSubscriptionState;
    var stmt: ?*c.sqlite3_stmt = null;
    const sql =
        \\INSERT INTO relay_translation_log (direction, source_id, translated_id, success, error_msg, ts)
        \\VALUES (?, ?, ?, ?, ?, ?)
        \\RETURNING id
    ;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return error.BadSubscriptionState;
    }
    defer _ = c.sqlite3_finalize(stmt);
    const now: i64 = @intCast(@divTrunc(clock.wallNs(), std.time.ns_per_s));
    if (c.sqlite3_bind_text(stmt, 1, direction.label().ptr, @intCast(direction.label().len), c.sqliteTransientAsDestructor()) != c.SQLITE_OK) return error.BadSubscriptionState;
    if (c.sqlite3_bind_text(stmt, 2, source_id.ptr, @intCast(source_id.len), c.sqliteTransientAsDestructor()) != c.SQLITE_OK) return error.BadSubscriptionState;
    if (c.sqlite3_bind_text(stmt, 3, translated_id.ptr, @intCast(translated_id.len), c.sqliteTransientAsDestructor()) != c.SQLITE_OK) return error.BadSubscriptionState;
    if (c.sqlite3_bind_int64(stmt, 4, if (success) 1 else 0) != c.SQLITE_OK) return error.BadSubscriptionState;
    if (error_msg.len == 0) {
        if (c.sqlite3_bind_null(stmt, 5) != c.SQLITE_OK) return error.BadSubscriptionState;
    } else {
        if (c.sqlite3_bind_text(stmt, 5, error_msg.ptr, @intCast(error_msg.len), c.sqliteTransientAsDestructor()) != c.SQLITE_OK) return error.BadSubscriptionState;
    }
    if (c.sqlite3_bind_int64(stmt, 6, now) != c.SQLITE_OK) return error.BadSubscriptionState;
    if (c.sqlite3_step(stmt) != c.SQLITE_ROW) return error.BadSubscriptionState;
    return c.sqlite3_column_int64(stmt, 0);
}

/// Paginated log read, newest first.
pub fn listLog(
    db: *c.sqlite3,
    offset: u32,
    out: []LogEntry,
) RelayError!u32 {
    assertLe(out.len, max_list_rows);
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "SELECT id, direction, source_id, translated_id, success, error_msg, ts FROM relay_translation_log ORDER BY id DESC LIMIT ? OFFSET ?", -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return error.BadSubscriptionState;
    }
    defer _ = c.sqlite3_finalize(stmt);
    if (c.sqlite3_bind_int64(stmt, 1, @intCast(out.len)) != c.SQLITE_OK) return error.BadSubscriptionState;
    if (c.sqlite3_bind_int64(stmt, 2, @intCast(offset)) != c.SQLITE_OK) return error.BadSubscriptionState;

    var n: u32 = 0;
    while (n < out.len) {
        const rc = c.sqlite3_step(stmt);
        if (rc == c.SQLITE_DONE) break;
        if (rc != c.SQLITE_ROW) return error.BadSubscriptionState;
        var e: LogEntry = .{
            .id = c.sqlite3_column_int64(stmt, 0),
            .direction = .at_to_ap,
            .success = c.sqlite3_column_int64(stmt, 4) != 0,
            .ts = c.sqlite3_column_int64(stmt, 6),
        };
        // direction
        const dp = c.sqlite3_column_text(stmt, 1);
        const dn: usize = @intCast(c.sqlite3_column_bytes(stmt, 1));
        const dtext = dp[0..dn];
        if (std.mem.eql(u8, dtext, "at_to_ap")) e.direction = .at_to_ap else if (std.mem.eql(u8, dtext, "ap_to_at")) e.direction = .ap_to_at else return error.BadSubscriptionState;
        // source_id
        const sp = c.sqlite3_column_text(stmt, 2);
        const sn: usize = @intCast(c.sqlite3_column_bytes(stmt, 2));
        const cs: u16 = @intCast(@min(sn, max_log_id_bytes));
        if (sn > 0) @memcpy(e.source_id_buf[0..cs], sp[0..cs]);
        e.source_id_len = cs;
        // translated_id
        const tp = c.sqlite3_column_text(stmt, 3);
        const tn: usize = @intCast(c.sqlite3_column_bytes(stmt, 3));
        const ct: u16 = @intCast(@min(tn, max_log_id_bytes));
        if (tn > 0) @memcpy(e.translated_id_buf[0..ct], tp[0..ct]);
        e.translated_id_len = ct;
        // error_msg (nullable)
        if (c.sqlite3_column_type(stmt, 5) == c.SQLITE_TEXT) {
            const ep = c.sqlite3_column_text(stmt, 5);
            const en: usize = @intCast(c.sqlite3_column_bytes(stmt, 5));
            const ce: u8 = @intCast(@min(en, e.error_msg_buf.len));
            if (en > 0) @memcpy(e.error_msg_buf[0..ce], ep[0..ce]);
            e.error_msg_len = ce;
        }
        out[n] = e;
        n += 1;
    }
    return n;
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;
const sqlite_mod = core.storage.sqlite;
const schema = @import("schema.zig");

fn applyRelaySchema(db: *c.sqlite3) !void {
    for (schema.all_migrations) |m| {
        const sql_z = try testing.allocator.dupeZ(u8, m.up);
        defer testing.allocator.free(sql_z);
        var errmsg: [*c]u8 = null;
        const rc = c.sqlite3_exec(db, sql_z.ptr, null, null, &errmsg);
        if (errmsg != null) c.sqlite3_free(errmsg);
        if (rc != c.SQLITE_OK) return error.TestSchemaFailed;
    }
}

test "subscription lifecycle: subscribe → pause → list shows paused" {
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try applyRelaySchema(db);
    var sc = core.clock.SimClock.init(1_700_000_000);

    const id_a = try subscribe(db, sc.clock(), .atproto_firehose, "wss://bsky.network");
    const id_b = try subscribe(db, sc.clock(), .activitypub_inbox, "https://mastodon.social/inbox");
    try testing.expect(id_a != id_b);

    try setState(db, id_a, .paused);

    var rows: [4]Subscription = undefined;
    const n = try listSubscriptions(db, 0, &rows);
    try testing.expectEqual(@as(u32, 2), n);
    // Find id_a, assert paused.
    var found_a = false;
    for (rows[0..n]) |r| {
        if (r.id == id_a) {
            try testing.expectEqual(State.paused, r.state);
            try testing.expectEqual(Kind.atproto_firehose, r.kind);
            try testing.expectEqualStrings("wss://bsky.network", r.source());
            found_a = true;
        }
    }
    try testing.expect(found_a);
}

test "subscription dedup: subscribe twice → same id, state active" {
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try applyRelaySchema(db);
    var sc = core.clock.SimClock.init(1);

    const a = try subscribe(db, sc.clock(), .atproto_firehose, "wss://a");
    try setState(db, a, .failed);
    const b = try subscribe(db, sc.clock(), .atproto_firehose, "wss://a");
    try testing.expectEqual(a, b);

    var rows: [4]Subscription = undefined;
    const n = try listSubscriptions(db, 0, &rows);
    try testing.expectEqual(@as(u32, 1), n);
    try testing.expectEqual(State.active, rows[0].state);
}

test "setState on missing subscription returns SubscriptionNotFound" {
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try applyRelaySchema(db);
    try testing.expectError(error.SubscriptionNotFound, setState(db, 9999, .paused));
}

test "translation log append + paginate (newest first)" {
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try applyRelaySchema(db);
    var sc = core.clock.SimClock.init(1_700_000_000);

    // Append 5 entries.
    var ids: [5]i64 = undefined;
    var i: u8 = 0;
    while (i < 5) : (i += 1) {
        sc.advance(1 * std.time.ns_per_s);
        var src_buf: [32]u8 = undefined;
        const src = try std.fmt.bufPrint(&src_buf, "at://x/coll/{d}", .{i});
        var tr_buf: [32]u8 = undefined;
        const tr = try std.fmt.bufPrint(&tr_buf, "https://h/o/{d}", .{i});
        ids[i] = try appendLog(db, sc.clock(), .at_to_ap, src, tr, true, "");
    }
    try testing.expect(ids[4] > ids[0]);

    // Page 1: 2 newest.
    var rows: [2]LogEntry = undefined;
    var n = try listLog(db, 0, &rows);
    try testing.expectEqual(@as(u32, 2), n);
    try testing.expectEqual(ids[4], rows[0].id);
    try testing.expectEqual(ids[3], rows[1].id);

    // Page 2.
    n = try listLog(db, 2, &rows);
    try testing.expectEqual(@as(u32, 2), n);
    try testing.expectEqual(ids[2], rows[0].id);
    try testing.expectEqual(ids[1], rows[1].id);
}

test "translation log records errors with error_msg" {
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try applyRelaySchema(db);
    var sc = core.clock.SimClock.init(1);

    _ = try appendLog(db, sc.clock(), .ap_to_at, "https://m/act/1", "at://x/y/z", false, "bad cbor");

    var rows: [1]LogEntry = undefined;
    const n = try listLog(db, 0, &rows);
    try testing.expectEqual(@as(u32, 1), n);
    try testing.expect(!rows[0].success);
    try testing.expectEqualStrings("bad cbor", rows[0].errorMsg());
    try testing.expectEqual(Direction.ap_to_at, rows[0].direction);
}
