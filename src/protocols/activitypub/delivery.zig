//! Federation delivery enqueue helper.
//!
//! Computes a deduplicated set of recipient inboxes, strips `bto`/`bcc`
//! (and `bto`/`bcc` aliases) from the activity payload, and inserts a
//! row per recipient into `ap_federation_outbox`.
//!
//! Tiger Style:
//!   * Bounded recipient set (`max_recipients_per_activity`).
//!   * Backpressure surface: `OutboxFull` when the table is at capacity.
//!   * No allocator on the hot path — every buffer is caller-owned.
//!
//! `bto`/`bcc` stripping (AP §6.2): the strip is implemented with a
//! single-pass scanner that copies the JSON minus any `"bto"` or `"bcc"`
//! field (string or array value). It is *not* a full JSON parser, but
//! is robust against the shapes Mastodon, Pleroma, Misskey produce.

const std = @import("std");
const c = @import("sqlite").c;
const core = @import("core");

const FedError = core.errors.FedError;
const StorageError = core.errors.StorageError;
const limits = core.limits;
const assertLe = core.assert.assertLe;
const Clock = core.clock.Clock;

pub const max_recipients_per_activity: u32 = 64;
pub const max_inbox_url_bytes: usize = 512;

pub const Recipient = struct {
    inbox: []const u8,
    shared_inbox: []const u8 = "",
};

/// Build a deduplicated recipient set from a flat input list. If a
/// recipient has a `shared_inbox`, that wins (and dedups across multiple
/// recipients on the same instance). Bounded by
/// `max_recipients_per_activity`.
///
/// Output slot identity: each element of `out` is the chosen delivery
/// URL — shared inbox if available, else per-actor inbox.
pub fn dedupRecipients(
    inputs: []const Recipient,
    sender_actor: []const u8,
    out: []Recipient,
) FedError!u32 {
    if (out.len < inputs.len) return error.OutboxFull;
    var n: u32 = 0;
    var i: usize = 0;
    while (i < inputs.len) : (i += 1) {
        const r = inputs[i];
        // Choose target: prefer shared_inbox.
        const chosen = if (r.shared_inbox.len > 0) r.shared_inbox else r.inbox;
        if (chosen.len == 0 or chosen.len > max_inbox_url_bytes) continue;
        // Skip the sender's own inbox (AP §6.10).
        if (std.mem.eql(u8, chosen, sender_actor)) continue;
        // Dedup linear scan — bounded by `n`, capped by
        // max_recipients_per_activity.
        var dup = false;
        var j: u32 = 0;
        while (j < n) : (j += 1) {
            if (std.mem.eql(u8, out[j].inbox, chosen)) {
                dup = true;
                break;
            }
        }
        if (dup) continue;
        if (n >= max_recipients_per_activity) break;
        out[n] = .{ .inbox = chosen, .shared_inbox = r.shared_inbox };
        n += 1;
    }
    assertLe(n, max_recipients_per_activity);
    return n;
}

/// Strip `bto` and `bcc` keys (and their values) from a JSON activity.
/// Returns the new length written into `out`. Returns `BadObject` on
/// malformed JSON. `out` must be at least `input.len` bytes.
pub fn stripBcc(input: []const u8, out: []u8) FedError!usize {
    if (out.len < input.len) return error.SignatureMalformed;
    var w: usize = 0;
    var i: usize = 0;
    var guard: u32 = 0;
    while (i < input.len) {
        guard += 1;
        if (guard > 64 * 1024) return error.SignatureMalformed;

        // Look for a `"bto"` or `"bcc"` key at the current scan
        // position. We treat both `"bto"` (3 chars + quote) and
        // `"bcc"` identically. Match against the literal — false
        // positives (a string value containing "bto") are avoided by
        // requiring the colon ahead.
        if (input[i] == '"' and i + 5 <= input.len) {
            const tag = input[i + 1 .. i + 4];
            if ((std.mem.eql(u8, tag, "bto") or std.mem.eql(u8, tag, "bcc")) and input[i + 4] == '"') {
                // Scan ahead for ':'.
                var k: usize = i + 5;
                while (k < input.len and (input[k] == ' ' or input[k] == '\t' or input[k] == ':')) : (k += 1) {}
                // Confirm we actually saw the colon (else it's
                // something like `"bto": ...` inside a sibling value
                // — treat conservatively and skip the field).
                if (std.mem.indexOfScalarPos(u8, input, i + 5, ':') != null) {
                    // Skip value (string, array, or null/object).
                    const end = try skipJsonValueAt(input, k);
                    // Also skip trailing comma if present.
                    var skip_end = end;
                    while (skip_end < input.len and (input[skip_end] == ' ' or input[skip_end] == '\t' or input[skip_end] == '\n')) {
                        skip_end += 1;
                    }
                    if (skip_end < input.len and input[skip_end] == ',') skip_end += 1;
                    // If the previous emitted char in `out` was `,`,
                    // and the next non-ws char in input is `}` or `]`,
                    // we should remove the trailing comma we wrote.
                    if (w > 0 and out[w - 1] == ',') {
                        var t: usize = skip_end;
                        while (t < input.len and (input[t] == ' ' or input[t] == '\t' or input[t] == '\n')) t += 1;
                        if (t < input.len and (input[t] == '}' or input[t] == ']')) {
                            w -= 1;
                        }
                    }
                    i = skip_end;
                    continue;
                }
            }
        }
        out[w] = input[i];
        w += 1;
        i += 1;
    }
    return w;
}

/// Iterative JSON-value skipper. Returns the offset *after* the value
/// that begins at `start` (start must point at the first byte of the
/// value, after any whitespace).
fn skipJsonValueAt(buf: []const u8, start: usize) FedError!usize {
    var i: usize = start;
    // Skip leading whitespace.
    while (i < buf.len and (buf[i] == ' ' or buf[i] == '\t' or buf[i] == '\n')) i += 1;
    if (i >= buf.len) return error.SignatureMalformed;
    switch (buf[i]) {
        '"' => {
            i += 1;
            var guard: u32 = 0;
            while (i < buf.len) : (i += 1) {
                guard += 1;
                if (guard > 1024 * 1024) return error.SignatureMalformed;
                if (buf[i] == '\\') {
                    i += 1;
                    continue;
                }
                if (buf[i] == '"') return i + 1;
            }
            return error.SignatureMalformed;
        },
        '[' => {
            var depth: u32 = 1;
            i += 1;
            var guard: u32 = 0;
            while (i < buf.len and depth > 0) : (i += 1) {
                guard += 1;
                if (guard > 1024 * 1024) return error.SignatureMalformed;
                if (buf[i] == '"') {
                    // skip string
                    i += 1;
                    while (i < buf.len and buf[i] != '"') : (i += 1) {
                        if (buf[i] == '\\' and i + 1 < buf.len) i += 1;
                    }
                } else if (buf[i] == '[') {
                    depth += 1;
                } else if (buf[i] == ']') {
                    depth -= 1;
                }
            }
            return i;
        },
        '{' => {
            var depth: u32 = 1;
            i += 1;
            var guard: u32 = 0;
            while (i < buf.len and depth > 0) : (i += 1) {
                guard += 1;
                if (guard > 1024 * 1024) return error.SignatureMalformed;
                if (buf[i] == '"') {
                    i += 1;
                    while (i < buf.len and buf[i] != '"') : (i += 1) {
                        if (buf[i] == '\\' and i + 1 < buf.len) i += 1;
                    }
                } else if (buf[i] == '{') {
                    depth += 1;
                } else if (buf[i] == '}') {
                    depth -= 1;
                }
            }
            return i;
        },
        't', 'f', 'n', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-' => {
            while (i < buf.len) : (i += 1) {
                const ch = buf[i];
                if (ch == ',' or ch == '}' or ch == ']' or ch == ' ' or ch == '\n' or ch == '\t') {
                    return i;
                }
            }
            return i;
        },
        else => return error.SignatureMalformed,
    }
}

// ──────────────────────────────────────────────────────────────────────
// Outbox enqueue
// ──────────────────────────────────────────────────────────────────────

/// Insert one row per recipient into `ap_federation_outbox`. Payload
/// must already have had bto/bcc stripped. `key_id` identifies the
/// local actor's signing key. `now_ns` is wall-clock nanoseconds; the
/// next-attempt timestamp is set to *now* (eligible immediately).
pub fn enqueueDeliveries(
    db: *c.sqlite3,
    clock: Clock,
    recipients: []const Recipient,
    payload: []const u8,
    key_id: []const u8,
) FedError!u32 {
    if (recipients.len > max_recipients_per_activity) return error.OutboxFull;
    const now_s = clock.wallUnix();
    var stmt: ?*c.sqlite3_stmt = null;
    const sql =
        \\INSERT INTO ap_federation_outbox
        \\  (target_inbox, shared_inbox, payload, key_id, attempts, next_attempt_at, state, inserted_at)
        \\VALUES (?, ?, ?, ?, 0, ?, 'pending', ?)
    ;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return error.OutboxFull;
    }
    defer _ = c.sqlite3_finalize(stmt);
    var n: u32 = 0;
    for (recipients) |r| {
        _ = c.sqlite3_reset(stmt);
        _ = c.sqlite3_clear_bindings(stmt);
        if (c.sqlite3_bind_text(stmt, 1, r.inbox.ptr, @intCast(r.inbox.len), c.sqliteTransientAsDestructor()) != c.SQLITE_OK) {
            return error.OutboxFull;
        }
        if (r.shared_inbox.len > 0) {
            if (c.sqlite3_bind_text(stmt, 2, r.shared_inbox.ptr, @intCast(r.shared_inbox.len), c.sqliteTransientAsDestructor()) != c.SQLITE_OK) {
                return error.OutboxFull;
            }
        } else {
            _ = c.sqlite3_bind_null(stmt, 2);
        }
        if (c.sqlite3_bind_blob(stmt, 3, payload.ptr, @intCast(payload.len), c.sqliteTransientAsDestructor()) != c.SQLITE_OK) {
            return error.OutboxFull;
        }
        if (c.sqlite3_bind_text(stmt, 4, key_id.ptr, @intCast(key_id.len), c.sqliteTransientAsDestructor()) != c.SQLITE_OK) {
            return error.OutboxFull;
        }
        if (c.sqlite3_bind_int64(stmt, 5, now_s) != c.SQLITE_OK) return error.OutboxFull;
        if (c.sqlite3_bind_int64(stmt, 6, now_s) != c.SQLITE_OK) return error.OutboxFull;
        if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.OutboxFull;
        n += 1;
    }
    return n;
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;
const schema = @import("schema.zig");

test "dedupRecipients collapses shared_inbox duplicates" {
    const inputs = [_]Recipient{
        .{ .inbox = "https://a/u1/inbox", .shared_inbox = "https://a/inbox" },
        .{ .inbox = "https://a/u2/inbox", .shared_inbox = "https://a/inbox" },
        .{ .inbox = "https://b/u/inbox", .shared_inbox = "" },
    };
    var out: [16]Recipient = undefined;
    const n = try dedupRecipients(&inputs, "https://self/u", &out);
    try testing.expectEqual(@as(u32, 2), n);
    try testing.expectEqualStrings("https://a/inbox", out[0].inbox);
    try testing.expectEqualStrings("https://b/u/inbox", out[1].inbox);
}

test "dedupRecipients excludes the sender" {
    const inputs = [_]Recipient{
        .{ .inbox = "https://me/inbox", .shared_inbox = "" },
        .{ .inbox = "https://them/inbox", .shared_inbox = "" },
    };
    var out: [4]Recipient = undefined;
    const n = try dedupRecipients(&inputs, "https://me/inbox", &out);
    try testing.expectEqual(@as(u32, 1), n);
    try testing.expectEqualStrings("https://them/inbox", out[0].inbox);
}

test "stripBcc removes bto field from a small object" {
    const input = "{\"id\":\"x\",\"bto\":[\"https://w3.org/Public\"],\"actor\":\"a\"}";
    var out: [256]u8 = undefined;
    const n = try stripBcc(input, &out);
    const s = out[0..n];
    try testing.expect(std.mem.indexOf(u8, s, "bto") == null);
    try testing.expect(std.mem.indexOf(u8, s, "\"actor\":\"a\"") != null);
}

test "stripBcc removes bcc field with object value" {
    const input = "{\"a\":1,\"bcc\":\"https://x\",\"b\":2}";
    var out: [128]u8 = undefined;
    const n = try stripBcc(input, &out);
    const s = out[0..n];
    try testing.expect(std.mem.indexOf(u8, s, "bcc") == null);
    try testing.expect(std.mem.indexOf(u8, s, "\"a\":1") != null);
    try testing.expect(std.mem.indexOf(u8, s, "\"b\":2") != null);
}

test "stripBcc leaves bto-less activity intact" {
    const input = "{\"id\":\"x\",\"actor\":\"a\",\"to\":[\"https://w3.org/Public\"]}";
    var out: [256]u8 = undefined;
    const n = try stripBcc(input, &out);
    try testing.expectEqualStrings(input, out[0..n]);
}

test "enqueueDeliveries inserts one row per recipient" {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    try schema.applyAllForTests(db);

    var sc = core.clock.SimClock.init(1_700_000_000);
    const recipients = [_]Recipient{
        .{ .inbox = "https://a/inbox" },
        .{ .inbox = "https://b/inbox" },
    };
    const n = try enqueueDeliveries(db, sc.clock(), &recipients, "{\"id\":\"x\"}", "kid1");
    try testing.expectEqual(@as(u32, 2), n);

    var stmt: ?*c.sqlite3_stmt = null;
    _ = c.sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM ap_federation_outbox WHERE state='pending'", -1, &stmt, null);
    defer _ = c.sqlite3_finalize(stmt);
    try testing.expect(c.sqlite3_step(stmt) == c.SQLITE_ROW);
    try testing.expectEqual(@as(i64, 2), c.sqlite3_column_int64(stmt, 0));
}

test "stripBcc handles bto with no comma cleanup needed" {
    const input = "{\"bto\":[\"x\"],\"id\":\"y\"}";
    var out: [128]u8 = undefined;
    const n = try stripBcc(input, &out);
    try testing.expect(std.mem.indexOf(u8, out[0..n], "bto") == null);
    try testing.expect(std.mem.indexOf(u8, out[0..n], "\"id\":\"y\"") != null);
}

test "stripBcc handles trailing bcc requiring comma removal" {
    const input = "{\"id\":\"z\",\"bcc\":[\"x\"]}";
    var out: [128]u8 = undefined;
    const n = try stripBcc(input, &out);
    const s = out[0..n];
    try testing.expect(std.mem.indexOf(u8, s, "bcc") == null);
    // Trailing comma cleaned up.
    try testing.expect(std.mem.indexOf(u8, s, ",}") == null);
    try testing.expect(std.mem.endsWith(u8, s, "}"));
}
