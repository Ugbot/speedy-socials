//! Admin routes for the relay plugin.
//!
//! Auth is stubbed: every request must include `X-Relay-Admin: 1`. A
//! later phase wires real auth via the auth plugin (TBD).
//!
//! Routes:
//!
//!   POST   /admin/relay/subscribe          → create / re-activate a subscription
//!   DELETE /admin/relay/subscribe/:id      → pause a subscription
//!   GET    /admin/relay/subscriptions      → list (JSON)
//!   GET    /admin/relay/log                → translation log (JSON, paginated)
//!
//! All bodies are JSON. Responses use the fixed-length `response.Builder`
//! (Tiger Style: known Content-Length, single shot). For "log" we cap
//! at `subscription.max_list_rows` entries per call so the response fits
//! in the connection's write buffer.

const std = @import("std");
const core = @import("core");

const HandlerContext = core.http.router.HandlerContext;
const Status = core.http.response.Status;
const Router = core.http.router.Router;
const Method = core.http.request.Method;

const sub = @import("subscription.zig");
const State = @import("state.zig");

const max_response_bytes: usize = 8 * 1024;

fn requireAdmin(hc: *HandlerContext) bool {
    const v = hc.request.header("X-Relay-Admin") orelse return false;
    return std.mem.eql(u8, v, "1");
}

fn writeJson(hc: *HandlerContext, status: Status, body: []const u8) !void {
    try hc.response.startStatus(status);
    try hc.response.header("Content-Type", "application/json");
    try hc.response.headerFmt("Content-Length", "{d}", .{body.len});
    try hc.response.header("Connection", "close");
    try hc.response.finishHeaders();
    try hc.response.body(body);
}

// ── Route handlers ─────────────────────────────────────────────────────

fn handleSubscribe(hc: *HandlerContext) anyerror!void {
    if (!requireAdmin(hc)) return writeJson(hc, .forbidden, "{\"error\":\"admin auth required\"}");
    const state = State.get();
    const db = state.reader_db orelse return writeJson(hc, .service_unavailable, "{\"error\":\"db not ready\"}");

    // Tiny body parser: `{ "kind": "...", "source": "..." }`. We only
    // pull two string fields, no allocator.
    const body = hc.request.body;
    var kind_slice: []const u8 = "";
    var source_slice: []const u8 = "";
    parseTwoStringFields(body, "kind", "source", &kind_slice, &source_slice) catch {
        return writeJson(hc, .bad_request, "{\"error\":\"malformed body\"}");
    };
    const kind = sub.Kind.parse(kind_slice) orelse {
        return writeJson(hc, .bad_request, "{\"error\":\"unknown kind\"}");
    };
    if (source_slice.len == 0) {
        return writeJson(hc, .bad_request, "{\"error\":\"missing source\"}");
    }

    const id = sub.subscribe(db, state.clock, kind, source_slice) catch {
        return writeJson(hc, .internal, "{\"error\":\"subscribe failed\"}");
    };

    var buf: [256]u8 = undefined;
    const out = try std.fmt.bufPrint(&buf, "{{\"id\":{d},\"state\":\"active\"}}", .{id});
    try writeJson(hc, .created, out);
}

fn handleUnsubscribe(hc: *HandlerContext) anyerror!void {
    if (!requireAdmin(hc)) return writeJson(hc, .forbidden, "{\"error\":\"admin auth required\"}");
    const state = State.get();
    const db = state.reader_db orelse return writeJson(hc, .service_unavailable, "{\"error\":\"db not ready\"}");

    const id_text = hc.params.get("id") orelse {
        return writeJson(hc, .bad_request, "{\"error\":\"missing id\"}");
    };
    const id = std.fmt.parseInt(i64, id_text, 10) catch {
        return writeJson(hc, .bad_request, "{\"error\":\"bad id\"}");
    };
    sub.setState(db, id, .paused) catch |err| switch (err) {
        error.SubscriptionNotFound => return writeJson(hc, .not_found, "{\"error\":\"not found\"}"),
        else => return writeJson(hc, .internal, "{\"error\":\"pause failed\"}"),
    };
    try writeJson(hc, .ok, "{\"state\":\"paused\"}");
}

fn handleListSubscriptions(hc: *HandlerContext) anyerror!void {
    if (!requireAdmin(hc)) return writeJson(hc, .forbidden, "{\"error\":\"admin auth required\"}");
    const state = State.get();
    const db = state.reader_db orelse return writeJson(hc, .service_unavailable, "{\"error\":\"db not ready\"}");

    var rows: [sub.max_list_rows]sub.Subscription = undefined;
    const n = sub.listSubscriptions(db, 0, &rows) catch {
        return writeJson(hc, .internal, "{\"error\":\"list failed\"}");
    };

    var buf: [max_response_bytes]u8 = undefined;
    var w: usize = 0;
    w += try copySliceInto(buf[w..], "[");
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        if (i > 0) w += try copySliceInto(buf[w..], ",");
        const r = rows[i];
        const written = try std.fmt.bufPrint(
            buf[w..],
            "{{\"id\":{d},\"kind\":\"{s}\",\"source\":\"{s}\",\"state\":\"{s}\",\"created_at\":{d}}}",
            .{ r.id, r.kind.label(), r.source(), r.state.label(), r.created_at },
        );
        w += written.len;
    }
    w += try copySliceInto(buf[w..], "]");
    try writeJson(hc, .ok, buf[0..w]);
}

fn handleListLog(hc: *HandlerContext) anyerror!void {
    if (!requireAdmin(hc)) return writeJson(hc, .forbidden, "{\"error\":\"admin auth required\"}");
    const state = State.get();
    const db = state.reader_db orelse return writeJson(hc, .service_unavailable, "{\"error\":\"db not ready\"}");

    // Cursor: query string `?offset=N`. Defaults to 0.
    var offset: u32 = 0;
    const pq = hc.request.pathAndQuery();
    if (pq.query.len > 0) {
        if (std.mem.indexOf(u8, pq.query, "offset=")) |k| {
            const v_start = k + "offset=".len;
            var v_end = v_start;
            while (v_end < pq.query.len and pq.query[v_end] != '&') v_end += 1;
            offset = std.fmt.parseInt(u32, pq.query[v_start..v_end], 10) catch 0;
        }
    }

    var rows: [16]sub.LogEntry = undefined;
    const n = sub.listLog(db, offset, &rows) catch {
        return writeJson(hc, .internal, "{\"error\":\"log read failed\"}");
    };

    var buf: [max_response_bytes]u8 = undefined;
    var w: usize = 0;
    w += try copySliceInto(buf[w..], "[");
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        if (i > 0) w += try copySliceInto(buf[w..], ",");
        const e = rows[i];
        // Note: in production we'd JSON-escape error_msg; here it's a
        // stub field with admin-supplied data.
        const written = try std.fmt.bufPrint(
            buf[w..],
            "{{\"id\":{d},\"direction\":\"{s}\",\"source_id\":\"{s}\",\"translated_id\":\"{s}\",\"success\":{s},\"ts\":{d}}}",
            .{ e.id, e.direction.label(), e.sourceId(), e.translatedId(), if (e.success) "true" else "false", e.ts },
        );
        w += written.len;
    }
    w += try copySliceInto(buf[w..], "]");
    try writeJson(hc, .ok, buf[0..w]);
}

fn copySliceInto(dest: []u8, src: []const u8) !usize {
    if (src.len > dest.len) return error.ResponseBufferFull;
    @memcpy(dest[0..src.len], src);
    return src.len;
}

/// Single-pass JSON parser that pulls the string values of two named
/// top-level keys. Iterative, bounded. The fields' slices are views
/// into `body` and remain valid for the request lifetime.
fn parseTwoStringFields(
    body: []const u8,
    key_a: []const u8,
    key_b: []const u8,
    out_a: *[]const u8,
    out_b: *[]const u8,
) !void {
    var i: usize = 0;
    var guard: u32 = 0;
    while (i < body.len) {
        guard += 1;
        if (guard > 4096) return error.Malformed;
        if (body[i] != '"') {
            i += 1;
            continue;
        }
        const k_start = i + 1;
        var k_end = k_start;
        while (k_end < body.len and body[k_end] != '"') k_end += 1;
        if (k_end >= body.len) return error.Malformed;
        const key = body[k_start..k_end];
        i = k_end + 1;
        // skip ws + ':'
        while (i < body.len and (body[i] == ' ' or body[i] == '\t' or body[i] == ':')) i += 1;
        if (i >= body.len or body[i] != '"') continue;
        const v_start = i + 1;
        var v_end = v_start;
        while (v_end < body.len and body[v_end] != '"') v_end += 1;
        if (v_end >= body.len) return error.Malformed;
        if (std.mem.eql(u8, key, key_a)) out_a.* = body[v_start..v_end];
        if (std.mem.eql(u8, key, key_b)) out_b.* = body[v_start..v_end];
        i = v_end + 1;
    }
}

// ── Registration ───────────────────────────────────────────────────────

pub fn register(router: *Router, plugin_index: u16) !void {
    try router.register(.post, "/admin/relay/subscribe", handleSubscribe, plugin_index);
    try router.register(.delete, "/admin/relay/subscribe/:id", handleUnsubscribe, plugin_index);
    try router.register(.get, "/admin/relay/subscriptions", handleListSubscriptions, plugin_index);
    try router.register(.get, "/admin/relay/log", handleListLog, plugin_index);
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "parseTwoStringFields finds both fields in any order" {
    var a: []const u8 = "";
    var b: []const u8 = "";
    try parseTwoStringFields(
        "{\"kind\":\"atproto_firehose\",\"source\":\"wss://x\"}",
        "kind",
        "source",
        &a,
        &b,
    );
    try testing.expectEqualStrings("atproto_firehose", a);
    try testing.expectEqualStrings("wss://x", b);

    a = "";
    b = "";
    try parseTwoStringFields(
        "{\"source\":\"wss://y\",\"kind\":\"activitypub_inbox\"}",
        "kind",
        "source",
        &a,
        &b,
    );
    try testing.expectEqualStrings("activitypub_inbox", a);
    try testing.expectEqualStrings("wss://y", b);
}
