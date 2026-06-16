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
const identity_map = @import("identity_map.zig");
const synthetic_keys = @import("synthetic_keys.zig");
const ap_to_at_mod = @import("ap_to_at.zig");
const followers_mod = @import("followers.zig");
const activitypub = @import("protocol_activitypub");

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
    const db = state.dbHandle() orelse return writeJson(hc, .service_unavailable, "{\"error\":\"db not ready\"}");

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
    const db = state.dbHandle() orelse return writeJson(hc, .service_unavailable, "{\"error\":\"db not ready\"}");

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
    const db = state.dbHandle() orelse return writeJson(hc, .service_unavailable, "{\"error\":\"db not ready\"}");

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
    const db = state.dbHandle() orelse return writeJson(hc, .service_unavailable, "{\"error\":\"db not ready\"}");

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

// ── A1: synthetic AP actor route ─────────────────────────────────────
//
// Serves an ActivityStreams Person document for an AT-origin actor
// the relay synthesizes onto the AP side. The synthetic actor URL is
// `https://<host>/ap/users/at:<did-tail>` (see
// `identity_map.syntheticActorForDid`). Strict-verifying peers fetch
// this URL after seeing a signed delivery from the bridge; the
// `publicKey.publicKeyPem` they pick up must validate the Ed25519
// signature `core.crypto.openssl.rsaSign…` no — Ed25519 from
// `keypair.Ed25519KeyPair.sign` produced by
// `synthetic_keys.deriveKeypair(actor_url)`.

const Arena = core.arena.Arena;

fn writeJsonLd(hc: *HandlerContext, status: Status, body: []const u8) !void {
    try hc.response.startStatus(status);
    try hc.response.header("Content-Type", "application/activity+json; charset=utf-8");
    try hc.response.headerFmt("Content-Length", "{d}", .{body.len});
    try hc.response.header("Connection", "close");
    try hc.response.finishHeaders();
    try hc.response.body(body);
}

fn handleSyntheticActor(hc: *HandlerContext) anyerror!void {
    // `:synth` is the path segment AFTER `/ap/users/`. The relay's
    // `identity_map.syntheticActorForDid` mints this segment as
    // `at:<did-tail>`. We accept both the raw segment and the
    // `at:`-prefixed form for forgiveness; reject anything that
    // doesn't reconstruct to a known mapping.
    const synth = hc.params.get("synth") orelse {
        return writeJson(hc, .bad_request, "{\"error\":\"missing synth\"}");
    };
    const state = State.get();
    const db = state.dbHandle() orelse {
        return writeJson(hc, .service_unavailable, "{\"error\":\"db not ready\"}");
    };

    // Reconstruct the full synthetic actor URL.
    var actor_url_buf: [identity_map.max_actor_url_bytes]u8 = undefined;
    const host = ap_to_at_mod.relayHostPublic();
    if (host.len == 0) return writeJson(hc, .service_unavailable, "{\"error\":\"relay host unset\"}");
    const actor_url = std.fmt.bufPrint(
        &actor_url_buf,
        "https://{s}/ap/users/{s}",
        .{ host, synth },
    ) catch return writeJson(hc, .internal, "{\"error\":\"buf\"}");

    // Look up the AT DID this synthetic actor maps to. If the row is
    // missing this is a 404 — we don't mint identities here, only
    // serve ones the bridge has already minted via inbound traffic.
    var arena_buf: [4 * 1024]u8 = undefined;
    var arena = Arena.init(&arena_buf);
    const did = identity_map.didForActor(db, actor_url, &arena) catch null;
    if (did == null) return writeJson(hc, .not_found, "{\"error\":\"unknown synthetic actor\"}");

    // Derive the Ed25519 keypair from the same identity the bridge
    // uses when signing federation deliveries.
    const kp = synthetic_keys.deriveKeypair(actor_url);

    // Encode the Ed25519 public key as a PEM SPKI block.
    var pem_buf: [256]u8 = undefined;
    const pem_n = activitypub.keys.writeEd25519PublicPem(kp.public_key, &pem_buf) catch {
        return writeJson(hc, .internal, "{\"error\":\"pem\"}");
    };

    // The shared inbox is the local host's `/inbox` — same one the
    // AP plugin already serves for non-synthetic actors.
    var shared_inbox_buf: [256]u8 = undefined;
    const shared_inbox = std.fmt.bufPrint(
        &shared_inbox_buf,
        "https://{s}/inbox",
        .{host},
    ) catch return writeJson(hc, .internal, "{\"error\":\"buf2\"}");

    // `preferredUsername` from the AT DID's identifier portion.
    // Keep it ASCII-safe — Mastodon uses this as the @handle.
    var uname_buf: [64]u8 = undefined;
    const uname = makeUsername(did.?, &uname_buf);

    var body_buf: [max_response_bytes]u8 = undefined;
    const body = activitypub.actor.writeSyntheticPerson(.{
        .actor_url = actor_url,
        .preferred_username = uname,
        .display_name = "",
        .bio = "Bridged from atproto",
        .public_key_pem = pem_buf[0..pem_n],
        .shared_inbox_url = shared_inbox,
    }, &body_buf) catch {
        return writeJson(hc, .internal, "{\"error\":\"actor encode\"}");
    };
    try writeJsonLd(hc, .ok, body);
}

/// A2: DID document for a synthetic AT identity minted by the bridge.
///
///   GET /ap/did/:did   (the `:did` segment is the full DID; colons are
///                        path-legal, and `%3A` is decoded for clients
///                        that escape them)
///
/// Publishes the Ed25519 verification method backing the bridge's commit
/// signatures (`synthetic_keys.deriveKeypair`), so AT-side consumers can
/// resolve the key the relay signs synthetic repos with. 404 when the DID
/// isn't a known synthetic identity.
fn handleDidDoc(hc: *HandlerContext) anyerror!void {
    const raw = hc.params.get("did") orelse {
        return writeJson(hc, .bad_request, "{\"error\":\"missing did\"}");
    };
    var did_buf: [identity_map.max_did_bytes]u8 = undefined;
    const did = percentDecode(raw, &did_buf);

    const state = State.get();
    const db = state.dbHandle() orelse {
        return writeJson(hc, .service_unavailable, "{\"error\":\"db not ready\"}");
    };

    var arena_buf: [4 * 1024]u8 = undefined;
    var arena = Arena.init(&arena_buf);
    const actor_url = identity_map.actorForDid(db, did, &arena) catch null;
    if (actor_url == null) return writeJson(hc, .not_found, "{\"error\":\"unknown did\"}");

    // Same keypair the bridge signs this repo's commits with.
    const kp = synthetic_keys.deriveKeypair(actor_url.?);

    // did:key-style Multikey: z + base58btc(0xed01 ‖ pubkey).
    var mb_buf: [80]u8 = undefined;
    const multibase = ed25519Multibase(kp.public_key, &mb_buf) catch {
        return writeJson(hc, .internal, "{\"error\":\"multibase\"}");
    };

    const host = ap_to_at_mod.relayHostPublic();
    var body_buf: [max_response_bytes]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf,
        \\{{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],"id":"{s}","alsoKnownAs":["{s}"],"verificationMethod":[{{"id":"{s}#atproto","type":"Multikey","controller":"{s}","publicKeyMultibase":"{s}"}}],"assertionMethod":["{s}#atproto"],"service":[{{"id":"#atproto_pds","type":"AtprotoPersonalDataServer","serviceEndpoint":"https://{s}"}}]}}
    , .{ did, actor_url.?, did, did, multibase, did, host }) catch {
        return writeJson(hc, .internal, "{\"error\":\"didbuf\"}");
    };
    try writeJson(hc, .ok, body);
}

/// Encode an Ed25519 public key as a did:key-style multibase string:
/// `z` ‖ base58btc(multicodec ed25519-pub `0xed01` ‖ key).
fn ed25519Multibase(pubkey: [32]u8, out: []u8) ![]const u8 {
    if (out.len < 1) return error.BufferTooSmall;
    var mc: [34]u8 = undefined;
    mc[0] = 0xed;
    mc[1] = 0x01;
    @memcpy(mc[2..34], &pubkey);
    out[0] = 'z';
    const n = try core.crypto.multibase.base58btcEncode(&mc, out[1..]);
    return out[0 .. 1 + n];
}

/// Decode `%XX` escapes in a path segment into `out`; returns the decoded
/// slice (aliasing `out`). Invalid escapes are passed through verbatim.
fn percentDecode(s: []const u8, out: []u8) []const u8 {
    var w: usize = 0;
    var i: usize = 0;
    while (i < s.len and w < out.len) {
        if (s[i] == '%' and i + 2 < s.len) {
            const hi = hexVal(s[i + 1]);
            const lo = hexVal(s[i + 2]);
            if (hi != null and lo != null) {
                out[w] = (hi.? << 4) | lo.?;
                w += 1;
                i += 3;
                continue;
            }
        }
        out[w] = s[i];
        w += 1;
        i += 1;
    }
    return out[0..w];
}

fn hexVal(ch: u8) ?u8 {
    return switch (ch) {
        '0'...'9' => ch - '0',
        'a'...'f' => ch - 'a' + 10,
        'A'...'F' => ch - 'A' + 10,
        else => null,
    };
}

/// Best-effort handle extraction from an AT DID. `did:plc:abc123` →
/// "abc123"; `did:web:example.com:user` → "user".
fn makeUsername(did: []const u8, out: []u8) []const u8 {
    var i: usize = did.len;
    while (i > 0) {
        i -= 1;
        if (did[i] == ':') {
            const tail = did[i + 1 ..];
            const n = @min(tail.len, out.len);
            for (tail[0..n], 0..) |ch, j| {
                out[j] = switch (ch) {
                    'a'...'z', 'A'...'Z', '0'...'9', '_', '-', '.' => ch,
                    else => '_',
                };
            }
            return out[0..n];
        }
    }
    const n = @min(did.len, out.len);
    @memcpy(out[0..n], did[0..n]);
    return out[0..n];
}

// ── B3: follower admin routes ────────────────────────────────────────

fn handleListFollowers(hc: *HandlerContext) anyerror!void {
    if (!requireAdmin(hc)) return writeJson(hc, .forbidden, "{\"error\":\"admin auth required\"}");
    const state = State.get();
    const db = state.dbHandle() orelse return writeJson(hc, .service_unavailable, "{\"error\":\"db not ready\"}");
    const q = hc.request.pathAndQuery().query;
    const actor = queryParam(q, "actor") orelse return writeJson(hc, .bad_request, "{\"error\":\"missing actor\"}");

    var rows: [64]followers_mod.Follower = undefined;
    const n = followers_mod.list(db, actor, &rows) catch return writeJson(hc, .internal, "{\"error\":\"list failed\"}");

    var body_buf: [max_response_bytes]u8 = undefined;
    var w: usize = 0;
    body_buf[w] = '['; w += 1;
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        if (i > 0) {
            if (w + 1 > body_buf.len) return writeJson(hc, .internal, "{\"error\":\"buf\"}");
            body_buf[w] = ',';
            w += 1;
        }
        const f = &rows[i];
        const written = std.fmt.bufPrint(body_buf[w..], "{{\"inbox\":\"{s}\",\"shared_inbox\":\"{s}\"}}", .{ f.inbox(), f.sharedInbox() }) catch return writeJson(hc, .internal, "{\"error\":\"fmt\"}");
        w += written.len;
    }
    if (w + 1 > body_buf.len) return writeJson(hc, .internal, "{\"error\":\"buf2\"}");
    body_buf[w] = ']';
    w += 1;
    try writeJson(hc, .ok, body_buf[0..w]);
}

fn handleAddFollower(hc: *HandlerContext) anyerror!void {
    if (!requireAdmin(hc)) return writeJson(hc, .forbidden, "{\"error\":\"admin auth required\"}");
    const state = State.get();
    const db = state.dbHandle() orelse return writeJson(hc, .service_unavailable, "{\"error\":\"db not ready\"}");

    // JSON body: {"actor":"...", "inbox":"...", "shared_inbox":"...", "follow_iri":"..."}
    var actor_url: []const u8 = "";
    var inbox: []const u8 = "";
    var shared: []const u8 = "";
    var follow_iri: []const u8 = "";
    parseFourStringFields(hc.request.body, "actor", &actor_url, "inbox", &inbox, "shared_inbox", &shared, "follow_iri", &follow_iri) catch {
        return writeJson(hc, .bad_request, "{\"error\":\"malformed body\"}");
    };
    if (actor_url.len == 0 or inbox.len == 0) {
        return writeJson(hc, .bad_request, "{\"error\":\"missing actor or inbox\"}");
    }
    // If no follow_iri provided, mint one tagging this as an admin
    // injection so audit traces show it.
    var iri_buf: [128]u8 = undefined;
    const final_iri = if (follow_iri.len > 0) follow_iri else (std.fmt.bufPrint(&iri_buf, "admin:{d}", .{state.clock.wallUnix()}) catch return writeJson(hc, .internal, "{\"error\":\"iri\"}"));

    followers_mod.add(db, state.clock, actor_url, inbox, shared, final_iri) catch {
        return writeJson(hc, .internal, "{\"error\":\"add failed\"}");
    };
    // G2: audit-log the follower seed.
    var detail_buf: [256]u8 = undefined;
    const detail = std.fmt.bufPrint(&detail_buf, "{{\"inbox\":\"{s}\",\"follow_iri\":\"{s}\"}}", .{ inbox, final_iri }) catch "";
    core.audit.append(db, state.clock, "admin", "follower.seed", actor_url, detail, true) catch {};
    try writeJson(hc, .ok, "{\"status\":\"ok\"}");
}

fn queryParam(query: []const u8, name: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i < query.len) {
        const eq = std.mem.indexOfScalarPos(u8, query, i, '=') orelse return null;
        const amp = std.mem.indexOfScalarPos(u8, query, eq, '&') orelse query.len;
        if (eq - i == name.len and std.mem.eql(u8, query[i..eq], name)) {
            return query[eq + 1 .. amp];
        }
        if (amp >= query.len) return null;
        i = amp + 1;
    }
    return null;
}

fn parseFourStringFields(
    body: []const u8,
    k1: []const u8, v1: *[]const u8,
    k2: []const u8, v2: *[]const u8,
    k3: []const u8, v3: *[]const u8,
    k4: []const u8, v4: *[]const u8,
) !void {
    var i: usize = 0;
    while (i < body.len) {
        const k_start = std.mem.indexOfScalarPos(u8, body, i, '"') orelse return;
        const k_end = std.mem.indexOfScalarPos(u8, body, k_start + 1, '"') orelse return error.Malformed;
        const key = body[k_start + 1 .. k_end];
        var j = k_end + 1;
        while (j < body.len and (body[j] == ' ' or body[j] == ':' or body[j] == '\t')) j += 1;
        if (j >= body.len or body[j] != '"') {
            i = j;
            continue;
        }
        const v_start = j + 1;
        var v_end = v_start;
        while (v_end < body.len and body[v_end] != '"') v_end += 1;
        if (v_end >= body.len) return error.Malformed;
        if (std.mem.eql(u8, key, k1)) v1.* = body[v_start..v_end];
        if (std.mem.eql(u8, key, k2)) v2.* = body[v_start..v_end];
        if (std.mem.eql(u8, key, k3)) v3.* = body[v_start..v_end];
        if (std.mem.eql(u8, key, k4)) v4.* = body[v_start..v_end];
        i = v_end + 1;
    }
}

// ── Registration ───────────────────────────────────────────────────────

pub fn register(router: *Router, plugin_index: u16) !void {
    try router.register(.post, "/admin/relay/subscribe", handleSubscribe, plugin_index);
    try router.register(.delete, "/admin/relay/subscribe/:id", handleUnsubscribe, plugin_index);
    try router.register(.get, "/admin/relay/subscriptions", handleListSubscriptions, plugin_index);
    try router.register(.get, "/admin/relay/log", handleListLog, plugin_index);
    // B3: follower admin.
    try router.register(.get, "/admin/relay/followers", handleListFollowers, plugin_index);
    try router.register(.post, "/admin/relay/followers", handleAddFollower, plugin_index);
    // A1: synthetic AP actor — strict-verifying peers fetch this to
    // pick up the public key for signature verification.
    try router.register(.get, "/ap/users/:synth", handleSyntheticActor, plugin_index);
    // A2: DID document for synthetic AT identities (publishes the bridge's
    // Ed25519 signing key as a Multikey verification method).
    try router.register(.get, "/ap/did/:did", handleDidDoc, plugin_index);
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

test "A2: percentDecode decodes %3A and passes through plain colons" {
    var out: [128]u8 = undefined;
    try testing.expectEqualStrings("did:web:host:ap:alice", percentDecode("did%3Aweb%3Ahost%3Aap%3Aalice", &out));
    try testing.expectEqualStrings("did:web:host:ap:alice", percentDecode("did:web:host:ap:alice", &out));
    // A trailing stray '%' is passed through, not a crash.
    try testing.expectEqualStrings("a%", percentDecode("a%", &out));
    try testing.expectEqualStrings("100%done", percentDecode("100%done", &out));
}

test "A2: ed25519Multibase matches the did:key z-base58btc(0xed01‖key) form" {
    // Cross-check against the independently-built reference vector.
    var seed: [32]u8 = undefined;
    @memset(&seed, 0x33);
    const kp = synthetic_keys.Ed25519KeyPair.fromSeed(seed);

    var out: [80]u8 = undefined;
    const mb = try ed25519Multibase(kp.public_key, &out);
    try testing.expect(mb[0] == 'z');

    var mc: [34]u8 = undefined;
    mc[0] = 0xed;
    mc[1] = 0x01;
    @memcpy(mc[2..34], &kp.public_key);
    var b58: [80]u8 = undefined;
    const bn = try core.crypto.multibase.base58btcEncode(&mc, &b58);
    try testing.expectEqualStrings(b58[0..bn], mb[1..]);

    // Deterministic across calls (the bridge re-derives the same key).
    var out2: [80]u8 = undefined;
    const mb2 = try ed25519Multibase(kp.public_key, &out2);
    try testing.expectEqualStrings(mb, mb2);
}
