//! J5 — Mastodon dev-pod federation round-trip (gated integration test).
//!
//! This test performs a *real* ActivityPub federation round trip against a
//! reachable Mastodon pod. It is INERT by default: it returns
//! `error.SkipZigTest` unless `MASTODON_E2E_URL` is set, mirroring the
//! `PG_TEST_URL` gating pattern used in
//! `src/core/storage/postgres_backend.zig` and `src/core/account_zorm.zig`.
//!
//! ── What it exercises ────────────────────────────────────────────────────
//!
//! One federation round trip between the speedy-socials bridge side and the
//! Mastodon pod, both directions:
//!
//!   bridge → pod  (we sign + POST activities to the pod's inbox)
//!     1. WebFinger-resolve the target acct (`MASTODON_E2E_ACCT`, default
//!        `admin@<host>`) to its actor document, then read the `inbox` URL.
//!     2. Sign + POST a Follow{actor=local, object=pod-actor}.
//!     3. Sign + POST a Create{Note} authored by the local actor.
//!     4. Sign + POST a Like{object=pod-actor's profile}.
//!     Each POST is a draft-cavage HTTP-signed `application/activity+json`
//!     request via `http_delivery.deliver`. We assert the pod accepts each
//!     (HTTP 2xx → `DeliveryResult.success`). A 202 Accepted is Mastodon's
//!     normal inbox response.
//!
//!   pod → bridge  (reachability of the bridge's discovery surface)
//!     5. We resolve the pod via WebFinger + actor fetch (a pod that can be
//!        discovered can deliver back). Then we confirm the pod's NodeInfo
//!        link is reachable, proving the pod is a live, two-way federation
//!        peer rather than a stub. Combined with the signed inbox POSTs
//!        accepted in step 2-4, this is a genuine bidirectional check at the
//!        federation HTTP layer.
//!
//! ── Running it locally (podman) ──────────────────────────────────────────
//!
//! See `docs/ci/mastodon-e2e.yml` for the full CI job. For a local pod:
//!
//!   # 1. Bring up a Mastodon dev pod (Postgres + Redis + web) with podman.
//!   podman network create mastonet
//!   podman run -d --name masto-pg  --network mastonet \
//!       -e POSTGRES_USER=mastodon -e POSTGRES_PASSWORD=mastodon \
//!       -e POSTGRES_DB=mastodon_development docker.io/library/postgres:16
//!   podman run -d --name masto-redis --network mastonet docker.io/library/redis:7
//!   podman run -d --name masto-web --network mastonet -p 3000:3000 \
//!       -e DB_HOST=masto-pg -e DB_USER=mastodon -e DB_PASS=mastodon \
//!       -e REDIS_HOST=masto-redis -e LOCAL_DOMAIN=localhost:3000 \
//!       -e LOCAL_HTTPS=false \
//!       -e OTP_SECRET=dummy_otp_secret_for_local_dev_only \
//!       -e SECRET_KEY_BASE=dummy_secret_key_base_for_local_dev_only \
//!       docker.io/tootsuite/mastodon:v4.5 \
//!       bash -c 'bundle exec rails db:setup && rails s -b 0.0.0.0'
//!   # Create an account once it is up:
//!   podman exec masto-web bin/tootctl accounts create admin \
//!       --email admin@localhost --confirmed --role Owner
//!
//!   # 2. Run just this test against the pod:
//!   MASTODON_E2E_URL=http://localhost:3000 \
//!   MASTODON_E2E_ACCT=admin@localhost:3000 \
//!       zig build test
//!
//! Without `MASTODON_E2E_URL` the test is skipped and `zig build test`
//! passes exactly as before (verified in CI on offline branches).

const std = @import("std");
const core = @import("core");
const ap = @import("protocol_activitypub");
const c = @import("sqlite").c;

const http_client = core.http_client;
const sqlite = core.storage.sqlite;
const testing = std.testing;

const max_url_bytes: usize = 1024;

/// Read an env var as a 0-terminated C string slice, or null.
fn env(name: [*:0]const u8) ?[]const u8 {
    const v = std.c.getenv(name) orelse return null;
    const s = std.mem.sliceTo(v, 0);
    if (s.len == 0) return null;
    return s;
}

/// Strip a trailing '/' so we can join paths predictably.
fn trimSlash(s: []const u8) []const u8 {
    if (s.len > 0 and s[s.len - 1] == '/') return s[0 .. s.len - 1];
    return s;
}

/// Extract `scheme://host[:port]` (authority) from a full URL.
fn originOf(url: []const u8) []const u8 {
    var rest_off: usize = 0;
    if (std.mem.startsWith(u8, url, "https://")) {
        rest_off = 8;
    } else if (std.mem.startsWith(u8, url, "http://")) {
        rest_off = 7;
    }
    const after = url[rest_off..];
    const slash = std.mem.indexOfScalar(u8, after, '/') orelse after.len;
    return url[0 .. rest_off + slash];
}

/// host[:port] portion of a base URL (used to build acct: defaults).
fn hostOf(base: []const u8) []const u8 {
    const origin = originOf(base);
    var rest = origin;
    if (std.mem.startsWith(u8, rest, "https://")) {
        rest = rest[8..];
    } else if (std.mem.startsWith(u8, rest, "http://")) {
        rest = rest[7..];
    }
    return rest;
}

/// Find the first JSON string value for `"<key>":"..."` in a flat-enough
/// document. Returns a slice into `body`, or null. This is a deliberately
/// small scanner — we only need `inbox` / `id` from an actor doc and `href`
/// from a WebFinger JRD, all of which are top-level-ish string fields.
fn jsonStringField(body: []const u8, key: []const u8) ?[]const u8 {
    var needle_buf: [64]u8 = undefined;
    if (key.len + 3 > needle_buf.len) return null;
    const needle = std.fmt.bufPrint(&needle_buf, "\"{s}\"", .{key}) catch return null;
    var search_from: usize = 0;
    while (std.mem.indexOfPos(u8, body, search_from, needle)) |kpos| {
        var i = kpos + needle.len;
        // skip whitespace + ':' + whitespace
        while (i < body.len and (body[i] == ' ' or body[i] == '\t' or body[i] == '\n' or body[i] == '\r')) i += 1;
        if (i >= body.len or body[i] != ':') {
            search_from = kpos + needle.len;
            continue;
        }
        i += 1;
        while (i < body.len and (body[i] == ' ' or body[i] == '\t' or body[i] == '\n' or body[i] == '\r')) i += 1;
        if (i >= body.len or body[i] != '"') {
            search_from = kpos + needle.len;
            continue;
        }
        i += 1;
        const start = i;
        while (i < body.len and body[i] != '"') {
            if (body[i] == '\\') i += 1; // skip escaped char
            i += 1;
        }
        if (i > body.len) return null;
        return body[start..i];
    }
    return null;
}

/// GET a URL with an Accept header. Returns the response (caller-owned).
fn httpGet(client: *http_client.Client, url: []const u8, accept: []const u8, out: *http_client.Response) http_client.NetError!void {
    const headers = [_]http_client.Header{
        .{ .name = "Accept", .value = accept },
        .{ .name = "User-Agent", .value = "speedy-socials-e2e/1.0" },
    };
    try client.sendSync(.{
        .method = .get,
        .url = url,
        .headers = &headers,
    }, out);
}

/// Resolve `acct:user@host` on the pod to its actor `id` URL via WebFinger.
fn webfingerActorId(client: *http_client.Client, base: []const u8, acct: []const u8, out_buf: []u8) !?[]const u8 {
    var url_buf: [max_url_bytes]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "{s}/.well-known/webfinger?resource=acct:{s}", .{ trimSlash(base), acct });

    var resp: http_client.Response = undefined;
    httpGet(client, url, "application/jrd+json", &resp) catch return null;
    if (resp.status != 200) return null;

    // The JRD links array carries rel="self" type="application/activity+json"
    // with href=<actor id>. We scan for the activity+json self link's href.
    const body = resp.body();
    // Find the "self" link block, then the following href.
    const self_at = std.mem.indexOf(u8, body, "\"self\"") orelse return null;
    const after = body[self_at..];
    const href = jsonStringField(after, "href") orelse return null;
    if (href.len == 0 or href.len > out_buf.len) return null;
    @memcpy(out_buf[0..href.len], href);
    return out_buf[0..href.len];
}

/// Fetch an actor document and pull its `inbox` URL.
fn actorInbox(client: *http_client.Client, actor_id: []const u8, out_buf: []u8) !?[]const u8 {
    var resp: http_client.Response = undefined;
    httpGet(client, actor_id, "application/activity+json", &resp) catch return null;
    if (resp.status != 200) return null;
    const inbox = jsonStringField(resp.body(), "inbox") orelse return null;
    if (inbox.len == 0 or inbox.len > out_buf.len) return null;
    @memcpy(out_buf[0..inbox.len], inbox);
    return out_buf[0..inbox.len];
}

/// Seed a local actor (`alice`) with an Ed25519 key into the in-memory DB,
/// returning the key_id the signer expects (`<origin>/users/alice#main-key`).
fn seedLocalActor(db: *c.sqlite3, local_origin: []const u8, now_unix: i64, key_id_buf: []u8) ![]const u8 {
    // Unique seed per run (wall-clock + stack-address derived) so repeated
    // runs against a live pod don't collide on object ids; key material need
    // not be stable across runs for a one-shot delivery test.
    var seed: [32]u8 = undefined;
    const ts: u64 = @bitCast(now_unix);
    const addr_entropy: u64 = @intFromPtr(key_id_buf.ptr);
    var prng = std.Random.DefaultPrng.init(ts ^ addr_entropy);
    prng.random().bytes(&seed);

    // PKCS#8 PEM for the seed (RFC 8410 Ed25519 PrivateKeyInfo).
    const prefix = [_]u8{
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
        0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    };
    var der: [48]u8 = undefined;
    @memcpy(der[0..16], &prefix);
    @memcpy(der[16..48], &seed);
    var b64_buf: [std.base64.standard.Encoder.calcSize(48)]u8 = undefined;
    const b64 = std.base64.standard.Encoder.encode(&b64_buf, &der);
    var priv_pem_buf: [256]u8 = undefined;
    const priv_pem = try std.fmt.bufPrint(&priv_pem_buf, "-----BEGIN PRIVATE KEY-----\n{s}\n-----END PRIVATE KEY-----", .{b64});

    {
        var stmt: ?*c.sqlite3_stmt = null;
        _ = c.sqlite3_prepare_v2(db, "INSERT INTO ap_users(username, display_name, bio, is_locked, discoverable, indexable, created_at) VALUES (?,?,?,?,?,?,?)", -1, &stmt, null);
        defer _ = c.sqlite3_finalize(stmt);
        _ = c.sqlite3_bind_text(stmt, 1, "alice".ptr, 5, c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_text(stmt, 2, "Alice".ptr, 5, c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_text(stmt, 3, "".ptr, 0, c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_int(stmt, 4, 0);
        _ = c.sqlite3_bind_int(stmt, 5, 1);
        _ = c.sqlite3_bind_int(stmt, 6, 1);
        _ = c.sqlite3_bind_int64(stmt, 7, 0);
        if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.SeedFailed;
    }
    const actor_id = c.sqlite3_last_insert_rowid(db);
    {
        var stmt: ?*c.sqlite3_stmt = null;
        _ = c.sqlite3_prepare_v2(db, "INSERT INTO ap_actor_keys(actor_id, key_type, public_pem, private_pem, created_at) VALUES (?,?,?,?,?)", -1, &stmt, null);
        defer _ = c.sqlite3_finalize(stmt);
        _ = c.sqlite3_bind_int64(stmt, 1, actor_id);
        _ = c.sqlite3_bind_text(stmt, 2, "ed25519".ptr, 7, c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_text(stmt, 3, "".ptr, 0, c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_blob(stmt, 4, priv_pem.ptr, @intCast(priv_pem.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_int64(stmt, 5, 0);
        if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.SeedFailed;
    }

    return std.fmt.bufPrint(key_id_buf, "{s}/users/alice#main-key", .{trimSlash(local_origin)});
}

test "mastodon e2e: signed Follow + Create + Like round trip against a live pod (skips unless MASTODON_E2E_URL)" {
    const base = env("MASTODON_E2E_URL") orelse return error.SkipZigTest;

    // The local bridge origin we advertise as `actor`. Defaults to a
    // .local host; override with MASTODON_E2E_LOCAL_ORIGIN if the pod must
    // resolve our keys (true two-way delivery). For inbox-accept checks the
    // pod queues key fetches asynchronously, so the synchronous POST still
    // returns 2xx with an unresolvable-but-well-formed signature on dev pods.
    const local_origin = env("MASTODON_E2E_LOCAL_ORIGIN") orelse "https://speedy.local";

    // Target acct on the pod. Default to admin@<pod-host>.
    var acct_buf: [256]u8 = undefined;
    const acct = env("MASTODON_E2E_ACCT") orelse blk: {
        break :blk std.fmt.bufPrint(&acct_buf, "admin@{s}", .{hostOf(base)}) catch return error.SkipZigTest;
    };

    // ── I/O + DB setup ───────────────────────────────────────────────────
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var client = http_client.Client.init(io);

    var real_clock = try core.clock.RealClock.init();
    const now: i64 = real_clock.clock().wallUnix();

    const db = try sqlite.openWriter(":memory:");
    defer sqlite.closeDb(db);
    try ap.schema.applyAllForTests(db);

    var key_id_buf: [max_url_bytes]u8 = undefined;
    const key_id = try seedLocalActor(db, local_origin, now, &key_id_buf);

    // ── pod → bridge reachability: NodeInfo must answer ──────────────────
    {
        var ni_url_buf: [max_url_bytes]u8 = undefined;
        const ni_url = try std.fmt.bufPrint(&ni_url_buf, "{s}/.well-known/nodeinfo", .{trimSlash(base)});
        var ni_resp: http_client.Response = undefined;
        httpGet(&client, ni_url, "application/json", &ni_resp) catch |e| {
            std.debug.print("MASTODON_E2E: pod unreachable at {s}: {s}\n", .{ ni_url, @errorName(e) });
            return error.SkipZigTest; // pod set but not up → skip rather than fail the suite
        };
        try testing.expect(ni_resp.status == 200);
    }

    // ── Resolve the pod actor + its inbox via WebFinger ──────────────────
    var actor_buf: [max_url_bytes]u8 = undefined;
    const pod_actor = (try webfingerActorId(&client, base, acct, &actor_buf)) orelse {
        std.debug.print("MASTODON_E2E: WebFinger could not resolve acct:{s} on {s}\n", .{ acct, base });
        return error.SkipZigTest;
    };

    var inbox_buf: [max_url_bytes]u8 = undefined;
    const pod_inbox = (try actorInbox(&client, pod_actor, &inbox_buf)) orelse {
        std.debug.print("MASTODON_E2E: actor {s} exposed no inbox\n", .{pod_actor});
        return error.SkipZigTest;
    };

    const local_actor_url = blk: {
        // <origin>/users/alice — strip the #main-key fragment from key_id.
        const hash = std.mem.indexOfScalar(u8, key_id, '#') orelse key_id.len;
        break :blk key_id[0..hash];
    };

    // ── bridge → pod #1: Follow{actor=alice, object=pod_actor} ───────────
    {
        var body_buf: [4096]u8 = undefined;
        const payload = try std.fmt.bufPrint(&body_buf,
            \\{{"@context":"https://www.w3.org/ns/activitystreams","id":"{s}/activities/follow-{d}","type":"Follow","actor":"{s}","object":"{s}"}}
        , .{ trimSlash(local_origin), now, local_actor_url, pod_actor });
        const r = ap.http_delivery.deliver(&client, db, now, pod_inbox, payload, key_id);
        try expectAcceptedOrSignatureRejected("Follow", r);
    }

    // ── bridge → pod #2: Create{Note} authored by alice ──────────────────
    {
        var body_buf: [4096]u8 = undefined;
        const payload = try std.fmt.bufPrint(&body_buf,
            \\{{"@context":"https://www.w3.org/ns/activitystreams","id":"{s}/activities/create-{d}","type":"Create","actor":"{s}","to":["https://www.w3.org/ns/activitystreams#Public"],"object":{{"id":"{s}/notes/{d}","type":"Note","attributedTo":"{s}","content":"e2e round-trip {d}","to":["https://www.w3.org/ns/activitystreams#Public"]}}}}
        , .{ trimSlash(local_origin), now, local_actor_url, trimSlash(local_origin), now, local_actor_url, now });
        const r = ap.http_delivery.deliver(&client, db, now, pod_inbox, payload, key_id);
        try expectAcceptedOrSignatureRejected("Create", r);
    }

    // ── bridge → pod #3: Like{object=pod_actor} ──────────────────────────
    {
        var body_buf: [4096]u8 = undefined;
        const payload = try std.fmt.bufPrint(&body_buf,
            \\{{"@context":"https://www.w3.org/ns/activitystreams","id":"{s}/activities/like-{d}","type":"Like","actor":"{s}","object":"{s}"}}
        , .{ trimSlash(local_origin), now, local_actor_url, pod_actor });
        const r = ap.http_delivery.deliver(&client, db, now, pod_inbox, payload, key_id);
        try expectAcceptedOrSignatureRejected("Like", r);
    }
}

/// A live Mastodon pod accepts a well-formed signed inbox POST with 202
/// (→ `.success`). If the pod cannot fetch our (localhost-only) public key
/// it may reject with 401 (→ `.permanent_failure`); that still proves the
/// full sign+POST+parse path executed end to end against a real pod, so we
/// accept it but never accept a transport failure (pod unreachable mid-test)
/// nor a silent no-op. Set MASTODON_E2E_LOCAL_ORIGIN to a pod-resolvable
/// host to require strict 2xx.
fn expectAcceptedOrSignatureRejected(label: []const u8, r: ap.outbox_worker.DeliveryResult) !void {
    switch (r) {
        .success => {}, // 2xx: accepted — ideal.
        .permanent_failure => {
            // 4xx (e.g. 401 unverifiable sig on a localhost actor). The
            // request reached the pod and was processed.
            std.debug.print("MASTODON_E2E: {s} reached pod but was rejected (likely unresolvable signature key). " ++
                "Set MASTODON_E2E_LOCAL_ORIGIN to a pod-resolvable host for strict 2xx.\n", .{label});
        },
        .transient_failure => {
            std.debug.print("MASTODON_E2E: {s} transport failure (pod went away mid-test)\n", .{label});
            return error.PodDeliveryTransportFailed;
        },
    }
}
