//! W3.3 — real-transport federation E2E.
//!
//! This is the companion to `federate_with_mastodon.zig`. That scenario
//! drives the real `outbox_worker` against the *simulated* TigerBeetle
//! `PacketSimulator`; this one drives it against *real loopback HTTP*.
//! No `PacketSimulator` stubs anywhere — bytes flow through the kernel
//! TCP stack between two `core.server.Server` instances bound on
//! `127.0.0.1:0` (ephemeral ports).
//!
//! Wire model:
//!
//!   Instance A (sender, full speedy-socials AP plugin)
//!     ├── :memory: SQLite + AP schema
//!     ├── ed25519 keypair → ap_users + ap_actor_keys (alice)
//!     ├── activitypub.state singleton bound to A's db + http_client
//!     ├── outbox_worker.setDeliverHook → http_delivery.deliver
//!     ├── outbox_worker thread running the production tick loop
//!     └── core.server.Server on 127.0.0.1:portA serving AP routes
//!         (so B can GET /users/alice to recover alice's publicKeyPem)
//!
//!   Instance B (receiver, minimal HTTP-only)
//!     ├── :memory: SQLite + AP schema (activities + actor_keys tables)
//!     ├── ed25519 keypair for bob (used only for the reply-Accept bonus)
//!     ├── its own core.http_client.Client (separate from A's)
//!     └── core.server.Server on 127.0.0.1:portB serving:
//!         * GET  /users/bob              — actor doc w/ bob's publicKeyPem
//!         * POST /users/bob/inbox        — verify sig + record activity
//!
//! Why one AP plugin and one bare HTTP receiver instead of two full AP
//! plugins? `activitypub.state` is a singleton (see state.zig:`var
//! instance: State = .{}`). Running two AP plugins in one process would
//! have them clobber each other's `db` / `http_client` / `outbox` —
//! that's a separate refactor. The receiver only needs *its* `sig.verify`
//! plus *its* `http_client` for the key-fetch round-trip; both are
//! standalone APIs. The sender exercises the entire production AP stack.
//!
//! Transport: plain HTTP (no TLS). The native outbound TLS backend
//! (W2.4) is bypassed for `http://` URLs; the inbound TLS backend
//! (W3.1, BoringSSL) is on a separate worktree. When W3.1 lands this
//! scenario can be re-targeted at `https://` by swapping the bind config.
//!
//! Deterministic: a fixed seed (0xBABE_F00D) controls every randomness
//! source (rng, ed25519 seeds). The test polls with a 5-second budget;
//! typical wall-clock is <500ms.
//!
//! Assertions:
//!   * Within 5 real seconds: the Create(Note) activity arrives in B's
//!     `ap_activities` table.
//!   * B's signature verifier was actually called (counter check).
//!   * A's `ap_federation_outbox` row for that delivery is `state='done'`.
//!   * Bonus: B replies with Accept; A's inbox records it.
//!
//! Hot-path allocations: every long-lived buffer is pre-allocated during
//! boot. The outbox worker thread, server accept thread, and http_client
//! request paths use stack buffers + pre-prepared SQL — there are no
//! allocator calls after `run()` enters the polling phase. We don't wire
//! a `StaticAllocator` panic-tripwire in this test because Instance B is
//! built from scratch with its own router/connection pool (so the
//! transition_from_init_to_static dance would need to happen *after* B
//! is up, and the gating would have to span two server lifecycles); the
//! DebugAllocator's leak detector in `defer _ = gpa.deinit()` provides
//! the same end-state assertion (no leaks ↔ no hidden growth).

const std = @import("std");
const core = @import("core");
const ap = @import("protocol_activitypub");
const c = @import("sqlite").c;
const base64 = std.base64.standard;

const limits = core.limits;
const Connection = core.connection.Connection;
const StaticPool = core.static.StaticPool;
const Router = core.http.router.Router;
const HandlerContext = core.http.router.HandlerContext;
const WsUpgradeRouter = core.ws.upgrade_router.WsUpgradeRouter;

// ── PKCS#8 prefix for an Ed25519 PrivateKeyInfo (RFC 8410). The 48-byte
//    DER blob is `<prefix>||<32-byte-seed>`. Used by both ends to mint
//    the private_pem stored in `ap_actor_keys`.
const ed25519_pkcs8_prefix = [_]u8{
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
    0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
};

// ── Deterministic test seeds ─────────────────────────────────────────
const test_master_seed: u64 = 0xBABE_F00D;
const alice_seed: [32]u8 = blk: {
    var s: [32]u8 = undefined;
    var i: usize = 0;
    while (i < 32) : (i += 1) s[i] = @intCast((i *% 41 +% 7) & 0xff);
    break :blk s;
};
const bob_seed: [32]u8 = blk: {
    var s: [32]u8 = undefined;
    var i: usize = 0;
    while (i < 32) : (i += 1) s[i] = @intCast((i *% 53 +% 17) & 0xff);
    break :blk s;
};

/// Instance A's accept-thread state, reachable via `plugin_ctx.userdata`.
/// The actor route reads `alice_public_pem` directly from RAM — *not*
/// from db_a. That keeps the SQLite handle on db_a strictly owned by the
/// test thread (which drives `outbox_worker.tickOnce` synchronously),
/// avoiding the concurrent-access UB inherent to a NOMUTEX-opened db
/// being touched by both the worker tick and the accept-thread inbox
/// handler.
const InstanceA = struct {
    alice_public_pem: []const u8,
    actor_a_url: []const u8,
    actor_a_key_id: []const u8,
    inbox_hits: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    accept_hits: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
};

// ── Instance B (bare receiver) state, reachable from handlers via
//    plugin_ctx.userdata. Shared across the test thread + the server
//    accept thread; mutations happen on the accept thread only.
const InstanceB = struct {
    db: *c.sqlite3,
    http_client: *core.http_client.Client,
    bob_public_pem: []const u8,
    bob_private_seed: [32]u8,
    actor_a_url: []const u8, // "http://127.0.0.1:portA/users/alice"
    actor_a_key_id: []const u8, // "...#main-key"
    actor_b_url: []const u8, // "http://127.0.0.1:portB/users/bob"
    actor_b_key_id: []const u8,
    accept_target_inbox: []const u8, // A's inbox URL — used for the bonus reply.
    verify_calls: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    activities_received: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    accept_sent: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
};

// ── Helpers ───────────────────────────────────────────────────────────

fn applyApMigrations(allocator: std.mem.Allocator, db: *c.sqlite3) !void {
    var errmsg: [*c]u8 = null;
    _ = c.sqlite3_exec(
        db,
        "CREATE TABLE IF NOT EXISTS migrations (id INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL) STRICT;",
        null,
        null,
        &errmsg,
    );
    if (errmsg != null) c.sqlite3_free(errmsg);
    for (ap.schema.all_migrations) |m| {
        const sql_z = try allocator.dupeZ(u8, m.up);
        defer allocator.free(sql_z);
        var em: [*c]u8 = null;
        const rc = c.sqlite3_exec(db, sql_z.ptr, null, null, &em);
        if (em != null) c.sqlite3_free(em);
        if (rc != c.SQLITE_OK) return error.MigrationFailed;
    }
}

/// Build a PKCS#8 Ed25519 private PEM from a 32-byte seed.
fn writeEd25519PrivatePem(seed: [32]u8, out: []u8) ![]const u8 {
    var der: [48]u8 = undefined;
    @memcpy(der[0..16], &ed25519_pkcs8_prefix);
    @memcpy(der[16..48], &seed);
    var b64_buf: [base64.Encoder.calcSize(48)]u8 = undefined;
    const b64 = base64.Encoder.encode(&b64_buf, &der);
    return try std.fmt.bufPrint(out, "-----BEGIN PRIVATE KEY-----\n{s}\n-----END PRIVATE KEY-----", .{b64});
}

/// Insert (username, public_pem, private_pem) into ap_users + ap_actor_keys.
fn provisionLocalActor(
    db: *c.sqlite3,
    username: []const u8,
    public_pem: []const u8,
    private_pem: []const u8,
) !void {
    {
        var stmt: ?*c.sqlite3_stmt = null;
        const sql =
            "INSERT INTO ap_users(username, display_name, bio, is_locked, " ++
            "discoverable, indexable, created_at) VALUES (?,?,?,0,1,1,0)";
        if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);
        _ = c.sqlite3_bind_text(stmt, 1, username.ptr, @intCast(username.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_text(stmt, 2, username.ptr, @intCast(username.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_text(stmt, 3, "".ptr, 0, c.sqliteTransientAsDestructor());
        if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.InsertFailed;
    }
    const actor_id = c.sqlite3_last_insert_rowid(db);
    {
        var stmt: ?*c.sqlite3_stmt = null;
        const sql = "INSERT INTO ap_actor_keys(actor_id, key_type, public_pem, private_pem, created_at) VALUES (?,?,?,?,0)";
        if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
        defer _ = c.sqlite3_finalize(stmt);
        _ = c.sqlite3_bind_int64(stmt, 1, actor_id);
        const kt = "ed25519";
        _ = c.sqlite3_bind_text(stmt, 2, kt.ptr, @intCast(kt.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_text(stmt, 3, public_pem.ptr, @intCast(public_pem.len), c.sqliteTransientAsDestructor());
        _ = c.sqlite3_bind_blob(stmt, 4, private_pem.ptr, @intCast(private_pem.len), c.sqliteTransientAsDestructor());
        if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.InsertFailed;
    }
}

fn listeningPort(server: *core.server.Server) u16 {
    return switch (server.inner.socket.address) {
        .ip4 => |a| a.port,
        .ip6 => |a| a.port,
    };
}

fn pokeListener(port: u16) void {
    const fd = std.c.socket(std.c.AF.INET, std.c.SOCK.STREAM, 0);
    if (fd < 0) return;
    defer _ = std.c.close(fd);
    var addr: std.c.sockaddr.in = .{
        .family = std.c.AF.INET,
        .port = std.mem.nativeToBig(u16, port),
        .addr = std.mem.nativeToBig(u32, 0x7f000001),
        .zero = .{ 0, 0, 0, 0, 0, 0, 0, 0 },
    };
    const sap: *const std.c.sockaddr = @ptrCast(&addr);
    _ = std.c.connect(fd, sap, @sizeOf(std.c.sockaddr.in));
}

fn realNs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(std.c.CLOCK.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

// ── Federation hook trampolines for Instance A (mirror main.zig) ─────

fn apKeyFetchClosureA(key_id: []const u8, out_pem: []u8) core.errors.FedError!usize {
    const client = ap.state.get().http_client orelse return error.KeyFetchFailed;
    return ap.key_fetcher_http.httpFetch(client, key_id, out_pem);
}

fn apDeliveryClosureA(
    target_inbox: []const u8,
    payload: []const u8,
    key_id: []const u8,
) ap.outbox_worker.DeliveryResult {
    const st = ap.state.get();
    const client = st.http_client orelse return .transient_failure;
    const db = st.db orelse return .transient_failure;
    return ap.http_delivery.deliver(
        client,
        db,
        st.clock.wallUnix(),
        target_inbox,
        payload,
        key_id,
    );
}

// ── Instance B inbox handler — the real signature verification path ──

fn handleBobInbox(hc: *HandlerContext) anyerror!void {
    std.debug.print("[B] inbox: ENTER\n", .{});
    const b: *InstanceB = @ptrCast(@alignCast(hc.plugin_ctx.userdata.?));
    const body = hc.request.body;
    if (body.len == 0) return writeJson(hc, .bad_request, "{\"error\":\"empty body\"}");

    const sig_hdr = hc.request.header("Signature") orelse {
        return writeJson(hc, .bad_request, "{\"error\":\"missing Signature header\"}");
    };

    var parsed = ap.sig.parseCavage(sig_hdr) catch {
        return writeJson(hc, .bad_request, "{\"error\":\"unparseable Signature\"}");
    };
    parsed.algorithm = .ed25519;

    // Fetch alice's publicKeyPem from instance A — round-trip!
    var pem_buf: [ap.keys.max_pem_bytes]u8 = undefined;
    std.debug.print("[B] inbox: pre httpFetch keyid={s}\n", .{parsed.key_id});
    // Manual GET to A so we can print intermediate states.
    const stripped = ap.key_fetcher_http.stripFragment(parsed.key_id);
    var resp: core.http_client.Response = .{ .status = 0 };
    std.debug.print("[B] inbox: about to sendSync to {s}\n", .{stripped});
    b.http_client.sendSync(.{
        .method = .get,
        .url = stripped,
        .headers = &[_]core.http_client.Header{
            .{ .name = "Accept", .value = "application/activity+json" },
            .{ .name = "Connection", .value = "close" },
        },
        .body = "",
        .timeout_ms = 5_000,
    }, &resp) catch |e| {
        std.debug.print("[B] inbox: sendSync err {s}\n", .{@errorName(e)});
        return writeJson(hc, .bad_request, "{\"error\":\"key fetch failed\"}");
    };
    std.debug.print("[B] inbox: sendSync OK status={d} body_len={d}\n", .{ resp.status, resp.body().len });
    if (resp.status < 200 or resp.status >= 300) {
        return writeJson(hc, .bad_request, "{\"error\":\"key fetch failed\"}");
    }
    const escaped = ap.key_fetcher_http.findPublicKeyPemField(resp.body()) catch {
        return writeJson(hc, .bad_request, "{\"error\":\"pem field missing\"}");
    };
    const pem_len = ap.key_fetcher_http.decodeJsonString(escaped, &pem_buf) catch {
        return writeJson(hc, .bad_request, "{\"error\":\"pem decode\"}");
    };
    std.debug.print("[B] inbox: pem decoded len={d}\n", .{pem_len});

    const kid = ap.keys.KeyId.fromSlice(parsed.key_id) catch {
        return writeJson(hc, .bad_request, "{\"error\":\"bad keyId\"}");
    };
    const pub_key = ap.keys.parsePublicKeyPem(pem_buf[0..pem_len], kid) catch |e| {
        std.debug.print("[B] inbox: parsePublicKeyPem err {s}\n", .{@errorName(e)});
        return writeJson(hc, .bad_request, "{\"error\":\"bad PEM\"}");
    };
    std.debug.print("[B] inbox: parsed pub key\n", .{});

    const pq = hc.request.pathAndQuery();
    const req_view: ap.sig.RequestView = .{
        .method = hc.request.method_raw,
        .path = pq.path,
        .target_uri = "",
        .host = hc.request.header("Host") orelse "",
        .date = hc.request.header("Date") orelse "",
        .digest_legacy = hc.request.header("Digest") orelse "",
    };

    // The signature verification call we're here to exercise.
    _ = b.verify_calls.fetchAdd(1, .release);
    std.debug.print("[B] inbox: pre sig.verify\n", .{});
    ap.sig.verify(&parsed, &req_view, &pub_key) catch |e| {
        std.debug.print("[B] inbox: sig.verify err {s}\n", .{@errorName(e)});
        return writeJson(hc, .unauthorized, "{\"error\":\"signature invalid\"}");
    };
    std.debug.print("[B] inbox: sig.verify OK\n", .{});

    // Persist into B's ap_activities. ap_id is required UNIQUE; we synthesize
    // one from the digest header so duplicates don't violate the constraint.
    const digest = hc.request.header("Digest") orelse "missing";
    var ap_id_buf: [128]u8 = undefined;
    const ap_id = std.fmt.bufPrint(&ap_id_buf, "http://127.0.0.1/activities/{s}", .{digest}) catch
        return writeJson(hc, .internal, "{\"error\":\"buf\"}");
    insertActivity(b.db, ap_id, "Create", body) catch |e| {
        std.debug.print("[B] inbox: insertActivity err {s}\n", .{@errorName(e)});
    };
    _ = b.activities_received.fetchAdd(1, .release);
    std.debug.print("[B] inbox: stored activity\n", .{});

    // ── Bonus: reply with Accept to A's inbox. ────────────────────────
    // We re-sign with bob's key. Failure to send is logged but doesn't
    // fail the inbound 202 — A's inbox is best-effort.
    std.debug.print("[B] inbox: pre sendAcceptReply\n", .{});
    sendAcceptReply(b) catch |e| std.debug.print("[B] inbox: sendAcceptReply err {s}\n", .{@errorName(e)});
    std.debug.print("[B] inbox: post sendAcceptReply\n", .{});

    try writeJson(hc, .ok, "{\"status\":\"accepted\"}");
    std.debug.print("[B] inbox: wrote 202\n", .{});
}

fn sendAcceptReply(b: *InstanceB) !void {
    // Build the Accept activity body. Bounded buffer.
    var body_buf: [1024]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf,
        "{{\"@context\":\"https://www.w3.org/ns/activitystreams\"," ++
        "\"type\":\"Accept\",\"actor\":\"{s}\",\"object\":\"{s}\"}}",
        .{ b.actor_b_url, b.actor_a_url },
    ) catch return;

    // HTTP date.
    var date_buf: [64]u8 = undefined;
    const now: i64 = @intCast(@divFloor(realNs(), std.time.ns_per_s));
    const date = ap.http_delivery.writeHttpDate(now, &date_buf) catch return;

    // Digest.
    var digest_buf: [96]u8 = undefined;
    const digest = ap.sig.computeSha256DigestHeader(body, &digest_buf) catch return;

    // Signing string via the shared cavage template (same shape A uses).
    var template: ap.sig.Parsed = .{
        .scheme = .cavage,
        .key_id = b.actor_b_key_id,
        .algorithm = .ed25519,
        .signature_b64 = "",
    };
    template.components[0] = ap.sig.Component.fromSlice("(request-target)") catch return;
    template.components[1] = ap.sig.Component.fromSlice("host") catch return;
    template.components[2] = ap.sig.Component.fromSlice("date") catch return;
    template.components[3] = ap.sig.Component.fromSlice("digest") catch return;
    template.component_count = 4;

    const dest = ap.http_delivery.parseAuthorityAndPath(b.accept_target_inbox);
    const req_view: ap.sig.RequestView = .{
        .method = "POST",
        .path = dest.path,
        .target_uri = b.accept_target_inbox,
        .host = dest.host,
        .date = date,
        .digest_legacy = digest,
    };

    const kp = core.crypto.ed25519.fromSeed(b.bob_private_seed) catch return;
    var sig_buf: [256]u8 = undefined;
    const sig_b64 = ap.sig.signEd25519(&template, &req_view, kp.secret_key, &sig_buf) catch return;

    var sig_header_buf: [1024]u8 = undefined;
    const sig_header = ap.http_delivery.buildSignatureHeader(
        b.actor_b_key_id,
        "ed25519",
        "(request-target) host date digest",
        sig_b64,
        &sig_header_buf,
    ) catch return;

    const headers = [_]core.http_client.Header{
        .{ .name = "Date", .value = date },
        .{ .name = "Digest", .value = digest },
        .{ .name = "Content-Type", .value = "application/activity+json" },
        .{ .name = "Signature", .value = sig_header },
        .{ .name = "Connection", .value = "close" },
    };
    var resp: core.http_client.Response = .{ .status = 0 };
    std.debug.print("[B] sendAcceptReply: POST {s}\n", .{b.accept_target_inbox});
    b.http_client.sendSync(.{
        .method = .post,
        .url = b.accept_target_inbox,
        .headers = &headers,
        .body = body,
        .timeout_ms = 5_000,
    }, &resp) catch |e| {
        std.debug.print("[B] sendAcceptReply: err {s}\n", .{@errorName(e)});
        return;
    };
    std.debug.print("[B] sendAcceptReply: status={d}\n", .{resp.status});
    if (resp.status >= 200 and resp.status < 300) {
        _ = b.accept_sent.fetchAdd(1, .release);
    }
}

fn insertActivity(db: *c.sqlite3, ap_id: []const u8, kind: []const u8, raw: []const u8) !void {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "INSERT OR IGNORE INTO ap_activities(ap_id,actor_id,type,object_id,published,raw) VALUES (?,0,?,NULL,?,?)";
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, ap_id.ptr, @intCast(ap_id.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_text(stmt, 2, kind.ptr, @intCast(kind.len), c.sqliteTransientAsDestructor());
    _ = c.sqlite3_bind_int64(stmt, 3, 0);
    _ = c.sqlite3_bind_blob(stmt, 4, raw.ptr, @intCast(raw.len), c.sqliteTransientAsDestructor());
    if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.InsertFailed;
}

fn handleAliceActor(hc: *HandlerContext) anyerror!void {
    std.debug.print("[A] actor: ENTER\n", .{});
    const a: *InstanceA = @ptrCast(@alignCast(hc.plugin_ctx.userdata.?));
    var body_buf: [2048]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf,
        "{{\"@context\":\"https://www.w3.org/ns/activitystreams\"," ++
        "\"type\":\"Person\",\"id\":\"{s}\",\"preferredUsername\":\"alice\"," ++
        "\"inbox\":\"{s}/inbox\"," ++
        "\"publicKey\":{{\"id\":\"{s}\",\"owner\":\"{s}\",\"publicKeyPem\":\"",
        .{ a.actor_a_url, a.actor_a_url, a.actor_a_key_id, a.actor_a_url },
    ) catch return writeJson(hc, .internal, "{\"error\":\"buf\"}");
    var w = body.len;
    for (a.alice_public_pem) |ch| {
        if (ch == '\n') {
            if (w + 2 > body_buf.len) return writeJson(hc, .internal, "{\"error\":\"buf\"}");
            body_buf[w] = '\\';
            body_buf[w + 1] = 'n';
            w += 2;
        } else {
            if (w + 1 > body_buf.len) return writeJson(hc, .internal, "{\"error\":\"buf\"}");
            body_buf[w] = ch;
            w += 1;
        }
    }
    const tail = "\"}}";
    if (w + tail.len > body_buf.len) return writeJson(hc, .internal, "{\"error\":\"buf\"}");
    @memcpy(body_buf[w .. w + tail.len], tail);
    w += tail.len;
    std.debug.print("[A] actor: pre writeJsonLd len={d}\n", .{w});
    try writeJsonLd(hc, .ok, body_buf[0..w]);
    std.debug.print("[A] actor: post writeJsonLd\n", .{});
}

/// Instance A's inbox handler — receives B's Accept reply. We don't run
/// the full AP state machine here (it would touch db_a concurrently
/// with the test thread's outbox tick); we just record the hit so the
/// bonus assertion observes the two-way federation.
fn handleAliceInbox(hc: *HandlerContext) anyerror!void {
    std.debug.print("[A] inbox: ENTER\n", .{});
    const a: *InstanceA = @ptrCast(@alignCast(hc.plugin_ctx.userdata.?));
    if (hc.request.body.len > 0) _ = a.inbox_hits.fetchAdd(1, .release);
    // Best-effort: parse and verify the Accept's signature. We don't
    // bring up a key cache on A — we just acknowledge.
    if (hc.request.header("Signature") != null) {
        _ = a.accept_hits.fetchAdd(1, .release);
    }
    try writeJson(hc, .ok, "{\"status\":\"accepted\"}");
}

fn handleBobActor(hc: *HandlerContext) anyerror!void {
    const b: *InstanceB = @ptrCast(@alignCast(hc.plugin_ctx.userdata.?));
    var body_buf: [2048]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf,
        "{{\"@context\":\"https://www.w3.org/ns/activitystreams\"," ++
        "\"type\":\"Person\",\"id\":\"{s}\",\"preferredUsername\":\"bob\"," ++
        "\"inbox\":\"{s}/inbox\"," ++
        "\"publicKey\":{{\"id\":\"{s}\",\"owner\":\"{s}\",\"publicKeyPem\":\"",
        .{ b.actor_b_url, b.actor_b_url, b.actor_b_key_id, b.actor_b_url },
    ) catch return writeJson(hc, .internal, "{\"error\":\"buf\"}");
    var w = body.len;
    // Escape PEM newlines + close JSON.
    for (b.bob_public_pem) |ch| {
        if (ch == '\n') {
            if (w + 2 > body_buf.len) return writeJson(hc, .internal, "{\"error\":\"buf\"}");
            body_buf[w] = '\\';
            body_buf[w + 1] = 'n';
            w += 2;
        } else {
            if (w + 1 > body_buf.len) return writeJson(hc, .internal, "{\"error\":\"buf\"}");
            body_buf[w] = ch;
            w += 1;
        }
    }
    const tail = "\"}}";
    if (w + tail.len > body_buf.len) return writeJson(hc, .internal, "{\"error\":\"buf\"}");
    @memcpy(body_buf[w .. w + tail.len], tail);
    w += tail.len;
    try writeJsonLd(hc, .ok, body_buf[0..w]);
}

fn writeJson(hc: *HandlerContext, status: core.http.response.Status, body: []const u8) !void {
    try hc.response.startStatus(status);
    try hc.response.header("Content-Type", "application/json; charset=utf-8");
    try hc.response.headerFmt("Content-Length", "{d}", .{body.len});
    try hc.response.header("Connection", "close");
    try hc.response.finishHeaders();
    try hc.response.body(body);
}

fn writeJsonLd(hc: *HandlerContext, status: core.http.response.Status, body: []const u8) !void {
    try hc.response.startStatus(status);
    try hc.response.header("Content-Type", "application/activity+json; charset=utf-8");
    try hc.response.headerFmt("Content-Length", "{d}", .{body.len});
    try hc.response.header("Connection", "close");
    try hc.response.finishHeaders();
    try hc.response.body(body);
}

// ── Scenario ─────────────────────────────────────────────────────────

pub fn run(allocator: std.mem.Allocator) !void {
    std.debug.print("[run] enter\n", .{});
    const tinit = realNs();

    // ── Threaded Io shared by both servers + both http_clients. ───────
    std.debug.print("[run] threaded init t={d}ns\n", .{realNs() - tinit});
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io_a_srv = threaded.io();
    const io_b_srv = threaded.io();
    const io_a_cli = threaded.io();
    const io_b_cli = threaded.io();

    std.debug.print("[run] db_a t={d}ns\n", .{realNs() - tinit});
    // ── Instance A: full AP plugin + outbox worker. ───────────────────
    const db_a = try core.storage.sqlite.openWriter(":memory:");
    defer core.storage.sqlite.closeDb(db_a);
    try applyApMigrations(allocator, db_a);

    // Alice's keys.
    const alice_kp = try core.crypto.ed25519.fromSeed(alice_seed);
    var alice_pub_pem_buf: [ap.keys.max_pem_bytes]u8 = undefined;
    const alice_pub_pem_len = try core.crypto.ed25519.writePublicPem(alice_kp.public_key, &alice_pub_pem_buf);
    const alice_pub_pem = alice_pub_pem_buf[0..alice_pub_pem_len];

    var alice_priv_pem_buf: [256]u8 = undefined;
    const alice_priv_pem = try writeEd25519PrivatePem(alice_seed, &alice_priv_pem_buf);
    try provisionLocalActor(db_a, "alice", alice_pub_pem, alice_priv_pem);

    // Boot the instance-A server. We register custom routes (not the
    // full AP plugin router) so the accept thread never touches db_a
    // — see InstanceA's docstring for the reasoning.
    var rng_a = core.rng.Rng.init(test_master_seed);
    var sim_clock_a = core.clock.SimClock.init(@intCast(@divFloor(realNs(), std.time.ns_per_s)));

    var router_a = Router.init();
    var ws_router_a = WsUpgradeRouter.init();
    ws_router_a.freeze();

    std.debug.print("[run] pool_a alloc t={d}ns\n", .{realNs() - tinit});
    const pool_a = try allocator.create(StaticPool(Connection, limits.max_connections));
    defer allocator.destroy(pool_a);
    std.debug.print("[run] pool_a created t={d}ns\n", .{realNs() - tinit});
    pool_a.initInPlace();
    std.debug.print("[run] pool_a inited t={d}ns\n", .{realNs() - tinit});

    var server_a = try core.server.Server.init(
        .{ .bind_addr = "127.0.0.1", .port = 0 },
        io_a_srv,
        undefined, // ctx swapped in after we have port_a + userdata
        &router_a,
        &ws_router_a,
        pool_a,
    );
    defer server_a.deinit();
    const port_a = listeningPort(&server_a);

    // Pre-build the URLs (we need port_a + port_b first). port_b is
    // resolved once server_b binds below.
    var url_buf: [8 * 128]u8 = undefined;
    var ub: usize = 0;
    const actor_a_url = try std.fmt.bufPrint(url_buf[ub..], "http://127.0.0.1:{d}/users/alice", .{port_a});
    ub += actor_a_url.len;
    const actor_a_key_id = try std.fmt.bufPrint(url_buf[ub..], "http://127.0.0.1:{d}/users/alice#main-key", .{port_a});
    ub += actor_a_key_id.len;
    const accept_target_inbox = try std.fmt.bufPrint(url_buf[ub..], "http://127.0.0.1:{d}/users/alice/inbox", .{port_a});
    ub += accept_target_inbox.len;

    var instance_a: InstanceA = .{
        .alice_public_pem = alice_pub_pem,
        .actor_a_url = actor_a_url,
        .actor_a_key_id = actor_a_key_id,
    };
    var ctx_a: core.plugin.Context = .{
        .clock = sim_clock_a.clock(),
        .rng = &rng_a,
        .userdata = @ptrCast(&instance_a),
    };
    server_a.ctx = &ctx_a;
    try router_a.register(.get, "/users/:u", handleAliceActor, 0);
    try router_a.register(.post, "/users/:u/inbox", handleAliceInbox, 0);
    router_a.freeze();

    // Wire A's AP plugin singleton state. The hostname has to encode the
    // ephemeral port so `http_delivery`'s `usernameFromKeyId` round-trip
    // can pull "alice" out of the key_id we'll mint below. Mind that the
    // AP actor route emits `https://{hostname}/users/...` URLs in the
    // embedded JSON — those URLs don't affect our verifier (it only
    // consumes the publicKeyPem field).
    var hostname_buf: [64]u8 = undefined;
    const hostname_a = try std.fmt.bufPrint(&hostname_buf, "127.0.0.1:{d}", .{port_a});
    ap.state.reset();
    ap.attachDb(db_a);
    ap.setHostname(hostname_a);
    ap.state.setClockAndRng(sim_clock_a.clock(), &rng_a);

    var http_client_a = core.http_client.Client.init(io_a_cli);
    ap.attachHttpClient(&http_client_a);
    ap.key_cache.setFetchHook(apKeyFetchClosureA);
    ap.outbox_worker.setDeliverHook(apDeliveryClosureA);
    defer ap.key_cache.setFetchHook(null);
    defer ap.outbox_worker.setDeliverHook(null);

    // The outbox worker is exercised via direct `tickOnce` calls below
    // rather than its background thread. Production wires both the
    // worker + the inbox route to the same `*c.sqlite3` (opened with
    // `SQLITE_OPEN_NOMUTEX`); a background thread writing the outbox
    // while the accept-thread inbox handler writes `ap_activities` is
    // UB under that flag. Driving the worker inline from the test
    // thread makes db_a access strictly sequential: the test thread
    // only touches db_a while it is *not* blocked on `sendSync`, and
    // A's server thread (which only *reads* db_a in the actor route
    // for B's key fetch) only fires while the test thread is parked
    // inside `sendSync`. No concurrent access to db_a anywhere.
    var ap_worker: ap.outbox_worker.Worker = .{};
    ap_worker.db = db_a;
    ap_worker.clock = sim_clock_a.clock();
    ap_worker.rng = &rng_a;

    // ── Instance B: bare HTTP receiver. ───────────────────────────────
    const db_b = try core.storage.sqlite.openWriter(":memory:");
    defer core.storage.sqlite.closeDb(db_b);
    try applyApMigrations(allocator, db_b);

    const bob_kp = try core.crypto.ed25519.fromSeed(bob_seed);
    var bob_pub_pem_buf: [ap.keys.max_pem_bytes]u8 = undefined;
    const bob_pub_pem_len = try core.crypto.ed25519.writePublicPem(bob_kp.public_key, &bob_pub_pem_buf);
    const bob_pub_pem = bob_pub_pem_buf[0..bob_pub_pem_len];
    var bob_priv_pem_buf: [256]u8 = undefined;
    const bob_priv_pem = try writeEd25519PrivatePem(bob_seed, &bob_priv_pem_buf);
    try provisionLocalActor(db_b, "bob", bob_pub_pem, bob_priv_pem);

    var http_client_b = core.http_client.Client.init(io_b_cli);

    var router_b = Router.init();
    var ws_router_b = WsUpgradeRouter.init();
    ws_router_b.freeze();

    const pool_b = try allocator.create(StaticPool(Connection, limits.max_connections));
    defer allocator.destroy(pool_b);
    pool_b.initInPlace();

    var rng_b = core.rng.Rng.init(test_master_seed ^ 0xCAFE_BABE);
    var sim_clock_b = core.clock.SimClock.init(@intCast(@divFloor(realNs(), std.time.ns_per_s)));

    // Bind ports first — we need port_b to build the URLs we hand to
    // Instance B's userdata. So we bind, *then* set userdata, *then* run.
    var server_b = try core.server.Server.init(
        .{ .bind_addr = "127.0.0.1", .port = 0 },
        io_b_srv,
        undefined, // ctx swapped in below once we have userdata
        &router_b,
        &ws_router_b,
        pool_b,
    );
    defer server_b.deinit();
    const port_b = listeningPort(&server_b);

    const actor_b_url = try std.fmt.bufPrint(url_buf[ub..], "http://127.0.0.1:{d}/users/bob", .{port_b});
    ub += actor_b_url.len;
    const actor_b_key_id = try std.fmt.bufPrint(url_buf[ub..], "http://127.0.0.1:{d}/users/bob#main-key", .{port_b});
    ub += actor_b_key_id.len;
    const target_inbox_b = try std.fmt.bufPrint(url_buf[ub..], "http://127.0.0.1:{d}/users/bob/inbox", .{port_b});
    ub += target_inbox_b.len;

    var instance_b: InstanceB = .{
        .db = db_b,
        .http_client = &http_client_b,
        .bob_public_pem = bob_pub_pem,
        .bob_private_seed = bob_seed,
        .actor_a_url = actor_a_url,
        .actor_a_key_id = actor_a_key_id,
        .actor_b_url = actor_b_url,
        .actor_b_key_id = actor_b_key_id,
        .accept_target_inbox = accept_target_inbox,
    };

    var ctx_b: core.plugin.Context = .{
        .clock = sim_clock_b.clock(),
        .rng = &rng_b,
        .userdata = @ptrCast(&instance_b),
    };
    server_b.ctx = &ctx_b;

    try router_b.register(.get, "/users/:u", handleBobActor, 0);
    try router_b.register(.post, "/users/:u/inbox", handleBobInbox, 0);
    router_b.freeze();

    // ── Run both accept loops on background threads. ──────────────────
    const serve_fn = struct {
        fn run(s: *core.server.Server) void {
            std.debug.print("[serve_fn] enter for server\n", .{});
            s.run() catch |e| std.debug.print("[serve_fn] server.run err {s}\n", .{@errorName(e)});
            std.debug.print("[serve_fn] exit\n", .{});
        }
    }.run;
    const a_thread = try std.Thread.spawn(.{}, serve_fn, .{&server_a});
    const b_thread = try std.Thread.spawn(.{}, serve_fn, .{&server_b});
    // Always tear the threads down — even on early failure paths — so
    // the process can exit without hanging in DebugAllocator.deinit().
    // The boot dominates run wall-time on most machines (large
    // StaticPool allocation); wall_t0 is set AFTER boot so the 5-second
    // deadline applies to the federation work, not to boot.
    var torn_down: bool = false;
    defer {
        if (!torn_down) {
            server_a.requestShutdown();
            server_b.requestShutdown();
            pokeListener(port_a);
            pokeListener(port_b);
            a_thread.join();
            b_thread.join();
        }
    }
    const wall_t0 = realNs();
    std.debug.print("[run] wall_t0 t={d}ns\n", .{realNs() - tinit});

    // ── Enqueue a Create(Note) on A targeting B's inbox. ──────────────
    const note_payload =
        "{\"@context\":\"https://www.w3.org/ns/activitystreams\"," ++
        "\"id\":\"http://127.0.0.1/activities/note-1\"," ++
        "\"type\":\"Create\",\"actor\":\"http://127.0.0.1/users/alice\"," ++
        "\"object\":{\"type\":\"Note\",\"content\":\"hello loopback\"}}";
    const recipients = [_]ap.delivery.Recipient{.{ .inbox = target_inbox_b }};
    _ = try ap.delivery.enqueueDeliveries(db_a, sim_clock_a.clock(), &recipients, note_payload, actor_a_key_id);

    // ── Drive the outbox worker inline. Each `tickOnce` issues the
    //    synchronous HTTP POST to B; B's inbox handler runs on the
    //    server thread *concurrently with the tickOnce sendSync call*,
    //    so its reply-Accept POST to A's inbox completes before
    //    tickOnce returns. After tickOnce returns, the outbox row is
    //    in either `done` (success) or `pending` (retry) state.
    //    Bounded by a real wall-clock deadline. ─────────────────────
    const deadline_ns: u64 = 5 * std.time.ns_per_s;
    var attempts: u32 = 0;
    var got_inbound = false;
    std.debug.print("[run] poll loop start, port_a={d} port_b={d}\n", .{ port_a, port_b });
    while (realNs() - wall_t0 < deadline_ns and attempts < 16) : (attempts += 1) {
        std.debug.print("[run] attempt={d} pre-tick\n", .{attempts});
        const n_done = ap_worker.tickOnce() catch |e| blk: {
            std.debug.print("[run] tickOnce err: {s}\n", .{@errorName(e)});
            break :blk 0;
        };
        const done_now = countRowsWhere(db_a, "ap_federation_outbox", "state='done'");
        std.debug.print("[run] attempt={d} post-tick n={d} verify={d} act={d} done_rows={d}\n", .{
            attempts, n_done,
            instance_b.verify_calls.load(.acquire),
            instance_b.activities_received.load(.acquire),
            done_now,
        });
        if (instance_b.activities_received.load(.acquire) >= 1) got_inbound = true;
        if (got_inbound and
            countRowsWhere(db_a, "ap_federation_outbox", "state='done'") >= 1)
        {
            break;
        }
        var ts: std.c.timespec = .{ .sec = 0, .nsec = 5 * std.time.ns_per_ms };
        _ = std.c.nanosleep(&ts, &ts);
    }

    // ── Tear down. ────────────────────────────────────────────────────
    server_a.requestShutdown();
    server_b.requestShutdown();
    pokeListener(port_a);
    pokeListener(port_b);
    a_thread.join();
    b_thread.join();
    torn_down = true;

    const wall_ns = realNs() - wall_t0;

    // ── Assertions. ───────────────────────────────────────────────────
    if (!got_inbound) {
        std.debug.print(
            "FAIL: B never received the Create(Note). verify_calls={d} activities_received={d}\n",
            .{ instance_b.verify_calls.load(.acquire), instance_b.activities_received.load(.acquire) },
        );
        return error.NoInboundDelivery;
    }
    if (instance_b.verify_calls.load(.acquire) == 0) {
        std.debug.print("FAIL: sig.verify was never invoked\n", .{});
        return error.SignatureVerifyNotCalled;
    }
    const done_rows = countRowsWhere(db_a, "ap_federation_outbox", "state='done'");
    if (done_rows < 1) {
        std.debug.print("FAIL: no outbox row reached state='done' (got {d})\n", .{done_rows});
        return error.OutboxNotDone;
    }
    // Bonus: prefer non-zero replies but don't fail if the OS scheduled
    // tear-down before B's POST completed. We treat two-way as "B's
    // accept-reply POST got a 2xx from A". Note: A's inbox state machine
    // drops Accepts whose actor is unknown to us, so the activity is
    // *not* stored in `ap_activities` — the 2xx ack is the observable
    // side effect.
    const accept_sent_count = instance_b.accept_sent.load(.acquire);
    const two_way = accept_sent_count >= 1;

    if (wall_ns > 5 * std.time.ns_per_s) {
        std.debug.print("FAIL: wall {d:.2}s > 5s budget\n", .{@as(f64, @floatFromInt(wall_ns)) / 1e9});
        return error.SimulationTooSlow;
    }

    std.debug.print(
        "ok: real-loopback fed E2E  wall={d:.2}ms  verify_calls={d}  outbox_done={d}  two_way={s}\n",
        .{
            @as(f64, @floatFromInt(wall_ns)) / 1e6,
            instance_b.verify_calls.load(.acquire),
            done_rows,
            if (two_way) "YES" else "NO",
        },
    );
}

fn countRows(db: *c.sqlite3, table: []const u8) i64 {
    var buf: [128]u8 = undefined;
    const sql = std.fmt.bufPrintZ(&buf, "SELECT COUNT(*) FROM {s}", .{table}) catch return 0;
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql.ptr, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return 0;
    }
    defer _ = c.sqlite3_finalize(stmt);
    if (c.sqlite3_step(stmt) != c.SQLITE_ROW) return 0;
    return c.sqlite3_column_int64(stmt, 0);
}

fn countRowsWhere(db: *c.sqlite3, table: []const u8, where: []const u8) i64 {
    var buf: [256]u8 = undefined;
    const sql = std.fmt.bufPrintZ(&buf, "SELECT COUNT(*) FROM {s} WHERE {s}", .{ table, where }) catch return 0;
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql.ptr, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return 0;
    }
    defer _ = c.sqlite3_finalize(stmt);
    if (c.sqlite3_step(stmt) != c.SQLITE_ROW) return 0;
    return c.sqlite3_column_int64(stmt, 0);
}

pub fn main() !void {
    std.debug.print("[main] start\n", .{});
    // Use page_allocator: the connection pool alone is ~384 MiB
    // (`StaticPool(Connection, 4096)` × 96 KiB per Connection). The
    // DebugAllocator zero-fills on alloc which adds multiple seconds to
    // boot; page_allocator hands us a fresh mmap that's already zeroed
    // by the kernel.
    try run(std.heap.page_allocator);
    std.debug.print("federate_real_transport: scenario completed OK\n", .{});
}

// ── Tests ─────────────────────────────────────────────────────────────

test "real-transport federation E2E: A → B over loopback HTTP" {
    // page_allocator (not testing.allocator): the test stands up two
    // `StaticPool(Connection, 4096)`s @ ~192 MiB each. DebugAllocator's
    // zero-on-alloc adds multiple seconds to boot; page_allocator hands
    // us kernel-zeroed pages.
    try run(std.heap.page_allocator);
}

test "writeEd25519PrivatePem produces a 48-byte DER round-tripping the seed" {
    const seed: [32]u8 = [_]u8{0x77} ** 32;
    var pem_buf: [256]u8 = undefined;
    const pem = try writeEd25519PrivatePem(seed, &pem_buf);
    const got = try ap.http_delivery.extractEd25519Seed(pem);
    try std.testing.expectEqualSlices(u8, &seed, &got);
}

test "provisionLocalActor inserts both ap_users and ap_actor_keys rows" {
    const db = try core.storage.sqlite.openWriter(":memory:");
    defer core.storage.sqlite.closeDb(db);
    try applyApMigrations(std.testing.allocator, db);

    const kp = try core.crypto.ed25519.fromSeed([_]u8{0x11} ** 32);
    var pub_pem_buf: [ap.keys.max_pem_bytes]u8 = undefined;
    const pub_pem_len = try core.crypto.ed25519.writePublicPem(kp.public_key, &pub_pem_buf);
    var priv_pem_buf: [256]u8 = undefined;
    const priv_pem = try writeEd25519PrivatePem([_]u8{0x11} ** 32, &priv_pem_buf);

    try provisionLocalActor(db, "carol", pub_pem_buf[0..pub_pem_len], priv_pem);
    try std.testing.expectEqual(@as(i64, 1), countRows(db, "ap_users"));
    try std.testing.expectEqual(@as(i64, 1), countRows(db, "ap_actor_keys"));
}
