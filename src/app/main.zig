//! Composition root: build core, register plugins, run server.
//!
//! This is the *only* place the GeneralPurposeAllocator and the plugin
//! list are mentioned. Everything below `server.run()` operates on
//! statically-sized buffers handed in here.

const std = @import("std");
const Io = std.Io;
const core = @import("core");
const echo = @import("protocol_echo");
const atproto = @import("protocol_atproto");
const activitypub = @import("protocol_activitypub");
const mastodon = @import("protocol_mastodon");
const relay = @import("protocol_relay");
const media = @import("protocol_media");

const limits = core.limits;
const Connection = core.connection.Connection;
const StaticPool = core.static.StaticPool;

/// Liveness hook: process is up. Always ready. Plugins will add more
/// substantive hooks (storage, etc.) in later phases.
fn alwaysReadyHook(_: ?*anyopaque) core.health.Status {
    return .ready;
}

/// F2: deep readiness — the writer thread is responsible for actually
/// persisting plugin writes. If the channel is closed (writer
/// stopped or crashed) we are not ready.
fn writerReadyHook(ud: ?*anyopaque) core.health.Status {
    const ch: *const core.storage.Channel = @ptrCast(@alignCast(ud orelse return .not_ready));
    if (ch.closed.load(.acquire)) return .not_ready;
    return .ready;
}

/// F2: the AP federation outbox worker drains pending deliveries.
/// We surface `not_ready` when the worker has not yet been started.
fn apOutboxReadyHook(_: ?*anyopaque) core.health.Status {
    const st = activitypub.state.get();
    if (!st.outbox.running.load(.acquire)) return .not_ready;
    return .ready;
}

/// F2: relay firehose consumer.
fn relayConsumerReadyHook(_: ?*anyopaque) core.health.Status {
    if (relay.firehose_consumer.current() == null) return .not_ready;
    return .ready;
}

// ── Inbound TLS (W3.2) wiring helpers ────────────────────────────────
//
// `InboundTlsHolder` owns the heap-allocated inbound TLS backend for
// the lifetime of `main`. We allocate via the GPA (boot-only) and
// never reallocate. The backend itself uses no allocator on the hot
// path; its slot pool is heap-allocated once at `init`.
//
// Default backend: `core.tls.ianic_inbound.IanicInboundBackend` — pure
// Zig, no system OpenSSL link required for server TLS. The OpenSSL
// link stays in the build narrowly for RSA-PKCS1v15-SHA256 signing
// (used by ActivityPub federation outbound delivery for Mastodon's
// rsa-sha256 actors); see `src/core/crypto/openssl.zig`.

const InboundTlsHolder = struct {
    backend: ?*core.tls.ianic_inbound.IanicInboundBackend = null,
    allocator: ?std.mem.Allocator = null,

    fn deinit(self: *InboundTlsHolder) void {
        if (self.backend) |b| {
            b.deinit();
            if (self.allocator) |a| a.destroy(b);
        }
        self.* = .{};
    }
};

/// If `TLS_CERT_PATH` and `TLS_KEY_PATH` are both set in the
/// environment, load the PEMs, build the inbound TLS backend, and
/// return a `core.tls.TlsBackend` pointing at it. Otherwise return
/// null (plain-HTTP fall-through).
fn loadInboundTlsIfConfigured(
    holder: *InboundTlsHolder,
    allocator: std.mem.Allocator,
    io: std.Io,
    log_ptr: *core.log.Log,
) !?core.tls.TlsBackend {
    // Zig 0.16's `std.process` no longer exposes the global-env helpers
    // (`getEnvVarOwned`); the replacement is `Environ` which carries
    // through `init.environ_map`. For boot config we just consult the
    // POSIX `environ` directly — bounded, no alloc, portable to macOS +
    // Linux. Windows is not a target here.
    const cert_path_c = std.c.getenv("TLS_CERT_PATH") orelse return null;
    const key_path_c = std.c.getenv("TLS_KEY_PATH") orelse {
        log_ptr.warn("boot", "TLS_CERT_PATH set without TLS_KEY_PATH — refusing to start inbound TLS");
        return null;
    };
    const cert_path = std.mem.sliceTo(cert_path_c, 0);
    const key_path = std.mem.sliceTo(key_path_c, 0);

    const cert_pem = try std.Io.Dir.cwd().readFileAlloc(io, cert_path, allocator, .limited(256 * 1024));
    defer allocator.free(cert_pem);
    const key_pem = try std.Io.Dir.cwd().readFileAlloc(io, key_path, allocator, .limited(256 * 1024));
    defer allocator.free(key_pem);

    const ptr = try allocator.create(core.tls.ianic_inbound.IanicInboundBackend);
    errdefer allocator.destroy(ptr);
    ptr.* = try core.tls.ianic_inbound.IanicInboundBackend.init(allocator, io, cert_pem, key_pem);
    holder.backend = ptr;
    holder.allocator = allocator;
    log_ptr.info("boot", "inbound TLS backend initialised (IanicInboundBackend, pure-Zig TLS 1.3)");
    return ptr.backend();
}

/// Shutdown phase: drain the log ring before we close storage. Wired
/// here so the phase order is owned by the composition root.
fn flushLogsPhase(ud: ?*anyopaque) anyerror!void {
    const log_ptr: *core.log.Log = @ptrCast(@alignCast(ud.?));
    try core.log.flushToStderr(log_ptr);
}

/// Shutdown phase: signal the AP outbox worker to drain before we
/// close storage.
fn flushApOutboxPhase(_: ?*anyopaque) anyerror!void {
    activitypub.state.get().outbox.signalStop();
}

// ── Federation hook trampolines ───────────────────────────────────────
// The existing hook ABIs (`FetchHookFn`, `DeliverFn`, `HttpFetcher`) do
// not carry a closure pointer. We bind module-level state via
// `activitypub.attachHttpClient` / `atproto.attachHttpClient` at boot,
// and these trampolines read it back.

fn apKeyFetchClosure(key_id: []const u8, out_pem: []u8) core.errors.FedError!usize {
    const client = activitypub.state.get().http_client orelse return error.KeyFetchFailed;
    return activitypub.key_fetcher_http.httpFetch(client, key_id, out_pem);
}

fn apDeliveryClosure(
    target_inbox: []const u8,
    payload: []const u8,
    key_id: []const u8,
) activitypub.outbox_worker.DeliveryResult {
    const st = activitypub.state.get();
    const client = st.http_client orelse return .transient_failure;
    const db = st.db orelse return .transient_failure;
    return activitypub.http_delivery.deliver(
        client,
        db,
        st.clock.wallUnix(),
        target_inbox,
        payload,
        key_id,
    );
}

fn atDidFetchClosure(url: []const u8, out: []u8) core.errors.AtpError!usize {
    const client = atproto.state.get().http_client orelse return error.NotImplemented;
    var resp_storage: core.http_client.Response = .{ .status = 0 };
    const resp = &resp_storage;
    const req: core.http_client.Request = .{
        .method = .get,
        .url = url,
        .headers = &[_]core.http_client.Header{
            .{ .name = "Accept", .value = "application/did+ld+json, application/json" },
        },
        .body = "",
        .timeout_ms = 15_000,
    };
    client.sendSync(req, resp) catch return error.NotImplemented;
    if (resp.status < 200 or resp.status >= 300) return error.NotImplemented;
    const body = resp.body();
    const n = @min(body.len, out.len);
    @memcpy(out[0..n], body[0..n]);
    return n;
}

pub fn main() !void {
    // F3: optional config file. Loaded FIRST so existing env-driven
    // boot logic picks up file-supplied values; pre-existing env
    // vars override the file (file is the floor).
    if (std.c.getenv("CONFIG_PATH")) |env_c| {
        const path = std.mem.sliceTo(env_c, 0);
        if (path.len > 0) {
            core.config.loadFromFile(path) catch |err| {
                std.debug.print("config: failed to load {s}: {s}\n", .{ path, @errorName(err) });
            };
        }
    }

    // GPA only exists during boot, for the big static pool allocation.
    // After `serve()` starts, no further allocations occur on the hot
    // path. We do not pass `allocator` past this function.
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const gpa_allocator = gpa.allocator();

    // Wrap the GPA in a TigerBeetle StaticAllocator. While in `.init`
    // state, allocations pass through. After the boot sequence we flip
    // to `.static`, after which any allocation panics — guaranteeing
    // the hot path is allocation-free. The wrapper is heap-allocated so
    // its address (used as the vtable `ptr`) is stable across the boot
    // function frame.
    const static_alloc = try gpa_allocator.create(core.alloc.StaticAllocator);
    defer gpa_allocator.destroy(static_alloc);
    static_alloc.* = core.alloc.StaticAllocator.init(gpa_allocator);
    defer static_alloc.deinit();
    const allocator = static_alloc.allocator();

    // Threaded Io backend. In Phase 6 we'll swap in a simulation backing
    // for deterministic replay tests.
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Connection pool sits on the heap (too big for the stack) but is
    // created once and never resized.
    const pool = try allocator.create(StaticPool(Connection, limits.max_connections));
    defer allocator.destroy(pool);
    pool.initInPlace();

    var real_clock = try core.clock.RealClock.init();
    var rng = core.rng.Rng.initFromOs();

    // ── Observability (Phase 7) ────────────────────────────────────
    // Heap-allocate the log so its ~2 MiB ring isn't on the stack.
    const log_ptr = try allocator.create(core.log.Log);
    defer allocator.destroy(log_ptr);
    log_ptr.* = core.log.Log.init(real_clock.clock());
    // E4: expose globally so core.server can emit access-log lines
    // without threading the pointer through every layer.
    core.log.setGlobal(log_ptr);

    // Seed + build hash + start time go in as the first entries.
    {
        var seed_buf: [32]u8 = undefined;
        const seed_str = std.fmt.bufPrint(&seed_buf, "0x{x}", .{rng.seed}) catch unreachable;
        var ts_buf: [32]u8 = undefined;
        const ts_str = std.fmt.bufPrint(&ts_buf, "{d}", .{real_clock.clock().wallUnix()}) catch unreachable;
        log_ptr.record(.info, "boot", "starting", &.{
            .{ .k = "seed", .v = seed_str },
            .{ .k = "start_unix", .v = ts_str },
        });
    }

    var drainer = core.log.Drainer.init(log_ptr, 100 * std.time.ns_per_ms);
    try drainer.start();
    defer drainer.stopAndJoin();

    var shutdown = core.shutdown.Shutdown.init();
    try core.shutdown.installSignalHandlers(&shutdown);
    defer core.shutdown.uninstallSignalHandlers();

    var health = core.health.Health.init(&shutdown);
    try health.addHook("process", alwaysReadyHook, null);
    // F2 deep-check hooks added AFTER the subsystems they probe boot.
    // (See registrations further down in main once `channel`, etc.
    // exist.)

    // Register the shutdown phases in canonical order. Server stop is
    // wired below once `server` exists.
    try shutdown.addPhase("flush_logs", flushLogsPhase, log_ptr);

    // ── storage subsystem ──────────────────────────────────────────
    // Open the SQLite writer connection + spin up the writer thread.
    // Plugins push queries onto `channel`; the writer drains them.
    const db_path: [:0]const u8 = "./speedy_socials.db";
    const db = try core.storage.sqlite.openWriter(db_path);
    defer core.storage.sqlite.closeDb(db);

    var stmt_table = core.storage.StmtTable.init();
    defer stmt_table.finalizeAll();

    var channel = core.storage.Channel.init();
    var writer = core.storage.Writer.init(db, &stmt_table, &channel);

    var handle = core.storage.Handle.init(&channel, &stmt_table);

    var ctx: core.plugin.Context = .{
        .clock = real_clock.clock(),
        .rng = &rng,
        .storage = &handle,
        .userdata = &health,
    };

    // Register plugins. New protocol → new entry here. Core unchanged.
    var registry = core.plugin.Registry.init();
    _ = try registry.register(echo.plugin);
    _ = try registry.register(atproto.plugin);
    _ = try registry.register(activitypub.plugin);
    _ = try registry.register(mastodon.plugin);
    // AP-27: advertise atproto in NodeInfo metadata so peers discover
    // the dual-protocol surface. Set after both plugins are registered
    // (order matters only conceptually; the AP NodeInfo handler reads
    // this on each request).
    activitypub.state.setAdvertiseAtproto(true);
    // Op-A: wire the relay's record-change hook so AT deletes /
    // updates emit AP Delete / Update activities.
    atproto.repo.setChangeHook(relay.at_to_ap_changes.onChange);
    // Relay registers AFTER its siblings — its `init` calls
    // `Registry.find` for "atproto" and "activitypub" (the sole
    // sibling-lookup carve-out; see src/protocols/relay/plugin.zig).
    _ = try registry.register(relay.plugin);
    _ = try registry.register(media.plugin);

    // Hand the relay the registry pointer so it can do its one-time
    // sibling lookup during `initAll`.
    relay.attachRegistry(&registry);

    // INFRA-1/2/3/5: wire pluggable backends with safe defaults.
    // Operators swap these out via env at boot.
    //   * Account store: SQLite-backed by DEFAULT (AT-8..AT-11 are
    //     durable — accounts survive restart). `ACCOUNT_BACKEND=memory`
    //     selects the ephemeral in-process backend for tests / throwaway
    //     dev nodes.
    //   * Email sender: LogSink by default; flip to webhook when
    //     `EMAIL_WEBHOOK_URL` is set.
    //   * Blob store: FsStore rooted at `MEDIA_ROOT` (existing var).
    //   * Secrets: FileStore rooted at `SECRETS_DIR` if set.
    var account_backend_mem = core.account.MemoryBackend.init();
    var account_backend_sqlite = core.account.SqliteBackend.init(db);
    const use_memory_accounts = blk: {
        if (std.c.getenv("ACCOUNT_BACKEND")) |envp| {
            break :blk std.mem.eql(u8, std.mem.sliceTo(envp, 0), "memory");
        }
        break :blk false;
    };
    if (use_memory_accounts) {
        core.account.setGlobal(account_backend_mem.backend());
        log_ptr.warn("boot", "account backend: in-memory (EPHEMERAL — accounts do NOT survive restart; ACCOUNT_BACKEND=memory)");
    } else {
        core.account.setGlobal(account_backend_sqlite.backend());
        log_ptr.info("boot", "account backend: sqlite (durable)");
    }
    defer core.account.resetGlobal();

    var email_log = core.email.LogSink.init();
    core.email.setGlobal(email_log.sender());
    defer core.email.resetGlobal();

    // Blob backend wires up later in the boot sequence (after the
    // media plugin computes its MEDIA_ROOT). See `media.setMediaRoot`
    // below — the FsStore picks up the same root via `setBlobBackend`.
    defer core.blob.resetGlobal();

    if (std.c.getenv("SECRETS_DIR")) |sd_ptr| {
        const sd = std.mem.sliceTo(sd_ptr, 0);
        if (sd.len > 0) {
            const secrets_static = struct {
                var store: core.secrets.FileStore = undefined;
            };
            secrets_static.store = core.secrets.FileStore.init(sd);
            core.secrets.setGlobal(secrets_static.store.store());
        }
    }
    defer core.secrets.resetGlobal();

    try registry.initAll(&ctx);
    defer registry.deinitAll(&ctx);

    // ── schema migrations ──────────────────────────────────────────
    var schema = core.storage.Schema.init();
    try schema.register(core.storage.bootstrap_migration);
    try schema.register(core.audit.audit_migration);
    // DUAL-1: cross-protocol identity-map schema lives at core so
    // both AP and AT plugins can read/write it.
    try schema.register(core.dual_identity.migration);
    // AT-8..11: durable account tables (atp_accounts / email tokens /
    // app passwords / invites) backing `core.account.SqliteBackend`.
    try schema.register(core.account.sqlite_migration);
    try registry.registerAllSchemas(&ctx, &schema);
    try schema.applyAll(db);

    // ── prepared statements + writer thread ────────────────────────
    try stmt_table.prepareAll(db);
    try writer.start();
    defer writer.stop();
    // F2: writer-channel health probe.
    try health.addHook("storage_writer", writerReadyHook, @ptrCast(&channel));

    // Relay's admin queries reuse the writer connection — they are
    // rare, admin-bound, and synchronous (good enough for Phase 5).
    relay.state.attachDb(db);

    // W5.1: spin the AT→AP firehose consumer. Registers an in-process
    // sink against `atproto.firehose.append` and drains a bounded
    // ring on a dedicated thread, calling `relay.handleFirehoseEvent`
    // on each record and appending to `relay_translation_log`. The
    // sink is unregistered + the worker joined on the `defer` below.
    // W6: load the synthetic-key pepper from env before any
    // synthetic actor is minted. A missing env value is a soft fail
    // — the dev-default pepper still works but logs a warning so
    // operators see it.
    if (std.c.getenv("RELAY_SYNTHETIC_KEY_PEPPER")) |pep_c| {
        const pep = std.mem.sliceTo(pep_c, 0);
        if (pep.len > 0) {
            relay.synthetic_keys.setPepper(pep);
            log_ptr.info("boot", "relay synthetic-key pepper loaded from RELAY_SYNTHETIC_KEY_PEPPER");
        }
    }
    if (relay.synthetic_keys.isDefaultPepper()) {
        log_ptr.warn("boot", "relay synthetic-key pepper is the development default — set RELAY_SYNTHETIC_KEY_PEPPER for production");
    }

    // W6: optional AT→AP bridge delivery target. When set, every
    // successful AT→AP translation enqueues an AP outbox row
    // addressed at this inbox URL.
    if (std.c.getenv("RELAY_BRIDGE_AP_TARGET")) |tgt_c| {
        const tgt = std.mem.sliceTo(tgt_c, 0);
        if (tgt.len > 0) {
            relay.firehose_consumer.setBridgeTargetInbox(tgt);
            log_ptr.info("boot", "relay AT→AP bridge target inbox configured");
        }
    }

    // B5: outbox-depth backpressure cap. When `ap_federation_outbox`
    // has more than this many pending rows the consumer pauses
    // translation. Default unset = disabled.
    if (std.c.getenv("RELAY_OUTBOX_BACKPRESSURE_CAP")) |cap_c| {
        const s = std.mem.sliceTo(cap_c, 0);
        if (std.fmt.parseInt(u64, s, 10)) |cap| {
            relay.firehose_consumer.setOutboxBackpressureCap(cap);
            log_ptr.info("boot", "relay consumer outbox backpressure cap configured");
        } else |_| {}
    }

    // D1/D2: open a *separate* sqlite connection for the firehose
    // consumer thread. Sqlite is opened with SQLITE_OPEN_NOMUTEX so
    // a single handle is not safe across threads; each long-lived
    // thread that touches the db needs its own handle. WAL mode +
    // busy_timeout makes the rare concurrent writes between this
    // thread and the HTTP handler thread cleanly serialize.
    const consumer_db = core.storage.sqlite.openWriter(db_path) catch |err| blk: {
        log_ptr.record(.warn, "boot", "relay consumer db open failed (using shared handle as fallback)", &.{
            .{ .k = "err", .v = @errorName(err) },
        });
        break :blk db;
    };
    const consumer_db_owned = consumer_db != db;
    defer if (consumer_db_owned) core.storage.sqlite.closeDb(consumer_db);

    _ = relay.firehose_consumer.start(gpa_allocator, consumer_db, real_clock.clock(), "speedy-socials.local") catch |err| blk: {
        log_ptr.record(.warn, "boot", "relay firehose consumer failed to start", &.{
            .{ .k = "err", .v = @errorName(err) },
        });
        break :blk null;
    };
    defer relay.firehose_consumer.stop(gpa_allocator);
    log_ptr.info("boot", "relay firehose consumer started (dedicated db handle)");
    // F2: probe.
    try health.addHook("relay_firehose_consumer", relayConsumerReadyHook, null);

    // W5.2 + W6: install the relay's AP-inbox hook. Fires after
    // every accepted AP activity; the relay translates it into a
    // committed atp_records row + ap_to_at translation-log entry.
    relay.ap_to_at.setRelayHost("speedy-socials.local");
    activitypub.inbox.setRelayInboxHook(relay.ap_to_at.onActivityReceived);
    log_ptr.info("boot", "relay ap-to-at hook wired");

    // ── ActivityPub worker pool + state wiring (Phase 3b) ──────────
    const ap_workers = try allocator.create(activitypub.state.PoolType);
    defer allocator.destroy(ap_workers);
    ap_workers.initInPlace();
    try ap_workers.start();
    defer ap_workers.stop();

    activitypub.attachDb(db);
    activitypub.attachWorkers(ap_workers);
    activitypub.setHostname("speedy-socials.local");

    // Wire the RSA verify hook so ActivityPub HTTP signatures with
    // `alg=rsa-sha256` actually verify (Mastodon's default).
    activitypub.keys.setRsaVerifyHook(core.crypto.rsa.verifyPkcs1v15Sha256);
    log_ptr.info("boot", "rsa verify hook wired (core.crypto.rsa.verifyPkcs1v15Sha256)");

    // G4: STRICT_HTTP_SIG=1 makes the AP inbox reject unverified
    // activities. Default soft acceptance matches the historic
    // behaviour; production deployments that federate with
    // strict-verifying peers should set this.
    if (std.c.getenv("STRICT_HTTP_SIG")) |envp| {
        const v = std.mem.sliceTo(envp, 0);
        if (v.len > 0 and (v[0] == '1' or v[0] == 't' or v[0] == 'T')) {
            activitypub.state.setStrictHttpSig(true);
            log_ptr.info("boot", "AP inbox strict HTTP-signature mode enabled");
        }
    }

    // AP-9: outbound HTTP-signature scheme. Default cavage (fediverse
    // majority); `AP_OUTBOUND_SIG=rfc9421` makes `http_delivery.deliver`
    // emit RFC 9421 `Signature-Input` + `Signature` + `Content-Digest`.
    if (std.c.getenv("AP_OUTBOUND_SIG")) |envp| {
        const v = std.mem.sliceTo(envp, 0);
        if (std.mem.eql(u8, v, "rfc9421")) {
            activitypub.state.setOutboundSigScheme(.rfc9421);
            log_ptr.info("boot", "AP outbound signatures: RFC 9421 (AP_OUTBOUND_SIG=rfc9421)");
        }
    }

    // Build the outbound HTTPS client. It shares a dedicated 4-thread
    // pool so federation fetches don't contend with inbox workers.
    // Until a TLS backend is wired in, `https://` requests fail with
    // `error.TlsUnavailable`; plaintext `http://` works in full.
    const http_workers = try allocator.create(core.workers.Pool(4));
    defer allocator.destroy(http_workers);
    http_workers.initInPlace();
    try http_workers.start();
    defer http_workers.stop();

    var http_client = core.http_client.Client.init(io);
    _ = &http_client;

    // Wire the native outbound TLS backend (Zig 0.16 std.crypto.tls).
    // Server-side TLS is not implemented in 0.16 stdlib; see
    // `src/core/tls/README.md` for the BoringSSL follow-up.
    var tls_backend_state = try core.tls.native_outbound.NativeOutboundBackend.init(allocator, io);
    defer tls_backend_state.deinit();
    core.http_client.setTlsBackend(tls_backend_state.backend());
    log_ptr.info("boot", "tls backend wired (native outbound)");

    // Bind the HTTP client to the protocol plugins so their federation
    // hook trampolines can find it. After this, AP key fetches +
    // outbox deliveries and AT DID resolutions hit the wire for real.
    activitypub.attachHttpClient(&http_client);
    atproto.attachHttpClient(&http_client);
    activitypub.key_cache.setFetchHook(apKeyFetchClosure);
    activitypub.outbox_worker.setDeliverHook(apDeliveryClosure);
    atproto.did_resolver.setFetcher(atDidFetchClosure);

    log_ptr.info("boot", "outbound http client + worker pool ready");

    // Argon2id needs an allocator + io for password hash/verify. We
    // configure them here, before the static allocator transitions to
    // its locked mode. Password operations only run on the rare login
    // path; they intentionally borrow the GPA-backed allocator (the
    // hot per-request path remains alloc-free).
    core.crypto.argon2id.configure(gpa_allocator, io);
    log_ptr.info("boot", "argon2id configured (gpa + io)");

    // ── Mastodon plugin wiring (W1.3) ─────────────────────────────
    mastodon.attachDb(db);
    mastodon.setHostname("speedy-socials.local");

    // Start the AP outbox worker by re-running init paths now that the
    // db is attached. The plugin's init has already run with db=null;
    // since the worker thread is idempotent we kick it now.
    {
        const st = activitypub.state.get();
        if (!st.outbox.running.load(.acquire)) {
            st.outbox.start(db, real_clock.clock(), &rng) catch {};
        }
    }

    try shutdown.addPhase("flush_ap_outbox", flushApOutboxPhase, null);
    // F2: probe the outbox worker.
    try health.addHook("ap_outbox_worker", apOutboxReadyHook, null);

    // ── AT Protocol PDS wiring (Phase 4b) ──────────────────────────
    var atp_workers: core.workers.Pool(8) = undefined;
    atp_workers.initInPlace();
    try atp_workers.start();
    defer atp_workers.stop();

    atproto.attachDb(db);
    atproto.attachWorkers(&atp_workers);

    // AT-24: optional periodic blob-GC worker. Off unless
    // BLOB_GC_INTERVAL_SECS is set. Uses its own sqlite handle (NOMUTEX
    // → one handle per long-lived thread), same pattern as the firehose
    // consumer above.
    var blob_gc_worker: ?*atproto.blob_gc.Worker = null;
    if (std.c.getenv("BLOB_GC_INTERVAL_SECS")) |envp| {
        const s = std.mem.sliceTo(envp, 0);
        if (std.fmt.parseInt(i64, s, 10)) |interval| {
            if (interval > 0) {
                if (core.storage.sqlite.openWriter(db_path)) |gdb| {
                    const w = allocator.create(atproto.blob_gc.Worker) catch unreachable;
                    w.* = .{ .db = gdb, .clock = real_clock.clock(), .interval_seconds = interval };
                    w.start() catch {};
                    blob_gc_worker = w;
                    log_ptr.info("boot", "blob GC worker started");
                } else |_| {}
            }
        } else |_| {}
    }
    defer if (blob_gc_worker) |w| {
        w.stop();
        core.storage.sqlite.closeDb(w.db);
        allocator.destroy(w);
    };

    // DUAL-1: unified signup. When the AT plugin's `createAccount` mints
    // a local account it also provisions the matching AP actor (user row
    // + Ed25519 key) via this hook, and binds the two in the
    // cross-protocol identity map — one signup, both networks.
    atproto.setApProvisionHook(activitypub.provisionLocalUser);
    log_ptr.info("boot", "unified signup wired (AT createAccount → AP actor provisioning)");

    // ── Media plugin wiring (W1.4 + W5.5 filesystem spillover) ────
    media.attachDb(db);
    media.setBaseUrl("http://127.0.0.1:8080");
    // L1/F6: MEDIA_ROOT env (default `./media`). Container deployments
    // mount a volume here so blobs survive restarts.
    const media_root_buf_static = struct {
        var buf: [512]u8 = undefined;
        var len: usize = 0;
    };
    const media_root: []const u8 = blk: {
        if (std.c.getenv("MEDIA_ROOT")) |envp| {
            const s = std.mem.sliceTo(envp, 0);
            if (s.len > 0 and s.len < media_root_buf_static.buf.len) {
                @memcpy(media_root_buf_static.buf[0..s.len], s);
                media_root_buf_static.len = s.len;
                break :blk media_root_buf_static.buf[0..s.len];
            }
        }
        const default_path = "./media";
        @memcpy(media_root_buf_static.buf[0..default_path.len], default_path);
        media_root_buf_static.len = default_path.len;
        break :blk media_root_buf_static.buf[0..default_path.len];
    };
    media.setMediaRoot(media_root);
    // INFRA-3: wire the blob store now that MEDIA_ROOT is resolved.
    const blob_fs_static = struct {
        var store: core.blob.FsStore = undefined;
    };
    blob_fs_static.store = core.blob.FsStore.init(media_root);
    core.blob.setGlobal(blob_fs_static.store.store());
    // Best-effort mkdir so the spillover path has somewhere to land.
    // EEXIST is fine; other errors log a warning + leave the inline
    // path working.
    {
        var path_z_buf: [513]u8 = undefined;
        @memcpy(path_z_buf[0..media_root.len], media_root);
        path_z_buf[media_root.len] = 0;
        const path_z: [*:0]const u8 = @ptrCast(&path_z_buf);
        const rc = std.c.mkdir(path_z, @as(std.c.mode_t, 0o755));
        if (rc != 0 and std.c._errno().* != 17) { // 17 = EEXIST on macOS+Linux
            log_ptr.warn("boot", "media root mkdir failed (filesystem spillover disabled)");
        }
    }
    log_ptr.info("boot", "media root configured");

    // ── HTTP server ────────────────────────────────────────────────
    var router = core.http.router.Router.init();
    // Health routes use plugin slot u16::MAX as a sentinel — they
    // don't belong to any registered plugin.
    try core.health.registerRoutes(&router, std.math.maxInt(u16));

    // E1/E2: initialise the global metrics registry + register
    // /metrics. Done before plugins so they can find the registry
    // ids if they want to register custom metrics.
    core.metrics.initGlobal();
    try core.metrics.registerMetricsRoute(&router, std.math.maxInt(u16));
    log_ptr.info("boot", "metrics registry initialised; /metrics serving");

    // G3: rate-limiting. Off by default; configured via env. Format:
    // RATE_LIMIT=<capacity>:<refill_per_sec>  (e.g. "60:30").
    if (std.c.getenv("RATE_LIMIT")) |env_c| {
        const spec = std.mem.sliceTo(env_c, 0);
        const colon = std.mem.indexOfScalar(u8, spec, ':') orelse 0;
        if (colon > 0 and colon < spec.len - 1) {
            const cap = std.fmt.parseInt(u32, spec[0..colon], 10) catch 0;
            const refill = std.fmt.parseInt(u32, spec[colon + 1 ..], 10) catch 0;
            if (cap > 0 and refill > 0) {
                core.rate_limit.configureGlobal(.{ .capacity = cap, .refill_per_sec = refill });
                log_ptr.info("boot", "rate limiter configured (per-IP token bucket)");
            }
        }
    }
    try registry.registerAllRoutes(&ctx, &router);

    // ── WebSocket subscription registry (W2.1) ─────────────────────
    // Shared across plugins that emit/consume real-time streams
    // (AT subscribeRepos, Mastodon streaming). Heap-allocated because
    // it carries a static pool sized for `max_subscriptions` slots.
    const ws_registry_ptr = try allocator.create(core.ws.registry.Registry);
    defer allocator.destroy(ws_registry_ptr);
    ws_registry_ptr.initInPlace();
    atproto.attachWsRegistry(ws_registry_ptr);
    mastodon.attachWsRegistry(ws_registry_ptr);

    // ── WebSocket upgrade router ───────────────────────────────────
    // Plugins that own a WS path (AT subscribeRepos, Mastodon
    // streaming, future bridges) register here. Frozen before the
    // server starts so the accept loop sees an immutable router.
    var ws_upgrade_router = core.ws.upgrade_router.WsUpgradeRouter.init();
    try registry.registerAllWsUpgrades(&ctx, &ws_upgrade_router);

    // ── Lock down the boot allocator ───────────────────────────────
    // From here on, the static allocator panics on any `alloc`/`resize`
    // call. The hot path is required to be allocation-free; this is the
    // tripwire that proves it. See `src/third_party/tigerbeetle/alloc/`.
    static_alloc.transition_from_init_to_static();
    log_ptr.info("boot", "static allocator transitioned: hot path is now alloc-free");
    // Flip back to `.deinit` at scope exit so all preceding
    // `defer allocator.destroy(...)` calls can free their slots. Defers
    // run LIFO, so registering this AFTER every destroy-defer means it
    // runs FIRST on the way out.
    defer static_alloc.transition_from_static_to_deinit();

    // ── Inbound TLS (W3.1) ─────────────────────────────────────────
    // Env-var driven: TLS_CERT_PATH + TLS_KEY_PATH must both be set to
    // turn on inbound TLS. When set, build a `BoringInboundBackend` and
    // install it on the server. When unset, fall through to plain HTTP
    // (the existing behaviour and the production-safe default for
    // deployments behind a terminating LB / sidecar).
    var inbound_tls_holder = InboundTlsHolder{};
    defer inbound_tls_holder.deinit();
    const inbound_tls_backend = try loadInboundTlsIfConfigured(&inbound_tls_holder, gpa_allocator, io, log_ptr);

    var server = try core.server.Server.init(
        .{
            .bind_addr = "127.0.0.1",
            .port = 8080,
            .tls = inbound_tls_backend,
        },
        io,
        &ctx,
        &router,
        &ws_upgrade_router,
        pool,
    );
    defer server.deinit();

    if (inbound_tls_backend == null) {
        log_ptr.info("boot", "listening on 127.0.0.1:8080 (plain HTTP — set TLS_CERT_PATH+TLS_KEY_PATH for HTTPS)");
    } else {
        log_ptr.info("boot", "listening on 127.0.0.1:8080 (HTTPS via system OpenSSL)");
    }

    // Run the server; on signal, the handler flips shutdown.requested
    // which Server.run() polls and drops out of accept loop.
    serve_loop: while (true) {
        server.run() catch |err| {
            log_ptr.record(.err, "server", "accept loop ended with error", &.{
                .{ .k = "err", .v = @errorName(err) },
            });
            break :serve_loop;
        };
        if (shutdown.isRequested()) {
            server.requestShutdown();
            break :serve_loop;
        }
        break :serve_loop;
    }

    log_ptr.info("shutdown", "running phases");
    // F1: SHUTDOWN_GRACE_MS (default 10s) is a soft budget. The
    // phases run to completion; a warning fires when they overrun.
    const grace_ms: u64 = blk: {
        if (std.c.getenv("SHUTDOWN_GRACE_MS")) |envp| {
            const s = std.mem.sliceTo(envp, 0);
            if (std.fmt.parseInt(u64, s, 10)) |n| {
                break :blk n;
            } else |_| {}
        }
        break :blk 10_000;
    };
    if (shutdown.runPhasesWithBudget(grace_ms)) |first_err| {
        log_ptr.record(.err, "shutdown", "phase reported error", &.{
            .{ .k = "err", .v = @errorName(first_err) },
        });
    }
}

test {
    _ = echo;
    _ = atproto;
    _ = activitypub;
    _ = mastodon;
    _ = relay;
    _ = media;
}
