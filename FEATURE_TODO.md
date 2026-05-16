# Feature Status — speedy-socials

_Last updated: 2026-05-16 (post-W5 audit: relay bridge now live in both directions; media spillover wired). Reflects the Tiger-Style
rewrite under `src/core/`, `src/app/`, `src/protocols/`. See ADR-001 ..
ADR-004 in `docs/adr/` for context. Each line below was checked
against the actual source tree at this commit — if you spot drift,
fix it._

## Shipped

### Core runtime

- [x] Plugin contract (`src/core/plugin.zig`) — ABI v2: name, routes,
      `Registry`, shared `Context` (storage, clock, prng, metrics,
      shutdown).
- [x] Static-allocation runtime via TigerBeetle's `StaticAllocator`
      (vendored under `src/third_party/tigerbeetle/alloc/`).
- [x] Counting allocator wrapper for live-byte instrumentation.
- [x] Single-writer SQLite storage with prepared-statement cache.
- [x] Bounded worker pool (`src/core/workers.zig`).
- [x] HTTP/1.1 parser + request/response/router under `src/core/http/`.
- [x] WebSocket primitives: RFC 6455 handshake helpers, frame codec,
      sharded subscription registry under `src/core/ws/`.
- [x] Lossy ring log (`src/core/log.zig`).
- [x] Prometheus metrics exposition (`src/core/metrics.zig`).
- [x] `/healthz` + `/readyz` (`src/core/health.zig`).
- [x] Graceful shutdown coordinator (`src/core/shutdown.zig`).
- [x] Deterministic PRNG re-exported through `src/core/prng.zig`
      (Xoshiro256, Ratio, EnumWeightsType, Combination, Reservoir).
- [x] Intrusive collections: stack, list, queue (vendored from TB).
- [x] Local `Clock` vtable + `TimeSimClock` simulation adapter
      (`src/core/clock.zig`).
- [x] Simulation harness: `TimeSim` drift models, `SimIo` sector-level
      fault injection, `PacketSimulator` with exponential latency,
      Bernoulli loss, scripted partitions.
- [x] Fuzz seed parsing + distribution helpers
      (`src/core/testing/fuzz.zig`).

### Protocols

- [x] `echo` — reference plugin that proves the contract.
- [x] `activitypub`:
  - [x] Ed25519 HTTP Signatures (sign + verify), see ADR-001.
  - [x] Eight inbox state machines (`Follow`, `Accept`, `Reject`,
        `Undo Follow`, `Create Note`, `Announce`, `Like`, `Delete`).
  - [x] Outbox + delivery worker with retry/backoff queue.
  - [x] Collections (followers, following, outbox).
  - [x] NodeInfo discovery (`/.well-known/nodeinfo`,
        `/nodeinfo/2.0`).
  - [x] Key cache with `setFetchHook` seam.
- [x] `atproto`:
  - [x] CID v1 (dag-cbor, sha-256, base32).
  - [x] TID (Bluesky's monotonic ID format).
  - [x] dag-cbor encoder/decoder.
  - [x] MST (Merkle Search Tree) read + write.
  - [x] Repo persistence backed by single-writer SQLite.
  - [x] JWT auth (HS256) with session store.
  - [x] did:plc and did:web parsers.
  - [x] XRPC: `com.atproto.server.describeServer`,
        `com.atproto.server.createSession`, `com.atproto.repo.*`.
- [x] `relay` — AP↔AT bidirectional bridge, see ADR-002.

### Observability + ops

- [x] Prometheus `/metrics`.
- [x] Per-plugin metric namespaces.
- [x] Lossy ring log with structured fields.
- [x] Graceful shutdown on SIGINT/SIGTERM.
- [x] Bench harness for the storage layer (`bench/storage_bench.zig`).

### Tests + simulation

- [x] 422 test blocks at this commit.
- [x] `zig build sim` runs the federation scenario deterministically.
- [x] The same scenario runs under `zig build test` against
      `std.testing.allocator`.
- [x] Vendored TB `testing/` module's tests run as part of the suite.

## Recently shipped (W2.x / W3.x)

These were listed as stubs in earlier snapshots; they have all been
wired through to real implementations. Listed here to clear the
backlog of stale "stubbed" claims.

- [x] AP HTTP key fetcher (`key_cache.setFetchHook` → `apKeyFetchClosure`
      in `src/app/main.zig`).
- [x] AP federation delivery POST (`outbox_worker.setDeliverHook` →
      `apDeliveryClosure` → `activitypub.http_delivery.deliver`).
- [x] AP RSA-SHA256 *signature verify* (`keys.setRsaVerifyHook` →
      `core.crypto.rsa.verifyPkcs1v15Sha256`, pure-Zig via `std.crypto.Certificate.rsa`).
- [x] AP RSA-SHA256 *signing* via OpenSSL link
      (`core.crypto.rsa.signPkcs1v15Sha256` → outbound delivery).
- [x] AT DID resolver HTTP fetcher (`did_resolver.setFetcher` →
      `atDidFetchClosure`).
- [x] AT WS `subscribeRepos` firehose — handler in
      `src/protocols/atproto/sync_firehose.zig`, dispatched via
      `core.ws.upgrade_router`.
- [x] AT CAR file sync endpoints (`getRepo`, `getBlocks`,
      `getCheckout`) — CAR encoder/decoder in `src/protocols/atproto/car.zig`.
- [x] AT secp256k1 signing/verification (`core.crypto.secp256k1`).
- [x] AT Argon2id password hashing (`core.crypto.argon2id`, configured
      at boot with the GPA + Io).
- [x] AT ES256 DPoP (handled in `src/protocols/atproto/oauth_dpop.zig`;
      the only remaining `NotImplemented` is the optional alg path).
- [x] AT `com.atproto.identity.resolveHandle` (W3.2 follow-up: wired
      through the module-level DID resolver).
- [x] HTTP/1.1 keep-alive in `core/server.zig`.
- [x] Server-side WebSocket upgrade dispatch
      (`core.ws.upgrade_router` + `core/server.zig` integration).
- [x] Mastodon API v1 surface — instance, accounts, statuses,
      timelines, notifications, apps, OAuth2, streaming WS.
- [x] OAuth2 authorization server (auth code, password,
      client_credentials).
- [x] Media uploads + image thumbnails + blurhash; large-blob
      filesystem spillover is the only remaining gap (see below).
- [x] Federation E2E simulation against the real `outbox_worker`
      (`zig build sim`).
- [x] `bench/baseline.json` regression-guarded benches.
- [x] Un-gated TigerBeetle intrusive tests.
- [x] CI workflow template, Dockerfile, justfile (see `docs/ci/`).
- [x] TLS termination: outbound (`std.crypto.tls`, W2.4) +
      inbound (`ianic_inbound`, pure-Zig TLS 1.3, W3.2 — replaces the
      W3.1 OpenSSL-backed default; OpenSSL link retained narrowly for
      RSA signing).

## Recently shipped (W4 + W5)

- [x] **W4 infrastructure borrow.** Vendored TigerBeetle stdx —
      `BoundedArrayType`, `RingBufferType`, `IOPSType`, `BitSetType`
      — under `src/third_party/tigerbeetle/stdx/` with a thin local
      shim. Exposed as `core.stdx` for plugins.
- [x] **W5.1 AT→AP firehose consumer pipeline.** The relay's
      `firehose_consumer` thread subscribes to in-process AT firehose
      appends (new `firehose.registerLocalSink`), drains a bounded
      `RingBufferType` of size 512 with a drop-oldest policy, and
      runs each newly-committed AT record through
      `relay.handleFirehoseEvent`. Translation log accumulates
      `at_to_ap` entries.
- [x] **W5.2 AP→AT inbox translation hook.** The AP inbox handler
      fires `inbox.setRelayInboxHook` (new) after every successful
      activity dispatch; the relay's `ap_to_at.onActivityReceived`
      translates the four load-bearing types (Create{Note}, Like,
      Announce, Follow) into AT-side log entries with synthetic
      did:web minted on first encounter.
- [x] **W5.3 deterministic cross-protocol simulation.**
      `tests/sim/relay_bridge_scenario.zig` drives both bridge
      directions under SimClock and asserts both `at_to_ap` and
      `ap_to_at` rows land in `relay_translation_log`.
- [x] **W5.5 media filesystem spillover.** Blobs above the
      `media_inline_threshold_bytes` (16 KiB) cap now spill to
      `<media_root>/<cid>` and the db row carries the existing
      `fs:<cid>` marker that `loadBlob` already understood. `getBlob`
      streams the file back (up to 4 MiB single-body response).
      Uses POSIX `open`/`read`/`write` directly to avoid plumbing
      `std.Io.Dir` through the plugin `Context`.

## Open work

Real remaining gaps, ordered by impact.

- [ ] **HTTPS-fronted WebSocket data plane.** The WS *handshake* is
      routed through the TLS backend (W3.2 ianic_inbound), but each
      handler's frame loop (`writeAll` / `pumpInbound` in
      `sync_firehose.zig` + `streaming_ws.zig`) reads + writes via
      the bare socket. Under HTTPS this means WSS connections work
      for the upgrade but garbage on app data. **W5.4 investigation
      result:** ianic's blocking `Connection.read` pulls from an
      `Io.Reader` that returns `error.EndOfStream` on EAGAIN —
      mapping the existing MSG_PEEK + MSG_DONTWAIT pattern onto it
      requires either (a) extracting the cipher and using ianic's
      `nonblock.Connection`, (b) patching ianic to distinguish
      WouldBlock, or (c) buffering all ciphertext at the server
      level. **Mitigation today:** terminate TLS at an LB / sidecar
      and run WS over plain HTTP behind it.
- [ ] **Multi-SNI cert dispatch** on the inbound TLS backends. ianic
      parses the `server_name` extension on the *client* side but
      does not expose a cert-selector callback to the *server*. A
      future tranche either patches ianic or stages a small
      pre-handshake peek to surface SNI. Single-cert deployments
      unaffected.
- [ ] **AP federation delivery of translated activities.** The
      relay's AT→AP and AP→AT pipelines log translations but do not
      yet enqueue the resulting AP activities into the federation
      outbox — that needs a per-synthetic-actor signing key + a
      followers table. Translation log + sim scenarios are the
      verifiable evidence that translation is correct; delivery is a
      separately-scoped follow-up.
- [ ] **AT repo commit from AP→AT translation.** Mirror of the
      delivery gap: `ap_to_at.onActivityReceived` writes a log row
      but does not yet `atproto.repo.commit` the translated record,
      because the synthetic AT repos have no signing keys
      provisioned. Same follow-up as the AP delivery side.
- [ ] **Per-socket connect/read timeouts** for the outbound HTTP
      client. `timeout_ms` is plumbed but `std.Io.net` doesn't expose
      the underlying setsockopt portably yet. Track upstream Zig.
- [ ] **WS subscription registry backpressure policy** — currently
      drops oldest when a shard queue is full. Same policy applies
      to the relay firehose consumer's ring. Confirm with prod load
      shape before promising at-least-once semantics.
- [ ] **Multi-level storage migration.** TickStream's
      `fixed_multilevel.zig` + `disk_writer.zig` would replace the
      single-writer SQLite hot path for the AT firehose. Sketched
      in `docs/design/`; out of scope for W4/W5.
- [ ] **Multi-tenant isolation** — per-vhost plugin Registry shards.
      Deferred.
- [ ] **AT firehose cursor persistence + reconnection** for the case
      where speedy-socials runs as a downstream subscriber to an
      external relay (distinct from W5.1, which subscribes to the
      local firehose in-process).
- [ ] **`trace.zig` Chrome-format tracing.** Originally on the W4
      list; TB's `trace.zig` transitively pulls in its own IO/Time/
      StatsD/event types — too much glue for W4. Either a dedicated
      vendor tranche or a thin in-tree shim.
- [ ] **Request-body size cap** above the HTTP parser's hard limit
      (current cap is per-buffer, not per-endpoint).
- [ ] **Structured access log** — the ring log captures application
      events but not HTTP access lines.

---

_See [`README.md`](README.md) for the public-facing overview and the
[`docs/adr/`](docs/adr/) directory for the design records._
