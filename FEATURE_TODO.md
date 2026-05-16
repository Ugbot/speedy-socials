# Feature Status — speedy-socials

_Last updated: 2026-05-16 (post-W3.2 audit). Reflects the Tiger-Style
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

## Open work

Real remaining gaps, ordered by impact.

- [ ] **HTTPS-fronted WebSocket data plane.** The WS *handshake* is
      routed through the TLS backend, but each handler's frame loop
      (`writeAll` / `pumpInbound` in `sync_firehose.zig` +
      `streaming_ws.zig`) reads + writes via the bare socket. Under
      HTTPS this means WSS connections work for the upgrade but
      garbage on app data. Mitigation today: terminate TLS at an LB
      and run WS over plain HTTP behind it. Production fix: add a
      `read_nonblock` hook to the TLS vtable + route the WS handlers
      through it.
- [ ] **Media filesystem spillover.** `src/protocols/media/routes.zig`
      rejects large blobs (>16 KiB inline cap) with 413 because the
      plugin `Context` doesn't carry an `std.Io.Dir` handle yet.
      Plumb Io through, then wire `storeBlobAt` to fall through to
      `media_root` for oversize uploads.
- [ ] **Multi-SNI cert dispatch** on the inbound TLS backends.
      Single-cert deployments unaffected; needed before serving more
      than one hostname from one process.
- [ ] **Per-socket connect/read timeouts** for the outbound HTTP
      client. `timeout_ms` is plumbed but `std.Io.net` doesn't expose
      the underlying setsockopt portably yet. Track upstream Zig.
- [ ] **WS subscription registry backpressure policy** — currently
      drops oldest when a shard queue is full. Confirm with prod
      load shape before promising at-least-once semantics.
- [ ] **Request-body size cap** above the HTTP parser's hard limit
      (current cap is per-buffer, not per-endpoint).
- [ ] **Structured access log** — the ring log captures application
      events but not HTTP access lines.

---

_See [`README.md`](README.md) for the public-facing overview and the
[`docs/adr/`](docs/adr/) directory for the design records._
