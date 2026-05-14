# Feature Status — speedy-socials

_Last updated: 2026-05-14. Reflects the Tiger-Style rewrite under
`src/core/`, `src/app/`, `src/protocols/`. See ADR-001 .. ADR-004 in
`docs/adr/` for context. This file is a snapshot at this commit;
other open work-tranches (W1.1 .. W1.5) flip items from `stubbed` to
shipped as they land._

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

## Stubbed (function-pointer seams ready, real impl pending)

These are wired so tests and the simulation can inject deterministic
behaviour. The default implementations return errors so missing
production wiring is loud rather than silent.

- [ ] AP HTTP key fetcher — `key_cache.setFetchHook`; default returns
      `KeyFetchFailed` (W1.2).
- [ ] AP federation delivery POST — `outbox_worker.setDeliverHook`;
      default returns transient failure so the retry queue can be
      exercised in tests (W1.2).
- [ ] AP RSA-SHA256 signature verify — `keys.setRsaVerifyHook`;
      Ed25519 verifies natively, RSA bindings (BoringSSL) land in
      W1.2.
- [ ] AT DID resolver HTTP fetcher — parser is ready, HTTP fetch is
      W1.2.
- [ ] AT WS `subscribeRepos` (firehose) — frame codec is shipped;
      waiting on the server-side WS upgrade dispatch in W1.1.
- [ ] AT CAR file sync endpoints (`getRepo`, `getBlocks`,
      `getCheckout`) — XRPC routes scaffolded, CAR encoder/decoder is
      a follow-up.
- [ ] AT secp256k1 signing/verification (W1.2).
- [ ] AT Argon2id password hashing (W1.2).
- [ ] AT ES256 DPoP (W1.2).

## Planned

Larger surfaces that have not been started yet.

- [ ] TLS termination — required before federation can happen against
      real peers (W1.1).
- [ ] HTTP/1.1 keep-alive in `core/server.zig` (W1.1).
- [ ] Server-side WebSocket upgrade dispatch (W1.1).
- [ ] Mastodon API v1 surface (W1.3):
  - [ ] `/api/v1/instance`, `/api/v2/instance`
  - [ ] `/api/v1/accounts/*`, `/api/v1/statuses/*`
  - [ ] `/api/v1/timelines/{home,public,tag/:tag}`
  - [ ] `/api/v1/notifications`
  - [ ] `/api/v1/apps`, `/oauth/authorize`, `/oauth/token`
  - [ ] `/api/v1/streaming/*` over WebSocket
- [ ] OAuth2 authorization server (auth code, password,
      client_credentials) — bundled with W1.3.
- [ ] Media uploads + image thumbnails + blurhash (W1.4).
- [ ] Federation E2E simulation end-to-end against the real
      `outbox_worker` (W1.5).
- [ ] `bench/baseline.json` for regression-guarded benches (W1.5).
- [ ] Un-gate the vendored TB intrusive tests against `core.prng`
      (W1.5).
- [ ] CI workflow, Dockerfile, justfile (this tranche, W1.6).

## Issues + tech debt

- [ ] `core/server.zig` lacks HTTP/1.1 keep-alive — one request per
      TCP connection (fix in W1.1).
- [ ] No backpressure on the WS subscription registry's per-shard
      queues — bounded but currently drops oldest. Confirm policy.
- [ ] AP outbox retry queue uses a fixed exponential schedule; a
      jittered policy would smooth thundering-herd on recovery.
- [ ] No request-body size cap above the HTTP parser's hard limit.
- [ ] No structured access log — the ring log captures application
      events only.

---

_See [`README.md`](README.md) for the public-facing overview and the
[`docs/adr/`](docs/adr/) directory for the design records._
