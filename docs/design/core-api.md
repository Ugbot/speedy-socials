# `core/` public API reference (K4)

This page surveys every module re-exported from `src/core/root.zig`,
its public surface, and the seams plugins can swap. It's the
"what's there" companion to
[`pluggable-infra.md`](pluggable-infra.md), which goes deeper on the
backend interfaces.

_Last updated: 2026-05-20._

| Module | Lives in | Public surface |
|---|---|---|
| `core.limits` | `core/limits.zig` | Compile-time caps for buffers, headers, routes, log ring, scope/message lengths, etc. |
| `core.assert` | `core/assert.zig` | `assert`, `assertLe`, `unreachableState`, panic helpers. |
| `core.errors` | `core/errors.zig` | Cross-cutting error sets: `HttpError`, `RouterError`, `FedError`, `AtpError`, `StorageError`, `WsError`. |
| `core.alloc` | `core/alloc.zig` | `StaticAllocator` (TigerBeetle vendored) lifecycle helpers. |
| `core.static` | `core/static.zig` | `StaticPool(T, N)` — heap-free fixed slot pool. |
| `core.arena` | `core/arena.zig` | Per-request `Arena` allocator with bounded scratch. |
| `core.clock` | `core/clock.zig` | `Clock` vtable; `RealClock`, `SimClock`. |
| `core.rng` / `core.prng` | `core/rng.zig`, `core/prng.zig` | Deterministic PRNG re-exports of TB stdx + helpers. |
| `core.plugin` | `core/plugin.zig` | `Plugin`, `Registry`, `Context`. |
| `core.connection` | `core/connection.zig` | Per-connection state struct. |
| `core.server` | `core/server.zig` | Event loop entrypoint `serve` + accept loop. |
| `core.tls` | `core/tls.zig` | `TlsBackend` vtable; in-tree backends: `IanicInboundBackend`, `BoringInboundBackend`, `StubTlsBackend`. |
| `core.tls_cert_admin` | `core/tls/cert_admin.zig` | C2/C4/C5 — cert hot-reload, SNI cert table, outbound pin hook. |
| `core.storage` | `core/storage.zig` | `Channel`, `Schema`, `Migration`, `Handle`, `Backend` vtable + `SqliteBackend`. |
| `core.log` | `core/log.zig` | Lossy ring `Log`; `Log.record/info/warn/err`; `Drainer` thread. |
| `core.metrics` | `core/metrics.zig` | Prometheus-style `Counter`/`Gauge`/`Histogram`; `/metrics` route. |
| `core.shutdown` | `core/shutdown.zig` | Phase-ordered shutdown coordinator; `signalStop`, `runPhasesWithBudget`. |
| `core.health` | `core/health.zig` | `/healthz` + `/readyz` hook registry. |
| `core.workers` | `core/workers.zig` | Bounded worker pool for blocking jobs (DID fetch, RSA verify). |
| `core.intrusive` | `core/intrusive.zig` | TB intrusive list / stack / queue. |
| `core.sim` | `core/sim.zig` | `TimeSim`, `SimIo`, `PacketSimulator` for deterministic tests. |
| `core.http_client` | `core/http_client.zig` | Outbound HTTP/1.1 client with TLS pluggability. |
| `core.audit` | `core/audit.zig` | `core_audit_log` table writer for sensitive ops. |
| `core.rate_limit` | `core/rate_limit.zig` | Per-IP token bucket; `Limiter.allow`. |
| `core.config` | `core/config.zig` | JSON config-file loader (`CONFIG_PATH`). |
| `core.email` | `core/email.zig` | INFRA-2 — `Sender` vtable + LogSink / Webhook / Null / Mock impls. |
| `core.blob` | `core/blob.zig` | INFRA-3 — `Store` vtable + FsStore / MemoryStore. |
| `core.secrets` | `core/secrets.zig` | INFRA-5 — `Store` vtable + FileStore / MemoryStore. |
| `core.account` | `core/account.zig` | INFRA-1 (high-level) — `Backend` vtable + MemoryBackend. |
| `core.dns` | `core/dns.zig` | `lookupTxt` for DNS TXT records via libc `res_query`. |
| `core.dual_identity` | `core/dual_identity.zig` | DUAL-1 — `core_identity_map` writer + readers (AP actor ↔ AT DID). |
| `core.trace` | `core/trace.zig` | E3 — Chrome-format trace ring + `begin`/`end`/`flushTo`. |
| `core.cert_probe` | `core/cert_probe.zig` | F2 — PEM `notAfter` parser for /readyz cert-expiry checks. |
| `core.tenancy` | `core/tenancy.zig` | H1/H2/H3 — Host→tenant table, per-request current tenant, lifecycle states. |

## Crypto submodules

`core.crypto.*` (vendored to one audit point per algorithm):

- `core.crypto.ed25519` — Ed25519 sign/verify + key derivation.
- `core.crypto.secp256k1` — secp256k1 ECDSA-SHA256 with low-S.
- `core.crypto.p256` — NIST P-256 ECDSA-SHA256 with low-S (AT-25).
- `core.crypto.rsa` — RSA-PKCS1v15-SHA256 (OpenSSL-backed).
- `core.crypto.argon2id` — Argon2id PHC.
- `core.crypto.multibase` / `multicodec` — base32 + varint prefixes.
- `core.crypto.openssl` — libcrypto C-ABI wrapper.

## HTTP + WebSocket primitives

`core.http.{parser, request, response, response_stream, router}` —
HTTP/1.1 parser + `Router` (per-route `RouteMeta` via
`registerWithMeta` for G5 body-size caps).

`core.ws.{handshake, frame, messages, event_ring, registry,
upgrade_router}` — WebSocket RFC 6455 primitives + sharded
subscription registry.

## TigerBeetle re-exports

`core.stdx` — `BoundedArrayType`, `RingBufferType`, `IOPSType`,
`BitSetType`, vendored helpers.

## Conventions

- Every `pub fn` either has a doc comment or a name that obviously
  conveys its contract (`open`, `close`, `init`, `deinit`, getter
  names matching their field).
- Vtables follow the shape `{ ptr: *anyopaque, vtable: *const VTable }`,
  with `VTable` carrying function pointers. Concrete impls
  expose a method (`backend()` / `store()` / `sender()`) returning
  the vtable struct.
- Module-level singletons (`setGlobal`/`global`/`resetGlobal`) are
  used sparingly — only where a single shared instance is the right
  shape (account backend, email sender, blob store, secrets,
  replay cache).
- Error sets are typed per-subsystem in `core.errors`; cross-set
  conversion is explicit at the boundary.

## When you add a new module

1. Re-export from `core/root.zig`.
2. Add an entry to the table above.
3. If it's a vtable seam, also list it in
   [`pluggable-infra.md`](pluggable-infra.md).
4. If it touches storage, register its `Migration` from the
   composition root or the owning plugin's `register_schema`.

## HTTP client hook pattern (INFRA-7)

`core.http_client.Client` is the single outbound HTTP surface. Plugins
do **not** call it directly; they receive it through a hook (a function
pointer the composition root binds at boot), which keeps the plugin
testable with a stub and avoids threading the client pointer everywhere.

Examples wired in `app/main.zig`:

- **AP key fetch** — `activitypub.key_cache.setFetchHook(apKeyFetchClosure)`;
  the closure reads `activitypub.state.get().http_client` and calls
  `key_fetcher_http.httpFetch`.
- **AP federation delivery** —
  `activitypub.outbox_worker.setDeliverHook(apDeliveryClosure)`.
- **AT DID resolution** — `atproto.did_resolver.setFetcher(atDidFetchClosure)`.
- **PLC submit** (AT-19) reads `atproto.state.get().http_client` directly
  on the rare admin path.

To swap transport (e.g. a proxy, a recording client for tests, or an
mTLS variant), implement the same `Client.sendSync(req, *resp)` surface
and bind it via `atproto.attachHttpClient` / `activitypub.attachHttpClient`
before the hooks fire. TLS for `https://` URLs is itself pluggable via
`core.http_client.setTlsBackend` (see `core.tls`).
