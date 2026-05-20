# Pluggable infrastructure seams

speedy-socials exposes a small set of vtable-style backends so the
core protocol code stays agnostic about its dependencies. This doc
lists every seam, what it abstracts, the default implementation, and
how to swap it for production.

_Last updated: 2026-05-20._

| Seam | Module | Default | Swap point |
|---|---|---|---|
| Wall + monotonic clock | `core.clock.Clock` | `RealClock` | `SimClock` (tests), custom impl |
| Random number generator | `core.rng.Rng` | seeded Xoshiro256 | inject a different `*Rng` |
| TLS termination (inbound) | `core.tls.Backend` | `IanicInboundBackend` | `BoringInboundBackend`, `StubTlsBackend` |
| HTTP client (outbound) | `core.http_client.Client` | stdlib `std.crypto.tls` | swap via composition root |
| Storage | direct SQLite + `core.storage.Channel` | per-thread sqlite connections | see INFRA-1 (real Backend vtable still open) |
| Account lifecycle | `core.account.Backend` | `MemoryBackend` | SQLite-backed impl (sibling file follow-up) |
| Email sending | `core.email.Sender` | `LogSink` | `WebhookSender`, `NullSender`, `Mock` |
| Blob storage | `core.blob.Store` | `FsStore` at `MEDIA_ROOT` | `MemoryStore` (tests), future S3/GCS |
| Secret / key store | `core.secrets.Store` | `FileStore` at `SECRETS_DIR` (when set) | `MemoryStore` (tests), env-derived |
| DID resolution | `atproto.did_resolver.Fetcher` | wired to `core.http_client.Client` | inject a caching proxy / offline directory |
| AP key fetcher | `activitypub.key_cache.setFetchHook` | wired to `core.http_client.Client` | inject a caching proxy / mock |
| Rate limiter | `core.rate_limit.Limiter` | in-process token bucket | swap state struct for a Redis-backed impl |

---

## INFRA-4 — Rate limiter

The rate limiter is an in-process token bucket maintained in
`core.rate_limit.Limiter`. It's keyed by IP, sized at 4096 slots with
LRU eviction, and configured via the env var
`RATE_LIMIT=<capacity>:<refill_per_sec>` (off by default).

To swap for a distributed implementation:

1. Replace the inner data structure (`buckets`) with a thin wrapper
   around Redis `INCR`/`EXPIRE` calls.
2. Keep the same public method shape: `Limiter.allow(ip: []const u8,
   now_ns: u64) bool`. Callers in `core/server.zig` don't change.

Note: the existing limiter is per-process. A multi-replica deployment
will undercount by `replicas × capacity`. For now, run replicas
behind a layer 4 LB with sticky-IP routing; the distributed swap is
a follow-up.

## INFRA-6 — DID resolver

`atproto/did_resolver.zig` defines a `Fetcher` function pointer:

```zig
pub const HttpFetcher = struct {
    ptr: *anyopaque,
    fetch_fn: *const fn (ptr: *anyopaque, url: []const u8, out: []u8) FetchError![]const u8,
};
```

The module-level singleton is set via `did_resolver.setFetcher`. The
composition root wires `atDidFetchClosure` (in `src/app/main.zig`) at
boot, which delegates to the shared `core.http_client.Client`.

To swap for an alternative resolver (e.g., a caching proxy that
consults a local `did:plc` mirror first, or an offline directory for
tests):

```zig
const my_fetcher: did_resolver.HttpFetcher = .{
    .ptr = &my_state,
    .fetch_fn = myFetchImpl,
};
did_resolver.setFetcher(my_fetcher);
```

The resolver already wraps a 256-entry LRU cache (`LRU` struct in
the same file). External overrides typically replace the lower
`fetch_fn` path rather than the cache.

## INFRA-7 — HTTP client

`core/http_client.zig` exposes a thin wrapper over stdlib's
`std.crypto.tls` outbound connection path. Each plugin that needs
outbound HTTP attaches via a setter hook:

- `activitypub.key_cache.setFetchHook` — `apKeyFetchClosure`
- `atproto.did_resolver.setFetcher` — `atDidFetchClosure`
- `activitypub.outbox_worker.setDeliverHook` — `apDeliveryClosure`

To swap for a different HTTP backend (e.g., libcurl, an in-memory
mock, or a request-logging proxy for tests):

1. Implement the closure signature each hook expects.
2. Register your closure at boot via the corresponding `setXHook`.
3. Existing handlers keep calling `key_cache.resolve` / `did_resolver.resolveDid`
   etc. — they don't know about the swap.

This keeps the protocol code free of HTTP-client concerns and lets
tests inject deterministic responses without spinning up real
sockets. The `MockTlsBackend` (see `tls/test_mock_tls.zig`) is the
canonical example of an inbound test fixture; the outbound hooks
follow the same pattern in reverse.
