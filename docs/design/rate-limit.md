# Rate limiting (INFRA-4)

`core.rate_limit` is the inbound request limiter. It is already a
swappable seam — this document surfaces it so the swap is discoverable.

## Today: in-process per-IP token bucket

`core.rate_limit.Limiter` is a fixed-size (4096-slot) table of token
buckets keyed by client IP, LRU-evicting on overflow. It is wired into
`core/server.zig` *before* route dispatch; over-limit requests get a
`429 Too Many Requests`.

Configuration is via the `RATE_LIMIT=<capacity>:<refill_per_sec>`
environment variable (e.g. `RATE_LIMIT=60:30` → burst 60, refill 30/s).
Unset = disabled (the production-safe default behind a trusted LB).

The bucket math (`allow(key, now_ns)`) is pure and clock-driven, so it is
deterministic under the simulation clock.

## Swapping in a shared (Redis-backed) limiter

The limiter is consulted through `core.rate_limit.global()`. A
distributed deployment that needs a *shared* limit across many process
replicas replaces the in-process table with a backend that talks to a
shared store (e.g. Redis `INCR`+`EXPIRE`, or a token-bucket Lua script):

1. Implement the same surface as `Limiter` (`allow(key, now_ns) bool`,
   `configureGlobal(opts)`).
2. Point `global()` at the shared implementation at boot.
3. Keep the per-process table as an L1 cache in front of the shared
   store to bound round-trips, if latency matters.

Per-route differential limits are a follow-up: today the limit is global.
The `Router.RouteMeta` extension (see PUNCHLIST G5) is the hook a
per-route policy would read.
