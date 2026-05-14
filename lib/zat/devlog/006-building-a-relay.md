# building a relay in zig

the previous devlogs covered zat as a library — parsing, decoding, verifying. this one is about what happens when you point those primitives at the full network and try to keep up. [zlay](https://tangled.org/zzstoatzz.io/zlay) is an AT Protocol relay written in zig, running at `zlay.waow.tech`, serving ~2,750 PDS hosts with ~6,000 lines of code.

## why build another relay

there are already working relay implementations — bluesky's reference [indigo](https://github.com/bluesky-social/indigo) in Go and [rsky](https://github.com/blacksky-algorithms/rsky) (by Rudy Fraser / BlackSky) in Rust. but running indigo taught me things about the protocol that reading the spec didn't:

- how identity resolution interacts with event ordering under load
- what happens when 2,750 PDS hosts each send 100ms of silence between bursts
- where the actual bottlenecks are (spoiler: not parsing)

building another implementation from zat's primitives — CBOR, CAR, signatures, DID resolution — was the fastest way to verify the library works at scale, and to understand the design space.

## architecture

zlay crawls PDS hosts directly. there's no fan-out relay in between. the bootstrap relay (bsky.network) is called once at startup to get the host list via `listHosts`, then all data flows directly from each PDS.

```
PDS hosts (2,750)
  ↓ one OS thread each
[subscriber] → decode frame → validate signature → [broadcaster]
                                    ↓                      ↓
                          [validator cache]         downstream consumers
                          [collection index]           (WebSocket)
                          [disk persist]
```

the key modules:

- **subscriber** — one thread per PDS, WebSocket connection with auto-reconnect and exponential backoff. decodes firehose frames using zat's CBOR codec, extracts ops from commits.
- **validator** — signing key cache + 4 background resolver threads. on cache miss, the frame passes through unvalidated and the DID is queued for resolution. subsequent commits from the same account are verified.
- **broadcaster** — lock-free fan-out to downstream consumers. ref-counted shared frames (one copy, N consumers). ring buffer of 50k frames for cursor replay.
- **collection index** — RocksDB with two column families (`rbc` for collection→DID, `cbr` for DID→collection). indexes live commits inline, no separate process.
- **event log** — postgres for account state, cursor tracking, host management. disk persistence for event replay.

### design choices that differ from indigo

**optimistic validation.** indigo blocks on DID resolution — every event waits for the signing key before proceeding. zlay passes frames through on cache miss and resolves in the background. first commit from an unknown account is unvalidated; everything after is verified. in practice, >99.9% of frames hit the cache after the first few minutes.

**inline collection index.** indigo runs [collectiondir](https://github.com/bluesky-social/indigo/tree/main/cmd/collectiondir) as a sidecar — a separate process that subscribes to the relay's localhost firehose and maintains a pebble KV store. zlay indexes directly in its event processing pipeline. one process, one deployment, one thing to monitor.

**OS threads, not goroutines.** one thread per PDS host. predictable memory, no GC pauses, but thread count scales linearly. 2,750 threads is fine — most are blocked on WebSocket reads. per-thread RSS is modest (stack pages on demand, ~1-2 MiB when active).

**single port.** everything — WebSocket firehose, HTTP API, admin endpoints — on port 3000. a second port (3001) serves only prometheus metrics. indigo does the same: 2470 for everything, 2471 for metrics. this required patching the websocket.zig fork to support HTTP fallback — when a non-WebSocket request arrives, the handshake parser routes it to an HTTP handler instead of returning an error.

## deployment war stories

### the musl saga

first deploy: alpine linux container, default zig target. relay starts, connects to PDS hosts, processes a few hundred events, then `SIGILL` — illegal instruction in RocksDB's LRU cache.

the cause: zig 0.15's C++ code generator for musl targets emits instructions that don't exist on baseline x86_64. RocksDB is C++ linked via rocksdb-zig, and the LRU cache's `std::function` vtable dispatch was the casualty.

fix chain:
1. `-Dcpu=baseline` — force baseline instruction set. helped, but musl's C++ ABI still had issues.
2. switch from alpine to debian bookworm-slim, `-Dtarget=x86_64-linux-gnu` — use glibc. this stuck.

the Dockerfile comment is a warning to future-me: "zig 0.15's C++ codegen for musl produces illegal instructions in RocksDB's LRU cache."

### TCP splits everything

behind traefik (k3s's ingress controller), POST endpoints would hang or return "invalid JSON." the issue: reverse proxies split HTTP headers and body across TCP segments.

the original code did one `stream.read()` and assumed the full request was in that buffer. traefik sent headers in frame 1, body in frame 2. the JSON parser got an empty body.

same class of bug in the WebSocket handshake — karlseguin's websocket.zig assumed the HTTP upgrade response arrived in one TCP segment. behind a TLS-terminating proxy, it doesn't. had to fork the library to buffer full lines before parsing.

lesson: if there's a reverse proxy between you and the client, TCP will split your data at the worst possible boundary.

### RocksDB iterator lifetimes

rocksdb-zig returns `Data` structs with a `rocksdb_free` finalizer. natural instinct: call `.deinit()` when done. but iterator entries are views into rocksdb's internal snapshot buffers — calling `.deinit()` on them double-frees and triggers `SIGABRT`.

separately: rocksdb-zig passes the database path pointer directly to the C API. if the path isn't null-terminated (which zig slices generally aren't), rocksdb reads past the slice boundary. fix: always use `realpathAlloc`, which guarantees null termination.

both bugs were invisible in tests and only appeared under production load patterns.

### pg.zig doesn't coerce

the backfill status endpoint crashed on first request. postgres `COALESCE(SUM(imported_count), 0)` returns `numeric`, not `bigint`. Go's pq driver silently coerces. pg.zig panics. fix: explicit `::bigint` casts on every aggregate.

strictness has its benefits — you catch schema bugs earlier. but you pay for it in production when the schema is "correct" by postgres standards and wrong by your driver's standards.

## the collection index backfill

the collection index only knows about accounts that have posted since live indexing started. historical data — tens of millions of `(DID, collection)` pairs — needs to come from somewhere.

the backfiller discovers collections from two sources: [lexicon garden](https://lexicon.garden/llms.txt) (~700 NSIDs scraped from their llms.txt) and a RocksDB scan of collections already observed from the firehose. then it pages through `listReposByCollection` on bsky.network for each collection, adding DIDs to the index.

progress is tracked in postgres — cursor position and imported count per collection — so crashes resume where they left off. triggered via admin API, monitored via status endpoint.

first backfill run: 1,287 collections discovered. the small ones (niche lexicons, alt clients) complete in seconds. the big ones — `app.bsky.feed.like`, `app.bsky.feed.post`, `app.bsky.actor.profile` — each have 20-30M+ DIDs and take hours to page through at 1,000 per request with a 100ms pause between pages.

as of writing: backfill complete — 1,287 collections indexed, 61M DIDs imported.

## the build pipeline

zig cross-compilation from macOS to linux/amd64 via Docker is slow (QEMU emulation). the production server is already x86_64 linux. so the deploy recipe SSHs into the server, does a native `zig build`, builds a thin runtime image with `buildah`, imports it directly into k3s's containerd (no registry), and restarts the deployment. the whole cycle takes under a minute.

the runtime Dockerfile is five lines: debian base, ca-certificates, copy the binary, expose ports, entrypoint.

## numbers

| | indigo (Go) | zlay (zig) |
|---|---|---|
| dependencies | ~50 Go modules | 4 (zat, websocket, pg, rocksdb) |
| memory | ~6 GiB (GOMEMLIMIT) | ~2.9 GiB (~2,750 hosts) |
| collection index | sidecar process (pebble) | inline (RocksDB) |
| validation | blocking (DID resolution) | optimistic (pass-through on miss) |
| services to deploy | 2 (relay + collectiondir) | 1 |

the first measurement (1.8 GiB at 1,486 hosts) was misleading — memory climbed to 6.6 GiB as the relay connected to all ~2,750 hosts, approaching the 8 GiB OOM limit. two fixes brought it back down:

1. **thread stack sizes.** zig's default is 16 MB per thread. with ~2,750 subscriber threads that maps 44 GB of virtual memory. most threads just read WebSockets and decode CBOR — 2 MB is generous. all `Thread.spawn` calls now pass `.{ .stack_size = 2 * 1024 * 1024 }`.

2. **c_allocator instead of GeneralPurposeAllocator.** GPA is actually a debug allocator (renamed `DebugAllocator` in zig 0.15) — it tracks per-allocation metadata and never returns freed small allocations to the OS. since zlay links glibc, `std.heap.c_allocator` gives glibc malloc with per-thread arenas, `madvise`-based page return, and production-grade fragmentation mitigation.

## what zat exercises

zlay is the heaviest consumer of zat. every firehose frame exercises the CBOR codec. every commit exercises CAR parsing. every new account exercises DID resolution and key extraction. the collection index uses NSID validation. the backfill uses HTTP client patterns.

running at ~600 events/sec sustained, zat processes roughly 50M CBOR decodes per day. that's a different kind of test than unit vectors.

## spec compliance

after the memory fixes, the next pass was checking zlay against the actual lexicon definitions for what a relay should implement. three gaps:

1. **`getHostStatus` was missing.** the lexicon says "implemented by relays" — zlay had `listHosts` but not the single-host query. straightforward handler: look up host, count accounts, map internal status values to the lexicon's `hostStatus` enum.

2. **admin takedowns didn't emit `#account` events.** `/admin/repo/ban` zeroed payloads on disk but never told downstream consumers the account was taken down. the spec says a relay's own takedown should produce an `#account` event. fix: build a CBOR frame (`active: false, status: "takendown"`), persist it, broadcast it.

3. **DID migration was unvalidated.** when an account appeared from a different PDS host, zlay blindly updated the host_id. now it queues a migration check — the validator's background threads resolve the DID document, check `pdsEndpoint()`, and only update if the new host matches.

## what's next

the backfill is complete — 1,287 collections indexed, 61M DIDs. the next step is a correctness audit — diff `listReposByCollection` results across a sample of collections against bsky.network's collectiondir and verify the sets match.

longer term: full commit diff verification via MST inversion. zlay already handles `#sync` frames and validates signatures, but the inductive firehose check (`verifyCommitDiff`) isn't wired into the hot path yet. the primitives exist in zat — it's a throughput tradeoff.
