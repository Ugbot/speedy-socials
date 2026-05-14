# speedy-socials

A Tiger-Style ActivityPub + AT Protocol social server written in Zig
0.16. Runs as a single statically-linked binary. The HTTP/WS surface,
storage, worker pool, plugin contract, and federation primitives are
hand-written under `src/core/`; each wire protocol (ActivityPub, AT
Protocol, the AP↔AT relay, and the echo reference plugin) is a separate
plugin under `src/protocols/`. A Mastodon-compatible v1 API is being
layered on top.

This is a from-scratch rewrite under Tiger Style discipline (no
allocator on the hot path, bounded queues, asserted invariants, single
static allocator at startup). It is not a production-ready Mastodon
drop-in — see the status table below for what's actually shipping.

## Status

Legend: `shipping` = merged + tested, `stubbed` = function-pointer seam
in place but the real implementation is pending, `planned` = not yet
started.

| Area | Status | Notes |
|------|--------|-------|
| Plugin contract (ABI v2) | shipping | `src/core/plugin.zig`; echo plugin proves the contract |
| HTTP/1.1 server | shipping | request/response/router under `src/core/http/`; keep-alive pending (W1.1) |
| WebSocket primitives | shipping | RFC 6455 framing + sharded subscription registry under `src/core/ws/` |
| WebSocket upgrade dispatch | stubbed | server-side `Upgrade: websocket` plumbing is W1.1 |
| Single-writer SQLite storage | shipping | prepared-statement cache, single writer thread |
| Bounded worker pool | shipping | `src/core/workers.zig` |
| Static allocation runtime | shipping | TigerBeetle `StaticAllocator` vendored, see ADR-004 |
| Lossy ring log + Prometheus | shipping | `src/core/log.zig`, `src/core/metrics.zig` |
| Graceful shutdown + health | shipping | `src/core/shutdown.zig`, `src/core/health.zig` |
| Simulation harness | shipping | `TimeSim` drift, `SimIo` fault injection, `PacketSimulator` under `src/core/sim.zig` |
| ActivityPub inbox + delivery | shipping | 8 inbox state machines, outbox + delivery worker, collections, NodeInfo |
| ActivityPub Ed25519 signatures | shipping | native Zig Ed25519, see ADR-001 |
| ActivityPub HTTP key fetch | stubbed | `key_cache.setFetchHook`; default returns `KeyFetchFailed` (W1.2) |
| ActivityPub federation POST | stubbed | `outbox_worker.setDeliverHook`; default returns transient failure (W1.2) |
| ActivityPub RSA-SHA256 verify | stubbed | `keys.setRsaVerifyHook` seam; Ed25519 verifies natively (W1.2) |
| AT Protocol repo + records | shipping | CID/TID/dag-cbor/MST, repo persistence, JWT auth |
| AT Protocol XRPC | shipping | `describeServer`, `createSession`, `repo.*` |
| AT Protocol DID resolver | stubbed | did:plc/did:web parser ready; HTTP fetcher pending (W1.2) |
| AT Protocol firehose | stubbed | `subscribeRepos` waits on WS-upgrade dispatch (W1.1) |
| AT Protocol CAR sync | stubbed | endpoints stubbed; CAR encoder/decoder is a follow-up |
| AT Protocol secp256k1 / ES256 / Argon2id | stubbed | seams in place (W1.2) |
| AP↔AT relay | shipping | bidirectional translation, see ADR-002 |
| Mastodon API v1 | stubbed | full surface is W1.3 |
| Media uploads + blurhash | stubbed | W1.4 |
| Federation E2E simulation | stubbed | hooks wired against simulated transport; real-transport sim is W1.5 |
| TLS | planned | real federation needs HTTPS; W1.1 includes the BoringSSL link plan |
| OAuth2 server | planned | bundled with Mastodon API (W1.3) |

Test count at this commit: **422** test blocks across core, protocols,
and the simulation scenario. Run `zig build test --summary all` to
execute them.

## Architecture

```
.
├── src/
│   ├── app/
│   │   └── main.zig             # entry point; wires Registry + plugins
│   ├── core/                    # Tiger Style runtime
│   │   ├── root.zig             # public re-exports (alloc, sim, prng, …)
│   │   ├── server.zig           # TCP accept loop + connection lifecycle
│   │   ├── plugin.zig           # plugin contract (ABI v2)
│   │   ├── http/                # parser, request, response, router
│   │   ├── ws/                  # RFC 6455 framing + sharded sub registry
│   │   ├── storage/             # single-writer SQLite + prepared stmts
│   │   ├── workers.zig          # bounded worker pool
│   │   ├── metrics.zig          # Prometheus exposition
│   │   ├── health.zig           # /healthz, /readyz
│   │   ├── shutdown.zig         # graceful shutdown coordinator
│   │   ├── sim.zig              # TimeSim / SimIo / PacketSimulator
│   │   └── testing/             # fuzz helpers
│   ├── protocols/
│   │   ├── echo/                # reference plugin — read this first
│   │   ├── activitypub/         # AP: signatures, inbox, outbox, NodeInfo
│   │   ├── atproto/             # AT: CID/TID/dag-cbor/MST/JWT/XRPC
│   │   ├── relay/               # AP↔AT bidirectional bridge
│   │   ├── mastodon/            # Mastodon API v1 (W1.3, landing)
│   │   └── media/               # uploads + thumbnails (W1.4, landing)
│   └── third_party/
│       └── tigerbeetle/         # vendored TB primitives (Apache-2.0)
├── third_party/
│   └── zig-sqlite/              # vendored SQLite bindings
├── bench/                       # micro-benchmarks
├── tests/sim/                   # simulation scenarios
└── docs/adr/                    # design records (ADR-001 … ADR-004)
```

Read the ADRs under `docs/adr/` for the deep dives: 001 covers
Ed25519 HTTP signatures, 002 covers the AP↔AT relay, 003 explains why
the originally-vendored AT Protocol libraries were retired and
re-implemented, and 004 covers the TigerBeetle vendoring policy.

## Quick start

Requires Zig **0.16.0** or later.

```bash
# macOS
brew install zig

# or download from https://ziglang.org/download/

git clone https://github.com/bengamble/speedy-socials.git
cd speedy-socials
zig build run
```

The server binds to `127.0.0.1:8080` and creates `speedy_socials.db` on
first start.

```bash
# echo plugin — proves the plugin contract is wired
curl http://127.0.0.1:8080/echo

# health
curl http://127.0.0.1:8080/healthz

# NodeInfo discovery (ActivityPub)
curl http://127.0.0.1:8080/.well-known/nodeinfo

# Mastodon API v1 instance metadata (lands with W1.3)
curl http://127.0.0.1:8080/api/v1/instance
```

## Build targets

All exposed by `build.zig`:

| Target | Purpose |
|--------|---------|
| `zig build` | build the `speedy-socials` binary into `zig-out/bin/` |
| `zig build run` | build + run the server |
| `zig build test` | run all test blocks (core, plugins, sim scenario, vendored TB testing module) |
| `zig build sim` | run the federation simulation scenario as a standalone executable |
| `zig build bench-storage` | run the SQLite storage benchmark in `bench/storage_bench.zig` |

Add `--summary all` to the test step to see per-block pass counts.

## Project structure

- `src/core/` — the Tiger Style runtime. Everything in here is
  allocation-bounded, has explicit error sets, and asserts its
  invariants. Re-exports its public surface through `root.zig`.
- `src/protocols/` — one directory per wire protocol. Each exposes a
  `plugin.zig` that satisfies the contract in `core.plugin`. The
  contract is one paragraph: a plugin declares its name, owns its
  routes, registers HTTP/WS handlers via the `Registry`, and receives a
  shared `Context` (storage, metrics, clock, prng, shutdown). Plugins
  do not reach into each other — the relay is the only carve-out, and
  ADR-002 explains why.
- `src/app/main.zig` — wires the runtime: creates the registry,
  registers each plugin, then runs `core.server`.
- `bench/` — micro-benchmarks. Currently only the storage layer.
- `tests/sim/` — simulation scenarios that drive the system through
  `core.sim` (deterministic clock, deterministic I/O, scripted network
  partitions).
- `docs/adr/` — Architecture Decision Records.

## Testing

```bash
zig build test --summary all   # 422 test blocks at this commit
zig build sim                  # federation scenario, deterministic
zig build bench-storage        # storage micro-bench
```

The simulation scenario also runs under `zig build test` against
`std.testing.allocator` — leaks fail the build.

## Contributing

This codebase follows **Tiger Style**:

- No allocator on the hot path. Plan capacity at startup; pre-allocate
  inside `StaticAllocator`.
- Bounded everything: bounded queues, bounded retries, bounded
  buffers, bounded loops.
- Assert invariants — both pre- and post-conditions. Asserts are part
  of the design, not an afterthought.
- Single-writer SQLite. The writer thread owns the connection.
- Function-pointer seams for anything that needs to be swapped at
  runtime (key fetch, RSA verify, federation delivery). Default
  implementations return errors; tests and the real wiring install
  hooks.

To add a new protocol, copy `src/protocols/echo/` and start adapting
it — the echo plugin is the documented reference. The plugin contract
lives in `src/core/plugin.zig`. Wire your new module into `build.zig`
following the existing `plugin_modules` array, then register it in
`src/app/main.zig`.

## Roadmap

See [`FEATURE_TODO.md`](FEATURE_TODO.md) for the current-state
checklist. Major open phase items at this commit:

- **W1.1 server-upgrades** — TLS, WS upgrade dispatch, HTTP/1.1
  keep-alive.
- **W1.2 crypto-net** — outbound HTTPS, BoringSSL RSA verify, Argon2id,
  secp256k1, ES256, Ed25519 consolidation.
- **W1.3 mastodon-api** — full `/api/v1` surface + OAuth2 server +
  streaming routes.
- **W1.4 media** — uploads, thumbnails, blurhash.
- **W1.5 sim-bench** — end-to-end federation simulation, baseline
  benchmark file, un-gate vendored TB intrusive tests.

## Third-party code

Vendored third-party components live under `third_party/` and
`src/third_party/`. See [`NOTICE`](NOTICE) for the full attribution and
imported-commit list, and the `LICENSE` file under each subtree for the
original license text.

The TigerBeetle utilities under `src/third_party/tigerbeetle/` are
distributed under the Apache License, Version 2.0, copyright
Tigerbeetle, Inc. The vendoring procedure and the per-component
rationale are documented in
[`docs/adr/004-vendor-tigerbeetle.md`](docs/adr/004-vendor-tigerbeetle.md).

## Copyright

Copyright © 2025–2026 Ben Gamble. The contents of this repository,
except where otherwise noted, are licensed under the terms in the
top-level [`LICENSE`](LICENSE) file.

Third-party components retain their own copyrights and licenses. See
[`NOTICE`](NOTICE) for the full attribution, and the `LICENSE` files
under each `third_party/` subtree (e.g.
[`third_party/zig-sqlite/LICENSE`](third_party/zig-sqlite/LICENSE),
[`src/third_party/tigerbeetle/LICENSE`](src/third_party/tigerbeetle/LICENSE))
for the original license text.

The vendored TigerBeetle utilities are distributed under the Apache
License, Version 2.0, copyright Tigerbeetle, Inc. The original sources
live at <https://github.com/tigerbeetle/tigerbeetle>; the imported
commit is recorded in `NOTICE` and in
`docs/adr/004-vendor-tigerbeetle.md`. No cross-licensing of project
code with vendored code is implied.
