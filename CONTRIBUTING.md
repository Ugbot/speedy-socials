# Contributing to speedy-socials

## Quick start

```
zig build           # builds the binary
zig build test      # runs every test block + sim scenarios as tests
zig build sim       # runs simulation scenarios as standalone programs
zig build bench     # runs the storage / HTTP / firehose benches
```

Zig 0.16.0 is the supported compiler. The codebase tracks the
stable release; nightly is not exercised.

## Layout

```
src/
  app/            # composition root (main.zig)
  core/           # http server, sqlite plumbing, log, metrics, TLS,
                  # crypto, http_client, plugin runtime
  protocols/      # one folder per plugin (activitypub, atproto,
                  # mastodon, media, echo, relay)
  third_party/    # vendored libraries (see third_party/README.md)
tests/
  sim/            # deterministic federation simulations
  fixtures/       # static fixtures (test cert + key)
docs/
  adr/            # architecture decision records
  design/         # design notes (protocol-relay, translation-matrix)
PUNCHLIST.md      # flat list of remaining production-readiness work
```

## Plugin contract (ABI v2)

Every protocol lives behind `core.plugin.Plugin`:

```zig
pub const Plugin = struct {
    name: []const u8,
    version: u32,
    init: *const fn (state: ?*anyopaque, ctx: *Context) anyerror!void,
    deinit: *const fn (state: ?*anyopaque, ctx: *Context) void,
    register_routes: ?*const fn (...) = null,
    register_ws_upgrade: ?*const fn (...) = null,
    register_schema: ?*const fn (...) = null,
};
```

Each plugin gets a `*Context` carrying `clock`, `rng`, `storage`,
`userdata`. The composition root in `src/app/main.zig` wires
shared state (db handles, worker pools, etc.) into plugin module
singletons via `attachDb` / `attachHttpClient` / `setHostname` /
similar helpers — *plugins do not import each other*. The relay
plugin is the **only** carve-out (see ADR-002 / module doc).

## Tiger Style invariants

These are project-wide. Reviewers will flag departures.

1. **No hot-path allocation.** Allocators are wrapped in a
   `StaticAllocator` that panics on `alloc` after the boot phase
   transitions to `.static`. Any post-boot allocation is a bug.
2. **Bounded buffers.** Every loop has an asserted upper bound;
   every collection has a compile-time max size. See
   `src/core/limits.zig` for the canonical caps.
3. **No panics on the request path.** Errors propagate via Zig's
   error sets; the request handler's top-level swallow logs +
   returns a clean 500 (see `G6` in `PUNCHLIST.md`).
4. **No silent error swallows.** If a path could fail, either
   propagate the error or log it via the ring log with enough
   context to diagnose.
5. **Test inputs are randomized.** Use the vendored TigerBeetle
   PRNG (`core.prng`) seeded from the test's deterministic seed —
   not hardcoded sample data.
6. **Multi-tenant isolation, when it lands** (see PUNCHLIST `H`),
   filters via SQL `WHERE` clauses, not application code.

## When to vendor

External code goes under `third_party/`. Per `feedback_vendor_deps.md`
the preferred mechanism is a git submodule pinned to a known SHA;
copy-vendoring is acceptable when (a) the upstream is small and
stable (b) we've patched the source. See
`third_party/README.md` for the per-entry strategy.

## Commit / PR conventions

- One logical change per commit. The PUNCHLIST item id should
  appear in the commit subject (`W6:`, `A1:`, `B4:`, etc.).
- No co-author lines.
- Run `zig build test` before pushing; the CI workflow
  (`docs/ci/`) is informational at this stage but will gate merges
  once F4 (multi-arch Docker) lands.
- When you tick a PUNCHLIST item, do it in the same commit that
  ships the implementation. The `[x]` should reference the commit
  SHA (`[x] **W6.** (commit abc1234)`) for forensic value.

## Testing checklist

When adding behaviour that crosses a protocol boundary:

- Unit test for the translator / handler in its own plugin module
- Unit test for the bridge translation (if applicable) in
  `src/protocols/relay/`
- Cross-protocol scenario in `tests/sim/relay_bridge_scenario.zig`
- Translation matrix row in `docs/design/translation-matrix.md`
- PUNCHLIST entry ticked or split

## Useful debug commands

```
RELAY_BRIDGE_AP_TARGET=https://peer.example/inbox \
RELAY_SYNTHETIC_KEY_PEPPER=$(openssl rand -hex 32) \
TLS_CERT_PATH=./tests/fixtures/test.crt \
TLS_KEY_PATH=./tests/fixtures/test.key \
STRICT_HTTP_SIG=1 \
SHUTDOWN_GRACE_MS=15000 \
./zig-out/bin/speedy-socials
```

```
# tail the access log
curl -sN http://127.0.0.1:8080/admin/relay/log | jq '.[]'
# scrape Prometheus
curl -s http://127.0.0.1:8080/metrics
# check readiness
curl -s http://127.0.0.1:8080/readyz
```
