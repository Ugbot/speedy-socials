# Phase 8 — Legacy Retirement Inventory

Date: 2026-05-14

Each entry was verified by grepping the new tree (`src/core/`, `src/app/`,
`src/protocols/`, `build.zig`, `build.zig.zon`, `bench/`) for any import,
reference, or path dependency. The new tree contains zero references to
any of the following paths.

## src/ top-level (legacy monolith)

All `delete`. None are imported by `src/core/`, `src/app/`, or
`src/protocols/`. The build graph only enters via `src/app/main.zig`,
which imports `core` + the four protocol plugin modules.

| Path                       | LOC  | Disposition | Notes                                                |
|----------------------------|------|-------------|------------------------------------------------------|
| `src/activitypub.zig`      |  506 | delete      | Superseded by `src/protocols/activitypub/`.          |
| `src/api.zig`              |   10 | delete      | Stub re-export of legacy api/.                       |
| `src/atproto_storage.zig`  |  383 | delete      | Superseded by `src/protocols/atproto/` + core storage.|
| `src/auth.zig`             |  219 | delete      | Legacy.                                              |
| `src/cache.zig`            |  359 | delete      | Legacy.                                              |
| `src/compat.zig`           |   18 | delete      | Legacy compat shim.                                  |
| `src/crypto_sig.zig`       |  437 | delete      | Only consumed by legacy (`database.zig`, `federation.zig`, `test_federation.zig`, `main.zig`). Not imported by `src/protocols/activitypub/keys.zig` or `src/protocols/atproto/keypair.zig`. |
| `src/database.zig`         | 1379 | delete      | Superseded by `src/core/storage/`.                   |
| `src/email.zig`            |  362 | delete      | Legacy.                                              |
| `src/federation.zig`       |  734 | delete      | Superseded by `src/protocols/activitypub/`.          |
| `src/jobs.zig`             |  422 | delete      | Superseded by `src/core/workers.zig`.                |
| `src/main.zig`             |  119 | delete      | Superseded by `src/app/main.zig`.                    |
| `src/media.zig`            |  302 | delete      | Legacy.                                              |
| `src/ratelimit.zig`        |  291 | delete      | Legacy.                                              |
| `src/root.zig`             |   23 | delete      | Old root; new root is `src/core/root.zig`.           |
| `src/search.zig`           |  461 | delete      | Legacy.                                              |
| `src/server.zig`           | 2063 | delete      | Superseded by `src/core/server.zig`.                 |
| `src/test_federation.zig`  |  371 | delete      | Tests for legacy federation/crypto.                  |
| `src/test.zig`             |   18 | delete      | Legacy test entry.                                   |
| `src/types.zig`            |  442 | delete      | Legacy.                                              |
| `src/utils.zig`            |   98 | delete      | Legacy.                                              |
| `src/web.zig`              |  317 | delete      | Legacy.                                              |
| `src/websocket.zig`        |  757 | delete      | Superseded by `src/core/ws/`.                        |

## src/api/ (legacy)

All `delete`. Not referenced by the build graph.

| Path                    | LOC  | Disposition |
|-------------------------|------|-------------|
| `src/api/admin.zig`     |  371 | delete      |
| `src/api/atproto.zig`   |  141 | delete      |
| `src/api/mastodon.zig`  | 1018 | delete      |

## src/relay/ (legacy)

All `delete`. The new relay lives at `src/protocols/relay/`.

| Path                          | LOC  | Disposition |
|-------------------------------|------|-------------|
| `src/relay/ap_to_at.zig`      |  151 | delete      |
| `src/relay/at_to_ap.zig`      |  210 | delete      |
| `src/relay/identity_map.zig`  |  246 | delete      |
| `src/relay/mod.zig`           |  107 | delete      |
| `src/relay/subscription.zig`  |  162 | delete      |
| `src/relay/translate.zig`     | 1082 | delete      |

## lib/atproto/ (absorbed reference)

All `delete`. ~2,737 LOC. Not referenced by `build.zig.zon` dependencies
(only `sqlite` remains there). The Tiger Style PDS scaffolding now lives
in `src/protocols/atproto/`.

## lib/zat/ (absorbed reference)

All `delete`. ~10,149 LOC (including its own `src/internal/repo/{mst,cbor,car,…}`).
Not referenced by `build.zig.zon` dependencies. Its primitives (MST, CID,
dag-cbor, TID, syntax, did, keypair) have been re-implemented in
`src/protocols/atproto/`.

License compliance: `NOTICE` is updated (not removed) to preserve the
MIT attribution to nate nowack, noting that the structure influenced our
rewrite in `src/protocols/atproto/`.

## third_party/

| Path                          | Disposition | Notes                                                              |
|-------------------------------|-------------|--------------------------------------------------------------------|
| `third_party/zig-sqlite/`     | **keep**    | Live SQLite dependency declared in `build.zig.zon`.                |
| `third_party/zig-websocket/`  | delete      | Only consumed by `lib/zat/build.zig.zon`. With `lib/zat` gone it has no consumer (new code uses `src/core/ws/`). |

## .gitmodules

Already absent from main; confirmed.

## build.zig.zon

- Remove the `lib` entry from `.paths` (no longer present in tree).
- Remove `third_party/zig-websocket` references (none — never declared
  as a top-level dep, was only a path dep inside `lib/zat`).
- `sqlite` path dependency is retained.

## Summary

- `keep`: `third_party/zig-sqlite/`, `docs/`, `PROTOCOL_AUDIT.md`,
  `FEATURE_TODO.md`, `LICENSE`, `NOTICE` (updated), `bench/`,
  `.claude/plans/audit-the-project-and-steady-tome.md`.
- `port`: none. All referenced primitives were already rewritten in
  earlier phases under `src/protocols/atproto/` and
  `src/protocols/activitypub/`.
- `delete`: everything listed above.
