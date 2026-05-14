# Phase 8 — Legacy Retirement Inventory

Date: 2026-05-14
Branch: `worktree-agent-a13db435eddf09eda` (base: `35c3a1a`)

## Status: BLOCKED — pending integration of Phases 0–7

The Phase 8 brief assumes that Phases 0–7 have all been merged onto a single
trunk, producing the new tree at `src/core/`, `src/app/`, and `src/protocols/`,
and that ancillary artefacts (`docs/adr/003-fork-protocol-libs.md`, `NOTICE`,
`third_party/zig-sqlite/`, `bench/`) exist in the working tree.

On this branch (base `35c3a1a moving this`), **none of those preconditions hold**:

| Expected | Actual on this branch |
| -------- | --------------------- |
| `src/core/` | does not exist |
| `src/app/` | does not exist |
| `src/protocols/` | does not exist |
| `src/app/main.zig` referenced by `build.zig` | `build.zig` points at legacy `src/main.zig` |
| `docs/adr/003-fork-protocol-libs.md` | absent (only 001 and 002 exist) |
| `NOTICE` | absent |
| `third_party/zig-sqlite/` (vendored) | absent — sqlite is still a tarball dependency in `build.zig.zon` |
| `third_party/zig-websocket/` | absent |
| `bench/` | absent |
| `lib/zat/` populated | empty submodule directory (`.gitmodules` still lists it) |

The new-tree work for Phases 0–7 lives on sibling worktree branches
(`worktree-agent-a38d87a00ba8d7de1`, `…-a4ff8f3722151c7eb`,
`…-a67df6154177ee300`, `…-a765763f7f16eb599`, `…-af5ccf9fa4e733c1d`) that have
not been merged into any common base. None of them contains the *whole* new
tree on its own.

Because the only code currently in this branch's build graph is the legacy
code itself (`src/main.zig` is the build entry point), deleting it would
immediately break `zig build`. The brief's Step 4 sanity check (`zig build`
green, 211 tests still pass) therefore cannot be satisfied from this branch
in isolation.

Attempting to merge the sibling worktree branches into this one was blocked
by the harness (correctly — it falls outside the explicit "do not touch
`src/protocols/`" constraint and overlaps with the three agents still
finishing Phases 3b / 4b / 5).

## Recommended sequencing

1. Land Phases 0, 1, 2, 3 (a+b), 4 (a+b), 5, 6, 7 onto `main` (or a Phase-8
   integration branch) so the new tree is present *together with* the
   legacy tree.
2. Re-run Phase 8 from that integrated branch. At that point every legacy
   file below can be safely `git rm`d, `build.zig`/`build.zig.zon` can be
   repointed at `src/app/main.zig`, and the dependency on `lib/atproto`
   can be dropped.

The inventory below is correct as a static analysis of *what* must go; only
the *when* is blocked.

---

## Step 1 — Legacy surface

Total legacy LOC on this branch: **16,330** across the files listed below.

### Top-level `src/*.zig` (23 files)

All currently form a single build target rooted at `src/main.zig`. None of
them is referenced from anything outside the legacy tree (there is no
"outside" on this branch yet). Each will be `delete` once the new tree is
in place, with one possible `port` candidate (see crypto note).

| File | LOC | Classification | Notes |
| ---- | --- | -------------- | ----- |
| `src/main.zig` | — | delete | Legacy executable entry; replaced by `src/app/main.zig`. |
| `src/root.zig` | — | delete | Legacy module root. |
| `src/server.zig` | — | delete | Pre-plugin HTTP server. |
| `src/api.zig` | — | delete | Pre-plugin router. |
| `src/web.zig` | — | delete | Web UI shell, superseded. |
| `src/activitypub.zig` | — | delete | Superseded by `src/protocols/activitypub/`. |
| `src/federation.zig` | — | delete | Folded into AP plugin. |
| `src/atproto_storage.zig` | — | delete | Superseded by `src/protocols/atproto/`. |
| `src/database.zig` | — | delete | Replaced by `src/core/storage/`. |
| `src/cache.zig` | — | delete | Replaced by core cache. |
| `src/ratelimit.zig` | — | delete | Replaced by core ratelimit. |
| `src/jobs.zig` | — | delete | Replaced by core job system. |
| `src/search.zig` | — | delete | Replaced by FTS5 in core storage. |
| `src/auth.zig` | — | delete | Replaced by plugin auth surfaces. |
| `src/email.zig` | — | delete | Out of scope for greenfield. |
| `src/media.zig` | — | delete | Out of scope for greenfield. |
| `src/websocket.zig` | — | delete | Replaced by `src/core/ws/` (Phase 6). |
| `src/types.zig` | — | delete | Legacy aggregate type module. |
| `src/utils.zig` | — | delete | Subsumed by core utilities. |
| `src/compat.zig` | — | delete | Zig 0.15 shim — Phase 0 moved to 0.16. |
| `src/test.zig` | — | delete | Legacy test aggregator. |
| `src/test_federation.zig` | — | delete | Superseded by Phase 3 tests. |
| `src/crypto_sig.zig` | — | port-or-delete | Ed25519 + HTTP-sig helpers. The brief flags this as "kept by the original plan." Per Step 2: if `src/protocols/activitypub/keys.zig` or `src/protocols/atproto/keypair.zig` re-implements Ed25519 (they do, per the Phase 4 keypair commit visible on sibling branch `worktree-agent-a765763f7f16eb599`), then `delete`. Otherwise relocate to `src/core/crypto/ed25519.zig`. Final call deferred to integration. |

### Legacy subdirectories

| Path | Classification | Notes |
| ---- | -------------- | ----- |
| `src/api/admin.zig` | delete | Old admin endpoints; superseded by plugin admin surface. |
| `src/api/atproto.zig` | delete | Hand-rolled AT endpoints; superseded by `src/protocols/atproto/`. |
| `src/api/mastodon.zig` | delete | Old Mastodon-compat API; out of greenfield scope. |
| `src/relay/ap_to_at.zig` | delete | Pre-plugin relay; superseded by Phase 5 `src/protocols/relay/`. |
| `src/relay/at_to_ap.zig` | delete | "" |
| `src/relay/identity_map.zig` | delete | "" |
| `src/relay/mod.zig` | delete | "" |
| `src/relay/subscription.zig` | delete | "" |
| `src/relay/translate.zig` | delete | "" |

### Vendored / submodule code

| Path | Classification | Notes |
| ---- | -------------- | ----- |
| `lib/atproto/` (21 files, declared as path dep in `build.zig.zon`) | delete | Absorbed reference. Phase 4 replaces it natively under `src/protocols/atproto/`. Removing requires also deleting the `.atproto = .{ .path = "lib/atproto" }` entry from `build.zig.zon` and dropping the `atproto_mod` wiring from `build.zig`. |
| `lib/zat/` (empty submodule dir + `.gitmodules` entry) | delete | Submodule is unpopulated on this branch. Removal entails `git submodule deinit lib/zat`, `git rm lib/zat`, and stripping the `[submodule "lib/zat"]` block from `.gitmodules`. The brief said `.gitmodules` was "already gone" — on this branch it is **not** gone. |

### `third_party/` and `bench/`

Neither directory exists on this branch, so the "keep `third_party/zig-sqlite/`,
keep `bench/`, delete `third_party/zig-websocket/`" decisions in the brief
are moot here. They will need to be re-evaluated once Phase 0's vendoring
work (visible on `worktree-agent-a38d87a00ba8d7de1`) is on trunk.

### Other files referenced by the brief

| Path | Classification | Notes |
| ---- | -------------- | ----- |
| `LICENSE` | keep | Unchanged. |
| `NOTICE` | n/a | Does not exist on this branch; Phase 0 was supposed to create it. Will need creation/update at integration time. |
| `README.md` | keep, update later | Currently describes the legacy app. Will be updated at integration. |
| `FEATURE_TODO.md` | keep, update later | Same. |
| `PROTOCOL_AUDIT.md` | keep | Historical reference per brief. |
| `docs/` (all) | keep | Historical per brief. |
| `docs/adr/001-…`, `docs/adr/002-…` | keep | Historical. |
| `docs/adr/003-fork-protocol-libs.md` | n/a | Does not exist; Phase 0/4 was to author it. Cannot append the Retirement paragraph requested by Step 5 because the file isn't here yet. |
| `.claude/plans/audit-the-project-and-steady-tome.md` | n/a | Not present on this branch (lives in another worktree). Keep per brief once integrated. |
| `speedy_socials.db` | delete-or-gitignore | A committed SQLite file. Out of Phase 8 scope per the brief but worth flagging. |

## Step 2 — Reference verification

Search for legacy imports from the new tree:

- `src/core/`, `src/app/`, `src/protocols/` — not present on this branch ⇒
  no references to verify. On the sibling branches the brief instructs us
  not to touch these, so verification must be done from the eventual
  integration branch.

Within the legacy tree itself, every top-level `src/*.zig` is reachable
from `src/main.zig` via the standard module graph, and `lib/atproto/` is
consumed by `src/atproto_storage.zig`, `src/api/atproto.zig`, and
`src/main.zig` (per `build.zig` import wiring).

## Step 3 — Delete

**Not executed.** Reasons above. Once the integration branch exists,
the deletion set is exactly the union of every row classified `delete`
above plus the corresponding `build.zig` / `build.zig.zon` / `.gitmodules`
edits.

## Step 4 — Sanity

`zig build` on this branch currently still builds the *legacy* tree
unmodified. No deletions were performed, so no regression is possible.

## Step 5 — ADR update

Deferred: `docs/adr/003-fork-protocol-libs.md` does not exist on this
branch. The retirement paragraph to append, once the ADR is in place,
should read:

> ## Retirement (2026-05-14)
>
> The vendored `lib/atproto/` reference (absorbed from zat at commit
> `cbd23a0`) and the placeholder `lib/zat/` submodule have been
> removed in favour of the native implementation under
> `src/protocols/atproto/`. The corresponding `.atproto` path dependency
> and `[submodule "lib/zat"]` entry were dropped from `build.zig.zon`
> and `.gitmodules` respectively. The MIT attribution to nate nowack
> remains in `NOTICE` because the file structure under
> `src/protocols/atproto/` was inspired by zat's layout even though the
> code has been rewritten.
