# ADR 003 — Fork the protocol libraries in-tree

Date: 2026-05-14
Status: Accepted
Supersedes: none

## Context

speedy-socials depended on two protocol libraries:

- `lib/zat` — submodule of https://tangled.sh/zat.dev/zat, pinned at commit
  `1c3eaec0f8825b47ed1390fc53872c5d12db2254` (tag v0.2.17-2-g1c3eaec).
  Provides AT Protocol primitives: MST, CBOR, CAR, DID resolution, OAuth,
  JWT, firehose/jetstream, syntax validators.
- `lib/atproto` — in-tree path dependency that wrapped zat with a higher
  level PDS scaffold (commit/repo/storage/router + handlers + auth).

The greenfield Tiger Style rewrite (see plan
`audit-the-project-and-steady-tome.md`) requires:

1. Refactoring AT Protocol primitives to the Tiger Style contract:
   bounded buffers, no recursion, static allocation, assertions,
   simulation-testable I/O.
2. Conforming to the new plugin contract (`core/plugin.zig`).
3. Tracking against the `atproto-interop-tests` fixtures we will own
   under `third_party/`.

These changes are invasive enough that maintaining a fork as a submodule
or path-dep is friction — every refactor requires either upstream PRs or
local patches we have to rebase on each upstream change.

## Decision

Absorb both `lib/zat` and `lib/atproto` into this repository as
first-class source. Remove the submodule entry, drop the `atproto` path
dependency from `build.zig.zon` once the new layout lands, evolve the
code in-tree.

## Consequences

Positive:
- We own velocity. Tiger Style refactor can land in single commits
  without coordinating with upstream maintainers.
- Tests (interop fixtures, sim replay) ship and gate in our CI alone.
- No version-pinning friction during the Zig 0.16 / 0.17 upgrades.

Negative:
- We lose upstream improvements automatically. Mitigation: watch zat
  upstream for spec-relevant changes (especially around
  `atproto-interop-tests`) and cherry-pick.
- License compliance burden: preserve `lib/zat/LICENSE` (MIT) and
  attribute in `NOTICE`.

## Notes

- The zat upstream is MIT-licensed. The original author is credited in
  `NOTICE`.
- `lib/atproto` was already in-tree (not a submodule); only its
  bookkeeping as a `build.zig.zon` path dependency changes.
- The absorbed source is the starting point for Phase 4 of the plan;
  it is not yet Tiger Style and is not yet plugin-shaped.
