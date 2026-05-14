# ADR 004 — Vendor TigerBeetle utilities in-tree

Date: 2026-05-14
Status: Accepted
Supersedes: none
Related: ADR-003 (forking the protocol libraries), the plan at
`.claude/plans/audit-the-project-and-steady-tome.md`

## Context

After Phases 0–8 of the Tiger Style greenfield rewrite, three pieces of
load-bearing infrastructure from the original plan were still missing
or under-built:

1. The "zero allocations on the hot path" rule was documented and
   asserted-in-spirit, but not *enforced*: the planned
   `NoAllocAllocator` (a wrapper that panics on `alloc` after boot
   completes) was never written. Without it, the invariant lives in
   review-time discipline, not in the binary.
2. Tree walks and LRU lists were each hand-rolled — `[MAX]Frame` arrays
   for the MST, hand-rolled list-plus-hashmap for the AP key cache —
   correct, but more LOC than we needed and not battle-tested.
3. The simulation harness the plan promised ("deterministic time +
   seeded RNG + recordable I/O so federation sequences can be replayed")
   never landed. We had `SimClock` (advance-only) and seeded Xoshiro,
   but no drift modelling, no fault-injecting I/O, and no packet
   simulator.

TigerBeetle (Tigerbeetle, Inc., Apache 2.0) has battle-tested,
near-drop-in code for every one of these. Local checkout:
`/Users/bengamble/tickstream/third-party/tigerbeetle` at commit
`44544ee11057bbc8fe826cb7f93e8e00a57f2fc1`.

## Decision

Vendor a focused subset of TigerBeetle's source into
`src/third_party/tigerbeetle/`, preserve the original Apache-2.0 license
and copyright headers, and re-export the chosen surface through the
existing `core.*` namespace.

Specifically (full inventory in `src/third_party/tigerbeetle/README.md`):

- **Allocators** — `static_allocator.zig`, `counting_allocator.zig`
- **Intrusive collections** — `stack.zig`, `list.zig`, `queue.zig`
- **PRNG** — `stdx/prng.zig` (Xoshiro256 + Ratio + weighted-enum
  sampling + distribution helpers)
- **Simulation primitives** — `testing/time.zig` (TimeSim with drift
  models), `testing/io.zig` (synchronous SimIo with sector-level fault
  injection), `testing/fuzz.zig` (seed parsing + distributions). The
  `testing/packet_simulator.zig` equivalent was *rewritten from scratch*
  (~200 LOC) to provide the same contract without dragging in
  `vsr.Command`, the full `stdx` toolkit, or TB's `Duration`/`Instant`
  types — see ADR's Notes section below.

The four adoption sites in our tree are:

- `src/protocols/atproto/mst.zig` — MST walker now uses `Stack(Frame)`.
- `src/protocols/activitypub/key_cache.zig` — LRU is `List(KeyEntry)`.
- `src/protocols/activitypub/outbox_worker.zig` — in-flight deliveries
  tracked in a named `Queue` for diagnostics; backoff jitter built from
  `Rng.exponential` + signed `Ratio`.
- `src/core/workers.zig` — per-worker `Queue` for diagnostics.

`src/app/main.zig` wraps the GPA in `StaticAllocator` and transitions to
`.static` after the boot sequence completes; from that point on, any
request handler that tries to allocate panics with TB's assertion
message. The previously-ad-hoc "poison allocator" in
`bench/storage_bench.zig` was replaced with `StaticAllocator` so the
hot-path zero-alloc claim is enforced via the same code path the real
binary uses.

A new `zig build sim` step runs the federation simulation scenario
under `tests/sim/federate_with_mastodon.zig`.

## Consequences

Positive:

- The "no allocations on the hot path" invariant is enforced in the
  binary, not just review-time.
- Intrusive collections give us O(1) move-to-front for the AP key
  cache LRU and named queues for diagnostics — both wins we wouldn't
  have built ourselves without considerable effort.
- The weighted-enum PRNG sampling unlocks meaningful swarm testing on
  the AP inbox state machines and the AT MST operations.
- The simulation harness is the foundation for the "deterministic
  replay of federation sequences" the plan promised. `zig build sim`
  runs and exercises it today.
- Test count rose from 324 → 370 (+46 tests across the four tranches).

Negative:

- We now track TigerBeetle's upstream for relevant fixes. The
  re-vendor procedure is documented in
  `src/third_party/tigerbeetle/README.md`. Cadence: quarterly review,
  plus an immediate re-vendor when a known-relevant fix lands
  upstream.
- The Apache-2.0 attribution carries an ongoing obligation: every
  vendored file keeps its TB copyright header, the `LICENSE` and
  `NOTICE` files must remain accurate, and any modifications applied
  at copy time must be itemised (per Apache §4(b)). We track all of
  these in `src/third_party/tigerbeetle/README.md`.
- The `packet_simulator.zig` rewrite is *our* code, not TB's. It
  matches TB's contract but its bug surface is independent. Tests
  cover the four key behaviours (latency, loss, partition window,
  asymmetric partitions).

## Notes

### What we deliberately did *not* vendor

- **`src/lsm/`** — SQLite is our persistence story. Pulling in an LSM
  would either be unused or force a competing storage path.
- **`src/aof.zig`** — VSR-entangled. Our federation outbox + firehose
  events tables in SQLite cover the durable-log use case via the same
  storage subsystem the rest of the project uses.
- **`src/cdc/`** — VSR-coupled change data capture. Our federation
  outbox already streams to remote ActivityPub inboxes; we don't need
  AMQP.
- **`src/io/{linux,darwin,windows}.zig`** — TB's io_uring/kqueue/IOCP
  loop. The performance wins are dominated by direct I/O for the LSM,
  which we don't have. We use `std.Io.Threaded` + a worker pool today;
  switching is a sideways move at best.
- **`src/multiversion.zig`** + `src/build_multiversion.zig` —
  interesting, but the binary upgrade story is out of scope for now.
- **`src/vsr/`, `src/message_pool.zig`, `src/message_buffer.zig`,
  `src/message_bus.zig`** — too entangled with the TB cluster model.
  We may revisit `message_buffer.zig`'s state-machine pattern later for
  HTTP/1.1 keep-alive read tracking.
- **`src/state_machine.zig`** — BeetleBank-specific.
- **`src/repl/`** — BeetleBank-specific.
- **`src/stdx/{flags,radix,unshare,zipfian,bit_set,time_units}.zig`** —
  redundant or low-ROI for our domain. Cherry-pick later if a clear
  need emerges.

### Why `packet_simulator.zig` was rewritten

TB's `packet_simulator.zig` is parameterised on `vsr.Command`,
references `stdx.PRNG.Ratio`, uses TB's `Duration`/`Instant` types, and
depends on `QueueType` and `constants.tick_ms`. Decoupling cleanly
would have required pulling in roughly half of `stdx` plus a parallel
type system for time. The clean port budget was ~1 hour; the from-
scratch alternative was ~200 LOC. We chose the latter, kept the same
public contract (`PacketSimulator(comptime Packet: type)` parameterised
on a caller-supplied envelope with `from`/`to`/`payload`/`copy`
accessors), and matched the four behaviours we care about — exponential
latency, Bernoulli loss, scripted symmetric partitions, scripted
asymmetric partitions. The rewrite carries our own copyright; the rest
of `src/third_party/tigerbeetle/testing/` is TB's.

### License compatibility

Apache 2.0 is a permissive license compatible with the rest of the
repository. No relicensing of project code or of vendored code occurs;
each retains its original terms. The README copyright line is explicit
about this boundary.

### Re-vendor history

| Date | TB commit | Notes |
|------|-----------|-------|
| 2026-05-14 | `44544ee11057bbc8fe826cb7f93e8e00a57f2fc1` | Initial vendor (this ADR). |
