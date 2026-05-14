# Vendored TigerBeetle utilities

This directory holds source code copied (or, for one file, rewritten to
the same contract) from [TigerBeetle](https://github.com/tigerbeetle/tigerbeetle),
distributed under the Apache License, Version 2.0. The full license
text is in [`LICENSE`](LICENSE). The re-vendor metadata for the project
overall lives in `NOTICE` at the repository root.

**Source**: `https://github.com/tigerbeetle/tigerbeetle`
**Imported commit**: `44544ee11057bbc8fe826cb7f93e8e00a57f2fc1`
**Imported date**: 2026-05-14
**Author**: Tigerbeetle, Inc. and contributors

## Why we vendored

The rationale per component lives in
[`docs/adr/004-vendor-tigerbeetle.md`](../../../docs/adr/004-vendor-tigerbeetle.md).
In short: TigerBeetle's Tiger Style toolbox is exactly the missing
infrastructure for speedy-socials' "no-alloc after boot" invariant,
intrusive tree-walking, weighted-enum swarm testing, and deterministic
simulation. Most of it is generic enough to drop in; the simulation
primitives need light decoupling from VSR.

## File inventory

| Vendored path | Original TB path | LOC | Purpose | Modifications |
|---|---|---|---|---|
| `alloc/static_allocator.zig` | `src/static_allocator.zig` | 83 | State-machine allocator: panics on alloc after the boot phase transitions to `.static`. | None (Zig 0.16 compatible as-is). |
| `alloc/counting_allocator.zig` | `src/counting_allocator.zig` | 73 | Live-bytes instrumentation wrapper. | None. |
| `intrusive/stack.zig` | `src/stack.zig` | 261 | Intrusive LIFO. | Replaced `@import("constants.zig")` with the local `_shim.zig`. PRNG-using fuzz tests gated with a `// TODO: re-enable with core.prng` until tranche 3 consolidation. |
| `intrusive/list.zig` | `src/list.zig` | 237 | Intrusive doubly-linked w/ O(1) remove. | Same shim + TODO-gate as above. |
| `intrusive/queue.zig` | `src/queue.zig` | 391 | Intrusive named FIFO with iteration. | Same shim + TODO-gate as above. |
| `intrusive/_shim.zig` | (new) | tiny | Provides `pub const verify: bool = std.debug.runtime_safety;` so the vendored collections do not require TB's full `constants.zig`. | Local. |
| `intrusive/root.zig` | (new) | tiny | Module root that re-exports `Stack`/`List`/`Queue`/`StackType`/`DoublyLinkedListType`/`QueueType`. | Local. |
| `prng/prng.zig` | `src/stdx/prng.zig` | 677 | Xoshiro256 PRNG plus `Ratio`, `EnumWeightsType`, `Combination`, `Reservoir`, and the swarm-testing helpers TB uses for fuzzing. | `stdx` import redirected at `_shim.zig`; the file-path-dependent `"no floating point please"` test rebound to the vendored path with a `FileNotFound`-tolerant skip. |
| `prng/_shim.zig` | (new) | small | Minimal `stdx` surface (`Snap` no-op, `cut`, `KiB`, `BitSetType`, `Flags.parse_flag_value_fuzz`) so `prng.zig` builds without TB's full `stdx`. | Local. |
| `testing/time.zig` | `src/testing/time.zig` | 99 | `TimeSim` with `linear`/`periodic`/`step`/`non_ideal` drift models exposed through a vtable. | Decoupled from TB's `vsr.Time` interface; standalone. |
| `testing/io.zig` | `src/testing/io.zig` | 366 | Synchronous in-memory I/O with sector-level fault injection (PRNG-driven). | Slim port: TB's async `Completion` ring and `QueueType` dependency removed. The synchronous backing matches our `std.Io` injection surface. |
| `testing/fuzz.zig` | `src/testing/fuzz.zig` | ~150 | `random_int_exponential`, `range_inclusive_ms`, `parse_seed` (base-10 or 40-char git SHA). | Retargeted at `std.Random.Xoshiro256` — TB's `stdx.PRNG` is available via `prng/`, but the testing helpers themselves are kept minimal. |
| `testing/packet_simulator.zig` | `src/testing/packet_simulator.zig` | ~200 (new) | Network fault injection: exponential latency, Bernoulli loss, scripted symmetric + asymmetric partitions. Same contract as TB's. | **Rewritten from scratch** to avoid TB's dependencies on `vsr.Command`, `stdx.PRNG.Ratio`, the `Duration`/`Instant` types, `QueueType`, and `constants.tick_ms`. The public API is `PacketSimulator(comptime Packet: type)` where `Packet` must expose `from`, `to`, `payload`, and `copy` accessor functions — see the file header for the full contract. |
| `testing/root.zig` | (new) | tiny | Module root re-exporting `time`, `io`, `fuzz`, `packet_simulator`. | Local. |

## How the rest of the tree imports this

`src/core/` is the stable boundary:

- `core.alloc` (`src/core/alloc.zig`) re-exports `StaticAllocator` and
  `CountingAllocator`.
- `core.intrusive` (`src/core/intrusive.zig`) re-exports `Stack`/`List`/`Queue`.
- `core.prng` (`src/core/prng.zig`) re-exports the rich TB PRNG; the
  existing `core.rng.Rng` API is preserved (additive change).
- `core.sim` (`src/core/sim.zig`) re-exports `TimeSim`, `SimIo`, and
  `PacketSimulator`.
- `core.testing.fuzz` (`src/core/testing/fuzz.zig`) re-exports the seed
  parser + distribution helpers.

The `TimeSim` adapter that projects through the local `Clock` vtable
lives in `src/core/clock.zig` (`TimeSimClock`).

Plugins and protocols must use the `core.*` aliases — they should not
`@import` `src/third_party/tigerbeetle/...` directly.

## Re-vendor procedure

Rough recipe for refreshing from a newer TB upstream:

1. Pin the new TB commit: `cd <somewhere>/tigerbeetle && git rev-parse HEAD`.
2. Diff each vendored file against the new commit; review changes:
   `diff -u <our-vendored> <tigerbeetle/src/...>`
3. Re-apply the per-file modifications listed in the table above (the
   `_shim.zig` redirections, the TODO-gated tests, the trivial header
   comment).
4. Run `zig build && zig build test --summary all && zig build sim` —
   all should stay green.
5. Update the "Imported commit" line in this file and the matching line
   in `/NOTICE`. Update `docs/adr/004-vendor-tigerbeetle.md` with a
   one-line entry under "Re-vendor history".

## Skipped from TigerBeetle

Deliberately not vendored — see ADR-004 for per-component reasoning:

- `src/lsm/`, `src/aof.zig`, `src/cdc/` — SQLite is our persistence
  story; the AP outbox + AT firehose tables cover the durable-log
  case.
- `src/multiversion.zig`, `src/build_multiversion.zig` — interesting,
  out of scope.
- `src/io/{linux,darwin,windows}.zig` — TB's io_uring/kqueue/IOCP loop.
  We use `std.Io.Threaded` plus a worker pool; the win from TB's loop
  is in storage I/O ordering which we don't need.
- `src/vsr/`, `src/message_pool.zig`, `src/message_buffer.zig`,
  `src/message_bus.zig` — too entangled with the TB replica/client
  cluster model.
- `src/state_machine.zig`, `src/repl/` — BeetleBank-specific.
- `src/stdx/{flags,radix,unshare,zipfian,bit_set,time_units}.zig` —
  redundant for our domain or low-ROI. Future cherry-picks.

## License

Apache License, Version 2.0. See [`LICENSE`](LICENSE) in this directory
for the full text. The original source headers are preserved verbatim
in every vendored file. Modifications applied at copy time are
itemised in the table above and in each file's header.

No relicensing is performed. Project code outside `src/third_party/`
remains under the top-level repository LICENSE; vendored code remains
under Apache 2.0.
