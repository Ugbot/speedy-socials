# Performance benchmarks — independent verification

This document records **measured** numbers for the three perf claims made
during the Wave-4 work, and states for each whether the measurement
**confirms** or **contradicts** the agent-reported claim.

All numbers below were produced on:

- **Host:** Apple M3 Pro, 12 cores, macOS (darwin 24.6.0)
- **Toolchain:** Zig 0.16.0, `-Doptimize=ReleaseFast`
- **Method:** each bench is a standalone executable wired into `build.zig`.
  Run them with:

  ```sh
  zig build bench-firehose -Doptimize=ReleaseFast   # bench/firehose_bench.zig
  zig build bench-mst       -Doptimize=ReleaseFast   # bench/mst_bench.zig
  zig build bench-zorm      -Doptimize=ReleaseFast   # bench/zorm_bench.zig
  ```

Benchmarks use small, bounded iteration counts so each finishes in a few
seconds. Numbers are hardware- and run-dependent; re-run on the target
machine before quoting. Each bench also asserts a conservative floor so a
regression fails CI, while printing the true measured ratio.

---

## 1. Firehose append — L0 ring vs direct per-event INSERT

**Claim under test:** the D3 L0-ring hot path is ~450× faster than a direct
`INSERT INTO atp_firehose_events` (+ cursor `UPDATE`) per event.

**Method** (`bench/firehose_bench.zig`, N = 50,000, real WAL **file** DB so
the direct path pays the realistic per-transaction fsync/checkpoint cost):

- **direct:** one autocommitted single-row `INSERT` + cursor `UPDATE` per
  event, each in its own WAL transaction.
- **L0 ring:** the production path `atproto.firehose.append` — lands the
  event in the in-memory L0 ring (`firehose_store`), assigning its seq with
  no SQLite on the hot path; durable L1 writes are amortised across a
  batched flush. This is the *production* path, not the separate
  `firehose_buffer.Ring` the earlier bench used.

We report both mean throughput (ns/event over the whole run) and the
**common-path (p0..p99) append latency**, which isolates the pure in-memory
ring write from the handful of periodic batch-flush spikes — that
common-path number is what a "per-event speedup" claim refers to.

**Measured (N = 50,000):**

| metric                                   | direct     | L0 ring    | ratio   |
|------------------------------------------|------------|------------|---------|
| mean throughput                          | 19,263 ns/ev | 834 ns/ev (hot) | **23.1×** |
| ring + batched L1 flush (end-to-end)     | —          | 845 ns/ev  | 22.8×   |
| common-path (p0..p99) append latency     | 16,588 ns  | 136 ns     | **122×** |

Both paths landed all 50,000 rows durably.

**Verdict: PARTIALLY CONTRADICTS.** The qualitative claim is **confirmed** —
the L0 ring removes SQLite from the firehose hot path and the common-path
append is ~**122×** faster (136 ns vs 16,588 ns). But the specific
**~450× magnitude is NOT reproduced** on this hardware: the measured
common-path speedup is ~122×, and the steady-state mean-throughput speedup
is ~23×. 450× is plausible only on hardware with a much slower durable
write path (e.g. spinning disk / fsync-bound storage where each direct
transaction costs far more); on an M3 Pro with a fast SSD the win is large
but ~3–4× short of 450×.

> Note: the **previous** `bench/firehose_bench.zig` was misleading — its
> "direct" path actually routed through `firehose.append` (the shared L0
> store), so it measured ring-vs-ring and failed with a row-count mismatch
> (the 10k-slot store held back unflushed events). It has been rewritten to
> compare a true direct `INSERT` against the production ring path.

---

## 2. Incremental MST — block writes on a +1 commit vs full rebuild

**Claim under test:** an incremental MST commit that touches one record
writes ~200× fewer blocks than re-deriving the whole tree.

**Method** (`bench/mst_bench.zig`, N = 500 and N = 2000):

- **full rebuild:** `Tree.buildAndEmit` — re-derives and emits every node
  block.
- **+1 incremental:** warm the node cache (first incremental persist does a
  full rebuild that populates it), insert one new record, then
  `Tree.buildAndEmitIncremental` and count only the node blocks the encoder
  re-emits (`out_emitted`). Unchanged sibling subtrees keep their cached
  CIDs and are not re-encoded.

"Blocks written" is the dominant per-commit cost (each block is a DAG-CBOR
encode + SHA-256 CID + a row in `atp_mst_blocks`).

**Measured:**

| N    | full rebuild | +1 incremental | block-write reduction | wall-clock |
|------|-------------:|---------------:|----------------------:|-----------:|
| 500  | 125 blocks   | 5 blocks       | **25.0×**             | 2.2×       |
| 2000 | 521 blocks   | 5 blocks       | **104.2×**            | 2.4×       |

The +1 commit always re-emits exactly the nodes on the new leaf's
root→leaf path (here 5, ≈ the tree height at fanout 4). The reduction
therefore **scales with N**: total nodes grow ~linearly while the changed
path stays ~`log_4(N)` deep.

**Verdict: CONFIRMS (direction & scaling); magnitude is N-dependent.** The
incremental encoder writes dramatically fewer blocks, and the ratio grows
with tree size exactly as expected. At N = 2000 we measure ~**104×**; the
~200× figure is reachable at larger repos (extrapolating, N ≈ 4000–8000
records puts full-rebuild block counts in the ~1000–2000 range against the
same ~5-block incremental path). So ~200× is **consistent** with the trend
but only at repo sizes roughly 2–4× larger than the N = 2000 case measured
here. At the small N tested it is correspondingly smaller (25× at N = 500).

---

## 3. zorm CRUD vs hand-written SQL

**Claim under test:** the zorm ORM adds only a small constant overhead over
hand-written SQL, not an order of magnitude.

**Method** (`bench/zorm_bench.zig`, N = 10,000, in-memory SQLite, **same**
`core.storage.SqliteBackend` for both paths):

- **zorm:** `zorm.Repository(T).insertNow` / `findByPk` — comptime SQL
  generation + struct↔row marshalling through the zorm adapter vtable.
- **hand:** a prepared `INSERT` / `SELECT` issued directly against the
  backend with manual bind/read.

Both write/read the identical 5-column row into the identical table, so the
delta is pure ORM marshalling + vtable-indirection overhead. (Both paths
prepare per operation, so statement-prepare cost is held constant.)

**Measured (N = 10,000):**

| op       | zorm        | hand        | overhead |
|----------|------------:|------------:|---------:|
| insert   | 2,413 ns/op | 2,157 ns/op | **1.12×** |
| findByPk | 1,864 ns/op | 1,649 ns/op | **1.13×** |

Both paths found all 10,000 rows.

**Verdict: CONFIRMS.** zorm adds ~12–13% over hand-written SQL on both
insert and point-read — a small constant overhead, far from an order of
magnitude. The comptime SQL generation and the layout-identical adapter
recast (`zorm_adapter`) keep the marshalling cost low.

---

## Summary

| # | Claim                                    | Reported | Measured (this host)             | Verdict              |
|---|------------------------------------------|----------|----------------------------------|----------------------|
| 1 | firehose ring vs direct insert           | ~450×    | ~122× common-path, ~23× mean     | Partially contradicts (direction confirmed, magnitude not reproduced) |
| 2 | incremental MST vs full rebuild          | ~200×    | 25× @N=500, 104× @N=2000 (scales) | Confirms direction & scaling; ~200× needs larger N |
| 3 | zorm CRUD overhead vs hand-written SQL   | small    | 1.12× insert, 1.13× findByPk     | Confirms             |
