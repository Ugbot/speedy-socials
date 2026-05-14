# Simulation scenarios

These tests exercise speedy-socials end-to-end against deterministic time
and a flaky simulated network, using the vendored TigerBeetle simulation
primitives in `src/third_party/tigerbeetle/testing/`.

Run all simulation scenarios:

```
zig build sim
```

Each scenario also runs as a regular `zig build test` block under
`std.testing.allocator`, so it participates in the normal CI suite.

## Scenarios

### `federate_with_mastodon.zig` — full federation E2E

End-to-end federation: a real in-process `outbox_worker` driving an AP
schema in `:memory:` SQLite, with the delivery hook plumbed into a
`PacketSimulator` and the worker's clock projected from a drift-enabled
`TimeSim` via `core.clock.TimeSimClock`.

What's exercised:

- `outbox_worker.tickOnce` (the production polling tick — same code path
  the real server uses)
- `delivery.enqueueDeliveries` (the production enqueue path)
- The full `ap_federation_outbox` retry+backoff state machine
- A `PacketSimulator` carrying 100 `Create(Note)` deliveries with:
  - exponential one-way latency, mean 50ms, floor 5ms
  - 5% packet loss
  - one scripted partition at simulated `t=10s..15s`, both directions
  - max 64 packets in-flight per directed path
- `TimeSim` with `+5ppb` linear drift, projected through `TimeSimClock`,
  so the worker's wall clock isn't perfectly stationary

How the seam works: the deliver hook submits each activity to the
`PacketSimulator` and returns `transient_failure`, leaving the outbox
row `pending`. When the simulator actually delivers the packet to the
peer's receive log, an out-of-band ACK marks the corresponding outbox
row `done`. This models a federation receiver that confirms receipt
asynchronously (idempotent POST + ack) rather than the producer
synchronously waiting on the HTTPS round-trip.

Assertions:

- Every Activity ID appears in the peer's recv log at least once.
- `ap_federation_dead_letter` has zero rows (no delivery hit
  `max_delivery_attempts=8`).
- All 100 outbox rows end in `state='done'`.
- Wall-clock runtime under 5 real seconds — sim is meaningless if it
  isn't fast.

Typical recorded output:

```
ok: 100 activities delivered  wall=2014ms  attempts=105
dropped_loss=5 dropped_partition=0 dropped_capacity=0 duplicates=0
```

(105 attempts for 100 activities ≈ 5 retries triggered by 5% packet
loss — the partition window is dodged because most first-attempt packets
deliver in <100ms before t=10s.)

### `firehose_subscriber.zig` — AT Protocol firehose under WS partition

Smaller scenario covering the two-tier firehose delivery contract from
`src/protocols/atproto/firehose.zig`:

- Persistent table (`atp_firehose_events`) is append-only and **never**
  drops.
- The live ring (in-memory, bounded) drops oldest events under burst.
  Subscribers detect cursor gaps and recover from the persistent table.

What's exercised:

- 500 firehose events appended at deterministic timestamps over 60
  simulated seconds.
- A subscriber maintains a cursor and polls via `firehose.readSince`.
- A scripted WS partition at `t=20s..30s`. During the partition the
  subscriber's live pull is skipped; after the partition it catches up
  from the persistent table.

Assertions:

- Persistent count == events appended (no loss).
- Subscriber's eventual count == events appended (full catch-up).
- Cursor is strictly monotonic (no replay of seen events).
- A non-zero count of "recovered after partition" events — proves the
  partition actually delayed traffic.
- Wall-clock runtime under 5 real seconds.
