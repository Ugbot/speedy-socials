# Simulation scenarios

These tests exercise speedy-socials end-to-end. Two flavours:

| step              | transport                                       | use case                                                   |
| ----------------- | ----------------------------------------------- | ---------------------------------------------------------- |
| `zig build sim`   | simulated network (TigerBeetle `PacketSimulator`) | deterministic replay, network chaos (loss, partition, drift) |
| `zig build sim-real` | real loopback TCP/HTTP between two `core.server`s | proves the production W2.2 outbound wiring is bytes-correct |

The simulated scenarios use the vendored TigerBeetle primitives in
`src/third_party/tigerbeetle/testing/`. The real-loopback scenario uses
real kernel sockets on `127.0.0.1:0` (ephemeral ports) — no DNS, no TLS,
no external services.

Each scenario also runs as a regular `zig build test` block, so it
participates in the normal CI suite.

## Differences at a glance

The `federate_with_mastodon` scenario tests *the worker's behaviour under
network chaos*: it bypasses the HTTP client entirely, submitting packets
straight into `PacketSimulator` and letting an out-of-band ACK mark
outbox rows done. This is the right harness for fuzzing partition
windows, loss rates, jitter, drift, and dead-letter triggers — none of
which the kernel TCP stack lets you script reproducibly.

The `federate_real_transport` scenario tests *the actual wire output*:
it stands up two `core.server.Server`s on real ephemeral ports, drives
one through the production `outbox_worker` + `http_delivery` +
`http_client` path, and watches bytes arrive on the other end, complete
with HTTP signature parsing + ed25519 key fetch round-trip. This is the
right harness for confirming W2.2's outbound HTTP wiring is correct
end-to-end and that the receiver's `sig.verify` reconstructs the same
signing string the sender built. It does not exercise chaos — TCP either
works or it doesn't.

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

### `federate_real_transport.zig` — full bytes-on-the-wire AP federation

Companion to the synthetic scenario above. Stands up:

* **Instance A** (sender): `:memory:` SQLite + AP schema, alice's
  Ed25519 keypair provisioned in `ap_users` + `ap_actor_keys`. The
  module-level `activitypub.state` singleton is bound to db_a +
  http_client_a. The outbox worker is driven inline via direct
  `tickOnce` calls (a background thread would race the inbox route on
  the SQLite handle, which is opened with `SQLITE_OPEN_NOMUTEX`). A
  `core.server.Server` on `127.0.0.1:0` serves a custom
  `/users/alice` route that publishes alice's `publicKeyPem` —
  registered as a test-local handler, *not* the full AP routes plugin,
  so the accept thread never touches db_a.

* **Instance B** (receiver): `:memory:` SQLite, bob's Ed25519 keypair,
  its own `http_client`, and a `core.server.Server` on `127.0.0.1:0`
  serving:
  - `GET  /users/bob` — bob's actor doc (for the bonus Accept reply)
  - `POST /users/bob/inbox` — parses the HTTP signature, fetches
    alice's PEM from A via the round-trip GET on its own
    `http_client`, calls `sig.verify` (the production verifier),
    persists the activity into `ap_activities`, then sends an `Accept`
    back to A's `/users/alice/inbox` over the same wire path.

Transport: plain HTTP (no TLS). When the W3.1 inbound BoringSSL TLS
backend lands the scenario can be re-targeted at `https://` by
swapping the bind config.

What's exercised:

- The production `outbox_worker.tickOnce` polling + state machine
- `http_delivery.deliver` — signing string + Date + Digest + draft-cavage
  Signature header construction
- `core.http_client.Client.sendSync` — plaintext outbound HTTP
- `key_fetcher_http.httpFetch` — round-trip fetch + JSON unescape of
  `publicKeyPem`
- `sig.parseCavage` + `sig.verify` (production paths) on the receiver
- The full kernel TCP socket lifecycle (`accept` → `read` → `write` → `close`)
  on both ends

Assertions:

- Within 5 wall-clock seconds: B's `ap_activities` contains the
  delivered Create(Note) row.
- B's `sig.verify` was actually invoked (counter check — proves we
  didn't accidentally fall through to a soft-accept code path).
- A's `ap_federation_outbox` row for the delivery transitioned to
  `state='done'`.
- Bonus: B's reply-Accept POST got a `2xx` from A (two-way federation).

Typical recorded output:

```
ok: real-loopback fed E2E  wall=87.2ms  verify_calls=1  outbox_done=1  two_way=YES
```

Note: server boot dominates total process wall-time on most machines
(StaticPool allocation is ~384 MiB per instance for
`limits.max_connections=4096` × 96 KiB per Connection slot). The 5-second
deadline applies to the federation work *after* both servers are bound
and threaded — booting takes a separate ~1-3 seconds depending on host.

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
