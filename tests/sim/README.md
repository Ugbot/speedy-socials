# Simulation scenarios

These tests exercise speedy-socials end-to-end against deterministic time
and a flaky simulated network, using the vendored TigerBeetle simulation
primitives in `src/third_party/tigerbeetle/testing/`.

Run all simulation scenarios:

```
zig build sim
```

## Scenarios

### `federate_with_mastodon.zig`

Drives 20 ActivityPub `Create(Note)` deliveries from a local node to a
simulated Mastodon peer over a link with:

- exponential latency (mean 50ms, floor 5ms)
- 5% packet loss
- one scripted partition at simulated `t=10s` lasting 5s

Asserts at-least-once delivery, no dead-letter, and all 20 outbox rows
end in `state=done`.

**Current scope: proof-of-concept.** The scenario runs against a
hand-rolled outbox state-machine that mirrors `outbox_worker.zig`'s
retry/backoff policy (`max_delivery_attempts=8`, exponential backoff
floor `200ms · 2^attempts`, capped at 5s). It does **not** boot the
real `outbox_worker` against `SimIo`-backed storage — that requires
plumbing `SimIo` through `core.storage` and is intentionally scoped out
of Tranche 4 to avoid editing other tranches' files.

**Follow-up (post-Tranche 4):** wire `core.storage` to accept an
`Io = SimIo` config parameter (mirroring the existing `Clock` injection)
and have this scenario drive the real worker. The `Activity` data shape
and assertions in this file are stable, so the swap-in is mechanical.
