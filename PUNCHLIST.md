# speedy-socials — punchlist

Flat list of remaining work to take the project from "demo bridge"
to "operates confidently as a production multi-network node, router,
and bridge." Each item is independently tickable. Acceptance lines
are what "done" means — not a step-by-step plan.

Sections are loose groupings, not phases — items within a section
can be tackled in any order. Items between sections are usually
independent too (dependencies are called out inline).

_Last refreshed: 2026-05-19._

---

## A. Bridge correctness (load-bearing for the relay claim)

- [x] **A1. AP synthetic-actor key publication.**
      Acceptance: GET `https://<host>/ap/users/<synth>` returns an
      ActivityStreams Person with a `publicKey` block whose `id`
      matches the `key_id` stamped on `ap_federation_outbox` rows
      (`<actor>#main-key`) and whose `publicKeyPem` decodes to the
      Ed25519 public key derived by `relay.synthetic_keys`. A
      Mastodon-side strict-verifying peer accepts a delivery from
      the bridge in a manual integration run.

- [ ] **A2. AT synthetic-DID key publication.**
      Acceptance: AT `com.atproto.identity.resolveDid` / DID document
      for a synthetic did:web actor lists the verification method
      backing the Ed25519 key the bridge signs commits with. A
      Bluesky-style relay client validates the commit signature
      against the published key.

- [~] **A3. Delete / Undo translation, both directions.**
      AP→AT *done* (commit b488d4d follow-up): Delete activities
      probe each bridged collection and remove the matching
      `atp_records` row; unknown object_ids become a logged no-op.
      AT→AP *still open*: the firehose consumer doesn't yet fire on
      record deletions (no firehose-deletion event today). Split
      into A3a (done) + A3b (open).
      Acceptance for A3b: deleting an AT record emits an AP Delete
      activity into `ap_federation_outbox`.

- [ ] **A4. Update translation, both directions.**
      Acceptance: AP `Update{Note}` mutates the bridged
      `atp_records` row in place (CID changes; firehose event
      emitted). AT record updates produce AP `Update` activities.

- [ ] **A5. Move + Block activity translation.**
      Acceptance: AP `Move`, `Block`, `Flag` activities each produce
      a translation-log entry referencing the bridged AT analogue
      (or land in a "consciously dropped" log with rationale).

- [ ] **A6. Activity coverage for `app.bsky.graph.listitem`, `app.bsky.feed.threadgate`, `app.bsky.graph.list`.**
      Acceptance: each of those AT collections produces a
      translation-log entry (or is logged as explicitly out-of-scope
      with the reason). Today they hit the silent-skip path.

- [ ] **A7. Idempotency on replay.**
      Acceptance: replaying the same firehose seq through the
      consumer twice produces exactly one outbox row + one
      atp_records mutation. Today the consumer uses (did, ts) which
      is precise *enough* under sane clock skew; an idempotency key
      tied to `at_uri` would make this airtight.

- [ ] **A8. Bridge stops cleanly under shutdown.**
      Acceptance: SIGINT during a steady-state bridge run drains
      the in-flight ring, flushes the outbox enqueues, and exits
      with no panic and no leaked threads. (Already mostly working;
      needs an explicit shutdown phase order check.)

---

## B. Follower / fanout model

- [ ] **B1. Per-synthetic-actor follower table.**
      Acceptance: a `relay_followers` table maps
      `(synthetic_actor, follower_inbox, shared_inbox)`. Seeded via
      AP `Follow` activities landing in the inbox for synthetic
      actors (no admin route needed for the happy path).

- [ ] **B2. AT→AP fanout uses the follower table, not a single env target.**
      Acceptance: when N AP peers follow a synthetic actor, one AT
      commit produces N `ap_federation_outbox` rows. The
      `RELAY_BRIDGE_AP_TARGET` env knob becomes a *fallback* (or is
      removed entirely with a deprecation notice).

- [ ] **B3. Admin route `/relay/followers` to inspect + force-seed.**
      Acceptance: `GET /relay/followers?actor=<synth>` lists the
      follower set. `POST /relay/followers` (admin auth) injects an
      entry for test or migration scenarios.

- [ ] **B4. Unfollow propagation.**
      Acceptance: AP `Undo{Follow}` removes the follower row;
      subsequent AT commits do not deliver to that inbox.

- [ ] **B5. Outbox depth → consumer backpressure feedback.**
      Acceptance: when `ap_federation_outbox` row count exceeds a
      configurable cap, the relay consumer pauses translation (does
      not drop firehose events — they're durable in the AT firehose
      table) until the depth recedes. Surfaced via `/metrics`.

---

## C. TLS / WSS edges

- [ ] **C1. HTTPS-fronted WebSocket data plane.**
      Acceptance: a WSS client connects to
      `/api/v1/streaming/user` against a TLS-enabled boot,
      negotiates the upgrade, sends + receives one binary frame
      with the expected payload. Integration test
      `tests/integration/wss_loopback.zig` passes deterministically.

- [ ] **C2. Multi-SNI cert dispatch.**
      Acceptance: with `TLS_SNI_CERTS=host1=...,host2=...` set, two
      `tls.Client` connections targeting different SNIs each
      receive their own cert chain. Either ianic upstream gains a
      `cert_selector` callback or a pre-handshake peek is added.

- [ ] **C3. Per-socket connect / read timeouts on the outbound client.**
      Acceptance: `core.http_client.Request.timeout_ms = 1000`
      against an unreachable host returns within 1 ± 0.2 s rather
      than hanging until the kernel default. Blocked on upstream
      `std.Io.net`.

- [ ] **C4. TLS cert hot-reload.**
      Acceptance: SIGHUP (or `POST /admin/tls/reload`) causes the
      inbound TLS backend to re-read `TLS_CERT_PATH` /
      `TLS_KEY_PATH` from disk without dropping in-flight
      connections. New connections negotiate against the new cert.

- [ ] **C5. Cert pinning hook on the outbound TLS path.**
      Acceptance: `core.tls.native_outbound` exposes an optional
      pin-verification callback. Federation requests to a pinned
      host fail closed when the cert chain doesn't match the pin.

---

## D. Storage / concurrency

- [ ] **D1. Single-writer-thread invariant for all atp_records / atp_commits writes.**
      Acceptance: the relay's commit path routes through
      `core.storage.Channel` / `Writer` rather than calling
      `sqlite3_prepare_v2` from the AP HTTP thread + the firehose
      consumer thread directly. `SQLITE_OPEN_NOMUTEX` race surface
      shrinks to one thread. A stress test with concurrent inbound
      AP requests + AT firehose traffic runs 60 s with zero panics.

- [ ] **D2. Per-thread reader connections.**
      Acceptance: the firehose consumer + Mastodon API handlers
      each get their own `openReader` connection (WAL allows N
      readers + 1 writer). Sqlite locking errors disappear from
      the panic surface.

- [ ] **D3. Multi-level storage for the AT firehose hot path.**
      Acceptance: TickStream's `fixed_multilevel.zig` (or an
      in-tree equivalent) replaces direct
      `INSERT INTO atp_firehose_events`. L0 holds the latest 10k
      events in memory, L1 batches to disk every N ms, SQLite
      `atp_firehose_events` becomes the manifest. Bench shows
      ≥10× throughput on firehose append vs the current path.

- [ ] **D4. AT MST persistence (block storage) rather than full reload per commit.**
      Acceptance: `atproto.repo.commit` does not call `loadTree` on
      the full record set every time. Tree blocks live in
      `atp_mst_blocks` and are loaded lazily. p99 commit latency
      stops growing linearly with record count.

- [ ] **D5. Database migration safety on upgrade.**
      Acceptance: a CI step boots speedy-socials against a db
      created by the previous tagged release and verifies every
      route serves a 200 / 4xx (no 500s from missing tables /
      columns).

---

## E. Observability

- [ ] **E1. `iops` request-latency histogram on `/metrics`.**
      Acceptance: `/metrics` exposes
      `http_request_duration_seconds_bucket` with at least p50, p95,
      p99 calculable. Driven by the vendored
      `core.stdx.IOPSType`. Smoke test: drive 1000 requests, assert
      histogram total count matches.

- [ ] **E2. Per-protocol counters.**
      Acceptance: `relay_translated_total{direction="at_to_ap"}` and
      `{direction="ap_to_at"}` increment on every translation.
      `ap_outbox_depth`, `firehose_consumer_dropped_total` exposed.

- [ ] **E3. Chrome-format tracing (vendored `trace.zig`).**
      Acceptance: `zig build -Dtrace=true` produces a Chrome trace
      JSON viewable in `chrome://tracing`. Spans cover `accept →
      route → handler` and `firehose append → consumer translate →
      outbox enqueue`. Either vendor TB's `trace.zig` with the
      transitive deps, or write a thin in-tree shim.

- [ ] **E4. Structured access log.**
      Acceptance: every HTTP request emits a single ring-log line
      with method, path, status, duration_ms, request_id.
      `core.log` learns an access-log severity that doesn't compete
      with application warns/errors.

- [ ] **E5. Per-route latency in the ring log.**
      Acceptance: the access log line carries `route_pattern`
      (e.g. `/api/v1/statuses/:id`) so post-hoc analysis groups
      sanely.

- [ ] **E6. `bench/baseline.json` regression gate in CI.**
      Acceptance: CI step runs `zig build bench`, compares to
      `baseline.json`, fails when any metric regresses > 5% (or a
      configurable threshold). Baseline refreshed via an opt-in
      flag.

---

## F. Operational

- [ ] **F1. Graceful drain on shutdown.**
      Acceptance: SIGTERM with `SHUTDOWN_GRACE_MS=10000` set
      finishes in-flight HTTP requests, flushes the AP outbox
      retry queue's nearest-due window, and joins the firehose
      consumer + AP outbox worker before exit. Zero panics, zero
      half-written rows.

- [ ] **F2. Health route deep-checks.**
      Acceptance: `/healthz` returns 200 on quick liveness;
      `/readyz` exercises DB writer, AP outbox worker, firehose
      consumer, and TLS cert validity (expiry within N days fails
      ready). Failure modes are visible in the response body.

- [ ] **F3. Config from a single file (TOML or JSON) in addition to env.**
      Acceptance: `--config /etc/speedy-socials/config.toml` is
      honoured. All env-var knobs (`TLS_*`, `MEDIA_ROOT`,
      `RELAY_BRIDGE_AP_TARGET`, `RELAY_SYNTHETIC_KEY_PEPPER`, etc.)
      have equivalents. CLI flags win over env over file.

- [ ] **F4. Dockerfile multi-arch build (linux/amd64 + linux/arm64).**
      Acceptance: `docker buildx build --platform linux/amd64,linux/arm64`
      produces a working image on both architectures. Single CI job
      pushes a multi-arch manifest.

- [ ] **F5. Backup / restore documented + tested.**
      Acceptance: a one-page runbook describes how to snapshot the
      SQLite WAL + media root and restore on a fresh host. A CI
      step exercises the round trip.

- [x] **F6. `MEDIA_ROOT` configurable + survives container restart.**
      Acceptance: `MEDIA_ROOT=/var/lib/speedy-socials/media` is
      respected; existing oversize blobs are still readable after a
      restart. (W5.5 hardcoded `./media` — make it env-driven.)

---

## G. Security

- [ ] **G1. Magic-login / test-bypass removed in release builds.**
      Acceptance: a build with `-Drelease` rejects the dev
      shortcuts (verified by a test that exercises the auth paths
      in release mode). Per the CLAUDE.md baseline rule.

- [ ] **G2. Audit log for sensitive operations.**
      Acceptance: role changes, exports, key rotations, follower
      seeding, cert reloads each write to an append-only
      `audit_log` table with actor, action, target, timestamp.

- [ ] **G3. Rate limiting on inbound AP inbox + Mastodon API.**
      Acceptance: a single IP exceeding N requests / second gets
      429s. Token-bucket implementation, configurable per route.

- [ ] **G4. HTTP signature strict-verify mode behind a flag.**
      Acceptance: `STRICT_HTTP_SIG=1` rejects inbox POSTs that
      arrive without a verifiable signature (today the route
      accepts unverified activities with a soft-warn). Default
      stays soft for compatibility.

- [ ] **G5. Request-body size cap per endpoint.**
      Acceptance: AP inbox accepts ≤256 KiB, media accepts ≤8 MiB,
      streaming endpoints accept 0 (upgrade-only). Anything larger
      returns 413 before the body finishes streaming.

- [x] **G6. Sanitize errors before they leave the process.**
      Acceptance: no stack traces, file paths, or sqlite error
      strings appear in HTTP responses. Errors map to opaque codes
      + the underlying detail goes to the ring log.

---

## H. Multi-tenancy (deferred but listed for completeness)

- [ ] **H1. Per-vhost plugin registries.**
      Acceptance: one process serves `instance1.example` and
      `instance2.example` with isolated storage + identity. Routes
      dispatch by Host header to a tenant-specific Registry.

- [ ] **H2. Tenant ID propagated through every query.**
      Acceptance: every SQL statement that touches user-owned data
      includes a `tenant_id` predicate. A static analysis pass (or
      review checklist) verifies coverage.

- [ ] **H3. Tenant lifecycle routes.**
      Acceptance: admin can create / suspend / delete a tenant
      without touching the filesystem. Suspended tenants return 503
      on all routes.

---

## I. Activity-type coverage matrix (cross-cutting; pairs with A3–A6)

- [ ] **I1. Translation matrix doc.**
      Acceptance: `docs/design/translation-matrix.md` lists every
      AP activity type × AT collection and marks each cell as
      bridged / dropped / impossible with a rationale.

- [ ] **I2. AT `app.bsky.actor.profile` → AP `Person` updates.**
      Acceptance: changes to the synthetic AT actor's profile
      record propagate to the AP `Person` document the relay
      serves. Test: edit profile, fetch AP actor, see the change.

- [ ] **I3. AP `Person` updates → AT profile record.**
      Acceptance: when an AP `Update{Person}` arrives for an actor
      we mirror, the corresponding AT `app.bsky.actor.profile` row
      is updated.

---

## J. Determinism / testing

- [ ] **J1. Cross-protocol sim covers Delete, Update, follow + unfollow.**
      Acceptance: `tests/sim/relay_bridge_scenario.zig` grows from
      "Create round trip" to "full Create / Update / Delete /
      Follow / Unfollow round trip" with a fixed PRNG seed.

- [ ] **J2. Chaos sim: deliver during AT firehose ring overflow.**
      Acceptance: a scripted scenario sustains an AT append rate
      that overflows the consumer ring, verifies the
      `firehose_consumer_dropped_total` counter advances, and
      confirms that re-running with a fresh consumer recovers all
      missed events via persistent table replay.

- [ ] **J3. Long-running deterministic-replay test.**
      Acceptance: 1 hour of simulated firehose traffic under a
      fixed seed produces byte-identical translation log + outbox
      state across two runs.

- [ ] **J4. Fuzz the relay translators with random AP activity bodies.**
      Acceptance: 10k random-but-valid AP `Create{Note}` /
      `Like` / `Announce` / `Follow` activities feed
      `relay.ap_to_at.onActivityReceived` without a panic. Builds
      on the vendored TB fuzz helpers.

- [ ] **J5. Integration test against a real Mastodon dev pod.**
      Acceptance: a CI job (skippable for offline branches) brings
      up a Mastodon dev image, points the bridge at it, and
      exercises one Create + Like + Follow round trip end-to-end.

---

## K. Documentation

- [ ] **K1. `docs/design/protocol-relay.md` updated post-W6.**
      Acceptance: the doc reflects "translations actually commit /
      enqueue," documents the synthetic key + pepper scheme, and
      links to A1/A2 as the known interop gap.

- [ ] **K2. Operator runbook.**
      Acceptance: `docs/ops/runbook.md` describes startup,
      shutdown, key rotation, cert renewal, backup, and the most
      common failure modes (consumer ring overflow, AP outbox
      backed up, sqlite WAL grew).

- [ ] **K3. CONTRIBUTING.md.**
      Acceptance: clear instructions on `zig build test`, `zig
      build sim`, when to add a new TB / TickStream vendor, the
      Tiger Style invariants (no hot-path alloc, bounded buffers,
      no panic), and how the plugin contract works.

- [ ] **K4. Public API surface review.**
      Acceptance: every `pub fn` in `src/core/` has either a doc
      comment or is named obviously enough to forgo one. Run
      `zig build docs` (if/once supported) without warnings.

---

## L. Cleanups noticed during W4–W6

- [x] **L1. Remove the `MEDIA_ROOT` hardcode (`./media`) — use env.**
      Acceptance: `src/app/main.zig` reads the env value once at
      boot; no path string lives in source. Pairs with F6.

- [ ] **L2. Promote `tickstream` to a real submodule or write its absence into the README.**
      Acceptance: either `.gitmodules` lists a tickstream entry
      with a verified URL, or `third_party/README.md` explicitly
      states "TickStream is referenced as inspiration only; no
      vendored code." Closes the W4 pivot ambiguity.

- [ ] **L3. Trim dead `_ = stored_inline` style discards from
      media routes.**
      Acceptance: zig 0.16's "pointless discard" check passes
      cleanly with `-Werror`-equivalent strictness.

- [ ] **L4. Boring_inbound retained-but-unused warning.**
      Acceptance: the file's doc comment makes explicit that it's
      kept as an alternative backend, and tests for it still run
      under `zig build test` so it doesn't bit-rot.

- [ ] **L5. `RsaSignNotImplemented` error variant is now reachable only when OpenSSL is unlinkable; rename or remove.**
      Acceptance: dead-error-variant audit produces a clean list;
      `ap.http_delivery` either always has signing available or
      surfaces a different error.

---

## How to use this list

- Treat each `- [ ]` as a single ticket.
- "Done" means the acceptance criterion is verifiable on a CI
  run, not "the code compiles."
- When you tick an item, write the commit SHA (or short note)
  next to it for forensic value:
  `- [x] A1. (commit abc1234)`.
- Reorder freely. The section grouping is a reading aid, not a
  dependency tree.
- If an item turns out to need decomposition mid-work, split it
  here rather than letting the original entry sprawl.
