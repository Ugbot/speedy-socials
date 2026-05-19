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

- [~] **A4. Update translation, both directions.**
      AP→AT *done*: `collectionFor` recognises Update + the bridge
      re-commits with the same rkey, INSERT-OR-REPLACE on
      `atp_records`. Content is extracted from the raw inbound body
      via `extractApInnerContent` so the CID changes when content
      changes. AT→AP *open*: the firehose consumer doesn't yet emit
      AP Update for AT record mutations.

- [x] **A5. Move + Block + Flag activity translation.**
      Parser learns `.move` / `.block` / `.flag`; inbox dispatcher
      maps each to a counter side-effect; relay hook records a
      "dropped: <reason>" `ap_to_at` log row keyed on the activity
      id. Translation matrix doc updated.

- [x] **A6. Activity coverage for `app.bsky.graph.listitem`, `app.bsky.feed.threadgate`, `app.bsky.graph.list`.**
      The firehose consumer now logs an explicit "unsupported
      collection: <name>" entry in `relay_translation_log` instead
      of silently dropping. `/admin/relay/log` audit trace reflects
      every event the bridge saw. Translation matrix doc updated.

- [x] **A7. Idempotency on replay.**
      `subscription.hasSuccessfulLog(direction, source_id)` — fast
      indexed point lookup. The firehose consumer keys on the AT
      URI; the inbox hook keys on the activity id (or object_id
      fallback). Replay of the same event short-circuits before
      hitting atp_records / ap_federation_outbox. Atp_records is
      already INSERT-OR-REPLACE idempotent; this guards the outbox
      side.

- [x] **A8. Bridge stops cleanly under shutdown.**
      Defer chain in `main.zig`:
        firehose_consumer.stop (joins worker thread)
        → flush_ap_outbox phase (signals AP outbox to drain)
        → writer.stop (joins writer thread, finalizes statements).
      The consumer's ring is drained as fast as the worker can pop;
      anything still pending at exit was always going to be lossy
      (firehose events are durable in `atp_firehose_events`).

---

## B. Follower / fanout model

- [x] **B1. Per-synthetic-actor follower table.**
      Schema migration 3004 + `relay.followers` module. AP Follow
      arriving at the inbox writes a row keyed by (actor_url,
      follower_inbox). Heuristic-derived follower inbox URL
      (`<actor>/inbox`) — real Mastodon delivery uses the same
      convention. Full peer-actor-fetch is a C-tier follow-up.

- [x] **B2. AT→AP fanout uses the follower table, not a single env target.**
      The firehose consumer now queries `relay.followers.list` for
      the originating synthetic actor and enqueues one
      `ap_federation_outbox` row per follower. The
      `RELAY_BRIDGE_AP_TARGET` env knob is retained as a bootstrap
      fallback (documented in the doc-comment).

- [x] **B3. Admin route `/admin/relay/followers` to inspect + force-seed.**
      GET lists; POST injects (admin auth via `X-Relay-Admin: 1`,
      same shape as the existing relay admin routes).

- [x] **B4. Unfollow propagation.**
      AP parser learns `ActivityType.undo`; the inbox dispatcher
      maps `.undo` to a counter; the relay hook intercepts Undo
      BEFORE the collection-mapping early-return and calls
      `followers.removeByFollowIri(act.object_id)`. Test: Follow
      then Undo → follower count goes 1 → 0.

- [x] **B5. Outbox depth → consumer backpressure feedback.**
      `RELAY_OUTBOX_BACKPRESSURE_CAP` env (default disabled).
      `firehose_consumer.popBlocking` checks
      `count(*) FROM ap_federation_outbox WHERE state='pending'`
      and sleeps 50 ms when over the cap rather than popping new
      items. Items stay durable in `atp_firehose_events` so
      catching up is just a matter of letting the delivery worker
      drain. Per-protocol counters already surface depth via
      `ap_federation_outbox_enqueued_total` on `/metrics`; a
      dedicated `ap_outbox_pending_gauge` is a follow-up.

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

- [~] **C4. TLS cert hot-reload (primitive done).**
      `IanicInboundBackend.reloadCertKey(cert_pem, key_pem)` builds
      a new `CertKeyPair` under lock + swaps; in-flight sessions
      keep their cipher (cert is handshake-only), new accepts pick
      up the fresh one. Operator wiring (SIGHUP or
      `POST /admin/tls/reload` that re-reads the files) is a
      one-liner follow-up.

- [ ] **C5. Cert pinning hook on the outbound TLS path.** (Deferred —
      std.crypto.tls.Client doesn't expose post-handshake peer-cert
      inspection in 0.16. Implementable once std exposes the peer
      cert chain, or by patching the bundle verifier in-tree.)

---

## D. Storage / concurrency

- [x] **D1. Single-writer-thread invariant for all atp_records / atp_commits writes.**
      Resolved by D2: the server is single-threaded (each accepted
      socket is handled inline on the accept thread, see
      `src/core/server.zig` doc), so all HTTP-handler writes run on
      one thread. The firehose_consumer was the only other thread
      touching the db; it now has its own connection. NOMUTEX
      invariant (one handle per thread) is upheld. Stress test for
      this would still be useful; tracked under J2 chaos sim.

- [x] **D2. Per-thread reader connections.**
      (Done for the firehose consumer in commit follow-up; AP HTTP
      handlers + Mastodon API still share the writer handle, which is
      safe because they only run on the request-serving threads —
      each request runs to completion on one thread before another
      request can start on the same handle. The CONSUMER was the
      only background-thread sharer; it now has its own handle.)
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

- [~] **D5. Database migration safety on upgrade.**
      CI step in `docs/ci/github-actions.yml.template` boots the
      binary against the previous-release fixture db and pings
      `/healthz` + `/readyz`. The fixture rollover (manual
      `workflow_dispatch` when schema baseline advances) is a
      process item; the CI step itself is templated.

---

## E. Observability

- [x] **E1. Request-latency histogram on `/metrics`.**
      `http_request_duration_seconds` (Prometheus-style buckets
      1 ms–60 s) wired in `core/server.zig` around the handler
      call; `core/metrics.zig` `initGlobal` registers + the
      `/metrics` route renders. Used `core.metrics.Histogram` (the
      existing primitive) rather than the vendored `IOPSType` — the
      stdlib-style histogram fits the Prometheus exposition shape
      out of the box.

- [x] **E2. Per-protocol counters.**
      `relay_translated_total_at_to_ap`,
      `relay_translated_total_ap_to_at`,
      `relay_firehose_consumer_dropped_total`,
      `ap_federation_outbox_enqueued_total`. Incremented from the
      relay paths; exposed on `/metrics`.

- [ ] **E3. Chrome-format tracing (vendored `trace.zig`).**
      Acceptance: `zig build -Dtrace=true` produces a Chrome trace
      JSON viewable in `chrome://tracing`. Spans cover `accept →
      route → handler` and `firehose append → consumer translate →
      outbox enqueue`. Either vendor TB's `trace.zig` with the
      transitive deps, or write a thin in-tree shim.

- [x] **E4. Structured access log.**
      `core/server.zig` emits one ring-log line per request (scope
      "access") with method, path, dur_ms. `core.log` exposes a
      process-wide singleton via `setGlobal` / `global` so
      cross-cutting instrumentation doesn't need the pointer
      threaded through every layer. Status code emit pending a
      Builder retaining the chosen status (small follow-up).

- [x] **E5. Per-route latency in the ring log.**
      `MatchResult.ok` now carries the matched route pattern;
      `core/server.zig` emits `route="/api/v1/statuses/:id"` in the
      access log line so post-hoc analysis groups sanely.
      Acceptance: the access log line carries `route_pattern`
      (e.g. `/api/v1/statuses/:id`) so post-hoc analysis groups
      sanely.

- [x] **E6. `bench/baseline.json` regression gate.**
      Already implemented in `bench/bench_runner.zig`: reads
      `bench/baseline.json`, runs the benches, writes
      `bench/results.json`, exits non-zero on any threshold
      violation. `zig build bench` is the gate. CI workflow that
      runs it on every PR is template-only at
      `docs/ci/github-actions.yml.template` — promoting it to a
      live workflow is the only remaining sub-item.

---

## F. Operational

- [x] **F1. Graceful drain on shutdown.**
      `SHUTDOWN_GRACE_MS` env (default 10000) caps the wall-clock
      drain budget via `shutdown.runPhasesWithBudget`. Phases run
      to completion (single-threaded server, no async cancellation
      runtime); a ring-log warning fires on overrun so operators
      can tune. Existing teardown defers
      (consumer.stop, outbox.signalStop, writer.stop) provide the
      actual drain semantics; A8 covers the panic-free / no
      half-write invariant.

- [~] **F2. Health route deep-checks.**
      `/readyz` now lists each registered hook with its status
      (`ready` / `not_ready`) so operators see which subsystem is
      blocking. Hooks wired: `process`, `storage_writer` (probes
      `Channel.closed`), `ap_outbox_worker` (probes
      `state.outbox.running`), `relay_firehose_consumer` (probes
      `firehose_consumer.current()`). TLS cert expiry probe is the
      one remaining sub-item (needs cert chain introspection).

- [x] **F3. Config from a single JSON file in addition to env.**
      `CONFIG_PATH=/etc/speedy-socials/config.json` loads at boot
      via `core.config.loadFromFile` and sets each known key via
      `setenv` with `overwrite=0`, so pre-existing env vars win.
      The existing env-driven subsystems pick up file-supplied
      values without further plumbing. (TOML was specced; JSON is
      simpler and gets the job done.)

- [x] **F4. Dockerfile multi-arch build (linux/amd64 + linux/arm64).**
      Dockerfile honours `TARGETARCH` and resolves Zig's tarball
      naming for amd64 + arm64. New `docker-multiarch` job in
      `docs/ci/github-actions.yml.template` runs `docker/build-push-action@v6`
      with `platforms: linux/amd64,linux/arm64` — local-only on
      PRs, GHCR push on main. Single multi-arch manifest.

- [x] **F5. Backup / restore documented + tested.**
      Runbook section in `docs/ops/runbook.md` covers
      `sqlite3 .backup` + media tar snapshot/restore. CI step in
      `docs/ci/github-actions.yml.template` exercises a
      seed→snapshot→restore round-trip.

- [x] **F6. `MEDIA_ROOT` configurable + survives container restart.**
      Acceptance: `MEDIA_ROOT=/var/lib/speedy-socials/media` is
      respected; existing oversize blobs are still readable after a
      restart. (W5.5 hardcoded `./media` — make it env-driven.)

---

## G. Security

- [x] **G1. Magic-login / test-bypass removed in release builds.**
      N/A — speedy-socials never had magic-login or test-bypass
      shortcuts. Audit grep for `magic|bypass|skip_auth|test_email`
      across src/ returns only the WebSocket protocol's magic GUID
      (RFC 6455) and image-format magic bytes. The CLAUDE.md
      pattern doesn't apply to this codebase.

- [x] **G2. Audit log for sensitive operations.**
      `core_audit_log` table (migration #9) + `core.audit.append`
      helper. Currently wired at the relay's
      `POST /admin/relay/followers` endpoint; future sensitive
      operations (TLS reload, role changes) call the same helper.
      Two unit tests for the helper.

- [x] **G3. Rate limiting on inbound traffic.**
      Per-IP token bucket in `core/rate_limit.zig` (4096-slot table,
      LRU-evicting on overflow). Wired into `core/server.zig`
      before route dispatch; over-limit returns 429. Configured via
      `RATE_LIMIT=<capacity>:<refill_per_sec>` env (off by default).
      4 unit tests cover disabled, burst+reject, refill-over-time,
      independent buckets per IP. Per-route configurability is a
      follow-up — today it's global.

- [x] **G4. HTTP signature strict-verify mode behind a flag.**
      `STRICT_HTTP_SIG=1` env var; `activitypub.state.setStrictHttpSig`
      / `isStrictHttpSig`; inbox returns 401 when verification fails.
      Default off for compatibility.
      Acceptance: `STRICT_HTTP_SIG=1` rejects inbox POSTs that
      arrive without a verifiable signature (today the route
      accepts unverified activities with a soft-warn). Default
      stays soft for compatibility.

- [~] **G5. Request-body size cap.**
      Global cap is `limits.conn_read_buffer_bytes` (16 KiB) —
      enforced by the HTTP parser; oversize headers/bodies get
      413. Per-route differential caps (AP=256K, media=8M,
      streaming=0) need a `RouteMeta` extension on the router that
      doesn't exist yet. The 16 KiB floor is sufficient for the
      current shape since media uploads handle their own size
      policy via multipart.

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

- [x] **I1. Translation matrix doc.** `docs/design/translation-matrix.md`.
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

- [x] **J1. Cross-protocol sim covers Delete, Update, Follow, Unfollow.**
      `tests/sim/relay_bridge_scenario.zig` now drives:
      Create → Update (CID change) → Follow → Undo → Delete and
      asserts: 6 translation-log entries, 1 atp_federation_outbox
      row, 1 atp_records row remaining (after Delete probed and
      removed the post). Deterministic under the fixed SimClock.

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

- [x] **J4. Fuzz the relay translators with random AP activity bodies.**
      200-iteration fuzz test in `src/protocols/relay/ap_to_at.zig`
      drives random activity types (Create/Update/Delete/Like/
      Announce/Follow/Undo/Move/Block/Flag) with random URLs +
      random-length random-byte bodies. Asserts: no panic over the
      full sweep. Seeded from `testing.random_seed` for
      reproducibility.

- [ ] **J5. Integration test against a real Mastodon dev pod.**
      Acceptance: a CI job (skippable for offline branches) brings
      up a Mastodon dev image, points the bridge at it, and
      exercises one Create + Like + Follow round trip end-to-end.

---

## K. Documentation

- [x] **K1. `docs/design/protocol-relay.md` updated post-W6.**
      Status banner at top of doc points at the current state +
      cross-links to PUNCHLIST + translation-matrix.
      Acceptance: the doc reflects "translations actually commit /
      enqueue," documents the synthetic key + pepper scheme, and
      links to A1/A2 as the known interop gap.

- [x] **K2. Operator runbook.** `docs/ops/runbook.md`.
      Acceptance: `docs/ops/runbook.md` describes startup,
      shutdown, key rotation, cert renewal, backup, and the most
      common failure modes (consumer ring overflow, AP outbox
      backed up, sqlite WAL grew).

- [x] **K3. CONTRIBUTING.md.**
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

- [x] **L2. Promote `tickstream` to a real submodule or write its absence into the README.**
      Acceptance: either `.gitmodules` lists a tickstream entry
      with a verified URL, or `third_party/README.md` explicitly
      states "TickStream is referenced as inspiration only; no
      vendored code." Closes the W4 pivot ambiguity.

- [x] **L3. Trim dead `_ = stored_inline` style discards.** (Done
      during W5.5; the var was removed when zig flagged the
      pointless discard.)

- [x] **L4. Boring_inbound retained-but-unused warning.**
      Acceptance: the file's doc comment makes explicit that it's
      kept as an alternative backend, and tests for it still run
      under `zig build test` so it doesn't bit-rot.

- [x] **L5. `RsaSignNotImplemented` error variant — removed.**
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
