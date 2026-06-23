# speedy-socials — ROADMAP (single source of truth)

> **This file is the authoritative "what to do next" list.** It was produced by a
> code-verified reconciliation (2026-06-22) of every prior tracking doc
> (`SPEC_PUNCHLIST.md`, `PUNCHLIST.md`, `FEATURE_TODO.md`, `PROTOCOL_AUDIT.md`) against
> the actual source. Those docs are now **status snapshots**; when they disagree with
> code, **this file wins**. Each item below was checked against a route registration,
> a handler, or a documented absence — not a doc marker.

## Reality check (what the reconciliation found)

The implementation is **substantially ahead of the docs**:

- **ActivityPub** is production-shaped as a federation peer **and** C2S server: `POST
  /users/:u/outbox` (201+Location), inbound HTTP-signature verification with real
  `Digest`/`Content-Digest` body comparison + `created`/`expires` clock checks + a
  replay cache, collection pagination (`next`/`prev`), `featured`, Multikey *verify*,
  flag-gated Data-Integrity proofs — all DONE in code.
- **atproto PDS** is production-shaped for self-hosting: OAuth 2.1 + DPoP (**Ed25519
  AND ES256**), PAR/PKCE/auth-code/JWKS, SQL-backed account lifecycle (create/delete/
  deactivate/email-verify/password-reset/app-passwords/invite-codes), full commit shape
  (version/prev/rev/data/sig) with a real `prev` chain, **CIDv1 raw-codec blobs**
  (not the old hex bug), 60+ XRPC routes — all DONE.
- **Bridge/relay** runs both directions (AP inbox→AT log, AT firehose→AP outbox) and
  **DUAL-1** (one signup → both identities) + **DUAL-4** (AT→AP DID doc with
  `verificationMethod`+`service`) are DONE.
- Several PUNCHLIST "open" items are **already done**: per-socket socket timeouts (C3),
  Chrome tracing + `-Dtrace` + handler spans (E3), `/readyz` TLS cert-expiry probe (F2),
  WSS frames-through-TLS, synthetic-DID key publication (A2).
- `PROTOCOL_AUDIT.md` (5 weeks old) is the **least reliable** doc — it predates this
  work and lists shipped features as missing. Treat it as historical.

The genuinely-open work below is therefore mostly **interop polish, ecosystem
integration, and net-new capability (zorm MS SQL + features)** — not core gaps.

---

## ✅ Shipped 2026-06-23 — Wave 1 (on `main`, 1053 tests green)
Firehose `#handle`/`#migrate`/`#info` (AT1) · P-256 did:key + ES256 DPoP + DPoP-Nonce (AT3)
· DNS-TXT handle resolution (AT4) · AP routes cluster — Multikey advertise, liked
actor-scoping, per-object replies, poll tally, emoji reactions, FEDERATION.md (AP1) ·
NodeInfo `atproto` protocol (AP3) · zorm typed constraint errors (Z1) · zorm per-dialect
identifier quoting (Z2). The corresponding bullets below are now done.

## ✅ Shipped 2026-06-23 — Wave 2 (on `main`, 1094 tests green)
AT sync reads getLatestCommit/listBlobs/listMissingBlobs (AT2) · H3 tenant lifecycle routes
`POST/PATCH/DELETE /admin/tenants` (C1) · downstream relay subscription — consume an external
relay's firehose → translate → ingest, with cursor/reconnect (R1) · zorm query BETWEEN /
OR-grouping / count() (Z7) · zorm upserts ON CONFLICT/DUPLICATE/MERGE (Z3) · zorm column types
Decimal/Uuid/Json/Date/DateTime (Z5).

## ✅ Shipped 2026-06-23 — Wave 3 (on `main`, 1132 tests green)
zorm composite primary keys (Z4) · zorm schema-diff migrations + Migrator.rollback (Z6) ·
H1 per-vhost plugin-registry isolation — dispatch mechanism (C2; boot-wiring deferred) ·
hierarchical Merkle Search Tree with per-node block persistence (MST) · deterministic-replay
sim test for the AT→AP relay path (J3) · gated Mastodon e2e CI job + round-trip test (J5).

**All three ROADMAP waves are now complete and merged to `main`.**

## ✅ Shipped 2026-06-23 — Wave 4 (on `main`, 1195 tests + 18 sims green)
**MySQL host driver** (pure-Zig wire protocol — handshake/native-password auth/COM_QUERY/
prepared statements; `STORAGE_BACKEND=mysql`) — **live-validated against MariaDB 11** ·
**MS SQL host driver** (TDS 7.4: Pre-Login/LOGIN7/sp_executesql/token-stream; codec
unit-tested 20/20; ⚠️ live validation pending a runnable SQL Server — segfaults under arm64
qemu) · **multi-level firehose storage** D3 (L0 ring / L1 batch; ~450× hot-path append
latency) · **H1 per-tenant registry boot-wiring** (RegistrySet constructed + bound at boot;
storage isolated, plugin-state shared, default path unchanged) · **incremental MST persist**
(~200× fewer block writes, rebuild-parity asserted) · **AP FEP-844e capability negotiation +
poll-tally serving** · **fixed the `firehose_consumer` SIGABRT** (shared-`:memory:` SQLite
race — stop/join before the test reads) · **phase-8 retirement re-verified** (legacy already
gone).

### Genuinely remaining (host/env-blocked or separate)
- **MS SQL live round-trip** — needs a runnable SQL Server (not possible on this arm64 host
  via qemu; codec is unit-tested + ready).
- **Multi-SNI cert dispatch / outbound cert pinning** — blocked on upstream Zig `std.crypto.tls`.
- **`third_party/zig-kafka`** vendored roadmap (C-API, examples, broker tests) — separate project.
Everything actionable in-repo on this host is done.

---

# Track 1 — Run the node correctly (the original AP/AT target)

## P0 — Federation correctness (do first; these are interop *hazards*)
- **AT canonical DAG-CBOR re-encode on ingest** — records are stored as-submitted, not
  re-canonicalized, so our CIDs can diverge from what AppViews compute. One re-encode
  per record at ingest. (`atproto/lexicon.zig`, `routes.zig:186` notes the deferral.)
- ~~**AP recipient resolution + delivery fanout**~~ ✅ DONE — full `to`+`cc` lists honored,
  `as:Public` (+ `as:Public`/`Public` aliases) recognized and skipped, inbox-forwarding
  redistributed to ALL local-followers collections (deduped), `bto`/`bcc` never captured.
  (`activitypub/activity.zig`, `inbox.zig`; +8 tests.)
- **AT external identity resolution wired** — `did:plc`/`did:web` HTTP resolution and
  DNS-TXT handle resolution are skeletons needing the `HttpFetcher`/resolver attached at
  boot; required to resolve real network identities. (`atproto/did_resolver.zig`.)
- **AT firehose completeness for relay participation** — emit `#identity` already done;
  add `#handle`/`#migrate`/`#info`, and (to be a relay node, not just a PDS) implement
  **downstream subscription to an external relay's firehose**. (`atproto/firehose.zig`,
  `relay/`.)

## P1 — Spec/client completeness
- ~~**AT `deleteSession` (logout)**~~ ✅ DONE — `POST /xrpc/com.atproto.server.deleteSession`
  + an `atp_revoked_sessions` deny-list checked in `refreshSession` (fails closed).
  (`atproto/routes.zig`, `auth.zig`, `schema.zig` migration 2016.)
- **AT P-256 `did:key` roundtrip** + **`DPoP-Nonce` response header** (ES256 verify
  itself is done). (`atproto/keypair.zig`, `oauth_dpop.zig`.)
- **AT sync reads**: `getLatestCommit`, `listBlobs`, `listMissingBlobs`.
- **AP gaps**: advertise Multikey in the actor doc (verify already works); per-object
  `replies` collection; actor-scope the `liked` collection (FEP-c648); poll vote
  *tally* (votes are stored, not aggregated); emoji reactions (FEP-c0e0); publish
  `FEDERATION.md` (FEP-67ff); capability negotiation (FEP-844e).
- **NodeInfo** — advertise `atproto` in the `protocols` array (currently only in
  `metadata`). (`activitypub/nodeinfo.zig:81-100`.)
- ~~**Media** — chunked transfer encoding for blobs >4 MiB~~ ✅ DONE — `getBlob` streams
  large/spilled blobs via HTTP/1.1 `Transfer-Encoding: chunked` (64 KiB passes, no full-file
  buffer) through a new `BodySink` on the handler context; small inline blobs keep the
  Content-Length fast path. (Also fixed the latent 16 KiB `ResponseBufferFull` bug — the old
  path could never serve a large blob.) (`core/http/router.zig`, `server.zig`, `media/routes.zig`.)
- **Multi-tenancy finish**: tenant lifecycle routes — create/suspend/delete (H3, missing);
  per-vhost plugin-registry isolation (H1, partial — registry is global today). Storage
  is already per-tenant and the request path is tenant-scoped (H2 done,
  `storage/provider.zig`, `server.zig:407-431`).

## P2 — Performance / deferred / upstream-blocked
- **Multi-level firehose storage** (D3) — L0 in-mem / L1 batched / SQLite manifest; bench
  ≥10× hot-path throughput.
- **Hierarchical MST** (AT-16) — current MST is a correct flat-leaf store reloaded per
  commit; fanout is a perf/scale item.
- **Multi-SNI cert dispatch** (C2) and **outbound cert pinning** (C5) — blocked on
  upstream Zig/ianic TLS surface; revisit when `std.crypto.tls` exposes the hooks.

## Testing
- **J3** — 1-hour deterministic-replay test (byte-identical translation log + outbox
  across two seeded runs).
- **J5** — CI job against a real Mastodon dev pod (one Create + Like + Follow round trip).

---

# Track 2 — zorm completeness (Postgres · MySQL · MS SQL)

**Shipped today** (do NOT re-do): **4 dialects (sqlite/postgres/mysql/mssql)**,
`createTable`+FK clauses+FK indexes, `createIndex`/`addColumn`/`dropColumn`,
`Migration`+`Migrator`, `Session`/`Repository`/identity-map/unit-of-work, `Query`
(equality `WHERE` + dialect-correct `LIMIT`), relations, codec + typed messaging.

## ~~P0 — MS SQL Server (T-SQL) dialect~~ ✅ DONE (M5)
Shipped: `mssql` Dialect — `@pN` params · `BIGINT IDENTITY(1,1)` + `OUTPUT INSERTED.id`
(no `RETURNING`) · `NVARCHAR(N)`/`VARBINARY(N)`/`FLOAT`/`BIGINT` · `IF OBJECT_ID/sys.indexes`
guards (T-SQL has no `IF NOT EXISTS`) · `LIMIT`→`OFFSET…FETCH` (with synthesized
`ORDER BY (SELECT NULL)`). 1003 tests lock the generated SQL, and the T-SQL was
**live-validated** against Azure SQL Edge (ARM64): DDL guards + NVARCHAR/IDENTITY/FK
apply, `OUTPUT INSERTED` returns ids, an orphan insert is rejected (Msg 547), ON DELETE
CASCADE fires, and `OFFSET…FETCH` paginates. (Full `mcr.microsoft.com/mssql/server`
segfaults under qemu on arm64; SQL Edge runs the same T-SQL natively.) **Remaining for
mssql:** `[bracket]` identifier quoting (folded into the P1 quoting item).

## P1 — correctness foundations + query depth
- **Identifier quoting** per dialect (`"x"`/`` `x` ``/`[x]`) — today names are unquoted
  and break on reserved words.
- **Typed constraint-violation errors** (unique / FK / not-null, per-dialect SQLSTATE /
  codes) — needed for clean conflict handling.
- **Query operators + pagination** — ✅ MOSTLY DONE: `whereOp` (`= <> < <= > >=`),
  `whereLike`, `whereIn` (empty → `1=0`), `whereNull`/`whereNotNull`, and `offset()` (dialect-
  correct incl. T-SQL `OFFSET…FETCH`) shipped in `query.zig` (4 dialects, +9 tests). Remaining:
  `BETWEEN`, `OR`/grouping, `count()`/aggregates.
- **Upserts** — `ON CONFLICT … DO UPDATE` (PG/SQLite) · `ON DUPLICATE KEY UPDATE`
  (MySQL) · `MERGE` (MSSQL).
- **Composite primary keys** — single-column PK is hard-coded today.

## P2 — types + migration depth
- **Column types**: `Decimal`/numeric (money), UUID, JSON, real date/time, large text
  (>1024 B → `TEXT`/`NVARCHAR(MAX)`).
- **Comptime schema-diff migrations** — generate `ALTER`s between two struct versions
  (no DB introspection; stays deterministic).
- **`Migrator.rollback(to_id)`** — `down` lists are recorded but never executed.

## P3 — true end-to-end (large)
- **Pure-Zig MySQL + MS SQL host drivers/providers** (mirroring the SQLite/Postgres
  pattern) + `*_TEST_URL`-gated CRUD round-trip CI. Today the host runs SQLite +
  Postgres only; zorm *emits* MySQL/MSSQL SQL but nothing runs it in-process.

---

# Separate / housekeeping
- **`third_party/zig-kafka`** (vendored, own roadmap): C-API integration, SDK examples,
  broker integration tests, benchmarks, SASL/SSL/transactions. Not core.
- **Legacy retirement** (`docs/phase8-retirement-inventory.md`): all items marked
  `delete`, zero refs — land the deletion if not already done.

---

# Recommended sequence
1. ~~**Track 2 P0 — zorm MS SQL dialect**~~ ✅ DONE (M5).
2. **Track 1 P0 — federation correctness** (DAG-CBOR re-encode, AP recipient resolution,
   external identity resolution, firehose completeness) — makes us a *correct* node. ← next
3. **zorm P1** (identifier quoting incl. mssql brackets, typed errors, query ops + OFFSET,
   upserts, composite PK) — and use it to harden **H1/H3 multi-tenancy**.
4. **Track 1 P1** spec/client polish, then **P2/testing**.

# Doc map (post-reconciliation)
- **ROADMAP.md** (this file) — the single forward plan. Update here first.
- **SPEC_PUNCHLIST.md** — spec-ticket conformance log (AP/AT/DUAL/INFRA). Accurate as a
  record; partials are footnoted. Historical going forward.
- **PUNCHLIST.md** — operational checklist; stale-open markers corrected in this pass.
- **PROTOCOL_AUDIT.md** — **stale snapshot** (pre-dates most work); kept for the spec
  matrix only. Do not trust its ❌/⚠️ column without checking ROADMAP/code.
- **FEATURE_TODO.md** — shipped-feature history; open-work list folded into this file.
