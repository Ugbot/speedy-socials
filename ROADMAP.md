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

# Track 1 — Run the node correctly (the original AP/AT target)

## P0 — Federation correctness (do first; these are interop *hazards*)
- **AT canonical DAG-CBOR re-encode on ingest** — records are stored as-submitted, not
  re-canonicalized, so our CIDs can diverge from what AppViews compute. One re-encode
  per record at ingest. (`atproto/lexicon.zig`, `routes.zig:186` notes the deferral.)
- **AP recipient resolution + delivery fanout** — only `to_first` and the first
  `cc`-followers match are used; parse/honor full `to`/`cc`/`bcc`/`audience`, special-case
  `as:Public`, and redistribute inbox-forwarding to all cc-followers (AP §7.1.3).
  (`activitypub/inbox.zig:286-307`, `routes.zig:766-813`.)
- **AT external identity resolution wired** — `did:plc`/`did:web` HTTP resolution and
  DNS-TXT handle resolution are skeletons needing the `HttpFetcher`/resolver attached at
  boot; required to resolve real network identities. (`atproto/did_resolver.zig`.)
- **AT firehose completeness for relay participation** — emit `#identity` already done;
  add `#handle`/`#migrate`/`#info`, and (to be a relay node, not just a PDS) implement
  **downstream subscription to an external relay's firehose**. (`atproto/firehose.zig`,
  `relay/`.)

## P1 — Spec/client completeness
- **AT `deleteSession` (logout)** — no route today; clients can only discard tokens.
- **AT P-256 `did:key` roundtrip** + **`DPoP-Nonce` response header** (ES256 verify
  itself is done). (`atproto/keypair.zig`, `oauth_dpop.zig`.)
- **AT sync reads**: `getLatestCommit`, `listBlobs`, `listMissingBlobs`.
- **AP gaps**: advertise Multikey in the actor doc (verify already works); per-object
  `replies` collection; actor-scope the `liked` collection (FEP-c648); poll vote
  *tally* (votes are stored, not aggregated); emoji reactions (FEP-c0e0); publish
  `FEDERATION.md` (FEP-67ff); capability negotiation (FEP-844e).
- **NodeInfo** — advertise `atproto` in the `protocols` array (currently only in
  `metadata`). (`activitypub/nodeinfo.zig:81-100`.)
- **Media** — chunked transfer encoding so blobs >4 MiB stream instead of being unserved.
  (`media/routes.zig:356`.)
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
`ORDER BY (SELECT NULL)`). 1003 tests lock the generated SQL. **Remaining for mssql:**
`[bracket]` identifier quoting (folded into the P1 quoting item) and a **live round-trip
against `mcr.microsoft.com/mssql/server`** — deferred (the podman VM disk was full of
other containers in the dev env; the T-SQL is standard and unit-locked).

## P1 — correctness foundations + query depth
- **Identifier quoting** per dialect (`"x"`/`` `x` ``/`[x]`) — today names are unquoted
  and break on reserved words.
- **Typed constraint-violation errors** (unique / FK / not-null, per-dialect SQLSTATE /
  codes) — needed for clean conflict handling.
- **Query operators + pagination**: `<,>,<=,>=,!=`, `LIKE`, `IN`, `IS NULL`, `BETWEEN`,
  `OR`/grouping, `count()`, and **`OFFSET`** (where T-SQL's `OFFSET…FETCH` pays off).
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
5. (when a disk-headroom env is available) live SQL Server round-trip to close out M5.

# Doc map (post-reconciliation)
- **ROADMAP.md** (this file) — the single forward plan. Update here first.
- **SPEC_PUNCHLIST.md** — spec-ticket conformance log (AP/AT/DUAL/INFRA). Accurate as a
  record; partials are footnoted. Historical going forward.
- **PUNCHLIST.md** — operational checklist; stale-open markers corrected in this pass.
- **PROTOCOL_AUDIT.md** — **stale snapshot** (pre-dates most work); kept for the spec
  matrix only. Do not trust its ❌/⚠️ column without checking ROADMAP/code.
- **FEATURE_TODO.md** — shipped-feature history; open-work list folded into this file.
