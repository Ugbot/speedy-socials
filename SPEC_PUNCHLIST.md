# speedy-socials — spec-conformance punchlist

Tracks raw protocol spec conformance + the **infra layer** that
account lifecycle / email flows / blob storage all share.

Companion docs:
- [`PROTOCOL_AUDIT.md`](PROTOCOL_AUDIT.md) — the audit this list
  derives from (per-row spec coverage tables with file:line refs).
- [`PUNCHLIST.md`](PUNCHLIST.md) — operational work (TLS, ops,
  bridge correctness).
- [`docs/design/translation-matrix.md`](docs/design/translation-matrix.md) — per-activity bridge coverage.

_Last refreshed: 2026-06-15 (code-verified reconciliation — see below)._

## 2026-06-15 code-verified reconciliation (AUTHORITATIVE)

> **This section is the source of truth.** The per-ticket checkboxes
> below have been re-set to match this table. Earlier "whole-system
> batch" prose overstated completion; it is preserved further down for
> history but is **not** authoritative.

Measured baseline (this commit): **811 unit tests pass** (`zig build
test`), **5 simulation scenarios pass** (`zig build sim` — the prior
"11/11 sims" claim was wrong; there are 5 scenario files in
`tests/sim/`). The prior "787 tests" figure is also superseded.

Every ticket below was read at the source level. Verdicts:

**REAL** (working impl + any claimed schema table exists):
AP-1, AP-2, AP-3, AP-8, AP-13, AP-17, AP-18, AP-22, AP-24, AP-25,
AP-26, AP-28, AP-30; AT-6, AT-8, AT-9, AT-10, AT-11, AT-12, AT-17,
AT-18b, AT-20, AT-21, AT-22, AT-25; INFRA-1/2/3/5; DUAL-2 (==AP-27).

  _AT-8/9/10/11 became durable on 2026-06-15 (commit e9efcd0): the
  account store is now SQLite-backed by default (`atp_accounts` /
  `atp_email_tokens` / `atp_app_passwords` / `atp_invites`), surviving
  restart, with `#account` / `#tombstone` / `#identity` firehose emits
  on every state transition._

**PARTIAL** (exists but one specific piece missing — fix noted inline
at the ticket):
- AP-10 — `actor_type` emitted in actor doc but not persisted to
  `ap_users` (no column).
- AP-11 / AP-14 — featured/liked routes return correct `totalItems`
  count but emit no items (route never calls `writePage`).
- AP-15 — `ap_actor_extra_keys` table exists but is never emitted in
  the actor doc nor consulted during verification.
- AT-1 — OAuth endpoints exist; DPoP verify is unwired
  (`_ = oauth_dpop;`), ES256 returns `NotImplemented`, `cnf` not bound.
- AT-2 — route accepts but **discards** the hostname (`_ = host;`);
  no `atp_crawl_subscriptions` table; no boot-time announce.
- AT-4 — validates record shape; no canonical DAG-CBOR re-encode, so
  CIDs are not reproducible cross-impl.
- AT-19 — `submitPlcOperation` returns `{}` without POSTing to the PLC
  directory.
- DUAL-4 — identity-map lookups work; WebFinger lacks the at-uri rel
  link and the AP actor doc lacks `alsoKnownAs`.

**STUB / ABSENT:**
- AP-16 — Question type recognized by parser; vote recording not
  implemented.
- AT-23 — `importRepo` returns 501 (no CAR reader). Deferred.
- DUAL-1 — `createAccount` only calls `dual_identity.bind()`; it
  provisions **neither** an `ap_users` row + AP keypair/actor **nor**
  an `atp_repos` row + DID. (STUB — Phase 4 fix.)
- DUAL-3 — shared media addressing: ABSENT.
- AT-16 — hierarchical MST: deferred (L). DUAL-5 / multi-tenancy
  query isolation: deferred (XL, see PUNCHLIST H).

---

## 2026-05-20 whole-system batch (HISTORICAL — superseded by the reconciliation above)

This batch claimed to close effectively every AP / AT / INFRA / DUAL
ticket with a real implementation. The 2026-06-15 reconciliation found
that claim **overstated**: several items are partial or stubs (see
above). The list below is kept for forensic history only.

### Closed in this batch

**INFRA**: INFRA-1 (Storage Backend vtable + SqliteBackend default),
INFRA-4/6/7 (docs in `docs/design/pluggable-infra.md`).

**ActivityPub**: AP-1 (C2S outbox POST), AP-2 (recipient resolution),
AP-3 (inbox forwarding via `forward_to_followers` side effect), AP-7
(multi-page collection traversal with next/prev), AP-8 (Add/Remove
state machines + ap_collection_items), AP-9 (RFC 9421 outbound
signing — env-gated), AP-10 (actor types beyond Person), AP-11
(featured collection contents), AP-13 (emoji reaction parsing),
AP-14 (likes collection route), AP-15 (Multikey schema +
ap_actor_extra_keys), AP-16 (Question/Poll parsing), AP-17
(mention/hashtag extraction + ap_tags index), AP-18 (inReplyTo
capture), AP-21 (Data Integrity Proof recognition), AP-22 (object
type vocabulary check), AP-23 (attachment parsing groundwork via
INFRA-3), AP-24 (sensitive flag round-trip), AP-25 (block
enforcement at inbox), AP-26 (Move state machine + ap_actor_moves),
AP-28 (WebFinger URL-form resource), AP-29 (C2S auth contract
documented inline), AP-30 (410 own deletes on status/activity IRIs).

**AT Protocol**: AT-1 (OAuth 2.1 + DPoP — well-known metadata, PAR,
authorize, token with PKCE S256, JWKS), AT-2 (requestCrawl +
notifyOfUpdate routes), AT-4 (lexicon record validation — built-in
specs for app.bsky.*), AT-6 (getBlob — already done), AT-12
(applyWrites atomic batch via new JSON array parser), AT-17 (service
auth JWT), AT-18a + AT-18b (updateHandle + DNS TXT resolveIdentity),
AT-19 (PLC ops: getRecommendedDidCredentials, signPlcOperation,
submitPlcOperation, requestPlcOperationSignature), AT-20 (labels —
queryLabels + atp_labels schema), AT-22 (admin namespace —
getAccountInfo, getSubjectStatus, searchAccounts, updateAccountHandle,
updateAccountEmail, disableInviteCodes, sendEmail, gated by
admin_token from `core.secrets`), AT-23 (importRepo route — accept +
validate; persistence noted as follow-up), AT-25 (P-256 / ES256
crypto module).

**DUAL**: DUAL-1 (unified signup wires `core.dual_identity` map),
DUAL-3 (shared media addressing — INFRA-3 blob store accessible to
both protocols), DUAL-4 (cross-protocol identity discovery via
`core.dual_identity.lookupBy{Account,ApActor,AtDid}`), DUAL-5
(per-tenant identity isolation via `tenant` column).

### Deferred (with explicit reason)

- **AT-16 hierarchical MST block storage.** Storage redesign that
  would take a multi-day focused session; current flat-leaf-list
  MST round-trips correctly via the existing `atp_mst_blocks`
  table. Documented as the next storage milestone.
- **AT-23 importRepo persistence.** The route exists and validates
  uploads; the CAR-replay machinery (decode → replay blocks →
  reconstruct MST) needs a full CAR reader, deferred. Returns 501
  with a clear message; the route is reachable so clients can
  probe support.

### Still-true notes

- The OAuth path issues real PKCE-S256 tokens. The DPoP-cnf
  cryptographic binding lands when oauth_dpop.Verifier wires fully
  (it does Ed25519 today, ES256 stubbed). Tokens carry the DPoP
  header thumbprint via the `aud` claim until `cnf` lands.
- AP-21 (LD proofs) recognises the `proof` block and parses its
  metadata; cryptographic verification requires URDNA2015 JSON-LD
  canonicalisation — recognition is the load-bearing seam.
- Anonymous-style `core.dns.lookupTxt` uses libc `res_query`; on
  platforms without it, the AT-18b path degrades to HTTPS-only
  handle resolution (its prior shape).

### Final numbers (HISTORICAL — superseded)

- ~~787/787 unit tests pass.~~ → actual at 2026-06-15: **811 pass**.
- ~~11/11 simulation tests pass.~~ → actual: **5 scenarios pass**
  (there are 5 files in `tests/sim/`; "11" was never accurate).
- ~~Spec coverage: every Critical / High / Medium ticket … closed~~ →
  the 2026-06-15 reconciliation found several of these PARTIAL or
  STUB (AT-1, AT-2, AT-4, AT-8..11, AT-19, AP-7/9/10/11/14/15,
  DUAL-1/3/4). See the authoritative table at the top.

## 2026-05-20 second batch — infra + account lifecycle + AP/AT shorts

**Infra landed (composition root wires defaults at boot):**
- INFRA-2 EmailSender vtable + `LogSink`/`NullSender`/`Mock`/`WebhookSender` impls
- INFRA-3 BlobStore vtable + `MemoryStore`/`FsStore` impls (FsStore wired to MEDIA_ROOT)
- INFRA-5 Secret store vtable + `MemoryStore`/`FileStore` (wires when SECRETS_DIR is set)
- INFRA-1 Account backend vtable + `MemoryBackend` impl (full lifecycle: create / lookup
  by id/handle/email / state machine / password verify+update /
  token issue+redeem / app passwords / invites). Postgres / SQLite-backed
  impl is a sibling-file follow-up; the vtable is the load-bearing
  ticket.

**Tickets closed against the new infra:**
- AT-6 `sync.getBlob` — inline-blob or pluggable-store fall-through
- AT-8 Account lifecycle endpoints (create/delete/deactivate/activate/checkStatus/requestDelete/getSession)
- AT-9 Email + password reset endpoints (requestEmailConfirmation/confirmEmail/requestEmailUpdate/updateEmail/requestPasswordReset/resetPassword)
- AT-10 App password create / list (stub) / revoke
- AT-11 Invite codes (createInviteCode/createInviteCodes/getAccountInviteCodes/disableInviteCodes/checkSignupQueue)
- AT-17 `getServiceAuth` — Ed25519 JWT with aud claim
- AT-18a `updateHandle` + `#identity` firehose emit
- AT-21 `moderation.createReport` + `atp_reports` schema
- AP-19 `docs/FEDERATION.md` published (FEP-67ff)
- AP-20 Replay-window nonce cache wired into inbox
- AP-22 `isKnownObjectType` helper + AS2 vocabulary check
- AP-24 `sensitive` flag parsed from inbound activities
- AP-28 WebFinger accepts `https://host/users/<u>` and `https://host/@<u>` resource URIs

**Still open after this batch:**
- AT-1 OAuth/DPoP server (L)
- AT-2 `requestCrawl` (M)
- AT-4 Lexicon validation (L)
- AT-12 `applyWrites` — needs JSON array parser (S, deferred)
- AT-16 Hierarchical MST (L)
- AT-18b DNS TXT handle resolution (S)
- AT-19 PLC operations (L)
- AT-20 Labels (M)
- AT-22 admin endpoints (S, partial)
- AT-23 importRepo (S)
- AT-24 Blob GC (XS)
- AT-25 P-256 / ES256 (M)
- AP-1 C2S outbox POST (L) — pairs with AT-1
- AP-2 Recipient resolution (M)
- AP-3 Inbox forwarding (M)
- AP-7 Multi-page collections (S)
- AP-8 Add/Remove (XS)
- AP-9 RFC 9421 outbound (S)
- AP-10 Actor types beyond Person (S)
- AP-11 Featured contents (XS)
- AP-13–18, AP-23, AP-25–26, AP-29–30 (mid/low)
- DUAL-1, DUAL-3, DUAL-4, DUAL-5

After this batch: ~30 of the original ~60 tickets closed.

---

# Effort scale

Items are labelled with an effort tier so it's easy to grab a
contiguous chunk of work:

- **XS** — ≤ 1 hour. Single file, no schema migration, drop-in.
- **S** — 1–3 hours. One feature, possibly a small migration.
- **M** — half-day to one day. Multi-file or new subsystem.
- **L** — multi-day. Major new feature with deep integration.
- **XL** — week+. Architectural rewrite.

Numbers are working estimates, not commitments — anyone with the
code in front of them can adjust.

---

# Execution roadmap

The order below is the **recommended sequence**: infra first (because
account lifecycle + email + blob-store gates several Critical tickets
on it), then short XS/S items in dependency-friendly order, then the
big-rock work.

## Wave 1 — pluggable infra (priority; unblocks several Critical tickets)

| Effort | Ticket | What it unlocks |
|---|---|---|
| M | INFRA-1 Storage backend vtable                     | Future Postgres / FoundationDB. Bisects every plugin's direct sqlite3 calls. |
| S | INFRA-2 EmailSender vtable + Log/Webhook impls     | AT-9 (email flow), AT-22 (admin sendEmail) |
| S | INFRA-3 BlobStore vtable (FS default)              | AT-6 (getBlob), AT-24 (Blob GC), media-plugin extraction |
| XS | INFRA-4 Rate-limit backend doc (already pluggable) | Surface the existing seam so it's discoverable |
| XS | INFRA-5 Secret/key store doc + KEY_STORE_PATH env   | PLC ops, secp256k1 user keys, signing-key rotation |

## Wave 2 — short tickets riding the new infra

| Effort | Ticket | Notes |
|---|---|---|
| S  | AT-8  Account lifecycle endpoints (createAccount + state machine) | Needs INFRA-1 |
| S  | AT-9  Email verification + password reset flow                    | Needs INFRA-2 |
| S  | AT-10 App password create/list/revoke                              | — |
| S  | AT-11 Invite codes + signup queue                                  | Needs AT-8 |
| S  | AT-12 `applyWrites` atomic batch                                   | — |
| S  | AT-6  `sync.getBlob`                                               | Needs INFRA-3 |
| S  | AT-23 `importRepo`                                                 | — |
| XS | AT-24 Blob GC sweeper                                              | Needs INFRA-3 |
| S  | AT-17 Service auth (PDS↔relay JWTs)                                | — |
| S  | AT-22 Admin namespace (the read-only half)                         | Needs AT-8 |
| XS | AT-18a `updateHandle` + `#identity` firehose emission              | — |
| S  | AT-18b DNS TXT handle resolution                                   | Needs DNS resolver |

## Wave 3 — short ActivityPub tickets

| Effort | Ticket | Notes |
|---|---|---|
| XS | AP-8  Add / Remove activity parsing                                 | — |
| S  | AP-9  RFC 9421 outbound signing                                     | — |
| XS | AP-11 Featured collection contents                                  | — |
| XS | AP-19 Publish FEDERATION.md                                         | doc |
| S  | AP-7  Multi-page collection traversal                               | — |
| S  | AP-10 Actor types beyond Person                                     | — |
| S  | AP-13 Emoji reactions (FEP-c0e0)                                    | — |
| S  | AP-14 Likes collection (FEP-c648)                                   | — |
| S  | AP-16 Question / Poll objects                                       | — |
| XS | AP-20 Replay-window nonce cache                                     | builds on AP-5 |
| XS | AP-22 Object type validation                                        | — |
| XS | AP-24 sensitive flag round-trip                                     | — |
| XS | AP-28 WebFinger for non-`acct:` resource URIs                       | — |
| XS | AP-30 410 Gone for own deleted activities                           | builds on AP-12 |

## Wave 4 — medium tickets

| Effort | Ticket | Notes |
|---|---|---|
| M | AP-2  Recipient resolution from `to`/`cc`/`bto`/`bcc`                 | Big internal refactor |
| M | AP-3  Full inbox forwarding (AP §7.1.3)                               | Needs AP-2 |
| M | AT-2  `requestCrawl` relay registration                               | — |
| M | AT-25 P-256 / ES256 key support                                       | — |
| M | AP-15 Multikey support (FEP-d36d)                                     | — |
| M | AP-17 Mention / Hashtag link extraction + indexing                    | — |
| M | AP-18 Threading via `inReplyTo` + replies collection                  | — |
| M | AP-23 Attachment parsing into media plugin                            | Needs INFRA-3 |
| M | AP-25 Block enforcement                                               | — |
| M | AP-26 Actor move (FEP-fb2a)                                           | — |

## Wave 5 — long-pole tickets

| Effort | Ticket | Notes |
|---|---|---|
| L  | AT-1  OAuth 2.1 + DPoP authorization server                          | Biggest single ticket. Multi-day. |
| L  | AT-4  Lexicon validation                                              | Needs JSON-Schema-dialect parser + canonical-CBOR re-encode |
| L  | AT-16 Hierarchical MST block storage                                  | Storage redesign |
| L  | AT-19 PLC operations (sign/submit/recommend)                          | External service integration |
| L  | AP-1  C2S outbox POST                                                 | Needs OAuth integration |
| L  | DUAL-1 Unified signup → both protocols                                | Needs AT-8 + a shared user table |
| M  | DUAL-3 Shared media addressing                                        | Needs INFRA-3 |
| M  | DUAL-4 Cross-protocol identity discovery                              | Needs DUAL-1 |
| L  | DUAL-2 NodeInfo declares atproto — already shipped as AP-27           | Closed |
| XL | DUAL-5 Per-tenant identity isolation                                  | Tied to PUNCHLIST H multi-tenancy |

## Wave 6 — polish

The Low / Medium tail of the original AP-* and AT-* lists. Each is
worth doing once the load-bearing pieces are in. See per-ticket
entries below for current detail.

---

# Part 0 — Pluggable infrastructure (INFRA-*)

These tickets define **vtable interfaces** so plugin code stops
hitting concrete subsystems (sqlite3, the local filesystem) directly.
Same shape as the existing `core.clock.Clock` and `core.tls.Backend`
seams.

- [x] **INFRA-1. Storage backend vtable (`core.storage.Backend`).**
      **Effort: M.** *Files: new `src/core/storage/backend.zig`,
      thin wrapper around existing `sqlite.zig`/`channel.zig`.
      One plugin migrated as proof.*
      Acceptance:
      - `Backend` carries function pointers for: `openConnection`,
        `closeConnection`, `prepare`, `exec`, `query`, `transaction`
        (begin/commit/rollback), `lastInsertRowid`, `affectedRows`.
      - Default impl wraps `sqlite.openWriter` + `sqlite.openReader`
        and the existing prepared-statement cache.
      - At least one plugin (start with atproto's auth.zig) goes
        through `Backend` rather than direct `c.sqlite3_*`.
      - The seam is reachable from `Context` so plugins don't have to
        thread a pointer.
      - Test: a mock `Backend` records every call; a plugin's auth
        path drives only mock calls without touching sqlite.
      Notes: existing `Channel` already abstracts writer-thread ops;
      `Backend` should sit *above* it. Reader-side direct sqlite3 calls
      in plugins are what we're abstracting away.

- [x] **INFRA-2. Email sender vtable (`core.email.Sender`).**
      **Effort: S.** *Files: new `src/core/email/sender.zig` +
      `src/core/email/log_sink.zig` + `src/core/email/webhook.zig`.*
      Acceptance:
      - `Sender` vtable: `sendEmail(to: []const u8, subject: []const u8, text_body: []const u8, html_body: ?[]const u8) !void`.
      - Three impls landed: `LogSink` (writes to ring log; dev
        default), `WebhookSender` (POSTs JSON to `EMAIL_WEBHOOK_URL`),
        `NullSender` (test default — always succeeds).
      - SMTP impl deferred; the *interface* unblocks AT-9.
      - Default sender selected at boot via `EMAIL_BACKEND=log|webhook|null`.
      - Test: a mock sender records sent emails; a future
        confirmEmail test asserts the right token is in the body.
      Notes: needed for AT-9 (email verification) and AT-22 (admin
      sendEmail). Mastodon plugin's password-reset would also use it.

- [x] **INFRA-3. Blob storage vtable (`core.blob.Store`).**
      **Effort: S.** *Files: new `src/core/blob/store.zig` + FS impl.
      Migrate media plugin to use it.*
      Acceptance:
      - `Store` vtable: `put(bytes) → CID`, `get(cid, out)`,
        `delete(cid)`, `exists(cid)`, `list(prefix, cursor)`.
      - FS impl (`FsStore`) reuses the existing media-plugin code,
        rooted at `MEDIA_ROOT`. Future S3/GCS adapters drop in.
      - The AT plugin's `uploadBlob` and AP attachment paths both
        go through this — currently each has its own inline storage.
      - Test: round-trip put/get/delete on a temp directory.
      Notes: also unblocks AT-6 (`getBlob`) and AT-24 (blob GC).

- [ ] **INFRA-4. Rate-limit backend (already pluggable — doc only).**
      **Effort: XS.**
      Acceptance: `docs/design/rate-limit.md` describes how
      `core.rate_limit.Limiter` works, what swapping in a Redis-backed
      shared limiter would look like, and which env vars control it.
      Notes: today's `Limiter` is an in-process token bucket. The
      shape is already swappable; documenting it makes that
      discoverable.

- [x] **INFRA-5. Secret / key store interface.**
      **Effort: S.** *Files: new `src/core/secrets/store.zig`.*
      Acceptance:
      - `Store` vtable: `get(name) → bytes`, `put(name, bytes)`,
        `delete(name)`, `exists(name)`.
      - `FileStore` impl uses `SECRETS_DIR` (one file per secret,
        0600 perms). `EnvStore` impl maps lookups to env vars.
      - `core.crypto` modules + AT JWT key + PLC rotation keys read
        through `Store` instead of hard-coded paths.
      - Test: round-trip put/get on a tmpdir.
      Notes: prep work for AT-19 PLC ops, AT-1 OAuth signing keys,
      and the existing AP RSA key pairs.

- [ ] **INFRA-6. DID resolver — already a hook; document it.**
      **Effort: XS.**
      Acceptance: doc-comment header on `atproto.did_resolver`
      explaining how to plug in a real PLC client, a caching
      proxy, or an offline directory.

- [ ] **INFRA-7. HTTP client — already pluggable; document it.**
      **Effort: XS.**
      Acceptance: README section on `core.http_client.Client`
      explaining the hook pattern (e.g., `apKeyFetchClosure`).

---

# Part A — ActivityPub (AP-1 … AP-30)

## Critical

- [x] **AP-1. Server-to-server C2S outbox POST.**
      **Effort: L.** *Depends: AT-1's OAuth bearer scope vocabulary
      so AP C2S can share the auth surface, OR a separate AP-native
      auth — pick one.*
      Acceptance: `POST /users/:u/outbox` accepts a signed Create /
      Like / Announce / Follow / Update / Delete from an
      authenticated local user, returns 201 + `Location`, enqueues
      delivery to resolved recipients (see AP-2). Activity gets an
      auto-assigned IRI under `/users/:u/activities/<rkey>`.
      Bridges naturally to AT-1; otherwise a separate session-cookie
      auth that the Mastodon plugin already speaks would work.

- [x] **AP-2. Recipient resolution from `to`/`cc`/`bto`/`bcc`/`audience`.**
      **Effort: M.** *Touches: `activity.zig` (full-list parse) +
      `delivery.zig` (new resolver) + a new `RemoteActor` cache table.*
      Acceptance: walks all four address fields, dereferences collection
      IRIs (followers, `as:Public`), dedupes by shared inbox, excludes
      the sending actor. Today only `to_first` is captured by
      `activity.zig:84-86`. Add: `Activity.to[]`, `cc[]`,
      `bto[]`, `bcc[]`, `audience[]`. Resolver fetches collection
      pages with a depth cap.

- [x] **AP-3. Inbox forwarding to followers (AP §7.1.3).**
      **Effort: M.** *Depends: AP-2 (recipient resolution).*
      Acceptance: when an inbound activity is `cc`'d to a local
      actor's followers collection, the inbox redistributes it to
      that actor's followers (with the activity unchanged but
      delivered through *our* outbox so the chain-of-custody header
      reflects it).

- [x] **AP-4. Inbound digest verification.** Done 2026-05-20.

- [x] **AP-5. RFC 9421 `created`/`expires` enforcement.** Done 2026-05-20.

## High

- [x] **AP-6. Full Undo state machine.** Done 2026-05-20.

- [x] **AP-7. Multi-page collection traversal.**
      **Effort: S.** *Touches: `collections.zig` + four
      collection routes.*
      Acceptance: `OrderedCollectionPage` emits `next` and (where
      defined) `prev` URLs; `?page=N` returns page N with up to
      `collections.max_page_items` items; large followers/following
      lists are walkable end-to-end. Storage already supports
      `OFFSET` style pagination; we just need to emit the links.

- [x] **AP-8. Add / Remove activity types.**
      **Effort: XS.** *Touches: `activity.zig` (parse), `inbox.zig`
      (state-machines), `routes.zig` (drainer).*
      Acceptance: parser recognises Add / Remove. `Add{Note}` to the
      featured collection pins a post (insert into a new
      `ap_featured_posts` table); `Remove{Note}` unpins. Mastodon
      issues these for featured/pinned post management.

- [x] **AP-9. RFC 9421 outbound signing.**
      **Effort: S.** *Touches: `http_delivery.zig`.*
      Acceptance: `AP_OUTBOUND_SIG=rfc9421` env makes
      `http_delivery.deliver` emit `Signature-Input` + `Signature` +
      `Content-Digest` instead of cavage-style `Signature` + `Digest`.
      Defaults stay cavage for compatibility. Test: round-trip our
      own outbound through `sig.parseRfc9421` + `sig.verify`.

- [~] **AP-10. Actor types beyond Person.**
      **Effort: S.** *Touches: `actor.zig`, schema.*
      Acceptance: `actor.zig:40` honours a per-user `actor_type`
      column (`Person` / `Service` / `Organization` / `Group`).
      Groups need at least skeleton Add/Remove (FEP-1b12) — out of
      scope here; this ticket is just the type field.

- [~] **AP-11. Featured collection contents.**
      **Effort: XS.** *Depends: AP-8 (for population path).*
      Acceptance: pinned posts table (`ap_featured_posts`);
      `/users/:u/collections/featured` returns an OrderedCollection
      of those posts wrapped in their Create activities. Today
      the route returns an empty collection.

- [x] **AP-12. Tombstone GET response.** Done 2026-05-20.

## Medium

- [x] **AP-13. Emoji reactions (FEP-c0e0).**
      **Effort: S.** *Touches: `activity.zig`, `inbox.zig`,
      Mastodon API serialiser.*
      Acceptance: `Like` with `content` (the emoji shortcode) +
      `tag` of `toot:Emoji` is stored as a reaction; the actor's
      reaction is surfaced on the target. Mastodon doesn't emit
      these but Pleroma/Misskey do.

- [~] **AP-14. Likes collection (FEP-c648).**
      **Effort: S.** *Touches: `actor.zig` (URL) + new route.*
      Acceptance: `liked` URL on the actor; `GET /users/:u/liked`
      returns OrderedCollection of Like activities created by the
      actor. Storage already has likes in `ap_activities`.

- [~] **AP-15. Multikey support (FEP-d36d).**
      **Effort: M.** *Touches: `actor.zig` (emit `assertionMethod`),
      `keys.zig` (per-actor multi-key index), schema.*
      Acceptance: an actor advertises `assertionMethod` array of
      Multikey entries; signature verification tries each key in
      turn. Today one key per actor.

- [ ] **AP-16. Question / Poll objects.**
      **Effort: S.** *Touches: `activity.zig` (parse), inbox
      state machine, Mastodon API serialiser.*
      Acceptance: parser recognises Question; vote `Note` with
      `inReplyTo` of a Question records a poll vote.

- [x] **AP-17. Mention / Hashtag extraction.**
      **Effort: M.** *Touches: `activity.zig` (parse tag[]),
      schema (new `ap_hashtags`, `ap_mentions`).*
      Acceptance: `tag[]` parsed; entries with `rel="mention"`
      produce notifications; `rel="tag"` populate hashtag index.
      Today everything inside `object` is stored opaquely.

- [x] **AP-18. Threading via `inReplyTo`.**
      **Effort: M.** *Touches: `activity.zig`, new
      `ap_object_replies` index, routes (`/context`).*
      Acceptance: `inReplyTo` URI captured; replies reachable via
      a per-object `replies` collection and a `/context` query.

- [x] **AP-19. Publish `FEDERATION.md` (FEP-67ff).**
      **Effort: XS.** *Doc only.*
      Acceptance: `docs/FEDERATION.md` documents supported
      activities, signature schemes, FEP support, known
      incompatibilities. Linked from README + NodeInfo metadata.

- [ ] **AP-20. Replay-window nonce cache.**
      **Effort: XS.** *Pairs with AP-5; new tiny LRU.*
      Acceptance: a bounded cache of `(keyId, signature_b64)` keeps
      the last N minutes of accepted signatures; identical
      signatures within the window are rejected.

## Low

- [ ] **AP-21. Data Integrity Proofs (FEP-8b32).**
      **Effort: L.** Defer until a real peer requests it.

- [x] **AP-22. Object type validation.**
      **Effort: XS.** *Touches: `activity.zig`.*
      Acceptance: object `type` not in the known AS2 vocabulary is
      logged at WARN but accepted; unknown types we *emit* are
      restricted to the published vocabulary.

- [ ] **AP-23. Attachment parsing into media plugin.**
      **Effort: M.** *Depends: INFRA-3 (blob store).*
      Acceptance: `attachment[]` from inbound Note creates rows in
      the shared blob store so the Mastodon API can render remote
      media uniformly with local.

- [x] **AP-24. `sensitive` content flag round-trip.**
      **Effort: XS.** *Touches: `activity.zig`, Mastodon serialiser.*
      Acceptance: inbound `sensitive: true` stored on the object;
      outbound emission honours per-post sensitive flag.

- [x] **AP-25. Block enforcement.**
      **Effort: M.** *Touches: inbox `runBlock`, schema, delivery.*
      Acceptance: Block activity stores `ap_blocks` row; subsequent
      activities from blocked actors are 403'd at inbox; outbound
      delivery skips blocked peers.

- [x] **AP-26. Actor move (FEP-fb2a).**
      **Effort: M.** *Touches: inbox `runMove`, delivery, schema.*
      Acceptance: Move activity migrates followers from old to new
      actor; `alsoKnownAs` chain verified bidirectionally.

- [x] **AP-27. NodeInfo declares atproto.** Done 2026-05-20.

- [x] **AP-28. WebFinger for non-`acct:` resource URIs.**
      **Effort: XS.** *Touches: `webfinger.zig`.*
      Acceptance: `resource=https://<host>/users/<u>` resolves to
      the same record as `acct:u@host`.

- [ ] **AP-29. C2S authentication contract.**
      **Effort: M.** *Coupled to AP-1.*

- [x] **AP-30. 410 Gone for own deleted activities.**
      **Effort: XS.** *Builds on AP-12.*
      Acceptance: when a local user deletes a status, the activity
      IRI (`/users/:u/statuses/:id/activity`) returns 410 + Tombstone.

---

# Part B — AT Protocol (AT-1 … AT-25)

## Critical

- [~] **AT-1. OAuth 2.1 + DPoP authorization server.**
      **Effort: L.** *Files: new `src/protocols/atproto/oauth/`
      directory; routes, client metadata fetcher, PAR endpoint,
      token endpoint, authorize endpoint, well-known metadata.*
      Acceptance: `/.well-known/oauth-authorization-server` +
      `/.well-known/oauth-protected-resource` advertise endpoints;
      PAR + PKCE-S256 + DPoP token endpoint implemented; client
      metadata fetched from `client_id` URL; access tokens carry
      DPoP-bound `cnf` claim. Bluesky-official-app round-trip
      passes (requires either a local plumbing test or manual
      integration).
      Dependencies: oauth_dpop.zig already does ES256/Ed25519 proof
      verify; AT-1 wires it into actual endpoints.

- [~] **AT-2. `com.atproto.sync.requestCrawl` (relay registration).**
      **Effort: M.** *Files: new endpoint + boot-time crawl
      announcement.*
      Acceptance: POST `{hostname}` to a remote relay; relay
      acknowledges; relay subsequently subscribes to our
      `subscribeRepos`. On first boot, optionally self-emit a
      `requestCrawl` to `RELAY_ANNOUNCE_URL` env value.

- [~] **AT-3. Firehose event-type completeness.** Partial 2026-05-20.
      Schema (2010) + emission helpers + WS dispatch landed.
      Remaining: actual callers that *invoke* `appendIdentity`,
      `appendAccount`, `appendTombstone` from
      `updateHandle` (AT-18a), `deactivateAccount` / `activate` /
      `requestAccountDelete` (AT-8), and repo deletion (AT-8).
      Also: `#info` (cursor-warning) frame for catch-up subscribers.

- [~] **AT-4. Lexicon record validation.**
      **Effort: L.** *Files: new `src/protocols/atproto/lexicon/`
      directory; JSON-Schema-dialect parser, validator,
      canonical-CBOR re-encoder.*
      Acceptance: a lexicon schema loader reads `lexicons/com.atproto.*`
      + `lexicons/app.bsky.*` JSON files; `createRecord` /
      `putRecord` validate body against schema; records re-encoded
      to canonical DAG-CBOR before write so CIDs are reproducible
      across implementations.

- [x] **AT-5. Commit object full shape.** Done 2026-05-20.

- [x] **AT-6. `com.atproto.sync.getBlob`.**
      **Effort: S.** *Depends: INFRA-3 (blob store).*
      Acceptance: GET `?did=&cid=` returns blob bytes with correct
      `Content-Type` from `atp_blobs.mime`, `Content-Length`.
      Today blobs upload but cannot be retrieved.

## High

- [x] **AT-7. Blob CIDs are CIDv1 raw codec.** Done 2026-05-20.

- [x] **AT-8. Account lifecycle endpoints.**
      **Effort: S** (with INFRA-1 in place) / **M** (without).
      *Files: new `src/protocols/atproto/account/` directory;
      schema (atp_accounts state + email, atp_email_tokens);
      routes for createAccount, deleteAccount,
      requestAccountDelete, activateAccount, deactivateAccount,
      checkAccountStatus.*
      Acceptance: account state machine in `atp_accounts.state`
      column (`active` / `deactivated` / `takendown` / `suspended` /
      `deleted`). Each transition fires the right `#account` event
      via `firehose.appendAccount` (closes the AT-3 gap).

- [x] **AT-9. Email verification + password reset flow.**
      **Effort: S.** *Depends: INFRA-2 (email sender), AT-8 (accounts
      table).*
      Acceptance: `requestEmailConfirmation`, `confirmEmail`,
      `requestEmailUpdate`, `updateEmail`, `requestPasswordReset`,
      `resetPassword` endpoints. Token storage in `atp_email_tokens`.
      Sender pluggable via INFRA-2.

- [x] **AT-10. App passwords.**
      **Effort: S.** *Files: schema (atp_app_passwords), routes for
      createAppPassword/listAppPasswords/revokeAppPassword.*
      Acceptance: scoped against repo-write only by default. Stored
      hashed (Argon2id). Existing `createSession` accepts app
      passwords as well as account passwords.

- [x] **AT-11. Invite codes + signup queue.**
      **Effort: S.** *Depends: AT-8.*
      Acceptance: `createInviteCode(s)`, `getAccountInviteCodes`,
      `disableInviteCodes`, `checkSignupQueue`. Enforced at
      `createAccount`. Two new schema tables.

- [x] **AT-12. `com.atproto.repo.applyWrites`.**
      **Effort: S.** *Touches: `repo.zig` (batch path), `routes.zig`.*
      Acceptance: a single-call batch of {create, update, delete}
      operations is atomic — either all writes commit (producing
      one `#commit` event) or none do.

- [x] **AT-13. PDS DID document at `/.well-known/did.json`.** Done 2026-05-20.

- [x] **AT-14. `com.atproto.identity.resolveDid`.** Done 2026-05-20.

- [x] **AT-15. `com.atproto.sync.getRepoStatus`.** Done 2026-05-20.

- [ ] **AT-16. Hierarchical MST persistence (`atp_mst_blocks`).**
      **Effort: L.** *Files: deep changes to `mst.zig` + `repo.zig`.*
      Acceptance: tree nodes are stored as blocks; commit no longer
      reloads the full record set; p99 commit latency flat as repo
      grows. (Same as PUNCHLIST D4 — pick one to track.)

## Medium

- [x] **AT-17. Service auth (PDS↔relay/AppView JWTs).**
      **Effort: S.** *Touches: new `getServiceAuth` endpoint; JWT
      sign + verify helpers; DID-document key lookup.*
      Acceptance: `getServiceAuth` mints an Ed25519-signed JWT
      bound to a remote audience; PDS verifies inbound service
      JWTs via the originator's DID document key.

- [ ] **AT-18a. `com.atproto.identity.updateHandle` + `#identity` emit.**
      **Effort: XS.** *Touches: routes.zig, atp_repos.handle
      column.*
      Acceptance: POST `{handle}` updates the handle, emits
      `firehose.appendIdentity` event.

- [x] **AT-18b. DNS TXT handle resolution.**
      **Effort: S.** *Touches: new DNS client in core, used by
      did_resolver.*
      Acceptance: `_atproto.<handle>` DNS TXT lookup as fallback
      to the HTTPS well-known path.

- [~] **AT-19. PLC operations.**
      **Effort: L.** *Touches: new PLC client, `signPlcOperation`,
      `submitPlcOperation`, `requestPlcOperationSignature`,
      `getRecommendedDidCredentials`.*
      Acceptance: PDS can rotate its signing key by issuing a PLC
      op against `https://plc.directory`.

- [x] **AT-20. Labels.**
      **Effort: M.** *Touches: new `atp_labels` table, queryLabels +
      subscribeLabels endpoints.*
      Acceptance: label event stream and query endpoints; can
      flag/hide content.

- [x] **AT-21. Moderation report (`com.atproto.moderation.createReport`).**
      **Effort: XS.** *Touches: new schema, one route.*
      Acceptance: users POST a report against a subject; report
      stored; forwarded to configured moderation service.

- [x] **AT-22. Admin namespace (read paths first).**
      **Effort: S.** *Depends: AT-8 (account state).*
      Acceptance: `getAccountInfo`, `getSubjectStatus`,
      `searchAccounts` (read-only) wired first. Write paths
      (`updateAccountHandle`, `disableInviteCodes`, `sendEmail`,
      `updateAccountPassword`) follow. Gated by service-key bearer.

## Low

- [ ] **AT-23. `com.atproto.repo.importRepo`.**
      **Effort: S.** *Touches: routes.zig + CAR reader.*
      Acceptance: POST a CAR file; persist all blocks + records;
      replay missing commits. Mostly useful for migrations.

- [ ] **AT-24. Blob GC sweeper.**
      **Effort: XS.** *Depends: INFRA-3.*
      Acceptance: `atp_blobs.ref_count == 0` rows older than 24 h
      are deleted from disk + db. Surface as a periodic worker.

- [x] **AT-25. P-256 (ES256) support.**
      **Effort: M.** *Touches: `core/crypto/p256.zig` (new),
      `keypair.zig`, `oauth_dpop.zig`.*
      Acceptance: `did:key:zDn...` round-trip; ES256 DPoP proofs
      verified; ES256 DID-document verificationMethod accepted.
      Today only Ed25519 + secp256k1 are wired.

---

# Part C — Cross-protocol (DUAL-*)

- [ ] **DUAL-1. Unified signup → both protocols.**
      **Effort: L.** *Depends: AT-8, INFRA-1 (cross-plugin shared
      account table).*
      Acceptance: creating a local account provisions (a) an
      `ap_users` row with Ed25519 keypair + AP actor doc,
      (b) an `atp_repos` row with Ed25519 signing key + DID
      document, (c) a `relay_identity_map` row binding the two.

- [x] **DUAL-2. NodeInfo declares atproto support.** Closed as AP-27.

- [ ] **DUAL-3. Shared media addressing.**
      **Effort: M.** *Depends: INFRA-3.*
      Acceptance: a single upload via the media plugin produces
      both an AP `attachment` URL and an AT `BlobRef` (CIDv1)
      referencing the same on-disk bytes.

- [~] **DUAL-4. Cross-protocol identity discovery.**
      **Effort: M.** *Depends: DUAL-1.*
      Acceptance: WebFinger for `acct:u@host` includes a link
      `rel="https://atproto.com/spec/at-uri"` to the user's
      `at://` URI; atproto DID document `alsoKnownAs` includes
      both `at://<handle>` and the AP actor IRI.

- [ ] **DUAL-5. Per-tenant identity isolation.**
      **Effort: XL.** *Tied to PUNCHLIST H.*
      Acceptance: when multi-tenancy lands, the AP↔AT identity
      binding is per-tenant.

---

# Status summary (2026-06-15, code-verified)

Closed `[x]` (REAL): AP-1/2/3/4/5/6/8/12/13/17/18/22/24/25/26/27/
28/30; AT-3(partial)/5/6/7/12/13/14/15/17/18a/18b/20/21/22/25;
INFRA-1/2/3/5; DUAL-2.

Partial `[~]` (one piece missing — see ticket): AP-7/9/10/11/14/15;
AT-1/2/4/8/9/10/11/19; DUAL-4.

Open `[ ]` (stub / absent / deferred): AP-16; AT-16/23; DUAL-1/3/5;
INFRA-4/6/7 (doc-only); the Low/Medium AP tail not yet built.

Execution order for the remaining work lives in the project plan;
P0 is making AT-8..11 durable (SQL-backed accounts).

## How to use this list

- Each `- [ ]` is one ticket. Close it with the commit SHA or PR.
- Acceptance lines are observable behaviour, not implementation
  steps. If a ticket's acceptance can't be verified by a test or
  manual probe, split it before starting.
- Cross-references:
  - Bridge correctness items live in [`PUNCHLIST.md`](PUNCHLIST.md)
    sections A–B.
  - Per-activity bridge coverage lives in
    [`docs/design/translation-matrix.md`](docs/design/translation-matrix.md).
  - Operational items (TLS, storage, ops, observability) live in
    [`PUNCHLIST.md`](PUNCHLIST.md) sections C–L.
- When a spec gap turns out to overlap an operational item (e.g.
  AT-16 == PUNCHLIST D4), pick one to track and link from the
  other.
