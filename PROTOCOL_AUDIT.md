# Protocol Conformance Audit

> ⚠️ **STALE SNAPSHOT (2026-05-19) — superseded by [`ROADMAP.md`](ROADMAP.md).**
> A 2026-06-22 code-verified reconciliation found this audit predates most of the
> implementation: many rows marked ❌/⚠️ below are now **done in code** (AP C2S outbox
> POST, AP signature `Digest`/`created`/`expires`/replay verification, AT OAuth 2.1 +
> DPoP incl. ES256, AT account lifecycle, CIDv1 blobs, full commit shape, 60+ XRPC
> routes). **Do not trust the per-row ❌/⚠️ columns without checking [`ROADMAP.md`](ROADMAP.md)
> or the code.** Kept only for the spec-matrix structure; the executive verdict below
> has been corrected to current reality.

**Date**: 2026-05-19 (full rewrite — supersedes the 2026-03-17 audit,
which referenced files removed by the Tiger-Style restructure).
**Scope**: ActivityPub (W3C REC + Mastodon extensions + FEPs) and
AT Protocol (atproto PDS + relay).
**Posture**: Are we a **full node on each network**, not just a bridge.
**Paired with**: [`SPEC_PUNCHLIST.md`](SPEC_PUNCHLIST.md) (the ticketed
gap list), [`PUNCHLIST.md`](PUNCHLIST.md) (operational items),
[`docs/design/translation-matrix.md`](docs/design/translation-matrix.md)
(per-activity bridge coverage), [`FEATURE_TODO.md`](FEATURE_TODO.md).

This document audits what is in the tree against each spec. Each
section marks every requirement as **present** / **partial** / **missing**
with a file:line pointer. The companion `SPEC_PUNCHLIST.md` turns the
gaps into tickets (AP-1..AP-30, AT-1..AT-25) with one-line acceptance
criteria.

---

## Executive verdict (corrected 2026-06-22 against code)

| Posture                                          | Status |
|---|---|
| AP receiver / S2S federation peer (Mastodon-style) | ✅ production-shaped; remaining: full `cc`/`bcc`+`as:Public` recipient resolution, a few FEPs |
| AP independent server (clients post via AP C2S)    | ✅ viable — `POST /users/:u/outbox` returns 201+Location (`activitypub/routes.zig:993-1043`) |
| AT PDS for self-hosted accounts                    | ✅ usable — repo + firehose + SQL-backed account lifecycle + OAuth 2.1/DPoP (Ed25519 **and** ES256) all present |
| AT participant on the live Bluesky network          | ⚠️ close — `requestCrawl`, firehose, OAuth, account lifecycle all DONE; remaining: canonical DAG-CBOR re-encode, external-relay subscription, DNS-TXT/PLC HTTP resolution wiring |
| AP↔AT bridge / relay                                | ✅ shipped (W6 + B + A1) — see [`docs/adr/002-protocol-relay.md`](docs/adr/002-protocol-relay.md) |

_The detailed per-section ❌/⚠️ matrix below is the stale 2026-05-19 snapshot; see [`ROADMAP.md`](ROADMAP.md) for the reconciled open-work list._

**Bottom line.** The core primitives are good — both protocols have
real crypto, real storage, real signing, real firehose. The
**ecosystem layer** is what's missing: AP C2S + recipient resolution,
AT OAuth + relay registration + account lifecycle + non-`#commit`
firehose events.

---

# Part I — ActivityPub

Source tree: `src/protocols/activitypub/`. Files: `activity.zig`,
`actor.zig`, `collections.zig`, `delivery.zig`, `http_delivery.zig`,
`inbox.zig`, `key_cache.zig`, `key_fetcher_http.zig`, `keys.zig`,
`nodeinfo.zig`, `outbox_worker.zig`, `plugin.zig`, `routes.zig`,
`schema.zig`, `sig.zig`, `state.zig`, `webfinger.zig`.

## 1. Actor document (AP §4, AS2 §4.1)

| Requirement | Status | Where | Note |
|---|---|---|---|
| Actor IRI (`id`)                              | ✅ | `actor.zig:39` | |
| Actor type                                     | ⚠️ | `actor.zig:40` | `Person` only — no Service/Organization/Group |
| `preferredUsername` / `name` / `summary`       | ✅ | `actor.zig:41-46` | |
| `inbox` / `outbox`                             | ✅ | `actor.zig:49-50` | URLs emitted |
| `followers` / `following`                      | ✅ | `actor.zig:51-52` | URLs emitted |
| `featured`                                     | ✅ URL / ⚠️ contents | `actor.zig:53` | Collection always empty |
| `featuredTags`                                 | ❌ | — | Not emitted |
| `endpoints.sharedInbox`                        | ✅ | `actor.zig:54` | |
| `publicKey` (FEP-521a / Mastodon-required)     | ✅ | `actor.zig:73-79` | Ed25519 or RSA SPKI PEM |
| `manuallyApprovesFollowers`                    | ✅ | `actor.zig:63-64` | From `users.is_locked` |
| `discoverable` / `indexable` (`toot:`)         | ✅ | `actor.zig:66-70` | |
| Multiple keys (FEP-d36d Multikey)              | ❌ | — | Single key per actor |
| JSON-LD `@context` array                       | ✅ | `actor.zig:33-38` | AS2 + toot namespace |
| Conneg `application/activity+json`             | ✅ | `routes.zig:85-93` | Also LD+JSON profile |

## 2. Collections (AP §5, §6)

| Requirement | Status | Where | Note |
|---|---|---|---|
| OrderedCollection index                        | ✅ | `collections.zig:80-89` | `totalItems` + `first` |
| OrderedCollectionPage page                     | ✅ | `collections.zig:102-128` | Single page |
| `partOf` backpointer                           | ✅ | `collections.zig:106` | |
| Multi-page (`next` / `prev`)                   | ❌ | — | No `next`/`prev` emitted; cap is `collections.max_page_items` (40) |
| `?page=N` traversal                            | ⚠️ | `routes.zig:95-122` | Param parsed; only page=1 ever returned |
| Followers / following / outbox routes          | ✅ | `routes.zig:569-572` | GET only |
| `featured` collection contents                 | ❌ | — | Stub; route exists, items always empty |
| `liked` collection (FEP-c648)                  | ❌ | — | Neither URL on actor nor route |
| `replies` per-object                           | ❌ | — | Not emitted |

## 3. Inbox + S2S delivery (AP §7)

| Requirement | Status | Where | Note |
|---|---|---|---|
| `POST /users/:u/inbox`                         | ✅ | `routes.zig:568` | |
| `POST /inbox` (shared inbox)                   | ✅ | `routes.zig:573` | |
| 202 Accepted                                   | ✅ | `routes.zig:426-427` | |
| Actor-matches-signature check                  | ✅ | `inbox.zig:135-136` | |
| Side-effect drain pattern                      | ✅ | `routes.zig:427-445` | Effects queued, drained after 202 |
| Activity audit log                             | ✅ | `schema.zig:112-128` | `ap_activities` table |
| Forwarding-from-inbox (AP §7.1.3)              | ⚠️ | `inbox.zig:194-202` | Create *does* enqueue delivery via `.fanout` to `to_first`. But: only first to-recipient, only Create. Spec wants full cc-followers redistribution per §7.1.3 |
| Recipient resolution (`to`/`cc`/`bto`/`bcc`)    | ❌ | `activity.zig:84-86` | Only `to_first` parsed. `cc`/`bto`/`bcc`/`audience` never inspected on inbound |
| `bto` / `bcc` stripping outbound               | ✅ | `delivery.zig:76-131` | |
| Recipient dedup + shared-inbox preference      | ✅ | `delivery.zig:42-74` | |
| Public addressing (`as:Public`)                | ❌ | — | No special handling |

### 3.1 Activity-type coverage (AS2 vocabulary)

| Activity | Status | Where |
|---|---|---|
| Create   | ✅ full state machine | `inbox.zig:164-207` |
| Update   | ✅ | `inbox.zig:213-241` |
| Delete   | ✅ tombstone + 410 | `inbox.zig:244-269`, `schema.zig` |
| Follow   | ✅ auto-accept if unlocked | `inbox.zig:272-309` |
| Accept   | ✅ | `inbox.zig:312-344` |
| Reject   | ✅ | `inbox.zig:347-373` |
| Announce | ✅ | `inbox.zig:376-402` |
| Like     | ✅ | `inbox.zig:405-431` |
| Undo     | ⚠️ counter only — no `unfollow`/`unlike`/`unboost` cleanup of stored state | `inbox.zig:151` |
| Move     | ⚠️ counter only — no `Move{alsoKnownAs}` migration | `inbox.zig:154` |
| Block    | ⚠️ counter only — no enforcement on subsequent activities | `inbox.zig:155` |
| Flag     | ⚠️ counter only — no moderation queue | `inbox.zig:156` |
| Add / Remove | ❌ | — |
| Question (poll), Listen, Read, View, Travel, Arrive, Leave, Join, Offer, Invite, TentativeAccept, TentativeReject | ❌ | — |

## 4. Outbox (AP §6.3)

| Requirement | Status | Where | Note |
|---|---|---|---|
| `GET /users/:u/outbox` (index)                 | ✅ | `routes.zig:569` | |
| `GET ...?page=N` (page)                        | ⚠️ | `routes.zig:500-520` | Page 1 only |
| `POST /users/:u/outbox` (C2S)                  | ❌ | `routes.zig:563-573` | Route not registered. Confirmed: only `.get` registered |
| 201 Created + Location on C2S                  | ❌ | — | Not applicable until POST exists |

C2S is the load-bearing gap for "independent AP server" posture. Today
clients use the Mastodon API (`/api/v1/statuses`) for posting.

## 5. HTTP signatures (`sig.zig`, `http_delivery.zig`, `keys.zig`)

| Scheme | Status | Where | Note |
|---|---|---|---|
| draft-cavage-12 verify (Ed25519)     | ✅ | `sig.zig:114-167, 425-432` | |
| draft-cavage-12 verify (RSA-SHA256)  | ✅ | `sig.zig:434-438` | Via OpenSSL hook |
| draft-cavage-12 sign (Ed25519)       | ✅ | `http_delivery.zig:190-260` | |
| draft-cavage-12 sign (RSA-SHA256)    | ✅ | `core.crypto.rsa.signPkcs1v15Sha256` | OpenSSL-backed |
| RFC 9421 verify (both algs)          | ✅ | `sig.zig:190-228, 407-442` | `Signature-Input` / `Signature` parsed |
| RFC 9421 sign                        | ❌ outbound | `http_delivery.zig` | Outbound POST only emits cavage-style `Signature` + `Digest` |
| `Digest` header verify (inbound)     | ❌ | `sig.zig:473-483` | Parsed; never compared against body bytes |
| `Content-Digest` header verify       | ❌ | `sig.zig:485-497` | Parsed; never compared |
| `Digest`/`Content-Digest` compute (outbound) | ✅ | `http_delivery.zig:206-207` | SHA-256 of body |
| `created` / `expires` enforcement    | ❌ | `sig.zig:104-106, 156-159, 258-260` | Parsed into `expires_unix` but never compared to clock |
| Replay window / nonce cache          | ❌ | — | Not implemented |

## 6. WebFinger + discovery

| Requirement | Status | Where |
|---|---|---|
| `GET /.well-known/webfinger?resource=acct:` | ✅ | `webfinger.zig`, `routes.zig:564` |
| `subject` / `aliases` / `links`              | ✅ | `webfinger.zig:33-37` |
| `self` (`application/activity+json`)         | ✅ | `webfinger.zig:36` |
| `profile-page` (`text/html`)                 | ✅ | `webfinger.zig:37` |
| Non-`acct:` resource URIs                    | ❌ | — |
| Host-meta (deprecated)                       | — | Intentionally omitted |

## 7. NodeInfo (`nodeinfo.zig`)

| Requirement | Status | Where |
|---|---|---|
| `/.well-known/nodeinfo` JRD              | ✅ | `routes.zig:565`, `nodeinfo.zig:50-57` |
| `/nodeinfo/2.1` document                 | ✅ | `nodeinfo.zig:70-86` |
| `software.{name,version,repository}`     | ✅ | `nodeinfo.zig:71-75` |
| `protocols`: `["activitypub"]`           | ✅ | `nodeinfo.zig:75` |
| Should we declare `protocols: ["activitypub","atproto"]`? | ❌ | NodeInfo schema does not enumerate atproto, but the AT side has its own well-known. Worth advertising "atproto" via custom metadata |
| `usage.users` / `usage.localPosts`       | ✅ | `nodeinfo.zig:79-84` |

## 8. FEP coverage

| FEP | Status |
|---|---|
| FEP-f1d5 NodeInfo                | ✅ |
| FEP-521a actor public keys       | ✅ (single key) |
| FEP-d36d Multikey                | ❌ |
| FEP-c0e0 emoji reactions         | ❌ |
| FEP-c648 likes collection        | ❌ |
| FEP-fb2a actor moves             | ⚠️ counted only |
| FEP-ef61 portable objects        | ❌ |
| FEP-8b32 Data Integrity Proofs   | ❌ |
| FEP-7888 AT↔AP bridging          | ✅ (relay plugin) |
| FEP-67ff `FEDERATION.md`         | ❌ not published |
| FEP-844e capability negotiation  | ❌ |
| FEP-1b12 group federation        | ❌ |

## 9. Object handling

`activity.zig` parses activities with a bounded scanner that captures
`{id, type, actor, object_id, object_type, to_first}`. Object bodies
are stored opaquely in the activity row. This means:

- No dedicated `ap_objects` table (objects live inside their owning
  activity row). Trade-off: smaller schema, weaker "all replies to X"
  queries.
- `inReplyTo` / `attachment` / `tag` (Mention/Hashtag) / `sensitive` /
  `content` are **not** extracted, so threading, hashtag indexing,
  and content-warning surfaces all sit on the Mastodon API side, not
  on AP-native paths.
- `Tombstone` is recognised on Delete (✅), but a 410 GET response
  for a deleted object does not yet return a Tombstone body.

## 10. Linked Data Signatures

Intentionally **not** supported. HTTP signatures (cavage + RFC 9421)
cover the live fediverse. RsaSignature2017 and Data Integrity Proofs
are deferred unless a peer surfaces that needs them.

---

# Part II — AT Protocol (atproto)

Source tree: `src/protocols/atproto/`. Files: `auth.zig`, `car.zig`,
`cid.zig`, `dag_cbor.zig`, `did_resolver.zig`, `did.zig`,
`firehose.zig`, `keypair.zig`, `mst.zig`, `oauth_dpop.zig`,
`plugin.zig`, `repo.zig`, `routes.zig`, `schema.zig`, `state.zig`,
`sync_firehose.zig`, `syntax.zig`, `tid.zig`, `xrpc.zig`.

## 1. Core primitives

| Primitive | Status | Where | Note |
|---|---|---|---|
| CID v1 (sha2-256, dag-cbor 0x71)            | ✅ | `cid.zig` | base32-lower with `b` prefix |
| CID raw codec 0x55 (blobs)                  | ⚠️ | `cid.zig` | Encoder exists, but `routes.zig:832` emits **hex SHA-256** as the blob CID — see AT-10 |
| DAG-CBOR canonical encode                   | ✅ | `dag_cbor.zig` | Sorted map keys, no indefinite forms |
| DAG-CBOR decoder                            | ✅ | `dag_cbor.zig` | Pull visitor |
| CAR v1 writer                               | ✅ | `car.zig` | Varint, header, blocks, roots |
| CAR v1 reader                               | ⚠️ | `car.zig:98+` | Skeleton — server-side write only |
| TID (13-char base32-sortable)               | ✅ | `tid.zig` | Monotonic per-process clock id |
| NSID syntax                                 | ✅ | `syntax.zig:96-111` | |
| Handle syntax                               | ✅ | `syntax.zig:39-92` | |
| AT-URI parsing                              | ⚠️ | `syntax.zig` | Constructs work in routes; parse roundtrip not heavily tested |
| MST — read + write                          | ⚠️ | `mst.zig` | Flat sorted store + commit CID over leaf list. Hierarchical hash-derived fanout *not* implemented — header notes "tree-shape encoding... in follow-up phase" |

## 2. Crypto + keys (`keypair.zig`, `core/crypto/`)

| Capability | Status | Where | Note |
|---|---|---|---|
| Ed25519 sign / verify        | ✅ | `keypair.zig:54-73`, `core/crypto/ed25519.zig` | |
| Ed25519 multicodec `0xed01`  | ✅ | `keypair.zig:94-105` | |
| secp256k1 sign / verify (low-S) | ✅ | `core/crypto/secp256k1.zig`, `keypair.zig:75-92` | Layered on stdlib `EcdsaSecp256k1Sha256`; low-S normalize on emit, reject high-S on verify. **The "stub" comment in `keypair.zig:75` is stale** — the body calls the real `core.crypto.secp256k1.sign/verify` |
| secp256k1 multicodec `0xe7`  | ✅ | `keypair.zig:106-112` | |
| `did:key` Ed25519 round-trip | ✅ | `keypair.zig:127-143` | |
| `did:key` secp256k1 round-trip | ✅ | `keypair.zig:106-112` | |
| P-256 (ES256) sign / verify  | ❌ | — | Not implemented (used by DPoP-only clients) |
| Argon2id password hashing    | ✅ | `auth.zig:35-88`, `core/crypto/argon2id.zig` | PHC-string round-trip |
| Multibase encode/decode      | ✅ | `core/crypto/multibase.zig` | |
| Multicodec varint            | ✅ | `core/crypto/multicodec.zig` | |

## 3. Repository (`repo.zig`, `mst.zig`)

| Capability | Status | Where | Note |
|---|---|---|---|
| Record persistence (`atp_records`)      | ✅ | `repo.zig`, `schema.zig` | |
| Commit record (`atp_commits`)           | ✅ | `repo.zig:38-56`, `routes.zig:721-732` | |
| Commit CBOR shape: full spec fields     | ❌ | `routes.zig:721-732` | Stub: `{did, data, sig}`. Missing `version`, `prev`, canonical `rev`. AT-11 |
| Commit signature (Ed25519)              | ✅ | `repo.zig`, via `core.crypto.ed25519` | |
| Commit signature (secp256k1)            | ✅ | now possible — `keypair.signSecp256k1` reachable | Untested at the commit-path boundary |
| MST persistence as blocks (`atp_mst_blocks`) | ❌ | — | Full-tree reload per commit; tracked as PUNCHLIST D4 |
| `prev` chain integrity                  | ⚠️ | — | `Commit.prev` field not written; chain rebuild on import unreliable |

## 4. XRPC endpoint coverage (`routes.zig`, `xrpc.zig`)

Implemented (grep-verified against `src/protocols/atproto/routes.zig`):

```
com.atproto.server.describeServer
com.atproto.server.createSession        (legacy JWT)
com.atproto.server.refreshSession
com.atproto.repo.createRecord
com.atproto.repo.putRecord              (delegates to createRecord — see AT-X below)
com.atproto.repo.getRecord
com.atproto.repo.deleteRecord
com.atproto.repo.listRecords
com.atproto.repo.describeRepo
com.atproto.repo.uploadBlob
com.atproto.sync.getRepo                (CAR)
com.atproto.sync.getRecord              (CAR)
com.atproto.sync.getBlocks              (CAR)
com.atproto.sync.listRepos
com.atproto.sync.subscribeRepos         (WS firehose)
com.atproto.identity.resolveHandle
/.well-known/atproto-did
```

**Missing** (verified by grep against `routes.zig` + `plugin.zig`):

| Namespace | Missing |
|---|---|
| `com.atproto.server.*` | `createAccount`, `deleteAccount`, `requestPasswordReset`, `resetPassword`, `requestEmailUpdate`, `confirmEmail`, `updateEmail`, `requestEmailConfirmation`, `createAppPassword`, `listAppPasswords`, `revokeAppPassword`, `createInviteCode(s)`, `getAccountInviteCodes`, `checkAccountStatus`, `activateAccount`, `deactivateAccount`, `requestAccountDelete`, `reserveSigningKey`, `getServiceAuth`, `deleteSession`, `getSession` |
| `com.atproto.repo.*` | `applyWrites`, `importRepo`, `listMissingBlobs` |
| `com.atproto.sync.*` | `getBlob`, `getLatestCommit`, `listBlobs`, `notifyOfUpdate`, `requestCrawl`, `getRepoStatus` |
| `com.atproto.identity.*` | `resolveDid`, `resolveIdentity`, `updateHandle`, `getRecommendedDidCredentials`, `signPlcOperation`, `submitPlcOperation`, `requestPlcOperationSignature` |
| `com.atproto.label.*` | `queryLabels`, `subscribeLabels` |
| `com.atproto.moderation.*` | `createReport` |
| `com.atproto.admin.*` | all (~14 endpoints) |
| `com.atproto.temp.*` | `checkSignupQueue`, optional |

`putRecord` quietly delegates to `createRecord` — same INSERT-OR-REPLACE
semantics fall out by accident, but `swapRecord` / `swapCommit` CAS
parameters are not honoured. AT-X.

## 5. Auth

| Mode | Status | Where | Note |
|---|---|---|---|
| Legacy JWT (Ed25519 HS-style)            | ✅ | `auth.zig:90-182` | Access (1h) + refresh (90d), JTI tracked |
| Session refresh                          | ✅ | `routes.zig:116-160` | |
| Session delete (logout)                  | ❌ | — | No `deleteSession` endpoint |
| App passwords                            | ❌ | — | Not implemented |
| OAuth 2.1 metadata endpoints             | ❌ | — | No `/.well-known/oauth-authorization-server` or `/.well-known/oauth-protected-resource` |
| PAR (Pushed Authorization Requests)      | ❌ | — | |
| PKCE S256                                 | ❌ | — | |
| Authorization code flow                   | ❌ | — | |
| DPoP proof verification (Ed25519)        | ✅ | `oauth_dpop.zig` | Verifier + replay-jti ring |
| DPoP proof verification (ES256)          | ❌ | `oauth_dpop.zig:13` | Returns `NotImplemented` |
| `DPoP-Nonce` response header             | ❌ | — | |
| Service auth (PDS↔relay/AppView JWTs)    | ❌ | — | |
| Scope enforcement on routes              | ⚠️ | `routes.zig` | JWT verified, but `scope` not gated per endpoint |

OAuth is the **single largest hole** for being a real network
participant. Today's clients (Bluesky official app, third-party apps)
all use the OAuth flow; only legacy clients use createSession/JWT.

## 6. Firehose + sync (`firehose.zig`, `sync_firehose.zig`)

| Capability | Status | Where | Note |
|---|---|---|---|
| Event persistence (`atp_firehose_events`)  | ✅ | `firehose.zig:1-81` | Append-only with monotonic seq |
| Cursor (`atp_firehose_cursor`)             | ✅ | `firehose.zig` | |
| `subscribeRepos` WS handler                | ✅ | `sync_firehose.zig:1-250` | Replay + live phases |
| `#commit` events                           | ✅ | `sync_firehose.zig:186-191` | dag-cbor frame, correct shape |
| `#identity` events                         | ❌ | — | Never appended |
| `#account` events                          | ❌ | — | |
| `#handle` (deprecated) / `#migrate` / `#tombstone` | ❌ | — | |
| `#info` (cursor warning)                   | ❌ | — | |
| In-process local sink                      | ✅ | `firehose.zig:30-40` | Used by relay consumer |
| External relay subscription (downstream)   | ❌ | — | If we want to consume an upstream relay's firehose, this is not wired |

Without `#identity` / `#account`, AppViews and downstream relays
cannot maintain a correct identity-to-handle index when a user
rotates their DID or changes handle.

## 7. Blobs

| Capability | Status | Where | Note |
|---|---|---|---|
| `uploadBlob` route                       | ✅ | `routes.zig:799-878` | Stores into `atp_blobs` |
| `BlobRef` `$type: "blob"` shape          | ✅ | `routes.zig` | |
| Blob CID is proper CIDv1 raw codec       | ❌ | `routes.zig:832-833` | Currently emits **hex SHA-256** instead of `b<base32>(0x01 0x55 0x12 0x20 ...)`. Interop bug. AT-10 |
| `sync.getBlob` route                     | ❌ | — | Blobs upload-only; not retrievable. AT-6 |
| `listBlobs` / `listMissingBlobs`         | ❌ | — | |
| Inline vs spilled-to-FS                  | ✅ via media plugin | `core.limits.media_inline_threshold_bytes` (16 KiB) | Media plugin handles AP-side spillover; AT side stores inline only |
| Orphan blob GC                           | ❌ | — | Ref-counted in schema but no sweep |

## 8. DID + identity

| Capability | Status | Where | Note |
|---|---|---|---|
| `did:plc` parse                          | ✅ | `did.zig:48-80` | |
| `did:web` parse                          | ✅ | `did.zig:48-80` | |
| `did:key` parse + format                 | ⚠️ | `keypair.zig:94-143` | Ed25519 + secp256k1 only; P-256 missing |
| `did:plc` resolution (HTTP to plc.directory) | ⚠️ | `did_resolver.zig:56-104` | Skeleton; needs HttpFetcher attached at boot |
| `did:web` resolution                     | ⚠️ | `did_resolver.zig:81-84` | Skeleton; same constraint |
| Handle → DID (HTTPS well-known)          | ✅ | `did_resolver.zig:95-104`, `routes.zig:316-335` | |
| Handle → DID (DNS TXT `_atproto.<handle>`) | ❌ | — | No DNS resolver wired |
| Our own DID document with `verificationMethod` (`#atproto`) + `service` (`#atproto_pds`, `AtprotoPersonalDataServer`) + `alsoKnownAs: at://<handle>` | ❌ | `routes.zig:299-309` | Only the DID **string** at `/.well-known/atproto-did`; no `did.json` document served |
| PLC ops sign / submit                    | ❌ | — | No key rotation path |

## 9. Lexicon validation

Status: **missing**. `routes.zig:186-194` notes "production would
lexicon-validate then re-encode canonically." Today:

- No schema parser.
- No `$type` ↔ NSID consistency check.
- Records stored as the bytes the client sent — **not** re-encoded
  to canonical DAG-CBOR. That makes CIDs reproducible by the client
  but breaks if a client submits non-canonical CBOR.
- No method-side validation of XRPC input/output objects.

This is a federation hazard: a record we accepted may not round-trip
through an AppView that *does* enforce canonical CBOR.

## 10. Account + moderation lifecycle

Status: **missing**.

- No `createAccount` → operators must seed users directly via
  `auth.setPassword` or test fixtures.
- No `deleteAccount` / `deactivateAccount` / `requestAccountDelete`.
- No email verification flow.
- No invite codes / signup queue.
- No `com.atproto.moderation.createReport` (user-facing report API).
- No `com.atproto.label.*` (label query + subscription).
- No `com.atproto.admin.*` (remote management).

## 11. Storage schema

Present (`schema.zig`): `atp_repos`, `atp_records`, `atp_commits`,
`atp_blobs`, `atp_firehose_events`, `atp_firehose_cursor`, plus the
AP-side tables and relay tables.

Missing: `atp_mst_blocks` (PUNCHLIST D4), `atp_app_passwords`,
`atp_invite_codes`, `atp_signup_queue`, `atp_labels`,
`atp_moderation_reports`, `atp_oauth_clients`, `atp_oauth_sessions`,
`atp_dpop_nonces`.

---

# Part III — Cross-cutting

## 12. Running both protocols on one host

This is the load-bearing user requirement: be a node on each network
simultaneously, sharing one process. Today:

- ✅ Plugin contract (`core/plugin.zig`) supports both AP and AT
  plugins loaded into the same `Registry`.
- ✅ Shared storage handle (`atp_*` and `ap_*` tables coexist in one
  SQLite file).
- ✅ Shared HTTP server and TLS termination.
- ✅ Shared metrics, ring log, shutdown coordinator.
- ⚠️ No tenant isolation — if we host multiple users on AP *and* the
  same identities should mirror to AT (or vice versa), the
  identity-mapping is via the relay's `relay_identity_map`, not a
  first-class "user X has identity (a) on AP and (b) on AT" table.
- ⚠️ No unified account creation — creating an account today gives
  you an AP user (Mastodon API) and *separately* gives you an AT
  repo. No "one signup, both protocols" path.
- ❌ NodeInfo advertises only `["activitypub"]` even though atproto
  is also speaking. Custom metadata should mention atproto so peer
  servers can discover dual-protocol support.

## 13. Bridge (relay plugin)

Out of scope for this audit — see [`docs/design/translation-matrix.md`](docs/design/translation-matrix.md)
for the per-activity coverage, and the `A.*` block in
[`PUNCHLIST.md`](PUNCHLIST.md) for operational items.

---

# How to use this audit

1. Treat each row in the tables above as a fact to verify before
   relying on it. If a status doesn't match the code today, fix the
   doc.
2. New work that closes a gap should reference the corresponding
   ticket in [`SPEC_PUNCHLIST.md`](SPEC_PUNCHLIST.md) (e.g. "Closes
   AT-3") in the commit message.
3. When you ship a feature that adds a new spec surface, add a row
   here in the same commit. Drift on this doc has burned us before;
   the 2026-03-17 version pointed at files that didn't exist by May.
4. The audits behind this rewrite were two parallel Explore-agent
   passes on 2026-05-19; both reports were sanity-checked against
   the actual source tree before this document was written.
   Corrections applied during the rewrite:
   - AP "no fanout" → corrected to "partial fanout on Create only".
   - AT "secp256k1 not implemented" → corrected to "implemented in
     `core/crypto/secp256k1.zig` with low-S; `keypair.zig:75`
     comment is stale and should be updated".
