# FEDERATION.md — speedy-socials (FEP-67ff)

This document summarises what `speedy-socials` federates with, which
ActivityPub features it implements, and where the known gaps are.
Maintained alongside [`PROTOCOL_AUDIT.md`](../PROTOCOL_AUDIT.md) and
[`SPEC_PUNCHLIST.md`](../SPEC_PUNCHLIST.md). When you ship a change
that affects federation, update both this file and the relevant row
in the audit.

_Last updated: 2026-05-20._

---

## Identity

- **Software name**: `speedy-socials`
- **Protocol**: ActivityPub (W3C REC, Jan 2018) + extensions
- **Also speaks**: AT Protocol (atproto). The two protocols share
  one process, one storage layer, one identity table where
  cross-protocol bridging is enabled.
- **NodeInfo**: `/.well-known/nodeinfo` + `/nodeinfo/2.1`. The
  metadata block surfaces `{atproto: {enabled, did}}` when both
  protocols are loaded.
- **Source**: <https://github.com/anthropics/speedy-socials>

## Actors

- One actor type: `Person` (Service / Organization / Group planned
  via AP-10).
- `publicKey` block carries an Ed25519 or RSA-SHA256 SPKI PEM
  (FEP-521a). Multiple keys per actor (FEP-d36d Multikey) planned
  via AP-15.
- `manuallyApprovesFollowers` (locked accounts) honoured.
- `discoverable` and `indexable` (Mastodon `toot:` namespace).
- `featured` URL emitted; population planned via AP-11.

## Activities — server-to-server

| Activity | Status |
|---|---|
| Create   | Implemented (full state machine, fanout to `to_first`) |
| Update   | Implemented |
| Delete   | Implemented (Tombstone + 410 Gone — AP-12) |
| Follow   | Implemented (auto-accept on unlocked accounts) |
| Accept   | Implemented (mirrors outbound Follow state) |
| Reject   | Implemented |
| Announce | Implemented |
| Like     | Implemented |
| Undo     | Implemented (Undo{Follow/Like/Announce} fully reverses) |
| Move     | Counter only; full migration via AP-26 |
| Block    | Counter only; enforcement via AP-25 |
| Flag     | Counter only |
| Add/Remove | Planned via AP-8 |
| Question (poll) | Planned via AP-16 |

## Client-to-server (C2S)

- **Status**: not implemented. Clients post via the Mastodon API
  (`/api/v1/statuses`). Native AP C2S outbox POST is tracked as
  AP-1; it ships with AT-1 OAuth so the two share an auth surface.

## HTTP signatures

- **draft-cavage-http-signatures-12**: implemented (verify + sign,
  Ed25519 + RSA-SHA256).
- **RFC 9421 HTTP Message Signatures**: verify + parse implemented.
  Outbound signing (configurable per peer) tracked as AP-9.
- **`Digest` and `Content-Digest` body verification**: implemented
  (constant-time compare against SHA-256 of the request body) —
  AP-4.
- **Signature freshness** (`created` / `expires`): enforced with
  ±300 s clock skew, 12 h max age — AP-5.
- **Replay-window nonce cache**: planned via AP-20.

## Collections

- `inbox`, `outbox`, `followers`, `following`, `featured`,
  `replies` (planned) emitted as URLs.
- Read paths: `OrderedCollection` index + first-page
  `OrderedCollectionPage`. Multi-page traversal with `next`/`prev`
  planned via AP-7.

## Discovery

- **WebFinger** (RFC 7033): `/.well-known/webfinger` serves
  `acct:`-resolved actor records. Non-`acct:` resource URIs
  planned via AP-28.
- **NodeInfo** (FEP-f1d5): JRD at `/.well-known/nodeinfo`, document
  at `/nodeinfo/2.1`.

## FEP support

| FEP | Status |
|---|---|
| FEP-67ff (FEDERATION.md) | ✅ this document |
| FEP-f1d5 (NodeInfo)       | ✅ |
| FEP-521a (actor public keys) | ✅ (one key per actor) |
| FEP-d36d (Multikey)       | Planned via AP-15 |
| FEP-c0e0 (emoji reactions) | Planned via AP-13 |
| FEP-c648 (likes collection) | Planned via AP-14 |
| FEP-7888 (AT↔AP bridging)  | ✅ (relay plugin, ADR-002) |
| FEP-fb2a (actor moves)    | Partial (counter only) |
| FEP-ef61 (portable objects) | Not planned |
| FEP-8b32 (Data Integrity proofs) | Deferred (HTTP sigs preferred) |
| FEP-1b12 (group federation) | Not planned |

## Known incompatibilities

- **Threading**: `inReplyTo` is captured but reply chains are not
  yet queryable via a `replies` collection or `/context` endpoint.
  Planned via AP-18.
- **Attachments**: not extracted from inbound activities. The
  Mastodon-API path handles attachments locally; remote media is
  not surfaced uniformly. Planned via AP-23 (depends on INFRA-3).
- **Mentions / hashtags**: not extracted from `tag[]`. Planned via
  AP-17.
- **Polls (Question)**: not supported. Planned via AP-16.
- **Block enforcement**: blocking activities are counted but don't
  reject subsequent activities from the blocked actor. Planned via
  AP-25.
- **Recipient resolution**: only the first `to` IRI is parsed;
  `cc`/`bto`/`bcc`/`audience` are dropped on the floor. Planned via
  AP-2.

## Operations + privacy

- **Strict signatures**: opt-in via `STRICT_HTTP_SIG=1`. Off by
  default for compatibility. Rejects inbound activities without a
  verifiable signature.
- **`bto` / `bcc` stripping**: outbound activities have these
  fields removed before delivery (W3C AP §6.2 requirement).
- **Audit log**: every accepted inbound activity is recorded in
  `ap_activities` with its raw body.
- **Rate limiting**: per-IP token bucket, configurable via
  `RATE_LIMIT=<capacity>:<refill_per_sec>`.

## Reporting bugs / asking for FEP coverage

Open an issue at the repo URL above. Federation incompatibilities
are P0; missing optional features are tagged as their corresponding
AP-* punchlist ticket.
