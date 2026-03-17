# Protocol Conformance Audit

**Date**: 2026-03-17
**Scope**: ActivityPub (W3C + Mastodon extensions + FEPs) and AT Protocol (atproto PDS)
**Baseline**: Latest specs as of March 2026

---

## ActivityPub

### CRITICAL — Blocks federation with any real server

#### AP-C1: HTTP Signatures are fake
**Files**: `src/activitypub.zig:600-604`, `src/federation.zig:103-105`
**Issue**: `generateHttpSignature()` fills the signature with `crypto.random.bytes` instead of performing RSA-SHA256 signing. No remote server will accept these.
**Spec**: draft-cavage-http-signatures-12, RFC 9421
**Fix**: Implement real RSA-PKCS1-v1_5 signing with SHA-256. Generate a 2048-bit RSA key pair per actor, store the private key in the database, and use it to sign the `(request-target)`, `host`, `date`, and `digest` headers.

#### AP-C2: No HTTP Signature verification
**File**: `src/activitypub.zig:380-390`
**Issue**: `verifyHttpSignature()` returns `true` unconditionally. Any actor can forge activities to the inbox.
**Spec**: draft-cavage-http-signatures-12 Section 3.2, RFC 9421
**Fix**: Parse the `Signature` header, fetch the remote actor's public key via their `publicKey.id`, reconstruct the signing string from the declared headers, and verify the RSA-SHA256 signature.

#### AP-C3: No RFC 9421 (HTTP Message Signatures) support
**Issue**: Mastodon 4.5+ enables RFC 9421 by default. Servers that only speak draft-cavage will lose interop over time.
**Spec**: RFC 9421
**Fix**: Support both draft-cavage-12 and RFC 9421. On outbound, use draft-cavage for now with RFC 9421 as opt-in. On inbound, accept both. RFC 9421 uses separate `Signature-Input` and `Signature` headers and signs `@method`, `@target-uri`, `content-digest`, `content-type`.

#### AP-C4: Mock RSA keys on actors
**File**: `src/activitypub.zig:257`
**Issue**: `publicKeyPem` is a hardcoded `"MOCK_PUBLIC_KEY"` string. Remote servers fetching the actor to verify signatures will get garbage.
**Fix**: Generate a real RSA-2048 key pair on account creation. Store private key in a new `actor_keys` table. Serve the PEM-encoded public key in the actor's `publicKey.publicKeyPem` field.

#### AP-C5: All incoming activity handlers are empty
**File**: `src/activitypub.zig:455-522`
**Issue**: `handleIncomingNote`, `handleIncomingFollow`, `handleIncomingLike`, `handleIncomingAccept`, `handleIncomingReject`, `handleIncomingUndo`, `handleIncomingUpdate`, `handleIncomingDelete` are all no-ops with `TODO` comments. The inbox accepts activities but discards them.
**Fix**: Implement each handler:
- `Follow` → store relationship, auto-send `Accept` (or queue for approval if `is_locked`), send `Accept`/`Reject` activity back
- `Create(Note)` → store remote post with `federated=true` flag, resolve mentions, index for search
- `Like` → increment favourite count, store remote like
- `Announce` → store as reblog, increment reblog count
- `Undo` → reverse the original activity (unfollow, unlike, unboost)
- `Delete` → mark object as deleted, return 410 Gone on future fetches
- `Update` → update stored remote object content
- `Accept`/`Reject` → update pending follow state

#### AP-C6: Hardcoded follower inboxes
**File**: `src/activitypub.zig:742-743`
**Issue**: `getFollowersInboxes()` returns hardcoded `mastodon.social/inbox` and `pixelfed.social/inbox` instead of querying the database. Would spam real public instances.
**Fix**: Query the database for followers, join with a remote actors table that stores their inbox/shared inbox URLs. Deduplicate by shared inbox to reduce delivery requests.

#### AP-C7: No Content-Type negotiation on actor endpoints
**Issue**: Actor profiles must be served as `application/activity+json` when the client sends `Accept: application/activity+json` or `Accept: application/ld+json; profile="https://www.w3.org/ns/activitystreams"`. No Accept header checking exists in the server routing.
**Spec**: W3C ActivityPub Section 3.2
**Fix**: Check the `Accept` header on `/users/{username}` requests. If it includes `application/activity+json` or the LD+JSON profile, serve the ActivityPub JSON-LD representation. Otherwise serve the HTML profile page.

#### AP-C8: Broken timestamp conversion
**File**: `src/activitypub.zig:525-528`
**Issue**: `timestampToIso8601()` always returns the hardcoded string `"2024-01-01T00:00:00Z"`. Every activity and note will have the same fake timestamp.
**Fix**: Implement real Unix timestamp to ISO 8601 conversion using `std.time.epoch` or manual calculation.

---

### HIGH — Required for Mastodon interoperability

#### AP-H1: No NodeInfo endpoint
**Issue**: `/.well-known/nodeinfo` is not implemented. Mastodon and other fediverse software use NodeInfo for server discovery, population stats, and protocol capability advertisement.
**Spec**: NodeInfo 2.1 (FEP-f1d5, FEP-0151)
**Fix**: Add `GET /.well-known/nodeinfo` returning a JRD with a link to a NodeInfo 2.1 document. The NodeInfo document must include `software.name`, `software.version`, `protocols: ["activitypub"]`, `openRegistrations`, and `usage.users` stats from the database.

#### AP-H2: Actor missing `featured` collection
**Issue**: Mastodon expects a `featured` field on actors pointing to an `OrderedCollection` of pinned posts. Missing from `PersonObject`.
**Spec**: Mastodon ActivityPub extensions (`toot:featured`)
**Fix**: Add `featured` and `featuredTags` URLs to `PersonObject`. Serve `GET /users/{username}/collections/featured` as an `OrderedCollection`.

#### AP-H3: Actor missing `discoverable` and `indexable`
**Issue**: These Mastodon namespace fields control profile directory inclusion and full-text search opt-in. Present in the Mastodon API `Account` type but missing from the ActivityPub `PersonObject`.
**Spec**: Mastodon namespace (`toot:discoverable`, `toot:indexable`)
**Fix**: Add `discoverable: bool` and `indexable: bool` to `PersonObject`. Source values from user profile settings.

#### AP-H4: Actor missing `manuallyApprovesFollowers`
**Issue**: Required for locked/approval-required accounts. The `is_locked` field exists in the database but is not exposed in the ActivityPub actor representation.
**Spec**: ActivityStreams 2.0 extension (widely adopted)
**Fix**: Add `manuallyApprovesFollowers: bool` to `PersonObject`, sourced from `users.is_locked`.

#### AP-H5: No outbox endpoint
**Issue**: Routes include `/users/{username}/inbox` but no `/users/{username}/outbox`. The outbox is required by the W3C spec as a readable `OrderedCollection` of the actor's published activities.
**Spec**: W3C ActivityPub Section 5.1
**Fix**: Implement `GET /users/{username}/outbox` returning an `OrderedCollection` with the user's public posts wrapped in `Create` activities, paginated.

#### AP-H6: No followers/following collection endpoints
**Issue**: URLs for `followers` and `following` are generated in actor objects (`activitypub.zig:251-252`) but no server routes serve these collections.
**Spec**: W3C ActivityPub Section 5.3, 5.4
**Fix**: Implement `GET /users/{username}/followers` and `GET /users/{username}/following` as paginated `OrderedCollection` responses. For privacy, return only the `totalItems` count to non-authenticated requests, and the full list to the account owner.

#### AP-H7: No Delete/Tombstone handling
**Issue**: The spec requires that deleted objects return 410 Gone with a `Tombstone` object. No implementation exists for sending `Delete` activities or responding with tombstones.
**Spec**: W3C ActivityPub Section 6.4, ActivityStreams 2.0 `Tombstone` type
**Fix**: When a user deletes a post, send a `Delete` activity with a `Tombstone` object to all followers. Store a tombstone record in the database. Return 410 with the tombstone on future GET requests for the deleted object's URI.

#### AP-H8: No `bto`/`bcc` stripping before delivery
**Issue**: The spec mandates removing `bto` and `bcc` fields from activities before delivering them to remote servers (they are used only for recipient calculation).
**Spec**: W3C ActivityPub Section 6.2
**Fix**: Strip `bto` and `bcc` from the serialized activity JSON before sending to any remote inbox.

#### AP-H9: No recipient deduplication
**Issue**: The spec requires deduplicating recipients across `to`, `cc`, `bto`, `bcc` and excluding the activity's own actor from the recipient list.
**Spec**: W3C ActivityPub Section 6.10
**Fix**: Build a deduplicated set of recipient inbox URLs. Remove the sending actor from the set. Use shared inboxes where available to reduce request count.

#### AP-H10: Like/Announce `object` field type mismatch
**Files**: `src/activitypub.zig:358`, `src/activitypub.zig:374`
**Issue**: For `Like` and `Announce` activities, the `object` field should be a URI string referencing the target. The code wraps it in a `NoteObject` struct with only an `id` field, which may not serialize correctly for remote servers.
**Fix**: The `object` field for `Like` and `Announce` should be a plain URI string (the target post's ActivityPub ID), not a full object.

---

### MEDIUM

#### AP-M1: Deprecated Atom link in WebFinger
**File**: `src/activitypub.zig:558-559`
**Issue**: WebFinger includes `http://schemas.google.com/g/2010#updates-from` with an Atom XML link. This is from the OStatus era and no longer relevant.
**Fix**: Remove the Atom link. Keep the `self` link (`application/activity+json`) and the `profile-page` link (`text/html`).

#### AP-M2: No `url` field on NoteObject
**Issue**: ActivityPub Note objects should include a `url` field pointing to the human-readable HTML page for the post. Missing from `NoteObject`.
**Fix**: Add `url: ?[]const u8` to `NoteObject`, set to `https://speedy-socials.local/@{username}/{post_id}`.

#### AP-M3: WebFinger Content-Type inconsistency
**Issue**: `federation.zig:321` correctly sets `application/jrd+json`, but `activitypub.zig:createWebFinger()` does not set a content type (it returns a struct, leaving content type to the caller). Ensure all WebFinger responses use `application/jrd+json`.

---

## AT Protocol

### CRITICAL — Not a functioning PDS

#### AT-C1: No repository (MST) implementation
**Issue**: AT Protocol requires records to be stored in a Merkle Search Tree, producing content-addressed commits. Records are currently stored in a flat `ArrayList` in memory (`src/api/atproto.zig:11`). No CAR file export, no commit objects, no content addressing, no revision tracking.
**Spec**: AT Protocol Repository specification (commit version 3, SHA-256 MST, DRISL-CBOR encoding)
**Fix**: Implement the MST data structure: SHA-256 hashing with 2-bit chunk prefix counting, key-sorted record storage, deterministic tree shape. Store MST nodes in SQLite. Implement CAR v1 export for `getRepo`.

#### AT-C2: No cryptographic signing of commits
**Issue**: Repository commits must be signed with the account's signing key (Ed25519 or secp256k1). No key generation or signing exists.
**Spec**: AT Protocol Repository — commit object `sig` field
**Fix**: Generate a signing key pair on account creation. Sign the DRISL-CBOR serialized unsigned commit with SHA-256 hash. Store the raw signature bytes in the commit's `sig` field.

#### AT-C3: No OAuth/DPoP authentication
**Issue**: AT Protocol's primary auth system (since September 2024) is OAuth with mandatory DPoP (ES256), PKCE (S256 only), and PAR. The implementation only has a simplified Bearer token system.
**Spec**: AT Protocol OAuth specification
**Required endpoints**:
- `/.well-known/oauth-protected-resource` — resource server metadata
- `/.well-known/oauth-authorization-server` — authorization server metadata
- PAR endpoint for pushed authorization requests
- Token endpoint with DPoP validation
**Fix**: This is a large implementation effort. As a stepping stone, the legacy `createSession`/`refreshSession` JWT auth is still supported for backward compatibility, but it needs real password verification and proper JWT signing.

#### AT-C4: DID document non-compliant
**File**: `src/api/atproto.zig:26-39`
**Issues**:
1. Service `id` is `"#bsky_pds"` — must be `"#atproto_pds"`
2. Missing `alsoKnownAs` array containing `at://{handle}`
3. Missing `verificationMethod` array with a `Multikey`-type entry, `id` ending in `#atproto`, and `publicKeyMultibase` field
4. Returns the DID document as JSON — `/.well-known/atproto-did` should return the DID string as `text/plain`, not the document
**Spec**: AT Protocol Identity — DID Document requirements
**Fix**: Change `/.well-known/atproto-did` to return the DID string as plain text. Serve the DID document at `/.well-known/did.json` (for `did:web` resolution). Add required fields.

#### AT-C5: `/.well-known/atproto-did` returns wrong format
**File**: `src/api/atproto.zig:25-47`
**Issue**: Returns a full JSON DID document. The spec requires this endpoint to return only the DID string (e.g., `did:web:speedy-socials.local`) as `text/plain`.
**Fix**: Return just the DID string with `Content-Type: text/plain`.

#### AT-C6: No sync endpoints
**Issue**: The entire `com.atproto.sync.*` namespace is missing. This includes the critical `subscribeRepos` WebSocket firehose that relays and AppViews use to consume data. Without this, the PDS is isolated.
**Required endpoints**: `getRepo`, `getRecord`, `getBlob`, `getBlocks`, `getLatestCommit`, `getRepoStatus`, `listBlobs`, `listRepos`, `subscribeRepos`, `notifyOfUpdate`, `requestCrawl`
**Fix**: Implement after the MST/repository layer is in place.

#### AT-C7: No identity endpoints
**Issue**: `com.atproto.identity.*` namespace is entirely missing.
**Required endpoints**: `resolveHandle`, `resolveDid`, `resolveIdentity`, `updateHandle`, `getRecommendedDidCredentials`, PLC operation endpoints
**Fix**: At minimum implement `resolveHandle` (returns DID for a handle) and `updateHandle`.

#### AT-C8: ~65 missing XRPC endpoints
**Issue**: Only 6 of ~70+ required XRPC endpoints are implemented: `describeServer`, `createSession`, `createRecord`, `listRecords`, `putRecord`, `getTimeline`.
**Missing namespaces**: Most of `com.atproto.server` (account management, app passwords, email, invites), most of `com.atproto.repo` (deleteRecord, getRecord, applyWrites, uploadBlob), all of `com.atproto.sync`, all of `com.atproto.identity`, all of `com.atproto.label`, all of `com.atproto.moderation`, all of `com.atproto.admin`.

#### AT-C9: `createSession` accepts any credential
**File**: `src/api/atproto.zig:88`
**Issue**: No password validation. Any identifier creates a valid session. This is a security vulnerability.
**Fix**: Validate credentials against the users table. Hash the provided password and compare with `password_hash`. Return `AuthenticationRequired` error on mismatch.

#### AT-C10: Records not persisted
**File**: `src/api/atproto.zig:11`
**Issue**: All AT Protocol records are stored in a global `ArrayList` in memory. Data is lost on process restart.
**Fix**: Store records in SQLite, ideally as MST nodes. As an interim step, a `records` table with `repo`, `collection`, `rkey`, `value` (JSON), `cid`, `created_at` columns would suffice.

#### AT-C11: Fake CIDs
**File**: `src/api/atproto.zig:184`
**Issue**: `createRecord` returns a random string as the CID. AT Protocol CIDs must be CIDv1 with SHA-256 hash and DAG-CBOR (or DRISL) codec, computed from the actual record content.
**Fix**: Serialize the record as CBOR, SHA-256 hash it, and produce a CIDv1 with codec `0x71` (dag-cbor) and hash `0x12` (sha2-256).

#### AT-C12: Fake record URIs
**File**: `src/api/atproto.zig:183`
**Issue**: Record key is hardcoded as `"record_id"`. AT Protocol record keys should be TIDs (timestamp-based identifiers: base32-sortable encoding of microsecond timestamp + clock ID).
**Fix**: Generate proper TIDs. Format: 13-character base32-sortable string encoding a 64-bit timestamp in microseconds.

#### AT-C13: `putRecord` delegates to `createRecord`
**File**: `src/api/atproto.zig:281-285`
**Issue**: `putRecord` just calls `createRecord`. Real put semantics require finding the existing record by collection+rkey, replacing it, updating the MST, and optionally supporting `swapRecord`/`swapCommit` for compare-and-swap.
**Fix**: Implement actual upsert logic with CAS support.

---

### HIGH

#### AT-H1: No Lexicon validation
**Issue**: Records should be validated against their Lexicon schema before storage. A record with `$type: "app.bsky.feed.post"` should be checked for required fields (`text`, `createdAt`, etc.). No validation exists.
**Fix**: Implement Lexicon schema loading and validation. At minimum, validate the built-in `app.bsky.*` schemas.

#### AT-H2: No `refreshSession` or `deleteSession`
**Issue**: Session lifecycle is incomplete. Clients cannot refresh expired tokens or log out.
**Fix**: Implement `com.atproto.server.refreshSession` (issue new access token from refresh token) and `com.atproto.server.deleteSession` (invalidate current session).

#### AT-H3: `describeServer` missing fields
**File**: `src/api/atproto.zig:49-56`
**Issue**: Missing `contact` info and supported DID methods list. Should declare capabilities.
**Fix**: Add `contact` object and `did` method support declaration.

#### AT-H4: No blob handling
**Issue**: `com.atproto.repo.uploadBlob`, `com.atproto.sync.getBlob`, `com.atproto.sync.listBlobs`, `com.atproto.repo.listMissingBlobs` are all missing. Media attachments cannot be stored or served.
**Fix**: Implement blob upload (store in filesystem or object storage), generate CIDv1 references (raw codec `0x55`, SHA-256), and serve blobs with proper Content-Security-Policy headers.

---

### MEDIUM

#### AT-M1: No XRPC error format
**Issue**: XRPC errors should return `{"error": "ErrorName", "message": "description"}` with specific error codes like `InvalidRequest`, `AuthenticationRequired`, `AccountNotFound`. Current errors use a generic `{"error": "..."}` format.
**Fix**: Define error types per the Lexicon definitions and return them consistently.

#### AT-M2: No rate limiting on XRPC endpoints
**Issue**: A rate limiter exists in `src/ratelimit.zig` but is not applied to AT Protocol XRPC endpoints.
**Fix**: Apply rate limiting middleware to all XRPC endpoints, matching Bluesky's rate limit policies.

---

## Database Schema Gaps

For both protocols to function, the database needs additional tables:

| Table | Purpose | Protocol |
|-------|---------|----------|
| `actor_keys` | RSA key pairs per actor (public + encrypted private PEM) | ActivityPub |
| `remote_actors` | Cached remote actor profiles, inbox URLs, public keys | ActivityPub |
| `remote_posts` | Federated posts received via inbox | ActivityPub |
| `delivery_queue` | Persistent federation delivery queue with retry state | ActivityPub |
| `tombstones` | Deleted object records for 410 Gone responses | ActivityPub |
| `at_records` | AT Protocol records (repo, collection, rkey, value, cid) | AT Protocol |
| `at_commits` | Repository commit chain (did, rev, data_cid, sig) | AT Protocol |
| `at_signing_keys` | Account signing keys for repository commits | AT Protocol |
| `at_blobs` | Blob metadata (cid, mime_type, size, file_path) | AT Protocol |
| `at_sessions` | Persistent AT Protocol sessions (replacing in-memory HashMap) | AT Protocol |

---

## Priority Order

### Phase 1: ActivityPub federation (get real federation working)
1. Real RSA key generation and storage (AP-C4, AP-C1)
2. HTTP Signature signing with draft-cavage-12 (AP-C1)
3. HTTP Signature verification (AP-C2)
4. Fix timestamp conversion (AP-C8)
5. Implement incoming activity handlers (AP-C5)
6. Fix follower inbox resolution from database (AP-C6)
7. Add Content-Type negotiation (AP-C7)
8. Add NodeInfo endpoint (AP-H1)
9. Add outbox, followers, following endpoints (AP-H5, AP-H6)
10. Add actor extensions: featured, discoverable, manuallyApprovesFollowers (AP-H2-H4)

### Phase 2: ActivityPub hardening
11. RFC 9421 signature support (AP-C3)
12. Delete/Tombstone handling (AP-H7)
13. bto/bcc stripping and recipient deduplication (AP-H8, AP-H9)
14. Fix Like/Announce object serialization (AP-H10)

### Phase 3: AT Protocol foundation
15. Fix `/.well-known/atproto-did` to return plain text (AT-C5)
16. Fix DID document fields (AT-C4)
17. Persist records in SQLite (AT-C10)
18. Real credential validation (AT-C9)
19. Generate proper TIDs and CIDs (AT-C11, AT-C12)
20. Implement `refreshSession`, `deleteSession`, `getSession` (AT-H2)

### Phase 4: AT Protocol repository
21. CBOR serialization
22. MST implementation
23. Commit signing
24. CAR export (`getRepo`)
25. Sync endpoints including `subscribeRepos` firehose
26. OAuth/DPoP authentication (AT-C3)
