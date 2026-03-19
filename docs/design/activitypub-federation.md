# Design: ActivityPub Federation

## Overview

Fix the ActivityPub federation implementation to produce real HTTP Signatures, handle incoming activities, persist federation state, and serve proper actor endpoints.

## Current State

| Component | Status | Issue |
|-----------|--------|-------|
| HTTP Signatures | Broken | Random bytes instead of Ed25519 signing |
| Public keys | Broken | Hardcoded `MOCK_PUBLIC_KEY` |
| Signature verification | Broken | Always returns true |
| Incoming handlers | Stub | All 9 handlers are NOOPs |
| Timestamps | Broken | Always returns `2024-01-01T00:00:00Z` |
| Actor endpoint | Stub | Returns error |
| Follower inboxes | Stub | Hardcoded mastodon.social/pixelfed.social |
| Federation tables | Missing | No remote actors, follows, posts |
| NodeInfo | Missing | No instance discovery |

## Architecture

```
┌─────────────────────────────────────────────┐
│                 server.zig                   │
│  Routes: /users/*, /inbox, /.well-known/*   │
└────────┬──────────────┬─────────────────────┘
         │              │
    ┌────▼────┐   ┌─────▼──────┐
    │ activ-  │   │ federation │
    │ itypub  │   │   .zig     │
    │  .zig   │   │            │
    │ (types, │   │ (delivery, │
    │  actors,│   │  inbox,    │
    │  notes) │   │  handlers) │
    └────┬────┘   └──────┬─────┘
         │               │
    ┌────▼───────────────▼──────┐
    │       crypto_sig.zig       │
    │  Ed25519 sign/verify       │
    │  Digest, PEM, headers      │
    └────────────┬───────────────┘
                 │
    ┌────────────▼───────────────┐
    │       database.zig          │
    │  actor_keys, remote_actors, │
    │  federation_follows, etc.   │
    └─────────────────────────────┘
```

### Responsibilities

- **`activitypub.zig`**: Types (Activity, NoteObject, PersonObject), object construction (createActorObject, createNoteObject, createFollowActivity, etc.), WebFinger struct
- **`federation.zig`**: HTTP delivery with real signatures, inbox handling with verification, all 9 incoming activity handlers, WebFinger endpoint handler, follower inbox resolution
- **`crypto_sig.zig`**: Ed25519 key generation, PEM encoding/decoding, SHA-256 digest, signing string construction, HTTP Signature header generation and verification
- **`database.zig`**: Federation tables, query functions for remote actors, follows, posts, interactions, activity dedup

## Database Schema

### `actor_keys` — Per-user Ed25519 signing keys

```sql
CREATE TABLE IF NOT EXISTS actor_keys (
    user_id INTEGER PRIMARY KEY,
    public_key_pem TEXT NOT NULL,
    private_key_raw BLOB NOT NULL,  -- 64-byte Ed25519 SecretKey
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

Key generation: on first access via `ensureActorKeyPair`. Uses `std.crypto.sign.Ed25519.KeyPair.generate()`, stores the 64-byte secret key and PEM-encoded public key.

### `remote_actors` — Cached remote AP actors

```sql
CREATE TABLE IF NOT EXISTS remote_actors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_uri TEXT UNIQUE NOT NULL,
    inbox_url TEXT NOT NULL,
    shared_inbox_url TEXT,
    public_key_pem TEXT,
    public_key_id TEXT,
    username TEXT,
    display_name TEXT,
    domain TEXT NOT NULL,
    avatar_url TEXT,
    last_fetched_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

Populated by: fetching remote actor on first interaction (Follow, Create, Like). Refreshed periodically or when signature verification fails.

### `federation_follows` — Cross-instance follow relationships

```sql
CREATE TABLE IF NOT EXISTS federation_follows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    local_user_id INTEGER,
    remote_actor_id INTEGER,
    activity_uri TEXT UNIQUE NOT NULL,
    direction TEXT NOT NULL,  -- 'inbound' or 'outbound'
    status TEXT NOT NULL DEFAULT 'pending',  -- pending, accepted, rejected
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (local_user_id) REFERENCES users(id),
    FOREIGN KEY (remote_actor_id) REFERENCES remote_actors(id)
);
```

### `federation_activities` — Deduplication log

```sql
CREATE TABLE IF NOT EXISTS federation_activities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    activity_uri TEXT UNIQUE NOT NULL,
    activity_type TEXT NOT NULL,
    actor_uri TEXT NOT NULL,
    object_uri TEXT,
    processed_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### `remote_posts` — Posts from remote actors

```sql
CREATE TABLE IF NOT EXISTS remote_posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_uri TEXT UNIQUE NOT NULL,
    remote_actor_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    content_warning TEXT,
    in_reply_to_uri TEXT,
    published_at DATETIME,
    received_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (remote_actor_id) REFERENCES remote_actors(id)
);
```

### `remote_interactions` — Remote likes/boosts on local posts

```sql
CREATE TABLE IF NOT EXISTS remote_interactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    activity_uri TEXT UNIQUE NOT NULL,
    remote_actor_id INTEGER NOT NULL,
    local_post_id INTEGER NOT NULL,
    interaction_type TEXT NOT NULL,  -- 'like' or 'announce'
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (remote_actor_id) REFERENCES remote_actors(id),
    FOREIGN KEY (local_post_id) REFERENCES posts(id)
);
```

## HTTP Signature Flow

### Outgoing (signing)

```
1. Serialize activity to JSON body
2. SHA-256 hash body → base64 → "SHA-256=<b64>" digest header
3. Format current time as RFC 7231 HTTP Date
4. Build signing string:
   "(request-target): post /inbox\nhost: remote.server\ndate: Thu, 19 Mar 2026 12:00:00 GMT\ndigest: SHA-256=..."
5. Ed25519 sign the signing string with actor's secret key
6. Base64 encode signature
7. Set Signature header:
   keyId="https://our.server/users/alice#main-key",algorithm="hs2019",headers="(request-target) host date digest",signature="<b64>"
8. POST to remote inbox with headers: Host, Date, Digest, Signature, Content-Type
```

### Incoming (verification)

```
1. Parse Signature header → keyId, algorithm, headers, signature
2. Extract actor URI from keyId (strip "#main-key" suffix)
3. Look up public key:
   a. Check remote_actors cache
   b. If missing/stale: HTTP GET actor URI with Accept: application/activity+json
   c. Parse publicKey.publicKeyPem from response
   d. Cache in remote_actors
4. Check domain against instance_blocks table
5. Reconstruct signing string from request headers
6. Decode base64 signature → Ed25519 verify with public key
7. Verify SHA-256 digest matches body
8. Check federation_activities for dedup
9. Dispatch to handler
```

## Incoming Activity Handlers

| Activity | Handler Logic |
|----------|--------------|
| **Follow** | Get/create remote_actor → create federation_follow (inbound, pending) → if user not locked: accept + queue Accept delivery |
| **Create** (Note) | Get/create remote_actor → store in remote_posts → if reply to local post: future notification |
| **Like** | Get/create remote_actor → find local post by URI → store in remote_interactions (type=like) |
| **Announce** | Get/create remote_actor → find local post by URI → store in remote_interactions (type=announce) |
| **Accept** | Find our outbound federation_follow by activity_uri → update status to accepted |
| **Reject** | Find our outbound federation_follow by activity_uri → update status to rejected |
| **Undo** | Parse inner object type → if Follow: delete federation_follow; if Like/Announce: delete remote_interaction |
| **Update** | If Person: update remote_actors fields; if Note: update remote_posts content |
| **Delete** | If object matches remote_posts: delete; if matches remote_actors: tombstone |

## Actor Endpoint (`/users/{username}`)

Returns ActivityPub Person object with `@context`, real Ed25519 public key:

```json
{
  "@context": [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/security/v1"
  ],
  "id": "https://instance.com/users/alice",
  "type": "Person",
  "preferredUsername": "alice",
  "inbox": "https://instance.com/users/alice/inbox",
  "outbox": "https://instance.com/users/alice/outbox",
  "followers": "https://instance.com/users/alice/followers",
  "following": "https://instance.com/users/alice/following",
  "publicKey": {
    "id": "https://instance.com/users/alice#main-key",
    "owner": "https://instance.com/users/alice",
    "publicKeyPem": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA...\n-----END PUBLIC KEY-----"
  },
  "endpoints": {
    "sharedInbox": "https://instance.com/inbox"
  }
}
```

Sub-paths:
- `/users/{username}/inbox` — POST: delegate to federation inbox handler
- `/users/{username}/followers` — GET: OrderedCollection with totalItems count
- `/users/{username}/following` — GET: OrderedCollection with totalItems count
- `/users/{username}/outbox` — GET: OrderedCollection with recent activities

## NodeInfo

Two endpoints:

`/.well-known/nodeinfo`:
```json
{
  "links": [{
    "rel": "http://nodeinfo.diaspora.software/ns/schema/2.0",
    "href": "https://instance.com/nodeinfo/2.0"
  }]
}
```

`/nodeinfo/2.0`:
```json
{
  "version": "2.0",
  "software": { "name": "speedy-socials", "version": "0.1.0" },
  "protocols": ["activitypub"],
  "usage": {
    "users": { "total": 42, "activeMonth": 10, "activeHalfyear": 30 },
    "localPosts": 1234
  },
  "openRegistrations": true
}
```

## Configuration

Extract hardcoded `speedy-socials.local` domain to a configurable value:

```zig
pub var instance_domain: []const u8 = "speedy-socials.local";
pub var instance_scheme: []const u8 = "https";
```

Set from environment variable `INSTANCE_DOMAIN` in `main.zig`. All URL generation in `activitypub.zig` and `federation.zig` uses these variables.

## Test Plan

`src/test_federation.zig`:

1. **Crypto**: Generate Ed25519 key pair → sign request → verify passes; tamper with body → verify fails; wrong key → verify fails
2. **PEM**: Generate key → encode to PEM → decode back → byte equality
3. **Signature header**: Parse valid `keyId="...",algorithm="hs2019",headers="...",signature="..."` → correct fields; reject malformed headers
4. **Timestamps**: Unix epoch 0 → `1970-01-01T00:00:00Z`; known date → correct ISO 8601; HTTP date format correct day/month names
5. **Database**: Create remote actor → query by URI → found; create federation follow → query inboxes → returned; mark activity processed → is_processed returns true
6. **Handlers**: Construct Follow JSON → call handleFollow → verify federation_follows record created; construct Undo Follow → call handleUndo → verify record deleted
