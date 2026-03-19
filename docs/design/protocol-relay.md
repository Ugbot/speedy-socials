# Design: AT Protocol / ActivityPub Protocol Relay

## Overview

A configurable translation layer that bridges AT Protocol and ActivityPub, deployable as either a local bridge (attached to a speedy-socials instance) or a standalone relay node (network infrastructure for cross-protocol communication).

## Problem

The social web is split between two incompatible protocol ecosystems:
- **AT Protocol** (Bluesky): ~20M users, content-addressed repos, firehose model
- **ActivityPub** (Mastodon, etc.): ~10M users, actor-addressed inboxes, push model

A user on Bluesky cannot follow a user on Mastodon and vice versa. Existing bridges (Bridgy Fed) are centralized and not self-hostable.

## Goals

1. A Bluesky user's posts appear in the fediverse timelines of their followers
2. A Mastodon user's posts appear in the Bluesky timeline of their followers
3. Follows, likes, and reposts translate bidirectionally
4. Self-hosted — no dependency on external bridge services
5. Configurable: bridge mode (single instance) or relay mode (network service)

## Module Structure

```
src/relay/
├── mod.zig              # Configuration, initialization, mode dispatch
├── translate.zig        # Pure protocol object translation functions
├── at_to_ap.zig         # AT→AP pipeline (firehose → translate → deliver)
├── ap_to_at.zig         # AP→AT pipeline (inbox → translate → repo write)
├── identity_map.zig     # Persistent DID↔Actor URI mapping
└── subscription.zig     # Relay subscription management
```

## Configuration

```zig
pub const RelayMode = enum {
    disabled,   // No cross-protocol translation
    bridge,     // Translate local instance users bidirectionally
    relay,      // Standalone relay service for network-level bridging
};

pub const RelayConfig = struct {
    mode: RelayMode = .disabled,

    // Relay mode: AT Proto firehose to subscribe to
    firehose_url: ?[]const u8 = null,

    // Relay mode: domain for hosting synthetic actors/DIDs
    relay_domain: ?[]const u8 = null,

    // Which AT Protocol collections to translate (default: all app.bsky.*)
    bridge_collections: []const []const u8 = &.{
        "app.bsky.feed.post",
        "app.bsky.feed.like",
        "app.bsky.feed.repost",
        "app.bsky.graph.follow",
        "app.bsky.actor.profile",
    },

    // Maximum activities per second per remote domain (rate limiting)
    max_delivery_rate: u32 = 10,
};
```

Environment variables:
- `RELAY_MODE` — `disabled`, `bridge`, or `relay`
- `RELAY_FIREHOSE_URL` — e.g., `wss://bsky.network/xrpc/com.atproto.sync.subscribeRepos`
- `RELAY_DOMAIN` — e.g., `relay.example.com`

## Translation Layer (`translate.zig`)

Pure functions with no I/O. Every translation is deterministic and testable in isolation.

### Object Mapping

#### Post → Note

```zig
pub fn atPostToApNote(
    allocator: Allocator,
    record_json: []const u8,    // app.bsky.feed.post record
    author_did: []const u8,
    rkey: []const u8,
    identity_map: *IdentityMap,
) !ApNote
```

Translation:
- `text` → `content` (wrapped in `<p>`, facets converted to HTML)
- `createdAt` → `published`
- `reply.parent.uri` → `inReplyTo`
- `embed.images` → `attachment[]` with `type: Image`
- `embed.external` → `attachment[]` with `type: Link`
- `langs` → `contentMap` (multi-language)
- Author DID → `attributedTo` actor URI via identity_map
- AT-URI → `id` object URI

#### Note → Post

```zig
pub fn apNoteToAtPost(
    allocator: Allocator,
    note: ApNote,
    identity_map: *IdentityMap,
) !AtPostRecord
```

Translation:
- `content` (HTML) → `text` (plain text) + `facets` (byte-offset annotations)
- `published` → `createdAt`
- `inReplyTo` → `reply.parent` (resolve to AT-URI via identity_map)
- `attachment[]` → `embed.images` or `embed.external`
- `summary` (content warning) → `labels` (self-label)

### Facet ↔ HTML Conversion

This is the most complex translation. AT Protocol uses byte-offset ranges into UTF-8 text with typed features. ActivityPub uses HTML.

#### Facets → HTML

```zig
pub fn facetsToHtml(allocator: Allocator, text: []const u8, facets: []const Facet) ![]u8
```

Algorithm:
1. Sort facets by byte start position
2. Walk the text, inserting HTML tags at facet boundaries:
   - `mention` feature → `<a href="{did}" class="mention">@handle</a>`
   - `link` feature → `<a href="{uri}">{display}</a>`
   - `tag` feature → `<a href="/tags/{tag}" class="hashtag">#tag</a>`
3. Escape non-facet text for HTML safety
4. Wrap in `<p>` tags, convert `\n` to `<br>`

#### HTML → Facets

```zig
pub fn htmlToFacets(allocator: Allocator, html: []const u8) !struct { text: []u8, facets: []Facet }
```

Algorithm:
1. Parse HTML, strip tags, collect plain text
2. For each `<a>` tag encountered:
   - Record byte start/end position in the plain text
   - Determine feature type from `class` or `href`:
     - `class="mention"` → mention feature with DID from href
     - `class="hashtag"` → tag feature
     - Other `<a>` → link feature with URI from href
3. Convert `<br>` to `\n`
4. Return plain text + facets array

### Activity Wrapping

```zig
pub fn wrapInCreate(allocator: Allocator, actor_uri: []const u8, object: ApNote) !ApActivity
pub fn atLikeToApLike(allocator: Allocator, record: AtLikeRecord, author_did: []const u8, rkey: []const u8, identity_map: *IdentityMap) !ApActivity
pub fn atRepostToApAnnounce(allocator: Allocator, record: AtRepostRecord, author_did: []const u8, rkey: []const u8, identity_map: *IdentityMap) !ApActivity
pub fn atFollowToApFollow(allocator: Allocator, record: AtFollowRecord, author_did: []const u8, rkey: []const u8, identity_map: *IdentityMap) !ApActivity
```

Reverse:
```zig
pub fn apLikeToAtLike(allocator: Allocator, activity: ApActivity, identity_map: *IdentityMap) !AtLikeRecord
pub fn apAnnounceToAtRepost(allocator: Allocator, activity: ApActivity, identity_map: *IdentityMap) !AtRepostRecord
pub fn apFollowToAtFollow(allocator: Allocator, activity: ApActivity, identity_map: *IdentityMap) !AtFollowRecord
```

## Identity Mapping (`identity_map.zig`)

### Database Schema

```sql
CREATE TABLE IF NOT EXISTS identity_mappings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    did TEXT UNIQUE NOT NULL,
    actor_uri TEXT UNIQUE NOT NULL,
    handle TEXT,
    domain TEXT NOT NULL,
    direction TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Direction Types

| Direction | Meaning | DID Format | Actor URI Format |
|-----------|---------|------------|------------------|
| `local` | Our own user | `did:web:instance.com:user` | `https://instance.com/users/{handle}` |
| `at_native` | AT user bridged to AP | Original DID (e.g., `did:plc:abc`) | `https://relay.com/ap/users/{handle}` |
| `ap_native` | AP user bridged to AT | `did:web:relay.com:ap:{handle}` | Original actor URI |

### Interface

```zig
pub const IdentityMap = struct {
    db: *Database,

    pub fn didToActorUri(self: *IdentityMap, allocator: Allocator, did: []const u8) !?[]const u8
    pub fn actorUriToDid(self: *IdentityMap, allocator: Allocator, actor_uri: []const u8) !?[]const u8
    pub fn ensureMapping(self: *IdentityMap, allocator: Allocator, did: []const u8, actor_uri: []const u8, handle: ?[]const u8, domain: []const u8, direction: Direction) !void
    pub fn getMappingByDid(self: *IdentityMap, allocator: Allocator, did: []const u8) !?Mapping
    pub fn getMappingByActorUri(self: *IdentityMap, allocator: Allocator, actor_uri: []const u8) !?Mapping
};
```

### Synthetic Identity Generation

In relay mode, when encountering a new AT-native user from the firehose:

1. Resolve DID to handle via ZAT's identity resolution
2. Generate synthetic actor URI: `https://{relay_domain}/ap/users/{handle}`
3. Store mapping with `direction=at_native`
4. Serve a synthetic Person object at that URI with the user's profile data
5. Serve WebFinger for `acct:{handle}@{relay_domain}`

When encountering a new AP-native user:

1. Generate synthetic DID: `did:web:{relay_domain}:ap:{handle}`
2. Store mapping with `direction=ap_native`
3. Serve a DID document at `https://{relay_domain}/.well-known/did/{encoded_did}`
4. Create an AT Protocol repo for this synthetic user

## AT→AP Pipeline (`at_to_ap.zig`)

### Bridge Mode

Hook into the XRPC handler chain. After `com.atproto.repo.createRecord` succeeds:

```
createRecord handler
    │
    ▼
Check: is collection in bridge_collections?
    │ yes
    ▼
translate.zig: convert AT record to AP activity
    │
    ▼
identity_map: resolve author DID to AP actor URI
    │
    ▼
federation.zig: deliver to AP followers
```

Implementation: add a post-commit hook in the XRPC createRecord handler that calls `relay.at_to_ap.onRecordCreated(did, collection, rkey, record)`.

### Relay Mode

Subscribe to AT Proto firehose, process events:

```
ZAT jetstream client (WebSocket)
    │
    ▼
Filter: is collection in bridge_collections?
    │ yes
    ▼
identity_map: get or create mapping for author DID
    │
    ▼
translate.zig: convert AT record to AP activity
    │
    ▼
subscription.zig: get subscribed AP instances
    │
    ▼
federation.zig: deliver to each subscriber's shared inbox
```

Uses ZAT's `jetstream.zig` client which provides:
- WebSocket connection to firehose
- Automatic reconnection
- Cursor-based resumption
- Filtering by collection

## AP→AT Pipeline (`ap_to_at.zig`)

### Bridge Mode

Extend the federation inbox handlers. After processing an AP activity:

```
federation.zig handleInbox
    │
    ▼
Normal AP processing (store in remote_posts, etc.)
    │
    ▼
relay.ap_to_at.onActivityReceived(activity_json)
    │
    ▼
identity_map: resolve AP actor to DID
    │
    ▼
translate.zig: convert AP activity to AT record
    │
    ▼
atproto repo: write record via lib/atproto
```

### Relay Mode

Accept AP activities at the relay's shared inbox:

```
Relay shared inbox receives AP activity
    │
    ▼
identity_map: get or create mapping for AP actor
    │
    ▼
translate.zig: convert to AT record
    │
    ▼
Write to synthetic AT repo for this AP user
    │
    ▼
Emit on relay's firehose (subscribeRepos)
```

## Subscription Management (`subscription.zig`)

### Relay Mode Only

AP instances subscribe by sending a Follow to the relay's actor:

```json
{
  "type": "Follow",
  "actor": "https://mastodon.social/users/admin",
  "object": "https://relay.example.com/actor"
}
```

The relay accepts and adds the instance's shared inbox to `relay_subscriptions`.

AT Protocol consumers subscribe via the standard firehose endpoint:
`GET /xrpc/com.atproto.sync.subscribeRepos`

### Database Schema

```sql
CREATE TABLE IF NOT EXISTS relay_subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subscriber_uri TEXT UNIQUE NOT NULL,
    protocol TEXT NOT NULL,       -- 'activitypub' or 'atproto'
    status TEXT NOT NULL DEFAULT 'active',
    subscribed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_delivered_at DATETIME
);
```

### Delivery

When a translated activity is ready:
1. Query `relay_subscriptions` for active subscribers of the target protocol
2. For AP subscribers: deliver via federation.zig (HTTP POST with signatures)
3. For AT subscribers: emit via firehose WebSocket connection

## Edge Cases

### Duplicate Detection

A user might be followed on both protocols. Without dedup, they'd see the same post twice.

Mitigation:
- Every translated activity includes the original protocol's URI in a custom field
- The `federation_activities` dedup table prevents processing the same activity twice
- Translated objects include `alsoKnownAs` cross-references

### Thread Reconstruction

AT Protocol threads use `reply.parent` and `reply.root` AT-URIs. AP uses `inReplyTo` object URIs.

When translating a reply:
1. Check identity_map for the parent post's cross-protocol URI
2. If found: set the correct protocol-native reference
3. If not found: the reply appears as a top-level post (graceful degradation)

### Media

AT Protocol stores blobs in repos with CID references. AP uses direct URLs.

In bridge mode: serve AT blobs at `/xrpc/com.atproto.sync.getBlob` — use this URL in AP attachments.
In relay mode: proxy blobs through the relay domain to avoid hotlinking AT Protocol PDS servers.

### Deletions

Both protocols support deletions, but they work differently:
- AT Protocol: delete the record from the repo, emit a tombstone on the firehose
- AP: send a `Delete` activity to all followers

The relay must translate deletions in both directions.

## Test Plan

1. **Translation round-trips**: AT post → AP Note → AT post preserves text, facets, timestamps
2. **Facet/HTML conversion**: Known facet patterns → correct HTML; known HTML → correct facets + byte offsets
3. **Identity mapping**: Create mapping → resolve DID → get actor URI; resolve actor URI → get DID
4. **Bridge mode integration**: Create AT record via XRPC → verify AP Note appears; send AP Note to inbox → verify AT record in repo
5. **Relay mode**: Mock firehose event → verify AP activity delivered to subscribers
6. **Deduplication**: Send same activity twice → processed only once
7. **Thread reconstruction**: Create reply chain → verify inReplyTo/reply.parent translated correctly
