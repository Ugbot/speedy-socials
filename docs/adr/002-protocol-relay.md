# ADR-002: AT Protocol / ActivityPub Protocol Relay

## Status

Accepted

## Date

2026-03-19

## Context

speedy-socials implements both AT Protocol (Bluesky-compatible) and ActivityPub (fediverse-compatible) endpoints. Users on either protocol cannot currently interact with users on the other. The social web is fragmented: a Mastodon user cannot follow a Bluesky user and vice versa.

We need a translation layer that bridges these two fundamentally different architectures:

| Dimension | AT Protocol | ActivityPub |
|-----------|-------------|-------------|
| Data model | Content-addressed repos (Merkle tree) | Actor-addressed inboxes (push) |
| Identity | DIDs (did:web, did:plc) | Actor URIs (https://domain/users/handle) |
| Discovery | Firehose subscription (pull) | WebFinger + inbox delivery (push) |
| Transport | XRPC over HTTPS | JSON-LD over HTTPS |
| Content refs | AT-URIs (at://did/collection/rkey) | Object URIs (https://domain/posts/id) |
| Rich text | Facets (byte offsets into UTF-8) | HTML with tags |
| Auth | DID-based + JWT sessions | HTTP Signatures per request |

## Decision

Build a **configurable protocol relay** as a first-class module (`src/relay/`) with two operating modes:

### Mode 1: Bridge

Attached to a speedy-socials instance. Translates the instance's own users bidirectionally:
- A local user's AT Proto post automatically becomes an AP Note delivered to fediverse followers
- An incoming AP Note from a fediverse user is written into the local AT Proto timeline
- Follows, likes, reposts translate bidirectionally
- Identity is unified: each local user has both a DID and an AP actor URI

**Use case**: Single-instance deployment where the operator wants their users visible on both networks.

### Mode 2: Relay

Standalone service that other instances subscribe to:
- Subscribes to an AT Proto firehose (e.g., Bluesky's `bsky.network` relay or another PDS)
- Translates firehose events into AP activities, delivered to subscribed fediverse instances
- Accepts AP activities at its shared inbox, translates to AT Proto records
- Creates synthetic AP actors for AT-native users and synthetic DIDs for AP-native users
- Exposes its own firehose endpoint for AT-native subscribers

**Use case**: Network-level bridge operated as infrastructure, similar to Bridgy Fed but self-hosted.

### Architecture: Translation Layer

The core design separates concerns into three layers:

```
                    ┌─────────────────────────────┐
                    │     Transport Layer          │
                    │  (HTTP, WebSocket, XRPC)     │
                    └─────────┬───────────────────┘
                              │
                    ┌─────────▼───────────────────┐
                    │     Translation Layer        │
                    │  translate.zig (pure fns)    │
                    │  identity_map.zig (DID↔URI)  │
                    └─────────┬───────────────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
    ┌─────────▼─────┐  ┌─────▼─────┐  ┌──────▼──────┐
    │ AT Protocol   │  │ Database  │  │ ActivityPub │
    │ (lib/atproto) │  │ (SQLite)  │  │ (federation)│
    └───────────────┘  └───────────┘  └─────────────┘
```

The translation layer is **pure functions** — no I/O, no state. It maps between protocol objects deterministically. The pipelines (`at_to_ap.zig`, `ap_to_at.zig`) orchestrate I/O around the pure translations.

### Identity Mapping

Each user gets a persistent identity mapping stored in SQLite:

| User type | DID | AP Actor URI | Direction |
|-----------|-----|--------------|-----------|
| Local user | `did:web:instance.com:user` | `https://instance.com/users/alice` | `local` |
| AT-native (relay) | `did:plc:abc123` | `https://relay.com/ap/users/alice.bsky.social` | `at_native` |
| AP-native (relay) | `did:web:relay.com:ap:alice` | `https://mastodon.social/users/alice` | `ap_native` |

For **bridge mode**, the mapping is straightforward — local users have both identities on the same domain.

For **relay mode**, the relay creates synthetic identities:
- AT-native users get synthetic AP actor URIs hosted on the relay's domain
- AP-native users get synthetic `did:web` DIDs under the relay's domain
- The relay serves WebFinger, actor profiles, and DID documents for these synthetic identities

### Content Translation

| AT → AP | AP → AT |
|---------|---------|
| `app.bsky.feed.post` → `Note` | `Note` → `app.bsky.feed.post` |
| Facets → HTML (`<a>`, `<span class="mention">`) | HTML → facets (parse tags, compute byte offsets) |
| `app.bsky.embed.images` → `attachment[]` | `attachment[]` → `app.bsky.embed.images` |
| `app.bsky.feed.like` → `Like` activity | `Like` → `app.bsky.feed.like` |
| `app.bsky.feed.repost` → `Announce` activity | `Announce` → `app.bsky.feed.repost` |
| `app.bsky.graph.follow` → `Follow` activity | `Follow` → `app.bsky.graph.follow` |
| `app.bsky.actor.profile` → `Person` update | `Person` update → `app.bsky.actor.profile` |

Facet↔HTML translation is the most complex piece. AT Protocol facets are byte-offset ranges into UTF-8 text with typed features (mention, link, tag). AP uses HTML. The translation must handle:
- Mention facets → `<a href="..." class="mention">@handle</a>`
- Link facets → `<a href="...">display text</a>`
- Tag facets → `<a href="..." class="hashtag">#tag</a>`
- Reverse: parse HTML, strip tags, compute byte offsets for the plain text

### Why not use Bridgy Fed?

Bridgy Fed is an existing AT↔AP bridge. However:
1. It's a centralized service — we want self-hosted
2. It's written in Python — doesn't integrate with our Zig server
3. It doesn't support relay mode — only individual user bridging
4. We already have both protocol stacks in-process — the translation layer is ~500 lines of pure functions

## Consequences

### Positive
- Users on speedy-socials are visible on both Bluesky and the fediverse
- Self-hosted relay reduces dependence on centralized bridges
- Translation layer is pure functions — easy to test, no mocking needed
- Bridge mode requires no additional infrastructure
- Relay mode can serve multiple instances

### Negative
- **Semantic loss in translation** — some features don't map cleanly:
  - AT Protocol thread gates have no AP equivalent
  - AP content warnings (`summary`) map to AT labels but not perfectly
  - AT Protocol's content-addressed data model (CIDs, Merkle proofs) has no AP equivalent
  - AP's arbitrary JSON-LD extensions may not translate
- **Double delivery risk** — without deduplication, a post could appear twice if a user is followed on both protocols. Mitigated by activity URI dedup in `federation_activities` table.
- **Identity confusion** — synthetic actors/DIDs may confuse users who see the same person with different identifiers on different servers. Mitigated by clear `alsoKnownAs` cross-references in actor/DID documents.
- **Maintenance burden** — protocol changes on either side require updating the translation layer.

### Future considerations
- **Selective bridging** — allow users to opt in/out of cross-protocol visibility
- **Thread reconstruction** — AT Protocol threads are reply chains; AP threads use `inReplyTo`. Both need reconstruction logic for display.
- **Media proxying** — blob references differ between protocols. The relay may need to proxy media.
- **Rate limiting** — relay mode firehose can be high-volume; need per-domain delivery rate limits.

## References

- [AT Protocol Specification](https://atproto.com/specs/atp)
- [ActivityPub W3C Recommendation](https://www.w3.org/TR/activitypub/)
- [Bridgy Fed](https://fed.brid.gy/) — existing AT↔AP bridge for reference
- [Bluesky Relay Architecture](https://atproto.com/guides/data-repos)
- ADR-001: Ed25519 HTTP Signatures (prerequisite for AP delivery)
