# AP ↔ AT translation matrix

Every ActivityPub activity type × ATProto collection (or vice
versa) is one of:
- **bridged** — the relay translates and writes / enqueues; behaviour
  documented inline below
- **dropped** — silently ignored; the row in the matrix explains why
- **impossible** — semantically incompatible (no useful mapping
  exists)

The matrix is curated by hand. When you add a new translation,
update this file in the same commit.

**Scope**: this file documents the **bridge** behaviour only. For
how each protocol behaves as a **native node** (independent of
bridging), see [`../../PROTOCOL_AUDIT.md`](../../PROTOCOL_AUDIT.md)
and [`../../SPEC_PUNCHLIST.md`](../../SPEC_PUNCHLIST.md).

_Last updated: 2026-05-19 (post-W6 + B + A1)._

## AP → AT (inbound AP inbox)

The hook fires on every successful `inbox.dispatch`. The relay
chooses behaviour per AP activity type.

| AP activity     | Behaviour     | Target / action |
|-----------------|---------------|-----------------|
| `Create{Note}`  | **bridged**   | commits `app.bsky.feed.post` row (rkey from object_id) |
| `Create{Article,Image,Video,Audio,...}` | dropped | no AT lexicon equivalent for arbitrary inline object types yet |
| `Update{Note}`  | **bridged**   | re-commits the same rkey; CID changes when inner content changes |
| `Delete`        | **bridged**   | probes post / like / repost / follow collections; first match removed |
| `Like`          | **bridged**   | commits `app.bsky.feed.like` |
| `Announce`      | **bridged**   | commits `app.bsky.feed.repost` |
| `Follow`        | **bridged**   | commits `app.bsky.graph.follow` + writes `relay_followers` row |
| `Undo{Follow}`  | **bridged**   | removes `relay_followers` row keyed on `act.object_id` (the Follow IRI) |
| `Undo{Like,Announce}` | dropped (TODO) | needs a reverse-lookup from like/repost id → AT rkey; trackable extension |
| `Accept`        | dropped       | server-state-machine only (the AP plugin updates follow state); no AT mirror |
| `Reject`        | dropped       | same |
| `Move`          | dropped (TODO) | bridging account moves needs identity_map migration logic |
| `Block`         | impossible    | no AT-side block primitive |
| `Flag`          | impossible    | no AT-side report primitive |
| `Add` / `Remove`| dropped (TODO) | per-collection logic; lists/featured belong to a future tranche |

## AT → AP (firehose consumer)

Driven by the in-process firehose sink. The consumer queries
`atp_records` for the records introduced by a commit and translates
each row by its collection NSID.

| AT collection                  | Behaviour | AP shape produced |
|--------------------------------|-----------|-------------------|
| `app.bsky.feed.post`           | **bridged** | `Create{Note}` with `content` = the AT `text` |
| `app.bsky.feed.like`           | **bridged** | `Like` (target = the AT `subject`) |
| `app.bsky.feed.repost`         | **bridged** | `Announce` (target = the AT `subject`) |
| `app.bsky.graph.follow`        | **bridged** | `Follow` (object = the bridged target's AP actor URL) |
| `app.bsky.feed.threadgate`     | dropped   | gate semantics don't map onto AP visibility model cleanly |
| `app.bsky.graph.list`          | dropped (TODO) | could map to AP `Collection`; future tranche |
| `app.bsky.graph.listitem`      | dropped (TODO) | depends on `list` being bridged first |
| `app.bsky.actor.profile`       | dropped (TODO; tracked as I2 in PUNCHLIST) | should propagate to AP Person updates |
| AT record deletions            | dropped (TODO; tracked as A3b) | firehose doesn't yet emit deletion events |
| AT record updates              | dropped (TODO; tracked as A4b) | firehose doesn't yet emit mutation events with old/new CID |

## Loop prevention

The relay logs every translation in `relay_translation_log` keyed
on `(direction, source_id)`. The consumer + inbox hook both check
for a prior log row before processing to avoid re-translating an
echo. _Status as of 2026-05-19:_ the log is written but the lookup
check isn't implemented yet — protected in practice by the fact
that bridged content carries a `bridgedFrom` field upstream peers
typically don't echo verbatim. Tracked as part of A7 in PUNCHLIST.

## How to extend

1. Pick the new AP activity type / AT collection.
2. Add the translation:
   - AP → AT: extend `relay.ap_to_at.collectionFor` and the body
     builder in `buildBridgeRecord`.
   - AT → AP: extend `relay.translate.AtKind` + `translate.atRecordToApActivity`.
3. Add a row to this matrix.
4. Add unit tests in the relay module + a scenario in
   `tests/sim/relay_bridge_scenario.zig` if it crosses both
   directions.
