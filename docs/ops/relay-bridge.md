# AP ↔ AT bridge / relay

speedy-socials can act as a bidirectional bridge between **ActivityPub** (AP,
Mastodon-style) and the **AT Protocol** (AT, Bluesky-style), and as a relay node
that subscribes to a downstream AT relay firehose. Translation is pure-function
(`src/protocols/relay/translate.zig`); the surrounding pipeline performs the DB
and network I/O.

## Translated activity / record types

The translators map a small, well-defined set of social actions in both
directions (`src/protocols/relay/translate.zig:13-25`, enums at `:52-68`,
`:215-218`):

| AT collection (record)   | ⇄ | AP activity         |
|--------------------------|---|---------------------|
| `app.bsky.feed.post`     | ⇄ | `Create(Note)`      |
| `app.bsky.feed.like`     | ⇄ | `Like`              |
| `app.bsky.feed.repost`   | ⇄ | `Announce`          |
| `app.bsky.graph.follow`  | ⇄ | `Follow`            |

- AP→AT direction: `apActivityToAtRecord`. AP kinds outside the table
  (`Update`, `Delete`, `Accept`, `Reject`, `Undo`, `Move`, `Block`, `Flag`,
  `Add`, `Remove`, `Question`) return `error.UnsupportedKind`
  (`translate.zig:215-229`).
- Translated strings are bounded; overflow returns
  `TranslationBufferTooSmall` (`translate.zig:11`, `:37-40`).

## Direction 1 — AT → AP (firehose consumer)

The AT→AP firehose consumer runs at boot (`src/app/main.zig:684+`). It registers
an in-process sink against `atproto.firehose.append`, drains a bounded ring on a
dedicated thread, calls `relay.handleFirehoseEvent` per record, and appends to
`relay_translation_log`.

Configuration (all read in `src/app/main.zig`):

| Env var                          | Effect | File:line |
|----------------------------------|--------|-----------|
| `RELAY_SYNTHETIC_KEY_PEPPER`     | Pepper for minting synthetic actor keys for bridged DIDs. **Set this in production** — a missing value uses the dev default and logs a warning. | `main.zig:693-702` |
| `RELAY_BRIDGE_AP_TARGET`         | When set, every successful AT→AP translation enqueues an AP outbox row addressed at this inbox URL. This is what *enables* AT→AP delivery. | `main.zig:707-713` |
| `RELAY_OUTBOX_BACKPRESSURE_CAP`  | Integer. When `ap_federation_outbox` has more than this many pending rows the consumer pauses translation. Unset = disabled. | `main.zig:718-724` |

So AT→AP bridging is **enabled by setting `RELAY_BRIDGE_AP_TARGET`** to the
remote AP inbox you want translated records delivered to.

## Direction 2 — AP → AT

The AP→AT path translates inbound AP activities (delivered to the AP inbox) into
AT records via `apActivityToAtRecord` (`translate.zig:215+`,
`src/protocols/relay/ap_to_at.zig`). It is part of the relay pipeline and does
not require a dedicated enable flag beyond the relay being wired
(`relay.state.init`, `src/protocols/relay/state.zig:60`). The relay host used to
synthesise AP actor IRIs / AT identities is configurable via
`relay.setRelayHost` (`state.zig:73`), defaulting to `speedy-socials.local`.

## Downstream relay subscription (`RELAY_DOWNSTREAM_*`)

`src/protocols/relay/downstream_subscriber.zig` subscribes to an upstream AT
relay's firehose (e.g. a Bluesky relay) and ingests its commits/records.
Configuration via `Config.fromEnv` (`downstream_subscriber.zig:77-98`):

| Env var                       | Effect | Default |
|-------------------------------|--------|---------|
| `RELAY_DOWNSTREAM_ENABLE`     | Master enable. True only when one of `1` / `true` / `yes` **and** a non-empty URL is set. | off |
| `RELAY_DOWNSTREAM_RELAY_URL`  | Upstream relay WebSocket URL (the `subscribe` path is appended by the connection layer). Empty URL forces `enable = false`. | (none) |
| `RELAY_DOWNSTREAM_RELAY_HOST` | Local AP host used to synthesise actor IRIs for incoming DIDs. | `speedy-socials.local` |

The subscriber exposes counters (`frames_seen`, `commits_ingested`,
`records_ingested`, `decode_errors`, `reconnects`, `last_seq`) for the admin
status route (`downstream_subscriber.zig:101-109`).

## Operational checklist

To run as a full bidirectional bridge + downstream relay:

```
# AT → AP delivery
RELAY_SYNTHETIC_KEY_PEPPER=<random secret>
RELAY_BRIDGE_AP_TARGET=https://remote.example/inbox
RELAY_OUTBOX_BACKPRESSURE_CAP=10000        # optional

# Downstream AT relay ingest
RELAY_DOWNSTREAM_ENABLE=true
RELAY_DOWNSTREAM_RELAY_URL=wss://relay.example/xrpc
RELAY_DOWNSTREAM_RELAY_HOST=mybridge.example
```

AP→AT works as soon as the relay plugin is wired and the AP inbox receives
supported activities; only the unsupported AP kinds above are dropped.
