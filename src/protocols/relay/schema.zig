//! Relay plugin schema migrations.
//!
//! Migration ids follow the `relay = 3xxx` namespace convention declared
//! in `core/storage/schema.zig`. Each migration is idempotent (CREATE
//! TABLE IF NOT EXISTS) so re-running on an already-migrated DB is a
//! no-op.
//!
//! Three tables:
//!
//!   * `relay_identity_map` — bidirectional DID ↔ AP-actor mapping.
//!     `did` is the AT Protocol identifier (`did:plc:…`, `did:web:…`).
//!     `ap_actor_url` is the canonical AP `id` IRI (`https://host/users/x`).
//!     Either side may be the "synthetic" one created by the relay.
//!
//!   * `relay_subscriptions` — durable subscription lifecycle. A relay
//!     either follows an external `atproto_firehose` (XRPC SSE) or
//!     periodically polls an `activitypub_inbox`. State is one of
//!     `active | paused | failed`; the admin routes flip it.
//!
//!   * `relay_translation_log` — append-only audit trail of every
//!     translation the relay performs. Used both for debugging and to
//!     deduplicate cross-protocol echoes (a Bluesky post we relayed to
//!     Mastodon must not bounce back). Index on `(direction, source_id)`
//!     supports the dedup query.

const core = @import("core");
const Migration = core.storage.Migration;

pub const identity_map_migration: Migration = .{
    .id = 3001,
    .name = "relay:identity_map",
    .up =
    \\CREATE TABLE IF NOT EXISTS relay_identity_map (
    \\    did          TEXT PRIMARY KEY,
    \\    ap_actor_url TEXT NOT NULL UNIQUE,
    \\    last_seen    INTEGER NOT NULL
    \\) STRICT;
    \\CREATE INDEX IF NOT EXISTS relay_identity_map_actor_idx
    \\    ON relay_identity_map (ap_actor_url);
    ,
    .down = "DROP TABLE relay_identity_map;",
};

pub const subscriptions_migration: Migration = .{
    .id = 3002,
    .name = "relay:subscriptions",
    .up =
    \\CREATE TABLE IF NOT EXISTS relay_subscriptions (
    \\    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    \\    kind        TEXT NOT NULL CHECK (kind IN ('atproto_firehose','activitypub_inbox')),
    \\    source      TEXT NOT NULL,
    \\    cursor      TEXT,
    \\    state       TEXT NOT NULL CHECK (state IN ('active','paused','failed')),
    \\    created_at  INTEGER NOT NULL,
    \\    UNIQUE (kind, source)
    \\) STRICT;
    ,
    .down = "DROP TABLE relay_subscriptions;",
};

pub const translation_log_migration: Migration = .{
    .id = 3003,
    .name = "relay:translation_log",
    .up =
    \\CREATE TABLE IF NOT EXISTS relay_translation_log (
    \\    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    \\    direction     TEXT NOT NULL CHECK (direction IN ('at_to_ap','ap_to_at')),
    \\    source_id     TEXT NOT NULL,
    \\    translated_id TEXT NOT NULL,
    \\    success       INTEGER NOT NULL,
    \\    error_msg     TEXT,
    \\    ts            INTEGER NOT NULL
    \\) STRICT;
    \\CREATE INDEX IF NOT EXISTS relay_translation_log_src_idx
    \\    ON relay_translation_log (direction, source_id);
    \\CREATE INDEX IF NOT EXISTS relay_translation_log_ts_idx
    \\    ON relay_translation_log (ts DESC);
    ,
    .down = "DROP TABLE relay_translation_log;",
};

pub const all_migrations = [_]Migration{
    identity_map_migration,
    subscriptions_migration,
    translation_log_migration,
};
