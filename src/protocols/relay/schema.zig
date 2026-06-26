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
    .up_pg =
    \\CREATE TABLE IF NOT EXISTS relay_identity_map (
    \\    did          TEXT PRIMARY KEY,
    \\    ap_actor_url TEXT NOT NULL UNIQUE,
    \\    last_seen    BIGINT NOT NULL
    \\);
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
    .up_pg =
    \\CREATE TABLE IF NOT EXISTS relay_subscriptions (
    \\    id          BIGSERIAL PRIMARY KEY,
    \\    kind        TEXT NOT NULL CHECK (kind IN ('atproto_firehose','activitypub_inbox')),
    \\    source      TEXT NOT NULL,
    \\    cursor      TEXT,
    \\    state       TEXT NOT NULL CHECK (state IN ('active','paused','failed')),
    \\    created_at  BIGINT NOT NULL,
    \\    UNIQUE (kind, source)
    \\);
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
    .up_pg =
    \\CREATE TABLE IF NOT EXISTS relay_translation_log (
    \\    id            BIGSERIAL PRIMARY KEY,
    \\    direction     TEXT NOT NULL CHECK (direction IN ('at_to_ap','ap_to_at')),
    \\    source_id     TEXT NOT NULL,
    \\    translated_id TEXT NOT NULL,
    \\    success       BIGINT NOT NULL,
    \\    error_msg     TEXT,
    \\    ts            BIGINT NOT NULL
    \\);
    \\CREATE INDEX IF NOT EXISTS relay_translation_log_src_idx
    \\    ON relay_translation_log (direction, source_id);
    \\CREATE INDEX IF NOT EXISTS relay_translation_log_ts_idx
    \\    ON relay_translation_log (ts DESC);
    ,
    .down = "DROP TABLE relay_translation_log;",
};

/// B1: per-synthetic-actor follower table. Populated by inbound AP
/// `Follow` activities targeting a bridge-owned actor and drained by
/// AP `Undo{Follow}` activities. The AT→AP firehose consumer reads
/// this table to fan out a translated activity to every known
/// follower of the originating synthetic actor.
pub const followers_migration: Migration = .{
    .id = 3004,
    .name = "relay:followers",
    .up =
    \\CREATE TABLE IF NOT EXISTS relay_followers (
    \\    actor_url      TEXT NOT NULL,
    \\    follower_inbox TEXT NOT NULL,
    \\    shared_inbox   TEXT,
    \\    follow_iri     TEXT NOT NULL,
    \\    created_at     INTEGER NOT NULL,
    \\    PRIMARY KEY (actor_url, follower_inbox)
    \\) STRICT;
    \\CREATE INDEX IF NOT EXISTS relay_followers_actor_idx
    \\    ON relay_followers (actor_url);
    \\CREATE INDEX IF NOT EXISTS relay_followers_follow_iri_idx
    \\    ON relay_followers (follow_iri);
    ,
    .up_pg =
    \\CREATE TABLE IF NOT EXISTS relay_followers (
    \\    actor_url      TEXT NOT NULL,
    \\    follower_inbox TEXT NOT NULL,
    \\    shared_inbox   TEXT,
    \\    follow_iri     TEXT NOT NULL,
    \\    created_at     BIGINT NOT NULL,
    \\    PRIMARY KEY (actor_url, follower_inbox)
    \\);
    \\CREATE INDEX IF NOT EXISTS relay_followers_actor_idx
    \\    ON relay_followers (actor_url);
    \\CREATE INDEX IF NOT EXISTS relay_followers_follow_iri_idx
    \\    ON relay_followers (follow_iri);
    ,
    .down = "DROP TABLE relay_followers;",
};

test "F7: every relay migration carries a clean Postgres dialect variant" {
    try core.storage.schema.assertPgDialectComplete(&all_migrations);
}

pub const all_migrations = [_]Migration{
    identity_map_migration,
    subscriptions_migration,
    translation_log_migration,
    followers_migration,
};
