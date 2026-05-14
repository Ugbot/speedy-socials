//! Media plugin schema migrations.
//!
//! Migration ids live in the 4xxx namespace (core=0xxx, ap=1xxx,
//! atproto=2xxx, relay=3xxx, media=4xxx).
//!
//! The blob *bytes* live in `atp_blobs` (the AT Protocol plugin owns
//! that table — see `protocols/atproto/schema.zig`). For blobs larger
//! than `limits.media_inline_threshold_bytes` the row's `data` column
//! holds an ASCII pointer of the form `fs:<relative-path>` rather than
//! the raw bytes; the file lives under the configured `media_root`.
//!
//! `media_attachments` is the Mastodon-facing attachment table: it
//! stores per-attachment metadata (description, focus, blurhash,
//! dimensions, mime, kind, owner) and references a blob via `blob_cid`.
//! A future status-create flow will set `status_id` once the
//! attachment is attached to a status.

const core = @import("core");
const Migration = core.storage.Migration;

pub const media_attachments_migration: Migration = .{
    .id = 4001,
    .name = "media:attachments",
    .up =
    \\CREATE TABLE IF NOT EXISTS media_attachments (
    \\    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    \\    owner_user_id  INTEGER NOT NULL,
    \\    blob_cid       TEXT NOT NULL,
    \\    kind           TEXT NOT NULL CHECK (kind IN ('image','video','gifv','audio','unknown')),
    \\    description    TEXT,
    \\    focus_x        REAL NOT NULL DEFAULT 0,
    \\    focus_y        REAL NOT NULL DEFAULT 0,
    \\    blurhash       TEXT,
    \\    width          INTEGER,
    \\    height         INTEGER,
    \\    mime           TEXT NOT NULL,
    \\    size           INTEGER NOT NULL,
    \\    status_id      INTEGER,
    \\    created_at     INTEGER NOT NULL
    \\) STRICT;
    \\CREATE INDEX IF NOT EXISTS media_attachments_status_idx
    \\    ON media_attachments (status_id);
    \\CREATE INDEX IF NOT EXISTS media_attachments_owner_idx
    \\    ON media_attachments (owner_user_id, created_at DESC);
    ,
    .down = "DROP TABLE media_attachments;",
};

pub const all_migrations = [_]Migration{
    media_attachments_migration,
};

/// Re-declaration of the AT-Protocol `atp_blobs` schema as a *test
/// helper only*. The production migration with id 2004 lives in
/// `protocols/atproto/schema.zig`; both plugins run inside the same
/// process so at runtime the table is already there by the time media
/// is hit.
///
/// Tests that exercise the media plugin standalone — without the
/// atproto plugin's schema — can pass this CREATE through
/// `core.storage.sqlite.execSql` directly to set up the table. It is
/// deliberately not a `Migration`: we never want it sharing id 2004
/// with the canonical migration.
pub const blobs_create_sql: []const u8 =
    \\CREATE TABLE IF NOT EXISTS atp_blobs (
    \\    cid        TEXT PRIMARY KEY,
    \\    did        TEXT NOT NULL,
    \\    mime       TEXT,
    \\    size       INTEGER NOT NULL,
    \\    ref_count  INTEGER NOT NULL DEFAULT 0,
    \\    data       BLOB NOT NULL,
    \\    created_at INTEGER NOT NULL
    \\) STRICT;
;

