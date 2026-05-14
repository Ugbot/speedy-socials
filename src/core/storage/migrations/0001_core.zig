//! Self-bootstrapping migration #1.
//!
//! Creates the `migrations` bookkeeping table itself. Every subsequent
//! migration relies on this row existing to record its application, so
//! this one must come first (id = 1) and be idempotent.

const schema = @import("../schema.zig");

pub const migration: schema.Migration = .{
    .id = 1,
    .name = "core:bootstrap_migrations_table",
    .up =
    \\CREATE TABLE IF NOT EXISTS migrations (
    \\    id          INTEGER PRIMARY KEY,
    \\    name        TEXT NOT NULL,
    \\    applied_at  INTEGER NOT NULL
    \\) STRICT;
    ,
    .down = "DROP TABLE migrations;",
};
