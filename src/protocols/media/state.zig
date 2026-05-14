//! Module-level state for the media plugin.
//!
//! Same pattern as the other plugins: a process-wide singleton that
//! route handlers read via `state.get()`. Populated exactly once at
//! boot.
//!
//! Storage layout:
//!   * The bytes of every uploaded blob live in `atp_blobs` (the AT
//!     Protocol plugin owns that table; see protocols/atproto/schema).
//!     We share it across media + atproto since both want
//!     content-addressed blob storage.
//!   * Blobs larger than `limits.media_inline_threshold_bytes` are
//!     spilled to the filesystem under `media_root`. The DB row holds
//!     an ASCII pointer of the form `fs:<relative-path>` instead of
//!     the bytes.
//!   * Per-attachment metadata lives in `media_attachments` (owned by
//!     the media plugin's schema migration 4001).

const std = @import("std");
const c = @import("sqlite").c;
const core = @import("core");

const Clock = core.clock.Clock;
const Rng = core.rng.Rng;

pub const State = struct {
    /// Writer-side SQLite connection. Direct synchronous access is
    /// fine here because media uploads are an admin path (rare,
    /// expensive) and the chunked download path uses read-mostly
    /// queries that play well with WAL.
    db: ?*c.sqlite3 = null,
    clock: Clock = undefined,
    rng: ?*Rng = null,
    /// External base URL prefix for `url` / `preview_url` fields.
    /// e.g. `http://localhost:8080`. Without a scheme the response uses
    /// a relative `/blobs/<cid>` URL.
    base_url: []const u8 = "",
    /// Filesystem root for spilled blobs. Created on demand.
    media_root: []const u8 = "./media",
};

var instance: State = .{};
var initialized: bool = false;

pub fn init(clock: Clock, rng: *Rng) void {
    instance = .{
        .db = null,
        .clock = clock,
        .rng = rng,
        .base_url = "",
        .media_root = "./media",
    };
    initialized = true;
}

pub fn attachDb(db: *c.sqlite3) void {
    instance.db = db;
}

pub fn setBaseUrl(url: []const u8) void {
    instance.base_url = url;
}

pub fn setMediaRoot(path: []const u8) void {
    instance.media_root = path;
}

pub fn get() *State {
    return &instance;
}

pub fn isInitialized() bool {
    return initialized;
}

pub fn reset() void {
    instance = .{};
    initialized = false;
}
