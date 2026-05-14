//! Module-level state for the relay plugin.
//!
//! Why a module-level singleton: route handlers receive a
//! `HandlerContext` carrying a `*Context` (plugin context) — but not a
//! plugin-private pointer. Storing typed handles in a process-wide
//! struct keeps the route signature unchanged. The struct is populated
//! exactly once in `plugin.init` and read-only afterwards (except for
//! `reader_db` which the composition root supplies via `attachDb`).
//!
//! Tiger Style: this is the *only* mutable global the relay owns. All
//! other state lives in SQLite.

const std = @import("std");
const c = @import("sqlite").c;
const core = @import("core");

const Plugin = core.plugin.Plugin;
const Clock = core.clock.Clock;

pub const State = struct {
    /// AT Protocol sibling plugin, located by name at init time. The
    /// relay is the *only* plugin allowed to do this lookup.
    atproto: ?*const Plugin = null,
    /// ActivityPub sibling plugin.
    activitypub: ?*const Plugin = null,

    /// Direct reader connection to SQLite. The composition root opens
    /// a per-thread reader and hands a pointer in via `attachDb`. The
    /// relay's identity-map + subscription helpers use this to issue
    /// synchronous, no-allocator reads/writes off the request hot path
    /// (these operations are admin-bound and rare).
    reader_db: ?*c.sqlite3 = null,

    /// Wall clock for `last_seen` and `ts` columns.
    clock: Clock = undefined,
};

var instance: State = .{};

pub fn init(atproto: ?*const Plugin, activitypub: ?*const Plugin, clock: Clock) void {
    instance = .{
        .atproto = atproto,
        .activitypub = activitypub,
        .reader_db = null,
        .clock = clock,
    };
}

pub fn attachDb(db: *c.sqlite3) void {
    instance.reader_db = db;
}

pub fn get() *State {
    return &instance;
}

pub fn reset() void {
    instance = .{};
}
