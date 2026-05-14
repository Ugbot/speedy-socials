//! Module-level state for the atproto plugin.
//!
//! Why a module-level singleton: route handlers receive a
//! `HandlerContext` carrying a `*Context` but no plugin-private pointer.
//! Storing typed handles (db, signing key, workers) in a process-wide
//! struct keeps the route signature unchanged. Populated exactly once
//! in `plugin.init`/`attachDb`/`attachWorkers` and read-only afterwards.
//!
//! Tiger Style: this is the *only* mutable global the atproto plugin
//! owns. Everything else lives in SQLite.

const std = @import("std");
const c = @import("sqlite").c;
const core = @import("core");

const Clock = core.clock.Clock;
const Rng = core.rng.Rng;
const keypair = @import("keypair.zig");
const tid = @import("tid.zig");

pub const State = struct {
    /// Direct writer-side SQLite connection. Used by the synchronous
    /// admin-bound paths (repo commit, firehose append) that don't need
    /// the writer-thread channel. WAL allows reads in parallel.
    reader_db: ?*c.sqlite3 = null,
    /// Worker pool — used for blocking I/O like DID resolution.
    workers: ?*anyopaque = null,
    /// PDS host name advertised by `describeServer` and used to mint
    /// did:web identifiers when no DID is supplied.
    host: []const u8 = "localhost:8080",
    /// Wall clock.
    clock: Clock = undefined,
    /// JWT signing key for access/refresh tokens. Seeded at boot from
    /// a random source; persists for process lifetime.
    jwt_key: keypair.Ed25519KeyPair = undefined,
    /// Monotonic TID generator (one per process).
    tid_state: tid.State = undefined,
};

var instance: State = .{};
var initialized: bool = false;

pub fn init(clock: Clock, rng: *Rng, host: []const u8) void {
    var seed: [32]u8 = undefined;
    var i: usize = 0;
    while (i < seed.len) : (i += 1) {
        seed[i] = rng.random().int(u8);
    }
    instance = .{
        .reader_db = null,
        .workers = null,
        .host = host,
        .clock = clock,
        .jwt_key = keypair.Ed25519KeyPair.fromSeed(seed),
        .tid_state = tid.State.init(rng),
    };
    initialized = true;
}

pub fn attachDb(db: *c.sqlite3) void {
    instance.reader_db = db;
}

pub fn attachWorkers(pool: *anyopaque) void {
    instance.workers = pool;
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
