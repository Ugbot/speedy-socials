//! Protocol Relay plugin — AP ↔ AT bridge.
//!
//! ## Sibling-lookup contract
//!
//! The relay is the **only** plugin in the system permitted to call
//! `core.plugin.Registry.find` to obtain pointers to sibling plugins.
//! Every other plugin gets its handles via `*Context` or its own
//! `*anyopaque` state.
//!
//! The reason for the carve-out: the relay is, by definition, a
//! consumer of two specific protocol implementations. It would be
//! contortive to thread typed handles through `Context` (which is
//! protocol-neutral) or to give every plugin a back-channel to every
//! other. Instead the composition root calls `attachRegistry` *before*
//! `initAll`, the relay's `init` resolves the names "atproto" and
//! "activitypub" once, and the resulting `*const Plugin` pointers are
//! cached in module-level `State` for the lifetime of the process.
//!
//! If either sibling is missing, the relay's `init` returns
//! `RelayError.SiblingPluginMissing` and refuses to start. Boot order
//! in `main.zig` therefore must register `atproto` and `activitypub`
//! *before* `relay`.
//!
//! ## Submodules
//!
//!   * `schema.zig`       — three migrations (identity map, subscriptions,
//!                          translation log).
//!   * `translate.zig`    — pure AT↔AP translators, arena-allocated.
//!   * `identity_map.zig` — DID↔actor mapping + synthetic id minting.
//!   * `subscription.zig` — subscription lifecycle + translation log.
//!   * `routes.zig`       — admin HTTP routes.
//!   * `state.zig`        — module-level state singleton.

const std = @import("std");
const core = @import("core");

const Plugin = core.plugin.Plugin;
const Context = core.plugin.Context;
const Registry = core.plugin.Registry;
const Router = core.http.router.Router;
const Schema = core.storage.Schema;
const RelayError = core.errors.RelayError;

pub const schema = @import("schema.zig");
pub const translate = @import("translate.zig");
pub const identity_map = @import("identity_map.zig");
pub const subscription = @import("subscription.zig");
pub const routes = @import("routes.zig");
pub const state = @import("state.zig");

/// The relay holds a pointer to the registry between `attachRegistry`
/// and `init`. `initAll` does not pass the registry through, so we
/// stash it here. Single-threaded boot path — no atomics needed.
var pending_registry: ?*const Registry = null;

/// Set by `main.zig` before `registry.initAll(&ctx)`. The relay's
/// `init` will read it to perform the sibling lookup.
pub fn attachRegistry(reg: *const Registry) void {
    pending_registry = reg;
}

fn init(_: ?*anyopaque, ctx: *Context) anyerror!void {
    const reg = pending_registry orelse return error.SiblingPluginMissing;

    // Sibling-lookup carve-out: the relay is the ONLY plugin that
    // may call Registry.find on its peers. See module doc above.
    const atproto = reg.find("atproto") orelse return error.SiblingPluginMissing;
    const activitypub = reg.find("activitypub") orelse return error.SiblingPluginMissing;

    state.init(atproto, activitypub, ctx.clock);

    // The reader db is attached separately by `main.zig` after the
    // storage subsystem has opened a reader connection. Routes are
    // still safe before that — they short-circuit to 503.
}

fn deinit(_: ?*anyopaque, _: *Context) void {
    state.reset();
    pending_registry = null;
}

fn registerSchema(_: ?*anyopaque, _: *Context, sch: *Schema) anyerror!void {
    for (schema.all_migrations) |m| try sch.register(m);
}

fn registerRoutes(_: ?*anyopaque, _: *Context, router: *Router, plugin_index: u16) anyerror!void {
    try routes.register(router, plugin_index);
}

pub const plugin: Plugin = .{
    .name = "relay",
    .version = 1,
    .init = init,
    .deinit = deinit,
    .register_schema = registerSchema,
    .register_routes = registerRoutes,
};

// ──────────────────────────────────────────────────────────────────────
// Integration helper
//
// `handleAtFirehoseEvent` is the entrypoint the (future) firehose
// consumer thread will call when an AT record arrives. It runs the
// pure translator, ensures the identity-map row exists, appends a
// translation-log entry, and returns. Synchronous; takes a `*c.sqlite3`
// reader connection plus an arena.
// ──────────────────────────────────────────────────────────────────────

const c = @import("sqlite").c;
const Arena = core.arena.Arena;

pub const FirehoseEvent = struct {
    /// AT-URI of the record (canonical dedup key).
    at_uri: []const u8,
    /// Author DID.
    did: []const u8,
    /// Collection name (e.g. `app.bsky.feed.post`).
    collection: []const u8,
    /// Raw record JSON body.
    record_json: []const u8,
    /// Wall-clock-derived ISO 8601 createdAt; fallback when the record
    /// doesn't carry one.
    fallback_created_at: []const u8,
};

/// Translate a single AT firehose event into an AP activity and write
/// a translation-log entry. Used by both the firehose consumer (future)
/// and the integration test below.
///
/// `relay_host` is the local AP host name we synthesize actor IRIs on.
pub fn handleFirehoseEvent(
    db: *c.sqlite3,
    clock: core.clock.Clock,
    relay_host: []const u8,
    ev: FirehoseEvent,
    arena: *Arena,
) RelayError!translate.ApOut {
    const kind = translate.AtKind.fromCollection(ev.collection) orelse {
        return error.UnsupportedKind;
    };
    const parsed = translate.parseAtPostBody(ev.record_json) catch translate.ParsedAtPost{
        .text = "",
        .created_at = "",
        .reply_parent = "",
        .subject = "",
    };
    const created_at = if (parsed.created_at.len > 0) parsed.created_at else ev.fallback_created_at;
    const subject_uri = if (parsed.subject.len > 0) parsed.subject else parsed.reply_parent;

    const record: translate.AtRecord = .{
        .kind = kind,
        .at_uri = ev.at_uri,
        .did = ev.did,
        .text = parsed.text,
        .created_at = created_at,
        .subject = subject_uri,
    };

    // Ensure mapping exists. If absent, mint a synthetic AP actor.
    var maybe_actor = try identity_map.actorForDid(db, ev.did, arena);
    if (maybe_actor == null) {
        const synth = try identity_map.syntheticActorForDid(relay_host, ev.did, arena);
        try identity_map.upsert(db, clock, ev.did, synth);
        maybe_actor = synth;
    }
    const author_actor = maybe_actor.?;

    // Mint stable AP identifiers for the activity and the object.
    // Encoding: take the AT-URI, replace '/' with ':' so it's a safe
    // path segment; the host is the relay's.
    const activity_id = try buildApId(relay_host, "activities", ev.at_uri, arena);
    const object_id = if (kind == .post)
        try buildApId(relay_host, "notes", ev.at_uri, arena)
    else
        try buildApId(relay_host, "objects", ev.at_uri, arena);

    const out = try translate.atRecordToApActivity(record, author_actor, activity_id, object_id, arena);

    _ = subscription.appendLog(
        db,
        clock,
        .at_to_ap,
        ev.at_uri,
        out.id,
        true,
        "",
    ) catch |e| switch (e) {
        // Log failure is non-fatal — the translation already happened.
        else => {},
    };

    return out;
}

fn buildApId(host: []const u8, segment: []const u8, at_uri: []const u8, arena: *Arena) RelayError![]const u8 {
    const alloc = arena.allocator();
    // Strip leading `at://`.
    const tail = if (std.mem.startsWith(u8, at_uri, "at://")) at_uri[5..] else at_uri;
    const total = "https://".len + host.len + 1 + segment.len + 1 + tail.len;
    if (total > identity_map.max_actor_url_bytes) return error.TranslationBufferTooSmall;
    const buf = alloc.alloc(u8, total) catch return error.TranslationBufferTooSmall;
    var w: usize = 0;
    @memcpy(buf[w..][0.."https://".len], "https://");
    w += "https://".len;
    @memcpy(buf[w..][0..host.len], host);
    w += host.len;
    buf[w] = '/';
    w += 1;
    @memcpy(buf[w..][0..segment.len], segment);
    w += segment.len;
    buf[w] = '/';
    w += 1;
    for (tail) |ch| {
        buf[w] = if (ch == '/') ':' else ch;
        w += 1;
    }
    return buf[0..w];
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;

test {
    _ = schema;
    _ = translate;
    _ = identity_map;
    _ = subscription;
    _ = routes;
    _ = state;
}

test "Relay plugin registers via Registry" {
    var rng = core.rng.Rng.init(0x42);
    var sc = core.clock.SimClock.init(0);
    var ctx: Context = .{ .clock = sc.clock(), .rng = &rng };

    var reg = Registry.init();
    // Order matters — siblings first.
    _ = try reg.register(@import("protocol_atproto").plugin);
    _ = try reg.register(@import("protocol_activitypub").plugin);
    _ = try reg.register(plugin);

    attachRegistry(&reg);
    try reg.initAll(&ctx);
    defer reg.deinitAll(&ctx);

    try testing.expect(reg.find("relay") != null);
    try testing.expect(state.get().atproto != null);
    try testing.expect(state.get().activitypub != null);
}

test "Relay plugin init fails when siblings missing" {
    var rng = core.rng.Rng.init(0x42);
    var sc = core.clock.SimClock.init(0);
    var ctx: Context = .{ .clock = sc.clock(), .rng = &rng };

    var reg = Registry.init();
    _ = try reg.register(plugin);
    attachRegistry(&reg);
    const got = reg.initAll(&ctx);
    try testing.expectError(error.SiblingPluginMissing, got);
}

test "sibling-lookup finds the expected named plugins" {
    var reg = Registry.init();
    _ = try reg.register(@import("protocol_atproto").plugin);
    _ = try reg.register(@import("protocol_activitypub").plugin);
    _ = try reg.register(plugin);
    const a = reg.find("atproto") orelse return error.TestExpectedFound;
    const b = reg.find("activitypub") orelse return error.TestExpectedFound;
    try testing.expectEqualStrings("atproto", a.name);
    try testing.expectEqualStrings("activitypub", b.name);
}

test "handleFirehoseEvent end-to-end: AT post → AP activity + outbox log" {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);

    // Apply relay schema.
    for (schema.all_migrations) |m| {
        const sql_z = try testing.allocator.dupeZ(u8, m.up);
        defer testing.allocator.free(sql_z);
        var errmsg: [*c]u8 = null;
        _ = c.sqlite3_exec(db, sql_z.ptr, null, null, &errmsg);
        if (errmsg != null) c.sqlite3_free(errmsg);
    }

    var sc = core.clock.SimClock.init(1_700_000_000);

    var buf: [16 * 1024]u8 = undefined;
    var arena = Arena.init(&buf);

    const ev: FirehoseEvent = .{
        .at_uri = "at://did:plc:alice/app.bsky.feed.post/abc123",
        .did = "did:plc:alice",
        .collection = "app.bsky.feed.post",
        .record_json = "{\"$type\":\"app.bsky.feed.post\",\"text\":\"Hello world\",\"createdAt\":\"2026-05-14T12:00:00Z\"}",
        .fallback_created_at = "2026-05-14T12:00:00Z",
    };

    const out = try handleFirehoseEvent(db, sc.clock(), "relay.example.com", ev, &arena);
    try testing.expect(out.activity_type == .create);
    try testing.expect(std.mem.startsWith(u8, out.actor, "https://relay.example.com/ap/users/"));
    try testing.expect(std.mem.startsWith(u8, out.id, "https://relay.example.com/activities/"));
    try testing.expect(std.mem.indexOf(u8, out.content_html, "Hello world") != null);

    // Identity map row exists.
    arena.reset();
    const actor = try identity_map.actorForDid(db, "did:plc:alice", &arena);
    try testing.expect(actor != null);

    // Translation log has one entry referencing the AT URI.
    var log_rows: [4]subscription.LogEntry = undefined;
    const n = try subscription.listLog(db, 0, &log_rows);
    try testing.expectEqual(@as(u32, 1), n);
    try testing.expectEqual(subscription.Direction.at_to_ap, log_rows[0].direction);
    try testing.expectEqualStrings(ev.at_uri, log_rows[0].sourceId());
    try testing.expect(log_rows[0].success);
}

test "handleFirehoseEvent rejects unknown collection" {
    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);
    for (schema.all_migrations) |m| {
        const sql_z = try testing.allocator.dupeZ(u8, m.up);
        defer testing.allocator.free(sql_z);
        var errmsg: [*c]u8 = null;
        _ = c.sqlite3_exec(db, sql_z.ptr, null, null, &errmsg);
        if (errmsg != null) c.sqlite3_free(errmsg);
    }
    var sc = core.clock.SimClock.init(1);
    var buf: [4096]u8 = undefined;
    var arena = Arena.init(&buf);
    const ev: FirehoseEvent = .{
        .at_uri = "at://did:plc:x/app.bsky.feed.threadgate/r",
        .did = "did:plc:x",
        .collection = "app.bsky.feed.threadgate",
        .record_json = "{}",
        .fallback_created_at = "2026",
    };
    try testing.expectError(
        error.UnsupportedKind,
        handleFirehoseEvent(db, sc.clock(), "h", ev, &arena),
    );
}
