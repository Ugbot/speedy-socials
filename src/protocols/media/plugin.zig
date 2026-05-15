//! Media plugin (W1.4).
//!
//! Handles multipart media uploads, computes BlurHash + image
//! dimensions / mime, stores blob bytes in `atp_blobs` (the shared
//! content-addressed blob table the AT Protocol plugin owns) with a
//! filesystem spillover for blobs larger than
//! `limits.media_inline_threshold_bytes`, and tracks per-attachment
//! metadata in `media_attachments` (owned here).
//!
//! Endpoints (Mastodon-shaped):
//!   POST /api/v2/media        — canonical upload
//!   POST /api/v1/media        — alias to v2
//!   GET  /api/v1/media/:id    — attachment metadata
//!   PUT  /api/v1/media/:id    — update description / focus
//!   GET  /blobs/:cid          — serve the blob bytes
//!
//! Decoder coverage (deliberately limited — full image decoders are
//! out of scope):
//!   * PNG: dimensions + 8-bit, non-interlaced pixel decode → real
//!     BlurHash.
//!   * JPEG / GIF / WebP: dimensions only. BlurHash falls back to a
//!     well-documented placeholder string (`pixels.stub_blurhash`).

const std = @import("std");
const c = @import("sqlite").c;
const core = @import("core");

pub const schema = @import("schema.zig");
pub const state = @import("state.zig");
pub const routes = @import("routes.zig");
pub const multipart = @import("multipart.zig");
pub const blurhash = @import("blurhash.zig");
pub const image = @import("image.zig");
pub const pixels = @import("pixels.zig");
pub const api = @import("api.zig");

const Plugin = core.plugin.Plugin;
const Context = core.plugin.Context;
const Router = core.http.router.Router;
const Schema = core.storage.Schema;

fn init(_: ?*anyopaque, ctx: *Context) anyerror!void {
    state.init(ctx.clock, ctx.rng);
}

fn deinit(_: ?*anyopaque, _: *Context) void {
    state.reset();
}

fn registerSchema(_: ?*anyopaque, _: *Context, sch: *Schema) anyerror!void {
    for (schema.all_migrations) |m| try sch.register(m);
}

fn registerRoutes(_: ?*anyopaque, _: *Context, router: *Router, plugin_index: u16) anyerror!void {
    try routes.register(router, plugin_index);
}

pub fn attachDb(db: *c.sqlite3) void {
    state.attachDb(db);
}

pub fn setBaseUrl(url: []const u8) void {
    state.setBaseUrl(url);
}

pub fn setMediaRoot(path: []const u8) void {
    state.setMediaRoot(path);
}

pub const plugin: Plugin = .{
    .name = "media",
    .version = 1,
    .init = init,
    .deinit = deinit,
    .register_schema = registerSchema,
    .register_routes = registerRoutes,
};

// ── tests ──────────────────────────────────────────────────────────

test {
    _ = schema;
    _ = state;
    _ = multipart;
    _ = blurhash;
    _ = image;
    _ = pixels;
    _ = routes;
    _ = api;
}

test "media plugin registers" {
    var rng = core.rng.Rng.init(0x42);
    var sc = core.clock.SimClock.init(0);
    var ctx: core.plugin.Context = .{ .clock = sc.clock(), .rng = &rng };

    var reg = core.plugin.Registry.init();
    _ = try reg.register(plugin);
    try reg.initAll(&ctx);
    defer reg.deinitAll(&ctx);
    try std.testing.expect(state.isInitialized());
}

test "media plugin: schema applies on :memory: db" {
    var rng = core.rng.Rng.init(0xAA);
    var sc = core.clock.SimClock.init(100);
    var ctx: core.plugin.Context = .{ .clock = sc.clock(), .rng = &rng };

    const sqlite_mod = core.storage.sqlite;
    const db = try sqlite_mod.openWriter(":memory:");
    defer sqlite_mod.closeDb(db);

    var sch = Schema.init();
    try sch.register(core.storage.bootstrap_migration);
    try registerSchema(null, &ctx, &sch);
    try sch.applyAll(db);

    // Confirm the media_attachments table exists.
    var stmt: ?*c.sqlite3_stmt = null;
    const rc = c.sqlite3_prepare_v2(db, "SELECT count(*) FROM media_attachments", -1, &stmt, null);
    try std.testing.expectEqual(@as(c_int, c.SQLITE_OK), rc);
    defer _ = c.sqlite3_finalize(stmt);
    try std.testing.expectEqual(@as(c_int, c.SQLITE_ROW), c.sqlite3_step(stmt.?));
}
