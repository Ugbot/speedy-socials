//! AT Protocol PDS plugin.
//!
//! Provides:
//!   * Schema migrations (id 2001-2008)
//!   * XRPC routes (server, repo, sync, identity namespaces)
//!   * Repo persistence (records, commits, MST blocks, blobs)
//!   * Firehose event emission
//!   * Ed25519 JWT auth (legacy) + DPoP skeleton
//!   * DID resolution scaffolding (HTTP fetcher injected)
//!
//! Boot order:
//!   1. `attachDb(db)` — composition root supplies the writer SQLite
//!      handle for synchronous admin/commit paths.
//!   2. `attachWorkers(pool)` — composition root supplies the worker
//!      pool for blocking I/O (DID resolution, blob storage).
//!   3. `Registry.initAll` calls `init` which seeds module-level state.
//!   4. `Registry.registerAllSchemas` registers our migrations.
//!   5. `Registry.registerAllRoutes` registers our XRPC routes.

const std = @import("std");
const core = @import("core");
const c = @import("sqlite").c;

pub const cid = @import("cid.zig");
pub const tid = @import("tid.zig");
pub const dag_cbor = @import("dag_cbor.zig");
pub const mst = @import("mst.zig");
pub const keypair = @import("keypair.zig");
pub const syntax = @import("syntax.zig");
pub const did = @import("did.zig");

pub const schema = @import("schema.zig");
pub const state = @import("state.zig");
pub const auth = @import("auth.zig");
pub const repo = @import("repo.zig");
pub const firehose = @import("firehose.zig");
pub const routes = @import("routes.zig");
pub const xrpc = @import("xrpc.zig");
pub const did_resolver = @import("did_resolver.zig");
pub const oauth_dpop = @import("oauth_dpop.zig");
pub const car = @import("car.zig");
pub const sync_firehose = @import("sync_firehose.zig");

const Plugin = core.plugin.Plugin;
const Context = core.plugin.Context;
const Router = core.http.router.Router;
const Schema = core.storage.Schema;
const WsUpgradeRouter = core.ws.upgrade_router.WsUpgradeRouter;

fn init(_: ?*anyopaque, ctx: *Context) anyerror!void {
    state.init(ctx.clock, ctx.rng, "localhost:8080");
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

fn registerWs(_: ?*anyopaque, _: *Context, router: *WsUpgradeRouter, plugin_index: u16) anyerror!void {
    try sync_firehose.registerRoutes(router, plugin_index);
}

pub fn attachDb(db: *c.sqlite3) void {
    state.attachDb(db);
}

pub fn attachWorkers(pool: *anyopaque) void {
    state.attachWorkers(pool);
}

pub fn attachWsRegistry(reg: *core.ws.registry.Registry) void {
    state.attachWsRegistry(reg);
}

pub fn attachHttpClient(client: *core.http_client.Client) void {
    state.attachHttpClient(client);
}

pub const plugin: Plugin = .{
    .name = "atproto",
    .version = 1,
    .init = init,
    .deinit = deinit,
    .register_schema = registerSchema,
    .register_routes = registerRoutes,
    .register_ws_upgrade = registerWs,
};

// ── tests ──────────────────────────────────────────────────────────

test {
    _ = cid;
    _ = tid;
    _ = dag_cbor;
    _ = mst;
    _ = keypair;
    _ = syntax;
    _ = did;
    _ = schema;
    _ = state;
    _ = auth;
    _ = repo;
    _ = firehose;
    _ = xrpc;
    _ = did_resolver;
    _ = oauth_dpop;
    _ = car;
    _ = sync_firehose;
    _ = @import("routes.zig");
}

test "atproto plugin registers" {
    var rng = core.rng.Rng.init(0x42);
    var sc = core.clock.SimClock.init(0);
    var ctx: core.plugin.Context = .{ .clock = sc.clock(), .rng = &rng };

    var reg = core.plugin.Registry.init();
    _ = try reg.register(plugin);
    try reg.initAll(&ctx);
    defer reg.deinitAll(&ctx);

    try std.testing.expect(state.isInitialized());
}

test "atproto: schema registers + applies on :memory: db" {
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

    // Confirm a representative table exists.
    var stmt: ?*c.sqlite3_stmt = null;
    const rc = c.sqlite3_prepare_v2(db, "SELECT count(*) FROM atp_repos", -1, &stmt, null);
    try std.testing.expectEqual(@as(c_int, c.SQLITE_OK), rc);
    defer _ = c.sqlite3_finalize(stmt);
    try std.testing.expectEqual(@as(c_int, c.SQLITE_ROW), c.sqlite3_step(stmt.?));
}

test "atproto: createSession produces tokens that verify" {
    // Drive a synthetic request through `createSession` indirectly by
    // hitting auth.sign with the state's key (the route is exercised in
    // integration tests). This test checks the boot path produces a
    // working signing key.
    var rng = core.rng.Rng.init(0xBB);
    var sc = core.clock.SimClock.init(1000);
    state.init(sc.clock(), &rng, "test.host");
    defer state.reset();
    const st = state.get();

    var claims: auth.Claims = .{ .scope = .access, .iat = 1000, .exp = 99999 };
    try claims.setSub("did:plc:test");
    try claims.setJti("jti-x");
    var buf: [auth.max_jwt_bytes]u8 = undefined;
    const tok = try auth.sign(st.jwt_key, claims, &buf);
    var got: auth.Claims = .{ .scope = .access, .iat = 0, .exp = 0 };
    try auth.verify(tok, st.jwt_key.public_key, 5000, &got);
    try std.testing.expectEqualStrings("did:plc:test", got.sub());
}
