//! C1 / H3: tenant lifecycle admin routes (create / update-state / delete).
//!
//! Exposes an admin-token-gated CRUD-ish surface over the process-wide
//! tenancy table (`core.tenancy`), complementing the verb-style transition
//! routes already in `core.tls.admin_routes`
//! (`POST /admin/tenants/:id/{suspend,activate,delete}`):
//!
//!   * `POST   /admin/tenants`     — register a new tenant (id + host) and
//!     open+migrate its per-tenant database via the storage provider → 201.
//!   * `PATCH  /admin/tenants/:id` — set state to `active` | `suspended`.
//!   * `DELETE /admin/tenants/:id` — mark the tenant `deleted` (the on-disk
//!     DB file is intentionally left in place; deletion is a state flip, not
//!     a destructive drop).
//!
//! Auth mirrors `tls/admin_routes.zig`: a shared-secret bearer token taken
//! from `ADMIN_TOKEN` at boot, presented via `Authorization: Bearer <tok>`
//! or `X-Admin-Token: <tok>`. An empty/unset token disables the routes
//! (always 401) — there is no implicit "anyone can administer tenants" mode.
//!
//! Tiger Style: bounded request parsing (bodies are read into fixed stack
//! buffers, capped well under the tenancy field limits), no allocation at
//! request time. The provider's `ensureTenant` is the only allocating call
//! and is boot-grade (opens a DB), which the create route accepts as the
//! cost of provisioning a tenant.

const std = @import("std");
const router_mod = @import("http/router.zig");
const tenancy = @import("tenancy.zig");
const storage = @import("storage.zig");
const audit = @import("audit.zig");
const Clock = @import("clock.zig").Clock;
const c = @import("sqlite").c;

const HandlerContext = router_mod.HandlerContext;
const Router = router_mod.Router;

// ── Boot-set configuration ──────────────────────────────────────────────

var admin_token: []const u8 = "";
var audit_db: ?*c.sqlite3 = null;
var audit_clock: Clock = undefined;

/// Set the admin bearer token used to gate the tenant routes. Borrowed
/// (must outlive the server — typically the env string). Empty disables.
pub fn setToken(token: []const u8) void {
    admin_token = token;
}

/// Wire optional audit logging for tenant lifecycle mutations. Boot-only.
pub fn setAudit(db: *c.sqlite3, clock: Clock) void {
    audit_db = db;
    audit_clock = clock;
}

/// Reset module state (tests only).
pub fn resetForTest() void {
    admin_token = "";
    audit_db = null;
}

// ── Auth (mirrors tls/admin_routes.zig) ──────────────────────────────────

/// Constant-time token comparison. Short-circuits only on the public
/// length difference; the byte comparison does not.
fn tokenMatches(presented: []const u8) bool {
    if (admin_token.len == 0) return false;
    if (presented.len != admin_token.len) return false;
    var diff: u8 = 0;
    for (presented, admin_token) |a, b| diff |= a ^ b;
    return diff == 0;
}

fn presentedToken(hc: *HandlerContext) ?[]const u8 {
    if (hc.request.header("X-Admin-Token")) |t| return std.mem.trim(u8, t, " \t");
    if (hc.request.header("Authorization")) |a| {
        const prefix = "Bearer ";
        if (a.len > prefix.len and std.mem.eql(u8, a[0..prefix.len], prefix)) {
            return std.mem.trim(u8, a[prefix.len..], " \t");
        }
    }
    return null;
}

/// Returns true when the request carries a valid admin token. On failure it
/// writes a 401 and returns false so the caller can early-out.
fn requireAdmin(hc: *HandlerContext) anyerror!bool {
    const presented = presentedToken(hc) orelse {
        try hc.response.simple(.unauthorized, "application/json", "{\"error\":\"admin auth required\"}");
        return false;
    };
    if (!tokenMatches(presented)) {
        try hc.response.simple(.unauthorized, "application/json", "{\"error\":\"admin auth required\"}");
        return false;
    }
    return true;
}

// ── Minimal bounded JSON field extraction ────────────────────────────────

/// Extract the string value for a top-level `"key": "value"` pair from a
/// small JSON object. Bounded scan over the request body (the caller caps
/// the body length before calling). Returns null when the key is absent or
/// the value isn't a simple unescaped string. No allocation.
fn jsonStringField(body: []const u8, key: []const u8) ?[]const u8 {
    // Search for `"<key>"`. Bounded by body.len.
    var needle_buf: [40]u8 = undefined;
    if (key.len + 2 > needle_buf.len) return null;
    needle_buf[0] = '"';
    @memcpy(needle_buf[1 .. 1 + key.len], key);
    needle_buf[1 + key.len] = '"';
    const needle = needle_buf[0 .. key.len + 2];

    const key_at = std.mem.indexOf(u8, body, needle) orelse return null;
    var i = key_at + needle.len;
    // Skip whitespace + the colon.
    while (i < body.len and (body[i] == ' ' or body[i] == '\t')) : (i += 1) {}
    if (i >= body.len or body[i] != ':') return null;
    i += 1;
    while (i < body.len and (body[i] == ' ' or body[i] == '\t')) : (i += 1) {}
    if (i >= body.len or body[i] != '"') return null;
    i += 1;
    const start = i;
    // Value runs to the next unescaped quote. We reject backslash escapes
    // (tenant ids/hosts/states never contain them) to keep this bounded and
    // unambiguous.
    while (i < body.len and body[i] != '"') : (i += 1) {
        if (body[i] == '\\') return null;
    }
    if (i >= body.len) return null;
    return body[start..i];
}

// ── Handlers ─────────────────────────────────────────────────────────────

const max_body_bytes: usize = 1024;

/// `POST /admin/tenants` — body `{"id":"<id>","host":"<host>"}`.
fn handleCreate(hc: *HandlerContext) anyerror!void {
    if (!try requireAdmin(hc)) return;

    const body = hc.request.body;
    if (body.len > max_body_bytes) {
        return hc.response.simple(.payload_too_large, "application/json", "{\"error\":\"body too large\"}");
    }

    const id = jsonStringField(body, "id") orelse {
        return hc.response.simple(.bad_request, "application/json", "{\"error\":\"missing id\"}");
    };
    const host = jsonStringField(body, "host") orelse {
        return hc.response.simple(.bad_request, "application/json", "{\"error\":\"missing host\"}");
    };
    if (id.len == 0 or id.len > tenancy.max_id_bytes or host.len == 0 or host.len > tenancy.max_host_bytes) {
        return hc.response.simple(.bad_request, "application/json", "{\"error\":\"id/host length out of range\"}");
    }

    // Reject duplicates explicitly (the table would otherwise append a second
    // entry shadowed by the first on lookup).
    if (tenancy.globalTable().lookupById(id) != null) {
        return hc.response.simple(.conflict, "application/json", "{\"error\":\"tenant exists\"}");
    }

    tenancy.globalTable().add(host, id) catch |err| {
        const msg = switch (err) {
            error.Full => "{\"error\":\"tenant table full\"}",
            error.TooLong => "{\"error\":\"id/host too long\"}",
        };
        return hc.response.simple(.internal, "application/json", msg);
    };

    // Open + migrate the per-tenant database. If no provider is configured
    // (single-process default deployment), the tenant is still registered in
    // the table; storage falls back to the default handle.
    if (storage.dbProvider()) |p| {
        p.ensureTenant(id) catch |err| {
            return hc.response.simple(.internal, "application/json", switch (err) {
                error.ProviderFull => "{\"error\":\"storage provider full\"}",
                error.OpenFailed => "{\"error\":\"tenant db open failed\"}",
                error.MigrateFailed => "{\"error\":\"tenant db migrate failed\"}",
                error.PathTooLong => "{\"error\":\"tenant db path too long\"}",
            });
        };
    }

    if (audit_db) |db| {
        audit.append(db, audit_clock, "admin", "tenant.create", id, host, true) catch {};
    }

    var buf: [256]u8 = undefined;
    const out = std.fmt.bufPrint(&buf, "{{\"id\":\"{s}\",\"host\":\"{s}\",\"state\":\"active\"}}", .{ id, host }) catch "{}";
    return hc.response.simple(.created, "application/json", out);
}

/// `PATCH /admin/tenants/:id` — body `{"state":"active"|"suspended"}`.
fn handlePatch(hc: *HandlerContext) anyerror!void {
    if (!try requireAdmin(hc)) return;

    const id = hc.params.get("id") orelse {
        return hc.response.simple(.bad_request, "application/json", "{\"error\":\"missing tenant id\"}");
    };

    const body = hc.request.body;
    if (body.len > max_body_bytes) {
        return hc.response.simple(.payload_too_large, "application/json", "{\"error\":\"body too large\"}");
    }
    const state_str = jsonStringField(body, "state") orelse {
        return hc.response.simple(.bad_request, "application/json", "{\"error\":\"missing state\"}");
    };

    // PATCH only flips between active/suspended. Use DELETE to mark deleted
    // so callers can't accidentally tombstone a tenant via a state update.
    const new_state: tenancy.State = if (std.mem.eql(u8, state_str, "active"))
        .active
    else if (std.mem.eql(u8, state_str, "suspended"))
        .suspended
    else
        return hc.response.simple(.bad_request, "application/json", "{\"error\":\"state must be active or suspended\"}");

    tenancy.globalTable().setState(id, new_state) catch {
        return hc.response.simple(.not_found, "application/json", "{\"error\":\"unknown tenant\"}");
    };

    if (audit_db) |db| {
        audit.append(db, audit_clock, "admin", "tenant.setstate", id, new_state.toString(), true) catch {};
    }

    var buf: [128]u8 = undefined;
    const out = std.fmt.bufPrint(&buf, "{{\"id\":\"{s}\",\"state\":\"{s}\"}}", .{ id, new_state.toString() }) catch "{}";
    return hc.response.simple(.ok, "application/json", out);
}

/// `DELETE /admin/tenants/:id` — mark the tenant `deleted`. The on-disk DB
/// file is left untouched (deletion is a state flip, not a drop).
fn handleDelete(hc: *HandlerContext) anyerror!void {
    if (!try requireAdmin(hc)) return;

    const id = hc.params.get("id") orelse {
        return hc.response.simple(.bad_request, "application/json", "{\"error\":\"missing tenant id\"}");
    };

    tenancy.globalTable().setState(id, .deleted) catch {
        return hc.response.simple(.not_found, "application/json", "{\"error\":\"unknown tenant\"}");
    };

    if (audit_db) |db| {
        audit.append(db, audit_clock, "admin", "tenant.delete", id, "deleted", true) catch {};
    }

    var buf: [128]u8 = undefined;
    const out = std.fmt.bufPrint(&buf, "{{\"id\":\"{s}\",\"state\":\"deleted\"}}", .{id}) catch "{}";
    return hc.response.simple(.ok, "application/json", out);
}

/// Register the tenant lifecycle routes. `plugin_index` is the sentinel
/// (core routes, no owning plugin).
pub fn registerRoutes(router: *Router, plugin_index: u16) !void {
    try router.register(.post, "/admin/tenants", handleCreate, plugin_index);
    try router.register(.patch, "/admin/tenants/:id", handlePatch, plugin_index);
    try router.register(.delete, "/admin/tenants/:id", handleDelete, plugin_index);
}

// ── Tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const Request = @import("http/request.zig").Request;
const Response = @import("http/response.zig");
const PathParams = router_mod.PathParams;
const Context = @import("plugin.zig").Context;
const sqlite = @import("storage/sqlite.zig");
const schema_mod = @import("storage/schema.zig");

// Build a HandlerContext driving a single handler. `auth` true presents the
// configured token; `body`/`params` exercise the parsing paths.
const TestHarness = struct {
    req: Request,
    builder: Response.Builder,
    hc: HandlerContext,
    headers: [1]@import("http/request.zig").Header,

    fn status(buf: []const u8) u16 {
        // "HTTP/1.1 NNN ..."
        const sp = std.mem.indexOfScalar(u8, buf, ' ').?;
        return std.fmt.parseInt(u16, buf[sp + 1 .. sp + 4], 10) catch 0;
    }
};

fn runHandler(
    handler: router_mod.Handler,
    method: @import("http/request.zig").Method,
    token: ?[]const u8,
    body: []const u8,
    id_param: ?[]const u8,
    resp_buf: []u8,
    ctx: *Context,
) !u16 {
    var headers_storage: [1]@import("http/request.zig").Header = undefined;
    var header_count: usize = 0;
    if (token) |t| {
        headers_storage[0] = .{ .name = "X-Admin-Token", .value = t };
        header_count = 1;
    }
    var req: Request = .{
        .method = method,
        .method_raw = "",
        .target = "/admin/tenants",
        .version = "HTTP/1.1",
        .headers = headers_storage[0..header_count],
        .body = body,
    };
    var builder = Response.Builder.init(resp_buf);
    var params: PathParams = .{};
    if (id_param) |idv| {
        params.keys[0] = "id";
        params.values[0] = idv;
        params.count = 1;
    }
    var hc: HandlerContext = .{
        .plugin_ctx = ctx,
        .request = &req,
        .response = &builder,
        .params = params,
    };
    try handler(&hc);
    const out = builder.bytes();
    const sp = std.mem.indexOfScalar(u8, out, ' ').?;
    return std.fmt.parseInt(u16, out[sp + 1 .. sp + 4], 10) catch 0;
}

test "jsonStringField extracts simple fields, rejects escapes/missing" {
    try testing.expectEqualStrings("t1", jsonStringField("{\"id\":\"t1\",\"host\":\"a.example\"}", "id").?);
    try testing.expectEqualStrings("a.example", jsonStringField("{\"id\":\"t1\",\"host\":\"a.example\"}", "host").?);
    try testing.expectEqualStrings("suspended", jsonStringField("{ \"state\" : \"suspended\" }", "state").?);
    try testing.expect(jsonStringField("{\"id\":\"t1\"}", "host") == null);
    try testing.expect(jsonStringField("{\"id\":\"a\\\"b\"}", "id") == null); // escape rejected
}

test "C1: admin token required (401 without)" {
    resetForTest();
    setToken("secret-admin-token");
    defer resetForTest();
    tenancy.setGlobalTable(.{});
    defer tenancy.setGlobalTable(.{});

    var ctx: Context = undefined;
    var rbuf: [1024]u8 = undefined;

    // No token → 401.
    try testing.expectEqual(@as(u16, 401), try runHandler(
        handleCreate,
        .post,
        null,
        "{\"id\":\"t1\",\"host\":\"a.example\"}",
        null,
        &rbuf,
        &ctx,
    ));
    // Wrong token → 401.
    try testing.expectEqual(@as(u16, 401), try runHandler(
        handleCreate,
        .post,
        "wrong",
        "{\"id\":\"t1\",\"host\":\"a.example\"}",
        null,
        &rbuf,
        &ctx,
    ));
    // The bad attempts must not have registered a tenant.
    try testing.expectEqual(@as(u8, 0), tenancy.globalTable().count);
}

test "C1: create → tenant active + DB ensured; suspend; delete" {
    resetForTest();
    setToken("secret-admin-token");
    defer resetForTest();
    tenancy.setGlobalTable(.{});
    defer tenancy.setGlobalTable(.{});

    // Temp provider so ensureTenant has somewhere to open the per-tenant DB.
    const root = "/tmp/sps-tenancy-routes-test";
    _ = std.c.mkdir(root, 0o755);
    const ddb = try sqlite.openWriter(":memory:");
    defer sqlite.closeDb(ddb);
    const provider_mod = @import("storage/provider.zig");
    var prov = provider_mod.SqliteProvider.init(testing.allocator, ddb, root);
    defer prov.deinit();
    var schema = schema_mod.Schema.init();
    try schema.register(.{ .id = 1, .name = "bookkeeping", .up = "CREATE TABLE migrations(id INTEGER PRIMARY KEY, name TEXT, applied_at INTEGER)", .down = null });
    try prov.dbProvider().migrate(&schema);
    storage.setProvider(prov.dbProvider());
    defer storage.setProvider(null);

    var ctx: Context = undefined;
    var rbuf: [1024]u8 = undefined;

    // Randomized-ish unique id so reruns don't collide on the table.
    var prng = std.Random.DefaultPrng.init(@bitCast(std.time.nanoTimestamp()));
    var id_buf: [12]u8 = undefined;
    const id = std.fmt.bufPrint(&id_buf, "t{d}", .{prng.random().int(u32)}) catch unreachable;
    var body_buf: [128]u8 = undefined;
    const body = try std.fmt.bufPrint(&body_buf, "{{\"id\":\"{s}\",\"host\":\"{s}.example\"}}", .{ id, id });

    // Create → 201, tenant present + active, per-tenant handle distinct.
    try testing.expectEqual(@as(u16, 201), try runHandler(handleCreate, .post, "secret-admin-token", body, null, &rbuf, &ctx));
    const t = tenancy.globalTable().lookupById(id) orelse return error.TenantMissing;
    try testing.expectEqual(tenancy.State.active, t.state);
    try testing.expect(prov.dbProvider().handleFor(id) != ddb); // distinct DB ensured

    // Suspend via PATCH → 200, state suspended.
    try testing.expectEqual(@as(u16, 200), try runHandler(handlePatch, .patch, "secret-admin-token", "{\"state\":\"suspended\"}", id, &rbuf, &ctx));
    try testing.expectEqual(tenancy.State.suspended, tenancy.globalTable().lookupById(id).?.state);

    // Reactivate via PATCH → 200, state active.
    try testing.expectEqual(@as(u16, 200), try runHandler(handlePatch, .patch, "secret-admin-token", "{\"state\":\"active\"}", id, &rbuf, &ctx));
    try testing.expectEqual(tenancy.State.active, tenancy.globalTable().lookupById(id).?.state);

    // Delete → 200, state deleted (DB file untouched on disk).
    try testing.expectEqual(@as(u16, 200), try runHandler(handleDelete, .delete, "secret-admin-token", "", id, &rbuf, &ctx));
    try testing.expectEqual(tenancy.State.deleted, tenancy.globalTable().lookupById(id).?.state);

    // PATCH/DELETE on unknown tenant → 404.
    try testing.expectEqual(@as(u16, 404), try runHandler(handlePatch, .patch, "secret-admin-token", "{\"state\":\"active\"}", "does-not-exist", &rbuf, &ctx));
    try testing.expectEqual(@as(u16, 404), try runHandler(handleDelete, .delete, "secret-admin-token", "", "does-not-exist", &rbuf, &ctx));

    // PATCH with an illegal state → 400.
    try testing.expectEqual(@as(u16, 400), try runHandler(handlePatch, .patch, "secret-admin-token", "{\"state\":\"deleted\"}", id, &rbuf, &ctx));

    // Duplicate create → 409.
    try testing.expectEqual(@as(u16, 409), try runHandler(handleCreate, .post, "secret-admin-token", body, null, &rbuf, &ctx));

    // Best-effort cleanup.
    var path_buf: [256]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buf, "{s}/{s}.db", .{ root, id }) catch unreachable;
    _ = std.c.unlink(path.ptr);
}
