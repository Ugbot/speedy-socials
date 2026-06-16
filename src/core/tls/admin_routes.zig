//! C4: TLS certificate hot-reload admin surface.
//!
//! Exposes `POST /admin/tls/reload`. On an authenticated request it
//! re-reads the cert + key PEMs from the boot-configured paths
//! (`TLS_CERT_PATH` / `TLS_KEY_PATH`) and swaps the live `CertKeyPair`
//! in the inbound backend via `cert_admin.reloadFromPaths`, then writes
//! a `core_audit_log` entry. A `SIGHUP` handler can be pointed at the
//! same `reloadNow` entry point.
//!
//! Auth is a shared-secret bearer token taken from `ADMIN_TOKEN` at boot.
//! If `ADMIN_TOKEN` is unset the route is disabled (always 403) — there is
//! no implicit "anyone can reload" mode, in line with the project's
//! "no magic bypass in production" rule.
//!
//! Allocation: cert reload reads two PEM files. The hot path runs under
//! the static allocator (which panics on `alloc`), so this module owns a
//! dedicated static scratch buffer wrapped in a `FixedBufferAllocator`,
//! guarded by a spinlock so two concurrent admin requests can't clobber
//! it. The boot loader caps each PEM at 256 KiB; 768 KiB of scratch holds
//! both with slack.

const std = @import("std");
const cert_admin = @import("cert_admin.zig");
const router_mod = @import("../http/router.zig");
const audit = @import("../audit.zig");
const c = @import("sqlite").c;

const HandlerContext = router_mod.HandlerContext;
const Router = router_mod.Router;
const Clock = @import("../clock.zig").Clock;
const Spinlock = @import("../static.zig").Spinlock;

// ── Boot-set configuration ──────────────────────────────────────────────

var admin_token: []const u8 = "";
var cert_path: []const u8 = "";
var key_path: []const u8 = "";
var audit_db: ?*c.sqlite3 = null;
var audit_clock: Clock = undefined;
var configured: bool = false;

var reload_buf: [768 * 1024]u8 = undefined;
var reload_lock: Spinlock = .{};

/// Wire the reload route's dependencies at boot, before the static
/// allocator is locked. `token` is borrowed (must outlive the server —
/// typically the env string, which is stable). Passing an empty token
/// leaves the route disabled.
pub fn configure(
    token: []const u8,
    cert_p: []const u8,
    key_p: []const u8,
    db: *c.sqlite3,
    clock: Clock,
) void {
    admin_token = token;
    cert_path = cert_p;
    key_path = key_p;
    audit_db = db;
    audit_clock = clock;
    configured = true;
}

/// Reset module state (tests only).
pub fn resetForTest() void {
    admin_token = "";
    cert_path = "";
    key_path = "";
    audit_db = null;
    configured = false;
}

/// Constant-time token comparison. Returns false fast only on the public
/// length difference; the byte comparison itself does not short-circuit.
fn tokenMatches(presented: []const u8) bool {
    if (admin_token.len == 0) return false;
    if (presented.len != admin_token.len) return false;
    var diff: u8 = 0;
    for (presented, admin_token) |a, b| diff |= a ^ b;
    return diff == 0;
}

/// Extract the bearer credential from an `Authorization: Bearer <tok>` or
/// `X-Admin-Token: <tok>` header.
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

/// The reload itself, factored out so a SIGHUP handler can call it
/// directly. Returns the error from `cert_admin` (or success). Records an
/// audit row when an audit db is configured.
pub fn reloadNow(actor: []const u8) cert_admin.Error!void {
    if (cert_path.len == 0 or key_path.len == 0) return error.CertPathUnset;

    reload_lock.lock();
    defer reload_lock.unlock();

    var fba = std.heap.FixedBufferAllocator.init(&reload_buf);
    const result = cert_admin.reloadFromPaths(cert_path, key_path, fba.allocator());

    if (audit_db) |db| {
        const ok = if (result) |_| true else |_| false;
        var detail_buf: [256]u8 = undefined;
        const detail = std.fmt.bufPrint(
            &detail_buf,
            "{{\"cert\":\"{s}\"}}",
            .{cert_path},
        ) catch "{}";
        audit.append(db, audit_clock, actor, "tls.reload", "inbound", detail, ok) catch {};
    }
    return result;
}

fn handleReload(hc: *HandlerContext) anyerror!void {
    if (!configured) {
        return hc.response.simple(.service_unavailable, "application/json", "{\"error\":\"tls reload not configured\"}");
    }
    const presented = presentedToken(hc) orelse {
        return hc.response.simple(.forbidden, "application/json", "{\"error\":\"admin auth required\"}");
    };
    if (!tokenMatches(presented)) {
        return hc.response.simple(.forbidden, "application/json", "{\"error\":\"admin auth required\"}");
    }

    reloadNow("admin") catch |err| {
        const msg = switch (err) {
            error.CertPathUnset => "{\"error\":\"cert paths not set\"}",
            error.CertReadFailed => "{\"error\":\"cert read failed\"}",
            error.KeyReadFailed => "{\"error\":\"key read failed\"}",
            error.ReloadFailed => "{\"error\":\"reload failed (bad PEM?)\"}",
            error.BackendNotConfigured => "{\"error\":\"no inbound TLS backend\"}",
        };
        return hc.response.simple(.internal, "application/json", msg);
    };
    return hc.response.simple(.ok, "application/json", "{\"reloaded\":true}");
}

/// Register `POST /admin/tls/reload`. Slot is the sentinel plugin index
/// (core route, no owning plugin).
pub fn registerRoutes(router: *Router, plugin_index: u16) !void {
    try router.register(.post, "/admin/tls/reload", handleReload, plugin_index);
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

test "tokenMatches: rejects when token unset, accepts exact match" {
    resetForTest();
    try testing.expect(!tokenMatches("anything"));

    admin_token = "s3cr3t-token-value";
    try testing.expect(tokenMatches("s3cr3t-token-value"));
    try testing.expect(!tokenMatches("s3cr3t-token-valuX"));
    try testing.expect(!tokenMatches("short"));
    try testing.expect(!tokenMatches(""));
    resetForTest();
}

test "tokenMatches: randomized non-matches over varying lengths" {
    var prng = std.Random.DefaultPrng.init(0x70_4B_3_5);
    const rand = prng.random();
    var secret_buf: [32]u8 = undefined;
    rand.bytes(&secret_buf);
    admin_token = &secret_buf;
    // A fresh random buffer of a different length must never match.
    var trial: usize = 0;
    while (trial < 128) : (trial += 1) {
        var other: [33]u8 = undefined;
        rand.bytes(&other);
        const len = rand.intRangeAtMost(usize, 0, other.len);
        try testing.expect(!tokenMatches(other[0..len]));
    }
    // The exact secret still matches.
    try testing.expect(tokenMatches(&secret_buf));
    resetForTest();
}
