//! AT-22: `com.atproto.admin.*` namespace (read-only first; write
//! paths follow when AT-8 lifecycle integration matures).
//!
//! Endpoints land here:
//!   * getAccountInfo
//!   * getSubjectStatus
//!   * searchAccounts
//!   * updateAccountHandle (write — uses Backend.setHandle)
//!   * updateAccountEmail (write — uses Backend.setEmail)
//!   * disableInviteCodes (write — uses Backend.disableInvite)
//!   * sendEmail (write — uses Sender)
//!
//! Authentication: gate via the `Authorization: Bearer <admin-token>`
//! header. The admin token is loaded from `core.secrets` at boot
//! under the name `admin_token`. When unset, all admin endpoints
//! return 503 ServiceUnavailable.

const std = @import("std");
const core = @import("core");
const HandlerContext = core.http.router.HandlerContext;
const Router = core.http.router.Router;

const State = @import("state.zig");
const xrpc = @import("xrpc.zig");
const account = core.account;
const email_mod = core.email;
const secrets_mod = core.secrets;
const firehose = @import("firehose.zig");

fn ensureAdmin(hc: *HandlerContext) bool {
    const store = secrets_mod.global() orelse {
        _ = xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "admin not configured") catch {};
        return false;
    };
    var token_buf: [256]u8 = undefined;
    const expected = store.get("admin_token", &token_buf) catch {
        _ = xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "admin token unset") catch {};
        return false;
    };

    const auth_hdr = hc.request.header("Authorization") orelse {
        _ = xrpc.writeError(hc, .unauthorized, "AuthenticationRequired", "missing bearer") catch {};
        return false;
    };
    if (!std.mem.startsWith(u8, auth_hdr, "Bearer ")) {
        _ = xrpc.writeError(hc, .unauthorized, "AuthenticationRequired", "bad scheme") catch {};
        return false;
    }
    const token = auth_hdr[7..];
    if (!std.mem.eql(u8, token, expected)) {
        _ = xrpc.writeError(hc, .unauthorized, "AuthenticationRequired", "bad admin token") catch {};
        return false;
    }
    return true;
}

fn getAccountInfo(hc: *HandlerContext) anyerror!void {
    if (!ensureAdmin(hc)) return;
    const backend = account.global() orelse return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "account backend not configured");
    const q = hc.request.pathAndQuery().query;
    const did = xrpc.queryParam(q, "did") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing did");
    var acc: account.Account = .{};
    const found = backend.lookupById(did, &acc) catch
        return xrpc.writeError(hc, .internal, "InternalError", "lookup");
    if (!found) return xrpc.writeError(hc, .not_found, "AccountNotFound", "no account");
    var resp_buf: [1024]u8 = undefined;
    const resp = std.fmt.bufPrint(&resp_buf,
        "{{\"did\":\"{s}\",\"handle\":\"{s}\",\"email\":\"{s}\",\"emailConfirmed\":{s},\"state\":\"{s}\"}}",
        .{
            acc.id(), acc.handle(), acc.email(),
            if (acc.email_confirmed) "true" else "false",
            acc.state.columnString(),
        },
    ) catch return xrpc.writeError(hc, .internal, "InternalError", "fmt");
    try xrpc.writeJsonBody(hc, .ok, resp);
}

fn getSubjectStatus(hc: *HandlerContext) anyerror!void {
    if (!ensureAdmin(hc)) return;
    const backend = account.global() orelse return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "account backend not configured");
    const q = hc.request.pathAndQuery().query;
    const did = xrpc.queryParam(q, "did") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing did");
    var acc: account.Account = .{};
    const found = backend.lookupById(did, &acc) catch
        return xrpc.writeError(hc, .internal, "InternalError", "lookup");
    if (!found) return xrpc.writeError(hc, .not_found, "AccountNotFound", "no account");
    var resp_buf: [256]u8 = undefined;
    const resp = std.fmt.bufPrint(&resp_buf,
        "{{\"subject\":{{\"$type\":\"com.atproto.admin.defs#repoRef\",\"did\":\"{s}\"}},\"takedown\":{{\"applied\":{s}}}}}",
        .{ did, if (acc.state == .takendown) "true" else "false" },
    ) catch return xrpc.writeError(hc, .internal, "InternalError", "fmt");
    try xrpc.writeJsonBody(hc, .ok, resp);
}

fn searchAccounts(hc: *HandlerContext) anyerror!void {
    if (!ensureAdmin(hc)) return;
    // Search by exact handle or email — the MemoryBackend doesn't yet
    // support prefix search; this endpoint surfaces what's available.
    const backend = account.global() orelse return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "account backend not configured");
    const q = hc.request.pathAndQuery().query;
    var acc: account.Account = .{};
    var found = false;
    if (xrpc.queryParam(q, "handle")) |handle| {
        found = backend.lookupByHandle(handle, &acc) catch false;
    } else if (xrpc.queryParam(q, "email")) |email| {
        found = backend.lookupByEmail(email, &acc) catch false;
    }
    if (!found) {
        try xrpc.writeJsonBody(hc, .ok, "{\"accounts\":[]}");
        return;
    }
    var resp_buf: [512]u8 = undefined;
    const resp = std.fmt.bufPrint(&resp_buf,
        "{{\"accounts\":[{{\"did\":\"{s}\",\"handle\":\"{s}\"}}]}}",
        .{ acc.id(), acc.handle() },
    ) catch return xrpc.writeError(hc, .internal, "InternalError", "fmt");
    try xrpc.writeJsonBody(hc, .ok, resp);
}

fn updateAccountHandle(hc: *HandlerContext) anyerror!void {
    if (!ensureAdmin(hc)) return;
    const st = State.get();
    const backend = account.global() orelse return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "account backend not configured");
    const did = xrpc.jsonStringField(hc.request.body, "did") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing did");
    const handle = xrpc.jsonStringField(hc.request.body, "handle") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing handle");
    backend.setHandle(did, handle, st.clock.wallUnix()) catch |e| switch (e) {
        error.AlreadyExists => return xrpc.writeError(hc, .bad_request, "HandleNotAvailable", "handle in use"),
        error.NotFound => return xrpc.writeError(hc, .not_found, "AccountNotFound", "no account"),
        else => return xrpc.writeError(hc, .internal, "InternalError", "set handle"),
    };
    if (st.dbHandle()) |db| {
        _ = firehose.appendIdentity(db, did, handle, st.clock.wallUnix()) catch {};
    }
    try xrpc.writeJsonBody(hc, .ok, "{}");
}

fn updateAccountEmail(hc: *HandlerContext) anyerror!void {
    if (!ensureAdmin(hc)) return;
    const st = State.get();
    const backend = account.global() orelse return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "account backend not configured");
    const did = xrpc.jsonStringField(hc.request.body, "did") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing did");
    const email = xrpc.jsonStringField(hc.request.body, "email") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing email");
    backend.setEmail(did, email, st.clock.wallUnix()) catch |e| switch (e) {
        error.NotFound => return xrpc.writeError(hc, .not_found, "AccountNotFound", "no account"),
        else => return xrpc.writeError(hc, .internal, "InternalError", "set email"),
    };
    try xrpc.writeJsonBody(hc, .ok, "{}");
}

fn disableInviteCodes(hc: *HandlerContext) anyerror!void {
    if (!ensureAdmin(hc)) return;
    const backend = account.global() orelse return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "account backend not configured");
    const code = xrpc.jsonStringField(hc.request.body, "code") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing code");
    backend.disableInvite(code) catch return xrpc.writeError(hc, .internal, "InternalError", "disable");
    try xrpc.writeJsonBody(hc, .ok, "{}");
}

fn sendEmail(hc: *HandlerContext) anyerror!void {
    if (!ensureAdmin(hc)) return;
    const sender = email_mod.global() orelse return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "email backend not configured");
    const to = xrpc.jsonStringField(hc.request.body, "recipientDid") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing recipientDid");
    const subject = xrpc.jsonStringField(hc.request.body, "subject") orelse "";
    const body = xrpc.jsonStringField(hc.request.body, "content") orelse "";
    // The admin endpoint addresses by DID; resolve to email if possible.
    const backend = account.global() orelse return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "account backend not configured");
    var acc: account.Account = .{};
    const found = backend.lookupById(to, &acc) catch
        return xrpc.writeError(hc, .internal, "InternalError", "lookup");
    if (!found) return xrpc.writeError(hc, .not_found, "AccountNotFound", "no account");
    sender.send(&.{ .to = acc.email(), .subject = subject, .text_body = body }) catch
        return xrpc.writeError(hc, .internal, "InternalError", "send");
    try xrpc.writeJsonBody(hc, .ok, "{}");
}

pub fn register(router: *Router, plugin_index: u16) !void {
    try router.register(.get, "/xrpc/com.atproto.admin.getAccountInfo", getAccountInfo, plugin_index);
    try router.register(.get, "/xrpc/com.atproto.admin.getSubjectStatus", getSubjectStatus, plugin_index);
    try router.register(.get, "/xrpc/com.atproto.admin.searchAccounts", searchAccounts, plugin_index);
    try router.register(.post, "/xrpc/com.atproto.admin.updateAccountHandle", updateAccountHandle, plugin_index);
    try router.register(.post, "/xrpc/com.atproto.admin.updateAccountEmail", updateAccountEmail, plugin_index);
    try router.register(.post, "/xrpc/com.atproto.admin.disableInviteCodes", disableInviteCodes, plugin_index);
    try router.register(.post, "/xrpc/com.atproto.admin.sendEmail", sendEmail, plugin_index);
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "AT-22: admin namespace registers 7 routes" {
    var r = Router.init();
    try register(&r, 0);
    try testing.expectEqual(@as(u32, 7), r.count);
}
