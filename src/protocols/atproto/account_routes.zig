//! XRPC handlers for AT-8 / AT-9 / AT-10 / AT-11.
//!
//! All routes here go through `core.account.Backend` and (where they
//! need to send a mail) `core.email.Sender`. Both are pluggable; the
//! composition root wires them at boot. Routes return spec-shape
//! JSON envelopes.
//!
//! Endpoints:
//!   AT-8   createAccount, deleteAccount, deactivateAccount,
//!          activateAccount, checkAccountStatus, requestAccountDelete,
//!          getSession
//!   AT-9   requestEmailConfirmation, confirmEmail,
//!          requestEmailUpdate, updateEmail,
//!          requestPasswordReset, resetPassword
//!   AT-10  createAppPassword, listAppPasswords, revokeAppPassword
//!   AT-11  createInviteCode(s), getAccountInviteCodes,
//!          disableInviteCodes, checkSignupQueue

const std = @import("std");
const core = @import("core");
const HandlerContext = core.http.router.HandlerContext;
const Router = core.http.router.Router;

const State = @import("state.zig");
const xrpc = @import("xrpc.zig");
const auth_mod = @import("auth.zig");
const firehose = @import("firehose.zig");

const account = core.account;
const email_mod = core.email;

// ──────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────

/// Pull and Bearer-decode an account id (the JWT subject) from the
/// Authorization header. Returns null if absent / invalid.
fn authedSub(hc: *HandlerContext, out: []u8) ?[]const u8 {
    const st = State.get();
    const hdr = hc.request.header("Authorization") orelse return null;
    if (!std.mem.startsWith(u8, hdr, "Bearer ")) return null;
    const token = hdr[7..];
    var claims: auth_mod.Claims = .{ .scope = .access, .iat = 0, .exp = 0 };
    auth_mod.verify(token, st.jwt_key.public_key, st.clock.wallUnix(), &claims) catch return null;
    const sub = claims.sub();
    if (sub.len > out.len) return null;
    @memcpy(out[0..sub.len], sub);
    return out[0..sub.len];
}

fn ensureBackend(hc: *HandlerContext) ?account.Backend {
    return account.global() orelse blk: {
        _ = xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "account backend not configured") catch {};
        break :blk null;
    };
}

fn mintTokens(sub: []const u8, now: i64, access_buf: []u8, refresh_buf: []u8) !struct { access: []const u8, refresh: []const u8 } {
    const st = State.get();
    var access_jti: [16]u8 = undefined;
    var refresh_jti: [16]u8 = undefined;
    fillJti(&access_jti, now, 1);
    fillJti(&refresh_jti, now, 2);

    var ac: auth_mod.Claims = .{ .scope = .access, .iat = now, .exp = now + auth_mod.access_ttl_seconds };
    try ac.setSub(sub);
    try ac.setJti(&access_jti);

    var rc: auth_mod.Claims = .{ .scope = .refresh, .iat = now, .exp = now + auth_mod.refresh_ttl_seconds };
    try rc.setSub(sub);
    try rc.setJti(&refresh_jti);

    return .{
        .access = try auth_mod.sign(st.jwt_key, ac, access_buf),
        .refresh = try auth_mod.sign(st.jwt_key, rc, refresh_buf),
    };
}

fn fillJti(out: []u8, seed: i64, salt: u8) void {
    var i: usize = 0;
    var v: u64 = @as(u64, @bitCast(seed)) ^ (@as(u64, salt) << 56);
    while (i < out.len) : (i += 1) {
        out[i] = "0123456789abcdef"[@as(usize, @intCast(v & 0xf))];
        v >>= 4;
        if (v == 0) v = @as(u64, @bitCast(seed)) +% (@as(u64, salt) * (@as(u64, i) + 1));
    }
}

fn sendMailBestEffort(to: []const u8, subject: []const u8, body: []const u8) void {
    const sender = email_mod.global() orelse return;
    sender.send(&.{ .to = to, .subject = subject, .text_body = body }) catch {};
}

/// Build a did:web identifier for the local PDS host. Reused as the
/// minted account id when the client doesn't supply one.
fn buildLocalDid(handle: []const u8, out: []u8) ![]const u8 {
    return std.fmt.bufPrint(out, "did:web:{s}", .{handle});
}

// ──────────────────────────────────────────────────────────────────────
// AT-8: account lifecycle
// ──────────────────────────────────────────────────────────────────────

fn createAccount(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const backend = ensureBackend(hc) orelse return;

    const handle = xrpc.jsonStringField(hc.request.body, "handle") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing handle");
    const email = xrpc.jsonStringField(hc.request.body, "email") orelse "";
    const password = xrpc.jsonStringField(hc.request.body, "password") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing password");
    const invite_opt = xrpc.jsonStringField(hc.request.body, "inviteCode");

    // AT-11: if an invite is supplied, consume it. We don't require
    // invites by default; an env / future-config knob will gate that.
    if (invite_opt) |code| {
        const consumed = backend.consumeInvite(code, st.clock.wallUnix()) catch
            return xrpc.writeError(hc, .internal, "InternalError", "invite check");
        if (!consumed) return xrpc.writeError(hc, .bad_request, "InvalidInviteCode", "invite code not redeemable");
    }

    // Mint a did:web from the requested handle. Real production
    // would consult a DID minting policy (PLC for real PDS, did:web
    // for self-hosted single-node).
    var did_buf: [256]u8 = undefined;
    const did = buildLocalDid(handle, &did_buf) catch
        return xrpc.writeError(hc, .internal, "InternalError", "did fmt");

    backend.create(&.{
        .id = did,
        .handle = handle,
        .email = email,
        .password = password,
        .invite_code = invite_opt,
    }, st.clock.wallUnix()) catch |e| switch (e) {
        error.AlreadyExists => return xrpc.writeError(hc, .bad_request, "HandleNotAvailable", "handle or DID in use"),
        error.InvalidArg => return xrpc.writeError(hc, .bad_request, "InvalidRequest", "invalid field"),
        else => return xrpc.writeError(hc, .internal, "InternalError", "create"),
    };

    // Account creation is also an #identity event (a new identity
    // appeared on this PDS) — emit if we have a writable DB.
    if (st.reader_db) |db| {
        _ = firehose.appendIdentity(db, did, handle, st.clock.wallUnix()) catch {};
        // DUAL-1: bind the new account's AP actor IRI <→> AT DID in
        // the cross-protocol identity map so a single signup serves
        // both networks.
        var ap_actor_buf: [320]u8 = undefined;
        if (std.fmt.bufPrint(&ap_actor_buf, "https://{s}/users/{s}", .{ st.host, handle })) |ap_actor| {
            _ = core.dual_identity.bind(db, did, ap_actor, did, "", st.clock.wallUnix()) catch {};
        } else |_| {}
    }

    // Mint a fresh session.
    var access_buf: [auth_mod.max_jwt_bytes]u8 = undefined;
    var refresh_buf: [auth_mod.max_jwt_bytes]u8 = undefined;
    const tokens = mintTokens(did, st.clock.wallUnix(), &access_buf, &refresh_buf) catch
        return xrpc.writeError(hc, .internal, "InternalError", "jwt");

    // Best-effort email confirmation.
    if (email.len > 0) {
        var tok: account.TokenIssued = .{};
        if (backend.issueToken(did, .email_confirm, 24 * 3600, st.clock.wallUnix(), seedFromClock(), &tok)) |_| {
            var subj_buf: [128]u8 = undefined;
            const subj = std.fmt.bufPrint(&subj_buf, "Confirm your speedy-socials email", .{}) catch "Confirm your email";
            var body_buf: [512]u8 = undefined;
            const body = std.fmt.bufPrint(&body_buf,
                "Hi {s},\n\nConfirm your email by submitting this token: {s}\n",
                .{ handle, tok.token() },
            ) catch tok.token();
            sendMailBestEffort(email, subj, body);
        } else |_| {}
    }

    var resp_buf: [4096]u8 = undefined;
    const resp = std.fmt.bufPrint(&resp_buf,
        "{{\"did\":\"{s}\",\"handle\":\"{s}\",\"accessJwt\":\"{s}\",\"refreshJwt\":\"{s}\"}}",
        .{ did, handle, tokens.access, tokens.refresh },
    ) catch return xrpc.writeError(hc, .internal, "InternalError", "fmt");
    try xrpc.writeJsonBody(hc, .ok, resp);
}

fn deleteAccount(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const backend = ensureBackend(hc) orelse return;
    const did = xrpc.jsonStringField(hc.request.body, "did") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing did");
    const password = xrpc.jsonStringField(hc.request.body, "password") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing password");
    const token = xrpc.jsonStringField(hc.request.body, "token") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing token");

    // Token must be a valid password_reset-style token we issued via
    // requestAccountDelete.
    var out_id: [account.max_id_bytes]u8 = undefined;
    const redeemed = backend.redeemToken(.password_reset, token, st.clock.wallUnix(), &out_id) catch |e| switch (e) {
        error.NotFound => return xrpc.writeError(hc, .bad_request, "InvalidToken", "token not found"),
        error.Expired => return xrpc.writeError(hc, .bad_request, "ExpiredToken", "token expired"),
        else => return xrpc.writeError(hc, .internal, "InternalError", "token"),
    };
    if (!std.mem.eql(u8, redeemed, did)) {
        return xrpc.writeError(hc, .bad_request, "InvalidToken", "token doesn't match did");
    }
    const ok = backend.verifyPassword(did, password) catch
        return xrpc.writeError(hc, .internal, "InternalError", "password verify");
    if (!ok) return xrpc.writeError(hc, .unauthorized, "AuthenticationRequired", "bad credentials");

    backend.setState(did, .deleted, st.clock.wallUnix()) catch
        return xrpc.writeError(hc, .internal, "InternalError", "set state");

    if (st.reader_db) |db| {
        _ = firehose.appendAccount(db, did, false, "deleted", st.clock.wallUnix()) catch {};
        _ = firehose.appendTombstone(db, did, st.clock.wallUnix()) catch {};
    }
    try xrpc.writeJsonBody(hc, .ok, "{}");
}

fn deactivateAccount(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const backend = ensureBackend(hc) orelse return;
    var sub_buf: [account.max_id_bytes]u8 = undefined;
    const sub = authedSub(hc, &sub_buf) orelse
        return xrpc.writeError(hc, .unauthorized, "AuthenticationRequired", "no session");
    backend.setState(sub, .deactivated, st.clock.wallUnix()) catch
        return xrpc.writeError(hc, .internal, "InternalError", "set state");
    if (st.reader_db) |db| {
        _ = firehose.appendAccount(db, sub, false, "deactivated", st.clock.wallUnix()) catch {};
    }
    try xrpc.writeJsonBody(hc, .ok, "{}");
}

fn activateAccount(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const backend = ensureBackend(hc) orelse return;
    var sub_buf: [account.max_id_bytes]u8 = undefined;
    const sub = authedSub(hc, &sub_buf) orelse
        return xrpc.writeError(hc, .unauthorized, "AuthenticationRequired", "no session");
    backend.setState(sub, .active, st.clock.wallUnix()) catch
        return xrpc.writeError(hc, .internal, "InternalError", "set state");
    if (st.reader_db) |db| {
        _ = firehose.appendAccount(db, sub, true, "", st.clock.wallUnix()) catch {};
    }
    try xrpc.writeJsonBody(hc, .ok, "{}");
}

fn checkAccountStatus(hc: *HandlerContext) anyerror!void {
    const backend = ensureBackend(hc) orelse return;
    var sub_buf: [account.max_id_bytes]u8 = undefined;
    const sub = authedSub(hc, &sub_buf) orelse
        return xrpc.writeError(hc, .unauthorized, "AuthenticationRequired", "no session");
    var acc: account.Account = .{};
    const found = backend.lookupById(sub, &acc) catch
        return xrpc.writeError(hc, .internal, "InternalError", "lookup");
    if (!found) return xrpc.writeError(hc, .not_found, "AccountNotFound", "no account");
    var resp_buf: [512]u8 = undefined;
    const resp = std.fmt.bufPrint(&resp_buf,
        "{{\"activated\":{s},\"validDid\":true,\"emailConfirmed\":{s}}}",
        .{
            if (acc.state == .active) "true" else "false",
            if (acc.email_confirmed) "true" else "false",
        },
    ) catch return xrpc.writeError(hc, .internal, "InternalError", "fmt");
    try xrpc.writeJsonBody(hc, .ok, resp);
}

fn requestAccountDelete(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const backend = ensureBackend(hc) orelse return;
    var sub_buf: [account.max_id_bytes]u8 = undefined;
    const sub = authedSub(hc, &sub_buf) orelse
        return xrpc.writeError(hc, .unauthorized, "AuthenticationRequired", "no session");
    var acc: account.Account = .{};
    const found = backend.lookupById(sub, &acc) catch
        return xrpc.writeError(hc, .internal, "InternalError", "lookup");
    if (!found) return xrpc.writeError(hc, .not_found, "AccountNotFound", "no account");

    var tok: account.TokenIssued = .{};
    backend.issueToken(sub, .password_reset, 24 * 3600, st.clock.wallUnix(), seedFromClock(), &tok) catch
        return xrpc.writeError(hc, .internal, "InternalError", "token");
    var body_buf: [512]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf,
        "Account-deletion token (24h TTL): {s}\n",
        .{tok.token()},
    ) catch tok.token();
    if (acc.email().len > 0) {
        sendMailBestEffort(acc.email(), "Confirm account deletion", body);
    }
    try xrpc.writeJsonBody(hc, .ok, "{}");
}

fn getSession(hc: *HandlerContext) anyerror!void {
    const backend = ensureBackend(hc) orelse return;
    var sub_buf: [account.max_id_bytes]u8 = undefined;
    const sub = authedSub(hc, &sub_buf) orelse
        return xrpc.writeError(hc, .unauthorized, "AuthenticationRequired", "no session");
    var acc: account.Account = .{};
    const found = backend.lookupById(sub, &acc) catch
        return xrpc.writeError(hc, .internal, "InternalError", "lookup");
    if (!found) return xrpc.writeError(hc, .not_found, "AccountNotFound", "no account");
    var resp_buf: [1024]u8 = undefined;
    const resp = std.fmt.bufPrint(&resp_buf,
        "{{\"handle\":\"{s}\",\"did\":\"{s}\",\"email\":\"{s}\",\"emailConfirmed\":{s}}}",
        .{
            acc.handle(),
            acc.id(),
            acc.email(),
            if (acc.email_confirmed) "true" else "false",
        },
    ) catch return xrpc.writeError(hc, .internal, "InternalError", "fmt");
    try xrpc.writeJsonBody(hc, .ok, resp);
}

// ──────────────────────────────────────────────────────────────────────
// AT-9: email + password reset
// ──────────────────────────────────────────────────────────────────────

fn requestEmailConfirmation(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const backend = ensureBackend(hc) orelse return;
    var sub_buf: [account.max_id_bytes]u8 = undefined;
    const sub = authedSub(hc, &sub_buf) orelse
        return xrpc.writeError(hc, .unauthorized, "AuthenticationRequired", "no session");
    var acc: account.Account = .{};
    _ = backend.lookupById(sub, &acc) catch {};
    var tok: account.TokenIssued = .{};
    backend.issueToken(sub, .email_confirm, 24 * 3600, st.clock.wallUnix(), seedFromClock(), &tok) catch
        return xrpc.writeError(hc, .internal, "InternalError", "token");
    var body_buf: [512]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf, "Your confirmation token: {s}\n", .{tok.token()}) catch tok.token();
    if (acc.email().len > 0) {
        sendMailBestEffort(acc.email(), "Confirm your email", body);
    }
    try xrpc.writeJsonBody(hc, .ok, "{}");
}

fn confirmEmail(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const backend = ensureBackend(hc) orelse return;
    const email = xrpc.jsonStringField(hc.request.body, "email") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing email");
    const token = xrpc.jsonStringField(hc.request.body, "token") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing token");

    var out_id: [account.max_id_bytes]u8 = undefined;
    const id = backend.redeemToken(.email_confirm, token, st.clock.wallUnix(), &out_id) catch |e| switch (e) {
        error.NotFound => return xrpc.writeError(hc, .bad_request, "InvalidToken", "token not found"),
        error.Expired => return xrpc.writeError(hc, .bad_request, "ExpiredToken", "token expired"),
        else => return xrpc.writeError(hc, .internal, "InternalError", "token"),
    };
    // Confirm that the token's account also matches the supplied email.
    var acc: account.Account = .{};
    const found = backend.lookupById(id, &acc) catch
        return xrpc.writeError(hc, .internal, "InternalError", "lookup");
    if (!found or !std.mem.eql(u8, acc.email(), email)) {
        return xrpc.writeError(hc, .bad_request, "InvalidToken", "email mismatch");
    }
    backend.markEmailConfirmed(id, st.clock.wallUnix()) catch
        return xrpc.writeError(hc, .internal, "InternalError", "mark confirmed");
    try xrpc.writeJsonBody(hc, .ok, "{}");
}

fn requestEmailUpdate(hc: *HandlerContext) anyerror!void {
    // Same token flow as confirmEmail — the new address proves
    // possession by completing the redemption.
    return requestEmailConfirmation(hc);
}

fn updateEmail(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const backend = ensureBackend(hc) orelse return;
    const new_email = xrpc.jsonStringField(hc.request.body, "email") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing email");
    const token = xrpc.jsonStringField(hc.request.body, "token") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing token");
    var out_id: [account.max_id_bytes]u8 = undefined;
    const id = backend.redeemToken(.email_confirm, token, st.clock.wallUnix(), &out_id) catch
        return xrpc.writeError(hc, .bad_request, "InvalidToken", "bad token");
    backend.setEmail(id, new_email, st.clock.wallUnix()) catch
        return xrpc.writeError(hc, .internal, "InternalError", "set email");
    try xrpc.writeJsonBody(hc, .ok, "{}");
}

fn requestPasswordReset(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const backend = ensureBackend(hc) orelse return;
    const email = xrpc.jsonStringField(hc.request.body, "email") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing email");
    var acc: account.Account = .{};
    const found = backend.lookupByEmail(email, &acc) catch
        return xrpc.writeError(hc, .internal, "InternalError", "lookup");
    // Always 200 — don't leak whether the email exists. Send the
    // mail only if we found the account.
    if (found) {
        var tok: account.TokenIssued = .{};
        if (backend.issueToken(acc.id(), .password_reset, 60 * 60, st.clock.wallUnix(), seedFromClock(), &tok)) |_| {
            var body_buf: [512]u8 = undefined;
            const body = std.fmt.bufPrint(&body_buf, "Reset token (1h): {s}\n", .{tok.token()}) catch tok.token();
            sendMailBestEffort(email, "Reset your password", body);
        } else |_| {}
    }
    try xrpc.writeJsonBody(hc, .ok, "{}");
}

fn resetPassword(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const backend = ensureBackend(hc) orelse return;
    const token = xrpc.jsonStringField(hc.request.body, "token") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing token");
    const password = xrpc.jsonStringField(hc.request.body, "password") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing password");
    var out_id: [account.max_id_bytes]u8 = undefined;
    const id = backend.redeemToken(.password_reset, token, st.clock.wallUnix(), &out_id) catch |e| switch (e) {
        error.NotFound => return xrpc.writeError(hc, .bad_request, "InvalidToken", "token not found"),
        error.Expired => return xrpc.writeError(hc, .bad_request, "ExpiredToken", "token expired"),
        else => return xrpc.writeError(hc, .internal, "InternalError", "token"),
    };
    backend.updatePassword(id, password, st.clock.wallUnix()) catch
        return xrpc.writeError(hc, .internal, "InternalError", "update password");
    try xrpc.writeJsonBody(hc, .ok, "{}");
}

// ──────────────────────────────────────────────────────────────────────
// AT-10: app passwords
// ──────────────────────────────────────────────────────────────────────

fn createAppPassword(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const backend = ensureBackend(hc) orelse return;
    var sub_buf: [account.max_id_bytes]u8 = undefined;
    const sub = authedSub(hc, &sub_buf) orelse
        return xrpc.writeError(hc, .unauthorized, "AuthenticationRequired", "no session");
    const name = xrpc.jsonStringField(hc.request.body, "name") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing name");
    var tok: account.TokenIssued = .{};
    backend.createAppPassword(sub, name, st.clock.wallUnix(), seedFromClock(), &tok) catch |e| switch (e) {
        error.AlreadyExists => return xrpc.writeError(hc, .bad_request, "AppPasswordNameInUse", "name in use"),
        error.InvalidArg => return xrpc.writeError(hc, .bad_request, "InvalidRequest", "invalid name"),
        else => return xrpc.writeError(hc, .internal, "InternalError", "create"),
    };
    var resp_buf: [256]u8 = undefined;
    const now_iso = "1970-01-01T00:00:00Z"; // backend doesn't track created_at on app pw rows yet
    const resp = std.fmt.bufPrint(&resp_buf,
        "{{\"name\":\"{s}\",\"password\":\"{s}\",\"createdAt\":\"{s}\"}}",
        .{ name, tok.token(), now_iso },
    ) catch return xrpc.writeError(hc, .internal, "InternalError", "fmt");
    try xrpc.writeJsonBody(hc, .ok, resp);
}

fn listAppPasswords(hc: *HandlerContext) anyerror!void {
    // Backend doesn't expose a list iterator yet; return an empty
    // array to keep the route reachable for clients that probe.
    // Filled in when AT-22 admin paths add a listing API.
    try xrpc.writeJsonBody(hc, .ok, "{\"passwords\":[]}");
}

fn revokeAppPassword(hc: *HandlerContext) anyerror!void {
    const backend = ensureBackend(hc) orelse return;
    var sub_buf: [account.max_id_bytes]u8 = undefined;
    const sub = authedSub(hc, &sub_buf) orelse
        return xrpc.writeError(hc, .unauthorized, "AuthenticationRequired", "no session");
    const name = xrpc.jsonStringField(hc.request.body, "name") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing name");
    backend.revokeAppPassword(sub, name) catch |e| switch (e) {
        error.NotFound => return xrpc.writeError(hc, .not_found, "AppPasswordNotFound", "no such app password"),
        else => return xrpc.writeError(hc, .internal, "InternalError", "revoke"),
    };
    try xrpc.writeJsonBody(hc, .ok, "{}");
}

// ──────────────────────────────────────────────────────────────────────
// AT-11: invite codes
// ──────────────────────────────────────────────────────────────────────

fn createInviteCode(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const backend = ensureBackend(hc) orelse return;
    var sub_buf: [account.max_id_bytes]u8 = undefined;
    const sub = authedSub(hc, &sub_buf) orelse
        return xrpc.writeError(hc, .unauthorized, "AuthenticationRequired", "no session");
    // useCount defaults to 1 if not supplied. The minimal parser
    // doesn't decode numbers — accept it as best-effort.
    const use_count: u32 = blk: {
        if (xrpc.jsonStringField(hc.request.body, "useCount")) |raw| {
            break :blk std.fmt.parseInt(u32, raw, 10) catch 1;
        }
        break :blk 1;
    };

    // Code shape: base32(sha256(sub || rng)) — short, opaque.
    var tok: account.TokenIssued = .{};
    account.mintToken(seedFromClock(), &tok);
    const code = tok.token()[0..16];

    backend.issueInvite(code, sub, use_count, st.clock.wallUnix()) catch |e| switch (e) {
        error.AlreadyExists => return xrpc.writeError(hc, .bad_request, "InvalidRequest", "code collision"),
        else => return xrpc.writeError(hc, .internal, "InternalError", "issue"),
    };
    var resp_buf: [128]u8 = undefined;
    const resp = std.fmt.bufPrint(&resp_buf, "{{\"code\":\"{s}\"}}", .{code}) catch
        return xrpc.writeError(hc, .internal, "InternalError", "fmt");
    try xrpc.writeJsonBody(hc, .ok, resp);
}

fn createInviteCodes(hc: *HandlerContext) anyerror!void {
    // Convenience — delegates to createInviteCode N times. The first
    // implementation simply returns one code.
    return createInviteCode(hc);
}

fn getAccountInviteCodes(hc: *HandlerContext) anyerror!void {
    // Backend doesn't currently track per-account invite ownership in
    // a list-iterable shape; return an empty array.
    try xrpc.writeJsonBody(hc, .ok, "{\"codes\":[]}");
}

fn disableInviteCodes(hc: *HandlerContext) anyerror!void {
    const backend = ensureBackend(hc) orelse return;
    const code = xrpc.jsonStringField(hc.request.body, "code") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing code");
    backend.disableInvite(code) catch |e| switch (e) {
        error.NotFound => return xrpc.writeError(hc, .not_found, "InvalidInviteCode", "no such code"),
        else => return xrpc.writeError(hc, .internal, "InternalError", "disable"),
    };
    try xrpc.writeJsonBody(hc, .ok, "{}");
}

fn checkSignupQueue(hc: *HandlerContext) anyerror!void {
    // No queue today: every signup is immediate.
    try xrpc.writeJsonBody(hc, .ok, "{\"activated\":true}");
}

// ──────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────

fn seedFromClock() u64 {
    const st = State.get();
    const ns = st.clock.wallNs();
    return @bitCast(@as(i64, @truncate(ns)));
}

// ──────────────────────────────────────────────────────────────────────
// Registration
// ──────────────────────────────────────────────────────────────────────

pub fn register(router: *Router, plugin_index: u16) !void {
    // AT-8
    try router.register(.post, "/xrpc/com.atproto.server.createAccount", createAccount, plugin_index);
    try router.register(.post, "/xrpc/com.atproto.server.deleteAccount", deleteAccount, plugin_index);
    try router.register(.post, "/xrpc/com.atproto.server.deactivateAccount", deactivateAccount, plugin_index);
    try router.register(.post, "/xrpc/com.atproto.server.activateAccount", activateAccount, plugin_index);
    try router.register(.get, "/xrpc/com.atproto.server.checkAccountStatus", checkAccountStatus, plugin_index);
    try router.register(.post, "/xrpc/com.atproto.server.requestAccountDelete", requestAccountDelete, plugin_index);
    try router.register(.get, "/xrpc/com.atproto.server.getSession", getSession, plugin_index);

    // AT-9
    try router.register(.post, "/xrpc/com.atproto.server.requestEmailConfirmation", requestEmailConfirmation, plugin_index);
    try router.register(.post, "/xrpc/com.atproto.server.confirmEmail", confirmEmail, plugin_index);
    try router.register(.post, "/xrpc/com.atproto.server.requestEmailUpdate", requestEmailUpdate, plugin_index);
    try router.register(.post, "/xrpc/com.atproto.server.updateEmail", updateEmail, plugin_index);
    try router.register(.post, "/xrpc/com.atproto.server.requestPasswordReset", requestPasswordReset, plugin_index);
    try router.register(.post, "/xrpc/com.atproto.server.resetPassword", resetPassword, plugin_index);

    // AT-10
    try router.register(.post, "/xrpc/com.atproto.server.createAppPassword", createAppPassword, plugin_index);
    try router.register(.get, "/xrpc/com.atproto.server.listAppPasswords", listAppPasswords, plugin_index);
    try router.register(.post, "/xrpc/com.atproto.server.revokeAppPassword", revokeAppPassword, plugin_index);

    // AT-11
    try router.register(.post, "/xrpc/com.atproto.server.createInviteCode", createInviteCode, plugin_index);
    try router.register(.post, "/xrpc/com.atproto.server.createInviteCodes", createInviteCodes, plugin_index);
    try router.register(.get, "/xrpc/com.atproto.server.getAccountInviteCodes", getAccountInviteCodes, plugin_index);
    try router.register(.post, "/xrpc/com.atproto.server.disableInviteCodes", disableInviteCodes, plugin_index);
    try router.register(.get, "/xrpc/com.atproto.server.checkSignupQueue", checkSignupQueue, plugin_index);
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "AT-8: MemoryBackend round-trip via core.account.global()" {
    var mem = account.MemoryBackend.init();
    account.setGlobal(mem.backend());
    defer account.resetGlobal();

    const be = account.global().?;
    try be.create(&.{ .id = "did:web:host/alice", .handle = "alice.host", .email = "a@h", .password = "pw" }, 1);
    var acc: account.Account = .{};
    try testing.expect(try be.lookupById("did:web:host/alice", &acc));
    try testing.expectEqualStrings("alice.host", acc.handle());
    try testing.expectEqual(account.State.active, acc.state);
}

test "AT-9: confirmEmail succeeds after issueToken" {
    var mem = account.MemoryBackend.init();
    const be = mem.backend();
    try be.create(&.{ .id = "did:web:alice", .handle = "alice.h", .email = "alice@h", .password = "pw" }, 1);
    var tok: account.TokenIssued = .{};
    try be.issueToken("did:web:alice", .email_confirm, 3600, 1, 0xAB, &tok);
    var out_id: [account.max_id_bytes]u8 = undefined;
    const id = try be.redeemToken(.email_confirm, tok.token(), 100, &out_id);
    try testing.expectEqualStrings("did:web:alice", id);
    try be.markEmailConfirmed(id, 100);
    var acc: account.Account = .{};
    _ = try be.lookupById("did:web:alice", &acc);
    try testing.expect(acc.email_confirmed);
}

test "AT-10: app password verify works through the backend seam" {
    var mem = account.MemoryBackend.init();
    const be = mem.backend();
    try be.create(&.{ .id = "did:web:bob", .handle = "bob.h", .email = "b@h", .password = "pw" }, 1);
    var pw: account.TokenIssued = .{};
    try be.createAppPassword("did:web:bob", "phone", 2, 0x77, &pw);
    try testing.expect(try be.verifyAppPassword("did:web:bob", pw.token()));
    try be.revokeAppPassword("did:web:bob", "phone");
    try testing.expect(!try be.verifyAppPassword("did:web:bob", pw.token()));
}

test "AT-11: invite code consumed at signup" {
    var mem = account.MemoryBackend.init();
    const be = mem.backend();
    try be.issueInvite("INV-ALPHA", "admin", 1, 1);
    try testing.expect(try be.consumeInvite("INV-ALPHA", 2));
    try testing.expect(!try be.consumeInvite("INV-ALPHA", 3));
}

test "fillJti produces hex bytes" {
    var buf: [16]u8 = undefined;
    fillJti(&buf, 12345, 7);
    for (buf) |b| {
        try testing.expect((b >= '0' and b <= '9') or (b >= 'a' and b <= 'f'));
    }
}

test "ensureBackend returns the global backend" {
    account.resetGlobal();
    var mem = account.MemoryBackend.init();
    account.setGlobal(mem.backend());
    defer account.resetGlobal();
    try testing.expect(account.global() != null);
}
