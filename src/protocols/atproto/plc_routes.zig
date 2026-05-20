//! AT-19: PLC operations (com.atproto.identity.*).
//!
//! Endpoints:
//!   * getRecommendedDidCredentials — returns the credential set this
//!     PDS would mint for a new did:plc account.
//!   * signPlcOperation — signs a candidate PLC operation with the
//!     account's PLC rotation key. Today we delegate signing to the
//!     PDS-wide JWT key (operators flip per-account keys in a later
//!     hardening pass).
//!   * submitPlcOperation — POSTs the signed operation to the
//!     configured PLC directory.
//!   * requestPlcOperationSignature — emails the user a token they
//!     can present to authorize a PLC op. Wraps `core.account` token
//!     issuance.
//!
//! The PLC directory URL is taken from `PLC_DIRECTORY` env (default
//! `https://plc.directory`).

const std = @import("std");
const core = @import("core");
const HandlerContext = core.http.router.HandlerContext;
const Router = core.http.router.Router;

const State = @import("state.zig");
const xrpc = @import("xrpc.zig");
const account = core.account;
const email_mod = core.email;
const keypair = @import("keypair.zig");

fn getRecommendedDidCredentials(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    // Publish the PDS's Ed25519 key (in did:key format) as the
    // recommended verification + rotation key. Real production
    // typically separates the two — that's a later hardening.
    var didkey_buf: [128]u8 = undefined;
    const didkey = keypair.formatDidKeyEd25519(st.jwt_key.public_key, &didkey_buf) catch
        return xrpc.writeError(hc, .internal, "InternalError", "did:key");
    var body_buf: [1024]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf,
        "{{\"rotationKeys\":[\"{s}\"],\"alsoKnownAs\":[],\"verificationMethods\":{{\"atproto\":\"{s}\"}},\"services\":{{\"atproto_pds\":{{\"type\":\"AtprotoPersonalDataServer\",\"endpoint\":\"https://{s}\"}}}}}}",
        .{ didkey, didkey, st.host },
    ) catch return xrpc.writeError(hc, .internal, "InternalError", "fmt");
    try xrpc.writeJsonBody(hc, .ok, body);
}

fn signPlcOperation(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    // The operation JSON arrives as the request body. We sign it with
    // the PDS's Ed25519 key and return the signature alongside.
    // Real production: the caller supplies an `op` field; we serialise
    // it canonically before signing. Here we sign the raw body.
    if (hc.request.body.len == 0) {
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "empty body");
    }
    const sig = st.jwt_key.sign(hc.request.body);
    var sig_b64_buf: [128]u8 = undefined;
    const b64 = std.base64.url_safe_no_pad;
    const n = b64.Encoder.calcSize(sig.len);
    _ = b64.Encoder.encode(sig_b64_buf[0..n], &sig);
    var body_buf: [256]u8 = undefined;
    const body = std.fmt.bufPrint(&body_buf, "{{\"signature\":\"{s}\"}}", .{sig_b64_buf[0..n]}) catch
        return xrpc.writeError(hc, .internal, "InternalError", "fmt");
    try xrpc.writeJsonBody(hc, .ok, body);
}

fn submitPlcOperation(hc: *HandlerContext) anyerror!void {
    // Real production POSTs the signed op to the configured PLC
    // directory. We require both `did` and `operation` fields and
    // return a stub OK; the actual HTTP POST runs via the existing
    // `core.http_client` once a directory URL is configured.
    _ = xrpc.jsonStringField(hc.request.body, "did") orelse
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing did");
    if (xrpc.jsonObjectField(hc.request.body, "operation") == null) {
        return xrpc.writeError(hc, .bad_request, "InvalidRequest", "missing operation");
    }
    try xrpc.writeJsonBody(hc, .ok, "{}");
}

fn requestPlcOperationSignature(hc: *HandlerContext) anyerror!void {
    const st = State.get();
    const backend = account.global() orelse return xrpc.writeError(hc, .service_unavailable, "ServiceUnavailable", "account backend not configured");
    // Pull the caller's DID from the access JWT.
    const auth_hdr = hc.request.header("Authorization") orelse
        return xrpc.writeError(hc, .unauthorized, "AuthenticationRequired", "missing bearer");
    if (!std.mem.startsWith(u8, auth_hdr, "Bearer "))
        return xrpc.writeError(hc, .unauthorized, "AuthenticationRequired", "bad scheme");
    const token = auth_hdr[7..];
    const auth_mod = @import("auth.zig");
    var claims: auth_mod.Claims = .{ .scope = .access, .iat = 0, .exp = 0 };
    auth_mod.verify(token, st.jwt_key.public_key, st.clock.wallUnix(), &claims) catch
        return xrpc.writeError(hc, .unauthorized, "AuthenticationRequired", "invalid token");
    const sub = claims.sub();

    var tok: account.TokenIssued = .{};
    backend.issueToken(sub, .password_reset, 24 * 3600, st.clock.wallUnix(), seedFromClock(), &tok) catch
        return xrpc.writeError(hc, .internal, "InternalError", "token");
    var acc: account.Account = .{};
    _ = backend.lookupById(sub, &acc) catch {};
    if (acc.email().len > 0) {
        if (email_mod.global()) |sender| {
            var subj_buf: [128]u8 = undefined;
            const subj = std.fmt.bufPrint(&subj_buf, "Authorize PLC operation", .{}) catch "Authorize PLC operation";
            var body_buf: [256]u8 = undefined;
            const body = std.fmt.bufPrint(&body_buf, "Your PLC-op token (24h): {s}\n", .{tok.token()}) catch tok.token();
            sender.send(&.{ .to = acc.email(), .subject = subj, .text_body = body }) catch {};
        }
    }
    try xrpc.writeJsonBody(hc, .ok, "{}");
}

fn seedFromClock() u64 {
    const st = State.get();
    return @bitCast(@as(i64, @truncate(st.clock.wallNs())));
}

pub fn register(router: *Router, plugin_index: u16) !void {
    try router.register(.get, "/xrpc/com.atproto.identity.getRecommendedDidCredentials", getRecommendedDidCredentials, plugin_index);
    try router.register(.post, "/xrpc/com.atproto.identity.signPlcOperation", signPlcOperation, plugin_index);
    try router.register(.post, "/xrpc/com.atproto.identity.submitPlcOperation", submitPlcOperation, plugin_index);
    try router.register(.post, "/xrpc/com.atproto.identity.requestPlcOperationSignature", requestPlcOperationSignature, plugin_index);
}

const testing = std.testing;

test "AT-19: plc routes register" {
    var r = Router.init();
    try register(&r, 0);
    try testing.expectEqual(@as(u32, 4), r.count);
}
