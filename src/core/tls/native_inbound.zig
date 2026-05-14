//! Inbound TLS server (server-side handshake).
//!
//! **Status: STUB.** Zig 0.16's `std.crypto.tls` ships only the client
//! side; there is no `tls.Server.init` in 0.16's stdlib. This module is
//! a scaffold so callers can wire `core.tls.TlsBackend` against a future
//! real implementation without churn.
//!
//! When implemented, this struct will provide:
//!   * `acceptTls(io, raw_stream) !Stream` — perform server-side TLS
//!     handshake against the accepted raw TCP stream.
//!   * Certificate + private key loading (PEM or PKCS#12 in-memory).
//!   * SNI fan-out so multiple hostnames can be served on one listener.
//!   * ALPN advertisement (`h2`, `http/1.1`).
//!
//! Until the std API matures (or the BoringSSL backend lands), use a
//! terminating LB / sidecar (Caddy, nginx) in front of speedy-socials,
//! and run the process itself on plain HTTP behind it. The
//! `PlainBackend` in `core.tls` is the production-safe default for that
//! deployment shape.
//!
//! See `README.md` for the BoringSSL replacement path.

const std = @import("std");
const Io = std.Io;
const net = std.Io.net;

const core_tls = @import("../tls.zig");
const TlsBackend = core_tls.TlsBackend;

/// Reason `wrap_stream` always fails today. Surfaced so callers can
/// pattern-match on the error and produce a clear operator message
/// instead of an opaque `error.Unexpected`.
pub const NotImplementedError = error{TlsServerNotImplementedInThisZig};

pub const NativeInboundBackend = struct {
    /// Latched the first time `wrap_stream` is called so we don't spam
    /// the log on every accept.
    warned: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    pub fn init() NativeInboundBackend {
        return .{};
    }

    pub fn deinit(_: *NativeInboundBackend) void {}

    pub fn backend(self: *NativeInboundBackend) TlsBackend {
        return .{ .ptr = self, .vtable = &vtable };
    }

    pub const vtable: TlsBackend.VTable = .{ .wrap_stream = wrap };

    fn wrap(ptr: *anyopaque, _: Io, raw: net.Stream) anyerror!net.Stream {
        const self: *NativeInboundBackend = @ptrCast(@alignCast(ptr));
        if (!self.warned.swap(true, .seq_cst)) {
            std.log.warn("NativeInboundBackend: server-side TLS is NOT implemented in Zig 0.16 stdlib; " ++
                "use a terminating proxy or wait for the BoringSSL backend.", .{});
        }
        _ = raw;
        return error.TlsServerNotImplementedInThisZig;
    }
};

// ── Tests ─────────────────────────────────────────────────────────────

const testing = std.testing;

test "NativeInboundBackend: init/deinit round-trip" {
    var be = NativeInboundBackend.init();
    defer be.deinit();
    _ = be.backend();
}

test "NativeInboundBackend: vtable conforms to core.tls.TlsBackend.VTable" {
    try testing.expectEqual(TlsBackend.VTable, @TypeOf(NativeInboundBackend.vtable));
}

test "NativeInboundBackend: wrap_stream returns TlsServerNotImplementedInThisZig" {
    var be = NativeInboundBackend.init();
    defer be.deinit();
    const tb = be.backend();
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const raw: net.Stream = .{ .socket = .{ .handle = -1, .address = undefined } };
    try testing.expectError(error.TlsServerNotImplementedInThisZig, tb.wrapStream(io, raw));
}

test "NativeInboundBackend: warning is latched (single emission)" {
    var be = NativeInboundBackend.init();
    defer be.deinit();
    const tb = be.backend();
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const raw: net.Stream = .{ .socket = .{ .handle = -1, .address = undefined } };
    _ = tb.wrapStream(io, raw) catch {};
    try testing.expect(be.warned.load(.seq_cst));
    _ = tb.wrapStream(io, raw) catch {};
    try testing.expect(be.warned.load(.seq_cst));
}
