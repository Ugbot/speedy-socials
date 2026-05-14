//! Pluggable TLS backend scaffolding.
//!
//! The server doesn't know how — or whether — TLS is implemented. A
//! `TlsBackend` is a tiny vtable: given the raw accepted stream and
//! the `Io` handle, return a wrapped stream the rest of the server
//! treats opaquely. The wrapper performs the handshake on the first
//! read/write.
//!
//! Two backends ship in W1.1:
//!   * `PlainBackend`  — null wrap, returns the raw stream untouched.
//!                       Server.Config defaults to this when no TLS is
//!                       configured at all.
//!   * `StubTlsBackend` — logs a warning that TLS isn't really wired,
//!                       then returns the raw stream. Lets ops scripts
//!                       point at the TLS code path without yet having
//!                       BoringSSL linked in (W1.2 lands the real one).
//!
//! Future backends (BoringSSL in W1.2) implement the same vtable; the
//! call site in `server.zig` is unchanged.
//!
//! Tiger Style: backends never allocate per-connection. State lives on
//! the backend struct itself; the vtable's `wrap_stream` returns by
//! value. If a future backend needs per-connection state, it gets a
//! static pool sized off `limits.max_connections` and indexes into it
//! using the accepted socket fd.

const std = @import("std");
const Io = std.Io;
const net = std.Io.net;
const TlsError = @import("errors.zig").TlsError;

/// Outbound TLS backend (client-side handshake via std.crypto.tls.Client).
/// See `src/core/tls/native_outbound.zig`.
pub const native_outbound = @import("tls/native_outbound.zig");

/// Inbound TLS backend stub. Zig 0.16's stdlib has no server-side TLS;
/// see `src/core/tls/native_inbound.zig` and `tls/README.md`.
pub const native_inbound = @import("tls/native_inbound.zig");

pub const TlsBackend = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Wrap an accepted raw TCP stream and return the post-TLS
        /// stream. Plain backends return the raw stream unchanged.
        /// Real backends perform (or schedule) the TLS handshake here.
        wrap_stream: *const fn (ptr: *anyopaque, io: Io, raw: net.Stream) anyerror!net.Stream,
    };

    pub fn wrapStream(self: TlsBackend, io: Io, raw: net.Stream) anyerror!net.Stream {
        return self.vtable.wrap_stream(self.ptr, io, raw);
    }
};

/// Pass-through backend. Returned `wrap_stream` is the identity
/// function. Useful as the default when the operator runs behind a
/// terminating LB / sidecar and the speedy-socials process speaks
/// plain HTTP on a private network.
pub const PlainBackend = struct {
    pub const vtable: TlsBackend.VTable = .{ .wrap_stream = wrap };

    pub fn backend(self: *PlainBackend) TlsBackend {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn wrap(_: *anyopaque, _: Io, raw: net.Stream) anyerror!net.Stream {
        return raw;
    }
};

/// Placeholder backend that pretends TLS is enabled but is really a
/// pass-through. Emits a single warning log line per process (lazily,
/// the first time `wrap_stream` is called) so it cannot be missed in
/// production logs. Lives here so callers can wire the config flag now
/// without waiting for the BoringSSL backend to land.
pub const StubTlsBackend = struct {
    warned: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    pub const vtable: TlsBackend.VTable = .{ .wrap_stream = wrap };

    pub fn backend(self: *StubTlsBackend) TlsBackend {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn wrap(ptr: *anyopaque, _: Io, raw: net.Stream) anyerror!net.Stream {
        const self: *StubTlsBackend = @ptrCast(@alignCast(ptr));
        if (!self.warned.swap(true, .seq_cst)) {
            std.log.warn("StubTlsBackend in use: TLS is NOT actually performed; " ++
                "connections are plain TCP. Use a real backend (W1.2) before exposing externally.", .{});
        }
        return raw;
    }
};

// ── tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

test {
    // Pull submodule tests into this module's test binary.
    _ = native_outbound;
    _ = native_inbound;
}

test "PlainBackend.wrap_stream is the identity function" {
    var plain: PlainBackend = .{};
    const be = plain.backend();
    // Synthesize a Stream value. We never read/write through it — we
    // only assert the wrap call returns the same bit-pattern back.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    // Construct a Stream from a sentinel handle. `wrap_stream` must
    // return precisely the value passed in.
    const raw: net.Stream = .{ .socket = .{ .handle = -1, .address = undefined } };
    const wrapped = try be.wrapStream(io, raw);
    try testing.expectEqual(@as(std.posix.fd_t, -1), wrapped.socket.handle);
}

test "StubTlsBackend.wrap_stream is also pass-through" {
    var stub: StubTlsBackend = .{};
    const be = stub.backend();
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const raw: net.Stream = .{ .socket = .{ .handle = -2, .address = undefined } };
    const wrapped = try be.wrapStream(io, raw);
    try testing.expectEqual(@as(std.posix.fd_t, -2), wrapped.socket.handle);
    // Second call should still pass through (warning already emitted).
    const wrapped2 = try be.wrapStream(io, raw);
    try testing.expectEqual(@as(std.posix.fd_t, -2), wrapped2.socket.handle);
}

test "TlsBackend vtable dispatch routes through the backend pointer" {
    const Counting = struct {
        calls: u32 = 0,

        const vt: TlsBackend.VTable = .{ .wrap_stream = wrap };

        fn wrap(ptr: *anyopaque, _: Io, raw: net.Stream) anyerror!net.Stream {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.calls += 1;
            return raw;
        }
    };
    var c: Counting = .{};
    const be: TlsBackend = .{ .ptr = &c, .vtable = &Counting.vt };
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const raw: net.Stream = .{ .socket = .{ .handle = @as(std.posix.fd_t, 42), .address = undefined } };
    _ = try be.wrapStream(io, raw);
    _ = try be.wrapStream(io, raw);
    _ = try be.wrapStream(io, raw);
    try testing.expectEqual(@as(u32, 3), c.calls);
}
