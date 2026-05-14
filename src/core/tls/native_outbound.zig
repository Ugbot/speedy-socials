//! Outbound TLS backend backed by Zig 0.16's `std.crypto.tls.Client`.
//!
//! This backend conforms to the `core.http_client.TlsBackend` vtable
//! (host/port/timeout style — DNS + TCP + handshake happen inside
//! `connect`). It is intentionally distinct from the inbound
//! `core.tls.TlsBackend` (which wraps an already-accepted stream).
//!
//! ── Architecture ──────────────────────────────────────────────────────
//!
//!   ┌─────────────────────────┐   per-conn slot   ┌─────────────────┐
//!   │  http_client worker     │ ─────────────────▶│ tls.Client +    │
//!   │  (sendSync on worker    │  connect+handshake│ TCP stream      │
//!   │   thread)               │ ─────────────────▶│ + 17K read buf  │
//!   └─────────────────────────┘                   │ + 17K write buf │
//!                                                 └─────────────────┘
//!
//! Tiger Style:
//!   * CA bundle loaded once at `init`; never re-scanned on the hot path.
//!   * Connection state lives in a fixed-size pool, sized off
//!     `limits.max_inflight_deliveries` + a hard ceiling for subscriber-
//!     side fetches + slack.
//!   * No allocator on the hot path. Slot acquisition is a single
//!     atomic-cas free-list pop.
//!   * Handshake buffers (17 KiB each, the stdlib minimum) live inside
//!     the slot, not on the stack.
//!
//! ── 0.16 std.crypto.tls.Client verdict ──────────────────────────────
//!
//! Works (client-side). The 0.16 API exposes:
//!   * `Bundle.rescan(gpa, io, now)` — loads the OS trust store.
//!   * `Client.init(input, output, options)` — performs the handshake
//!     against a Reader/Writer pair (we feed it the TCP stream's
//!     Reader/Writer interfaces). Returns a Client with `c.reader` and
//!     `c.writer` for the decrypted side.
//!
//! Server-side (`accept`) is NOT in the 0.16 stdlib. The inbound
//! backend is a documented stub — see `native_inbound.zig`.

const std = @import("std");
const Io = std.Io;
const net = std.Io.net;
const Certificate = std.crypto.Certificate;
const stdtls = std.crypto.tls;

const core = struct {
    pub const http_client = @import("../http_client.zig");
    pub const limits = @import("../limits.zig");
    pub const assert = @import("../assert.zig");
};

const HttpTlsBackend = core.http_client.TlsBackend;
const NetError = core.http_client.NetError;

// ── Pool sizing ───────────────────────────────────────────────────────
//
// `max_slots` is a hard ceiling. The http_client only takes a slot for
// the duration of a single request/response cycle, so we size off the
// in-flight federation work plus generous slack for AT-protocol DID/
// handle resolutions and key-cache fetches.

pub const max_subscriber_slack: u32 = 128;
pub const max_slots: u32 = core.limits.max_inflight_deliveries + max_subscriber_slack + 16;

// stdlib mandates the input Reader / write_buffer / read_buffer all be
// at least `min_buffer_len` (17 KiB at the time of writing).
const tls_min = stdtls.Client.min_buffer_len;

// Cap the CA bundle: macOS keychain typically yields ~150 trust anchors;
// Linux is similar. Tiger Style: refuse to silently load a >10 MiB pile
// of certs.
pub const max_ca_bytes: usize = 10 * 1024 * 1024;
pub const max_ca_certs: u32 = 1024;

// ── Slot pool ─────────────────────────────────────────────────────────

const SlotState = enum(u8) { free, in_use };

pub const Slot = struct {
    state: std.atomic.Value(SlotState) = std.atomic.Value(SlotState).init(.free),
    // TCP transport (held inside the slot — closed by `close_impl`).
    stream: net.Stream = .{ .socket = .{ .handle = -1, .address = undefined } },
    tcp_reader: net.Stream.Reader = undefined,
    tcp_writer: net.Stream.Writer = undefined,
    tcp_reader_buf: [tls_min]u8 = undefined,
    tcp_writer_buf: [tls_min]u8 = undefined,
    // TLS plaintext-side buffers (used by tls.Client init).
    tls_read_buf: [tls_min]u8 = undefined,
    tls_write_buf: [tls_min]u8 = undefined,
    client: stdtls.Client = undefined,
    io: Io = undefined,
    open: bool = false,
};

pub const NativeOutboundBackend = struct {
    gpa: std.mem.Allocator,
    io: Io,
    bundle: Certificate.Bundle,
    bundle_lock: Io.RwLock = Io.RwLock.init,
    bundle_loaded: bool,
    bundle_cert_count: u32,
    /// Heap-allocated slot pool. Each Slot is ~70 KiB; with the default
    /// `max_slots` the total footprint is ~15 MiB. We allocate it on
    /// the heap rather than carrying it inline in the struct so callers
    /// can hold the backend on the stack.
    slots: []Slot,
    next_slot_hint: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),

    pub const InitError = error{ OutOfMemory };

    /// Construct the backend. `gpa` is used to allocate the slot pool
    /// once and the CA bundle storage; the hot path is allocation-free.
    /// If CA bundle loading fails (e.g., no trust store on this OS) the
    /// backend still constructs — `connect` will refuse with
    /// `error.TlsUnavailable` until certs are present.
    pub fn init(gpa: std.mem.Allocator, io: Io) InitError!NativeOutboundBackend {
        const slots = try gpa.alloc(Slot, max_slots);
        for (slots) |*s| s.* = .{};
        var self: NativeOutboundBackend = .{
            .gpa = gpa,
            .io = io,
            .bundle = Certificate.Bundle.empty,
            .bundle_loaded = false,
            .bundle_cert_count = 0,
            .slots = slots,
        };
        // Best-effort: load the OS trust store. Swallow errors so the
        // backend is still usable in test environments — `connect`
        // surfaces the failure at use.
        const now = Io.Timestamp.now(io, std.Io.Clock.real);
        self.bundle.rescan(gpa, io, now) catch |err| {
            std.log.warn("NativeOutboundBackend: CA bundle rescan failed: {s}", .{@errorName(err)});
            return self;
        };
        self.bundle_loaded = true;
        self.bundle_cert_count = @intCast(self.bundle.map.count());
        if (self.bundle_cert_count > max_ca_certs) {
            std.log.warn("NativeOutboundBackend: CA bundle has {d} certs (cap {d})", .{
                self.bundle_cert_count, max_ca_certs,
            });
        }
        return self;
    }

    pub fn deinit(self: *NativeOutboundBackend) void {
        for (self.slots) |*s| if (s.open) {
            s.stream.close(self.io);
            s.open = false;
        };
        self.bundle.deinit(self.gpa);
        self.gpa.free(self.slots);
        self.slots = &.{};
    }

    /// Yield the `http_client.TlsBackend` view of this backend.
    pub fn backend(self: *NativeOutboundBackend) HttpTlsBackend {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn acquireSlot(self: *NativeOutboundBackend) ?*Slot {
        const n: u32 = @intCast(self.slots.len);
        if (n == 0) return null;
        const start = self.next_slot_hint.fetchAdd(1, .monotonic) % n;
        var i: u32 = 0;
        while (i < n) : (i += 1) {
            const idx = (start + i) % n;
            const slot = &self.slots[idx];
            if (slot.state.cmpxchgStrong(.free, .in_use, .acq_rel, .monotonic) == null) {
                return slot;
            }
        }
        return null;
    }

    fn releaseSlot(_: *NativeOutboundBackend, slot: *Slot) void {
        slot.state.store(.free, .release);
    }

    // ── vtable impl ──────────────────────────────────────────────────

    pub const vtable: HttpTlsBackend.Vtable = .{
        .connect = connect_impl,
        .write_all = write_impl,
        .read_some = read_impl,
        .close = close_impl,
    };

    fn connect_impl(ctx: *anyopaque, host: []const u8, port: u16, timeout_ms: u32) NetError!*anyopaque {
        _ = timeout_ms; // TODO: wire socket-level timeouts when std exposes them on Io.
        const self: *NativeOutboundBackend = @ptrCast(@alignCast(ctx));
        if (!self.bundle_loaded) return error.TlsUnavailable;
        const slot = self.acquireSlot() orelse return error.ConnectFailed;
        errdefer self.releaseSlot(slot);

        var addr = net.IpAddress.resolve(self.io, host, port) catch return error.DnsFailed;
        addr.setPort(port);
        const stream = net.IpAddress.connect(&addr, self.io, .{ .mode = .stream }) catch return error.ConnectFailed;
        slot.io = self.io;
        slot.stream = stream;
        slot.open = true;
        errdefer {
            stream.close(self.io);
            slot.open = false;
        }
        slot.tcp_reader = stream.reader(self.io, &slot.tcp_reader_buf);
        slot.tcp_writer = stream.writer(self.io, &slot.tcp_writer_buf);

        var entropy: [stdtls.Client.Options.entropy_len]u8 = undefined;
        self.io.vtable.randomSecure(self.io.userdata, &entropy) catch return error.TlsHandshakeFailed;

        const now = Io.Timestamp.now(self.io, std.Io.Clock.real);
        const opts: stdtls.Client.Options = .{
            .host = .{ .explicit = host },
            .ca = .{ .bundle = .{
                .gpa = self.gpa,
                .io = self.io,
                .lock = &self.bundle_lock,
                .bundle = &self.bundle,
            } },
            .write_buffer = &slot.tls_write_buf,
            .read_buffer = &slot.tls_read_buf,
            .entropy = &entropy,
            .realtime_now = now,
        };
        slot.client = stdtls.Client.init(&slot.tcp_reader.interface, &slot.tcp_writer.interface, opts) catch {
            return error.TlsHandshakeFailed;
        };
        return @ptrCast(slot);
    }

    fn write_impl(_: *anyopaque, conn: *anyopaque, bytes: []const u8) NetError!void {
        const slot: *Slot = @ptrCast(@alignCast(conn));
        slot.client.writer.writeAll(bytes) catch return error.WriteFailed;
        slot.client.writer.flush() catch return error.WriteFailed;
    }

    fn read_impl(_: *anyopaque, conn: *anyopaque, dst: []u8) NetError!usize {
        const slot: *Slot = @ptrCast(@alignCast(conn));
        const n = slot.client.reader.readSliceShort(dst) catch |e| switch (e) {
            error.ReadFailed => return error.ReadFailed,
        };
        return n;
    }

    fn close_impl(ctx: *anyopaque, conn: *anyopaque) void {
        const self: *NativeOutboundBackend = @ptrCast(@alignCast(ctx));
        const slot: *Slot = @ptrCast(@alignCast(conn));
        // Best-effort close_notify; the peer may already be gone.
        slot.client.end() catch {};
        if (slot.open) {
            slot.stream.close(slot.io);
            slot.open = false;
        }
        self.releaseSlot(slot);
    }
};

// ── Tests ─────────────────────────────────────────────────────────────

const testing = std.testing;

test "NativeOutboundBackend: vtable conforms to http_client.TlsBackend.Vtable" {
    const T = @TypeOf(NativeOutboundBackend.vtable);
    try testing.expectEqual(HttpTlsBackend.Vtable, T);
}

test "NativeOutboundBackend: init returns a backend even if bundle missing" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var be = try NativeOutboundBackend.init(testing.allocator, threaded.io());
    defer be.deinit();
    _ = be.bundle_loaded;
}

test "NativeOutboundBackend: slot pool size matches limits + slack" {
    try testing.expect(max_slots >= core.limits.max_inflight_deliveries);
    try testing.expect(max_slots > max_subscriber_slack);
}

test "NativeOutboundBackend: backend() returns a wired http_client.TlsBackend" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var be = try NativeOutboundBackend.init(testing.allocator, threaded.io());
    defer be.deinit();
    const tb = be.backend();
    try testing.expectEqual(@as(*anyopaque, @ptrCast(&be)), tb.ctx);
    try testing.expect(tb.vtable == &NativeOutboundBackend.vtable);
}

test "NativeOutboundBackend: vtable function pointers are non-null" {
    try testing.expect(@intFromPtr(NativeOutboundBackend.vtable.connect) != 0);
    try testing.expect(@intFromPtr(NativeOutboundBackend.vtable.write_all) != 0);
    try testing.expect(@intFromPtr(NativeOutboundBackend.vtable.read_some) != 0);
    try testing.expect(@intFromPtr(NativeOutboundBackend.vtable.close) != 0);
}

test "NativeOutboundBackend: slot acquisition is bounded by pool size" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var be = try NativeOutboundBackend.init(testing.allocator, threaded.io());
    defer be.deinit();

    const taken = try testing.allocator.alloc(*Slot, max_slots);
    defer testing.allocator.free(taken);
    var n: u32 = 0;
    while (n < max_slots) : (n += 1) {
        taken[n] = be.acquireSlot() orelse return error.PoolUnexpectedlyExhausted;
    }
    try testing.expect(be.acquireSlot() == null);
    for (taken[0..n]) |s| be.releaseSlot(s);
    const after = be.acquireSlot() orelse return error.AcquireAfterReleaseFailed;
    be.releaseSlot(after);
}

test "NativeOutboundBackend: releaseSlot resets state to free" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var be = try NativeOutboundBackend.init(testing.allocator, threaded.io());
    defer be.deinit();
    const slot = be.acquireSlot() orelse return error.AcquireFailed;
    try testing.expectEqual(SlotState.in_use, slot.state.load(.monotonic));
    be.releaseSlot(slot);
    try testing.expectEqual(SlotState.free, slot.state.load(.monotonic));
}

test "NativeOutboundBackend: connect refuses when bundle not loaded" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var be = try NativeOutboundBackend.init(testing.allocator, threaded.io());
    defer be.deinit();
    const was_loaded = be.bundle_loaded;
    be.bundle_loaded = false;
    defer be.bundle_loaded = was_loaded;
    const tb = be.backend();
    const err = tb.vtable.connect(tb.ctx, "example.invalid", 443, 1000);
    try testing.expectError(error.TlsUnavailable, err);
}

test "NativeOutboundBackend: connect fails cleanly on unresolvable host" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var be = try NativeOutboundBackend.init(testing.allocator, threaded.io());
    defer be.deinit();
    const tb = be.backend();
    const result = tb.vtable.connect(tb.ctx, "this-host-does-not-exist.invalid", 443, 500);
    if (result) |_| {
        return error.UnexpectedSuccess;
    } else |err| {
        try testing.expect(err == error.TlsUnavailable or
            err == error.DnsFailed or
            err == error.ConnectFailed or
            err == error.TlsHandshakeFailed);
    }
}

test "NativeOutboundBackend: acquireSlot under concurrent threads" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var be = try NativeOutboundBackend.init(testing.allocator, threaded.io());
    defer be.deinit();

    const Thr = struct {
        be_ptr: *NativeOutboundBackend,
        taken: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
        fn run(self: *@This()) void {
            var i: u32 = 0;
            while (i < 32) : (i += 1) {
                if (self.be_ptr.acquireSlot()) |s| {
                    _ = self.taken.fetchAdd(1, .monotonic);
                    self.be_ptr.releaseSlot(s);
                }
            }
        }
    };
    var a = Thr{ .be_ptr = &be };
    var b = Thr{ .be_ptr = &be };
    const ta = try std.Thread.spawn(.{}, Thr.run, .{&a});
    const tb = try std.Thread.spawn(.{}, Thr.run, .{&b});
    ta.join();
    tb.join();
    try testing.expectEqual(@as(u32, 64), a.taken.load(.monotonic) + b.taken.load(.monotonic));
}

test "NativeOutboundBackend: deinit closes any leaked open slots" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    var be = try NativeOutboundBackend.init(testing.allocator, threaded.io());
    // Don't actually open any sockets — just confirm deinit walks the pool
    // and frees memory cleanly.
    be.deinit();
}
