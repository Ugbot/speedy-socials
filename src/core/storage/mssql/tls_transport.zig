//! MSSQLTLS: the TDS-wrapped-TLS transport adapter.
//!
//! Microsoft SQL Server negotiates TLS *inside* the TDS Pre-Login phase: the
//! TLS handshake records are not written to the socket raw, but wrapped in
//! TDS packets of type PRELOGIN (0x12) with the normal 8-byte TDS header
//! (the last packet of each flight carrying the EOM status bit). Once the
//! TLS handshake completes the wrapping is dropped — LOGIN7 and every later
//! TDS message then travels *inside* the TLS session as ordinary TLS
//! application records flowing directly over the socket. This module is the
//! "TDS-wrapped TLS handshake" bridge.
//!
//! ── How it plugs into the stdlib TLS client ──────────────────────────────
//!
//! `std.crypto.tls.Client.init(input: *Io.Reader, output: *Io.Writer, opts)`
//! drives the whole handshake synchronously against a Reader/Writer pair and
//! then exposes `client.reader`/`client.writer` for the encrypted side. We
//! give it a Reader/Writer pair backed by *this* transport. While
//! `phase == .handshake`:
//!   * Writer flush  → accumulated TLS bytes are framed into 0x12 packets
//!                      (see `tds.frameTlsHandshake`) and sent on the fd.
//!   * Reader stream → a full TDS message is read off the fd and de-framed
//!                      (see `tds.dechunkTlsHandshake`); its payload (the raw
//!                      TLS handshake bytes) is served to the TLS client.
//! Immediately after `init` returns we flip `phase = .application`; from then
//! on drain/flush/stream are a straight passthrough to the socket, because
//! TLS records are no longer TDS-wrapped.
//!
//! The framing/de-framing logic is the PURE, unit-tested `tds.frameTls*` /
//! `tds.dechunkTls*` pair; this file is the thin stateful I/O wrapper around
//! them, mirroring how `conn.zig` wraps the pure packet codec.
//!
//! ⚠️ LIVE VALIDATION PENDING A RUNNABLE SQL SERVER. The frame/dechunk logic
//! and the phase-boundary bookkeeping are unit-tested (see `tds_test.zig`);
//! the socket round-trip cannot run on this arm64 host. The pure framing is
//! exercised with byte fixtures so the wire format is verified regardless.
//!
//! Tiger Style: fixed per-transport buffers (no hot-path allocation); every
//! length is explicit and bounds-checked; the socket fd is borrowed (the
//! owning `Conn` closes it).

const std = @import("std");
const tds = @import("tds.zig");
const Io = std.Io;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

pub const Error = error{
    WriteFailed,
    ReadFailed,
    Closed,
    BufferTooSmall,
    HandshakeFraming,
};

/// Reader/Writer buffers must clear the stdlib TLS minimum (max ciphertext
/// record length, ~16.5 KiB). We size generously and assert at init.
pub const tls_min: usize = std.crypto.tls.max_ciphertext_record_len;

/// Staging buffer for one in-flight TDS-framed handshake message. A TLS
/// flight can span several records; a generous cap keeps reassembly bounded
/// without heap. 64 KiB comfortably holds a ServerHello + Certificate +
/// CertificateVerify + Finished flight across its 0x12 packets.
pub const stage_cap: usize = 64 * 1024;

pub const Phase = enum(u8) { handshake, application };

/// A socket-backed transport that frames the TLS handshake in TDS 0x12
/// packets, then passes TLS records straight through after the handshake.
/// The struct is self-referential (the embedded `Io.Reader`/`Io.Writer`
/// carry pointers back into it via the vtable `@fieldParentPtr`), so it must
/// not be copied after `init`.
pub const TdsTlsTransport = struct {
    fd: c_int,
    phase: Phase = .handshake,
    packet_size: u32 = tds.default_packet_size,
    /// Per-message PacketID counter for outbound 0x12 frames.
    out_packet_id: u8 = 0,

    // ── Io.Reader plumbing ────────────────────────────────────────────────
    reader: Reader = undefined,
    reader_buf: [tls_min]u8 = undefined,

    // ── Io.Writer plumbing ────────────────────────────────────────────────
    writer: Writer = undefined,
    writer_buf: [tls_min]u8 = undefined,

    // ── TLS client's own plaintext-side buffers ───────────────────────────
    // Passed to `std.crypto.tls.Client.init` as `read_buffer`/`write_buffer`.
    // They must be distinct from `reader_buf`/`writer_buf` (which carry the
    // ciphertext side) and at least `tls_min` long.
    read_buf_app: [tls_min]u8 = undefined,
    writer_buf_app: [tls_min]u8 = undefined,

    // ── Handshake framing scratch ─────────────────────────────────────────
    /// Holds de-framed handshake payload bytes not yet served to the TLS
    /// client (`stage[stage_seek..stage_len]` are pending).
    stage: [stage_cap]u8 = undefined,
    stage_len: usize = 0,
    stage_seek: usize = 0,
    /// Raw socket bytes read while a TDS message is still incomplete (the
    /// tail past the last whole packet boundary is preserved here).
    framed: [stage_cap]u8 = undefined,
    framed_len: usize = 0,
    /// One TDS packet's worth of socket bytes per read syscall.
    rxbuf: [stage_cap]u8 = undefined,

    const ReaderVTable = Reader.VTable{
        .stream = readerStream,
    };
    const WriterVTable = Writer.VTable{
        .drain = writerDrain,
        .flush = writerFlush,
    };

    /// Initialise the embedded Reader/Writer over `fd`. The transport begins
    /// in the handshake phase. `packet_size` controls outbound 0x12 chunking.
    pub fn init(self: *TdsTlsTransport, fd: c_int, packet_size: u32) void {
        std.debug.assert(packet_size > tds.header_len);
        std.debug.assert(self.reader_buf.len >= tls_min);
        std.debug.assert(self.writer_buf.len >= tls_min);
        self.fd = fd;
        self.phase = .handshake;
        self.packet_size = packet_size;
        self.out_packet_id = 0;
        self.stage_len = 0;
        self.stage_seek = 0;
        self.framed_len = 0;
        self.reader = .{
            .vtable = &ReaderVTable,
            .buffer = &self.reader_buf,
            .seek = 0,
            .end = 0,
        };
        self.writer = .{
            .vtable = &WriterVTable,
            .buffer = &self.writer_buf,
            .end = 0,
        };
    }

    /// Flip to the application phase. Called by `conn.zig` once
    /// `std.crypto.tls.Client.init` returns, after which TLS records flow
    /// over the socket without TDS wrapping.
    pub fn finishHandshake(self: *TdsTlsTransport) void {
        self.phase = .application;
    }

    // ── raw socket helpers ────────────────────────────────────────────────

    fn rawWriteAll(self: *TdsTlsTransport, bytes: []const u8) Error!void {
        var off: usize = 0;
        while (off < bytes.len) {
            const n = std.c.write(self.fd, bytes.ptr + off, bytes.len - off);
            if (n <= 0) return error.WriteFailed;
            off += @intCast(n);
        }
    }

    /// One read syscall into `dst`; 0 bytes means the peer closed.
    fn rawReadSome(self: *TdsTlsTransport, dst: []u8) Error!usize {
        const n = std.c.read(self.fd, dst.ptr, dst.len);
        if (n == 0) return error.Closed;
        if (n < 0) return error.ReadFailed;
        return @intCast(n);
    }

    // ── Writer vtable ─────────────────────────────────────────────────────

    /// Send `payload` to the socket according to the current phase: framed in
    /// TDS 0x12 packets during the handshake, raw afterwards. A zero-length
    /// payload during application phase is a no-op; during handshake it still
    /// emits one empty EOM packet (mirrors `frameTlsHandshake`).
    fn sendPayload(self: *TdsTlsTransport, payload: []const u8) Error!void {
        switch (self.phase) {
            .handshake => {
                // Frame into one or more 0x12 packets. Worst case the framed
                // size is payload + a header per chunk; bound it in `rxbuf`.
                const cap = tds.tlsChunkPayloadCap(self.packet_size);
                var off: usize = 0;
                // Emit at least one packet (handles empty payload).
                while (true) {
                    const remaining = payload.len - off;
                    const chunk = @min(remaining, cap);
                    var hdr: [tds.header_len]u8 = undefined;
                    const is_last = (off + chunk) >= payload.len;
                    const total: u16 = @intCast(tds.header_len + chunk);
                    const status: u8 = if (is_last) tds.status_eom else tds.status_normal;
                    _ = tds.writeHeader(&hdr, .pre_login, status, total, self.out_packet_id) catch
                        return error.HandshakeFraming;
                    try self.rawWriteAll(&hdr);
                    if (chunk > 0) try self.rawWriteAll(payload[off .. off + chunk]);
                    self.out_packet_id +%= 1;
                    off += chunk;
                    if (is_last) break;
                }
            },
            .application => {
                if (payload.len > 0) try self.rawWriteAll(payload);
            },
        }
    }

    fn writerDrain(w: *Writer, data: []const []const u8, splat: usize) Writer.Error!usize {
        const self: *TdsTlsTransport = @fieldParentPtr("writer", w);
        // First flush any buffered bytes, then each data slice. We treat the
        // whole drain as one logical payload per phase rule by sending the
        // buffer then the slices; this preserves byte order on the wire.
        if (w.end > 0) {
            self.sendPayload(w.buffer[0..w.end]) catch return error.WriteFailed;
            w.end = 0;
        }
        var consumed: usize = 0;
        if (data.len > 0) {
            for (data[0 .. data.len - 1]) |slice| {
                if (slice.len > 0) self.sendPayload(slice) catch return error.WriteFailed;
                consumed += slice.len;
            }
            const last = data[data.len - 1];
            var s: usize = 0;
            while (s < splat) : (s += 1) {
                if (last.len > 0) self.sendPayload(last) catch return error.WriteFailed;
                consumed += last.len;
            }
        }
        return consumed;
    }

    fn writerFlush(w: *Writer) Writer.Error!void {
        const self: *TdsTlsTransport = @fieldParentPtr("writer", w);
        if (w.end > 0) {
            self.sendPayload(w.buffer[0..w.end]) catch return error.WriteFailed;
            w.end = 0;
        } else if (self.phase == .handshake) {
            // A handshake flush with nothing buffered would otherwise emit no
            // packet. The stdlib TLS client always flushes after writing the
            // ClientHello/Finished (non-empty), so an empty flush here means
            // "nothing to send" — do not emit a spurious empty 0x12 packet.
        }
    }

    // ── Reader vtable ─────────────────────────────────────────────────────

    /// Ensure `stage[stage_seek..stage_len]` holds at least some pending
    /// handshake bytes, reading and de-framing TDS 0x12 messages off the
    /// socket as needed. Returns false only on clean EOF with nothing staged.
    fn ensureStaged(self: *TdsTlsTransport) Error!bool {
        if (self.stage_seek < self.stage_len) return true;
        // Reset the stage; assemble one full TDS message (EOM-terminated).
        self.stage_seek = 0;
        self.stage_len = 0;
        while (true) {
            const dc = tds.dechunkTlsHandshake(&self.stage, self.framed[0..self.framed_len]) catch
                return error.HandshakeFraming;
            if (dc.complete) {
                // Preserve any bytes past this message for the next call.
                const tail = self.framed_len - dc.consumed;
                if (tail > 0) std.mem.copyForwards(u8, self.framed[0..tail], self.framed[dc.consumed..self.framed_len]);
                self.framed_len = tail;
                self.stage_len = dc.payload_len;
                self.stage_seek = 0;
                // An empty (zero-payload) message carries no handshake bytes;
                // keep assembling until we have something to serve.
                if (self.stage_len > 0) return true;
                if (self.framed_len == 0) {
                    // Need more socket bytes for the next message.
                    const got = try self.rawReadSome(self.rxbuf[0..self.framed.len]);
                    @memcpy(self.framed[0..got], self.rxbuf[0..got]);
                    self.framed_len = got;
                }
                continue;
            }
            // Need more socket bytes to complete the message.
            if (self.framed_len >= self.framed.len) return error.BufferTooSmall;
            const got = try self.rawReadSome(self.rxbuf[0 .. self.framed.len - self.framed_len]);
            @memcpy(self.framed[self.framed_len .. self.framed_len + got], self.rxbuf[0..got]);
            self.framed_len += got;
        }
    }

    fn readerStream(r: *Reader, w: *Writer, limit: Io.Limit) Reader.StreamError!usize {
        const self: *TdsTlsTransport = @fieldParentPtr("reader", r);
        switch (self.phase) {
            .handshake => {
                if (!(self.ensureStaged() catch |e| return mapReadErr(e))) return error.EndOfStream;
                const avail = self.stage[self.stage_seek..self.stage_len];
                const n = limit.slice(avail);
                if (n.len == 0) return 0;
                const wrote = w.write(n) catch return error.WriteFailed;
                self.stage_seek += wrote;
                return wrote;
            },
            .application => {
                // Pass through: one raw socket read into the writer's buffer.
                const dst = limit.slice(self.rxbuf[0..]);
                if (dst.len == 0) return 0;
                const got = self.rawReadSome(dst) catch |e| switch (e) {
                    error.Closed => return error.EndOfStream,
                    else => return mapReadErr(e),
                };
                const wrote = w.write(self.rxbuf[0..got]) catch return error.WriteFailed;
                return wrote;
            },
        }
    }

    fn mapReadErr(e: Error) Reader.StreamError {
        return switch (e) {
            error.Closed => error.EndOfStream,
            else => error.ReadFailed,
        };
    }
};

// ─────────────────────────────────────────────────────────────────────────
// Tests — the phase bookkeeping + the framing seam, exercised with byte
// fixtures and a socketpair so no SQL Server is required.
// ─────────────────────────────────────────────────────────────────────────

const testing = std.testing;

// `socketpair` is not surfaced by this toolchain's stripped `std.c`; declare
// the libc symbol directly so the loopback transport tests can run.
extern "c" fn socketpair(domain: c_int, sock_type: c_int, protocol: c_int, sv: *[2]c_int) c_int;

fn makeSocketPair() ?[2]c_int {
    var fds: [2]c_int = undefined;
    const rc = socketpair(std.c.AF.UNIX, std.c.SOCK.STREAM, 0, &fds);
    if (rc != 0) return null;
    return fds;
}

test "TdsTlsTransport: init starts in handshake phase with reset scratch" {
    var t: TdsTlsTransport = undefined;
    t.init(7, tds.default_packet_size);
    try testing.expectEqual(Phase.handshake, t.phase);
    try testing.expectEqual(@as(usize, 0), t.stage_len);
    try testing.expectEqual(@as(usize, 0), t.framed_len);
    try testing.expectEqual(@as(c_int, 7), t.fd);
    try testing.expect(t.reader.buffer.len >= tls_min);
    try testing.expect(t.writer.buffer.len >= tls_min);
    t.finishHandshake();
    try testing.expectEqual(Phase.application, t.phase);
}

test "TdsTlsTransport: handshake write frames into 0x12 then reads de-frame (socketpair)" {
    // A connected socketpair lets us drive the real drain/flush + stream
    // paths without a SQL Server: we write a handshake flight through the
    // transport, then read it back off the raw peer fd and confirm it is
    // TDS-0x12-framed; and we feed a TDS-framed reply into the peer and
    // confirm the transport de-frames it to the original bytes.
    const fds = makeSocketPair() orelse return error.SkipZigTest;
    defer _ = std.c.close(fds[0]);
    defer _ = std.c.close(fds[1]);

    var t: TdsTlsTransport = undefined;
    t.init(fds[0], tds.default_packet_size);

    // Randomized handshake-flight bytes (no hardcoded happy path).
    var prng = std.Random.DefaultPrng.init(0x7D5_71_5);
    const rand = prng.random();
    var flight: [600]u8 = undefined;
    rand.bytes(&flight);

    // Write through the transport (buffered) then flush → frames + sends.
    try t.writer.writeAll(&flight);
    try t.writer.flush();

    // Read the framed bytes off the peer fd and de-frame with the pure codec.
    var raw: [2048]u8 = undefined;
    var got: usize = 0;
    // The flight (600B) fits in one default packet, so expect a single EOM
    // packet of header_len + 600 bytes.
    const want = tds.header_len + flight.len;
    while (got < want) {
        const n = std.c.read(fds[1], raw[got..].ptr, raw.len - got);
        if (n <= 0) break;
        got += @intCast(n);
    }
    try testing.expectEqual(want, got);
    var out: [2048]u8 = undefined;
    const dc = try tds.dechunkTlsHandshake(&out, raw[0..got]);
    try testing.expect(dc.complete);
    try testing.expectEqual(flight.len, dc.payload_len);
    try testing.expectEqualSlices(u8, &flight, out[0..dc.payload_len]);

    // Now the reverse: frame a reply, push it into the peer, read via stream.
    var reply: [400]u8 = undefined;
    rand.bytes(&reply);
    var framed: [2048]u8 = undefined;
    const fn_len = try tds.frameTlsHandshake(&framed, &reply, tds.default_packet_size, 0);
    try writeAllFd(fds[1], framed[0..fn_len]);

    var recv: [400]u8 = undefined;
    try t.reader.readSliceAll(&recv);
    try testing.expectEqualSlices(u8, &reply, &recv);
}

test "TdsTlsTransport: multi-packet handshake flight chunks and reassembles" {
    const fds = makeSocketPair() orelse return error.SkipZigTest;
    defer _ = std.c.close(fds[0]);
    defer _ = std.c.close(fds[1]);

    var t: TdsTlsTransport = undefined;
    // Tiny packet size so a modest flight spans many 0x12 packets.
    const small_pkt: u32 = tds.header_len + 16;
    t.init(fds[0], small_pkt);

    var prng = std.Random.DefaultPrng.init(0xC0FFEE);
    const rand = prng.random();
    var flight: [200]u8 = undefined;
    rand.bytes(&flight);

    try t.writer.writeAll(&flight);
    try t.writer.flush();

    var raw: [4096]u8 = undefined;
    var got: usize = 0;
    // 200 bytes / 16-per-packet = 13 packets (last is 8 bytes) → 13*8 hdrs.
    const n_chunks = (flight.len + 15) / 16;
    const want = flight.len + n_chunks * tds.header_len;
    while (got < want) {
        const n = std.c.read(fds[1], raw[got..].ptr, raw.len - got);
        if (n <= 0) break;
        got += @intCast(n);
    }
    try testing.expectEqual(want, got);
    var out: [512]u8 = undefined;
    const dc = try tds.dechunkTlsHandshake(&out, raw[0..got]);
    try testing.expect(dc.complete);
    try testing.expectEqualSlices(u8, &flight, out[0..dc.payload_len]);
}

fn writeAllFd(fd: c_int, bytes: []const u8) !void {
    var off: usize = 0;
    while (off < bytes.len) {
        const n = std.c.write(fd, bytes.ptr + off, bytes.len - off);
        if (n <= 0) return error.WriteFailed;
        off += @intCast(n);
    }
}
