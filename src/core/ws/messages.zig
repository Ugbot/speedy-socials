//! Message reassembly from RFC 6455 frames.
//!
//! WebSocket allows a logical message (text or binary) to be split
//! across multiple frames: the first carries the type opcode with
//! FIN=0, intermediate frames carry opcode=continuation/FIN=0, and
//! the last carries opcode=continuation/FIN=1. Control frames (ping,
//! pong, close) MAY interleave but must not be fragmented.
//!
//! Tiger Style:
//!   * Reassembly buffer is caller-owned and fixed-size; the state
//!     machine borrows it. Overflow → `MessageTooLarge`, never grow.
//!   * No allocations. No recursion. Bounded `accept` loop is the
//!     caller's responsibility (one call per frame).

const std = @import("std");
const limits = @import("../limits.zig");
const WsError = @import("../errors.zig").WsError;
const frame_mod = @import("frame.zig");
const Opcode = frame_mod.Opcode;
const Frame = frame_mod.Frame;
const assert_mod = @import("../assert.zig");
const assert = assert_mod.assert;
const assertLe = assert_mod.assertLe;

/// Maximum reassembled message size. Bounded by the connection read
/// buffer (one in-flight message at a time per connection).
pub const max_message_bytes: usize = limits.conn_read_buffer_bytes;

pub const MessageKind = enum { text, binary };

/// Outcome of feeding a frame into the reassembler.
pub const Step = union(enum) {
    /// Frame consumed; more frames needed to complete the message.
    needs_more,
    /// A complete data message was assembled.
    message: struct {
        kind: MessageKind,
        payload: []const u8,
    },
    /// A control frame was observed and is passed through verbatim
    /// for the caller to handle (reply with pong, close handshake,
    /// etc.). Control frames are NEVER buffered into the message.
    control: struct {
        opcode: Opcode,
        payload: []const u8,
    },
};

pub const Reassembler = struct {
    buffer: []u8,
    len: usize,
    /// Set when a data frame with FIN=0 has been received; subsequent
    /// frames must be continuations until FIN=1.
    in_fragment: bool,
    /// Kind of the in-progress fragmented message.
    fragment_kind: MessageKind,

    pub fn init(buffer: []u8) Reassembler {
        return .{
            .buffer = buffer,
            .len = 0,
            .in_fragment = false,
            .fragment_kind = .binary,
        };
    }

    pub fn reset(self: *Reassembler) void {
        self.len = 0;
        self.in_fragment = false;
    }

    /// Feed one already-decoded-and-unmasked frame.
    pub fn accept(self: *Reassembler, f: Frame) WsError!Step {
        // Control frames never fragment and never touch the buffer.
        if (f.opcode.isControl()) {
            // Bound: frame.zig already enforces ≤125 bytes and FIN=1.
            assertLe(f.payload.len, 125);
            return .{ .control = .{ .opcode = f.opcode, .payload = f.payload } };
        }

        switch (f.opcode) {
            .text, .binary => {
                if (self.in_fragment) return error.UnexpectedNonContinuation;
                self.len = 0;
                self.fragment_kind = if (f.opcode == .text) .text else .binary;
                try self.appendPayload(f.payload);
                if (f.fin) {
                    return self.completeMessage();
                }
                self.in_fragment = true;
                return .needs_more;
            },
            .continuation => {
                if (!self.in_fragment) return error.UnexpectedContinuation;
                try self.appendPayload(f.payload);
                if (f.fin) {
                    self.in_fragment = false;
                    return self.completeMessage();
                }
                return .needs_more;
            },
            else => unreachable, // control already handled above
        }
    }

    fn appendPayload(self: *Reassembler, payload: []const u8) WsError!void {
        if (self.len + payload.len > self.buffer.len) return error.MessageTooLarge;
        @memcpy(self.buffer[self.len..][0..payload.len], payload);
        self.len += payload.len;
        assertLe(self.len, self.buffer.len);
    }

    fn completeMessage(self: *Reassembler) WsError!Step {
        if (self.fragment_kind == .text) {
            if (!std.unicode.utf8ValidateSlice(self.buffer[0..self.len])) {
                return error.InvalidUtf8;
            }
        }
        const slice = self.buffer[0..self.len];
        const k = self.fragment_kind;
        self.len = 0;
        return .{ .message = .{ .kind = k, .payload = slice } };
    }
};

// ── tests ──────────────────────────────────────────────────────

const testing = std.testing;

fn makeFrame(opcode: Opcode, payload: []u8, fin: bool) Frame {
    return .{
        .fin = fin,
        .rsv1 = false,
        .rsv2 = false,
        .rsv3 = false,
        .opcode = opcode,
        .masked = false,
        .mask = .{ 0, 0, 0, 0 },
        .payload = payload,
    };
}

test "Reassembler single-frame text message" {
    var buf: [256]u8 = undefined;
    var r = Reassembler.init(&buf);
    var payload = [_]u8{ 'h', 'i' };
    const step = try r.accept(makeFrame(.text, &payload, true));
    try testing.expect(step == .message);
    try testing.expectEqual(MessageKind.text, step.message.kind);
    try testing.expectEqualSlices(u8, "hi", step.message.payload);
}

test "Reassembler fragmented binary message" {
    var buf: [256]u8 = undefined;
    var r = Reassembler.init(&buf);
    var a = [_]u8{ 1, 2, 3 };
    var b = [_]u8{ 4, 5 };
    var c = [_]u8{ 6, 7, 8, 9 };

    const s1 = try r.accept(makeFrame(.binary, &a, false));
    try testing.expect(s1 == .needs_more);
    const s2 = try r.accept(makeFrame(.continuation, &b, false));
    try testing.expect(s2 == .needs_more);
    const s3 = try r.accept(makeFrame(.continuation, &c, true));
    try testing.expect(s3 == .message);
    try testing.expectEqual(MessageKind.binary, s3.message.kind);
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9 }, s3.message.payload);
}

test "Reassembler control frame passthrough between fragments" {
    var buf: [256]u8 = undefined;
    var r = Reassembler.init(&buf);
    var a = [_]u8{ 1, 2 };
    var ping = [_]u8{0xAB};
    var b = [_]u8{ 3, 4 };

    _ = try r.accept(makeFrame(.binary, &a, false));
    const ctrl = try r.accept(makeFrame(.ping, &ping, true));
    try testing.expect(ctrl == .control);
    try testing.expectEqual(Opcode.ping, ctrl.control.opcode);

    const done = try r.accept(makeFrame(.continuation, &b, true));
    try testing.expect(done == .message);
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4 }, done.message.payload);
}

test "Reassembler rejects continuation without start" {
    var buf: [256]u8 = undefined;
    var r = Reassembler.init(&buf);
    var p = [_]u8{1};
    try testing.expectError(error.UnexpectedContinuation, r.accept(makeFrame(.continuation, &p, true)));
}

test "Reassembler rejects new data frame mid-fragment" {
    var buf: [256]u8 = undefined;
    var r = Reassembler.init(&buf);
    var a = [_]u8{1};
    _ = try r.accept(makeFrame(.binary, &a, false));
    var b = [_]u8{2};
    try testing.expectError(error.UnexpectedNonContinuation, r.accept(makeFrame(.text, &b, true)));
}

test "Reassembler rejects oversize message" {
    var buf: [4]u8 = undefined;
    var r = Reassembler.init(&buf);
    var a = [_]u8{ 1, 2, 3 };
    _ = try r.accept(makeFrame(.binary, &a, false));
    var b = [_]u8{ 4, 5 };
    try testing.expectError(error.MessageTooLarge, r.accept(makeFrame(.continuation, &b, true)));
}

test "Reassembler rejects invalid UTF-8 text" {
    var buf: [16]u8 = undefined;
    var r = Reassembler.init(&buf);
    var bad = [_]u8{ 0xC3, 0x28 }; // invalid UTF-8 sequence
    try testing.expectError(error.InvalidUtf8, r.accept(makeFrame(.text, &bad, true)));
}
