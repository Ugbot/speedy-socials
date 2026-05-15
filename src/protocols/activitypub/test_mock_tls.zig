//! Test-only TLS backend that records outgoing bytes and replays a
//! canned response. Used by `http_delivery.zig` and other AP modules
//! that need to exercise the full HTTP/1.1 pipeline without opening a
//! real socket.
//!
//! Module-level static state is acceptable here: tests are run
//! single-threaded by `zig build test`, and each test resets via `reset`.

const std = @import("std");
const core = @import("core");
const TlsBackend = core.http_client.TlsBackend;
const NetError = core.http_client.NetError;

pub var seen_request: [16 * 1024]u8 = undefined;
pub var seen_request_len: usize = 0;
pub var canned_response: []const u8 = "";
pub var response_pos: usize = 0;

pub fn reset() void {
    seen_request_len = 0;
    response_pos = 0;
}

fn connect_impl(_: *anyopaque, _: []const u8, _: u16, _: u32) NetError!*anyopaque {
    seen_request_len = 0;
    response_pos = 0;
    return @ptrFromInt(0xCAFE);
}

fn write_impl(_: *anyopaque, _: *anyopaque, bytes: []const u8) NetError!void {
    const cap = @min(bytes.len, seen_request.len - seen_request_len);
    @memcpy(seen_request[seen_request_len .. seen_request_len + cap], bytes[0..cap]);
    seen_request_len += cap;
}

fn read_impl(_: *anyopaque, _: *anyopaque, dst: []u8) NetError!usize {
    if (response_pos >= canned_response.len) return 0;
    const remaining = canned_response[response_pos..];
    const n = @min(dst.len, remaining.len);
    @memcpy(dst[0..n], remaining[0..n]);
    response_pos += n;
    return n;
}

fn close_impl(_: *anyopaque, _: *anyopaque) void {}

const vtable: TlsBackend.Vtable = .{
    .connect = connect_impl,
    .write_all = write_impl,
    .read_some = read_impl,
    .close = close_impl,
};

pub fn backend() TlsBackend {
    return .{ .ctx = @ptrFromInt(0x1), .vtable = &vtable };
}
