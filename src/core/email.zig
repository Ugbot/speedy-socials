//! Email sender — pluggable interface for outbound transactional mail.
//!
//! Currently used (or about-to-be-used) by:
//!   * AT-9 account email verification + password reset
//!   * AT-22 admin sendEmail
//!   * Mastodon plugin password reset
//!
//! Concrete impls live alongside this file:
//!   * `LogSink`     — writes the email to the ring log. Default for dev.
//!   * `WebhookSender` — POSTs JSON `{to, subject, text, html?}` to a
//!                     configured URL. Production-shaped: the operator
//!                     wires their preferred provider (Postmark, AWS
//!                     SES, Resend, etc.) on the receiving end.
//!   * `NullSender`  — succeeds without doing anything. Test default;
//!                     not suitable for production.
//!
//! Tiger Style: vtable seam, no allocator on the hot path, bounded
//! buffers. The sender is selected at boot by env (`EMAIL_BACKEND=log|webhook|null`).

const std = @import("std");
const builtin = @import("builtin");
const core_log = @import("log.zig");

/// Maximum byte length of any single field in an email. Keeps stack
/// usage bounded and rejects pathological inputs early.
pub const max_field_bytes: usize = 4 * 1024;

pub const Error = error{
    InvalidAddress,
    InvalidBody,
    /// The configured backend refused or could not deliver the
    /// message. The send-site treats this as transient; callers
    /// retry per their own policy.
    DeliveryFailed,
};

/// One email message — fixed-size to avoid allocator on the hot path.
pub const Message = struct {
    to: []const u8,
    subject: []const u8,
    text_body: []const u8,
    /// Optional HTML body. Backends that don't render HTML can ignore.
    html_body: ?[]const u8 = null,
    /// Optional `From:` override. Defaults to whatever the backend
    /// has configured.
    from: ?[]const u8 = null,
};

pub const Sender = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        send: *const fn (ptr: *anyopaque, msg: *const Message) Error!void,
    };

    pub fn send(self: Sender, msg: *const Message) Error!void {
        if (msg.to.len == 0) return error.InvalidAddress;
        if (msg.to.len > max_field_bytes) return error.InvalidAddress;
        if (msg.subject.len > max_field_bytes) return error.InvalidBody;
        if (msg.text_body.len > 64 * max_field_bytes) return error.InvalidBody;
        return self.vtable.send(self.ptr, msg);
    }
};

// ──────────────────────────────────────────────────────────────────────
// LogSink — writes a single ring-log line per email. Dev default.
// ──────────────────────────────────────────────────────────────────────

pub const LogSink = struct {
    pub fn init() LogSink {
        return .{};
    }

    fn doSend(_: *anyopaque, msg: *const Message) Error!void {
        const ring = core_log.global() orelse return;
        var line_buf: [256]u8 = undefined;
        const line = std.fmt.bufPrint(
            &line_buf,
            "would send: to={s} subject=\"{s}\" body_bytes={d}",
            .{ msg.to, msg.subject, msg.text_body.len },
        ) catch line_buf[0..0];
        ring.record(.info, "email", line, &.{});
    }

    pub fn sender(self: *LogSink) Sender {
        return .{
            .ptr = self,
            .vtable = &.{ .send = doSend },
        };
    }
};

// ──────────────────────────────────────────────────────────────────────
// NullSender — for tests + suppression. Always succeeds.
// ──────────────────────────────────────────────────────────────────────

pub const NullSender = struct {
    pub fn init() NullSender {
        return .{};
    }

    fn doSend(_: *anyopaque, _: *const Message) Error!void {
        return;
    }

    pub fn sender(self: *NullSender) Sender {
        return .{
            .ptr = self,
            .vtable = &.{ .send = doSend },
        };
    }
};

// ──────────────────────────────────────────────────────────────────────
// Mock — records sent emails for tests. Buffers the last N messages.
// ──────────────────────────────────────────────────────────────────────

pub const Mock = struct {
    pub const capacity: usize = 16;

    pub const Recorded = struct {
        to_buf: [256]u8 = undefined,
        to_len: u16 = 0,
        subject_buf: [256]u8 = undefined,
        subject_len: u16 = 0,
        body_buf: [4096]u8 = undefined,
        body_len: u32 = 0,

        pub fn to(self: *const Recorded) []const u8 {
            return self.to_buf[0..self.to_len];
        }
        pub fn subject(self: *const Recorded) []const u8 {
            return self.subject_buf[0..self.subject_len];
        }
        pub fn body(self: *const Recorded) []const u8 {
            return self.body_buf[0..self.body_len];
        }
    };

    items: [capacity]Recorded = undefined,
    count: u8 = 0,

    pub fn init() Mock {
        return .{};
    }

    pub fn last(self: *const Mock) ?*const Recorded {
        if (self.count == 0) return null;
        return &self.items[self.count - 1];
    }

    pub fn slice(self: *const Mock) []const Recorded {
        return self.items[0..self.count];
    }

    pub fn reset(self: *Mock) void {
        self.count = 0;
    }

    fn doSend(ptr: *anyopaque, msg: *const Message) Error!void {
        const self: *Mock = @ptrCast(@alignCast(ptr));
        if (self.count >= capacity) return error.DeliveryFailed;
        var rec: Recorded = .{};
        const to_cap = @min(msg.to.len, rec.to_buf.len);
        @memcpy(rec.to_buf[0..to_cap], msg.to[0..to_cap]);
        rec.to_len = @intCast(to_cap);
        const sub_cap = @min(msg.subject.len, rec.subject_buf.len);
        @memcpy(rec.subject_buf[0..sub_cap], msg.subject[0..sub_cap]);
        rec.subject_len = @intCast(sub_cap);
        const body_cap = @min(msg.text_body.len, rec.body_buf.len);
        @memcpy(rec.body_buf[0..body_cap], msg.text_body[0..body_cap]);
        rec.body_len = @intCast(body_cap);
        self.items[self.count] = rec;
        self.count += 1;
    }

    pub fn sender(self: *Mock) Sender {
        return .{
            .ptr = self,
            .vtable = &.{ .send = doSend },
        };
    }
};

// ──────────────────────────────────────────────────────────────────────
// WebhookSender — POSTs JSON to a configured URL. Producer-agnostic;
// the operator runs whatever HTTP receiver wires up the real provider.
// ──────────────────────────────────────────────────────────────────────

pub const WebhookSender = struct {
    url: []const u8,
    http_client: ?*HttpClientErased = null,

    /// We don't want a hard dependency on `core.http_client.Client`
    /// here (it would create an import cycle when the email module is
    /// imported by core itself). The composition root attaches the
    /// client via `attachHttpClient` after both subsystems initialise.
    pub const HttpClientErased = opaque {};
    pub const PostFn = *const fn (
        client: *HttpClientErased,
        url: []const u8,
        body: []const u8,
    ) Error!void;

    var post_hook: ?PostFn = null;

    pub fn setPostHook(hook: PostFn) void {
        post_hook = hook;
    }

    pub fn init(url: []const u8) WebhookSender {
        return .{ .url = url };
    }

    pub fn attachHttpClient(self: *WebhookSender, client: *HttpClientErased) void {
        self.http_client = client;
    }

    fn doSend(ptr: *anyopaque, msg: *const Message) Error!void {
        const self: *WebhookSender = @ptrCast(@alignCast(ptr));
        const client = self.http_client orelse return error.DeliveryFailed;
        const hook = post_hook orelse return error.DeliveryFailed;

        // Build JSON body in a fixed buffer.
        var buf: [16 * 1024]u8 = undefined;
        const json = renderJson(msg, &buf) catch return error.InvalidBody;
        try hook(client, self.url, json);
    }

    pub fn sender(self: *WebhookSender) Sender {
        return .{
            .ptr = self,
            .vtable = &.{ .send = doSend },
        };
    }
};

fn renderJson(msg: *const Message, out: []u8) ![]const u8 {
    // Minimal JSON escaping using Zig 0.16's `std.Io.Writer.fixed`
    // wrapper over a fixed buffer.
    var writer: std.Io.Writer = .fixed(out);
    try writer.writeAll("{\"to\":");
    try writeJsonString(&writer, msg.to);
    try writer.writeAll(",\"subject\":");
    try writeJsonString(&writer, msg.subject);
    try writer.writeAll(",\"text\":");
    try writeJsonString(&writer, msg.text_body);
    if (msg.html_body) |h| {
        try writer.writeAll(",\"html\":");
        try writeJsonString(&writer, h);
    }
    if (msg.from) |f| {
        try writer.writeAll(",\"from\":");
        try writeJsonString(&writer, f);
    }
    try writer.writeAll("}");
    return writer.buffered();
}

fn writeJsonString(writer: *std.Io.Writer, s: []const u8) !void {
    try writer.writeByte('"');
    for (s) |b| switch (b) {
        '"' => try writer.writeAll("\\\""),
        '\\' => try writer.writeAll("\\\\"),
        '\n' => try writer.writeAll("\\n"),
        '\r' => try writer.writeAll("\\r"),
        '\t' => try writer.writeAll("\\t"),
        0...0x08, 0x0B, 0x0C, 0x0E...0x1F => try writer.print("\\u{x:0>4}", .{b}),
        else => try writer.writeByte(b),
    };
    try writer.writeByte('"');
}

// ──────────────────────────────────────────────────────────────────────
// Module-level singleton — selected at boot, looked up by senders.
// ──────────────────────────────────────────────────────────────────────

var global_sender: ?Sender = null;

pub fn setGlobal(s: Sender) void {
    global_sender = s;
}

pub fn global() ?Sender {
    return global_sender;
}

pub fn resetGlobal() void {
    global_sender = null;
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "Mock records sent messages" {
    var m = Mock.init();
    const snd = m.sender();
    try snd.send(&.{ .to = "alice@example.com", .subject = "hello", .text_body = "world" });
    try snd.send(&.{ .to = "bob@example.com", .subject = "ping", .text_body = "pong" });
    try testing.expectEqual(@as(u8, 2), m.count);
    try testing.expectEqualStrings("alice@example.com", m.items[0].to());
    try testing.expectEqualStrings("hello", m.items[0].subject());
    try testing.expectEqualStrings("pong", m.items[1].body());
}

test "Mock reset clears buffer" {
    var m = Mock.init();
    const snd = m.sender();
    try snd.send(&.{ .to = "a@b", .subject = "s", .text_body = "t" });
    m.reset();
    try testing.expectEqual(@as(u8, 0), m.count);
}

test "Sender rejects empty address" {
    var n = NullSender.init();
    const snd = n.sender();
    try testing.expectError(error.InvalidAddress, snd.send(&.{ .to = "", .subject = "", .text_body = "" }));
}

test "NullSender always succeeds" {
    var n = NullSender.init();
    const snd = n.sender();
    try snd.send(&.{ .to = "x@y", .subject = "s", .text_body = "t" });
}

test "renderJson produces a valid envelope" {
    var buf: [1024]u8 = undefined;
    const msg: Message = .{
        .to = "alice@example.com",
        .subject = "test \"quote\" thing",
        .text_body = "line1\nline2",
    };
    const out = try renderJson(&msg, &buf);
    try testing.expect(std.mem.indexOf(u8, out, "alice@example.com") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\\\"quote\\\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "line1\\nline2") != null);
}

test "global sender set/get/reset round-trips" {
    resetGlobal();
    try testing.expect(global() == null);
    var n = NullSender.init();
    setGlobal(n.sender());
    try testing.expect(global() != null);
    resetGlobal();
    try testing.expect(global() == null);
}
