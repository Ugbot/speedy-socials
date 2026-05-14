//! jetstream client - AT Protocol event stream via WebSocket
//!
//! typed, reconnecting client for the Bluesky Jetstream service.
//! parses commit, identity, and account events into typed structs.
//!
//! see: https://github.com/bluesky-social/jetstream

const std = @import("std");
const websocket = @import("websocket");
const json_helpers = @import("../xrpc/json.zig");
const sync = @import("sync.zig");

const mem = std.mem;
const json = std.json;
const posix = std.posix;
const Allocator = mem.Allocator;
const log = std.log.scoped(.zat);

pub const CommitAction = sync.CommitAction;
pub const AccountStatus = sync.AccountStatus;

pub const default_hosts = [_][]const u8{
    "jetstream1.us-east.bsky.network",
    "jetstream2.us-east.bsky.network",
    "jetstream1.us-west.bsky.network",
    "jetstream2.us-west.bsky.network",
    "jetstream.waow.tech",
    "jetstream.fire.hose.cam",
    "jet.firehose.stream",
    "sfo.firehose.stream",
    "nyc.firehose.stream",
    "london.firehose.stream",
    "frankfurt.firehose.stream",
    "chennai.firehose.stream",
};

pub const Options = struct {
    hosts: []const []const u8 = &default_hosts,
    wanted_collections: []const []const u8 = &.{},
    wanted_dids: []const []const u8 = &.{},
    cursor: ?i64 = null,
    max_message_size: usize = 1024 * 1024,
};

pub const Event = union(enum) {
    commit: CommitEvent,
    identity: IdentityEvent,
    account: AccountEvent,

    pub fn timeUs(self: Event) i64 {
        return switch (self) {
            inline else => |e| e.time_us,
        };
    }
};

pub const CommitEvent = struct {
    did: []const u8,
    time_us: i64,
    rev: ?[]const u8 = null,
    operation: CommitAction,
    collection: []const u8,
    rkey: []const u8,
    record: ?json.Value = null,
    cid: ?[]const u8 = null,
};

pub const IdentityEvent = struct {
    did: []const u8,
    time_us: i64,
    handle: ?[]const u8 = null,
    seq: ?i64 = null,
    time: ?[]const u8 = null,
};

pub const AccountEvent = struct {
    did: []const u8,
    time_us: i64,
    active: bool,
    status: ?AccountStatus = null,
    seq: ?i64 = null,
    time: ?[]const u8 = null,
};

/// parse a raw JSON payload into a typed Event.
/// allocator is used for JSON structural data (ObjectMaps for record fields).
/// string slices in the returned Event reference the source `payload` bytes.
/// keep both `payload` and allocator-owned memory alive while using the Event.
pub fn parseEvent(allocator: Allocator, payload: []const u8) !Event {
    const parsed = try json.parseFromSlice(json.Value, allocator, payload, .{});
    const root = parsed.value;

    const kind_str = json_helpers.getString(root, "kind") orelse return error.MissingKind;
    const did = json_helpers.getString(root, "did") orelse return error.MissingDid;
    const time_us = json_helpers.getInt(root, "time_us") orelse return error.MissingTimeUs;

    if (mem.eql(u8, kind_str, "commit")) {
        const op_str = json_helpers.getString(root, "commit.operation") orelse return error.MissingOperation;
        return .{ .commit = .{
            .did = did,
            .time_us = time_us,
            .operation = CommitAction.parse(op_str) orelse return error.UnknownOperation,
            .collection = json_helpers.getString(root, "commit.collection") orelse return error.MissingCollection,
            .rkey = json_helpers.getString(root, "commit.rkey") orelse return error.MissingRkey,
            .rev = json_helpers.getString(root, "commit.rev"),
            .cid = json_helpers.getString(root, "commit.cid"),
            .record = json_helpers.getPath(root, "commit.record"),
        } };
    } else if (mem.eql(u8, kind_str, "identity")) {
        return .{ .identity = .{
            .did = did,
            .time_us = time_us,
            .handle = json_helpers.getString(root, "identity.handle"),
            .seq = json_helpers.getInt(root, "identity.seq"),
            .time = json_helpers.getString(root, "identity.time"),
        } };
    } else if (mem.eql(u8, kind_str, "account")) {
        const status_str = json_helpers.getString(root, "account.status");
        return .{ .account = .{
            .did = did,
            .time_us = time_us,
            .active = json_helpers.getBool(root, "account.active") orelse true,
            .status = if (status_str) |s| AccountStatus.parse(s) else null,
            .seq = json_helpers.getInt(root, "account.seq"),
            .time = json_helpers.getString(root, "account.time"),
        } };
    }

    return error.UnknownKind;
}

pub const JetstreamClient = struct {
    allocator: Allocator,
    options: Options,
    last_time_us: ?i64 = null,

    pub fn init(allocator: Allocator, options: Options) JetstreamClient {
        return .{
            .allocator = allocator,
            .options = options,
            .last_time_us = options.cursor,
        };
    }

    pub fn deinit(_: *JetstreamClient) void {}

    /// subscribe with a user-provided handler.
    /// handler must implement: fn onEvent(*@TypeOf(handler), Event) void
    /// optional: fn onError(*@TypeOf(handler), anyerror) void
    /// optional: fn onConnect(*@TypeOf(handler), []const u8) void — called with host on connect
    /// blocks forever — reconnects with exponential backoff on disconnect.
    /// rotates through hosts on each reconnect attempt.
    pub fn subscribe(self: *JetstreamClient, handler: anytype) void {
        var backoff: u64 = 1;
        var host_index: usize = 0;
        const max_backoff: u64 = 60;
        var prev_host_index: usize = 0;

        while (true) {
            const host = self.options.hosts[host_index % self.options.hosts.len];
            const effective_index = host_index % self.options.hosts.len;

            // rewind cursor by 10s on host switch (different instances may lag)
            if (host_index > 0 and effective_index != prev_host_index) {
                if (self.last_time_us) |t| {
                    self.last_time_us = t - 10_000_000;
                }
                backoff = 1;
            }

            log.info("connecting to host {d}/{d}: {s}", .{ effective_index + 1, self.options.hosts.len, host });

            self.connectAndRead(host, handler) catch |err| {
                if (comptime @hasDecl(@TypeOf(handler.*), "onError")) {
                    handler.onError(err);
                } else {
                    log.err("jetstream error: {s}, reconnecting in {d}s...", .{ @errorName(err), backoff });
                }
            };

            prev_host_index = effective_index;
            host_index += 1;
            posix.nanosleep(backoff, 0);
            backoff = @min(backoff * 2, max_backoff);
        }
    }

    fn connectAndRead(self: *JetstreamClient, host: []const u8, handler: anytype) !void {
        var path_buf: [2048]u8 = undefined;
        const path = try self.buildSubscribePath(&path_buf);

        log.info("connecting to wss://{s}{s}", .{ host, path });

        var client = try websocket.Client.init(self.allocator, .{
            .host = host,
            .port = 443,
            .tls = true,
            .max_size = self.options.max_message_size,
        });
        defer client.deinit();

        var host_header_buf: [256]u8 = undefined;
        const host_header = std.fmt.bufPrint(&host_header_buf, "Host: {s}\r\n", .{host}) catch host;

        try client.handshake(path, .{ .headers = host_header });
        configureKeepalive(&client);

        log.info("jetstream connected to {s}", .{host});

        if (comptime @hasDecl(@TypeOf(handler.*), "onConnect")) {
            handler.onConnect(host);
        }

        var ws_handler = WsHandler(@TypeOf(handler.*)){
            .allocator = self.allocator,
            .handler = handler,
            .client_state = self,
        };
        try client.readLoop(&ws_handler);
    }

    fn buildSubscribePath(self: *JetstreamClient, buf: *[2048]u8) ![]const u8 {
        var w: std.Io.Writer = .fixed(buf);

        try w.writeAll("/subscribe");

        var has_param = false;

        for (self.options.wanted_collections) |col| {
            try w.writeByte(if (!has_param) '?' else '&');
            try w.writeAll("wantedCollections=");
            try w.writeAll(col);
            has_param = true;
        }

        for (self.options.wanted_dids) |did| {
            try w.writeByte(if (!has_param) '?' else '&');
            try w.writeAll("wantedDids=");
            try w.writeAll(did);
            has_param = true;
        }

        if (self.last_time_us) |cursor| {
            try w.writeByte(if (!has_param) '?' else '&');
            try w.print("cursor={d}", .{cursor});
        }

        return w.buffered();
    }
};

fn WsHandler(comptime H: type) type {
    return struct {
        allocator: Allocator,
        handler: *H,
        client_state: *JetstreamClient,

        const Self = @This();

        pub fn serverMessage(self: *Self, data: []const u8) !void {
            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();

            const event = parseEvent(arena.allocator(), data) catch |err| {
                log.debug("message parse error: {s}", .{@errorName(err)});
                return;
            };

            self.client_state.last_time_us = event.timeUs();
            self.handler.onEvent(event);
        }

        pub fn close(_: *Self) void {
            log.info("jetstream connection closed", .{});
        }
    };
}

/// enable TCP keepalive so reads don't block forever when a peer
/// disappears without FIN/RST (network partition, crash, power loss).
/// detection time: 10s idle + 5s × 2 probes = 20s.
fn configureKeepalive(client: *websocket.Client) void {
    const fd = client.stream.stream.handle;
    const builtin = @import("builtin");
    posix.setsockopt(fd, posix.SOL.SOCKET, posix.SO.KEEPALIVE, &std.mem.toBytes(@as(i32, 1))) catch return;
    const tcp: i32 = @intCast(posix.IPPROTO.TCP);
    if (builtin.os.tag == .linux) {
        posix.setsockopt(fd, tcp, posix.TCP.KEEPIDLE, &std.mem.toBytes(@as(i32, 10))) catch return;
    } else if (builtin.os.tag == .macos) {
        posix.setsockopt(fd, tcp, posix.TCP.KEEPALIVE, &std.mem.toBytes(@as(i32, 10))) catch return;
    }
    posix.setsockopt(fd, tcp, posix.TCP.KEEPINTVL, &std.mem.toBytes(@as(i32, 5))) catch return;
    posix.setsockopt(fd, tcp, posix.TCP.KEEPCNT, &std.mem.toBytes(@as(i32, 2))) catch return;
}

// === tests ===

test "parse commit event" {
    const payload =
        \\{
        \\  "did": "did:plc:abc123",
        \\  "time_us": 1700000000000,
        \\  "kind": "commit",
        \\  "commit": {
        \\    "rev": "3mbspmpaidl2a",
        \\    "operation": "create",
        \\    "collection": "app.bsky.feed.post",
        \\    "rkey": "xyz789",
        \\    "cid": "bafyreitest",
        \\    "record": {
        \\      "text": "hello world",
        \\      "$type": "app.bsky.feed.post"
        \\    }
        \\  }
        \\}
    ;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const event = try parseEvent(arena.allocator(), payload);
    const commit = event.commit;

    try std.testing.expectEqualStrings("did:plc:abc123", commit.did);
    try std.testing.expectEqual(@as(i64, 1700000000000), commit.time_us);
    try std.testing.expectEqualStrings("3mbspmpaidl2a", commit.rev.?);
    try std.testing.expectEqual(CommitAction.create, commit.operation);
    try std.testing.expectEqualStrings("app.bsky.feed.post", commit.collection);
    try std.testing.expectEqualStrings("xyz789", commit.rkey);
    try std.testing.expectEqualStrings("bafyreitest", commit.cid.?);
    try std.testing.expect(commit.record != null);
    try std.testing.expectEqualStrings("hello world", json_helpers.getString(commit.record.?, "text").?);
}

test "parse identity event" {
    const payload =
        \\{
        \\  "did": "did:plc:abc123",
        \\  "time_us": 1700000000000,
        \\  "kind": "identity",
        \\  "identity": {
        \\    "handle": "alice.bsky.social",
        \\    "seq": 42,
        \\    "time": "2024-01-01T00:00:00Z"
        \\  }
        \\}
    ;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const event = try parseEvent(arena.allocator(), payload);
    const identity = event.identity;

    try std.testing.expectEqualStrings("did:plc:abc123", identity.did);
    try std.testing.expectEqual(@as(i64, 1700000000000), identity.time_us);
    try std.testing.expectEqualStrings("alice.bsky.social", identity.handle.?);
    try std.testing.expectEqual(@as(i64, 42), identity.seq.?);
    try std.testing.expectEqualStrings("2024-01-01T00:00:00Z", identity.time.?);
}

test "parse account event" {
    const payload =
        \\{
        \\  "did": "did:plc:abc123",
        \\  "time_us": 1700000000000,
        \\  "kind": "account",
        \\  "account": {
        \\    "active": false,
        \\    "status": "suspended",
        \\    "seq": 99,
        \\    "time": "2024-01-01T00:00:00Z"
        \\  }
        \\}
    ;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const event = try parseEvent(arena.allocator(), payload);
    const account = event.account;

    try std.testing.expectEqualStrings("did:plc:abc123", account.did);
    try std.testing.expectEqual(@as(i64, 1700000000000), account.time_us);
    try std.testing.expectEqual(false, account.active);
    try std.testing.expectEqual(AccountStatus.suspended, account.status.?);
    try std.testing.expectEqual(@as(i64, 99), account.seq.?);
    try std.testing.expectEqualStrings("2024-01-01T00:00:00Z", account.time.?);
}

test "parse unknown kind returns error" {
    const payload =
        \\{
        \\  "did": "did:plc:abc123",
        \\  "time_us": 1700000000000,
        \\  "kind": "unknown_kind"
        \\}
    ;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    try std.testing.expectError(error.UnknownKind, parseEvent(arena.allocator(), payload));
}

test "parse commit with unknown operation returns error" {
    const payload =
        \\{
        \\  "did": "did:plc:abc123",
        \\  "time_us": 1700000000000,
        \\  "kind": "commit",
        \\  "commit": {
        \\    "operation": "archive",
        \\    "collection": "app.bsky.feed.post",
        \\    "rkey": "xyz789"
        \\  }
        \\}
    ;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    try std.testing.expectError(error.UnknownOperation, parseEvent(arena.allocator(), payload));
}

test "cursor tracking via time_us" {
    const payloads = [_][]const u8{
        \\{"did":"did:plc:a","time_us":100,"kind":"commit","commit":{"operation":"create","collection":"app.bsky.feed.post","rkey":"1"}}
        ,
        \\{"did":"did:plc:b","time_us":200,"kind":"commit","commit":{"operation":"create","collection":"app.bsky.feed.post","rkey":"2"}}
        ,
    };

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const e1 = try parseEvent(arena.allocator(), payloads[0]);
    const e2 = try parseEvent(arena.allocator(), payloads[1]);

    try std.testing.expect(e1.timeUs() > 0);
    try std.testing.expect(e2.timeUs() > e1.timeUs());
}

test "Event.timeUs works for all variants" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const commit = try parseEvent(arena.allocator(),
        \\{"did":"did:plc:a","time_us":100,"kind":"commit","commit":{"operation":"create","collection":"x","rkey":"1"}}
    );
    const identity = try parseEvent(arena.allocator(),
        \\{"did":"did:plc:a","time_us":200,"kind":"identity","identity":{}}
    );
    const account = try parseEvent(arena.allocator(),
        \\{"did":"did:plc:a","time_us":300,"kind":"account","account":{"active":true}}
    );

    try std.testing.expectEqual(@as(i64, 100), commit.timeUs());
    try std.testing.expectEqual(@as(i64, 200), identity.timeUs());
    try std.testing.expectEqual(@as(i64, 300), account.timeUs());
}

test "build subscribe path" {
    var client = JetstreamClient.init(std.testing.allocator, .{
        .wanted_collections = &.{"app.bsky.feed.post"},
    });

    var buf: [2048]u8 = undefined;
    const path = try client.buildSubscribePath(&buf);
    try std.testing.expectEqualStrings("/subscribe?wantedCollections=app.bsky.feed.post", path);
}

test "build subscribe path with multiple params" {
    var client = JetstreamClient.init(std.testing.allocator, .{
        .wanted_collections = &.{ "app.bsky.feed.post", "app.bsky.feed.like" },
        .wanted_dids = &.{"did:plc:abc123"},
        .cursor = 1700000000000,
    });

    var buf: [2048]u8 = undefined;
    const path = try client.buildSubscribePath(&buf);
    try std.testing.expectEqualStrings(
        "/subscribe?wantedCollections=app.bsky.feed.post&wantedCollections=app.bsky.feed.like&wantedDids=did:plc:abc123&cursor=1700000000000",
        path,
    );
}

test "build subscribe path no params" {
    var client = JetstreamClient.init(std.testing.allocator, .{});

    var buf: [2048]u8 = undefined;
    const path = try client.buildSubscribePath(&buf);
    try std.testing.expectEqualStrings("/subscribe", path);
}

test "parse commit event with delete operation" {
    const payload =
        \\{
        \\  "did": "did:plc:abc123",
        \\  "time_us": 1700000000000,
        \\  "kind": "commit",
        \\  "commit": {
        \\    "operation": "delete",
        \\    "collection": "app.bsky.feed.post",
        \\    "rkey": "xyz789"
        \\  }
        \\}
    ;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const commit = (try parseEvent(arena.allocator(), payload)).commit;

    try std.testing.expectEqual(CommitAction.delete, commit.operation);
    try std.testing.expect(commit.record == null);
    try std.testing.expect(commit.rev == null);
    try std.testing.expect(commit.cid == null);
}

test "parse identity event with minimal fields" {
    const payload =
        \\{
        \\  "did": "did:plc:abc123",
        \\  "time_us": 1700000000000,
        \\  "kind": "identity",
        \\  "identity": {}
        \\}
    ;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const identity = (try parseEvent(arena.allocator(), payload)).identity;

    try std.testing.expectEqualStrings("did:plc:abc123", identity.did);
    try std.testing.expect(identity.handle == null);
    try std.testing.expect(identity.seq == null);
    try std.testing.expect(identity.time == null);
}

test "parse missing did returns error" {
    const payload =
        \\{
        \\  "time_us": 1700000000000,
        \\  "kind": "commit"
        \\}
    ;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    try std.testing.expectError(error.MissingDid, parseEvent(arena.allocator(), payload));
}

test "default hosts contains known jetstream instances" {
    try std.testing.expectEqual(@as(usize, 12), default_hosts.len);
    try std.testing.expectEqualStrings("jetstream1.us-east.bsky.network", default_hosts[0]);
    try std.testing.expectEqualStrings("jetstream2.us-east.bsky.network", default_hosts[1]);
    try std.testing.expectEqualStrings("jetstream1.us-west.bsky.network", default_hosts[2]);
    try std.testing.expectEqualStrings("jetstream2.us-west.bsky.network", default_hosts[3]);
    try std.testing.expectEqualStrings("jetstream.waow.tech", default_hosts[4]);
    try std.testing.expectEqualStrings("jetstream.fire.hose.cam", default_hosts[5]);
    try std.testing.expectEqualStrings("jet.firehose.stream", default_hosts[6]);
    try std.testing.expectEqualStrings("chennai.firehose.stream", default_hosts[11]);
}

test "round-robin cycles through hosts" {
    const hosts = [_][]const u8{ "host-a", "host-b", "host-c" };
    // simulate the index logic from subscribe()
    for (0..9) |i| {
        const host = hosts[i % hosts.len];
        const expected: []const u8 = switch (i % 3) {
            0 => "host-a",
            1 => "host-b",
            2 => "host-c",
            else => unreachable,
        };
        try std.testing.expectEqualStrings(expected, host);
    }
}

test "options default hosts are used" {
    const opts = Options{};
    try std.testing.expectEqual(@as(usize, 12), opts.hosts.len);
    try std.testing.expectEqualStrings("jetstream1.us-east.bsky.network", opts.hosts[0]);
}

test "options custom single host" {
    const opts = Options{ .hosts = &.{"my-custom-host.example.com"} };
    try std.testing.expectEqual(@as(usize, 1), opts.hosts.len);
    try std.testing.expectEqualStrings("my-custom-host.example.com", opts.hosts[0]);
}
