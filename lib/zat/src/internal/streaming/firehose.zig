//! firehose codec - com.atproto.sync.subscribeRepos
//!
//! encode and decode AT Protocol firehose events over WebSocket. messages are
//! DAG-CBOR encoded (unlike jetstream, which is JSON). includes frame encoding/
//! decoding, CAR block packing, and CID creation for records.
//!
//! wire format per frame:
//!   [DAG-CBOR header: {op, t}] [DAG-CBOR payload: {seq, repo, ops, blocks, ...}]
//!
//! see: https://atproto.com/specs/event-stream

const std = @import("std");
const websocket = @import("websocket");
const cbor = @import("../repo/cbor.zig");
const car = @import("../repo/car.zig");
const sync = @import("sync.zig");

const mem = std.mem;
const Allocator = mem.Allocator;
const posix = std.posix;
const log = std.log.scoped(.zat);

pub const CommitAction = sync.CommitAction;
pub const AccountStatus = sync.AccountStatus;

pub const default_hosts = [_][]const u8{
    "bsky.network",
    "northamerica.firehose.network",
    "europe.firehose.network",
    "asia.firehose.network",
};

pub const Options = struct {
    hosts: []const []const u8 = &default_hosts,
    cursor: ?i64 = null,
    max_message_size: usize = 5 * 1024 * 1024, // 5MB — firehose frames can be large
};

/// decoded firehose event
pub const Event = union(enum) {
    commit: CommitEvent,
    identity: IdentityEvent,
    account: AccountEvent,
    info: InfoEvent,

    pub fn seq(self: Event) ?i64 {
        return switch (self) {
            .commit => |c| c.seq,
            .identity => |i| i.seq,
            .account => |a| a.seq,
            .info => null,
        };
    }
};

pub const CommitEvent = struct {
    seq: i64,
    repo: []const u8, // DID
    rev: []const u8, // TID — revision of the commit
    time: []const u8, // datetime — when event was received
    since: ?[]const u8 = null, // TID — rev of preceding commit (null = full repo export)
    commit: ?cbor.Cid = null, // CID of the commit object
    ops: []const RepoOp,
    blobs: []const cbor.Cid = &.{}, // new blobs referenced by records in this commit
    too_big: bool = false,
};

pub const RepoOp = struct {
    action: CommitAction,
    collection: []const u8,
    rkey: []const u8,
    cid: ?cbor.Cid = null, // CID of the record (null for deletes)
    record: ?cbor.Value = null, // decoded DAG-CBOR record from CAR block
};

pub const IdentityEvent = struct {
    seq: i64,
    did: []const u8,
    time: []const u8, // datetime — when event was received
    handle: ?[]const u8 = null,
};

pub const AccountEvent = struct {
    seq: i64,
    did: []const u8,
    time: []const u8, // datetime — when event was received
    active: bool = true,
    status: ?AccountStatus = null,
};

pub const InfoEvent = struct {
    name: ?[]const u8 = null,
    message: ?[]const u8 = null,
};

/// frame header from the wire
const FrameHeader = struct {
    op: i64,
    t: ?[]const u8 = null,
};

pub const FrameOp = enum(i64) {
    message = 1,
    err = -1,
};

pub const DecodeError = error{
    InvalidFrame,
    InvalidHeader,
    UnexpectedEof,
    MissingField,
    UnknownOp,
    UnknownEventType,
} || cbor.DecodeError || car.CarError;

/// decode a raw WebSocket binary frame into a firehose Event
pub fn decodeFrame(allocator: Allocator, data: []const u8) DecodeError!Event {
    // frame = [CBOR header] [CBOR payload] concatenated
    const header_result = try cbor.decode(allocator, data);
    const header_val = header_result.value;
    const payload_data = data[header_result.consumed..];

    // parse header
    const op = header_val.getInt("op") orelse return error.InvalidHeader;
    if (op == -1) return error.UnknownOp; // error frame

    const t = header_val.getString("t") orelse return error.InvalidHeader;

    // decode payload
    const payload = try cbor.decodeAll(allocator, payload_data);

    if (mem.eql(u8, t, "#commit")) {
        return try decodeCommit(allocator, payload);
    } else if (mem.eql(u8, t, "#identity")) {
        return decodeIdentity(payload);
    } else if (mem.eql(u8, t, "#account")) {
        return decodeAccount(payload);
    } else if (mem.eql(u8, t, "#info")) {
        return .{ .info = .{
            .name = payload.getString("name"),
            .message = payload.getString("message"),
        } };
    }

    return error.UnknownEventType;
}

fn decodeCommit(allocator: Allocator, payload: cbor.Value) DecodeError!Event {
    const seq_val = payload.getInt("seq") orelse return error.MissingField;
    const repo = payload.getString("repo") orelse return error.MissingField;
    const rev = payload.getString("rev") orelse return error.MissingField;
    const time = payload.getString("time") orelse return error.MissingField;

    // parse commit CID
    var commit_cid: ?cbor.Cid = null;
    if (payload.get("commit")) |commit_val| {
        switch (commit_val) {
            .cid => |c| commit_cid = c,
            else => {},
        }
    }

    // parse blobs array (array of CID links)
    var blobs: std.ArrayList(cbor.Cid) = .{};
    if (payload.getArray("blobs")) |blob_values| {
        for (blob_values) |blob_val| {
            switch (blob_val) {
                .cid => |c| try blobs.append(allocator, c),
                else => {},
            }
        }
    }

    // parse CAR blocks
    const blocks_bytes = payload.getBytes("blocks");
    var parsed_car: ?car.Car = null;
    if (blocks_bytes) |b| {
        parsed_car = car.read(allocator, b) catch null;
    }

    // parse ops
    const ops_array = payload.getArray("ops");
    var ops: std.ArrayList(RepoOp) = .{};

    if (ops_array) |op_values| {
        for (op_values) |op_val| {
            const action_str = op_val.getString("action") orelse continue;
            const action = CommitAction.parse(action_str) orelse continue;
            const path = op_val.getString("path") orelse continue;

            // split path into collection/rkey
            const slash = mem.indexOfScalar(u8, path, '/') orelse continue;
            const collection = path[0..slash];
            const rkey = path[slash + 1 ..];

            // extract CID from op and look up record from CAR blocks
            var op_cid: ?cbor.Cid = null;
            var record: ?cbor.Value = null;
            if (op_val.get("cid")) |cid_val| {
                switch (cid_val) {
                    .cid => |cid| {
                        op_cid = cid;
                        if (parsed_car) |c| {
                            if (car.findBlock(c, cid.raw)) |block_data| {
                                record = cbor.decodeAll(allocator, block_data) catch null;
                            }
                        }
                    },
                    else => {},
                }
            }

            try ops.append(allocator, .{
                .action = action,
                .collection = collection,
                .rkey = rkey,
                .cid = op_cid,
                .record = record,
            });
        }
    }

    return .{ .commit = .{
        .seq = seq_val,
        .repo = repo,
        .rev = rev,
        .time = time,
        .since = payload.getString("since"),
        .commit = commit_cid,
        .ops = try ops.toOwnedSlice(allocator),
        .blobs = try blobs.toOwnedSlice(allocator),
        .too_big = payload.getBool("tooBig") orelse false,
    } };
}

fn decodeIdentity(payload: cbor.Value) DecodeError!Event {
    return .{ .identity = .{
        .seq = payload.getInt("seq") orelse return error.MissingField,
        .did = payload.getString("did") orelse return error.MissingField,
        .time = payload.getString("time") orelse return error.MissingField,
        .handle = payload.getString("handle"),
    } };
}

fn decodeAccount(payload: cbor.Value) DecodeError!Event {
    const status_str = payload.getString("status");
    return .{ .account = .{
        .seq = payload.getInt("seq") orelse return error.MissingField,
        .did = payload.getString("did") orelse return error.MissingField,
        .time = payload.getString("time") orelse return error.MissingField,
        .active = payload.getBool("active") orelse true,
        .status = if (status_str) |s| AccountStatus.parse(s) else null,
    } };
}

// === encoder ===

/// encode a firehose Event into a wire frame: [DAG-CBOR header] [DAG-CBOR payload]
pub fn encodeFrame(allocator: Allocator, event: Event) ![]u8 {
    var list: std.ArrayList(u8) = .{};
    errdefer list.deinit(allocator);
    const writer = list.writer(allocator);

    const tag = switch (event) {
        .commit => "#commit",
        .identity => "#identity",
        .account => "#account",
        .info => "#info",
    };

    // encode header: {op: 1, t: "#..."}
    const header: cbor.Value = .{ .map = &.{
        .{ .key = "op", .value = .{ .unsigned = 1 } },
        .{ .key = "t", .value = .{ .text = tag } },
    } };
    try cbor.encode(allocator, writer, header);

    // encode payload based on event type
    switch (event) {
        .commit => |c| try encodeCommitPayload(allocator, writer, c),
        .identity => |i| try encodeIdentityPayload(allocator, writer, i),
        .account => |a| try encodeAccountPayload(allocator, writer, a),
        .info => |inf| try encodeInfoPayload(allocator, writer, inf),
    }

    return try list.toOwnedSlice(allocator);
}

fn encodeCommitPayload(allocator: Allocator, writer: anytype, commit: CommitEvent) !void {
    // build ops array and CAR blocks simultaneously
    var op_values: std.ArrayList(cbor.Value) = .{};
    defer op_values.deinit(allocator);
    var car_blocks: std.ArrayList(car.Block) = .{};
    defer car_blocks.deinit(allocator);
    var root_cids: std.ArrayList(cbor.Cid) = .{};
    defer root_cids.deinit(allocator);

    for (commit.ops) |op| {
        const action_str: []const u8 = @tagName(op.action);
        const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ op.collection, op.rkey });

        if (op.record) |record| {
            // encode record, create CID, add to CAR blocks
            const record_bytes = try cbor.encodeAlloc(allocator, record);
            const cid = try cbor.Cid.forDagCbor(allocator, record_bytes);

            try car_blocks.append(allocator, .{
                .cid_raw = cid.raw,
                .data = record_bytes,
            });

            if (root_cids.items.len == 0) {
                try root_cids.append(allocator, cid);
            }

            try op_values.append(allocator, .{ .map = @constCast(&[_]cbor.Value.MapEntry{
                .{ .key = "action", .value = .{ .text = action_str } },
                .{ .key = "cid", .value = .{ .cid = cid } },
                .{ .key = "path", .value = .{ .text = path } },
            }) });
        } else {
            try op_values.append(allocator, .{ .map = @constCast(&[_]cbor.Value.MapEntry{
                .{ .key = "action", .value = .{ .text = action_str } },
                .{ .key = "path", .value = .{ .text = path } },
            }) });
        }
    }

    // build CAR file from blocks
    const car_data = car.Car{
        .roots = root_cids.items,
        .blocks = car_blocks.items,
    };
    const blocks_bytes = try car.writeAlloc(allocator, car_data);

    // build blobs array
    var blob_values: std.ArrayList(cbor.Value) = .{};
    defer blob_values.deinit(allocator);
    for (commit.blobs) |blob| {
        try blob_values.append(allocator, .{ .cid = blob });
    }

    // build payload entries
    var entries: std.ArrayList(cbor.Value.MapEntry) = .{};
    defer entries.deinit(allocator);

    try entries.append(allocator, .{ .key = "blocks", .value = .{ .bytes = blocks_bytes } });
    if (commit.commit) |c| {
        try entries.append(allocator, .{ .key = "commit", .value = .{ .cid = c } });
    }
    try entries.append(allocator, .{ .key = "blobs", .value = .{ .array = blob_values.items } });
    try entries.append(allocator, .{ .key = "ops", .value = .{ .array = op_values.items } });
    try entries.append(allocator, .{ .key = "repo", .value = .{ .text = commit.repo } });
    try entries.append(allocator, .{ .key = "rev", .value = .{ .text = commit.rev } });
    try entries.append(allocator, .{ .key = "seq", .value = .{ .unsigned = @intCast(commit.seq) } });
    if (commit.since) |s| {
        try entries.append(allocator, .{ .key = "since", .value = .{ .text = s } });
    }
    try entries.append(allocator, .{ .key = "time", .value = .{ .text = commit.time } });
    if (commit.too_big) {
        try entries.append(allocator, .{ .key = "tooBig", .value = .{ .boolean = true } });
    }

    try cbor.encode(allocator, writer, .{ .map = entries.items });
}

fn encodeIdentityPayload(allocator: Allocator, writer: anytype, identity: IdentityEvent) !void {
    var entries: std.ArrayList(cbor.Value.MapEntry) = .{};
    defer entries.deinit(allocator);

    try entries.append(allocator, .{ .key = "did", .value = .{ .text = identity.did } });
    if (identity.handle) |h| {
        try entries.append(allocator, .{ .key = "handle", .value = .{ .text = h } });
    }
    try entries.append(allocator, .{ .key = "seq", .value = .{ .unsigned = @intCast(identity.seq) } });
    try entries.append(allocator, .{ .key = "time", .value = .{ .text = identity.time } });

    try cbor.encode(allocator, writer, .{ .map = entries.items });
}

fn encodeAccountPayload(allocator: Allocator, writer: anytype, account: AccountEvent) !void {
    var entries: std.ArrayList(cbor.Value.MapEntry) = .{};
    defer entries.deinit(allocator);

    if (!account.active) {
        try entries.append(allocator, .{ .key = "active", .value = .{ .boolean = false } });
    }
    try entries.append(allocator, .{ .key = "did", .value = .{ .text = account.did } });
    try entries.append(allocator, .{ .key = "seq", .value = .{ .unsigned = @intCast(account.seq) } });
    if (account.status) |s| {
        try entries.append(allocator, .{ .key = "status", .value = .{ .text = @tagName(s) } });
    }
    try entries.append(allocator, .{ .key = "time", .value = .{ .text = account.time } });

    try cbor.encode(allocator, writer, .{ .map = entries.items });
}

fn encodeInfoPayload(allocator: Allocator, writer: anytype, info: InfoEvent) !void {
    var entries: std.ArrayList(cbor.Value.MapEntry) = .{};
    defer entries.deinit(allocator);

    if (info.message) |m| {
        try entries.append(allocator, .{ .key = "message", .value = .{ .text = m } });
    }
    if (info.name) |n| {
        try entries.append(allocator, .{ .key = "name", .value = .{ .text = n } });
    }

    try cbor.encode(allocator, writer, .{ .map = entries.items });
}

pub const FirehoseClient = struct {
    allocator: Allocator,
    options: Options,
    last_seq: ?i64 = null,

    pub fn init(allocator: Allocator, options: Options) FirehoseClient {
        return .{
            .allocator = allocator,
            .options = options,
            .last_seq = if (options.cursor) |c| c else null,
        };
    }

    pub fn deinit(_: *FirehoseClient) void {}

    /// subscribe with a user-provided handler.
    /// handler must implement: fn onEvent(*@TypeOf(handler), Event) void
    /// optional: fn onError(*@TypeOf(handler), anyerror) void
    /// blocks forever — reconnects with exponential backoff on disconnect.
    /// rotates through hosts on each reconnect attempt.
    pub fn subscribe(self: *FirehoseClient, handler: anytype) void {
        var backoff: u64 = 1;
        var host_index: usize = 0;
        const max_backoff: u64 = 60;
        var prev_host_index: usize = 0;

        while (true) {
            const host = self.options.hosts[host_index % self.options.hosts.len];
            const effective_index = host_index % self.options.hosts.len;

            // reset backoff on host switch (fresh host deserves a fresh chance)
            if (host_index > 0 and effective_index != prev_host_index) {
                backoff = 1;
            }

            log.info("connecting to host {d}/{d}: {s}", .{ effective_index + 1, self.options.hosts.len, host });

            self.connectAndRead(host, handler) catch |err| {
                if (comptime @hasDecl(@TypeOf(handler.*), "onError")) {
                    handler.onError(err);
                } else {
                    log.err("firehose error: {s}, reconnecting in {d}s...", .{ @errorName(err), backoff });
                }
            };

            prev_host_index = effective_index;
            host_index += 1;
            posix.nanosleep(backoff, 0);
            backoff = @min(backoff * 2, max_backoff);
        }
    }

    fn connectAndRead(self: *FirehoseClient, host: []const u8, handler: anytype) !void {
        var path_buf: [256]u8 = undefined;
        var w: std.Io.Writer = .fixed(&path_buf);

        try w.writeAll("/xrpc/com.atproto.sync.subscribeRepos");
        if (self.last_seq) |cursor| {
            try w.print("?cursor={d}", .{cursor});
        }
        const path = w.buffered();

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

        log.info("firehose connected to {s}", .{host});

        var ws_handler = WsHandler(@TypeOf(handler.*)){
            .allocator = self.allocator,
            .handler = handler,
            .client_state = self,
        };
        try client.readLoop(&ws_handler);
    }
};

fn WsHandler(comptime H: type) type {
    return struct {
        allocator: Allocator,
        handler: *H,
        client_state: *FirehoseClient,

        const Self = @This();

        pub fn serverMessage(self: *Self, data: []const u8) !void {
            var arena = std.heap.ArenaAllocator.init(self.allocator);
            defer arena.deinit();

            const event = decodeFrame(arena.allocator(), data) catch |err| {
                log.debug("frame decode error: {s}", .{@errorName(err)});
                return;
            };

            if (event.seq()) |s| {
                self.client_state.last_seq = s;
            }

            self.handler.onEvent(event);
        }

        pub fn close(_: *Self) void {
            log.info("firehose connection closed", .{});
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

test "decode frame header" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // simulate a frame: header {op: 1, t: "#info"} + payload {name: "OutdatedCursor"}
    const header_bytes = [_]u8{
        0xa2, // map(2)
        0x62, 'o', 'p', 0x01, // "op": 1
        0x61, 't', 0x65, '#', 'i', 'n', 'f', 'o', // "t": "#info"
    };
    const payload_bytes = [_]u8{
        0xa1, // map(1)
        0x64, 'n', 'a', 'm', 'e', // "name"
        0x6e, 'O', 'u', 't', 'd', 'a', 't', 'e', 'd', 'C', 'u', 'r', 's', 'o', 'r', // "OutdatedCursor"
    };

    var frame: [header_bytes.len + payload_bytes.len]u8 = undefined;
    @memcpy(frame[0..header_bytes.len], &header_bytes);
    @memcpy(frame[header_bytes.len..], &payload_bytes);

    const event = try decodeFrame(alloc, &frame);
    const info = event.info;
    try std.testing.expectEqualStrings("OutdatedCursor", info.name.?);
}

test "decode identity frame" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // build frame via encoder for cleaner test
    const original = Event{ .identity = .{
        .seq = 42,
        .did = "did:plc:test",
        .time = "2024-01-15T10:30:00Z",
    } };
    const frame = try encodeFrame(alloc, original);

    const event = try decodeFrame(alloc, frame);
    const identity = event.identity;
    try std.testing.expectEqual(@as(i64, 42), identity.seq);
    try std.testing.expectEqualStrings("did:plc:test", identity.did);
    try std.testing.expectEqualStrings("2024-01-15T10:30:00Z", identity.time);
}

test "Event.seq works" {
    const info_event = Event{ .info = .{ .name = "test" } };
    try std.testing.expect(info_event.seq() == null);

    const identity_event = Event{ .identity = .{
        .seq = 42,
        .did = "did:plc:test",
        .time = "2024-01-15T10:30:00Z",
    } };
    try std.testing.expectEqual(@as(i64, 42), identity_event.seq().?);
}

// === encoder tests ===

test "encode → decode info frame" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const original = Event{ .info = .{
        .name = "OutdatedCursor",
        .message = "cursor is behind",
    } };

    const frame = try encodeFrame(alloc, original);
    const decoded = try decodeFrame(alloc, frame);

    try std.testing.expectEqualStrings("OutdatedCursor", decoded.info.name.?);
    try std.testing.expectEqualStrings("cursor is behind", decoded.info.message.?);
}

test "encode → decode identity frame" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const original = Event{ .identity = .{
        .seq = 42,
        .did = "did:plc:test123",
        .time = "2024-01-15T10:30:00Z",
        .handle = "alice.bsky.social",
    } };

    const frame = try encodeFrame(alloc, original);
    const decoded = try decodeFrame(alloc, frame);

    const id = decoded.identity;
    try std.testing.expectEqual(@as(i64, 42), id.seq);
    try std.testing.expectEqualStrings("did:plc:test123", id.did);
    try std.testing.expectEqualStrings("2024-01-15T10:30:00Z", id.time);
    try std.testing.expectEqualStrings("alice.bsky.social", id.handle.?);
}

test "encode → decode account frame" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const original = Event{ .account = .{
        .seq = 100,
        .did = "did:plc:suspended",
        .time = "2024-01-15T10:30:00Z",
        .active = false,
        .status = .suspended,
    } };

    const frame = try encodeFrame(alloc, original);
    const decoded = try decodeFrame(alloc, frame);

    const acct = decoded.account;
    try std.testing.expectEqual(@as(i64, 100), acct.seq);
    try std.testing.expectEqualStrings("did:plc:suspended", acct.did);
    try std.testing.expectEqualStrings("2024-01-15T10:30:00Z", acct.time);
    try std.testing.expectEqual(false, acct.active);
    try std.testing.expectEqual(AccountStatus.suspended, acct.status.?);
}

test "encode → decode commit frame with record" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const record: cbor.Value = .{ .map = &.{
        .{ .key = "$type", .value = .{ .text = "app.bsky.feed.post" } },
        .{ .key = "text", .value = .{ .text = "hello firehose" } },
    } };

    const original = Event{ .commit = .{
        .seq = 999,
        .repo = "did:plc:poster",
        .rev = "3k2abc000000",
        .time = "2024-01-15T10:30:00Z",
        .since = "3k2abd000000",
        .ops = &.{.{
            .action = .create,
            .collection = "app.bsky.feed.post",
            .rkey = "3k2abc",
            .record = record,
        }},
    } };

    const frame = try encodeFrame(alloc, original);
    const decoded = try decodeFrame(alloc, frame);

    const commit = decoded.commit;
    try std.testing.expectEqual(@as(i64, 999), commit.seq);
    try std.testing.expectEqualStrings("did:plc:poster", commit.repo);
    try std.testing.expectEqualStrings("3k2abc000000", commit.rev);
    try std.testing.expectEqualStrings("2024-01-15T10:30:00Z", commit.time);
    try std.testing.expectEqualStrings("3k2abd000000", commit.since.?);
    try std.testing.expectEqual(@as(usize, 0), commit.blobs.len);
    try std.testing.expectEqual(@as(usize, 1), commit.ops.len);

    const op = commit.ops[0];
    try std.testing.expectEqual(CommitAction.create, op.action);
    try std.testing.expectEqualStrings("app.bsky.feed.post", op.collection);
    try std.testing.expectEqualStrings("3k2abc", op.rkey);
    try std.testing.expect(op.cid != null);

    // record should be decoded from the CAR blocks
    const rec = op.record.?;
    try std.testing.expectEqualStrings("hello firehose", rec.getString("text").?);
    try std.testing.expectEqualStrings("app.bsky.feed.post", rec.getString("$type").?);
}

test "encode → decode commit with delete (no record)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const original = Event{ .commit = .{
        .seq = 500,
        .repo = "did:plc:deleter",
        .rev = "3k2xyz000000",
        .time = "2024-01-15T10:30:00Z",
        .ops = &.{.{
            .action = .delete,
            .collection = "app.bsky.feed.post",
            .rkey = "abc123",
            .record = null,
        }},
    } };

    const frame = try encodeFrame(alloc, original);
    const decoded = try decodeFrame(alloc, frame);

    try std.testing.expectEqual(@as(i64, 500), decoded.commit.seq);
    try std.testing.expectEqualStrings("3k2xyz000000", decoded.commit.rev);
    try std.testing.expectEqualStrings("2024-01-15T10:30:00Z", decoded.commit.time);
    try std.testing.expectEqual(@as(usize, 1), decoded.commit.ops.len);
    try std.testing.expectEqual(CommitAction.delete, decoded.commit.ops[0].action);
    try std.testing.expect(decoded.commit.ops[0].cid == null);
    try std.testing.expect(decoded.commit.ops[0].record == null);
}
