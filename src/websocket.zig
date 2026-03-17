const std = @import("std");
const database = @import("database.zig");

// WebSocket frame types
pub const FrameType = enum(u8) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
};

// WebSocket frame structure
pub const Frame = struct {
    fin: bool = true,
    rsv1: bool = false,
    rsv2: bool = false,
    rsv3: bool = false,
    opcode: FrameType,
    mask: bool = false,
    mask_key: [4]u8 = [_]u8{ 0, 0, 0, 0 },
    payload_len: u64,
    payload: []u8,
};

// WebSocket protocol implementation
pub const WebSocketProtocol = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) WebSocketProtocol {
        return WebSocketProtocol{
            .allocator = allocator,
        };
    }

    // Handle WebSocket upgrade request
    pub fn handleUpgrade(self: *WebSocketProtocol, request: anytype) !?WebSocketClient {
        // Check for WebSocket upgrade headers
        const upgrade_header = request.head.get("upgrade") orelse return null;
        const connection_header = request.head.get("connection") orelse return null;
        const sec_websocket_key = request.head.get("sec-websocket-key") orelse return null;
        const sec_websocket_version = request.head.get("sec-websocket-version") orelse return null;

        // Validate headers
        if (!std.ascii.eqlIgnoreCase(std.mem.span(upgrade_header), "websocket")) return null;
        if (!std.ascii.eqlIgnoreCase(std.mem.span(connection_header), "upgrade")) return null;
        if (!std.mem.eql(u8, std.mem.span(sec_websocket_version), "13")) return null;

        // Generate accept key
        const accept_key = try self.generateAcceptKey(std.mem.span(sec_websocket_key));

        // Send 101 Switching Protocols response
        const response =
            "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Accept: {s}\r\n" ++
            "\r\n";

        var response_buf = std.array_list.Managed(u8).init(self.allocator);
        defer response_buf.deinit();

        try std.fmt.format(response_buf.writer(), response, .{std.fmt.fmtSliceEscapeLower(&accept_key)});

        // TODO: Send response to client
        // For now, return the client (response sending would be handled by HTTP server)

        // Create client
        const client_id = try generateClientId(self.allocator);
        return try WebSocketClient.init(self.allocator, client_id, null); // TODO: Set user_id from auth
    }

    // Generate WebSocket accept key
    fn generateAcceptKey(self: *WebSocketProtocol, key: []const u8) ![28]u8 {
        // WebSocket accept key = base64(sha1(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
        const magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

        var combined = std.array_list.Managed(u8).init(self.allocator);
        defer combined.deinit();

        try combined.appendSlice(key);
        try combined.appendSlice(magic_string);

        var hash: [20]u8 = undefined;
        std.crypto.hash.Sha1.hash(combined.items, &hash);

        var encoded: [28]u8 = undefined;
        _ = std.base64.standard.Encoder.encode(&encoded, &hash);

        return encoded;
    }

    // Read WebSocket frame
    pub fn readFrame(self: *WebSocketProtocol, reader: anytype) !?Frame {
        // Read first byte (FIN, RSV, opcode)
        const byte1 = try reader.readByte();
        const fin = (byte1 & 0x80) != 0;
        const opcode = @as(FrameType, @enumFromInt(byte1 & 0x0F));

        // Read second byte (mask, payload length)
        const byte2 = try reader.readByte();
        const mask = (byte2 & 0x80) != 0;
        var payload_len = @as(u64, byte2 & 0x7F);

        // Extended payload length
        if (payload_len == 126) {
            payload_len = @as(u64, try reader.readIntBig(u16));
        } else if (payload_len == 127) {
            payload_len = try reader.readIntBig(u64);
        }

        // Read mask key if present
        var mask_key: [4]u8 = [_]u8{ 0, 0, 0, 0 };
        if (mask) {
            _ = try reader.read(std.mem.asBytes(&mask_key));
        }

        // Read payload
        const payload = try self.allocator.alloc(u8, payload_len);
        errdefer self.allocator.free(payload);

        if (payload_len > 0) {
            _ = try reader.read(payload);
        }

        // Unmask payload if needed
        if (mask) {
            for (payload, 0..) |*byte, i| {
                byte.* ^= mask_key[i % 4];
            }
        }

        return Frame{
            .fin = fin,
            .opcode = opcode,
            .mask = mask,
            .mask_key = mask_key,
            .payload_len = payload_len,
            .payload = payload,
        };
    }

    // Write WebSocket frame
    pub fn writeFrame(self: *WebSocketProtocol, writer: anytype, frame: Frame) !void {
        // First byte: FIN + opcode
        var byte1: u8 = @intFromEnum(frame.opcode);
        if (frame.fin) byte1 |= 0x80;

        try writer.writeByte(byte1);

        // Second byte: mask + payload length
        var byte2: u8 = 0;
        if (frame.mask) byte2 |= 0x80;

        if (frame.payload_len < 126) {
            byte2 |= @as(u8, @intCast(frame.payload_len));
            try writer.writeByte(byte2);
        } else if (frame.payload_len < 65536) {
            byte2 |= 126;
            try writer.writeByte(byte2);
            try writer.writeIntBig(u16, @as(u16, @intCast(frame.payload_len)));
        } else {
            byte2 |= 127;
            try writer.writeByte(byte2);
            try writer.writeIntBig(u64, frame.payload_len);
        }

        // Write mask key if present
        if (frame.mask) {
            try writer.write(std.mem.asBytes(&frame.mask_key));
        }

        // Mask payload if needed
        var payload_to_write = frame.payload;
        if (frame.mask) {
            const masked_payload = try self.allocator.dupe(u8, frame.payload);
            defer self.allocator.free(masked_payload);

            for (masked_payload, 0..) |*byte, i| {
                byte.* ^= frame.mask_key[i % 4];
            }
            payload_to_write = masked_payload;
        }

        // Write payload
        if (frame.payload_len > 0) {
            _ = try writer.write(payload_to_write);
        }
    }

    // Create text frame
    pub fn createTextFrame(self: *WebSocketProtocol, text: []const u8, mask: bool) !Frame {
        var mask_key: [4]u8 = [_]u8{ 0, 0, 0, 0 };
        if (mask) {
            std.crypto.random.bytes(&mask_key);
        }

        const payload = try self.allocator.dupe(u8, text);

        return Frame{
            .opcode = .text,
            .mask = mask,
            .mask_key = mask_key,
            .payload_len = text.len,
            .payload = payload,
        };
    }

    // Create ping frame
    pub fn createPingFrame(_: *WebSocketProtocol, mask: bool) !Frame {
        var mask_key: [4]u8 = [_]u8{ 0, 0, 0, 0 };
        if (mask) {
            std.crypto.random.bytes(&mask_key);
        }

        return Frame{
            .opcode = .ping,
            .mask = mask,
            .mask_key = mask_key,
            .payload_len = 0,
            .payload = &[_]u8{},
        };
    }

    // Create pong frame
    pub fn createPongFrame(self: *WebSocketProtocol, ping_payload: []const u8, mask: bool) !Frame {
        var mask_key: [4]u8 = [_]u8{ 0, 0, 0, 0 };
        if (mask) {
            std.crypto.random.bytes(&mask_key);
        }

        const payload = try self.allocator.dupe(u8, ping_payload);

        return Frame{
            .opcode = .pong,
            .mask = mask,
            .mask_key = mask_key,
            .payload_len = payload.len,
            .payload = payload,
        };
    }

    // Create close frame
    pub fn createCloseFrame(self: *WebSocketProtocol, code: u16, reason: []const u8, mask: bool) !Frame {
        var mask_key: [4]u8 = [_]u8{ 0, 0, 0, 0 };
        if (mask) {
            std.crypto.random.bytes(&mask_key);
        }

        var payload = try self.allocator.alloc(u8, 2 + reason.len);
        std.mem.writeIntBig(u16, payload[0..2], code);
        std.mem.copyForwards(u8, payload[2..], reason);

        return Frame{
            .opcode = .close,
            .mask = mask,
            .mask_key = mask_key,
            .payload_len = payload.len,
            .payload = payload,
        };
    }
};

// Generate unique client ID
fn generateClientId(allocator: std.mem.Allocator) ![]const u8 {
    var id_buf: [16]u8 = undefined;
    std.crypto.random.bytes(&id_buf);

    var encoded = std.array_list.Managed(u8).init(allocator);
    errdefer encoded.deinit();

    const encoder = std.base64.url_safe_no_pad.Encoder;
    try encoder.encodeWriter(encoded.writer(), &id_buf);

    return encoded.toOwnedSlice();
}

// WebSocket connection state
pub const ConnectionState = enum {
    connecting,
    open,
    closing,
    closed,
};

// Streaming event types (Mastodon-style)
pub const StreamEventType = enum {
    update, // New post in timeline
    notification, // New notification
    delete, // Post deleted
    status_update, // Post updated
    filters_changed, // User's filters changed

    pub fn toString(self: StreamEventType) []const u8 {
        return switch (self) {
            .update => "update",
            .notification => "notification",
            .delete => "delete",
            .status_update => "status.update",
            .filters_changed => "filters_changed",
        };
    }
};

// Stream event payload
pub const StreamEvent = struct {
    event: StreamEventType,
    payload: []const u8, // JSON string
    stream: []const u8, // Stream name (e.g., "public", "user", "user:notifications")

    pub fn deinit(self: *StreamEvent, allocator: std.mem.Allocator) void {
        allocator.free(self.payload);
        allocator.free(self.stream);
    }
};

// WebSocket client connection
pub const WebSocketClient = struct {
    id: []const u8,
    user_id: ?i64,
    streams: std.array_list.Managed([]const u8),
    state: ConnectionState,
    last_ping: i64,
    allocator: std.mem.Allocator,
    protocol: WebSocketProtocol,

    pub fn init(allocator: std.mem.Allocator, id: []const u8, user_id: ?i64) !WebSocketClient {
        return WebSocketClient{
            .id = try allocator.dupe(u8, id),
            .user_id = user_id,
            .streams = std.array_list.Managed([]const u8).init(allocator),
            .state = .connecting,
            .last_ping = std.time.timestamp(),
            .allocator = allocator,
            .protocol = WebSocketProtocol.init(allocator),
        };
    }

    pub fn deinit(self: *WebSocketClient) void {
        self.allocator.free(self.id);
        for (self.streams.items) |stream| {
            self.allocator.free(stream);
        }
        self.streams.deinit();
    }

    // Send a text message to the client
    pub fn sendText(self: *WebSocketClient, writer: anytype, text: []const u8) !void {
        const frame = try self.protocol.createTextFrame(text, false); // Server frames are not masked
        defer self.allocator.free(frame.payload);

        try self.protocol.writeFrame(writer, frame);
    }

    // Send a ping to the client
    pub fn sendPing(self: *WebSocketClient, writer: anytype) !void {
        const frame = try self.protocol.createPingFrame(false); // Server frames are not masked
        try self.protocol.writeFrame(writer, frame);
    }

    // Send a pong response
    pub fn sendPong(self: *WebSocketClient, writer: anytype, ping_payload: []const u8) !void {
        const frame = try self.protocol.createPongFrame(ping_payload, false); // Server frames are not masked
        defer self.allocator.free(frame.payload);
        try self.protocol.writeFrame(writer, frame);
    }

    // Send a close frame
    pub fn sendClose(self: *WebSocketClient, writer: anytype, code: u16, reason: []const u8) !void {
        const frame = try self.protocol.createCloseFrame(code, reason, false); // Server frames are not masked
        defer self.allocator.free(frame.payload);
        try self.protocol.writeFrame(writer, frame);
        self.state = .closing;
    }

    // Handle incoming frame
    pub fn handleFrame(self: *WebSocketClient, frame: Frame, writer: anytype) !bool {
        switch (frame.opcode) {
            .text => {
                // Handle text message (subscription commands, etc.)
                try self.handleTextMessage(frame.payload, writer);
            },
            .ping => {
                // Respond with pong
                try self.sendPong(writer, frame.payload);
            },
            .pong => {
                // Update ping timestamp
                self.updatePing();
            },
            .close => {
                // Connection closing
                self.state = .closed;
                return false; // Signal to close connection
            },
            else => {
                // Ignore other frame types
            },
        }
        return true; // Keep connection alive
    }

    // Handle text messages (subscription commands)
    fn handleTextMessage(self: *WebSocketClient, payload: []const u8, _: anytype) !void {
        // Parse JSON message for subscription commands
        var json_parser = std.json.Parser.init(self.allocator, false);
        defer json_parser.deinit();

        const parsed = try json_parser.parse(payload);
        defer parsed.deinit();

        const root = parsed.root.Object;

        // Handle subscription messages
        if (root.get("type")) |type_value| {
            if (std.mem.eql(u8, type_value.String, "subscribe")) {
                if (root.get("stream")) |stream_value| {
                    const stream_name = stream_value.String;
                    if (std.mem.eql(u8, stream_name, "public")) {
                        try self.subscribe(self.allocator, Stream.public);
                    } else if (std.mem.eql(u8, stream_name, "public:local")) {
                        try self.subscribe(self.allocator, Stream.@"public:local");
                    } else if (std.mem.startsWith(u8, stream_name, "hashtag:")) {
                        const tag = stream_name["hashtag:".len..];
                        const tag_dup = try self.allocator.dupe(u8, tag);
                        defer self.allocator.free(tag_dup);
                        const hashtag_stream = try Stream.hashtagStream(tag_dup, self.allocator);
                        defer self.allocator.free(hashtag_stream);
                        try self.subscribe(self.allocator, hashtag_stream);
                    } else if (std.mem.eql(u8, stream_name, "user")) {
                        try self.subscribe(self.allocator, Stream.user);
                    } else if (std.mem.startsWith(u8, stream_name, "list:")) {
                        const list_id_str = stream_name["list:".len..];
                        const list_id = try std.fmt.parseInt(i64, list_id_str, 10);
                        const list_stream = try Stream.listStream(list_id, self.allocator);
                        defer self.allocator.free(list_stream);
                        try self.subscribe(self.allocator, list_stream);
                    }
                }
            } else if (std.mem.eql(u8, type_value.String, "unsubscribe")) {
                if (root.get("stream")) |stream_value| {
                    const stream_name = stream_value.String;
                    if (std.mem.eql(u8, stream_name, "public")) {
                        self.unsubscribe(Stream.public);
                    } else if (std.mem.eql(u8, stream_name, "public:local")) {
                        self.unsubscribe(Stream.@"public:local");
                    } else if (std.mem.startsWith(u8, stream_name, "hashtag:")) {
                        const tag = stream_name["hashtag:".len..];
                        const tag_dup = try self.allocator.dupe(u8, tag);
                        defer self.allocator.free(tag_dup);
                        const hashtag_stream = try Stream.hashtagStream(tag_dup, self.allocator);
                        defer self.allocator.free(hashtag_stream);
                        self.unsubscribe(hashtag_stream);
                    } else if (std.mem.eql(u8, stream_name, "user")) {
                        self.unsubscribe(Stream.user);
                    } else if (std.mem.startsWith(u8, stream_name, "list:")) {
                        const list_id_str = stream_name["list:".len..];
                        const list_id = try std.fmt.parseInt(i64, list_id_str, 10);
                        const list_stream = try Stream.listStream(list_id, self.allocator);
                        defer self.allocator.free(list_stream);
                        self.unsubscribe(list_stream);
                    }
                }
            }
        }
    }

    pub fn updatePing(self: *WebSocketClient) void {
        self.last_ping = std.time.timestamp();
    }

    pub fn subscribe(self: *WebSocketClient, allocator: std.mem.Allocator, stream: []const u8) !void {
        // Check if already subscribed
        for (self.streams.items) |existing_stream| {
            if (std.mem.eql(u8, existing_stream, stream)) return;
        }

        try self.streams.append(try allocator.dupe(u8, stream));
    }

    pub fn unsubscribe(self: *WebSocketClient, stream: []const u8) void {
        for (self.streams.items, 0..) |existing_stream, i| {
            if (std.mem.eql(u8, existing_stream, stream)) {
                // Remove this stream
                std.mem.copyForwards([]const u8, self.streams.items[i .. self.streams.items.len - 1], self.streams.items[i + 1 ..]);
                self.streams.items.len -= 1;
                break;
            }
        }
    }

    pub fn isSubscribed(self: *WebSocketClient, stream: []const u8) bool {
        for (self.streams.items) |existing_stream| {
            if (std.mem.eql(u8, existing_stream, stream)) return true;
        }
        return false;
    }
};

// WebSocket server for managing connections
pub const WebSocketServer = struct {
    allocator: std.mem.Allocator,
    clients: std.StringHashMap(WebSocketClient),
    mutex: std.Thread.Mutex,

    pub fn init(allocator: std.mem.Allocator) WebSocketServer {
        return WebSocketServer{
            .allocator = allocator,
            .clients = std.StringHashMap(WebSocketClient).init(allocator),
            .mutex = std.Thread.Mutex{},
        };
    }

    pub fn deinit(self: *WebSocketServer) void {
        var iter = self.clients.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.clients.deinit();
    }

    // Add a new client connection
    pub fn addClient(self: *WebSocketServer, client: WebSocketClient) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        try self.clients.put(client.id, client);
        std.debug.print("WebSocket client {} connected (total: {})\n", .{ client.id, self.clients.count() });
    }

    // Remove a client connection
    pub fn removeClient(self: *WebSocketServer, client_id: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.clients.fetchRemove(client_id)) |kv| {
            kv.value.deinit(self.allocator);
            std.debug.print("WebSocket client {} disconnected (total: {})\n", .{ client_id, self.clients.count() });
        }
    }

    // Broadcast event to all subscribed clients
    pub fn broadcastEvent(self: *WebSocketServer, allocator: std.mem.Allocator, event: StreamEvent) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const event_json = try std.json.stringifyAlloc(allocator, .{
            .event = event.event.toString(),
            .payload = event.payload,
            .stream = event.stream,
        }, .{});
        defer allocator.free(event_json);

        var iter = self.clients.iterator();
        var clients_to_remove = std.array_list.Managed([]const u8).init(allocator);
        defer clients_to_remove.deinit();

        while (iter.next()) |entry| {
            const client = entry.value_ptr;
            if (client.isSubscribed(event.stream)) {
                // In a real implementation, you'd send the WebSocket frame here
                // For now, just log it
                std.debug.print("Sending event to client {}: {}\n", .{ client.id, event_json });
            }

            // Check for stale connections (no ping in 5 minutes)
            const now = std.time.timestamp();
            if (now - client.last_ping > 300) {
                try clients_to_remove.append(try allocator.dupe(u8, client.id));
            }
        }

        // Remove stale connections
        for (clients_to_remove.items) |client_id| {
            allocator.free(client_id);
        }
        // Note: In real implementation, you'd clean up stale connections here
    }

    // Send event to specific user
    pub fn sendToUser(self: *WebSocketServer, allocator: std.mem.Allocator, user_id: i64, event: StreamEvent) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const event_json = try std.json.stringifyAlloc(allocator, .{
            .event = event.event.toString(),
            .payload = event.payload,
            .stream = event.stream,
        }, .{});
        defer allocator.free(event_json);

        var iter = self.clients.iterator();
        while (iter.next()) |entry| {
            const client = entry.value_ptr;
            if (client.user_id == user_id and client.isSubscribed(event.stream)) {
                // Send to this client
                std.debug.print("Sending event to user {}: {}\n", .{ user_id, event_json });
            }
        }
    }

    // Update client ping time
    pub fn updatePing(self: *WebSocketServer, client_id: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.clients.getPtr(client_id)) |client| {
            client.last_ping = std.time.timestamp();
        }
    }
};

// Stream names (Mastodon-style)
pub const Stream = struct {
    pub const public = "public";
    pub const @"public:local" = "public:local";
    pub const @"public:remote" = "public:remote";
    pub const hashtag = "hashtag";
    pub const @"hashtag:local" = "hashtag:local";
    pub const user = "user";
    pub const @"user:notification" = "user:notification";
    pub const list = "list";
    pub const direct = "direct";

    pub fn userStream(user_id: i64, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "user:{d}", .{user_id});
    }

    pub fn userNotifications(user_id: i64, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "user:{d}:notification", .{user_id});
    }

    pub fn hashtagStream(tag: []const u8, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "hashtag:{s}", .{tag});
    }

    pub fn listStream(list_id: i64, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "list:{d}", .{list_id});
    }
};

// Event broadcasting helpers
pub fn broadcastPost(server: *WebSocketServer, allocator: std.mem.Allocator, post: database.Post, author_username: []const u8) !void {
    // Broadcast to public streams
    const public_event = StreamEvent{
        .event = .update,
        .payload = try createPostPayload(allocator, post, author_username),
        .stream = Stream.public,
    };
    defer public_event.deinit(allocator);

    try server.broadcastEvent(allocator, public_event);

    // Broadcast to author's followers
    // TODO: Get followers and send to user streams
}

pub fn broadcastNotification(server: *WebSocketServer, allocator: std.mem.Allocator, user_id: i64, notification: anytype) !void {
    const stream = try Stream.userNotifications(user_id, allocator);
    defer allocator.free(stream);

    const payload = try std.json.stringifyAlloc(allocator, notification, .{});
    defer allocator.free(payload);

    const event = StreamEvent{
        .event = .notification,
        .payload = payload,
        .stream = stream,
    };

    try server.sendToUser(allocator, user_id, event);
}

pub fn broadcastDelete(server: *WebSocketServer, allocator: std.mem.Allocator, post_id: i64) !void {
    const payload = try std.fmt.allocPrint(allocator, "{{\"id\": \"{}\"}}", .{post_id});
    defer allocator.free(payload);

    const event = StreamEvent{
        .event = .delete,
        .payload = payload,
        .stream = Stream.public,
    };

    try server.broadcastEvent(allocator, event);
}

// Helper to create post payload for streaming
fn createPostPayload(allocator: std.mem.Allocator, post: database.Post, author_username: []const u8) ![]u8 {
    const payload = struct {
        id: []const u8,
        content: []const u8,
        created_at: []const u8,
        account: struct {
            id: []const u8,
            username: []const u8,
            display_name: []const u8,
        },
        visibility: []const u8,
    }{
        .id = try std.fmt.allocPrint(allocator, "{}", .{post.id}),
        .content = post.content,
        .created_at = post.created_at,
        .account = .{
            .id = try std.fmt.allocPrint(allocator, "{}", .{post.user_id}),
            .username = author_username,
            .display_name = author_username, // TODO: Get actual display name
        },
        .visibility = post.visibility,
    };
    defer allocator.free(payload.id);
    defer allocator.free(payload.account.id);

    return std.json.stringifyAlloc(allocator, payload, .{});
}

// WebSocket upgrade handling
pub fn handleWebSocketUpgrade(allocator: std.mem.Allocator, request: anytype) !?WebSocketClient {
    // Check for WebSocket upgrade headers
    const upgrade_header = request.head.get("upgrade") orelse return null;
    const connection_header = request.head.get("connection") orelse return null;
    const sec_websocket_key = request.head.get("sec-websocket-key") orelse return null;
    const sec_websocket_version = request.head.get("sec-websocket-version") orelse return null;

    if (!std.ascii.eqlIgnoreCase(upgrade_header, "websocket")) return null;
    if (!std.ascii.eqlIgnoreCase(connection_header, "upgrade")) return null;
    if (!std.mem.eql(u8, sec_websocket_version, "13")) return null;

    // Generate WebSocket accept key
    const accept_key = try generateWebSocketAccept(allocator, sec_websocket_key);
    defer allocator.free(accept_key);

    // TODO: Send 101 Switching Protocols response with accept key

    // Create client
    const client_id = try generateClientId(allocator);
    return try WebSocketClient.init(allocator, client_id, null); // TODO: Set user_id from auth
}

// Generate WebSocket accept key
fn generateWebSocketAccept(allocator: std.mem.Allocator, key: []const u8) ![]u8 {
    const magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    const combined = try std.fmt.allocPrint(allocator, "{s}{s}", .{ key, magic_string });
    defer allocator.free(combined);

    var hash: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(combined, &hash);

    // Base64 encode
    const encoded_len = std.base64.standard.Encoder.calcSize(hash.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    _ = std.base64.standard.Encoder.encode(encoded, &hash);

    return encoded;
}

// Note: generateClientId is defined earlier in this file (line 266)
