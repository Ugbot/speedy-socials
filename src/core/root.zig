//! Public surface of the Tiger core, re-exported for plugins and the
//! composition root.

pub const limits = @import("limits.zig");
pub const assert = @import("assert.zig");
pub const errors = @import("errors.zig");
pub const static = @import("static.zig");
pub const arena = @import("arena.zig");
pub const clock = @import("clock.zig");
pub const rng = @import("rng.zig");
pub const plugin = @import("plugin.zig");
pub const connection = @import("connection.zig");
pub const server = @import("server.zig");
pub const storage = @import("storage.zig");
pub const log = @import("log.zig");
pub const metrics = @import("metrics.zig");
pub const shutdown = @import("shutdown.zig");
pub const health = @import("health.zig");

pub const http = struct {
    pub const parser = @import("http/parser.zig");
    pub const request = @import("http/request.zig");
    pub const response = @import("http/response.zig");
    pub const response_stream = @import("http/response_stream.zig");
    pub const router = @import("http/router.zig");
};

pub const ws = struct {
    pub const handshake = @import("ws/handshake.zig");
    pub const frame = @import("ws/frame.zig");
    pub const messages = @import("ws/messages.zig");
    pub const event_ring = @import("ws/event_ring.zig");
    pub const registry = @import("ws/registry.zig");
};

test {
    _ = limits;
    _ = assert;
    _ = errors;
    _ = static;
    _ = arena;
    _ = clock;
    _ = rng;
    _ = plugin;
    _ = connection;
    _ = server;
    _ = storage;
    _ = log;
    _ = metrics;
    _ = shutdown;
    _ = health;
    _ = http.parser;
    _ = http.request;
    _ = http.response;
    _ = http.response_stream;
    _ = http.router;
    _ = ws.handshake;
    _ = ws.frame;
    _ = ws.messages;
    _ = ws.event_ring;
    _ = ws.registry;
}
