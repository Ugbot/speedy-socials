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

pub const http = struct {
    pub const parser = @import("http/parser.zig");
    pub const request = @import("http/request.zig");
    pub const response = @import("http/response.zig");
    pub const response_stream = @import("http/response_stream.zig");
    pub const router = @import("http/router.zig");
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
    _ = http.parser;
    _ = http.request;
    _ = http.response;
    _ = http.response_stream;
    _ = http.router;
}
