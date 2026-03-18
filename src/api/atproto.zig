//! AT Protocol HTTP adapter
//!
//! Thin layer between the std.http server and the atproto library.
//! Constructs XrpcInput from HTTP requests, calls the library router,
//! and maps XrpcOutput back to HTTP responses.

const std = @import("std");
const http = std.http;
const atproto = @import("atproto");

/// Server-side AT Protocol context, initialized once at startup.
pub const AtprotoContext = struct {
    storage: atproto.Storage,
    config: atproto.PdsConfig,
    mem_storage: *atproto.MemoryStorage,

    pub fn init(allocator: std.mem.Allocator) AtprotoContext {
        const mem = allocator.create(atproto.MemoryStorage) catch @panic("Failed to allocate AT Proto storage");
        mem.* = atproto.MemoryStorage.init(allocator);
        return .{
            .storage = mem.storage(),
            .config = .{
                .did = "did:web:speedy-socials.local",
                .hostname = "speedy-socials.local",
                .service_endpoint = "https://speedy-socials.local",
                .available_user_domains = &.{".local"},
                .jwt_secret = "speedy-socials-jwt-secret-change-in-production",
            },
            .mem_storage = mem,
        };
    }

    pub fn deinit(self: *AtprotoContext, allocator: std.mem.Allocator) void {
        self.mem_storage.deinit();
        allocator.destroy(self.mem_storage);
    }
};

/// Global context — initialized in init(), used by handler functions.
var global_ctx: ?AtprotoContext = null;

pub fn initGlobal(allocator: std.mem.Allocator) void {
    global_ctx = AtprotoContext.init(allocator);
}

pub fn deinitGlobal(allocator: std.mem.Allocator) void {
    if (global_ctx) |*ctx| {
        ctx.deinit(allocator);
        global_ctx = null;
    }
}

/// Handle /.well-known/atproto-did — returns the DID as plain text.
pub fn handleAtprotoDid(allocator: std.mem.Allocator, response: anytype) !void {
    _ = allocator;
    const ctx = global_ctx orelse {
        try response.writer.writeAll("{\"error\":\"AT Protocol not initialized\"}");
        return;
    };
    const did = atproto.well_known.atprotoDid(ctx.config);
    try response.writer.writeAll(did);
}

/// Handle /xrpc/* — dispatch to the atproto library router.
pub fn handleXrpc(allocator: std.mem.Allocator, response: anytype, method: http.Method, path: []const u8, request: *http.Server.Request) !void {
    const ctx = global_ctx orelse {
        try response.writer.writeAll("{\"error\":\"AT Protocol not initialized\"}");
        return;
    };

    // Extract XRPC method name from path: /xrpc/com.atproto.server.describeServer
    const xrpc_method = if (std.mem.startsWith(u8, path, "/xrpc/"))
        path[6..]
    else
        path;

    // Strip query string if present
    const method_name = if (std.mem.indexOf(u8, xrpc_method, "?")) |qi|
        xrpc_method[0..qi]
    else
        xrpc_method;

    // Build XrpcInput from the HTTP request
    var input = atproto.XrpcInput{};

    // Read POST/PUT body if present
    var body_buf: ?[]u8 = null;
    defer if (body_buf) |b| allocator.free(b);
    if (method == .POST or method == .PUT) {
        var read_buf: [8192]u8 = undefined;
        const reader = request.readerExpectNone(&read_buf);
        body_buf = reader.allocRemaining(allocator, std.io.Limit.limited(1024 * 1024)) catch null;
        input.body = body_buf;
    }

    // Parse query parameters from the target URL
    var params: std.StringHashMapUnmanaged([]const u8) = .empty;
    defer params.deinit(allocator);

    const target = request.head.target;
    if (std.mem.indexOf(u8, target, "?")) |qi| {
        const query = target[qi + 1 ..];
        var pairs = std.mem.splitScalar(u8, query, '&');
        while (pairs.next()) |pair| {
            if (std.mem.indexOf(u8, pair, "=")) |eq| {
                params.put(allocator, pair[0..eq], pair[eq + 1 ..]) catch {};
            }
        }
    }
    input.params = params;

    // Extract authorization header
    var headers = request.iterateHeaders();
    while (headers.next()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "authorization")) {
            input.auth_token = h.value;
            break;
        }
    }

    // Dispatch to the library
    const output = try atproto.router.dispatch(method_name, allocator, ctx.storage, ctx.config, input);

    // Map output to HTTP response
    switch (output) {
        .success => |s| {
            try response.writer.writeAll(s.body);
            // Free body if it was allocated by the library
            if (s.body.len > 0 and s.body.ptr != "{}"[0..2].ptr) {
                allocator.free(s.body);
            }
        },
        .blob => |b| {
            try response.writer.writeAll(b.data);
        },
        .err => |e| {
            const err_json = try e.toJson(allocator);
            defer allocator.free(err_json);
            try response.writer.writeAll(err_json);
        },
    }
}
