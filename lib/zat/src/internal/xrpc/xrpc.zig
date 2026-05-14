//! XRPC Client - AT Protocol RPC calls
//!
//! simplifies calling AT Protocol endpoints.
//! handles query (GET) and procedure (POST) methods.
//!
//! see: https://atproto.com/specs/xrpc

const std = @import("std");
const Nsid = @import("../syntax/nsid.zig").Nsid;
const HttpTransport = @import("transport.zig").HttpTransport;

pub const XrpcClient = struct {
    allocator: std.mem.Allocator,
    transport: HttpTransport,

    /// pds or appview host (e.g., "https://bsky.social")
    host: []const u8,

    /// bearer token for authenticated requests
    access_token: ?[]const u8 = null,

    /// atproto JWTs are ~1KB; buffer needs room for "Bearer " prefix
    const max_auth_header_len = 2048;

    pub fn init(allocator: std.mem.Allocator, host: []const u8) XrpcClient {
        return .{
            .allocator = allocator,
            .transport = HttpTransport.init(allocator),
            .host = host,
        };
    }

    pub fn deinit(self: *XrpcClient) void {
        self.transport.deinit();
    }

    /// set bearer token for authenticated requests
    pub fn setAuth(self: *XrpcClient, token: []const u8) void {
        self.access_token = token;
    }

    /// call a query method (GET)
    pub fn query(self: *XrpcClient, nsid: Nsid, params: ?std.StringHashMap([]const u8)) !Response {
        const url = try self.buildUrl(nsid, params);
        defer self.allocator.free(url);

        return try self.doRequest(url, null);
    }

    /// call a procedure method (POST)
    pub fn procedure(self: *XrpcClient, nsid: Nsid, body: ?[]const u8) !Response {
        const url = try self.buildUrl(nsid, null);
        defer self.allocator.free(url);

        return try self.doRequest(url, body);
    }

    fn buildUrl(self: *XrpcClient, nsid: Nsid, params: ?std.StringHashMap([]const u8)) ![]u8 {
        var url: std.ArrayList(u8) = .empty;
        errdefer url.deinit(self.allocator);

        try url.appendSlice(self.allocator, self.host);
        try url.appendSlice(self.allocator, "/xrpc/");
        try url.appendSlice(self.allocator, nsid.raw);

        if (params) |p| {
            var first = true;
            var it = p.iterator();
            while (it.next()) |entry| {
                try url.append(self.allocator, if (first) '?' else '&');
                first = false;
                try url.appendSlice(self.allocator, entry.key_ptr.*);
                try url.append(self.allocator, '=');
                // url encode value
                for (entry.value_ptr.*) |c| {
                    if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~') {
                        try url.append(self.allocator, c);
                    } else {
                        try url.print(self.allocator, "%{X:0>2}", .{c});
                    }
                }
            }
        }

        return try url.toOwnedSlice(self.allocator);
    }

    fn doRequest(self: *XrpcClient, url: []const u8, body: ?[]const u8) !Response {
        var auth_header_buf: [max_auth_header_len]u8 = undefined;
        const auth_value: ?[]const u8 = if (self.access_token) |token|
            std.fmt.bufPrint(&auth_header_buf, "Bearer {s}", .{token}) catch null
        else
            null;

        const result = try self.transport.fetch(.{
            .url = url,
            .method = if (body != null) .POST else .GET,
            .payload = body,
            .authorization = auth_value,
        });

        return .{
            .allocator = self.allocator,
            .status = result.status,
            .body = result.body,
        };
    }

    pub const Response = struct {
        allocator: std.mem.Allocator,
        status: std.http.Status,
        body: []u8,

        pub fn deinit(self: *Response) void {
            self.allocator.free(self.body);
        }

        /// check if request succeeded
        pub fn ok(self: Response) bool {
            return self.status == .ok;
        }

        /// parse body as json
        pub fn json(self: Response) !std.json.Parsed(std.json.Value) {
            return try std.json.parseFromSlice(std.json.Value, self.allocator, self.body, .{});
        }
    };
};

// === tests ===

test "build url without params" {
    var client = XrpcClient.init(std.testing.allocator, "https://bsky.social");
    defer client.deinit();

    const nsid = Nsid.parse("app.bsky.actor.getProfile").?;
    const url = try client.buildUrl(nsid, null);
    defer std.testing.allocator.free(url);

    try std.testing.expectEqualStrings("https://bsky.social/xrpc/app.bsky.actor.getProfile", url);
}

test "build url with params" {
    var client = XrpcClient.init(std.testing.allocator, "https://bsky.social");
    defer client.deinit();

    var params = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer params.deinit();
    try params.put("actor", "did:plc:test123");

    const nsid = Nsid.parse("app.bsky.actor.getProfile").?;
    const url = try client.buildUrl(nsid, params);
    defer std.testing.allocator.free(url);

    try std.testing.expect(std.mem.startsWith(u8, url, "https://bsky.social/xrpc/app.bsky.actor.getProfile?"));
    try std.testing.expect(std.mem.indexOf(u8, url, "actor=did%3Aplc%3Atest123") != null);
}
