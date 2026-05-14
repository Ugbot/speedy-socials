//! Handle Resolver - resolve handles to DIDs
//!
//! resolves AT Protocol handles via HTTP:
//! https://{handle}/.well-known/atproto-did
//!
//! note: DNS TXT resolution (_atproto.{handle}) not yet implemented
//! as zig std doesn't provide TXT record lookup.
//!
//! see: https://atproto.com/specs/handle

const std = @import("std");
const Handle = @import("../syntax/handle.zig").Handle;
const Did = @import("../syntax/did.zig").Did;
const HttpTransport = @import("../xrpc/transport.zig").HttpTransport;

pub const HandleResolver = struct {
    allocator: std.mem.Allocator,
    transport: HttpTransport,
    doh_endpoint: []const u8,

    pub fn init(allocator: std.mem.Allocator) HandleResolver {
        return .{
            .allocator = allocator,
            .transport = HttpTransport.init(allocator),
            .doh_endpoint = "https://cloudflare-dns.com/dns-query",
        };
    }

    pub fn deinit(self: *HandleResolver) void {
        self.transport.deinit();
    }

    /// resolve a handle to a DID via HTTP well-known
    pub fn resolve(self: *HandleResolver, handle: Handle) ![]const u8 {
        if (self.resolveHttp(handle)) |did| {
            return did;
        } else |_| {
            return try self.resolveDns(handle);
        }
    }

    /// resolve via HTTP at https://{handle}/.well-known/atproto-did
    fn resolveHttp(self: *HandleResolver, handle: Handle) ![]const u8 {
        const url = try std.fmt.allocPrint(
            self.allocator,
            "https://{s}/.well-known/atproto-did",
            .{handle.str()},
        );
        defer self.allocator.free(url);

        const result = self.transport.fetch(.{ .url = url }) catch return error.HttpResolutionFailed;
        defer self.allocator.free(result.body);

        if (result.status != .ok) {
            return error.HttpResolutionFailed;
        }

        // response body should be the DID as plain text
        const did_str = std.mem.trim(u8, result.body, &std.ascii.whitespace);

        // validate it's a proper DID
        if (Did.parse(did_str) == null) {
            return error.InvalidDidInResponse;
        }

        return try self.allocator.dupe(u8, did_str);
    }

    /// resolve via DoH default: https://cloudflare-dns.com/dns-query
    pub fn resolveDns(self: *HandleResolver, handle: Handle) ![]const u8 {
        const dns_name = try std.fmt.allocPrint(
            self.allocator,
            "_atproto.{s}",
            .{handle.str()},
        );
        defer self.allocator.free(dns_name);

        const url = try std.fmt.allocPrint(
            self.allocator,
            "{s}?name={s}&type=TXT",
            .{ self.doh_endpoint, dns_name },
        );
        defer self.allocator.free(url);

        const result = self.transport.fetch(.{
            .url = url,
            .accept = "application/dns-json",
        }) catch return error.DnsResolutionFailed;
        defer self.allocator.free(result.body);

        if (result.status != .ok) {
            return error.DnsResolutionFailed;
        }

        const parsed = std.json.parseFromSlice(
            DnsResponse,
            self.allocator,
            result.body,
            .{},
        ) catch return error.InvalidDnsResponse;
        defer parsed.deinit();

        const dns_response = parsed.value;
        if (dns_response.Answer == null or dns_response.Answer.?.len == 0) {
            return error.NoDnsRecordsFound;
        }

        for (dns_response.Answer.?) |answer| {
            const data = answer.data orelse continue;
            const did_str = extractDidFromTxt(data) orelse continue;

            if (Did.parse(did_str) != null) {
                return try self.allocator.dupe(u8, did_str);
            }
        }

        return error.NoValidDidFound;
    }
};

fn extractDidFromTxt(txt_data: []const u8) ?[]const u8 {
    var data = txt_data;
    if (data.len >= 2 and data[0] == '"' and data[data.len - 1] == '"') {
        data = data[1 .. data.len - 1];
    }

    const prefix = "did=";
    if (std.mem.startsWith(u8, data, prefix)) {
        return data[prefix.len..];
    }

    return null;
}

const DnsResponse = struct {
    Status: i32,
    TC: bool,
    RD: bool,
    RA: bool,
    AD: bool,
    CD: bool,
    Question: ?[]Question = null,
    Answer: ?[]Answer = null,
};

const Question = struct {
    name: []const u8,
    type: i32,
};

const Answer = struct {
    name: []const u8,
    type: i32,
    TTL: i32,
    data: ?[]const u8 = null,
};

// === integration tests ===
// these actually hit the network - run with: zig test src/internal/handle_resolver.zig

test "resolve handle (http) - integration" {
    // use arena for http client internals that may leak
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var resolver = HandleResolver.init(arena.allocator());
    defer resolver.deinit();

    // resolve a known handle that has .well-known/atproto-did
    const handle = Handle.parse("jay.bsky.social") orelse return error.InvalidHandle;
    const did = resolver.resolveHttp(handle) catch |err| {
        // network errors are ok in CI without network access
        std.debug.print("network error (expected in some CI): {}\n", .{err});
        return;
    };

    // should be a valid did:plc
    try std.testing.expect(Did.parse(did) != null);
    try std.testing.expect(std.mem.startsWith(u8, did, "did:plc:"));
}

test "resolve handle (dns over http) - integration" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var resolver = HandleResolver.init(arena.allocator());
    defer resolver.deinit();

    const handle = Handle.parse("seiso.moe") orelse return error.InvalidHandle;
    const did = resolver.resolveDns(handle) catch |err| {
        // network errors are ok in CI without network access
        std.debug.print("network error (expected in some CI): {}\n", .{err});
        return;
    };

    // should be a valid DID
    try std.testing.expect(Did.parse(did) != null);
    try std.testing.expect(std.mem.startsWith(u8, did, "did:"));
}

test "resolve handle - integration" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var resolver = HandleResolver.init(arena.allocator());
    defer resolver.deinit();

    const handle = Handle.parse("jay.bsky.social") orelse return error.InvalidHandle;
    const did = resolver.resolve(handle) catch |err| {
        // network errors are ok in CI without network access
        std.debug.print("network error (expected in some CI): {}\n", .{err});
        return;
    };

    // should be a valid DID
    try std.testing.expect(Did.parse(did) != null);
    try std.testing.expect(std.mem.startsWith(u8, did, "did:"));
}
