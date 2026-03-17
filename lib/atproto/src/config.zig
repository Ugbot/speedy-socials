const std = @import("std");

/// Configuration for an AT Protocol Personal Data Server (PDS).
/// Passed to XRPC handlers to provide server identity and settings.
pub const PdsConfig = struct {
    /// Server DID (e.g., "did:web:example.com").
    did: []const u8,
    /// Server hostname (e.g., "example.com").
    hostname: []const u8,
    /// HTTPS service endpoint (e.g., "https://example.com").
    service_endpoint: []const u8,
    /// Domains available for user handle registration.
    available_user_domains: []const []const u8,
    /// Whether an invite code is required to create an account.
    invite_code_required: bool = false,
    /// Whether phone verification is required.
    phone_verification_required: bool = false,
    /// HMAC secret for signing session JWTs.
    jwt_secret: []const u8,
    /// Access token lifetime in seconds (default 30 minutes).
    access_token_ttl: i64 = 1800,
    /// Refresh token lifetime in seconds (default 90 days).
    refresh_token_ttl: i64 = 7776000,

    /// Generate the AT-URI prefix for this server's DID.
    pub fn atUriPrefix(self: PdsConfig) []const u8 {
        return self.did;
    }

    /// Build a did:web DID from the hostname.
    pub fn didFromHostname(hostname: []const u8, allocator: std.mem.Allocator) ![]const u8 {
        return std.fmt.allocPrint(allocator, "did:web:{s}", .{hostname});
    }
};

test "didFromHostname" {
    const did = try PdsConfig.didFromHostname("example.com", std.testing.allocator);
    defer std.testing.allocator.free(did);
    try std.testing.expectEqualStrings("did:web:example.com", did);
}
