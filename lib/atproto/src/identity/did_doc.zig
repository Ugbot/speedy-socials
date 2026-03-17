const std = @import("std");

/// DID document for serving from a PDS.
pub const DidDocument = struct {
    id: []const u8,
    also_known_as: []const []const u8,
    verification_method: []const VerificationMethod,
    service: []const Service,
};

pub const VerificationMethod = struct {
    id: []const u8,
    type_name: []const u8,
    controller: []const u8,
    public_key_multibase: []const u8,
};

pub const Service = struct {
    id: []const u8,
    type_name: []const u8,
    service_endpoint: []const u8,
};

/// Generate a DID document for did:web.
pub fn generateDidWeb(
    allocator: std.mem.Allocator,
    did: []const u8,
    handle: []const u8,
    public_key_multibase: []const u8,
    pds_endpoint: []const u8,
) ![]const u8 {
    const at_uri = try std.fmt.allocPrint(allocator, "at://{s}", .{handle});
    defer allocator.free(at_uri);

    const vm_id = try std.fmt.allocPrint(allocator, "{s}#atproto", .{did});
    defer allocator.free(vm_id);

    return std.json.Stringify.valueAlloc(allocator, .{
        .@"@context" = &[_][]const u8{
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1",
        },
        .id = did,
        .alsoKnownAs = &[_][]const u8{at_uri},
        .verificationMethod = &[_]struct {
            id: []const u8,
            type: []const u8,
            controller: []const u8,
            publicKeyMultibase: []const u8,
        }{.{
            .id = vm_id,
            .type = "Multikey",
            .controller = did,
            .publicKeyMultibase = public_key_multibase,
        }},
        .service = &[_]struct {
            id: []const u8,
            type: []const u8,
            serviceEndpoint: []const u8,
        }{.{
            .id = "#atproto_pds",
            .type = "AtprotoPersonalDataServer",
            .serviceEndpoint = pds_endpoint,
        }},
    }, .{});
}

test "generateDidWeb includes required fields" {
    const allocator = std.testing.allocator;
    const doc = try generateDidWeb(
        allocator,
        "did:web:example.com",
        "alice.example.com",
        "zDnaeVpCqkbjR4Nz6GKkqVnfPkp7fX3LKuqUwMYrVRtBJaJW",
        "https://example.com",
    );
    defer allocator.free(doc);

    // Verify key fields are present
    try std.testing.expect(std.mem.indexOf(u8, doc, "did:web:example.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, doc, "#atproto_pds") != null);
    try std.testing.expect(std.mem.indexOf(u8, doc, "AtprotoPersonalDataServer") != null);
    try std.testing.expect(std.mem.indexOf(u8, doc, "Multikey") != null);
    try std.testing.expect(std.mem.indexOf(u8, doc, "#atproto") != null);
    try std.testing.expect(std.mem.indexOf(u8, doc, "at://alice.example.com") != null);
}
