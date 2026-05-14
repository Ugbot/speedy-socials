//! DID Document - resolved identity information
//!
//! a did document contains:
//! - handle (from alsoKnownAs)
//! - signing key (from verificationMethod)
//! - pds endpoint (from service)
//!
//! see: https://atproto.com/specs/did

const std = @import("std");
const Did = @import("../syntax/did.zig").Did;

pub const DidDocument = struct {
    allocator: std.mem.Allocator,

    /// the did this document describes
    id: []const u8,

    /// handles (from alsoKnownAs, stripped of at:// prefix)
    handles: [][]const u8,

    /// verification methods (signing keys)
    verification_methods: []VerificationMethod,

    /// services (pds endpoints)
    services: []Service,

    pub const VerificationMethod = struct {
        id: []const u8,
        type: []const u8,
        controller: []const u8,
        public_key_multibase: []const u8,
    };

    pub const Service = struct {
        id: []const u8,
        type: []const u8,
        service_endpoint: []const u8,
    };

    /// get the primary handle (first valid one)
    pub fn handle(self: DidDocument) ?[]const u8 {
        if (self.handles.len == 0) return null;
        return self.handles[0];
    }

    /// get the atproto signing key
    pub fn signingKey(self: DidDocument) ?VerificationMethod {
        for (self.verification_methods) |vm| {
            if (std.mem.endsWith(u8, vm.id, "#atproto")) {
                return vm;
            }
        }
        return null;
    }

    /// get the pds endpoint
    pub fn pdsEndpoint(self: DidDocument) ?[]const u8 {
        for (self.services) |svc| {
            if (std.mem.endsWith(u8, svc.id, "#atproto_pds")) {
                return svc.service_endpoint;
            }
        }
        return null;
    }

    /// parse a did document from json
    pub fn parse(allocator: std.mem.Allocator, json_str: []const u8) !DidDocument {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json_str, .{});
        defer parsed.deinit();

        return try parseValue(allocator, parsed.value);
    }

    /// parse from an already-parsed json value
    pub fn parseValue(allocator: std.mem.Allocator, root: std.json.Value) !DidDocument {
        if (root != .object) return error.InvalidDidDocument;
        const obj = root.object;

        // id is required
        const id = if (obj.get("id")) |v| switch (v) {
            .string => |s| try allocator.dupe(u8, s),
            else => return error.InvalidDidDocument,
        } else return error.InvalidDidDocument;
        errdefer allocator.free(id);

        // parse alsoKnownAs -> handles
        var handles: std.ArrayList([]const u8) = .empty;
        errdefer {
            for (handles.items) |h| allocator.free(h);
            handles.deinit(allocator);
        }

        if (obj.get("alsoKnownAs")) |aka| {
            if (aka == .array) {
                for (aka.array.items) |item| {
                    if (item == .string) {
                        const s = item.string;
                        // strip at:// prefix if present
                        const h = if (std.mem.startsWith(u8, s, "at://"))
                            s[5..]
                        else
                            s;
                        try handles.append(allocator, try allocator.dupe(u8, h));
                    }
                }
            }
        }

        // parse verificationMethod
        var vms: std.ArrayList(VerificationMethod) = .empty;
        errdefer {
            for (vms.items) |vm| {
                allocator.free(vm.id);
                allocator.free(vm.type);
                allocator.free(vm.controller);
                allocator.free(vm.public_key_multibase);
            }
            vms.deinit(allocator);
        }

        if (obj.get("verificationMethod")) |vm_arr| {
            if (vm_arr == .array) {
                for (vm_arr.array.items) |item| {
                    if (item == .object) {
                        const vm_obj = item.object;
                        const vm = VerificationMethod{
                            .id = try allocator.dupe(u8, getStr(vm_obj, "id") orelse continue),
                            .type = try allocator.dupe(u8, getStr(vm_obj, "type") orelse ""),
                            .controller = try allocator.dupe(u8, getStr(vm_obj, "controller") orelse ""),
                            .public_key_multibase = try allocator.dupe(u8, getStr(vm_obj, "publicKeyMultibase") orelse ""),
                        };
                        try vms.append(allocator, vm);
                    }
                }
            }
        }

        // parse service
        var svcs: std.ArrayList(Service) = .empty;
        errdefer {
            for (svcs.items) |svc| {
                allocator.free(svc.id);
                allocator.free(svc.type);
                allocator.free(svc.service_endpoint);
            }
            svcs.deinit(allocator);
        }

        if (obj.get("service")) |svc_arr| {
            if (svc_arr == .array) {
                for (svc_arr.array.items) |item| {
                    if (item == .object) {
                        const svc_obj = item.object;
                        const svc = Service{
                            .id = try allocator.dupe(u8, getStr(svc_obj, "id") orelse continue),
                            .type = try allocator.dupe(u8, getStr(svc_obj, "type") orelse ""),
                            .service_endpoint = try allocator.dupe(u8, getStr(svc_obj, "serviceEndpoint") orelse ""),
                        };
                        try svcs.append(allocator, svc);
                    }
                }
            }
        }

        return .{
            .allocator = allocator,
            .id = id,
            .handles = try handles.toOwnedSlice(allocator),
            .verification_methods = try vms.toOwnedSlice(allocator),
            .services = try svcs.toOwnedSlice(allocator),
        };
    }

    pub fn deinit(self: *DidDocument) void {
        for (self.handles) |h| self.allocator.free(h);
        self.allocator.free(self.handles);

        for (self.verification_methods) |vm| {
            self.allocator.free(vm.id);
            self.allocator.free(vm.type);
            self.allocator.free(vm.controller);
            self.allocator.free(vm.public_key_multibase);
        }
        self.allocator.free(self.verification_methods);

        for (self.services) |svc| {
            self.allocator.free(svc.id);
            self.allocator.free(svc.type);
            self.allocator.free(svc.service_endpoint);
        }
        self.allocator.free(self.services);

        self.allocator.free(self.id);
    }

    fn getStr(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
        if (obj.get(key)) |v| {
            if (v == .string) return v.string;
        }
        return null;
    }
};

// === tests ===

test "parse did document" {
    const json =
        \\{
        \\  "id": "did:plc:z72i7hdynmk6r22z27h6tvur",
        \\  "alsoKnownAs": ["at://jay.bsky.social"],
        \\  "verificationMethod": [
        \\    {
        \\      "id": "did:plc:z72i7hdynmk6r22z27h6tvur#atproto",
        \\      "type": "Multikey",
        \\      "controller": "did:plc:z72i7hdynmk6r22z27h6tvur",
        \\      "publicKeyMultibase": "zQ3shXjHeiBuRCKmM36cuYnm7YEMzhGnCmCyW92sRJ9pribSF"
        \\    }
        \\  ],
        \\  "service": [
        \\    {
        \\      "id": "#atproto_pds",
        \\      "type": "AtprotoPersonalDataServer",
        \\      "serviceEndpoint": "https://shimeji.us-east.host.bsky.network"
        \\    }
        \\  ]
        \\}
    ;

    var doc = try DidDocument.parse(std.testing.allocator, json);
    defer doc.deinit();

    try std.testing.expectEqualStrings("did:plc:z72i7hdynmk6r22z27h6tvur", doc.id);
    try std.testing.expectEqualStrings("jay.bsky.social", doc.handle().?);
    try std.testing.expectEqualStrings("https://shimeji.us-east.host.bsky.network", doc.pdsEndpoint().?);

    const key = doc.signingKey().?;
    try std.testing.expect(std.mem.endsWith(u8, key.id, "#atproto"));
}

test "parse did document with no handle" {
    const json =
        \\{
        \\  "id": "did:plc:test123",
        \\  "alsoKnownAs": [],
        \\  "verificationMethod": [],
        \\  "service": []
        \\}
    ;

    var doc = try DidDocument.parse(std.testing.allocator, json);
    defer doc.deinit();

    try std.testing.expect(doc.handle() == null);
    try std.testing.expect(doc.pdsEndpoint() == null);
    try std.testing.expect(doc.signingKey() == null);
}
