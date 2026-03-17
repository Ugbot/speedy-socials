const std = @import("std");
const httpz = @import("httpz");

const types = @import("../types.zig");
const utils = @import("../utils.zig");

// AT Protocol DID for this server
const SERVER_DID = "did:web:speedy-socials.local";

// In-memory storage for AT Protocol records
var records = std.ArrayList(types.ATProtoRecord).init(std.heap.page_allocator);
var sessions = std.StringHashMap([]const u8).init(std.heap.page_allocator); // token -> did

const Service = struct {
    id: []const u8,
    type: []const u8,
    serviceEndpoint: []const u8,
};

const Links = struct {
    privacyPolicy: ?[]const u8 = null,
    termsOfService: ?[]const u8 = null,
};

pub fn getDID(_: *httpz.Request, res: *httpz.Response) !void {
    const did_doc = struct {
        @"@context": []const []const u8 = &[_][]const u8{
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1",
        },
        id: []const u8 = SERVER_DID,
        service: []const Service = &[_]Service{
            .{
                .id = "#bsky_pds",
                .type = "AtprotoPersonalDataServer",
                .serviceEndpoint = "https://speedy-socials.local",
            },
        },
    };

    const json = try utils.jsonResponse(res.arena, did_doc);
    defer res.arena.free(json);

    res.status = utils.HttpStatus.OK;
    res.header("Content-Type", "application/json");
    res.body = json;
}

pub fn describeServer(_: *httpz.Request, res: *httpz.Response) !void {
    const server_info = struct {
        did: []const u8 = SERVER_DID,
        availableUserDomains: []const []const u8 = &[_][]const u8{".local"},
        inviteCodeRequired: bool = false,
        phoneVerificationRequired: bool = false,
        links: Links = .{},
    };

    const json = try utils.jsonResponse(res.arena, server_info);
    defer res.arena.free(json);

    res.status = utils.HttpStatus.OK;
    res.header("Content-Type", "application/json");
    res.body = json;
}

pub fn createSession(req: *httpz.Request, res: *httpz.Response) !void {
    const body = req.body() orelse {
        res.status = utils.HttpStatus.BAD_REQUEST;
        res.body = try utils.jsonError(res.arena, "Missing request body");
        return;
    };

    var parsed = try std.json.parseFromSlice(std.json.Value, res.arena, body, .{});
    defer parsed.deinit();

    const identifier = parsed.value.object.get("identifier") orelse {
        res.status = utils.HttpStatus.BAD_REQUEST;
        res.body = try utils.jsonError(res.arena, "Missing identifier");
        return;
    };

    if (identifier != .string) {
        res.status = utils.HttpStatus.BAD_REQUEST;
        res.body = try utils.jsonError(res.arena, "Identifier must be a string");
        return;
    }

    // For demo purposes, accept any identifier and create a session
    const did = try std.fmt.allocPrint(std.heap.page_allocator, "did:web:{s}", .{identifier.string});
    const access_token = try utils.generateId(std.heap.page_allocator);

    try sessions.put(access_token, did);

    const session_response = struct {
        did: []const u8,
        accessJwt: []const u8,
        refreshJwt: []const u8,
        handle: []const u8,
    }{
        .did = did,
        .accessJwt = access_token,
        .refreshJwt = try utils.generateId(std.heap.page_allocator), // Simplified
        .handle = identifier.string,
    };

    const json = try utils.jsonResponse(res.arena, session_response);
    defer res.arena.free(json);

    res.status = utils.HttpStatus.OK;
    res.header("Content-Type", "application/json");
    res.body = json;
}

pub fn createRecord(req: *httpz.Request, res: *httpz.Response) !void {
    // Check authorization
    const auth_header = req.header("authorization") orelse {
        res.status = utils.HttpStatus.UNAUTHORIZED;
        res.body = try utils.jsonError(res.arena, "Missing authorization");
        return;
    };

    if (!std.mem.startsWith(u8, auth_header, "Bearer ")) {
        res.status = utils.HttpStatus.UNAUTHORIZED;
        res.body = try utils.jsonError(res.arena, "Invalid authorization format");
        return;
    }

    const token = auth_header[7..];
    _ = sessions.get(token) orelse {
        res.status = utils.HttpStatus.UNAUTHORIZED;
        res.body = try utils.jsonError(res.arena, "Invalid token");
        return;
    };

    const body = req.body() orelse {
        res.status = utils.HttpStatus.BAD_REQUEST;
        res.body = try utils.jsonError(res.arena, "Missing request body");
        return;
    };

    var parsed = try std.json.parseFromSlice(std.json.Value, res.arena, body, .{});
    defer parsed.deinit();

    const repo = parsed.value.object.get("repo") orelse {
        res.status = utils.HttpStatus.BAD_REQUEST;
        res.body = try utils.jsonError(res.arena, "Missing repo");
        return;
    };

    const collection = parsed.value.object.get("collection") orelse {
        res.status = utils.HttpStatus.BAD_REQUEST;
        res.body = try utils.jsonError(res.arena, "Missing collection");
        return;
    };

    const record_value = parsed.value.object.get("record") orelse {
        res.status = utils.HttpStatus.BAD_REQUEST;
        res.body = try utils.jsonError(res.arena, "Missing record");
        return;
    };

    if (repo != .string or collection != .string or record_value != .object) {
        res.status = utils.HttpStatus.BAD_REQUEST;
        res.body = try utils.jsonError(res.arena, "Invalid request format");
        return;
    }

    // Create AT Protocol record
    const record = types.ATProtoRecord{
        .@"$type" = try utils.duplicateString(std.heap.page_allocator, collection.string),
        .text = if (record_value.object.get("text")) |text| blk: {
            break :blk if (text == .string) try utils.duplicateString(std.heap.page_allocator, text.string) else null;
        } else null,
        .createdAt = try utils.iso8601Timestamp(std.heap.page_allocator),
    };

    try records.append(record);

    const response = struct {
        uri: []const u8,
        cid: []const u8,
    }{
        .uri = try std.fmt.allocPrint(std.heap.page_allocator, "at://{s}/{s}/{s}", .{ repo.string, collection.string, "record_id" }),
        .cid = try utils.generateId(std.heap.page_allocator),
    };

    const json = try utils.jsonResponse(res.arena, response);
    defer res.arena.free(json);

    res.status = utils.HttpStatus.OK;
    res.header("Content-Type", "application/json");
    res.body = json;
}

pub fn listRecords(req: *httpz.Request, res: *httpz.Response) !void {
    const repo = req.query("repo") orelse {
        res.status = utils.HttpStatus.BAD_REQUEST;
        res.body = try utils.jsonError(res.arena, "Missing repo parameter");
        return;
    };

    const collection = req.query("collection") orelse {
        res.status = utils.HttpStatus.BAD_REQUEST;
        res.body = try utils.jsonError(res.arena, "Missing collection parameter");
        return;
    };

    _ = repo; // TODO: Use repo parameter for filtering

    // Filter records by collection
    var filtered_records = std.ArrayList(types.ATProtoRecord).init(res.arena);
    defer filtered_records.deinit();

    for (records.items) |record| {
        if (utils.stringEqual(record.@"$type", collection)) {
            try filtered_records.append(record);
        }
    }

    const response = struct {
        records: []const types.ATProtoRecord,
        cursor: ?[]const u8 = null,
    }{
        .records = filtered_records.items,
    };

    const json = try utils.jsonResponse(res.arena, response);
    defer res.arena.free(json);

    res.status = utils.HttpStatus.OK;
    res.header("Content-Type", "application/json");
    res.body = json;
}

pub fn getTimeline(req: *httpz.Request, res: *httpz.Response) !void {
    // Check authorization
    const auth_header = req.header("authorization") orelse {
        res.status = utils.HttpStatus.UNAUTHORIZED;
        res.body = try utils.jsonError(res.arena, "Missing authorization");
        return;
    };

    if (!std.mem.startsWith(u8, auth_header, "Bearer ")) {
        res.status = utils.HttpStatus.UNAUTHORIZED;
        res.body = try utils.jsonError(res.arena, "Invalid authorization format");
        return;
    }

    const token = auth_header[7..];
    _ = sessions.get(token) orelse {
        res.status = utils.HttpStatus.UNAUTHORIZED;
        res.body = try utils.jsonError(res.arena, "Invalid token");
        return;
    };

    // Convert our records to feed items
    var feed_items = std.ArrayList(struct {
        post: types.ATProtoRecord,
    }).init(res.arena);
    defer feed_items.deinit();

    for (records.items) |record| {
        try feed_items.append(.{ .post = record });
    }

    const response = struct {
        feed: []const @TypeOf(feed_items.items[0]),
        cursor: ?[]const u8 = null,
    }{
        .feed = feed_items.items,
    };

    const json = try utils.jsonResponse(res.arena, response);
    defer res.arena.free(json);

    res.status = utils.HttpStatus.OK;
    res.header("Content-Type", "application/json");
    res.body = json;
}

pub fn putRecord(req: *httpz.Request, res: *httpz.Response) !void {
    // Similar to createRecord but for updating existing records
    // For simplicity, we'll treat this as creating a new record
    try createRecord(req, res);
}
