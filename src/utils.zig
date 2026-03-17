const std = @import("std");

// JSON utilities
pub fn jsonResponse(allocator: std.mem.Allocator, data: anytype) ![]const u8 {
    var buffer = std.array_list.Managed(u8).init(allocator);
    defer buffer.deinit();

    try std.json.stringify(data, .{}, buffer.writer());
    return buffer.toOwnedSlice();
}

pub fn jsonError(allocator: std.mem.Allocator, message: []const u8) ![]const u8 {
    const error_response = struct {
        @"error": []const u8,
    }{ .@"error" = message };

    return jsonResponse(allocator, error_response);
}

// ID generation utilities
pub fn generateId(allocator: std.mem.Allocator) ![]const u8 {
    var id_buf: [16]u8 = undefined;
    std.crypto.random.bytes(&id_buf);
    return std.fmt.allocPrint(allocator, "{x}", .{std.fmt.fmtSliceHexLower(&id_buf)});
}

// Time utilities
pub fn currentTimestamp(allocator: std.mem.Allocator) ![]const u8 {
    const now = std.time.timestamp();
    return std.fmt.allocPrint(allocator, "{d}", .{now});
}

pub fn iso8601Timestamp(allocator: std.mem.Allocator) ![]const u8 {
    const now = std.time.timestamp();
    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = @intCast(now) };
    const day = epoch_seconds.getEpochDay();
    const year_day = day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();

    return std.fmt.allocPrint(allocator, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        year_day.year,
        @intFromEnum(month_day.month),
        month_day.day_index + 1,
        0, 0, 0, // TODO: Add proper time components
    });
}

// String utilities
pub fn stringEqual(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

pub fn duplicateString(allocator: std.mem.Allocator, str: []const u8) ![]const u8 {
    return allocator.dupe(u8, str);
}

// Array utilities
pub fn sliceContains(comptime T: type, haystack: []const T, needle: T) bool {
    for (haystack) |item| {
        if (std.meta.eql(item, needle)) return true;
    }
    return false;
}

// HTTP utilities
pub const HttpMethod = enum {
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    HEAD,
    OPTIONS,

    pub fn fromString(str: []const u8) ?HttpMethod {
        if (stringEqual(str, "GET")) return .GET;
        if (stringEqual(str, "POST")) return .POST;
        if (stringEqual(str, "PUT")) return .PUT;
        if (stringEqual(str, "DELETE")) return .DELETE;
        if (stringEqual(str, "PATCH")) return .PATCH;
        if (stringEqual(str, "HEAD")) return .HEAD;
        if (stringEqual(str, "OPTIONS")) return .OPTIONS;
        return null;
    }
};

pub const HttpStatus = struct {
    pub const OK = 200;
    pub const CREATED = 201;
    pub const BAD_REQUEST = 400;
    pub const UNAUTHORIZED = 401;
    pub const FORBIDDEN = 403;
    pub const NOT_FOUND = 404;
    pub const METHOD_NOT_ALLOWED = 405;
    pub const CONFLICT = 409;
    pub const UNPROCESSABLE_ENTITY = 422;
    pub const INTERNAL_SERVER_ERROR = 500;
};
