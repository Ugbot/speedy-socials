const std = @import("std");

/// Input to an XRPC procedure/query. The consuming HTTP layer constructs
/// this from the HTTP request and passes it to handler functions.
/// No HTTP framework types are referenced.
pub const XrpcInput = struct {
    /// JSON body bytes for procedures (POST). Null for queries (GET).
    body: ?[]const u8 = null,
    /// Query parameters for queries. Owned by caller.
    params: std.StringHashMapUnmanaged([]const u8) = .empty,
    /// DID of the authenticated user, or null if unauthenticated.
    auth_did: ?[]const u8 = null,
    /// Raw authorization header value (for token extraction).
    auth_token: ?[]const u8 = null,
};

/// Output from an XRPC handler. The consuming HTTP layer reads this
/// and constructs the HTTP response.
pub const XrpcOutput = union(enum) {
    success: Success,
    blob: Blob,
    err: ErrorResponse,

    pub const Success = struct {
        /// JSON response body bytes.
        body: []const u8,
        /// Content type, defaults to application/json.
        content_type: []const u8 = "application/json",
    };

    pub const Blob = struct {
        /// Raw blob data.
        data: []const u8,
        /// MIME type of the blob.
        content_type: []const u8,
    };

    pub fn ok(body: []const u8) XrpcOutput {
        return .{ .success = .{ .body = body } };
    }

    pub fn errResponse(status: u16, error_name: []const u8, message: []const u8) XrpcOutput {
        return .{ .err = .{
            .status = status,
            .error_name = error_name,
            .message = message,
        } };
    }
};

/// XRPC error response structure matching the AT Protocol spec.
pub const ErrorResponse = struct {
    /// HTTP status code.
    status: u16,
    /// Machine-readable error name (e.g., "InvalidRequest", "AuthenticationRequired").
    error_name: []const u8,
    /// Human-readable error description.
    message: []const u8,

    pub fn toJson(self: ErrorResponse, allocator: std.mem.Allocator) ![]const u8 {
        return std.json.Stringify.valueAlloc(allocator, .{
            .@"error" = self.error_name,
            .message = self.message,
        }, .{});
    }
};

/// Standard XRPC error codes used across handlers.
pub const XrpcError = error{
    InvalidRequest,
    AuthenticationRequired,
    InvalidToken,
    ExpiredToken,
    AccountNotFound,
    InvalidHandle,
    InvalidPassword,
    AccountTakenDown,
    RepoNotFound,
    RecordNotFound,
    BlobNotFound,
    InvalidSwap,
    UpstreamFailure,
    MethodNotImplemented,
    InternalServerError,
};

/// Map an XrpcError to an ErrorResponse with appropriate HTTP status.
pub fn errorToResponse(err: XrpcError) ErrorResponse {
    return switch (err) {
        error.InvalidRequest => .{ .status = 400, .error_name = "InvalidRequest", .message = "Invalid request" },
        error.AuthenticationRequired => .{ .status = 401, .error_name = "AuthenticationRequired", .message = "Authentication required" },
        error.InvalidToken => .{ .status = 401, .error_name = "InvalidToken", .message = "Invalid or expired token" },
        error.ExpiredToken => .{ .status = 401, .error_name = "ExpiredToken", .message = "Token has expired" },
        error.AccountNotFound => .{ .status = 404, .error_name = "AccountNotFound", .message = "Account not found" },
        error.InvalidHandle => .{ .status = 400, .error_name = "InvalidHandle", .message = "Invalid handle" },
        error.InvalidPassword => .{ .status = 401, .error_name = "InvalidPassword", .message = "Invalid password" },
        error.AccountTakenDown => .{ .status = 403, .error_name = "AccountTakenDown", .message = "Account has been taken down" },
        error.RepoNotFound => .{ .status = 404, .error_name = "RepoNotFound", .message = "Repository not found" },
        error.RecordNotFound => .{ .status = 404, .error_name = "RecordNotFound", .message = "Record not found" },
        error.BlobNotFound => .{ .status = 404, .error_name = "BlobNotFound", .message = "Blob not found" },
        error.InvalidSwap => .{ .status = 409, .error_name = "InvalidSwap", .message = "Compare-and-swap failed" },
        error.UpstreamFailure => .{ .status = 502, .error_name = "UpstreamFailure", .message = "Upstream service failed" },
        error.MethodNotImplemented => .{ .status = 501, .error_name = "MethodNotImplemented", .message = "Method not implemented" },
        error.InternalServerError => .{ .status = 500, .error_name = "InternalServerError", .message = "Internal server error" },
    };
}

test "error to response mapping" {
    const resp = errorToResponse(error.InvalidRequest);
    try std.testing.expectEqual(@as(u16, 400), resp.status);
    try std.testing.expectEqualStrings("InvalidRequest", resp.error_name);
}
