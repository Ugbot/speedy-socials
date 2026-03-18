const std = @import("std");
const http = std.http;
const compat = @import("../compat.zig");
const database = @import("../database.zig");

// Admin API endpoints for moderation and instance management
pub const AdminAPI = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) AdminAPI {
        return AdminAPI{
            .allocator = allocator,
        };
    }

    // Get admin account list
    pub fn handleAdminAccounts(self: *AdminAPI, _: *database.Database, response: anytype, request: *http.Server.Request) !void {
        // Parse query parameters
        const query_param = request.head.target;
        _ = if (std.mem.indexOf(u8, query_param, "?")) |query_start| blk: {
            break :blk extractQueryParam(query_param[query_start..], "username") orelse "";
        } else "";

        // Get all users (simplified - in real implementation, add pagination and filtering)
        // For now, just return mock data
        const accounts = &[_]struct {
            id: []const u8,
            username: []const u8,
            email: []const u8,
            created_at: []const u8,
            statuses_count: u32 = 10,
            followers_count: u32 = 5,
            following_count: u32 = 3,
            role: []const u8 = "user",
            confirmed: bool = true,
            suspended: bool = false,
            silenced: bool = false,
        }{
            .{
                .id = "1",
                .username = "demo",
                .email = "demo@speedy-socials.local",
                .created_at = "2024-01-01T00:00:00.000Z",
            },
        };

        var json_buf = std.array_list.Managed(u8).init(self.allocator);
        defer json_buf.deinit();

        try compat.jsonStringify(accounts, .{}, json_buf.writer());
        try response.writer.writeAll(json_buf.items);
    }

    // Get admin instance statistics
    pub fn handleAdminStats(self: *AdminAPI, _: *database.Database, response: anytype) !void {
        const stats = struct {
            user_count: u32 = 1,
            status_count: u32 = 3,
            domain_count: u32 = 1,
            report_count: u32 = 0,
            instance_users: u32 = 1,
            instance_statuses: u32 = 3,
        }{};

        var json_buf = std.array_list.Managed(u8).init(self.allocator);
        defer json_buf.deinit();

        try compat.jsonStringify(stats, .{}, json_buf.writer());
        try response.writer.writeAll(json_buf.items);
    }

    // Suspend an account
    pub fn handleSuspendAccount(_: *AdminAPI, _: *database.Database, response: anytype, method: http.Method, _: i64) !void {
        if (method != .POST) {
            // Note: status cannot be changed after respondStreaming in Zig 0.15
            try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
            return;
        }

        // TODO: Implement account suspension
        // This would involve setting a suspended flag and preventing login/actions

        // status already committed via respondStreaming
        try response.writer.writeAll("{}");
    }

    // Unsuspend an account
    pub fn handleUnsuspendAccount(_: *AdminAPI, _: *database.Database, response: anytype, method: http.Method, _: i64) !void {
        if (method != .POST) {
            // Note: status cannot be changed after respondStreaming in Zig 0.15
            try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
            return;
        }

        // TODO: Implement account unsuspension

        // status already committed via respondStreaming
        try response.writer.writeAll("{}");
    }

    // Get reports
    pub fn handleAdminReports(self: *AdminAPI, db: *database.Database, response: anytype, request: *http.Server.Request) !void {
        // Parse query parameters
        const query_param = request.head.target;
        const resolved = if (std.mem.indexOf(u8, query_param, "?")) |query_start| blk: {
            break :blk extractQueryParam(query_param[query_start..], "resolved") orelse "false";
        } else "false";

        const status_filter = if (std.mem.eql(u8, resolved, "true")) "resolved" else "pending";

        const reports = try database.getReports(db, self.allocator, status_filter, 50, 0);
        defer {
            for (reports) |report| database.Report.deinit(report, self.allocator);
            self.allocator.free(reports);
        }

        var admin_reports = std.array_list.Managed(struct {
            id: []const u8,
            category: []const u8,
            comment: ?[]const u8,
            status: []const u8,
            created_at: []const u8,
            account: struct {
                id: []const u8,
                username: []const u8,
            },
            target_account: ?struct {
                id: []const u8,
                username: []const u8,
            },
            assigned_account: ?struct {
                id: []const u8,
                username: []const u8,
            },
        }).init(self.allocator);
        defer {
            for (admin_reports.items) |report| {
                self.allocator.free(report.id);
                self.allocator.free(report.account.id);
                if (report.target_account) |target| self.allocator.free(target.id);
                if (report.assigned_account) |assigned| self.allocator.free(assigned.id);
            }
            admin_reports.deinit();
        }

        for (reports) |report| {
            try admin_reports.append(.{
                .id = try std.fmt.allocPrint(self.allocator, "{}", .{report.id}),
                .category = report.category,
                .comment = report.comment,
                .status = report.status,
                .created_at = report.created_at,
                .account = .{
                    .id = try std.fmt.allocPrint(self.allocator, "{}", .{report.reporter_id}),
                    .username = "reporter", // TODO: Get actual username
                },
                .target_account = if (report.reported_user_id) |user_id| .{
                    .id = try std.fmt.allocPrint(self.allocator, "{}", .{user_id}),
                    .username = "reported_user", // TODO: Get actual username
                } else null,
                .assigned_account = null, // TODO: Implement assignment
            });
        }

        var json_buf = std.array_list.Managed(u8).init(self.allocator);
        defer json_buf.deinit();

        try compat.jsonStringify(admin_reports.items, .{}, json_buf.writer());
        try response.writer.writeAll(json_buf.items);
    }

    // Resolve a report
    pub fn handleResolveReport(_: *AdminAPI, db: *database.Database, response: anytype, method: http.Method, report_id: i64) !void {
        if (method != .POST) {
            // Note: status cannot be changed after respondStreaming in Zig 0.15
            try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
            return;
        }

        try database.resolveReport(db, report_id);
        // status already committed via respondStreaming
        try response.writer.writeAll("{}");
    }

    // Handle user blocking
    pub fn handleBlockAccount(_: *AdminAPI, db: *database.Database, response: anytype, method: http.Method, target_account_id: i64) !void {
        if (method != .POST) {
            // Note: status cannot be changed after respondStreaming in Zig 0.15
            try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
            return;
        }

        // For demo, use admin user ID 1 as the blocker
        const blocker_id: i64 = 1;

        try database.blockUser(db, blocker_id, target_account_id);
        // status already committed via respondStreaming
        try response.writer.writeAll("{}");
    }

    // Handle user unblocking
    pub fn handleUnblockAccount(_: *AdminAPI, db: *database.Database, response: anytype, method: http.Method, target_account_id: i64) !void {
        if (method != .POST) {
            // Note: status cannot be changed after respondStreaming in Zig 0.15
            try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
            return;
        }

        // For demo, use admin user ID 1 as the blocker
        const blocker_id: i64 = 1;

        try database.unblockUser(db, blocker_id, target_account_id);
        // status already committed via respondStreaming
        try response.writer.writeAll("{}");
    }

    // Handle user muting
    pub fn handleMuteAccount(_: *AdminAPI, db: *database.Database, response: anytype, method: http.Method, target_account_id: i64) !void {
        if (method != .POST) {
            // Note: status cannot be changed after respondStreaming in Zig 0.15
            try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
            return;
        }

        // For demo, use admin user ID 1 as the muter
        const muter_id: i64 = 1;

        try database.muteUser(db, muter_id, target_account_id);
        // status already committed via respondStreaming
        try response.writer.writeAll("{}");
    }

    // Handle user unmuting
    pub fn handleUnmuteAccount(_: *AdminAPI, db: *database.Database, response: anytype, method: http.Method, target_account_id: i64) !void {
        if (method != .POST) {
            // Note: status cannot be changed after respondStreaming in Zig 0.15
            try response.writer.writeAll("{\"error\": \"Method not allowed\"}");
            return;
        }

        // For demo, use admin user ID 1 as the muter
        const muter_id: i64 = 1;

        try database.unmuteUser(db, muter_id, target_account_id);
        // status already committed via respondStreaming
        try response.writer.writeAll("{}");
    }

    // Handle creating a report
    pub fn handleCreateReport(self: *AdminAPI, db: *database.Database, response: anytype, request: *http.Server.Request) !void {
        // Read request body
        var body_buf = std.array_list.Managed(u8).init(self.allocator);
        defer body_buf.deinit();

        try request.reader().readAllArrayList(&body_buf, 10 * 1024); // 10KB limit

        // Parse JSON
        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, body_buf.items, .{});
        defer parsed.deinit();

        const account_id = if (parsed.value.object.get("account_id")) |id_val| blk: {
            if (id_val == .string) {
                break :blk std.fmt.parseInt(i64, id_val.string, 10) catch null;
            }
            break :blk null;
        } else null;

        const status_ids = if (parsed.value.object.get("status_ids")) |ids_val| blk: {
            if (ids_val == .array and ids_val.array.items.len > 0) {
                const status_id_str = ids_val.array.items[0].string;
                break :blk std.fmt.parseInt(i64, status_id_str, 10) catch null;
            }
            break :blk null;
        } else null;

        const comment = if (parsed.value.object.get("comment")) |comment_val| blk: {
            if (comment_val == .string) {
                break :blk comment_val.string;
            }
            break :blk null;
        } else null;

        const category = if (parsed.value.object.get("category")) |cat_val| blk: {
            if (cat_val == .string) {
                break :blk cat_val.string;
            }
            break :blk "other";
        } else "other";

        if (account_id == null and status_ids == null) {
            response.status = .bad_request;
            try response.writer.writeAll("{\"error\": \"Either account_id or status_ids must be provided\"}");
            return;
        }

        // For demo, use admin user ID 1 as the reporter
        const reporter_id: i64 = 1;

        const report_id = try database.createReport(db, reporter_id, account_id, status_ids, category, comment);

        const report_response = struct {
            id: []const u8,
            action_taken: bool = false,
        }{
            .id = try std.fmt.allocPrint(self.allocator, "{}", .{report_id}),
        };
        defer self.allocator.free(report_response.id);

        var json_buf = std.array_list.Managed(u8).init(self.allocator);
        defer json_buf.deinit();

        try compat.jsonStringify(report_response, .{}, json_buf.writer());
        // status already committed via respondStreaming
        try response.writer.writeAll(json_buf.items);
    }

    // Handle trending tags
    pub fn handleTrendingTags(self: *AdminAPI, _: *database.Database, response: anytype, request: *http.Server.Request) !void {
        // Parse limit parameter
        const query_param = request.head.target;
        const limit_str = if (std.mem.indexOf(u8, query_param, "?")) |query_start| blk: {
            break :blk extractQueryParam(query_param[query_start..], "limit") orelse "10";
        } else "10";

        const limit = std.fmt.parseInt(u32, limit_str, 10) catch 10;
        const capped_limit = @min(limit, 20); // Cap at 20 trending tags

        // Mock trending tags for demo
        const trending_tags = &[_]struct {
            name: []const u8,
            url: []const u8,
            history: []const u32 = &[_]u32{ 10, 15, 20, 25, 30 },
        }{
            .{
                .name = "zig",
                .url = "https://speedy-socials.local/tags/zig",
            },
            .{
                .name = "programming",
                .url = "https://speedy-socials.local/tags/programming",
            },
            .{
                .name = "social",
                .url = "https://speedy-socials.local/tags/social",
            },
        };

        const mastodon_tags = trending_tags[0..@min(trending_tags.len, capped_limit)];

        var json_buf = std.array_list.Managed(u8).init(self.allocator);
        defer json_buf.deinit();

        try compat.jsonStringify(mastodon_tags, .{}, json_buf.writer());
        try response.writer.writeAll(json_buf.items);
    }
};

// Helper function to extract query parameters
fn extractQueryParam(query: []const u8, param_name: []const u8) ?[]const u8 {
    var param_iter = std.mem.splitSequence(u8, query[1..], "&"); // Skip the '?'
    while (param_iter.next()) |param| {
        if (std.mem.indexOf(u8, param, "=")) |equals_pos| {
            const key = param[0..equals_pos];
            const value = param[equals_pos + 1 ..];
            if (std.mem.eql(u8, key, param_name)) {
                return value;
            }
        }
    }
    return null;
}
