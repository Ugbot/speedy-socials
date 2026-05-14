const std = @import("std");
const zat = @import("zat");

const Allocator = std.mem.Allocator;

const DocEntry = struct { path: []const u8, file: []const u8 };

/// docs to publish as site.standard.document records
const docs = [_]DocEntry{
    .{ .path = "/", .file = "README.md" },
    .{ .path = "/roadmap", .file = "docs/roadmap.md" },
    .{ .path = "/changelog", .file = "CHANGELOG.md" },
};

/// devlog entries
const devlog = [_]DocEntry{
    .{ .path = "/devlog/001", .file = "devlog/001-self-publishing-docs.md" },
    .{ .path = "/devlog/002", .file = "devlog/002-firehose-and-benchmarks.md" },
    .{ .path = "/devlog/003", .file = "devlog/003-trust-chain.md" },
    .{ .path = "/devlog/004", .file = "devlog/004-sig-verify.md" },
    .{ .path = "/devlog/005", .file = "devlog/005-three-way-verify.md" },
    .{ .path = "/devlog/006", .file = "devlog/006-building-a-relay.md" },
    .{ .path = "/devlog/007", .file = "devlog/007-up-and-to-the-right.md" },
};

pub fn main() !void {
    // use page_allocator for CLI tool - OS reclaims on exit
    const allocator = std.heap.page_allocator;

    const handle = "zat.dev";

    const password = std.posix.getenv("ATPROTO_PASSWORD") orelse {
        std.debug.print("error: ATPROTO_PASSWORD not set\n", .{});
        return error.MissingEnv;
    };

    const pds = std.posix.getenv("ATPROTO_PDS") orelse "https://bsky.social";

    var client = zat.XrpcClient.init(allocator, pds);
    defer client.deinit();

    const session = try createSession(&client, allocator, handle, password);
    defer {
        allocator.free(session.did);
        allocator.free(session.access_token);
    }

    std.debug.print("authenticated as {s}\n", .{session.did});
    client.setAuth(session.access_token);

    // generate TID for publication (fixed timestamp for deterministic rkey)
    // using 2024-01-01 00:00:00 UTC as base timestamp (1704067200 seconds = 1704067200000000 microseconds)
    const pub_tid = zat.Tid.fromTimestamp(1704067200000000, 0);
    const pub_record = Publication{
        .url = "https://zat.dev",
        .name = "zat",
        .description = "AT Protocol building blocks for zig",
    };

    try putRecord(&client, allocator, session.did, "site.standard.publication", pub_tid.str(), pub_record);
    std.debug.print("created publication: at://{s}/site.standard.publication/{s}\n", .{ session.did, pub_tid.str() });

    var pub_uri_buf: std.ArrayList(u8) = .empty;
    defer pub_uri_buf.deinit(allocator);
    try pub_uri_buf.print(allocator, "at://{s}/site.standard.publication/{s}", .{ session.did, pub_tid.str() });
    const pub_uri = pub_uri_buf.items;

    // publish each doc with deterministic TIDs (same base timestamp, incrementing clock_id)
    const now = timestamp();

    for (docs, 0..) |doc, i| {
        const content = std.fs.cwd().readFileAlloc(allocator, doc.file, 1024 * 1024) catch |err| {
            std.debug.print("warning: could not read {s}: {}\n", .{ doc.file, err });
            continue;
        };
        defer allocator.free(content);

        const title = extractTitle(content) orelse doc.file;
        const tid = zat.Tid.fromTimestamp(1704067200000000, @intCast(i + 1)); // clock_id 1, 2, 3...

        const doc_record = Document{
            .site = pub_uri,
            .title = title,
            .path = doc.path,
            .textContent = content,
            .publishedAt = &now,
        };

        try putRecord(&client, allocator, session.did, "site.standard.document", tid.str(), doc_record);
        std.debug.print("published: {s} -> at://{s}/site.standard.document/{s}\n", .{ doc.file, session.did, tid.str() });
    }

    // devlog publication (clock_id 100 to separate from docs)
    const devlog_tid = zat.Tid.fromTimestamp(1704067200000000, 100);
    const devlog_pub = Publication{
        .url = "https://zat.dev",
        .name = "zat devlog",
        .description = "building zat in public",
    };

    try putRecord(&client, allocator, session.did, "site.standard.publication", devlog_tid.str(), devlog_pub);
    std.debug.print("created publication: at://{s}/site.standard.publication/{s}\n", .{ session.did, devlog_tid.str() });

    var devlog_uri_buf: std.ArrayList(u8) = .empty;
    defer devlog_uri_buf.deinit(allocator);
    try devlog_uri_buf.print(allocator, "at://{s}/site.standard.publication/{s}", .{ session.did, devlog_tid.str() });
    const devlog_uri = devlog_uri_buf.items;

    // publish devlog entries (clock_id 101, 102, ...)
    for (devlog, 0..) |entry, i| {
        const content = std.fs.cwd().readFileAlloc(allocator, entry.file, 1024 * 1024) catch |err| {
            std.debug.print("warning: could not read {s}: {}\n", .{ entry.file, err });
            continue;
        };
        defer allocator.free(content);

        const title = extractTitle(content) orelse entry.file;
        const tid = zat.Tid.fromTimestamp(1704067200000000, @intCast(101 + i));

        const doc_record = Document{
            .site = devlog_uri,
            .title = title,
            .path = entry.path,
            .textContent = content,
            .publishedAt = &now,
        };

        try putRecord(&client, allocator, session.did, "site.standard.document", tid.str(), doc_record);
        std.debug.print("published: {s} -> at://{s}/site.standard.document/{s}\n", .{ entry.file, session.did, tid.str() });
    }

    std.debug.print("done\n", .{});
}

const Publication = struct {
    @"$type": []const u8 = "site.standard.publication",
    url: []const u8,
    name: []const u8,
    description: ?[]const u8 = null,
};

const Document = struct {
    @"$type": []const u8 = "site.standard.document",
    site: []const u8,
    title: []const u8,
    path: ?[]const u8 = null,
    textContent: ?[]const u8 = null,
    publishedAt: []const u8,
};

const Session = struct {
    did: []const u8,
    access_token: []const u8,
};

fn createSession(client: *zat.XrpcClient, allocator: Allocator, handle: []const u8, password: []const u8) !Session {
    const CreateSessionInput = struct {
        identifier: []const u8,
        password: []const u8,
    };

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    try buf.print(allocator, "{f}", .{std.json.fmt(CreateSessionInput{
        .identifier = handle,
        .password = password,
    }, .{})});

    const nsid = zat.Nsid.parse("com.atproto.server.createSession").?;
    var response = try client.procedure(nsid, buf.items);
    defer response.deinit();

    if (!response.ok()) {
        std.debug.print("createSession failed: {s}\n", .{response.body});
        return error.AuthFailed;
    }

    var parsed = try response.json();
    defer parsed.deinit();

    const did = zat.json.getString(parsed.value, "did") orelse return error.MissingDid;
    const token = zat.json.getString(parsed.value, "accessJwt") orelse return error.MissingToken;

    return .{
        .did = try allocator.dupe(u8, did),
        .access_token = try allocator.dupe(u8, token),
    };
}

fn putRecord(client: *zat.XrpcClient, allocator: Allocator, repo: []const u8, collection: []const u8, rkey: []const u8, record: anytype) !void {
    // serialize record to json
    var record_buf: std.ArrayList(u8) = .empty;
    defer record_buf.deinit(allocator);
    try record_buf.print(allocator, "{f}", .{std.json.fmt(record, .{})});

    // build request body
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);

    try body.appendSlice(allocator, "{\"repo\":\"");
    try body.appendSlice(allocator, repo);
    try body.appendSlice(allocator, "\",\"collection\":\"");
    try body.appendSlice(allocator, collection);
    try body.appendSlice(allocator, "\",\"rkey\":\"");
    try body.appendSlice(allocator, rkey);
    try body.appendSlice(allocator, "\",\"record\":");
    try body.appendSlice(allocator, record_buf.items);
    try body.append(allocator, '}');

    const nsid = zat.Nsid.parse("com.atproto.repo.putRecord").?;
    var response = try client.procedure(nsid, body.items);
    defer response.deinit();

    if (!response.ok()) {
        std.debug.print("putRecord failed: {s}\n", .{response.body});
        return error.PutFailed;
    }
}

fn extractTitle(content: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len > 2 and trimmed[0] == '#' and trimmed[1] == ' ') {
            var title = trimmed[2..];
            // strip markdown link: [text](url) -> text
            if (std.mem.indexOf(u8, title, "](")) |bracket| {
                if (title[0] == '[') {
                    title = title[1..bracket];
                }
            }
            return title;
        }
    }
    return null;
}

fn timestamp() [20]u8 {
    const epoch_seconds = std.time.timestamp();
    const days: i32 = @intCast(@divFloor(epoch_seconds, std.time.s_per_day));
    const day_secs: u32 = @intCast(@mod(epoch_seconds, std.time.s_per_day));

    // calculate year/month/day from days since epoch (1970-01-01)
    var y: i32 = 1970;
    var remaining = days;
    while (true) {
        const year_days: i32 = if (@mod(y, 4) == 0 and (@mod(y, 100) != 0 or @mod(y, 400) == 0)) 366 else 365;
        if (remaining < year_days) break;
        remaining -= year_days;
        y += 1;
    }

    const is_leap = @mod(y, 4) == 0 and (@mod(y, 100) != 0 or @mod(y, 400) == 0);
    const month_days = [12]u8{ 31, if (is_leap) 29 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    var m: usize = 0;
    while (m < 12 and remaining >= month_days[m]) : (m += 1) {
        remaining -= month_days[m];
    }

    const hours = day_secs / 3600;
    const mins = (day_secs % 3600) / 60;
    const secs = day_secs % 60;

    var buf: [20]u8 = undefined;
    _ = std.fmt.bufPrint(&buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        @as(u32, @intCast(y)), @as(u32, @intCast(m + 1)), @as(u32, @intCast(remaining + 1)), hours, mins, secs,
    }) catch unreachable;
    return buf;
}
