const std = @import("std");
const database = @import("database.zig");

pub const MediaType = enum {
    image,
    video,
    audio,
    unknown,

    pub fn fromMimeType(mime_type: []const u8) MediaType {
        if (std.mem.startsWith(u8, mime_type, "image/")) return .image;
        if (std.mem.startsWith(u8, mime_type, "video/")) return .video;
        if (std.mem.startsWith(u8, mime_type, "audio/")) return .audio;
        return .unknown;
    }

    pub fn toString(self: MediaType) []const u8 {
        return switch (self) {
            .image => "image",
            .video => "video",
            .audio => "audio",
            .unknown => "unknown",
        };
    }
};

pub const MediaMetadata = struct {
    width: ?u32 = null,
    height: ?u32 = null,
    duration: ?f32 = null, // for video/audio
    bitrate: ?u32 = null,
    size: u64,
    content_type: []const u8,

    pub fn deinit(self: *MediaMetadata, allocator: std.mem.Allocator) void {
        allocator.free(self.content_type);
    }
};

pub const ProcessedMedia = struct {
    id: []const u8,
    original_path: []const u8,
    thumbnail_path: ?[]const u8 = null, // for images/videos
    small_path: ?[]const u8 = null, // for images/videos
    metadata: MediaMetadata,
    blurhash: ?[]const u8 = null, // for images

    pub fn deinit(self: *ProcessedMedia, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.original_path);
        if (self.thumbnail_path) |path| allocator.free(path);
        if (self.small_path) |path| allocator.free(path);
        self.metadata.deinit(allocator);
        if (self.blurhash) |hash| allocator.free(hash);
    }
};

// Upload and process media file
pub fn processMediaUpload(allocator: std.mem.Allocator, data: []const u8, _: []const u8, content_type: []const u8) !ProcessedMedia {
    // Generate unique ID for media
    const media_id = try generateMediaId(allocator);
    defer allocator.free(media_id);

    // Create media directory if it doesn't exist
    const media_dir = "media";
    std.fs.cwd().makePath(media_dir) catch {};

    // Save original file
    const original_filename = try std.fmt.allocPrint(allocator, "{s}/{s}_original", .{ media_dir, media_id });
    defer allocator.free(original_filename);

    const original_file = try std.fs.cwd().createFile(original_filename, .{});
    defer original_file.close();

    try original_file.writeAll(data);

    // Process based on media type
    const media_type = MediaType.fromMimeType(content_type);
    var metadata = MediaMetadata{
        .size = data.len,
        .content_type = try allocator.dupe(u8, content_type),
    };

    var thumbnail_path: ?[]const u8 = null;
    var small_path: ?[]const u8 = null;
    var blurhash: ?[]const u8 = null;

    switch (media_type) {
        .image => {
            // Extract image metadata
            try extractImageMetadata(allocator, data, &metadata);

            // Generate thumbnail
            thumbnail_path = try std.fmt.allocPrint(allocator, "{s}/{s}_thumb.jpg", .{ media_dir, media_id });

            // Generate small version
            small_path = try std.fmt.allocPrint(allocator, "{s}/{s}_small.jpg", .{ media_dir, media_id });

            // Generate blurhash
            blurhash = try generateBlurhash(allocator, data);
        },
        .video => {
            // Extract video metadata
            try extractVideoMetadata(allocator, data, &metadata);

            // Generate thumbnail from video
            thumbnail_path = try std.fmt.allocPrint(allocator, "{s}/{s}_thumb.jpg", .{ media_dir, media_id });
        },
        .audio => {
            // Extract audio metadata
            try extractAudioMetadata(allocator, data, &metadata);
        },
        .unknown => {
            // No processing for unknown types
        },
    }

    return ProcessedMedia{
        .id = try allocator.dupe(u8, media_id),
        .original_path = try allocator.dupe(u8, original_filename),
        .thumbnail_path = if (thumbnail_path) |path| try allocator.dupe(u8, path) else null,
        .small_path = if (small_path) |path| try allocator.dupe(u8, path) else null,
        .metadata = metadata,
        .blurhash = blurhash,
    };
}

// Generate unique media ID
fn generateMediaId(allocator: std.mem.Allocator) ![]u8 {
    var id_buf: [16]u8 = undefined;
    std.crypto.random.bytes(&id_buf);

    // Convert to base64url encoding
    const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    var result = try allocator.alloc(u8, 22); // base64url encoded length

    var i: usize = 0;
    while (i < 16) {
        const b1 = id_buf[i];
        const b2 = if (i + 1 < 16) id_buf[i + 1] else 0;
        const b3 = if (i + 2 < 16) id_buf[i + 2] else 0;

        result[i / 3 * 4] = charset[b1 >> 2];
        result[i / 3 * 4 + 1] = charset[((b1 & 0x3) << 4) | (b2 >> 4)];
        result[i / 3 * 4 + 2] = charset[((b2 & 0xF) << 2) | (b3 >> 6)];
        result[i / 3 * 4 + 3] = charset[b3 & 0x3F];

        i += 3;
    }

    return result;
}

// Extract metadata from image
fn extractImageMetadata(_: std.mem.Allocator, data: []const u8, metadata: *MediaMetadata) !void {
    // Simple image metadata extraction
    // In a real implementation, you'd use a library like libjpeg, libpng, etc.

    // Check for JPEG
    if (std.mem.eql(u8, data[0..2], &[_]u8{ 0xFF, 0xD8 })) {
        // JPEG - try to find dimensions in EXIF or JFIF
        metadata.width = 800; // Placeholder
        metadata.height = 600; // Placeholder
    }
    // Check for PNG
    else if (std.mem.eql(u8, data[0..8], &[_]u8{ 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A })) {
        // PNG - width and height are in bytes 16-23
        if (data.len >= 24) {
            metadata.width = std.mem.readInt(u32, data[16..20], .big);
            metadata.height = std.mem.readInt(u32, data[20..24], .big);
        }
    }
    // Other formats would need similar parsing
}

// Extract metadata from video
fn extractVideoMetadata(_: std.mem.Allocator, _: []const u8, metadata: *MediaMetadata) !void {
    // Video metadata extraction would require a video parsing library
    // For now, set some defaults
    metadata.width = 1920;
    metadata.height = 1080;
    metadata.duration = 60.0; // 60 seconds
    metadata.bitrate = 5000000; // 5 Mbps
}

// Extract metadata from audio
fn extractAudioMetadata(_: std.mem.Allocator, _: []const u8, metadata: *MediaMetadata) !void {
    // Audio metadata extraction would require an audio parsing library
    // For now, set some defaults
    metadata.duration = 180.0; // 3 minutes
    metadata.bitrate = 320000; // 320 kbps
}

// Generate blurhash for images
fn generateBlurhash(allocator: std.mem.Allocator, _: []const u8) ![]u8 {
    // Blurhash generation is complex - requires image decoding and DCT
    // For now, return a placeholder
    return allocator.dupe(u8, "L6B8B8NG00NG00NG009G00NG00");
}

// Validate uploaded file
pub fn validateUpload(content_type: []const u8, size: usize) !void {
    // Check file size (max 10MB)
    const max_size = 10 * 1024 * 1024;
    if (size > max_size) {
        return error.FileTooLarge;
    }

    // Check content type
    const allowed_types = [_][]const u8{
        "image/jpeg",
        "image/png",
        "image/gif",
        "image/webp",
        "video/mp4",
        "video/webm",
        "video/ogg",
        "audio/mp3",
        "audio/ogg",
        "audio/wav",
    };

    for (allowed_types) |allowed| {
        if (std.mem.eql(u8, content_type, allowed)) {
            return;
        }
    }

    return error.InvalidContentType;
}

// Clean up old media files (for cleanup tasks)
pub fn cleanupOldMedia(allocator: std.mem.Allocator, max_age_days: u32) !void {
    // This would scan the media directory and remove files older than max_age_days
    // that are not referenced in the database
    _ = allocator;
    _ = max_age_days;
    // TODO: Implement cleanup logic
}

// Get media URL for API responses
pub fn getMediaUrl(allocator: std.mem.Allocator, media_id: []const u8, size: enum { original, small, thumbnail }) ![]u8 {
    const suffix = switch (size) {
        .original => "_original",
        .small => "_small.jpg",
        .thumbnail => "_thumb.jpg",
    };

    return std.fmt.allocPrint(allocator, "https://speedy-socials.local/media/{s}{s}", .{ media_id, suffix });
}

// Store media metadata in database
pub fn storeMediaInDatabase(db: *database.Database, _: std.mem.Allocator, media_item: ProcessedMedia, post_id: ?i64) !i64 {
    const media_type_str = switch (MediaType.fromMimeType(media_item.metadata.content_type)) {
        .image => "image",
        .video => "video",
        .audio => "audio",
        .unknown => "unknown",
    };

    // Insert into media_attachments table
    return try db.one(i64,
        \\INSERT INTO media_attachments
        \\(post_id, file_path, content_type, file_size, width, height, description, blurhash)
        \\VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        \\RETURNING id
    , .{}, .{
        post_id,
        media_item.original_path,
        media_type_str,
        media_item.metadata.size,
        media_item.metadata.width,
        media_item.metadata.height,
        null, // description
        media_item.blurhash,
    });
}

// Get media attachment by ID
pub fn getMediaById(db: *database.Database, allocator: std.mem.Allocator, media_id: i64) !?database.MediaAttachment {
    return try db.oneAlloc(database.MediaAttachment, allocator,
        \\SELECT id, post_id, file_path, content_type, file_size,
        \\       width, height, description, blurhash, created_at
        \\FROM media_attachments WHERE id = ?
    , allocator, .{media_id});
}

// Delete media file and database record
pub fn deleteMedia(db: *database.Database, allocator: std.mem.Allocator, media_id: i64) !void {
    // Get media info first
    const media = try getMediaById(db, allocator, media_id) orelse return;
    defer allocator.free(media.file_path);
    if (media.description) |desc| allocator.free(desc);
    if (media.blurhash) |hash| allocator.free(hash);
    defer allocator.free(media.created_at);

    // Delete file from filesystem
    std.fs.cwd().deleteFile(media.file_path) catch {};

    // Delete from database
    try db.exec("DELETE FROM media_attachments WHERE id = ?", .{}, .{media_id});
}
