const std = @import("std");
const database = @import("database.zig");
const types = @import("types.zig");
const crypto = std.crypto;

/// Configurable instance domain and scheme. Set from main.zig at startup.
pub var instance_domain: []const u8 = "speedy-socials.local";
pub var instance_scheme: []const u8 = "https";

pub const ActivityType = enum {
    Create,
    Update,
    Delete,
    Follow,
    Accept,
    Reject,
    Undo,
    Like,
    Announce,
};

pub const ObjectType = enum {
    Note,
    Person,
    Service,
    Application,
    Group,
    Organization,
};

pub const Activity = struct {
    @"@context": []const []const u8 = &[_][]const u8{
        "https://www.w3.org/ns/activitystreams",
        "https://w3id.org/security/v1",
    },
    id: []const u8,
    type: ActivityType,
    actor: []const u8, // Actor's ActivityPub ID
    object: ActivityObject,
    published: []const u8,
    to: []const []const u8 = &[_][]const u8{"https://www.w3.org/ns/activitystreams#Public"},
    cc: ?[]const []const u8 = null,

    pub const ActivityObject = union(ObjectType) {
        Note: NoteObject,
        Person: PersonObject,
        Service: ServiceObject,
        Application: ApplicationObject,
        Group: GroupObject,
        Organization: OrganizationObject,
    };

    pub const NoteObject = struct {
        id: []const u8,
        type: []const u8 = "Note",
        attributedTo: []const u8,
        content: []const u8,
        published: []const u8,
        to: []const []const u8 = &[_][]const u8{"https://www.w3.org/ns/activitystreams#Public"},
        cc: ?[]const []const u8 = null,
        inReplyTo: ?[]const u8 = null,
        sensitive: bool = false,
        summary: ?[]const u8 = null,
        attachment: ?[]MediaAttachment = null,
        tag: ?[]Tag = null,

        pub const MediaAttachment = struct {
            type: []const u8,
            mediaType: []const u8,
            url: []const u8,
            name: ?[]const u8 = null,
        };

        pub const Tag = union(enum) {
            Mention: struct {
                type: []const u8 = "Mention",
                href: []const u8,
                name: []const u8,
            },
            Hashtag: struct {
                type: []const u8 = "Hashtag",
                href: []const u8,
                name: []const u8,
            },
        };
    };

    pub const PersonObject = struct {
        id: []const u8,
        type: []const u8 = "Person",
        preferredUsername: []const u8,
        name: ?[]const u8 = null,
        summary: ?[]const u8 = null,
        icon: ?ImageObject = null,
        image: ?ImageObject = null,
        inbox: []const u8,
        outbox: []const u8,
        followers: []const u8,
        following: []const u8,
        liked: ?[]const u8 = null,
        publicKey: PublicKey,
        endpoints: ?Endpoints = null,

        pub const ImageObject = struct {
            type: []const u8 = "Image",
            mediaType: []const u8,
            url: []const u8,
        };

        pub const PublicKey = struct {
            id: []const u8,
            owner: []const u8,
            publicKeyPem: []const u8,
        };

        pub const Endpoints = struct {
            sharedInbox: ?[]const u8 = null,
        };
    };

    pub const ServiceObject = struct {
        id: []const u8,
        type: []const u8 = "Service",
        name: []const u8,
        summary: ?[]const u8 = null,
        icon: ?PersonObject.ImageObject = null,
        inbox: []const u8,
        outbox: []const u8,
        followers: ?[]const u8 = null,
        following: ?[]const u8 = null,
        publicKey: PersonObject.PublicKey,
    };

    pub const ApplicationObject = PersonObject;
    pub const GroupObject = PersonObject;
    pub const OrganizationObject = PersonObject;

    pub fn deinit(self: *Activity, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.actor);
        // Deinit object based on type
        switch (self.object) {
            .Note => |*note| note.deinit(allocator),
            .Person => |*person| person.deinit(allocator),
            .Service => |*service| service.deinit(allocator),
            .Application => |*app| app.deinit(allocator),
            .Group => |*group| group.deinit(allocator),
            .Organization => |*org| org.deinit(allocator),
        }
        if (self.cc) |cc| allocator.free(cc);
    }
};

pub fn NoteObject_deinit(self: *Activity.NoteObject, allocator: std.mem.Allocator) void {
    allocator.free(self.id);
    allocator.free(self.attributedTo);
    allocator.free(self.content);
    allocator.free(self.published);
    if (self.cc) |cc| allocator.free(cc);
    if (self.inReplyTo) |irt| allocator.free(irt);
    if (self.summary) |summary| allocator.free(summary);
    if (self.attachment) |attachments| {
        for (attachments) |*att| att.deinit(allocator);
        allocator.free(attachments);
    }
    if (self.tag) |tags| {
        for (tags) |*tag| tag.deinit(allocator);
        allocator.free(tags);
    }
}

pub fn MediaAttachment_deinit(self: *Activity.NoteObject.MediaAttachment, allocator: std.mem.Allocator) void {
    allocator.free(self.type);
    allocator.free(self.mediaType);
    allocator.free(self.url);
    if (self.name) |name| allocator.free(name);
}

pub fn Tag_deinit(self: *Activity.NoteObject.Tag, allocator: std.mem.Allocator) void {
    switch (self.*) {
        .Mention => |*mention| {
            allocator.free(mention.href);
            allocator.free(mention.name);
        },
        .Hashtag => |*hashtag| {
            allocator.free(hashtag.href);
            allocator.free(hashtag.name);
        },
    }
}

pub fn PersonObject_deinit(self: *Activity.PersonObject, allocator: std.mem.Allocator) void {
    allocator.free(self.id);
    allocator.free(self.preferredUsername);
    if (self.name) |name| allocator.free(name);
    if (self.summary) |summary| allocator.free(summary);
    if (self.icon) |*icon| icon.deinit(allocator);
    if (self.image) |*image| image.deinit(allocator);
    allocator.free(self.inbox);
    allocator.free(self.outbox);
    allocator.free(self.followers);
    allocator.free(self.following);
    if (self.liked) |liked| allocator.free(liked);
    self.publicKey.deinit(allocator);
    if (self.endpoints) |*endpoints| endpoints.deinit(allocator);
}

pub fn ImageObject_deinit(self: *Activity.PersonObject.ImageObject, allocator: std.mem.Allocator) void {
    allocator.free(self.mediaType);
    allocator.free(self.url);
}

pub fn PublicKey_deinit(self: *Activity.PersonObject.PublicKey, allocator: std.mem.Allocator) void {
    allocator.free(self.id);
    allocator.free(self.owner);
    allocator.free(self.publicKeyPem);
}

pub fn Endpoints_deinit(self: *Activity.PersonObject.Endpoints, allocator: std.mem.Allocator) void {
    if (self.sharedInbox) |si| allocator.free(si);
}

pub fn ServiceObject_deinit(self: *Activity.ServiceObject, allocator: std.mem.Allocator) void {
    allocator.free(self.id);
    allocator.free(self.name);
    if (self.summary) |summary| allocator.free(summary);
    if (self.icon) |*icon| icon.deinit(allocator);
    allocator.free(self.inbox);
    allocator.free(self.outbox);
    if (self.followers) |followers| allocator.free(followers);
    if (self.following) |following| allocator.free(following);
    self.publicKey.deinit(allocator);
}

// Generate ActivityPub ID for user
pub fn getUserActivityPubId(allocator: std.mem.Allocator, username: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}://{s}/users/{s}", .{ instance_scheme, instance_domain, username });
}

// Generate ActivityPub inbox URL for user
pub fn getUserInboxUrl(allocator: std.mem.Allocator, username: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}://{s}/users/{s}/inbox", .{ instance_scheme, instance_domain, username });
}

// Generate ActivityPub outbox URL for user
pub fn getUserOutboxUrl(allocator: std.mem.Allocator, username: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}://{s}/users/{s}/outbox", .{ instance_scheme, instance_domain, username });
}

// Create ActivityPub actor (Person) object
pub fn createActorObject(db: *database.Database, allocator: std.mem.Allocator, user: database.User) !Activity.PersonObject {
    const actor_id = try getUserActivityPubId(allocator, user.username);
    const inbox_url = try getUserInboxUrl(allocator, user.username);
    const outbox_url = try getUserOutboxUrl(allocator, user.username);
    const followers_url = try std.fmt.allocPrint(allocator, "{s}://{s}/users/{s}/followers", .{ instance_scheme, instance_domain, user.username });
    const following_url = try std.fmt.allocPrint(allocator, "{s}://{s}/users/{s}/following", .{ instance_scheme, instance_domain, user.username });
    const liked_url = try std.fmt.allocPrint(allocator, "{s}://{s}/users/{s}/liked", .{ instance_scheme, instance_domain, user.username });

    // Get or generate Ed25519 key pair for HTTP signatures
    const key_pair = try database.ensureActorKeyPair(db, allocator, user.id);
    const public_key_pem = try allocator.dupe(u8, key_pair.public_key_pem);
    const public_key_id = try std.fmt.allocPrint(allocator, "{s}#main-key", .{actor_id});

    return Activity.PersonObject{
        .id = actor_id,
        .preferredUsername = try allocator.dupe(u8, user.username),
        .name = if (user.display_name) |dn| try allocator.dupe(u8, dn) else null,
        .summary = if (user.bio) |bio| try allocator.dupe(u8, bio) else null,
        .icon = if (user.avatar_url) |avatar| blk: {
            break :blk Activity.PersonObject.ImageObject{
                .mediaType = try allocator.dupe(u8, "image/jpeg"), // TODO: detect actual type
                .url = try allocator.dupe(u8, avatar),
            };
        } else null,
        .image = if (user.header_url) |header| blk: {
            break :blk Activity.PersonObject.ImageObject{
                .mediaType = try allocator.dupe(u8, "image/jpeg"), // TODO: detect actual type
                .url = try allocator.dupe(u8, header),
            };
        } else null,
        .inbox = inbox_url,
        .outbox = outbox_url,
        .followers = followers_url,
        .following = following_url,
        .liked = liked_url,
        .publicKey = .{
            .id = public_key_id,
            .owner = try allocator.dupe(u8, actor_id),
            .publicKeyPem = public_key_pem,
        },
        .endpoints = .{
            .sharedInbox = try std.fmt.allocPrint(allocator, "{s}://{s}/inbox", .{ instance_scheme, instance_domain }),
        },
    };
}

// Create ActivityPub Note object from post
pub fn createNoteObject(_: *database.Database, allocator: std.mem.Allocator, post: database.Post, author_username: []const u8) !Activity.NoteObject {
    const post_id = try std.fmt.allocPrint(allocator, "{s}://{s}/posts/{}", .{ instance_scheme, instance_domain, post.id });
    const author_id = try getUserActivityPubId(allocator, author_username);

    // Convert created_at timestamp to ISO 8601
    const created_at_iso = try timestampToIso8601(allocator, post.created_at);

    return Activity.NoteObject{
        .id = post_id,
        .attributedTo = author_id,
        .content = try allocator.dupe(u8, post.content),
        .published = created_at_iso,
        .sensitive = post.content_warning != null,
        .summary = if (post.content_warning) |cw| try allocator.dupe(u8, cw) else null,
        .inReplyTo = if (post.reply_to_id) |reply_id| blk: {
            break :blk try std.fmt.allocPrint(allocator, "{s}://{s}/posts/{}", .{ instance_scheme, instance_domain, reply_id });
        } else null,
    };
}

// Create Create activity for a new post
pub fn createCreateActivity(allocator: std.mem.Allocator, post: database.Post, author_username: []const u8) !Activity {
    const activity_id = try std.fmt.allocPrint(allocator, "{s}://{s}/activities/{}", .{ instance_scheme, instance_domain, post.id });
    const actor_id = try getUserActivityPubId(allocator, author_username);
    const published = try timestampToIso8601(allocator, post.created_at);

    const note = try createNoteObject(null, allocator, post, author_username); // TODO: pass db

    return Activity{
        .id = activity_id,
        .type = .Create,
        .actor = actor_id,
        .object = .{ .Note = note },
        .published = published,
    };
}

// Create Follow activity
pub fn createFollowActivity(allocator: std.mem.Allocator, follower_username: []const u8, following_username: []const u8) !Activity {
    const activity_id = try std.fmt.allocPrint(allocator, "{s}://{s}/activities/follow-{s}-{s}", .{ instance_scheme, instance_domain, follower_username, following_username });
    const actor_id = try getUserActivityPubId(allocator, follower_username);
    const target_id = try getUserActivityPubId(allocator, following_username);
    const published = try timestampToIso8601(allocator, std.time.timestamp());

    return Activity{
        .id = activity_id,
        .type = .Follow,
        .actor = actor_id,
        .object = .{ .Person = .{ .id = target_id } }, // Simplified
        .published = published,
    };
}

// Create Like activity
pub fn createLikeActivity(allocator: std.mem.Allocator, liker_username: []const u8, post_id: i64) !Activity {
    const activity_id = try std.fmt.allocPrint(allocator, "{s}://{s}/activities/like-{}-{}", .{ instance_scheme, instance_domain, post_id, std.time.timestamp() });
    const actor_id = try getUserActivityPubId(allocator, liker_username);
    const object_id = try std.fmt.allocPrint(allocator, "{s}://{s}/posts/{}", .{ instance_scheme, instance_domain, post_id });
    const published = try timestampToIso8601(allocator, std.time.timestamp());

    return Activity{
        .id = activity_id,
        .type = .Like,
        .actor = actor_id,
        .object = .{ .Note = .{ .id = object_id } }, // Simplified
        .published = published,
    };
}

// Create Announce (reblog/boost) activity
pub fn createAnnounceActivity(allocator: std.mem.Allocator, booster_username: []const u8, post_id: i64) !Activity {
    const activity_id = try std.fmt.allocPrint(allocator, "{s}://{s}/activities/announce-{}-{}", .{ instance_scheme, instance_domain, post_id, std.time.timestamp() });
    const actor_id = try getUserActivityPubId(allocator, booster_username);
    const object_id = try std.fmt.allocPrint(allocator, "{s}://{s}/posts/{}", .{ instance_scheme, instance_domain, post_id });
    const published = try timestampToIso8601(allocator, std.time.timestamp());

    return Activity{
        .id = activity_id,
        .type = .Announce,
        .actor = actor_id,
        .object = .{ .Note = .{ .id = object_id } }, // Simplified
        .published = published,
    };
}

// HTTP signature verification and incoming activity handling are in federation.zig and crypto_sig.zig

/// Convert a Unix epoch timestamp (seconds) to ISO 8601 format.
pub fn unixTimestampToIso8601(allocator: std.mem.Allocator, ts: i64) ![]u8 {
    const epoch_secs = std.time.epoch.EpochSeconds{ .secs = @intCast(ts) };
    const epoch_day = epoch_secs.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_secs = epoch_secs.getDaySeconds();

    const year: u16 = year_day.year;
    const month: u8 = @intFromEnum(month_day.month);
    const day: u8 = month_day.day_index + 1;
    const hour: u8 = @intCast(day_secs.getHoursIntoDay());
    const minute: u8 = @intCast(day_secs.getMinutesIntoHour());
    const second: u8 = @intCast(day_secs.getSecondsIntoMinute());

    return std.fmt.allocPrint(allocator, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        year, month, day, hour, minute, second,
    });
}

/// Convert a SQLite DATETIME string ("YYYY-MM-DD HH:MM:SS") to ISO 8601.
pub fn sqliteDatetimeToIso8601(allocator: std.mem.Allocator, sqlite_dt: []const u8) ![]u8 {
    // Already in "YYYY-MM-DD HH:MM:SS" format, just replace space with T and append Z
    if (sqlite_dt.len < 19) return allocator.dupe(u8, "1970-01-01T00:00:00Z");
    var buf = try allocator.alloc(u8, 20);
    @memcpy(buf[0..10], sqlite_dt[0..10]);
    buf[10] = 'T';
    @memcpy(buf[11..19], sqlite_dt[11..19]);
    buf[19] = 'Z';
    return buf;
}

/// Format a Unix timestamp as an HTTP Date header (RFC 7231).
/// Example: "Thu, 19 Mar 2026 12:00:00 GMT"
pub fn formatHttpDate(allocator: std.mem.Allocator, ts: i64) ![]u8 {
    const epoch_secs = std.time.epoch.EpochSeconds{ .secs = @intCast(ts) };
    const epoch_day = epoch_secs.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_secs = epoch_secs.getDaySeconds();

    const day_names = [_][]const u8{ "Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed" };
    // Epoch (1970-01-01) was a Thursday, day index 0
    const day_of_week = @as(usize, @intCast(@rem(@as(i64, @intCast(epoch_day.day)) + 4, 7)));
    const month_names = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    return std.fmt.allocPrint(allocator, "{s}, {d:0>2} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} GMT", .{
        day_names[day_of_week],
        @as(u8, month_day.day_index + 1),
        month_names[@as(usize, @intFromEnum(month_day.month)) - 1],
        @as(u16, year_day.year),
        @as(u8, @intCast(day_secs.getHoursIntoDay())),
        @as(u8, @intCast(day_secs.getMinutesIntoHour())),
        @as(u8, @intCast(day_secs.getSecondsIntoMinute())),
    });
}

/// Legacy compatibility wrapper — accepts anytype to handle both []const u8 and i64 callers.
fn timestampToIso8601(allocator: std.mem.Allocator, ts: anytype) ![]u8 {
    const T = @TypeOf(ts);
    if (T == i64) {
        return unixTimestampToIso8601(allocator, ts);
    } else if (T == []const u8 or T == [:0]const u8) {
        return sqliteDatetimeToIso8601(allocator, ts);
    } else {
        @compileError("timestampToIso8601: expected i64 or []const u8, got " ++ @typeName(T));
    }
}

// WebFinger support for user discovery
pub const WebFinger = struct {
    subject: []const u8,
    links: []Link,

    pub const Link = struct {
        rel: []const u8,
        type: ?[]const u8 = null,
        href: ?[]const u8 = null,
        template: ?[]const u8 = null,
    };
};

// Generate WebFinger response for user
pub fn createWebFinger(allocator: std.mem.Allocator, username: []const u8) !WebFinger {
    const subject = try std.fmt.allocPrint(allocator, "acct:{s}@{s}", .{ username, instance_domain });
    const profile_url = try getUserActivityPubId(allocator, username);

    return WebFinger{
        .subject = subject,
        .links = try allocator.dupe([]WebFinger.Link, &[_]WebFinger.Link{
            .{
                .rel = "http://webfinger.net/rel/profile-page",
                .type = "text/html",
                .href = profile_url,
            },
            .{
                .rel = "http://schemas.google.com/g/2010#updates-from",
                .type = "application/atom+xml",
                .href = try std.fmt.allocPrint(allocator, "{s}://{s}/users/{s}.atom", .{ instance_scheme, instance_domain, username }),
            },
            .{
                .rel = "self",
                .type = "application/activity+json",
                .href = profile_url,
            },
        }),
    };
}

// Activity delivery queue item (used by federation.zig)
pub const DeliveryJob = struct {
    activity_json: []const u8,
    inbox_url: []const u8,
    private_key_raw: [64]u8,
    key_id: []const u8,

    pub fn deinit(self: *const DeliveryJob, allocator: std.mem.Allocator) void {
        allocator.free(self.activity_json);
        allocator.free(self.inbox_url);
        allocator.free(self.key_id);
    }
};
