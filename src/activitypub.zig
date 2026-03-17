const std = @import("std");
const database = @import("database.zig");
const types = @import("types.zig");
const crypto = std.crypto;

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
    return std.fmt.allocPrint(allocator, "https://speedy-socials.local/users/{s}", .{username});
}

// Generate ActivityPub inbox URL for user
pub fn getUserInboxUrl(allocator: std.mem.Allocator, username: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "https://speedy-socials.local/users/{s}/inbox", .{username});
}

// Generate ActivityPub outbox URL for user
pub fn getUserOutboxUrl(allocator: std.mem.Allocator, username: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "https://speedy-socials.local/users/{s}/outbox", .{username});
}

// Create ActivityPub actor (Person) object
pub fn createActorObject(_: *database.Database, allocator: std.mem.Allocator, user: database.User) !Activity.PersonObject {
    const actor_id = try getUserActivityPubId(allocator, user.username);
    const inbox_url = try getUserInboxUrl(allocator, user.username);
    const outbox_url = try getUserOutboxUrl(allocator, user.username);
    const followers_url = try std.fmt.allocPrint(allocator, "https://speedy-socials.local/users/{s}/followers", .{user.username});
    const following_url = try std.fmt.allocPrint(allocator, "https://speedy-socials.local/users/{s}/following", .{user.username});
    const liked_url = try std.fmt.allocPrint(allocator, "https://speedy-socials.local/users/{s}/liked", .{user.username});

    // Generate RSA key pair for HTTP signatures
    // TODO: Generate proper key pair
    const public_key_pem = try allocator.dupe(u8, "-----BEGIN PUBLIC KEY-----\nMOCK_PUBLIC_KEY\n-----END PUBLIC KEY-----");
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
            .sharedInbox = try allocator.dupe(u8, "https://speedy-socials.local/inbox"),
        },
    };
}

// Create ActivityPub Note object from post
pub fn createNoteObject(_: *database.Database, allocator: std.mem.Allocator, post: database.Post, author_username: []const u8) !Activity.NoteObject {
    const post_id = try std.fmt.allocPrint(allocator, "https://speedy-socials.local/posts/{}", .{post.id});
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
            break :blk try std.fmt.allocPrint(allocator, "https://speedy-socials.local/posts/{}", .{reply_id});
        } else null,
    };
}

// Create Create activity for a new post
pub fn createCreateActivity(allocator: std.mem.Allocator, post: database.Post, author_username: []const u8) !Activity {
    const activity_id = try std.fmt.allocPrint(allocator, "https://speedy-socials.local/activities/{}", .{post.id});
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
    const activity_id = try std.fmt.allocPrint(allocator, "https://speedy-socials.local/activities/follow-{s}-{s}", .{ follower_username, following_username });
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
    const activity_id = try std.fmt.allocPrint(allocator, "https://speedy-socials.local/activities/like-{}-{}", .{ post_id, std.time.timestamp() });
    const actor_id = try getUserActivityPubId(allocator, liker_username);
    const object_id = try std.fmt.allocPrint(allocator, "https://speedy-socials.local/posts/{}", .{post_id});
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
    const activity_id = try std.fmt.allocPrint(allocator, "https://speedy-socials.local/activities/announce-{}-{}", .{ post_id, std.time.timestamp() });
    const actor_id = try getUserActivityPubId(allocator, booster_username);
    const object_id = try std.fmt.allocPrint(allocator, "https://speedy-socials.local/posts/{}", .{post_id});
    const published = try timestampToIso8601(allocator, std.time.timestamp());

    return Activity{
        .id = activity_id,
        .type = .Announce,
        .actor = actor_id,
        .object = .{ .Note = .{ .id = object_id } }, // Simplified
        .published = published,
    };
}

// HTTP signature verification for incoming activities
pub fn verifyHttpSignature(allocator: std.mem.Allocator, request: anytype, body: []const u8) !bool {
    // TODO: Implement HTTP signature verification
    // This is complex and involves:
    // 1. Parse Signature header
    // 2. Fetch public key from actor
    // 3. Verify signature against request headers and body
    _ = allocator;
    _ = request;
    _ = body;
    return true; // Placeholder
}

// Send activity to remote server
pub fn sendActivity(allocator: std.mem.Allocator, activity: Activity, target_inbox: []const u8) !void {
    // TODO: Implement HTTP POST to remote inbox with signature
    // This involves:
    // 1. Serialize activity to JSON
    // 2. Create HTTP signature
    // 3. POST to target inbox
    // 4. Handle delivery failures and retries
    _ = allocator;
    _ = activity;
    _ = target_inbox;
}

// Handle incoming activity
pub fn handleIncomingActivity(db: *database.Database, allocator: std.mem.Allocator, activity: Activity) !void {
    switch (activity.type) {
        .Create => {
            // Handle new post/note
            switch (activity.object) {
                .Note => |note| {
                    try handleIncomingNote(db, allocator, note);
                },
                else => {
                    // Ignore other object types for Create
                },
            }
        },
        .Follow => {
            // Handle follow request
            try handleIncomingFollow(db, allocator, activity);
        },
        .Like => {
            // Handle like/favourite
            try handleIncomingLike(db, allocator, activity);
        },
        .Announce => {
            // Handle announce/reblog
            try handleIncomingAnnounce(db, allocator, activity);
        },
        .Accept => {
            // Handle follow acceptance
            try handleIncomingAccept(db, allocator, activity);
        },
        .Reject => {
            // Handle follow rejection
            try handleIncomingReject(db, allocator, activity);
        },
        .Undo => {
            // Handle undo (unfollow, unlike, etc.)
            try handleIncomingUndo(db, allocator, activity);
        },
        .Update => {
            // Handle profile/post updates
            try handleIncomingUpdate(db, allocator, activity);
        },
        .Delete => {
            // Handle deletion
            try handleIncomingDelete(db, allocator, activity);
        },
    }
}

// Helper functions for handling incoming activities
fn handleIncomingNote(db: *database.Database, allocator: std.mem.Allocator, note: Activity.NoteObject) !void {
    // TODO: Store incoming post in database
    // This involves:
    // 1. Parse attributedTo to get author
    // 2. Store post with federated = true
    // 3. Handle mentions, hashtags, etc.
    _ = db;
    _ = allocator;
    _ = note;
}

fn handleIncomingFollow(db: *database.Database, allocator: std.mem.Allocator, activity: Activity) !void {
    // TODO: Handle incoming follow request
    // 1. Check if auto-accept follows
    // 2. Send Accept or Reject activity
    _ = db;
    _ = allocator;
    _ = activity;
}

fn handleIncomingLike(db: *database.Database, allocator: std.mem.Allocator, activity: Activity) !void {
    // TODO: Record incoming like
    _ = db;
    _ = allocator;
    _ = activity;
}

fn handleIncomingAnnounce(db: *database.Database, allocator: std.mem.Allocator, activity: Activity) !void {
    // TODO: Record incoming reblog
    _ = db;
    _ = allocator;
    _ = activity;
}

fn handleIncomingAccept(db: *database.Database, allocator: std.mem.Allocator, activity: Activity) !void {
    // TODO: Mark follow as accepted
    _ = db;
    _ = allocator;
    _ = activity;
}

fn handleIncomingReject(db: *database.Database, allocator: std.mem.Allocator, activity: Activity) !void {
    // TODO: Handle follow rejection
    _ = db;
    _ = allocator;
    _ = activity;
}

fn handleIncomingUndo(db: *database.Database, allocator: std.mem.Allocator, activity: Activity) !void {
    // TODO: Handle undo operations
    _ = db;
    _ = allocator;
    _ = activity;
}

fn handleIncomingUpdate(db: *database.Database, allocator: std.mem.Allocator, activity: Activity) !void {
    // TODO: Handle profile/post updates
    _ = db;
    _ = allocator;
    _ = activity;
}

fn handleIncomingDelete(db: *database.Database, allocator: std.mem.Allocator, activity: Activity) !void {
    // TODO: Handle deletion of posts/profiles
    _ = db;
    _ = allocator;
    _ = activity;
}

// Utility function to convert Unix timestamp to ISO 8601
fn timestampToIso8601(allocator: std.mem.Allocator, _: []const u8) ![]u8 {
    // Simple conversion - in production, use proper datetime formatting
    return allocator.dupe(u8, "2024-01-01T00:00:00Z"); // Placeholder
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
    const subject = try std.fmt.allocPrint(allocator, "acct:{s}@speedy-socials.local", .{username});
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
                .href = try std.fmt.allocPrint(allocator, "https://speedy-socials.local/users/{s}.atom", .{username}),
            },
            .{
                .rel = "self",
                .type = "application/activity+json",
                .href = profile_url,
            },
        }),
    };
}

// HTTP Signature for federation
pub const HttpSignature = struct {
    key_id: []const u8,
    algorithm: []const u8 = "rsa-sha256",
    headers: []const u8,
    signature: []const u8,

    pub fn deinit(self: *HttpSignature, allocator: std.mem.Allocator) void {
        allocator.free(self.key_id);
        allocator.free(self.algorithm);
        allocator.free(self.headers);
        allocator.free(self.signature);
    }
};

// Generate HTTP signature for federation requests
pub fn generateHttpSignature(allocator: std.mem.Allocator, _: []const u8, key_id: []const u8, method: []const u8, target: []const u8, host: []const u8, date: []const u8, digest: ?[]const u8) !HttpSignature {
    // Create signing string
    var signing_string = std.array_list.Managed(u8).init(allocator);
    defer signing_string.deinit();

    try std.fmt.format(signing_string.writer(), "(request-target): {s} {s}\n", .{ std.ascii.lowerString(allocator, method), target });
    try std.fmt.format(signing_string.writer(), "host: {s}\n", .{host});
    try std.fmt.format(signing_string.writer(), "date: {s}\n", .{date});
    if (digest) |d| {
        try std.fmt.format(signing_string.writer(), "digest: {s}\n", .{d});
    }

    // Parse private key (simplified - in real implementation, use proper RSA parsing)
    // For now, we'll use a placeholder signature
    const signature_bytes = try allocator.alloc(u8, 256); // RSA-2048 signature size
    defer allocator.free(signature_bytes);

    // Generate random signature for demo (replace with real RSA signing)
    crypto.random.bytes(signature_bytes);

    var signature_b64 = std.array_list.Managed(u8).init(allocator);
    errdefer signature_b64.deinit();

    const encoder = std.base64.standard.Encoder;
    try encoder.encodeWriter(signature_b64.writer(), signature_bytes);

    return HttpSignature{
        .key_id = try allocator.dupe(u8, key_id),
        .algorithm = try allocator.dupe(u8, "rsa-sha256"),
        .headers = try allocator.dupe(u8, "(request-target) host date" ++ if (digest != null) " digest" else ""),
        .signature = signature_b64.toOwnedSlice(),
    };
}

// Deliver activity to remote inbox
pub fn deliverActivity(allocator: std.mem.Allocator, activity_json: []const u8, inbox_url: []const u8, private_key_pem: []const u8, key_id: []const u8) !void {
    // Create HTTP client
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    // Prepare request
    const uri = try std.Uri.parse(inbox_url);

    // Generate date header
    const now = std.time.timestamp();
    // Format timestamp as a simple date string for HTTP Date header
    const date_str = try std.fmt.allocPrint(allocator, "{d}", .{now});
    defer allocator.free(date_str);

    // Generate digest
    const digest = try generateDigest(allocator, activity_json);
    defer allocator.free(digest);

    // Generate signature
    const signature = try generateHttpSignature(allocator, private_key_pem, key_id, "POST", uri.path, uri.host.?, date_str, digest);
    defer signature.deinit(allocator);

    // Create signature header
    const signature_header = try std.fmt.allocPrint(allocator,
        \\keyId="{s}",algorithm="{s}",headers="{s}",signature="{s}"
    , .{ signature.key_id, signature.algorithm, signature.headers, signature.signature });
    defer allocator.free(signature_header);

    // Make request
    const headers = [_]std.http.Header{
        .{ .name = "Host", .value = uri.host.? },
        .{ .name = "Date", .value = date_str },
        .{ .name = "Digest", .value = digest },
        .{ .name = "Signature", .value = signature_header },
        .{ .name = "Content-Type", .value = "application/activity+json" },
        .{ .name = "User-Agent", .value = "SpeedySocials/1.0" },
    };

    var req = try client.request(.POST, uri, .{ .headers = &headers, .keep_alive = false });
    defer req.deinit();

    // Write body
    req.transfer_encoding = .chunked;
    try req.start();
    _ = try req.writer().write(activity_json);
    try req.finish();

    // Read response
    try req.wait();

    if (req.response.status != .ok and req.response.status != .created and req.response.status != .accepted) {
        std.debug.print("Federation delivery failed: {} to {s}\n", .{ req.response.status, inbox_url });
        return error.DeliveryFailed;
    }

    std.debug.print("Successfully delivered activity to {s}\n", .{inbox_url});
}

// Generate SHA-256 digest for HTTP signature
fn generateDigest(allocator: std.mem.Allocator, body: []const u8) ![]u8 {
    var hash: [32]u8 = undefined;
    crypto.hash.sha2.Sha256.hash(body, &hash);

    var digest_buf = std.array_list.Managed(u8).init(allocator);
    errdefer digest_buf.deinit();

    try digest_buf.appendSlice("SHA-256=");
    const encoder = std.base64.standard.Encoder;
    try encoder.encodeWriter(digest_buf.writer(), &hash);

    return digest_buf.toOwnedSlice();
}

// Activity delivery queue item
pub const DeliveryJob = struct {
    activity_json: []const u8,
    inbox_url: []const u8,
    private_key_pem: []const u8,
    key_id: []const u8,

    pub fn deinit(self: *DeliveryJob, allocator: std.mem.Allocator) void {
        allocator.free(self.activity_json);
        allocator.free(self.inbox_url);
        allocator.free(self.private_key_pem);
        allocator.free(self.key_id);
    }
};

// Process federation delivery job
pub fn processDeliveryJob(allocator: std.mem.Allocator, job: DeliveryJob) !void {
    defer job.deinit(allocator);

    try deliverActivity(allocator, job.activity_json, job.inbox_url, job.private_key_pem, job.key_id);
}

// Queue activity for delivery to remote server
pub fn queueActivityDelivery(allocator: std.mem.Allocator, _: anytype, activity_json: []const u8, inbox_url: []const u8, private_key_pem: []const u8, key_id: []const u8) !void {
    const job = DeliveryJob{
        .activity_json = try allocator.dupe(u8, activity_json),
        .inbox_url = try allocator.dupe(u8, inbox_url),
        .private_key_pem = try allocator.dupe(u8, private_key_pem),
        .key_id = try allocator.dupe(u8, key_id),
    };

    // Add to job queue (simplified - in real implementation, pass to job system)
    _ = job;
    std.debug.print("Queued activity delivery to {s}\n", .{inbox_url});
}

// Get followers' inboxes for activity delivery
pub fn getFollowersInboxes(allocator: std.mem.Allocator, _: *database.Database, _: i64) ![]const []const u8 {
    var inboxes = std.array_list.Managed([]const u8).init(allocator);
    errdefer {
        for (inboxes.items) |inbox| allocator.free(inbox);
        inboxes.deinit();
    }

    // Query followers and their shared inboxes
    // This is a simplified version - in real implementation, you'd query the database
    // for followers and their ActivityPub inboxes

    // For demo, return some example inboxes
    try inboxes.append(try allocator.dupe(u8, "https://mastodon.social/inbox"));
    try inboxes.append(try allocator.dupe(u8, "https://pixelfed.social/inbox"));

    return inboxes.toOwnedSlice();
}

// Broadcast activity to all followers
pub fn broadcastToFollowers(allocator: std.mem.Allocator, db: *database.Database, job_queue: anytype, activity_json: []const u8, user_id: i64, private_key_pem: []const u8, key_id: []const u8) !void {
    const inboxes = try getFollowersInboxes(allocator, db, user_id);
    defer {
        for (inboxes) |inbox| allocator.free(inbox);
        allocator.free(inboxes);
    }

    for (inboxes) |inbox_url| {
        try queueActivityDelivery(allocator, job_queue, activity_json, inbox_url, private_key_pem, key_id);
    }
}
