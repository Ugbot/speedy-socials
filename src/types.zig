const std = @import("std");

// Common types for both Mastodon API and AT Protocol

pub const Account = struct {
    id: []const u8,
    username: []const u8,
    acct: []const u8, // username@domain
    display_name: []const u8,
    locked: bool = false,
    bot: bool = false,
    discoverable: bool = true,
    group: bool = false,
    created_at: []const u8, // ISO 8601 datetime
    note: []const u8,
    url: []const u8,
    avatar: ?[]const u8 = null,
    avatar_static: ?[]const u8 = null,
    header: ?[]const u8 = null,
    header_static: ?[]const u8 = null,
    followers_count: u32 = 0,
    following_count: u32 = 0,
    statuses_count: u32 = 0,
    last_status_at: ?[]const u8 = null,

    pub fn deinit(self: *Account, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.username);
        allocator.free(self.acct);
        allocator.free(self.display_name);
        allocator.free(self.created_at);
        allocator.free(self.note);
        allocator.free(self.url);
        if (self.avatar) |avatar| allocator.free(avatar);
        if (self.avatar_static) |avatar_static| allocator.free(avatar_static);
        if (self.header) |header| allocator.free(header);
        if (self.header_static) |header_static| allocator.free(header_static);
        if (self.last_status_at) |last_status_at| allocator.free(last_status_at);
    }
};

pub const Status = struct {
    id: []const u8,
    uri: []const u8,
    created_at: []const u8,
    account: Account,
    content: []const u8,
    visibility: Visibility,
    sensitive: bool = false,
    spoiler_text: ?[]const u8 = null,
    media_attachments: []MediaAttachment = &[_]MediaAttachment{},
    mentions: []Mention = &[_]Mention{},
    tags: []Tag = &[_]Tag{},
    emojis: []Emoji = &[_]Emoji{},
    reblogs_count: u32 = 0,
    favourites_count: u32 = 0,
    replies_count: u32 = 0,
    url: ?[]const u8 = null,
    in_reply_to_id: ?[]const u8 = null,
    in_reply_to_account_id: ?[]const u8 = null,
    reblog: ?*Status = null,
    poll: ?Poll = null,
    card: ?Card = null,
    language: ?[]const u8 = null,
    text: ?[]const u8 = null,
    favourited: bool = false,
    reblogged: bool = false,
    muted: bool = false,
    bookmarked: bool = false,
    pinned: bool = false,

    pub const Visibility = enum {
        public,
        unlisted,
        private,
        direct,
    };

    pub fn deinit(self: *Status, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.uri);
        allocator.free(self.created_at);
        allocator.free(self.content);
        if (self.spoiler_text) |spoiler_text| allocator.free(spoiler_text);
        for (self.media_attachments) |*attachment| attachment.deinit(allocator);
        allocator.free(self.media_attachments);
        for (self.mentions) |*mention| mention.deinit(allocator);
        allocator.free(self.mentions);
        for (self.tags) |*tag| tag.deinit(allocator);
        allocator.free(self.tags);
        for (self.emojis) |*emoji| emoji.deinit(allocator);
        allocator.free(self.emojis);
        if (self.url) |url| allocator.free(url);
        if (self.in_reply_to_id) |in_reply_to_id| allocator.free(in_reply_to_id);
        if (self.in_reply_to_account_id) |in_reply_to_account_id| allocator.free(in_reply_to_account_id);
        if (self.reblog) |reblog| reblog.deinit(allocator);
        if (self.poll) |poll| poll.deinit(allocator);
        if (self.card) |card| card.deinit(allocator);
        if (self.language) |language| allocator.free(language);
        if (self.text) |text| allocator.free(text);
        self.account.deinit(allocator);
    }
};

pub const MediaAttachment = struct {
    id: []const u8,
    type: MediaType,
    url: []const u8,
    preview_url: []const u8,
    remote_url: ?[]const u8 = null,
    meta: MediaMeta,
    description: ?[]const u8 = null,
    blurhash: ?[]const u8 = null,

    pub const MediaType = enum {
        image,
        video,
        gifv,
        audio,
        unknown,
    };

    pub const MediaMeta = union(MediaType) {
        image: ImageMeta,
        video: VideoMeta,
        gifv: VideoMeta,
        audio: AudioMeta,
        unknown: void,
    };

    pub const ImageMeta = struct {
        width: u32,
        height: u32,
        size: []const u8,
        aspect: f32,
    };

    pub const VideoMeta = struct {
        width: u32,
        height: u32,
        frame_rate: []const u8,
        duration: f32,
        bitrate: u32,
    };

    pub const AudioMeta = struct {
        duration: f32,
        bitrate: u32,
    };

    pub fn deinit(self: *MediaAttachment, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.url);
        allocator.free(self.preview_url);
        if (self.remote_url) |remote_url| allocator.free(remote_url);
        if (self.description) |description| allocator.free(description);
        if (self.blurhash) |blurhash| allocator.free(blurhash);
    }
};

pub const Mention = struct {
    id: []const u8,
    username: []const u8,
    url: []const u8,
    acct: []const u8,

    pub fn deinit(self: *Mention, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.username);
        allocator.free(self.url);
        allocator.free(self.acct);
    }
};

pub const Tag = struct {
    name: []const u8,
    url: []const u8,
    history: ?[]HistoryItem = null,

    pub const HistoryItem = struct {
        day: []const u8,
        uses: []const u8,
        accounts: []const u8,
    };

    pub fn deinit(self: *Tag, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.url);
        if (self.history) |history| {
            for (history) |*item| {
                allocator.free(item.day);
                allocator.free(item.uses);
                allocator.free(item.accounts);
            }
            allocator.free(history);
        }
    }
};

pub const Emoji = struct {
    shortcode: []const u8,
    url: []const u8,
    static_url: []const u8,
    visible_in_picker: bool,
    category: ?[]const u8 = null,

    pub fn deinit(self: *Emoji, allocator: std.mem.Allocator) void {
        allocator.free(self.shortcode);
        allocator.free(self.url);
        allocator.free(self.static_url);
        if (self.category) |category| allocator.free(category);
    }
};

pub const Poll = struct {
    id: []const u8,
    expires_at: ?[]const u8 = null,
    expired: bool = false,
    multiple: bool = false,
    votes_count: u32 = 0,
    voters_count: ?u32 = null,
    voted: bool = false,
    own_votes: ?[]u32 = null,
    options: []PollOption,
    emojis: []Emoji = &[_]Emoji{},

    pub const PollOption = struct {
        title: []const u8,
        votes_count: ?u32 = null,
    };

    pub fn deinit(self: *Poll, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        if (self.expires_at) |expires_at| allocator.free(expires_at);
        if (self.own_votes) |own_votes| allocator.free(own_votes);
        for (self.options) |*option| allocator.free(option.title);
        allocator.free(self.options);
        for (self.emojis) |*emoji| emoji.deinit(allocator);
        allocator.free(self.emojis);
    }
};

pub const Card = struct {
    url: []const u8,
    title: []const u8,
    description: []const u8,
    type: CardType,
    author_name: ?[]const u8 = null,
    author_url: ?[]const u8 = null,
    provider_name: ?[]const u8 = null,
    provider_url: ?[]const u8 = null,
    html: ?[]const u8 = null,
    width: ?u32 = null,
    height: ?u32 = null,
    image: ?[]const u8 = null,
    embed_url: ?[]const u8 = null,
    blurhash: ?[]const u8 = null,

    pub const CardType = enum {
        link,
        photo,
        video,
        rich,
    };

    pub fn deinit(self: *Card, allocator: std.mem.Allocator) void {
        allocator.free(self.url);
        allocator.free(self.title);
        allocator.free(self.description);
        if (self.author_name) |author_name| allocator.free(author_name);
        if (self.author_url) |author_url| allocator.free(author_url);
        if (self.provider_name) |provider_name| allocator.free(provider_name);
        if (self.provider_url) |provider_url| allocator.free(provider_url);
        if (self.html) |html| allocator.free(html);
        if (self.image) |image| allocator.free(image);
        if (self.embed_url) |embed_url| allocator.free(embed_url);
        if (self.blurhash) |blurhash| allocator.free(blurhash);
    }
};

pub const Instance = struct {
    uri: []const u8,
    title: []const u8,
    description: []const u8,
    short_description: []const u8,
    email: []const u8,
    version: []const u8,
    languages: [][]const u8,
    registrations: bool,
    approval_required: bool,
    invites_enabled: bool,
    urls: InstanceUrls,
    stats: InstanceStats,
    thumbnail: ?[]const u8 = null,
    contact_account: ?Account = null,

    pub const InstanceUrls = struct {
        streaming_api: []const u8,
    };

    pub const InstanceStats = struct {
        user_count: u32,
        status_count: u32,
        domain_count: u32,
    };

    pub fn deinit(self: *Instance, allocator: std.mem.Allocator) void {
        allocator.free(self.uri);
        allocator.free(self.title);
        allocator.free(self.description);
        allocator.free(self.short_description);
        allocator.free(self.email);
        allocator.free(self.version);
        for (self.languages) |lang| allocator.free(lang);
        allocator.free(self.languages);
        allocator.free(self.urls.streaming_api);
        if (self.thumbnail) |thumbnail| allocator.free(thumbnail);
        if (self.contact_account) |*contact_account| contact_account.deinit(allocator);
    }
};

// AT Protocol specific types
pub const ATProtoRecord = struct {
    @"$type": []const u8,
    text: ?[]const u8 = null,
    createdAt: []const u8,
    // Additional fields depending on record type
    facets: ?[]Facet = null,
    embed: ?Embed = null,

    pub const Facet = struct {
        index: ByteSlice,
        features: []Feature,

        pub const ByteSlice = struct {
            byteStart: u32,
            byteEnd: u32,
        };

        pub const Feature = union(enum) {
            mention: struct { did: []const u8 },
            link: struct { uri: []const u8 },
            tag: struct { tag: []const u8 },
        };
    };

    pub const Embed = union(enum) {
        images: []Image,
        external: External,
        record: RecordRef,
        recordWithMedia: RecordWithMedia,

        pub const Image = struct {
            image: Blob,
            alt: []const u8,
        };

        pub const External = struct {
            uri: []const u8,
            title: []const u8,
            description: []const u8,
        };

        pub const RecordRef = struct {
            record: struct {
                @"$type": []const u8,
                uri: []const u8,
                cid: []const u8,
            },
        };

        pub const RecordWithMedia = struct {
            record: RecordRef,
            media: union(enum) {
                images: []Image,
                external: External,
            },
        };
    };

    pub const Blob = struct {
        @"$type": []const u8 = "blob",
        ref: struct {
            @"$link": []const u8,
        },
        mimeType: []const u8,
        size: u32,
    };

    pub fn deinit(self: *ATProtoRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.@"$type");
        if (self.text) |text| allocator.free(text);
        allocator.free(self.createdAt);
        if (self.facets) |facets| {
            for (facets) |*facet| {
                for (facet.features) |*feature| {
                    switch (feature.*) {
                        .mention => |mention| allocator.free(mention.did),
                        .link => |link| allocator.free(link.uri),
                        .tag => |tag| allocator.free(tag.tag),
                    }
                }
                allocator.free(facet.features);
            }
            allocator.free(facets);
        }
        if (self.embed) |*embed| embed.deinit(allocator);
    }
};

pub fn Embed_deinit(self: *ATProtoRecord.Embed, allocator: std.mem.Allocator) void {
    switch (self.*) {
        .images => |images| {
            for (images) |*image| {
                allocator.free(image.alt);
                // Note: Blob deinit would be handled separately
            }
            allocator.free(images);
        },
        .external => |*external| {
            allocator.free(external.uri);
            allocator.free(external.title);
            allocator.free(external.description);
        },
        .record => {},
        .recordWithMedia => |*record_with_media| {
            switch (record_with_media.media) {
                .images => |images| {
                    for (images) |*image| {
                        allocator.free(image.alt);
                    }
                    allocator.free(images);
                },
                .external => |*external| {
                    allocator.free(external.uri);
                    allocator.free(external.title);
                    allocator.free(external.description);
                },
            }
        },
    }
}
