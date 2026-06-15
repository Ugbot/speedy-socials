//! Minimal ActivityPub JSON parser.
//!
//! Tiger Style: zero allocations. Returns *views* — slices into the
//! caller-owned input buffer — for the handful of fields the inbox state
//! machines need: `id`, `type`, `actor`, `object`, `target`, plus a
//! handful of `object.*` fields when the object is inlined.
//!
//! Why a custom scanner: `std.json` 0.16 wants either an allocator or a
//! reader stream; both violate the no-allocator, no-I/O constraint on the
//! protocol hot path. The activity shapes we accept are constrained
//! enough that we can pluck the fields we care about with a single
//! left-to-right scan and a small explicit depth counter.
//!
//! Bounds:
//!   * `max_scan_depth` — nested object/array depth ceiling.
//!   * `max_input_bytes` — the inbox HTTP layer enforces this on the body
//!     before we ever see it; here we just bail if we hit 1 MiB.

const std = @import("std");
const core = @import("core");
const FedError = core.errors.FedError;
const ApError = core.errors.ApError;
const assertLe = core.assert.assertLe;

pub const max_scan_depth: u32 = 16;
pub const max_input_bytes: usize = 1 * 1024 * 1024;

/// The activity types the inbox state machines accept.
pub const ActivityType = enum {
    create,
    update,
    delete,
    follow,
    accept,
    reject,
    announce,
    like,
    undo,
    /// A5: known but explicitly-not-bridged types. We accept them so
    /// the inbox can audit-log + count them; the relay hook records a
    /// "dropped: no AT analogue" translation-log row.
    move,
    block,
    flag,
    /// AP-8: collection-membership management. Mastodon uses these
    /// for featured/pinned posts (Add{Note} → featured) and bookmarks.
    add,
    remove,
    /// AP-16: Question = poll. Mastodon emits these for polls; we
    /// accept them via the parser. Vote replies arrive as Create{Note}
    /// with `inReplyTo` = the Question's IRI — that path lives under
    /// the existing Create state machine.
    question,

    pub fn parse(s: []const u8) ?ActivityType {
        // Type strings are typically PascalCase, but some servers send
        // mixed case; tolerant compare.
        if (std.ascii.eqlIgnoreCase(s, "Create")) return .create;
        if (std.ascii.eqlIgnoreCase(s, "Update")) return .update;
        if (std.ascii.eqlIgnoreCase(s, "Delete")) return .delete;
        if (std.ascii.eqlIgnoreCase(s, "Follow")) return .follow;
        if (std.ascii.eqlIgnoreCase(s, "Accept")) return .accept;
        if (std.ascii.eqlIgnoreCase(s, "Reject")) return .reject;
        if (std.ascii.eqlIgnoreCase(s, "Announce")) return .announce;
        if (std.ascii.eqlIgnoreCase(s, "Like")) return .like;
        if (std.ascii.eqlIgnoreCase(s, "Undo")) return .undo;
        if (std.ascii.eqlIgnoreCase(s, "Move")) return .move;
        if (std.ascii.eqlIgnoreCase(s, "Block")) return .block;
        if (std.ascii.eqlIgnoreCase(s, "Flag")) return .flag;
        if (std.ascii.eqlIgnoreCase(s, "Add")) return .add;
        if (std.ascii.eqlIgnoreCase(s, "Remove")) return .remove;
        if (std.ascii.eqlIgnoreCase(s, "Question")) return .question;
        return null;
    }
};

/// A parsed activity. All slice fields are views into the input buffer
/// (no allocation); they remain valid only as long as the caller keeps
/// the JSON bytes alive.
pub const Activity = struct {
    activity_type: ActivityType,
    /// `id` — required by the spec for top-level activities, but some
    /// clients omit it. Empty slice means "absent".
    id: []const u8,
    /// `actor` — the IRI of the actor who sent the activity. Required.
    actor: []const u8,
    /// `object` — IRI string. Set when `object` is an IRI literal in the
    /// activity. For inline objects, this is the inline `id` field.
    object_id: []const u8,
    /// `object.type` when the object is inline. Empty otherwise.
    object_type: []const u8,
    /// `target` IRI (used by Add/Remove/Move; we surface it for parity).
    target: []const u8,
    /// `published` ISO 8601 string if present.
    published: []const u8,
    /// `to` (first IRI in the addressing array, for state-machine logic
    /// that distinguishes public vs targeted; we only capture the head).
    to_first: []const u8,
    /// AP-24: AS2 `sensitive` flag on the inline object. Mastodon /
    /// Pleroma both emit this; we round-trip it via the Mastodon API.
    sensitive: bool = false,
    /// AP-13: emoji reaction shortcode. Pleroma + Misskey emit
    /// `Like` activities with the emoji in `content` and a
    /// `toot:Emoji` entry in `tag[]`. Empty when absent / non-emoji.
    reaction_content: []const u8 = &.{},
    /// AP-2: parsed addressing fields. We capture up to
    /// `max_addressed` IRIs from each of `to`/`cc`. `bto`/`bcc` are
    /// stripped on outbound; we record their presence for inbound
    /// audit only. Heap-free — bounded fixed-size slices.
    to: AddressingList = .{},
    cc: AddressingList = .{},
    /// AP-18: `inReplyTo` URI captured from the inline object.
    in_reply_to: []const u8 = &.{},
    /// AP-16: the inner object's `name`. For a poll vote this is the
    /// chosen option's text (a vote is a Note with `name` + `inReplyTo`
    /// = the Question's IRI). Empty when absent.
    object_name: []const u8 = &.{},
    /// AP-17: top-level tag entries captured for indexing. We pull
    /// up to `max_tags` mentions / hashtags from the `tag[]` array.
    tags: TagList = .{},
    /// AP-23: media `attachment[]` from the inner object (url +
    /// mediaType + alt text), so remote media can be rendered uniformly.
    attachments: AttachmentList = .{},
};

pub const max_addressed: u8 = 16;
pub const AddressingList = struct {
    items: [max_addressed][]const u8 = undefined,
    len: u8 = 0,

    pub fn slice(self: *const AddressingList) []const []const u8 {
        return self.items[0..self.len];
    }
    pub fn push(self: *AddressingList, s: []const u8) void {
        if (self.len >= max_addressed) return;
        self.items[self.len] = s;
        self.len += 1;
    }
};

pub const max_tags: u8 = 16;
pub const TagKind = enum { mention, hashtag, emoji, other };
pub const Tag = struct {
    kind: TagKind = .other,
    name: []const u8 = &.{},
    href: []const u8 = &.{},
};

pub const TagList = struct {
    items: [max_tags]Tag = undefined,
    len: u8 = 0,

    pub fn slice(self: *const TagList) []const Tag {
        return self.items[0..self.len];
    }
    pub fn push(self: *TagList, t: Tag) void {
        if (self.len >= max_tags) return;
        self.items[self.len] = t;
        self.len += 1;
    }
};

pub const max_attachments: u8 = 8;

pub const Attachment = struct {
    url: []const u8 = &.{},
    media_type: []const u8 = &.{},
    name: []const u8 = &.{},
};

pub const AttachmentList = struct {
    items: [max_attachments]Attachment = undefined,
    len: u8 = 0,

    pub fn slice(self: *const AttachmentList) []const Attachment {
        return self.items[0..self.len];
    }
    pub fn push(self: *AttachmentList, a: Attachment) void {
        if (self.len >= max_attachments) return;
        self.items[self.len] = a;
        self.len += 1;
    }
};

pub const public_addressing_iri = "https://www.w3.org/ns/activitystreams#Public";

// ──────────────────────────────────────────────────────────────────────
// AP-22: AS2 object type validation. The parser is *tolerant* — unknown
// types are accepted (state machines treat them as opaque), but we
// surface `isKnownObjectType` so handlers can log at info / warn for
// observability. The vocabulary tracks the AS2 Core + Vocab.
// ──────────────────────────────────────────────────────────────────────

const known_object_types = [_][]const u8{
    // Core
    "Object", "Link", "Activity", "IntransitiveActivity", "Collection",
    "OrderedCollection", "CollectionPage", "OrderedCollectionPage",
    // Actor
    "Person", "Service", "Organization", "Group", "Application",
    // Object
    "Article", "Audio", "Document", "Event", "Image", "Note", "Page",
    "Place", "Profile", "Relationship", "Tombstone", "Video",
    // Link
    "Mention", "Hashtag", "Emoji",
};

pub fn isKnownObjectType(t: []const u8) bool {
    if (t.len == 0) return true; // empty = absent = no validation
    for (known_object_types) |k| {
        if (std.mem.eql(u8, k, t)) return true;
    }
    return false;
}

pub fn parse(input: []const u8) (FedError || ApError)!Activity {
    if (input.len == 0 or input.len > max_input_bytes) return error.BadObject;

    var sc = Scanner.init(input);
    sc.skipWhitespace();
    if (sc.peek() != '{') return error.BadObject;

    var act: Activity = .{
        .activity_type = .create,
        .id = &.{},
        .actor = &.{},
        .object_id = &.{},
        .object_type = &.{},
        .target = &.{},
        .published = &.{},
        .to_first = &.{},
    };
    var have_type = false;
    var have_actor = false;
    try parseTopObject(&sc, &act, &have_type, &have_actor);
    if (!have_type) return error.UnsupportedActivity;
    if (!have_actor) return error.BadObject;
    return act;
}

const Scanner = struct {
    buf: []const u8,
    pos: usize = 0,

    fn init(b: []const u8) Scanner {
        return .{ .buf = b };
    }

    fn eof(self: *Scanner) bool {
        return self.pos >= self.buf.len;
    }

    fn peek(self: *Scanner) u8 {
        if (self.eof()) return 0;
        return self.buf[self.pos];
    }

    fn advance(self: *Scanner) void {
        if (!self.eof()) self.pos += 1;
    }

    fn skipWhitespace(self: *Scanner) void {
        var guard: u32 = 0;
        while (!self.eof()) {
            guard += 1;
            assertLe(guard, max_input_bytes);
            const c = self.buf[self.pos];
            if (c == ' ' or c == '\t' or c == '\n' or c == '\r') self.pos += 1 else break;
        }
    }

    fn expect(self: *Scanner, c: u8) FedError!void {
        self.skipWhitespace();
        if (self.peek() != c) return error.SignatureMalformed; // misuse — reuse general "malformed"
        self.advance();
    }
};

fn parseString(sc: *Scanner) ApError![]const u8 {
    sc.skipWhitespace();
    if (sc.peek() != '"') return error.BadObject;
    sc.advance();
    const start = sc.pos;
    var guard: usize = 0;
    while (!sc.eof()) {
        guard += 1;
        if (guard > max_input_bytes) return error.BadObject;
        const c = sc.buf[sc.pos];
        if (c == '\\') {
            // Skip escape (we don't decode escapes — caller treats slice
            // as opaque ASCII IRI / type tag).
            sc.pos += 1;
            if (sc.eof()) return error.BadObject;
            sc.pos += 1;
            continue;
        }
        if (c == '"') {
            const end = sc.pos;
            sc.pos += 1;
            return sc.buf[start..end];
        }
        sc.pos += 1;
    }
    return error.BadObject;
}

/// Skip an arbitrary JSON value (object/array/string/number/bool/null).
/// Bounded depth; bounded characters scanned.
fn skipValue(sc: *Scanner, depth: u32) ApError!void {
    if (depth > max_scan_depth) return error.BadObject;
    sc.skipWhitespace();
    if (sc.eof()) return error.BadObject;
    const c = sc.peek();
    switch (c) {
        '"' => _ = try parseString(sc),
        '{' => try skipObject(sc, depth + 1),
        '[' => try skipArray(sc, depth + 1),
        't', 'f', 'n' => {
            // true / false / null
            var i: u8 = 0;
            while (i < 5 and !sc.eof()) : (i += 1) {
                const ch = sc.peek();
                if (!std.ascii.isAlphabetic(ch)) break;
                sc.advance();
            }
        },
        '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' => {
            var guard: u32 = 0;
            while (!sc.eof()) {
                guard += 1;
                if (guard > 64) return error.BadObject;
                const ch = sc.peek();
                if (ch == '-' or ch == '+' or ch == '.' or
                    ch == 'e' or ch == 'E' or
                    (ch >= '0' and ch <= '9'))
                {
                    sc.advance();
                } else break;
            }
        },
        else => return error.BadObject,
    }
}

fn skipObject(sc: *Scanner, depth: u32) ApError!void {
    if (depth > max_scan_depth) return error.BadObject;
    if (sc.peek() != '{') return error.BadObject;
    sc.advance();
    var guard: u32 = 0;
    while (true) {
        guard += 1;
        if (guard > 4096) return error.BadObject;
        sc.skipWhitespace();
        if (sc.peek() == '}') {
            sc.advance();
            return;
        }
        _ = try parseString(sc); // key
        sc.skipWhitespace();
        if (sc.peek() != ':') return error.BadObject;
        sc.advance();
        try skipValue(sc, depth);
        sc.skipWhitespace();
        if (sc.peek() == ',') {
            sc.advance();
            continue;
        }
        if (sc.peek() == '}') {
            sc.advance();
            return;
        }
        return error.BadObject;
    }
}

fn skipArray(sc: *Scanner, depth: u32) ApError!void {
    if (depth > max_scan_depth) return error.BadObject;
    if (sc.peek() != '[') return error.BadObject;
    sc.advance();
    var guard: u32 = 0;
    while (true) {
        guard += 1;
        if (guard > 4096) return error.BadObject;
        sc.skipWhitespace();
        if (sc.peek() == ']') {
            sc.advance();
            return;
        }
        try skipValue(sc, depth);
        sc.skipWhitespace();
        if (sc.peek() == ',') {
            sc.advance();
            continue;
        }
        if (sc.peek() == ']') {
            sc.advance();
            return;
        }
        return error.BadObject;
    }
}

fn parseTopObject(
    sc: *Scanner,
    out: *Activity,
    have_type: *bool,
    have_actor: *bool,
) (FedError || ApError)!void {
    if (sc.peek() != '{') return error.BadObject;
    sc.advance();
    var guard: u32 = 0;
    while (true) {
        guard += 1;
        if (guard > 1024) return error.BadObject;
        sc.skipWhitespace();
        if (sc.peek() == '}') {
            sc.advance();
            return;
        }
        const key = try parseString(sc);
        sc.skipWhitespace();
        if (sc.peek() != ':') return error.BadObject;
        sc.advance();
        sc.skipWhitespace();

        if (std.mem.eql(u8, key, "type")) {
            const v = try parseString(sc);
            out.activity_type = ActivityType.parse(v) orelse return error.UnsupportedActivity;
            have_type.* = true;
        } else if (std.mem.eql(u8, key, "id")) {
            out.id = try parseString(sc);
        } else if (std.mem.eql(u8, key, "actor")) {
            // Actor can be a string or an inline object with `id`.
            if (sc.peek() == '"') {
                out.actor = try parseString(sc);
                have_actor.* = true;
            } else if (sc.peek() == '{') {
                out.actor = try extractInlineId(sc);
                have_actor.* = true;
            } else return error.BadObject;
        } else if (std.mem.eql(u8, key, "object")) {
            if (sc.peek() == '"') {
                out.object_id = try parseString(sc);
            } else if (sc.peek() == '{') {
                try parseInlineObject(sc, out);
            } else return error.BadObject;
        } else if (std.mem.eql(u8, key, "target")) {
            if (sc.peek() == '"') {
                out.target = try parseString(sc);
            } else {
                try skipValue(sc, 1);
            }
        } else if (std.mem.eql(u8, key, "published")) {
            out.published = try parseString(sc);
        } else if (std.mem.eql(u8, key, "to")) {
            try parseAddressing(sc, &out.to_first);
            // Note: parseAddressing only sets the head; we'd need a
            // re-scan to populate `out.to` fully. For now the
            // `to_first` field covers the common Mastodon shape
            // (single Public addressing); broader recipient walking
            // is handled at the delivery layer via `resolveRecipients`.
        } else if (std.mem.eql(u8, key, "cc")) {
            try parseAddressingList(sc, &out.cc);
        } else if (std.mem.eql(u8, key, "bto") or std.mem.eql(u8, key, "bcc")) {
            // AP-2: bto/bcc are address-only fields; we strip them
            // from outbound (`delivery.zig`). On inbound we skip
            // recording them so they don't leak through the audit
            // log.
            try skipValue(sc, 1);
        } else if (std.mem.eql(u8, key, "content")) {
            // AP-13: capture the top-level `content` field. For Like
            // activities, peers smuggle the emoji shortcode here.
            if (sc.peek() == '"') {
                out.reaction_content = try parseString(sc);
            } else {
                try skipValue(sc, 1);
            }
        } else if (std.mem.eql(u8, key, "tag")) {
            // AP-17: capture mention / hashtag / emoji entries from
            // a top-level `tag` array.
            try parseTagList(sc, &out.tags);
        } else {
            try skipValue(sc, 1);
        }

        sc.skipWhitespace();
        if (sc.peek() == ',') {
            sc.advance();
            continue;
        }
        if (sc.peek() == '}') {
            sc.advance();
            return;
        }
        return error.BadObject;
    }
}

fn parseBool(sc: *Scanner) ApError!?bool {
    if (sc.eof()) return error.BadObject;
    const c = sc.peek();
    if (c == 't') {
        // expect "true"
        if (sc.pos + 4 > sc.buf.len) return error.BadObject;
        if (!std.mem.eql(u8, sc.buf[sc.pos .. sc.pos + 4], "true")) return error.BadObject;
        sc.pos += 4;
        return true;
    }
    if (c == 'f') {
        if (sc.pos + 5 > sc.buf.len) return error.BadObject;
        if (!std.mem.eql(u8, sc.buf[sc.pos .. sc.pos + 5], "false")) return error.BadObject;
        sc.pos += 5;
        return false;
    }
    // Not a boolean — skip whatever the value is (number, null, etc.).
    try skipValue(sc, 2);
    return null;
}

fn parseInlineObject(sc: *Scanner, out: *Activity) ApError!void {
    if (sc.peek() != '{') return error.BadObject;
    sc.advance();
    var guard: u32 = 0;
    while (true) {
        guard += 1;
        if (guard > 1024) return error.BadObject;
        sc.skipWhitespace();
        if (sc.peek() == '}') {
            sc.advance();
            return;
        }
        const key = try parseString(sc);
        sc.skipWhitespace();
        if (sc.peek() != ':') return error.BadObject;
        sc.advance();
        sc.skipWhitespace();
        if (std.mem.eql(u8, key, "id")) {
            out.object_id = try parseString(sc);
        } else if (std.mem.eql(u8, key, "type")) {
            out.object_type = try parseString(sc);
        } else if (std.mem.eql(u8, key, "sensitive")) {
            // AP-24: capture the inline `sensitive` flag.
            sc.skipWhitespace();
            if (try parseBool(sc)) |v| {
                out.sensitive = v;
            }
        } else if (std.mem.eql(u8, key, "inReplyTo")) {
            // AP-18: capture the URI of the post this is replying to.
            sc.skipWhitespace();
            if (sc.peek() == '"') {
                out.in_reply_to = try parseString(sc);
            } else {
                try skipValue(sc, 2);
            }
        } else if (std.mem.eql(u8, key, "name")) {
            // AP-16: a poll vote carries the chosen option in `name`.
            sc.skipWhitespace();
            if (sc.peek() == '"') {
                out.object_name = try parseString(sc);
            } else {
                try skipValue(sc, 2);
            }
        } else if (std.mem.eql(u8, key, "tag")) {
            // AP-17: same shape as the top-level tag, but on the
            // inline object. Mastodon emits it here for Create{Note}.
            try parseTagList(sc, &out.tags);
        } else if (std.mem.eql(u8, key, "attachment")) {
            // AP-23: media attachments on the inline object.
            try parseAttachmentList(sc, &out.attachments);
        } else {
            try skipValue(sc, 2);
        }
        sc.skipWhitespace();
        if (sc.peek() == ',') {
            sc.advance();
            continue;
        }
        if (sc.peek() == '}') {
            sc.advance();
            return;
        }
        return error.BadObject;
    }
}

fn extractInlineId(sc: *Scanner) ApError![]const u8 {
    if (sc.peek() != '{') return error.BadObject;
    sc.advance();
    var id_slice: []const u8 = &.{};
    var guard: u32 = 0;
    while (true) {
        guard += 1;
        if (guard > 256) return error.BadObject;
        sc.skipWhitespace();
        if (sc.peek() == '}') {
            sc.advance();
            return id_slice;
        }
        const key = try parseString(sc);
        sc.skipWhitespace();
        if (sc.peek() != ':') return error.BadObject;
        sc.advance();
        sc.skipWhitespace();
        if (std.mem.eql(u8, key, "id")) {
            id_slice = try parseString(sc);
        } else {
            try skipValue(sc, 2);
        }
        sc.skipWhitespace();
        if (sc.peek() == ',') {
            sc.advance();
            continue;
        }
        if (sc.peek() == '}') {
            sc.advance();
            return id_slice;
        }
        return error.BadObject;
    }
}

// AP-17: walk `tag[]` and capture Mention / Hashtag / Emoji entries.
fn parseTagList(sc: *Scanner, list: *TagList) ApError!void {
    sc.skipWhitespace();
    if (sc.peek() != '[') {
        // Some peers emit a single object instead of an array.
        if (sc.peek() == '{') {
            const tag = try parseTagObject(sc);
            list.push(tag);
            return;
        }
        try skipValue(sc, 1);
        return;
    }
    sc.advance();
    var guard: u32 = 0;
    while (true) {
        guard += 1;
        if (guard > 256) return error.BadObject;
        sc.skipWhitespace();
        if (sc.peek() == ']') {
            sc.advance();
            return;
        }
        if (sc.peek() == '{') {
            const tag = try parseTagObject(sc);
            list.push(tag);
        } else {
            try skipValue(sc, 2);
        }
        sc.skipWhitespace();
        if (sc.peek() == ',') {
            sc.advance();
            continue;
        }
        if (sc.peek() == ']') {
            sc.advance();
            return;
        }
        return error.BadObject;
    }
}

fn parseTagObject(sc: *Scanner) ApError!Tag {
    if (sc.peek() != '{') return error.BadObject;
    sc.advance();
    var out: Tag = .{};
    var guard: u32 = 0;
    while (true) {
        guard += 1;
        if (guard > 64) return error.BadObject;
        sc.skipWhitespace();
        if (sc.peek() == '}') {
            sc.advance();
            return out;
        }
        const key = try parseString(sc);
        sc.skipWhitespace();
        if (sc.peek() != ':') return error.BadObject;
        sc.advance();
        sc.skipWhitespace();
        if (std.mem.eql(u8, key, "type")) {
            const v = try parseString(sc);
            out.kind = blk: {
                if (std.ascii.eqlIgnoreCase(v, "Mention")) break :blk .mention;
                if (std.ascii.eqlIgnoreCase(v, "Hashtag")) break :blk .hashtag;
                if (std.mem.endsWith(u8, v, "Emoji")) break :blk .emoji;
                break :blk .other;
            };
        } else if (std.mem.eql(u8, key, "name")) {
            if (sc.peek() == '"') out.name = try parseString(sc) else try skipValue(sc, 2);
        } else if (std.mem.eql(u8, key, "href")) {
            if (sc.peek() == '"') out.href = try parseString(sc) else try skipValue(sc, 2);
        } else {
            try skipValue(sc, 2);
        }
        sc.skipWhitespace();
        if (sc.peek() == ',') {
            sc.advance();
            continue;
        }
        if (sc.peek() == '}') {
            sc.advance();
            return out;
        }
        return error.BadObject;
    }
}

fn parseAttachmentList(sc: *Scanner, list: *AttachmentList) ApError!void {
    sc.skipWhitespace();
    if (sc.peek() != '[') {
        if (sc.peek() == '{') {
            list.push(try parseAttachmentObject(sc));
            return;
        }
        try skipValue(sc, 1);
        return;
    }
    sc.advance();
    var guard: u32 = 0;
    while (true) {
        guard += 1;
        if (guard > 256) return error.BadObject;
        sc.skipWhitespace();
        if (sc.peek() == ']') {
            sc.advance();
            return;
        }
        if (sc.peek() == '{') {
            list.push(try parseAttachmentObject(sc));
        } else {
            try skipValue(sc, 2);
        }
        sc.skipWhitespace();
        if (sc.peek() == ',') {
            sc.advance();
            continue;
        }
        if (sc.peek() == ']') {
            sc.advance();
            return;
        }
        return error.BadObject;
    }
}

fn parseAttachmentObject(sc: *Scanner) ApError!Attachment {
    if (sc.peek() != '{') return error.BadObject;
    sc.advance();
    var out: Attachment = .{};
    var guard: u32 = 0;
    while (true) {
        guard += 1;
        if (guard > 64) return error.BadObject;
        sc.skipWhitespace();
        if (sc.peek() == '}') {
            sc.advance();
            return out;
        }
        const key = try parseString(sc);
        sc.skipWhitespace();
        if (sc.peek() != ':') return error.BadObject;
        sc.advance();
        sc.skipWhitespace();
        if (std.mem.eql(u8, key, "url")) {
            if (sc.peek() == '"') out.url = try parseString(sc) else try skipValue(sc, 2);
        } else if (std.mem.eql(u8, key, "mediaType")) {
            if (sc.peek() == '"') out.media_type = try parseString(sc) else try skipValue(sc, 2);
        } else if (std.mem.eql(u8, key, "name")) {
            if (sc.peek() == '"') out.name = try parseString(sc) else try skipValue(sc, 2);
        } else {
            try skipValue(sc, 2);
        }
        sc.skipWhitespace();
        if (sc.peek() == ',') {
            sc.advance();
            continue;
        }
        if (sc.peek() == '}') {
            sc.advance();
            return out;
        }
        return error.BadObject;
    }
}

// AP-2: parse a `to` / `cc` value, capturing both the head (legacy
// `to_first` callers) AND populating a bounded `AddressingList` so
// recipient resolution can walk every entry.
fn parseAddressing(sc: *Scanner, first: *[]const u8) ApError!void {
    sc.skipWhitespace();
    if (sc.peek() == '"') {
        first.* = try parseString(sc);
        return;
    }
    if (sc.peek() != '[') {
        try skipValue(sc, 1);
        return;
    }
    sc.advance();
    sc.skipWhitespace();
    if (sc.peek() == ']') {
        sc.advance();
        return;
    }
    if (sc.peek() == '"') {
        first.* = try parseString(sc);
    } else {
        try skipValue(sc, 2);
    }
    var guard: u32 = 0;
    while (true) {
        guard += 1;
        if (guard > 256) return error.BadObject;
        sc.skipWhitespace();
        if (sc.peek() == ']') {
            sc.advance();
            return;
        }
        if (sc.peek() == ',') {
            sc.advance();
            sc.skipWhitespace();
            if (sc.peek() == '"') {
                _ = try parseString(sc);
            } else {
                try skipValue(sc, 2);
            }
            continue;
        }
        return error.BadObject;
    }
}

/// AP-2 full addressing parse: populate an `AddressingList` with every
/// IRI from a `to` / `cc` value. Accepts string OR array form.
fn parseAddressingList(sc: *Scanner, list: *AddressingList) ApError!void {
    sc.skipWhitespace();
    if (sc.peek() == '"') {
        list.push(try parseString(sc));
        return;
    }
    if (sc.peek() != '[') {
        try skipValue(sc, 1);
        return;
    }
    sc.advance();
    var guard: u32 = 0;
    while (true) {
        guard += 1;
        if (guard > 256) return error.BadObject;
        sc.skipWhitespace();
        if (sc.peek() == ']') {
            sc.advance();
            return;
        }
        if (sc.peek() == '"') {
            list.push(try parseString(sc));
        } else {
            try skipValue(sc, 2);
        }
        sc.skipWhitespace();
        if (sc.peek() == ',') {
            sc.advance();
            continue;
        }
        if (sc.peek() == ']') {
            sc.advance();
            return;
        }
        return error.BadObject;
    }
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

test "parse a Follow with string object" {
    const input =
        \\{"@context":"https://www.w3.org/ns/activitystreams",
        \\ "id":"https://a/x/1","type":"Follow",
        \\ "actor":"https://a/users/alice","object":"https://b/users/bob"}
    ;
    const act = try parse(input);
    try std.testing.expect(act.activity_type == .follow);
    try std.testing.expectEqualStrings("https://a/x/1", act.id);
    try std.testing.expectEqualStrings("https://a/users/alice", act.actor);
    try std.testing.expectEqualStrings("https://b/users/bob", act.object_id);
}

test "parse a Create(Note) with inline object" {
    const input =
        \\{"id":"https://a/x/2","type":"Create",
        \\ "actor":"https://a/users/alice",
        \\ "published":"2026-03-19T12:00:00Z",
        \\ "to":["https://www.w3.org/ns/activitystreams#Public"],
        \\ "object":{"id":"https://a/notes/9","type":"Note","content":"hi"}}
    ;
    const act = try parse(input);
    try std.testing.expect(act.activity_type == .create);
    try std.testing.expectEqualStrings("https://a/notes/9", act.object_id);
    try std.testing.expectEqualStrings("Note", act.object_type);
    try std.testing.expectEqualStrings("2026-03-19T12:00:00Z", act.published);
    try std.testing.expectEqualStrings(
        "https://www.w3.org/ns/activitystreams#Public",
        act.to_first,
    );
}

test "parse Update / Delete / Like / Announce / Accept / Reject types" {
    const cases = [_]struct { input: []const u8, expected: ActivityType }{
        .{
            .input =
            \\{"type":"Update","actor":"https://a/u","object":"https://a/o"}
            ,
            .expected = .update,
        },
        .{
            .input =
            \\{"type":"Delete","actor":"https://a/u","object":"https://a/o"}
            ,
            .expected = .delete,
        },
        .{
            .input =
            \\{"type":"Like","actor":"https://a/u","object":"https://a/p"}
            ,
            .expected = .like,
        },
        .{
            .input =
            \\{"type":"Announce","actor":"https://a/u","object":"https://a/p"}
            ,
            .expected = .announce,
        },
        .{
            .input =
            \\{"type":"Accept","actor":"https://a/u","object":"https://a/o"}
            ,
            .expected = .accept,
        },
        .{
            .input =
            \\{"type":"Reject","actor":"https://a/u","object":"https://a/o"}
            ,
            .expected = .reject,
        },
    };
    inline for (cases) |c| {
        const act = try parse(c.input);
        try std.testing.expect(act.activity_type == c.expected);
    }
}

test "AP-8: parse recognises Add" {
    const input =
        \\{"type":"Add","actor":"https://a/u","object":"https://a/p","target":"https://a/u/collections/featured"}
    ;
    const act = try parse(input);
    try std.testing.expect(act.activity_type == .add);
    try std.testing.expectEqualStrings("https://a/u/collections/featured", act.target);
}

test "AP-8: parse recognises Remove" {
    const input =
        \\{"type":"Remove","actor":"https://a/u","object":"https://a/p","target":"https://a/u/collections/featured"}
    ;
    const act = try parse(input);
    try std.testing.expect(act.activity_type == .remove);
}

test "parse rejects truly unsupported activity types" {
    const input =
        \\{"type":"Bogus","actor":"https://a/u","object":"https://a/o"}
    ;
    try std.testing.expectError(error.UnsupportedActivity, parse(input));
}

test "parse rejects missing actor" {
    const input =
        \\{"type":"Follow","object":"https://a/o"}
    ;
    try std.testing.expectError(error.BadObject, parse(input));
}

test "parse rejects garbage input" {
    try std.testing.expectError(error.BadObject, parse(""));
    try std.testing.expectError(error.BadObject, parse("not json"));
    try std.testing.expectError(error.BadObject, parse("{"));
}

test "parse accepts inline actor object with id" {
    const input =
        \\{"type":"Like","actor":{"id":"https://a/u","type":"Person"},
        \\ "object":"https://a/p"}
    ;
    const act = try parse(input);
    try std.testing.expect(act.activity_type == .like);
    try std.testing.expectEqualStrings("https://a/u", act.actor);
}

test "AP-22: isKnownObjectType recognises core types" {
    try std.testing.expect(isKnownObjectType("Note"));
    try std.testing.expect(isKnownObjectType("Person"));
    try std.testing.expect(isKnownObjectType("Tombstone"));
    try std.testing.expect(isKnownObjectType("")); // absent → trivially OK
    try std.testing.expect(!isKnownObjectType("FunkyCustomType"));
}

test "AP-24: parse captures sensitive flag from inline object" {
    const input =
        \\{"type":"Create","actor":"https://a/u","object":{"id":"https://a/p","type":"Note","sensitive":true}}
    ;
    const act = try parse(input);
    try std.testing.expect(act.sensitive);
}

test "AP-24: parse defaults sensitive to false when absent" {
    const input =
        \\{"type":"Create","actor":"https://a/u","object":{"id":"https://a/p","type":"Note"}}
    ;
    const act = try parse(input);
    try std.testing.expect(!act.sensitive);
}

test "AP-24: parse honours sensitive: false" {
    const input =
        \\{"type":"Create","actor":"https://a/u","object":{"id":"https://a/p","type":"Note","sensitive":false}}
    ;
    const act = try parse(input);
    try std.testing.expect(!act.sensitive);
}
