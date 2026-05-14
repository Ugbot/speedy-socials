//! Pure-function AT ↔ AP translators.
//!
//! Tiger Style:
//!   * No allocations beyond the per-call `*Arena` the caller supplies.
//!   * No recursion: every scan is iterative with a bounded guard.
//!   * No I/O. These functions take parsed views in, build parsed views
//!     out. The pipeline (`subscription.zig`) wraps them with the
//!     database / network writes.
//!   * Bounded buffers: every string the translator produces fits in
//!     `max_translated_bytes`; overflow returns
//!     `RelayError.TranslationBufferTooSmall`.
//!
//! Mapping:
//!
//!   AT → AP
//!     app.bsky.feed.post     → Create(Note)
//!     app.bsky.feed.like     → Like
//!     app.bsky.feed.repost   → Announce
//!     app.bsky.graph.follow  → Follow
//!
//!   AP → AT
//!     Create(Note)           → app.bsky.feed.post
//!     Like                   → app.bsky.feed.like
//!     Announce               → app.bsky.feed.repost
//!     Follow                 → app.bsky.graph.follow

const std = @import("std");
const core = @import("core");
const activitypub = @import("protocol_activitypub");

const RelayError = core.errors.RelayError;
const Arena = core.arena.Arena;
const ActivityType = activitypub.activity.ActivityType;
const Activity = activitypub.activity.Activity;
const assertLe = core.assert.assertLe;

/// Max length of any single translated string we emit (one HTML body,
/// one note id, one AP id, …). Translator returns
/// `TranslationBufferTooSmall` on overflow. Sized to fit a typical
/// social post (300-char Bluesky max + HTML padding) plus generous
/// headroom for facet expansion.
pub const max_translated_bytes: usize = 8 * 1024;

/// Maximum facets/attachments we look at per AT record. Anything past
/// this gets dropped — bounded, Tiger Style.
pub const max_facets: u32 = 32;

/// AT Protocol record kinds we translate.
pub const AtKind = enum {
    post,
    like,
    repost,
    follow,

    pub fn fromCollection(collection: []const u8) ?AtKind {
        if (std.mem.eql(u8, collection, "app.bsky.feed.post")) return .post;
        if (std.mem.eql(u8, collection, "app.bsky.feed.like")) return .like;
        if (std.mem.eql(u8, collection, "app.bsky.feed.repost")) return .repost;
        if (std.mem.eql(u8, collection, "app.bsky.graph.follow")) return .follow;
        return null;
    }

    pub fn toCollection(self: AtKind) []const u8 {
        return switch (self) {
            .post => "app.bsky.feed.post",
            .like => "app.bsky.feed.like",
            .repost => "app.bsky.feed.repost",
            .follow => "app.bsky.graph.follow",
        };
    }
};

/// View of an AT Protocol record sufficient to translate.
///
/// All slices are views into caller-owned bytes; the lifetime contract
/// matches the underlying JSON buffer the caller hands in.
pub const AtRecord = struct {
    kind: AtKind,
    /// AT-URI: `at://did/<collection>/<rkey>`. Used as the dedup key.
    at_uri: []const u8,
    /// Author DID. Always set.
    did: []const u8,
    /// `app.bsky.feed.post.text` (plain UTF-8). Empty for non-post kinds.
    text: []const u8,
    /// `app.bsky.feed.post.createdAt` (ISO 8601). For non-post kinds the
    /// caller fills in with the wall clock when the activity was seen.
    created_at: []const u8,
    /// For like/repost: the AT-URI being liked / reposted.
    /// For follow: the DID being followed.
    /// For post: the parent AT-URI when this is a reply; empty otherwise.
    subject: []const u8,
};

/// View of an AP activity sufficient to translate. Wraps the parser
/// `Activity` view with the fields the translator actually consumes.
pub const ApIn = struct {
    activity: Activity,
    /// HTML content (when `activity_type == .create` and the embedded
    /// object was a Note). Empty otherwise.
    content_html: []const u8,
};

/// Output of `atRecordToApActivity`. All slices are arena-allocated.
pub const ApOut = struct {
    activity_type: ActivityType,
    /// Wrapped `id` of the AP activity (per ActivityStreams).
    id: []const u8,
    /// Wrapped `actor` IRI.
    actor: []const u8,
    /// For Create(Note): the inner Note's `id`. For Like / Announce /
    /// Follow: the target object IRI. Empty when not applicable.
    object_id: []const u8,
    /// Inline Note: `content` (HTML). Empty for non-Create kinds.
    content_html: []const u8,
    /// `published` ISO 8601.
    published: []const u8,
    /// `to` (first recipient). Defaults to ActivityStreams Public.
    to: []const u8,
};

/// Output of `apActivityToAtRecord`.
pub const AtOut = struct {
    kind: AtKind,
    /// Synthetic AT-URI we'll write into the local repo.
    at_uri: []const u8,
    did: []const u8,
    text: []const u8,
    created_at: []const u8,
    subject: []const u8,
};

const as_public = "https://www.w3.org/ns/activitystreams#Public";

// ── AT → AP ───────────────────────────────────────────────────────────

/// Translate an AT Protocol record to an AP activity. Pure: no I/O, no
/// allocations outside `arena`. Bounded.
pub fn atRecordToApActivity(
    record: AtRecord,
    /// IRI the AP world should see as the author (caller supplies the
    /// host-specific mapping from `record.did`).
    author_ap_actor: []const u8,
    /// IRI the AP world should see as the activity's `id` (caller
    /// allocates a stable, dedup-friendly URI — typically derived from
    /// `record.at_uri` and the local AP host).
    activity_ap_id: []const u8,
    /// IRI for the wrapped Note (Create only). May equal `activity_ap_id`
    /// for other kinds.
    object_ap_id: []const u8,
    arena: *Arena,
) RelayError!ApOut {
    const alloc = arena.allocator();
    var out: ApOut = .{
        .activity_type = .create,
        .id = "",
        .actor = "",
        .object_id = "",
        .content_html = "",
        .published = "",
        .to = as_public,
    };

    switch (record.kind) {
        .post => {
            out.activity_type = .create;
            out.content_html = facetTextToHtml(record.text, arena) catch return error.TranslationBufferTooSmall;
        },
        .like => out.activity_type = .like,
        .repost => out.activity_type = .announce,
        .follow => out.activity_type = .follow,
    }

    out.id = dupeBounded(alloc, activity_ap_id) catch return error.TranslationBufferTooSmall;
    out.actor = dupeBounded(alloc, author_ap_actor) catch return error.TranslationBufferTooSmall;
    out.object_id = dupeBounded(alloc, object_ap_id) catch return error.TranslationBufferTooSmall;
    out.published = dupeBounded(alloc, record.created_at) catch return error.TranslationBufferTooSmall;
    return out;
}

// ── AP → AT ───────────────────────────────────────────────────────────

/// Translate an AP activity to an AT record. Pure / bounded.
///
/// The caller is responsible for producing a stable `at_uri` (typically
/// `at://did/<collection>/<rkey>` where `rkey` is derived from a hash
/// of the AP activity id, so a re-delivered activity dedups).
pub fn apActivityToAtRecord(
    in: ApIn,
    /// DID for the AT side. Caller resolves from `activity.actor` via
    /// `identity_map.zig`.
    author_did: []const u8,
    /// Synthetic AT-URI for the record we'll write.
    at_uri: []const u8,
    /// For Create(Note): the subject AT-URI when the AP Note was a
    /// reply (empty otherwise). For Like / Announce / Follow: the target
    /// (object IRI for likes/announces, target actor URI/DID for
    /// follows).
    subject: []const u8,
    /// ISO 8601 created-at. Caller passes activity.published or the
    /// current wall-clock when the activity lacked it.
    created_at: []const u8,
    arena: *Arena,
) RelayError!AtOut {
    const alloc = arena.allocator();
    var out: AtOut = .{
        .kind = .post,
        .at_uri = "",
        .did = "",
        .text = "",
        .created_at = "",
        .subject = "",
    };

    out.kind = switch (in.activity.activity_type) {
        .create => .post,
        .like => .like,
        .announce => .repost,
        .follow => .follow,
        // Update / Delete / Accept / Reject have no direct AT mirror;
        // we surface them as posts with an empty text + the activity id
        // recorded as subject. The relay's higher-level pipeline can
        // choose to drop them.
        .update, .delete, .accept, .reject => return error.UnsupportedKind,
    };

    if (out.kind == .post) {
        out.text = htmlToPlainText(in.content_html, arena) catch return error.TranslationBufferTooSmall;
    }

    out.at_uri = dupeBounded(alloc, at_uri) catch return error.TranslationBufferTooSmall;
    out.did = dupeBounded(alloc, author_did) catch return error.TranslationBufferTooSmall;
    out.subject = dupeBounded(alloc, subject) catch return error.TranslationBufferTooSmall;
    out.created_at = dupeBounded(alloc, created_at) catch return error.TranslationBufferTooSmall;
    return out;
}

// ── AT post body parsing ──────────────────────────────────────────────

/// Extract the minimum fields the AT-side translator needs from a
/// Bluesky-style post record's JSON. The JSON view of an
/// `app.bsky.feed.post` is well-known:
///
///   { "text": "...", "createdAt": "...", "reply": { "parent": { "uri": "..." } } }
///
/// We do a single bounded scan looking only for the keys we care about.
/// Anything else is ignored.
pub fn parseAtPostBody(json_bytes: []const u8) RelayError!ParsedAtPost {
    var p: ParsedAtPost = .{ .text = "", .created_at = "", .reply_parent = "", .subject = "" };
    var guard: u32 = 0;
    var i: usize = 0;
    // Bounded scanner: we never walk past `max_translated_bytes`
    // characters of input.
    while (i < json_bytes.len) {
        guard += 1;
        if (guard > max_translated_bytes) return error.BadAtRecord;
        if (json_bytes[i] != '"') {
            i += 1;
            continue;
        }
        // Read a string. If it matches a key we care about, copy the
        // following string value.
        const key = scanString(json_bytes, &i) catch {
            i += 1;
            continue;
        };
        // Skip whitespace and `:`.
        while (i < json_bytes.len and (json_bytes[i] == ' ' or json_bytes[i] == '\t')) i += 1;
        if (i >= json_bytes.len or json_bytes[i] != ':') continue;
        i += 1;
        while (i < json_bytes.len and (json_bytes[i] == ' ' or json_bytes[i] == '\t')) i += 1;

        if (std.mem.eql(u8, key, "text")) {
            if (i < json_bytes.len and json_bytes[i] == '"') {
                p.text = scanString(json_bytes, &i) catch "";
            }
        } else if (std.mem.eql(u8, key, "createdAt")) {
            if (i < json_bytes.len and json_bytes[i] == '"') {
                p.created_at = scanString(json_bytes, &i) catch "";
            }
        } else if (std.mem.eql(u8, key, "subject")) {
            // like / repost / follow body: `{ "subject": { "uri": "..." } }`
            // OR `{ "subject": "did:..." }` for follows.
            if (i < json_bytes.len and json_bytes[i] == '"') {
                p.subject = scanString(json_bytes, &i) catch "";
            } else if (i < json_bytes.len and json_bytes[i] == '{') {
                p.subject = findInlineString(json_bytes, &i, "uri") catch "";
            }
        } else if (std.mem.eql(u8, key, "uri")) {
            // Inside a "parent" object — captures the parent AT-URI of a reply.
            if (i < json_bytes.len and json_bytes[i] == '"') {
                if (p.reply_parent.len == 0) {
                    p.reply_parent = scanString(json_bytes, &i) catch "";
                }
            }
        }
    }
    return p;
}

pub const ParsedAtPost = struct {
    text: []const u8,
    created_at: []const u8,
    reply_parent: []const u8,
    /// Subject URI for like/repost or DID for follow.
    subject: []const u8,
};

// ── Facet → HTML / HTML → text ────────────────────────────────────────

/// Lightweight facet-aware text → HTML conversion.
///
/// The legacy translator did full facet parsing with anchor tag
/// generation; on the Tiger Style hot path the relay only needs *some*
/// HTML envelope so receiving fediverse software treats the post as
/// formatted. We wrap in `<p>` and convert newlines to `<br>`. Mentions
/// and links arrive textually inside `record.text`, so receiving
/// software still sees the link target — we just don't anchor-tag them.
///
/// Why: actually expanding facets requires an extra JSON pass and a
/// second arena allocation per facet. The relay's translation log
/// records the source AT-URI so a richer downstream renderer can re-
/// hydrate from the source when needed.
fn facetTextToHtml(text: []const u8, arena: *Arena) ![]const u8 {
    const alloc = arena.allocator();
    // Worst-case expansion is &amp; (5 bytes for 1) for every char +
    // <p></p> wrapping. Budget: 6×len + 8.
    if (text.len * 6 + 8 > max_translated_bytes) return error.OutOfMemory;
    var buf = try alloc.alloc(u8, text.len * 6 + 8);
    var w: usize = 0;
    // Tiger Style: bounded write loop.
    @memcpy(buf[w..][0..3], "<p>");
    w += 3;
    var i: usize = 0;
    while (i < text.len) : (i += 1) {
        const c = text[i];
        const piece: []const u8 = switch (c) {
            '&' => "&amp;",
            '<' => "&lt;",
            '>' => "&gt;",
            '"' => "&quot;",
            '\n' => "<br>",
            else => &[_]u8{c},
        };
        @memcpy(buf[w..][0..piece.len], piece);
        w += piece.len;
    }
    @memcpy(buf[w..][0..4], "</p>");
    w += 4;
    assertLe(w, buf.len);
    return buf[0..w];
}

/// HTML → plain text (entity-decoded, tags stripped, `<br>` → `\n`).
/// Bounded, iterative.
fn htmlToPlainText(html: []const u8, arena: *Arena) ![]const u8 {
    if (html.len > max_translated_bytes) return error.OutOfMemory;
    const alloc = arena.allocator();
    var buf = try alloc.alloc(u8, html.len);
    var w: usize = 0;
    var i: usize = 0;
    var guard: usize = 0;
    while (i < html.len) {
        guard += 1;
        if (guard > html.len * 2) break; // belt-and-braces termination
        const c = html[i];
        if (c == '<') {
            const end = std.mem.indexOfScalarPos(u8, html, i, '>') orelse break;
            const tag = html[i + 1 .. end];
            if (tag.len >= 2 and std.ascii.eqlIgnoreCase(tag[0..2], "br")) {
                buf[w] = '\n';
                w += 1;
            }
            i = end + 1;
            continue;
        }
        if (c == '&') {
            const end = std.mem.indexOfScalarPos(u8, html, i, ';') orelse {
                buf[w] = c;
                w += 1;
                i += 1;
                continue;
            };
            const entity = html[i .. end + 1];
            const replacement: ?u8 = if (std.mem.eql(u8, entity, "&amp;"))
                @as(u8, '&')
            else if (std.mem.eql(u8, entity, "&lt;"))
                @as(u8, '<')
            else if (std.mem.eql(u8, entity, "&gt;"))
                @as(u8, '>')
            else if (std.mem.eql(u8, entity, "&quot;"))
                @as(u8, '"')
            else if (std.mem.eql(u8, entity, "&#39;") or std.mem.eql(u8, entity, "&apos;"))
                @as(u8, '\'')
            else
                null;
            if (replacement) |r| {
                buf[w] = r;
                w += 1;
            } else {
                // Unknown entity — drop.
            }
            i = end + 1;
            continue;
        }
        buf[w] = c;
        w += 1;
        i += 1;
    }
    return buf[0..w];
}

// ── Internal helpers ──────────────────────────────────────────────────

fn dupeBounded(alloc: std.mem.Allocator, s: []const u8) ![]const u8 {
    if (s.len > max_translated_bytes) return error.OutOfMemory;
    const buf = try alloc.alloc(u8, s.len);
    @memcpy(buf, s);
    return buf;
}

const ScanError = error{Bad};

/// Scan a JSON string at `i`. On entry `bytes[i] == '"'`. On return `i`
/// points just past the closing quote. Returns the slice of bytes
/// between the quotes (escapes are not decoded — the caller treats the
/// view as opaque).
fn scanString(bytes: []const u8, i: *usize) ScanError![]const u8 {
    if (i.* >= bytes.len or bytes[i.*] != '"') return error.Bad;
    i.* += 1;
    const start = i.*;
    var guard: u32 = 0;
    while (i.* < bytes.len) {
        guard += 1;
        if (guard > max_translated_bytes) return error.Bad;
        const c = bytes[i.*];
        if (c == '\\') {
            i.* += 2;
            continue;
        }
        if (c == '"') {
            const end = i.*;
            i.* += 1;
            return bytes[start..end];
        }
        i.* += 1;
    }
    return error.Bad;
}

/// Scan an inline JSON object at `i` (`bytes[i] == '{'`) looking for
/// the string value of `key`. Iterative, bounded. Skips nested values
/// without recursion via a depth counter.
fn findInlineString(bytes: []const u8, i: *usize, key: []const u8) ScanError![]const u8 {
    if (i.* >= bytes.len or bytes[i.*] != '{') return error.Bad;
    i.* += 1;
    var depth: u32 = 1;
    var guard: u32 = 0;
    while (i.* < bytes.len) {
        guard += 1;
        if (guard > max_translated_bytes) return error.Bad;
        const c = bytes[i.*];
        if (c == '{') {
            depth += 1;
            i.* += 1;
            continue;
        }
        if (c == '}') {
            depth -= 1;
            i.* += 1;
            if (depth == 0) return error.Bad;
            continue;
        }
        if (c == '"') {
            const k = try scanString(bytes, i);
            // Skip `: <ws>`.
            while (i.* < bytes.len and (bytes[i.*] == ' ' or bytes[i.*] == '\t')) i.* += 1;
            if (i.* < bytes.len and bytes[i.*] == ':') {
                i.* += 1;
                while (i.* < bytes.len and (bytes[i.*] == ' ' or bytes[i.*] == '\t')) i.* += 1;
                if (depth == 1 and std.mem.eql(u8, k, key) and
                    i.* < bytes.len and bytes[i.*] == '"')
                {
                    return scanString(bytes, i);
                }
            }
            continue;
        }
        i.* += 1;
    }
    return error.Bad;
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;

fn makeArena(buf: []u8) Arena {
    return Arena.init(buf);
}

test "AtKind round-trips through collection name" {
    inline for (.{ .post, .like, .repost, .follow }) |k| {
        const collection = (@as(AtKind, k)).toCollection();
        try testing.expectEqual(@as(AtKind, k), AtKind.fromCollection(collection).?);
    }
    try testing.expectEqual(@as(?AtKind, null), AtKind.fromCollection("app.bsky.feed.threadgate"));
}

test "atRecordToApActivity translates a post into Create(Note)" {
    var buf: [4096]u8 = undefined;
    var arena = makeArena(&buf);
    const record: AtRecord = .{
        .kind = .post,
        .at_uri = "at://did:plc:alice/app.bsky.feed.post/abc",
        .did = "did:plc:alice",
        .text = "Hello & welcome!\nLine 2",
        .created_at = "2026-05-14T12:00:00Z",
        .subject = "",
    };
    const out = try atRecordToApActivity(
        record,
        "https://example/ap/users/alice",
        "https://example/ap/activities/abc",
        "https://example/ap/notes/abc",
        &arena,
    );
    try testing.expectEqual(ActivityType.create, out.activity_type);
    try testing.expectEqualStrings("https://example/ap/users/alice", out.actor);
    try testing.expectEqualStrings("https://example/ap/activities/abc", out.id);
    try testing.expectEqualStrings("https://example/ap/notes/abc", out.object_id);
    try testing.expectEqualStrings("<p>Hello &amp; welcome!<br>Line 2</p>", out.content_html);
}

test "atRecordToApActivity translates like → Like" {
    var buf: [2048]u8 = undefined;
    var arena = makeArena(&buf);
    const record: AtRecord = .{
        .kind = .like,
        .at_uri = "at://did:plc:alice/app.bsky.feed.like/r1",
        .did = "did:plc:alice",
        .text = "",
        .created_at = "2026-05-14T12:00:00Z",
        .subject = "at://did:plc:bob/app.bsky.feed.post/p1",
    };
    const out = try atRecordToApActivity(
        record,
        "https://example/ap/users/alice",
        "https://example/ap/activities/r1",
        "https://other/ap/notes/p1",
        &arena,
    );
    try testing.expectEqual(ActivityType.like, out.activity_type);
    try testing.expectEqualStrings("https://other/ap/notes/p1", out.object_id);
    try testing.expectEqualStrings("", out.content_html);
}

test "atRecordToApActivity translates repost → Announce and follow → Follow" {
    var buf: [2048]u8 = undefined;
    var arena = makeArena(&buf);
    inline for (.{
        .{ AtKind.repost, ActivityType.announce },
        .{ AtKind.follow, ActivityType.follow },
    }) |pair| {
        arena.reset();
        const record: AtRecord = .{
            .kind = pair[0],
            .at_uri = "at://did:plc:x/coll/k",
            .did = "did:plc:x",
            .text = "",
            .created_at = "2026-05-14T00:00:00Z",
            .subject = "at://did:plc:y/coll/k",
        };
        const out = try atRecordToApActivity(
            record,
            "https://h/users/x",
            "https://h/act/k",
            "https://h/obj/k",
            &arena,
        );
        try testing.expectEqual(pair[1], out.activity_type);
    }
}

test "apActivityToAtRecord translates Create(Note) → post" {
    var buf: [4096]u8 = undefined;
    var arena = makeArena(&buf);
    const activity: Activity = .{
        .activity_type = .create,
        .id = "https://m/act/1",
        .actor = "https://m/users/bob",
        .object_id = "https://m/notes/1",
        .object_type = "Note",
        .target = "",
        .published = "2026-05-14T00:00:00Z",
        .to_first = as_public,
    };
    const out = try apActivityToAtRecord(
        .{ .activity = activity, .content_html = "<p>Hello <b>world</b></p>" },
        "did:web:m:bob",
        "at://did:web:m:bob/app.bsky.feed.post/synth1",
        "",
        "2026-05-14T00:00:00Z",
        &arena,
    );
    try testing.expectEqual(AtKind.post, out.kind);
    try testing.expectEqualStrings("did:web:m:bob", out.did);
    try testing.expectEqualStrings("Hello world", out.text);
}

test "apActivityToAtRecord rejects Update/Delete/Accept/Reject" {
    var buf: [1024]u8 = undefined;
    var arena = makeArena(&buf);
    inline for (.{ ActivityType.update, ActivityType.delete, ActivityType.accept, ActivityType.reject }) |t| {
        arena.reset();
        const activity: Activity = .{
            .activity_type = t,
            .id = "",
            .actor = "https://m/users/bob",
            .object_id = "",
            .object_type = "",
            .target = "",
            .published = "",
            .to_first = "",
        };
        const got = apActivityToAtRecord(
            .{ .activity = activity, .content_html = "" },
            "did:web:m:bob",
            "at://x/coll/r",
            "",
            "2026",
            &arena,
        );
        try testing.expectError(error.UnsupportedKind, got);
    }
}

test "post round-trip: AT post → AP Create → AT post preserves text + created_at" {
    var buf: [8192]u8 = undefined;
    var arena = makeArena(&buf);

    const original_text = "Hi 2026!\nSecond line";
    const original_created = "2026-05-14T12:00:00Z";

    const at: AtRecord = .{
        .kind = .post,
        .at_uri = "at://did:plc:alice/app.bsky.feed.post/r",
        .did = "did:plc:alice",
        .text = original_text,
        .created_at = original_created,
        .subject = "",
    };
    const ap = try atRecordToApActivity(
        at,
        "https://h/users/alice",
        "https://h/act/r",
        "https://h/notes/r",
        &arena,
    );
    // Reverse direction. Synthesize an Activity view from the ApOut.
    const activity: Activity = .{
        .activity_type = ap.activity_type,
        .id = ap.id,
        .actor = ap.actor,
        .object_id = ap.object_id,
        .object_type = "Note",
        .target = "",
        .published = ap.published,
        .to_first = ap.to,
    };
    const at2 = try apActivityToAtRecord(
        .{ .activity = activity, .content_html = ap.content_html },
        "did:plc:alice",
        "at://did:plc:alice/app.bsky.feed.post/r",
        "",
        ap.published,
        &arena,
    );
    try testing.expectEqualStrings(original_text, at2.text);
    try testing.expectEqualStrings(original_created, at2.created_at);
}

test "like / repost / follow round-trip preserves kind" {
    var buf: [4096]u8 = undefined;
    var arena = makeArena(&buf);
    inline for (.{ AtKind.like, AtKind.repost, AtKind.follow }) |k| {
        arena.reset();
        const at: AtRecord = .{
            .kind = k,
            .at_uri = "at://did:plc:a/coll/r",
            .did = "did:plc:a",
            .text = "",
            .created_at = "2026-05-14T00:00:00Z",
            .subject = "at://did:plc:b/x/y",
        };
        const ap = try atRecordToApActivity(at, "https://h/u/a", "https://h/act/r", "https://h/o/r", &arena);
        const activity: Activity = .{
            .activity_type = ap.activity_type,
            .id = ap.id,
            .actor = ap.actor,
            .object_id = ap.object_id,
            .object_type = "",
            .target = "",
            .published = ap.published,
            .to_first = ap.to,
        };
        const at2 = try apActivityToAtRecord(
            .{ .activity = activity, .content_html = "" },
            "did:plc:a",
            at.at_uri,
            at.subject,
            ap.published,
            &arena,
        );
        try testing.expectEqual(k, at2.kind);
        try testing.expectEqualStrings(at.subject, at2.subject);
    }
}

test "parseAtPostBody extracts text + createdAt + reply.parent.uri" {
    const json =
        \\{"$type":"app.bsky.feed.post","text":"Hello!","createdAt":"2026-05-14T00:00:00Z","reply":{"parent":{"uri":"at://did:plc:bob/app.bsky.feed.post/abc","cid":"bafy..."},"root":{"uri":"at://did:plc:bob/app.bsky.feed.post/abc"}}}
    ;
    const p = try parseAtPostBody(json);
    try testing.expectEqualStrings("Hello!", p.text);
    try testing.expectEqualStrings("2026-05-14T00:00:00Z", p.created_at);
    try testing.expectEqualStrings("at://did:plc:bob/app.bsky.feed.post/abc", p.reply_parent);
}

test "parseAtPostBody extracts subject for likes/follows" {
    const like_json =
        \\{"$type":"app.bsky.feed.like","createdAt":"2026-05-14T00:00:00Z","subject":{"uri":"at://did:plc:bob/app.bsky.feed.post/x","cid":"bafy"}}
    ;
    const p = try parseAtPostBody(like_json);
    try testing.expectEqualStrings("at://did:plc:bob/app.bsky.feed.post/x", p.subject);

    const follow_json =
        \\{"$type":"app.bsky.graph.follow","createdAt":"2026-05-14T00:00:00Z","subject":"did:plc:bob"}
    ;
    const fp = try parseAtPostBody(follow_json);
    try testing.expectEqualStrings("did:plc:bob", fp.subject);
}

test "TranslationBufferTooSmall when output exceeds arena" {
    var tiny: [128]u8 = undefined;
    var arena = makeArena(&tiny);
    const text = "x" ** 200;
    const at: AtRecord = .{
        .kind = .post,
        .at_uri = "at://x/y/z",
        .did = "did:plc:x",
        .text = text,
        .created_at = "2026",
        .subject = "",
    };
    const got = atRecordToApActivity(at, "https://h/u", "https://h/a", "https://h/o", &arena);
    try testing.expectError(error.TranslationBufferTooSmall, got);
}

test "htmlToPlainText handles entities and br tags" {
    var buf: [1024]u8 = undefined;
    var arena = makeArena(&buf);
    const out = try htmlToPlainText("<p>Hi &amp; bye<br>line 2</p>", &arena);
    try testing.expectEqualStrings("Hi & bye\nline 2", out);
}
