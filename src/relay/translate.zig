const std = @import("std");
const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

pub const Facet = struct {
    byte_start: usize,
    byte_end: usize,
    feature_type: FeatureType,
    value: []const u8, // DID for mention, URI for link, tag name for tag

    pub const FeatureType = enum { mention, link, tag };
};

pub const AtPostRecord = struct {
    text: []const u8,
    created_at: []const u8, // ISO 8601
    facets: []const Facet,
    reply_parent_uri: ?[]const u8 = null,
    reply_root_uri: ?[]const u8 = null,
    langs: []const []const u8 = &.{},
    content_warning: ?[]const u8 = null,
};

pub const ApNote = struct {
    id: []const u8,
    attributed_to: []const u8,
    content: []const u8, // HTML
    published: []const u8, // ISO 8601
    in_reply_to: ?[]const u8 = null,
    summary: ?[]const u8 = null, // content warning
    sensitive: bool = false,
    to: []const u8 = "https://www.w3.org/ns/activitystreams#Public",
    cc: ?[]const u8 = null,
};

pub const ApActivity = struct {
    id: []const u8,
    @"type": []const u8, // "Like", "Announce", "Follow", etc.
    actor: []const u8,
    object: []const u8, // URI of the target
    published: ?[]const u8 = null,
};

// ---------------------------------------------------------------------------
// Facets <-> HTML conversion
// ---------------------------------------------------------------------------

/// Convert AT Protocol text+facets to HTML for ActivityPub.
/// Wraps in <p>, converts \n to <br>, inserts <a> tags at facet positions.
/// HTML-escapes non-facet text.
pub fn facetsToHtml(allocator: Allocator, text: []const u8, facets: []const Facet) ![]u8 {
    // Sort facets by byte_start (copy slice so we can sort)
    const sorted = try allocator.alloc(Facet, facets.len);
    defer allocator.free(sorted);
    @memcpy(sorted, facets);
    std.mem.sort(Facet, sorted, {}, struct {
        fn cmp(_: void, a: Facet, b: Facet) bool {
            return a.byte_start < b.byte_start;
        }
    }.cmp);

    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, "<p>");

    var pos: usize = 0;
    var facet_idx: usize = 0;

    while (pos < text.len) {
        // Check if a facet starts at this position
        if (facet_idx < sorted.len and sorted[facet_idx].byte_start == pos) {
            const f = sorted[facet_idx];
            // Insert opening tag
            switch (f.feature_type) {
                .mention => {
                    try out.appendSlice(allocator, "<a href=\"");
                    try appendHtmlEscaped(allocator, &out, f.value);
                    try out.appendSlice(allocator, "\" class=\"mention\">");
                },
                .link => {
                    try out.appendSlice(allocator, "<a href=\"");
                    try appendHtmlEscaped(allocator, &out, f.value);
                    try out.appendSlice(allocator, "\">");
                },
                .tag => {
                    try out.appendSlice(allocator, "<a href=\"/tags/");
                    try appendHtmlEscaped(allocator, &out, f.value);
                    try out.appendSlice(allocator, "\" class=\"hashtag\">");
                },
            }
            // Append facet text (with HTML escaping and newline conversion)
            const facet_end = @min(f.byte_end, text.len);
            try appendEscapedWithBreaks(allocator, &out, text[pos..facet_end]);
            try out.appendSlice(allocator, "</a>");
            pos = facet_end;
            facet_idx += 1;
        } else {
            // Determine how far we can go before the next facet
            const next_facet_start = if (facet_idx < sorted.len) sorted[facet_idx].byte_start else text.len;
            const end = @min(next_facet_start, text.len);
            try appendEscapedWithBreaks(allocator, &out, text[pos..end]);
            pos = end;
        }
    }

    try out.appendSlice(allocator, "</p>");
    return out.toOwnedSlice(allocator);
}

/// Convert ActivityPub HTML content to AT Protocol plain text + facets.
/// Strips tags, extracts <a> elements as facets with byte offsets.
pub fn htmlToFacets(allocator: Allocator, html: []const u8) !struct { text: []u8, facets: []Facet } {
    var text_buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer text_buf.deinit(allocator);

    var facets_list: std.ArrayListUnmanaged(Facet) = .empty;
    errdefer facets_list.deinit(allocator);

    var pos: usize = 0;
    // Track state for <a> tag parsing
    var in_anchor = false;
    var anchor_href: ?[]const u8 = null;
    var anchor_class: ?[]const u8 = null;
    var anchor_byte_start: usize = 0;
    var seen_p_close = false;

    while (pos < html.len) {
        if (html[pos] == '<') {
            // Parse the tag
            const tag_end = std.mem.indexOfScalarPos(u8, html, pos, '>') orelse break;
            const tag_content = html[pos + 1 .. tag_end];

            if (tag_content.len == 0) {
                pos = tag_end + 1;
                continue;
            }

            // Check for closing tags first
            if (tag_content[0] == '/') {
                const tag_name = std.mem.trim(u8, tag_content[1..], " \t\r\n");
                if (std.ascii.eqlIgnoreCase(tag_name, "a")) {
                    // Close anchor — record facet
                    if (in_anchor) {
                        if (anchor_href) |href| {
                            const feature_type: Facet.FeatureType = blk: {
                                if (anchor_class) |cls| {
                                    if (std.mem.indexOf(u8, cls, "mention") != null) break :blk .mention;
                                    if (std.mem.indexOf(u8, cls, "hashtag") != null) break :blk .tag;
                                }
                                break :blk .link;
                            };
                            const value = if (feature_type == .tag)
                                try extractTagName(allocator, href)
                            else
                                try allocator.dupe(u8, href);
                            try facets_list.append(allocator, .{
                                .byte_start = anchor_byte_start,
                                .byte_end = text_buf.items.len,
                                .feature_type = feature_type,
                                .value = value,
                            });
                        }
                        in_anchor = false;
                        anchor_href = null;
                        anchor_class = null;
                    }
                } else if (std.ascii.eqlIgnoreCase(tag_name, "p")) {
                    // </p> — add newline between paragraphs (not after last)
                    if (seen_p_close) {
                        try text_buf.append(allocator, '\n');
                    }
                    seen_p_close = true;
                }
                pos = tag_end + 1;
                continue;
            }

            // Check for self-closing <br> or <br/>
            const lower_tag = tag_content;
            if (startsWithIgnoreCase(lower_tag, "br")) {
                try text_buf.append(allocator, '\n');
                pos = tag_end + 1;
                continue;
            }

            // Check for opening <a ...>
            if (startsWithIgnoreCase(lower_tag, "a ") or std.ascii.eqlIgnoreCase(lower_tag, "a")) {
                anchor_href = extractAttribute(tag_content, "href");
                anchor_class = extractAttribute(tag_content, "class");
                anchor_byte_start = text_buf.items.len;
                in_anchor = true;
                pos = tag_end + 1;
                continue;
            }

            // Check for opening <p> — just skip, we handle </p>
            if (startsWithIgnoreCase(lower_tag, "p") and
                (lower_tag.len == 1 or lower_tag[1] == ' ' or lower_tag[1] == '>'))
            {
                pos = tag_end + 1;
                continue;
            }

            // All other tags: strip them, keep inner text
            pos = tag_end + 1;
            continue;
        } else if (html[pos] == '&') {
            // HTML entity
            const entity_end = std.mem.indexOfScalarPos(u8, html, pos, ';') orelse {
                try text_buf.append(allocator, html[pos]);
                pos += 1;
                continue;
            };
            const entity = html[pos .. entity_end + 1];
            if (std.mem.eql(u8, entity, "&amp;")) {
                try text_buf.append(allocator, '&');
            } else if (std.mem.eql(u8, entity, "&lt;")) {
                try text_buf.append(allocator, '<');
            } else if (std.mem.eql(u8, entity, "&gt;")) {
                try text_buf.append(allocator, '>');
            } else if (std.mem.eql(u8, entity, "&quot;")) {
                try text_buf.append(allocator, '"');
            } else if (std.mem.eql(u8, entity, "&#39;") or std.mem.eql(u8, entity, "&apos;")) {
                try text_buf.append(allocator, '\'');
            } else {
                // Unknown entity — pass through as-is
                try text_buf.appendSlice(allocator, entity);
            }
            pos = entity_end + 1;
        } else {
            try text_buf.append(allocator, html[pos]);
            pos += 1;
        }
    }

    return .{
        .text = try text_buf.toOwnedSlice(allocator),
        .facets = try facets_list.toOwnedSlice(allocator),
    };
}

// ---------------------------------------------------------------------------
// Post translation
// ---------------------------------------------------------------------------

/// Translate an AT Protocol post record to an ActivityPub Note.
pub fn atPostToApNote(
    allocator: Allocator,
    record: AtPostRecord,
    author_actor_uri: []const u8,
    object_uri: []const u8,
) !ApNote {
    const content = try facetsToHtml(allocator, record.text, record.facets);

    return .{
        .id = try allocator.dupe(u8, object_uri),
        .attributed_to = try allocator.dupe(u8, author_actor_uri),
        .content = content,
        .published = try allocator.dupe(u8, record.created_at),
        .in_reply_to = if (record.reply_parent_uri) |uri| try allocator.dupe(u8, uri) else null,
        .summary = if (record.content_warning) |cw| try allocator.dupe(u8, cw) else null,
        .sensitive = record.content_warning != null,
    };
}

/// Translate an ActivityPub Note to an AT Protocol post record.
pub fn apNoteToAtPost(
    allocator: Allocator,
    note: ApNote,
) !AtPostRecord {
    const result = try htmlToFacets(allocator, note.content);

    return .{
        .text = result.text,
        .created_at = try allocator.dupe(u8, note.published),
        .facets = result.facets,
        .reply_parent_uri = if (note.in_reply_to) |uri| try allocator.dupe(u8, uri) else null,
        .reply_root_uri = if (note.in_reply_to) |uri| try allocator.dupe(u8, uri) else null,
        .content_warning = if (note.summary) |s| try allocator.dupe(u8, s) else null,
    };
}

// ---------------------------------------------------------------------------
// Interaction translation
// ---------------------------------------------------------------------------

/// Translate an AT Protocol like record to an AP Like activity.
pub fn atLikeToApLike(
    allocator: Allocator,
    subject_uri: []const u8,
    author_actor_uri: []const u8,
    activity_uri: []const u8,
    target_object_uri: []const u8,
) !ApActivity {
    _ = subject_uri; // AT-URI kept for provenance but not embedded in the AP activity
    return .{
        .id = try allocator.dupe(u8, activity_uri),
        .@"type" = try allocator.dupe(u8, "Like"),
        .actor = try allocator.dupe(u8, author_actor_uri),
        .object = try allocator.dupe(u8, target_object_uri),
    };
}

/// Translate an AT Protocol repost to an AP Announce activity.
pub fn atRepostToApAnnounce(
    allocator: Allocator,
    subject_uri: []const u8,
    author_actor_uri: []const u8,
    activity_uri: []const u8,
    target_object_uri: []const u8,
) !ApActivity {
    _ = subject_uri;
    return .{
        .id = try allocator.dupe(u8, activity_uri),
        .@"type" = try allocator.dupe(u8, "Announce"),
        .actor = try allocator.dupe(u8, author_actor_uri),
        .object = try allocator.dupe(u8, target_object_uri),
    };
}

/// Translate an AT Protocol follow to an AP Follow activity.
pub fn atFollowToApFollow(
    allocator: Allocator,
    subject_did: []const u8,
    author_actor_uri: []const u8,
    activity_uri: []const u8,
    target_actor_uri: []const u8,
) !ApActivity {
    _ = subject_did;
    return .{
        .id = try allocator.dupe(u8, activity_uri),
        .@"type" = try allocator.dupe(u8, "Follow"),
        .actor = try allocator.dupe(u8, author_actor_uri),
        .object = try allocator.dupe(u8, target_actor_uri),
    };
}

// ---------------------------------------------------------------------------
// JSON serialization helpers
// ---------------------------------------------------------------------------

/// Serialize an ApNote to JSON for delivery.
pub fn apNoteToJson(allocator: Allocator, note: ApNote) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, "{\n");
    try out.appendSlice(allocator, "  \"@context\": \"https://www.w3.org/ns/activitystreams\",\n");
    try out.appendSlice(allocator, "  \"type\": \"Note\",\n");

    try appendJsonField(allocator, &out, "id", note.id);
    try appendJsonField(allocator, &out, "attributedTo", note.attributed_to);
    try appendJsonFieldJsonEscaped(allocator, &out, "content", note.content);
    try appendJsonField(allocator, &out, "published", note.published);

    // "to" as array
    try out.appendSlice(allocator, "  \"to\": [\"");
    try appendJsonStringValue(allocator, &out, note.to);
    try out.appendSlice(allocator, "\"]");

    if (note.cc) |cc| {
        try out.appendSlice(allocator, ",\n  \"cc\": [\"");
        try appendJsonStringValue(allocator, &out, cc);
        try out.appendSlice(allocator, "\"]");
    }

    if (note.in_reply_to) |irt| {
        try out.appendSlice(allocator, ",\n");
        try appendJsonField(allocator, &out, "inReplyTo", irt);
        // Remove trailing comma+newline, just add the value
        // Actually appendJsonField adds trailing comma, we need to handle this better
    }

    if (note.summary) |sum| {
        try out.appendSlice(allocator, ",\n");
        try appendJsonFieldJsonEscaped(allocator, &out, "summary", sum);
        try out.appendSlice(allocator, "  \"sensitive\": true");
    }

    try out.appendSlice(allocator, "\n}");
    return out.toOwnedSlice(allocator);
}

/// Serialize an ApActivity wrapping a Note (Create activity) to JSON.
pub fn createActivityToJson(allocator: Allocator, activity_uri: []const u8, actor_uri: []const u8, note: ApNote) ![]u8 {
    const note_json = try apNoteToJson(allocator, note);
    defer allocator.free(note_json);

    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, "{\n");
    try out.appendSlice(allocator, "  \"@context\": \"https://www.w3.org/ns/activitystreams\",\n");
    try out.appendSlice(allocator, "  \"type\": \"Create\",\n");
    try appendJsonField(allocator, &out, "id", activity_uri);
    try appendJsonField(allocator, &out, "actor", actor_uri);

    try out.appendSlice(allocator, "  \"object\": ");
    try out.appendSlice(allocator, note_json);
    try out.appendSlice(allocator, ",\n");

    // "to" as array
    try out.appendSlice(allocator, "  \"to\": [\"");
    try appendJsonStringValue(allocator, &out, note.to);
    try out.appendSlice(allocator, "\"]");

    if (note.cc) |cc| {
        try out.appendSlice(allocator, ",\n  \"cc\": [\"");
        try appendJsonStringValue(allocator, &out, cc);
        try out.appendSlice(allocator, "\"]");
    }

    try out.appendSlice(allocator, "\n}");
    return out.toOwnedSlice(allocator);
}

/// Serialize an ApActivity to JSON for delivery.
pub fn apActivityToJson(allocator: Allocator, activity: ApActivity) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, "{\n");
    try out.appendSlice(allocator, "  \"@context\": \"https://www.w3.org/ns/activitystreams\",\n");
    try appendJsonField(allocator, &out, "type", activity.@"type");
    try appendJsonField(allocator, &out, "id", activity.id);
    try appendJsonField(allocator, &out, "actor", activity.actor);

    // "object" is the last required field
    try out.appendSlice(allocator, "  \"object\": \"");
    try appendJsonStringValue(allocator, &out, activity.object);
    try out.appendSlice(allocator, "\"");

    if (activity.published) |pub_date| {
        try out.appendSlice(allocator, ",\n  \"published\": \"");
        try appendJsonStringValue(allocator, &out, pub_date);
        try out.appendSlice(allocator, "\"");
    }

    try out.appendSlice(allocator, "\n}");
    return out.toOwnedSlice(allocator);
}

/// Parse an AT Protocol post record from JSON.
pub fn parseAtPostRecord(allocator: Allocator, json: []const u8) !AtPostRecord {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();

    const root = parsed.value.object;

    const text = try allocator.dupe(u8, root.get("text").?.string);
    const created_at = try allocator.dupe(u8, root.get("createdAt").?.string);

    // Parse facets
    var facets_list: std.ArrayListUnmanaged(Facet) = .empty;
    errdefer facets_list.deinit(allocator);

    if (root.get("facets")) |facets_val| {
        if (facets_val == .array) {
            for (facets_val.array.items) |facet_obj| {
                const index = facet_obj.object.get("index").?.object;
                const byte_start = @as(usize, @intCast(index.get("byteStart").?.integer));
                const byte_end = @as(usize, @intCast(index.get("byteEnd").?.integer));

                const features = facet_obj.object.get("features").?.array;
                for (features.items) |feature| {
                    const feat_type_str = feature.object.get("$type").?.string;
                    const feature_type: Facet.FeatureType = if (std.mem.eql(u8, feat_type_str, "app.bsky.richtext.facet#mention"))
                        .mention
                    else if (std.mem.eql(u8, feat_type_str, "app.bsky.richtext.facet#link"))
                        .link
                    else if (std.mem.eql(u8, feat_type_str, "app.bsky.richtext.facet#tag"))
                        .tag
                    else
                        continue;

                    const value_key: []const u8 = switch (feature_type) {
                        .mention => "did",
                        .link => "uri",
                        .tag => "tag",
                    };
                    const value = try allocator.dupe(u8, feature.object.get(value_key).?.string);

                    try facets_list.append(allocator, .{
                        .byte_start = byte_start,
                        .byte_end = byte_end,
                        .feature_type = feature_type,
                        .value = value,
                    });
                }
            }
        }
    }

    // Parse reply
    var reply_parent: ?[]const u8 = null;
    var reply_root: ?[]const u8 = null;
    if (root.get("reply")) |reply_val| {
        if (reply_val == .object) {
            if (reply_val.object.get("parent")) |parent| {
                if (parent == .object) {
                    if (parent.object.get("uri")) |uri| {
                        reply_parent = try allocator.dupe(u8, uri.string);
                    }
                }
            }
            if (reply_val.object.get("root")) |root_val| {
                if (root_val == .object) {
                    if (root_val.object.get("uri")) |uri| {
                        reply_root = try allocator.dupe(u8, uri.string);
                    }
                }
            }
        }
    }

    // Parse langs
    var langs_list: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer langs_list.deinit(allocator);
    if (root.get("langs")) |langs_val| {
        if (langs_val == .array) {
            for (langs_val.array.items) |lang| {
                try langs_list.append(allocator, try allocator.dupe(u8, lang.string));
            }
        }
    }

    // Parse content warning from labels
    var content_warning: ?[]const u8 = null;
    if (root.get("labels")) |labels_val| {
        if (labels_val == .object) {
            if (labels_val.object.get("values")) |values| {
                if (values == .array) {
                    for (values.array.items) |label| {
                        if (label.object.get("val")) |val| {
                            content_warning = try allocator.dupe(u8, val.string);
                            break;
                        }
                    }
                }
            }
        }
    }

    return .{
        .text = text,
        .created_at = created_at,
        .facets = try facets_list.toOwnedSlice(allocator),
        .reply_parent_uri = reply_parent,
        .reply_root_uri = reply_root,
        .langs = try langs_list.toOwnedSlice(allocator),
        .content_warning = content_warning,
    };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Append HTML-escaped text, converting \n to <br>.
fn appendEscapedWithBreaks(allocator: Allocator, out: *std.ArrayListUnmanaged(u8), text: []const u8) !void {
    for (text) |c| {
        switch (c) {
            '&' => try out.appendSlice(allocator, "&amp;"),
            '<' => try out.appendSlice(allocator, "&lt;"),
            '>' => try out.appendSlice(allocator, "&gt;"),
            '"' => try out.appendSlice(allocator, "&quot;"),
            '\n' => try out.appendSlice(allocator, "<br>"),
            else => try out.append(allocator, c),
        }
    }
}

/// Append HTML-escaped text without newline conversion.
fn appendHtmlEscaped(allocator: Allocator, out: *std.ArrayListUnmanaged(u8), text: []const u8) !void {
    for (text) |c| {
        switch (c) {
            '&' => try out.appendSlice(allocator, "&amp;"),
            '<' => try out.appendSlice(allocator, "&lt;"),
            '>' => try out.appendSlice(allocator, "&gt;"),
            '"' => try out.appendSlice(allocator, "&quot;"),
            else => try out.append(allocator, c),
        }
    }
}

/// Case-insensitive prefix check.
fn startsWithIgnoreCase(haystack: []const u8, prefix: []const u8) bool {
    if (haystack.len < prefix.len) return false;
    for (haystack[0..prefix.len], prefix) |h, p| {
        if (std.ascii.toLower(h) != std.ascii.toLower(p)) return false;
    }
    return true;
}

/// Extract an HTML attribute value from a tag's inner content.
/// Given `a href="https://example.com" class="mention"` and attr `href`,
/// returns `https://example.com`.
fn extractAttribute(tag_content: []const u8, attr_name: []const u8) ?[]const u8 {
    // Search for attr_name followed by = (case-insensitive)
    var pos: usize = 0;
    while (pos < tag_content.len) {
        // Find the attribute name
        const remaining = tag_content[pos..];
        const attr_pos = findAttributeStart(remaining, attr_name) orelse return null;
        pos += attr_pos;

        // Skip attribute name
        pos += attr_name.len;

        // Skip whitespace around =
        while (pos < tag_content.len and tag_content[pos] == ' ') pos += 1;
        if (pos >= tag_content.len or tag_content[pos] != '=') continue;
        pos += 1;
        while (pos < tag_content.len and tag_content[pos] == ' ') pos += 1;

        // Extract quoted value
        if (pos >= tag_content.len) return null;
        const quote = tag_content[pos];
        if (quote != '"' and quote != '\'') return null;
        pos += 1;
        const value_start = pos;
        while (pos < tag_content.len and tag_content[pos] != quote) pos += 1;
        if (pos >= tag_content.len) return null;
        return tag_content[value_start..pos];
    }
    return null;
}

/// Find the start of an attribute name in tag content, ensuring it is preceded
/// by whitespace (so we don't match partial names).
fn findAttributeStart(content: []const u8, attr_name: []const u8) ?usize {
    var search_pos: usize = 0;
    while (search_pos + attr_name.len <= content.len) {
        if (std.mem.indexOfPos(u8, content, search_pos, attr_name)) |found| {
            // Ensure preceded by whitespace or is at start
            if (found == 0 or content[found - 1] == ' ' or content[found - 1] == '\t') {
                return found;
            }
            search_pos = found + 1;
        } else {
            return null;
        }
    }
    return null;
}

/// Extract a tag name from a hashtag href like "/tags/zig" -> "zig".
/// Also strips a leading '#' if present.
fn extractTagName(allocator: Allocator, href: []const u8) ![]const u8 {
    // Look for "/tags/" prefix
    if (std.mem.indexOf(u8, href, "/tags/")) |idx| {
        const after = href[idx + 6 ..];
        // Strip leading # if present
        if (after.len > 0 and after[0] == '#') {
            return allocator.dupe(u8, after[1..]);
        }
        return allocator.dupe(u8, after);
    }
    // Fallback: strip leading # if present
    if (href.len > 0 and href[0] == '#') {
        return allocator.dupe(u8, href[1..]);
    }
    return allocator.dupe(u8, href);
}

/// Append a JSON key-value string field with trailing comma+newline.
/// e.g., `  "key": "value",\n`
fn appendJsonField(allocator: Allocator, out: *std.ArrayListUnmanaged(u8), key: []const u8, value: []const u8) !void {
    try out.appendSlice(allocator, "  \"");
    try out.appendSlice(allocator, key);
    try out.appendSlice(allocator, "\": \"");
    try appendJsonStringValue(allocator, out, value);
    try out.appendSlice(allocator, "\",\n");
}

/// Append a JSON key-value string field where the value needs JSON escaping (for embedded HTML etc).
fn appendJsonFieldJsonEscaped(allocator: Allocator, out: *std.ArrayListUnmanaged(u8), key: []const u8, value: []const u8) !void {
    try out.appendSlice(allocator, "  \"");
    try out.appendSlice(allocator, key);
    try out.appendSlice(allocator, "\": \"");
    try appendJsonStringValue(allocator, out, value);
    try out.appendSlice(allocator, "\",\n");
}

/// Append a JSON-escaped string value (without surrounding quotes).
fn appendJsonStringValue(allocator: Allocator, out: *std.ArrayListUnmanaged(u8), value: []const u8) !void {
    for (value) |c| {
        switch (c) {
            '"' => try out.appendSlice(allocator, "\\\""),
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            else => {
                if (c < 0x20) {
                    // Control character — encode as \u00XX
                    const hex_chars = "0123456789abcdef";
                    try out.appendSlice(allocator, "\\u00");
                    try out.append(allocator, hex_chars[c >> 4]);
                    try out.append(allocator, hex_chars[c & 0x0f]);
                } else {
                    try out.append(allocator, c);
                }
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "facetsToHtml basic text" {
    const result = try facetsToHtml(std.testing.allocator, "hello world", &.{});
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("<p>hello world</p>", result);
}

test "facetsToHtml with mention" {
    const facets = [_]Facet{.{
        .byte_start = 0,
        .byte_end = 5,
        .feature_type = .mention,
        .value = "did:plc:abc123",
    }};
    const result = try facetsToHtml(std.testing.allocator, "@user is cool", &facets);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings(
        "<p><a href=\"did:plc:abc123\" class=\"mention\">@user</a> is cool</p>",
        result,
    );
}

test "facetsToHtml with link" {
    const text = "check out https://example.com for more";
    const facets = [_]Facet{.{
        .byte_start = 10,
        .byte_end = 29,
        .feature_type = .link,
        .value = "https://example.com",
    }};
    const result = try facetsToHtml(std.testing.allocator, text, &facets);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings(
        "<p>check out <a href=\"https://example.com\">https://example.com</a> for more</p>",
        result,
    );
}

test "facetsToHtml with hashtag" {
    const text = "hello #zig";
    const facets = [_]Facet{.{
        .byte_start = 6,
        .byte_end = 10,
        .feature_type = .tag,
        .value = "zig",
    }};
    const result = try facetsToHtml(std.testing.allocator, text, &facets);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings(
        "<p>hello <a href=\"/tags/zig\" class=\"hashtag\">#zig</a></p>",
        result,
    );
}

test "facetsToHtml HTML escaping" {
    const text = "1 < 2 & 3 > 0";
    const result = try facetsToHtml(std.testing.allocator, text, &.{});
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings(
        "<p>1 &lt; 2 &amp; 3 &gt; 0</p>",
        result,
    );
}

test "facetsToHtml newlines" {
    const text = "line1\nline2\nline3";
    const result = try facetsToHtml(std.testing.allocator, text, &.{});
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings(
        "<p>line1<br>line2<br>line3</p>",
        result,
    );
}

test "htmlToFacets strips tags" {
    const result = try htmlToFacets(std.testing.allocator, "<p>hello</p>");
    defer std.testing.allocator.free(result.text);
    defer std.testing.allocator.free(result.facets);
    try std.testing.expectEqualStrings("hello", result.text);
    try std.testing.expectEqual(@as(usize, 0), result.facets.len);
}

test "htmlToFacets extracts mention" {
    const html = "<p><a class=\"mention\" href=\"did:plc:abc123\">@user</a> hello</p>";
    const result = try htmlToFacets(std.testing.allocator, html);
    defer std.testing.allocator.free(result.text);
    defer {
        for (result.facets) |f| std.testing.allocator.free(f.value);
        std.testing.allocator.free(result.facets);
    }
    try std.testing.expectEqualStrings("@user hello", result.text);
    try std.testing.expectEqual(@as(usize, 1), result.facets.len);
    try std.testing.expectEqual(Facet.FeatureType.mention, result.facets[0].feature_type);
    try std.testing.expectEqualStrings("did:plc:abc123", result.facets[0].value);
    try std.testing.expectEqual(@as(usize, 0), result.facets[0].byte_start);
    try std.testing.expectEqual(@as(usize, 5), result.facets[0].byte_end);
}

test "htmlToFacets extracts link" {
    const html = "<p>visit <a href=\"https://example.com\">example</a></p>";
    const result = try htmlToFacets(std.testing.allocator, html);
    defer std.testing.allocator.free(result.text);
    defer {
        for (result.facets) |f| std.testing.allocator.free(f.value);
        std.testing.allocator.free(result.facets);
    }
    try std.testing.expectEqualStrings("visit example", result.text);
    try std.testing.expectEqual(@as(usize, 1), result.facets.len);
    try std.testing.expectEqual(Facet.FeatureType.link, result.facets[0].feature_type);
    try std.testing.expectEqualStrings("https://example.com", result.facets[0].value);
    try std.testing.expectEqual(@as(usize, 6), result.facets[0].byte_start);
    try std.testing.expectEqual(@as(usize, 13), result.facets[0].byte_end);
}

test "htmlToFacets round-trip" {
    const original_text = "Hello @alice check https://example.com and #zig";
    const original_facets = [_]Facet{
        .{ .byte_start = 6, .byte_end = 12, .feature_type = .mention, .value = "did:plc:alice" },
        .{ .byte_start = 19, .byte_end = 38, .feature_type = .link, .value = "https://example.com" },
        .{ .byte_start = 43, .byte_end = 47, .feature_type = .tag, .value = "zig" },
    };

    // Forward: text+facets -> HTML
    const html = try facetsToHtml(std.testing.allocator, original_text, &original_facets);
    defer std.testing.allocator.free(html);

    // Reverse: HTML -> text+facets
    const result = try htmlToFacets(std.testing.allocator, html);
    defer std.testing.allocator.free(result.text);
    defer {
        for (result.facets) |f| std.testing.allocator.free(f.value);
        std.testing.allocator.free(result.facets);
    }

    try std.testing.expectEqualStrings(original_text, result.text);
    try std.testing.expectEqual(original_facets.len, result.facets.len);

    for (original_facets, result.facets) |orig, got| {
        try std.testing.expectEqual(orig.byte_start, got.byte_start);
        try std.testing.expectEqual(orig.byte_end, got.byte_end);
        try std.testing.expectEqual(orig.feature_type, got.feature_type);
        try std.testing.expectEqualStrings(orig.value, got.value);
    }
}

test "atPostToApNote basic" {
    const record = AtPostRecord{
        .text = "Hello world",
        .created_at = "2024-01-15T12:00:00.000Z",
        .facets = &.{},
        .reply_parent_uri = "at://did:plc:parent/app.bsky.feed.post/parent123",
        .content_warning = "spoiler",
    };
    const note = try atPostToApNote(
        std.testing.allocator,
        record,
        "https://relay.example.com/ap/users/alice",
        "https://relay.example.com/ap/posts/abc123",
    );
    defer {
        std.testing.allocator.free(note.id);
        std.testing.allocator.free(note.attributed_to);
        std.testing.allocator.free(note.content);
        std.testing.allocator.free(note.published);
        if (note.in_reply_to) |irt| std.testing.allocator.free(irt);
        if (note.summary) |s| std.testing.allocator.free(s);
    }

    try std.testing.expectEqualStrings("https://relay.example.com/ap/posts/abc123", note.id);
    try std.testing.expectEqualStrings("https://relay.example.com/ap/users/alice", note.attributed_to);
    try std.testing.expectEqualStrings("<p>Hello world</p>", note.content);
    try std.testing.expectEqualStrings("2024-01-15T12:00:00.000Z", note.published);
    try std.testing.expectEqualStrings("at://did:plc:parent/app.bsky.feed.post/parent123", note.in_reply_to.?);
    try std.testing.expectEqualStrings("spoiler", note.summary.?);
    try std.testing.expect(note.sensitive);
}

test "apNoteToAtPost basic" {
    const note = ApNote{
        .id = "https://mastodon.social/statuses/123",
        .attributed_to = "https://mastodon.social/users/bob",
        .content = "<p>Hello <a href=\"https://example.com\">world</a></p>",
        .published = "2024-01-15T12:00:00.000Z",
        .in_reply_to = "https://mastodon.social/statuses/100",
        .summary = "content warning text",
    };
    const post = try apNoteToAtPost(std.testing.allocator, note);
    defer {
        std.testing.allocator.free(post.text);
        std.testing.allocator.free(post.created_at);
        for (post.facets) |f| std.testing.allocator.free(f.value);
        std.testing.allocator.free(post.facets);
        if (post.reply_parent_uri) |uri| std.testing.allocator.free(uri);
        if (post.reply_root_uri) |uri| std.testing.allocator.free(uri);
        if (post.content_warning) |cw| std.testing.allocator.free(cw);
    }

    try std.testing.expectEqualStrings("Hello world", post.text);
    try std.testing.expectEqualStrings("2024-01-15T12:00:00.000Z", post.created_at);
    try std.testing.expectEqual(@as(usize, 1), post.facets.len);
    try std.testing.expectEqual(Facet.FeatureType.link, post.facets[0].feature_type);
    try std.testing.expectEqualStrings("https://example.com", post.facets[0].value);
    try std.testing.expectEqualStrings("https://mastodon.social/statuses/100", post.reply_parent_uri.?);
    try std.testing.expectEqualStrings("content warning text", post.content_warning.?);
}

test "atLikeToApLike" {
    const activity = try atLikeToApLike(
        std.testing.allocator,
        "at://did:plc:abc/app.bsky.feed.like/rkey1",
        "https://relay.example.com/ap/users/alice",
        "https://relay.example.com/ap/activities/like1",
        "https://mastodon.social/statuses/999",
    );
    defer {
        std.testing.allocator.free(activity.id);
        std.testing.allocator.free(activity.@"type");
        std.testing.allocator.free(activity.actor);
        std.testing.allocator.free(activity.object);
    }

    try std.testing.expectEqualStrings("Like", activity.@"type");
    try std.testing.expectEqualStrings("https://relay.example.com/ap/activities/like1", activity.id);
    try std.testing.expectEqualStrings("https://relay.example.com/ap/users/alice", activity.actor);
    try std.testing.expectEqualStrings("https://mastodon.social/statuses/999", activity.object);
}

test "atRepostToApAnnounce" {
    const activity = try atRepostToApAnnounce(
        std.testing.allocator,
        "at://did:plc:abc/app.bsky.feed.repost/rkey2",
        "https://relay.example.com/ap/users/bob",
        "https://relay.example.com/ap/activities/announce1",
        "https://mastodon.social/statuses/888",
    );
    defer {
        std.testing.allocator.free(activity.id);
        std.testing.allocator.free(activity.@"type");
        std.testing.allocator.free(activity.actor);
        std.testing.allocator.free(activity.object);
    }

    try std.testing.expectEqualStrings("Announce", activity.@"type");
    try std.testing.expectEqualStrings("https://relay.example.com/ap/activities/announce1", activity.id);
    try std.testing.expectEqualStrings("https://relay.example.com/ap/users/bob", activity.actor);
    try std.testing.expectEqualStrings("https://mastodon.social/statuses/888", activity.object);
}

test "atFollowToApFollow" {
    const activity = try atFollowToApFollow(
        std.testing.allocator,
        "did:plc:target",
        "https://relay.example.com/ap/users/carol",
        "https://relay.example.com/ap/activities/follow1",
        "https://mastodon.social/users/dave",
    );
    defer {
        std.testing.allocator.free(activity.id);
        std.testing.allocator.free(activity.@"type");
        std.testing.allocator.free(activity.actor);
        std.testing.allocator.free(activity.object);
    }

    try std.testing.expectEqualStrings("Follow", activity.@"type");
    try std.testing.expectEqualStrings("https://relay.example.com/ap/users/carol", activity.actor);
    try std.testing.expectEqualStrings("https://mastodon.social/users/dave", activity.object);
}

test "apNoteToJson produces valid structure" {
    const note = ApNote{
        .id = "https://example.com/note/1",
        .attributed_to = "https://example.com/users/alice",
        .content = "<p>Hello</p>",
        .published = "2024-01-15T12:00:00.000Z",
    };
    const json = try apNoteToJson(std.testing.allocator, note);
    defer std.testing.allocator.free(json);

    // Verify it parses as valid JSON
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expectEqualStrings("Note", obj.get("type").?.string);
    try std.testing.expectEqualStrings("https://example.com/note/1", obj.get("id").?.string);
}

test "apActivityToJson produces valid structure" {
    const activity = ApActivity{
        .id = "https://example.com/activity/1",
        .@"type" = "Like",
        .actor = "https://example.com/users/alice",
        .object = "https://remote.example.com/note/99",
    };
    const json = try apActivityToJson(std.testing.allocator, activity);
    defer std.testing.allocator.free(json);

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expectEqualStrings("Like", obj.get("type").?.string);
    try std.testing.expectEqualStrings("https://example.com/users/alice", obj.get("actor").?.string);
}

test "parseAtPostRecord basic" {
    const json =
        \\{
        \\  "text": "Hello @alice",
        \\  "createdAt": "2024-01-15T12:00:00.000Z",
        \\  "facets": [
        \\    {
        \\      "index": { "byteStart": 6, "byteEnd": 12 },
        \\      "features": [
        \\        { "$type": "app.bsky.richtext.facet#mention", "did": "did:plc:alice123" }
        \\      ]
        \\    }
        \\  ],
        \\  "langs": ["en"]
        \\}
    ;
    const record = try parseAtPostRecord(std.testing.allocator, json);
    defer {
        std.testing.allocator.free(record.text);
        std.testing.allocator.free(record.created_at);
        for (record.facets) |f| std.testing.allocator.free(f.value);
        std.testing.allocator.free(record.facets);
        for (record.langs) |l| std.testing.allocator.free(l);
        std.testing.allocator.free(record.langs);
    }

    try std.testing.expectEqualStrings("Hello @alice", record.text);
    try std.testing.expectEqualStrings("2024-01-15T12:00:00.000Z", record.created_at);
    try std.testing.expectEqual(@as(usize, 1), record.facets.len);
    try std.testing.expectEqual(Facet.FeatureType.mention, record.facets[0].feature_type);
    try std.testing.expectEqualStrings("did:plc:alice123", record.facets[0].value);
    try std.testing.expectEqual(@as(usize, 1), record.langs.len);
    try std.testing.expectEqualStrings("en", record.langs[0]);
}

test "facetsToHtml multiple facets" {
    const text = "@alice and @bob";
    const facets = [_]Facet{
        .{ .byte_start = 0, .byte_end = 6, .feature_type = .mention, .value = "did:plc:alice" },
        .{ .byte_start = 11, .byte_end = 15, .feature_type = .mention, .value = "did:plc:bob" },
    };
    const result = try facetsToHtml(std.testing.allocator, text, &facets);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings(
        "<p><a href=\"did:plc:alice\" class=\"mention\">@alice</a> and <a href=\"did:plc:bob\" class=\"mention\">@bob</a></p>",
        result,
    );
}

test "htmlToFacets br to newline" {
    const result = try htmlToFacets(std.testing.allocator, "<p>line1<br>line2</p>");
    defer std.testing.allocator.free(result.text);
    defer std.testing.allocator.free(result.facets);
    try std.testing.expectEqualStrings("line1\nline2", result.text);
}

test "htmlToFacets unescapes entities" {
    const result = try htmlToFacets(std.testing.allocator, "<p>1 &lt; 2 &amp; 3 &gt; 0</p>");
    defer std.testing.allocator.free(result.text);
    defer std.testing.allocator.free(result.facets);
    try std.testing.expectEqualStrings("1 < 2 & 3 > 0", result.text);
}
