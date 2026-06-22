//! Build the `Person` JSON-LD actor document.
//!
//! Mastodon expects:
//!   * `id`, `type`, `preferredUsername`, `inbox`, `outbox`, `followers`,
//!     `following`, `featured`, `endpoints.sharedInbox`
//!   * `publicKey` object with `id`, `owner`, `publicKeyPem`
//!   * `manuallyApprovesFollowers` (AS extension)
//!   * `discoverable`, `indexable` (toot:)
//!
//! Tiger Style: caller-supplied output buffer.

const std = @import("std");

pub const WriteError = error{BufferTooSmall};

/// AP-10: actor type. AS2 allows Person / Service / Organization /
/// Group / Application. Mastodon honours Service ("bot") + Group +
/// Application; group fanout (FEP-1b12) is a future ticket — this
/// just controls the emitted `type` field.
pub const ActorType = enum {
    person,
    service,
    organization,
    group,
    application,

    pub fn asString(self: ActorType) []const u8 {
        return switch (self) {
            .person => "Person",
            .service => "Service",
            .organization => "Organization",
            .group => "Group",
            .application => "Application",
        };
    }

    pub fn parse(s: []const u8) ?ActorType {
        if (std.ascii.eqlIgnoreCase(s, "person")) return .person;
        if (std.ascii.eqlIgnoreCase(s, "service")) return .service;
        if (std.ascii.eqlIgnoreCase(s, "organization")) return .organization;
        if (std.ascii.eqlIgnoreCase(s, "group")) return .group;
        if (std.ascii.eqlIgnoreCase(s, "application")) return .application;
        return null;
    }
};

/// AP-15: a single additional published Ed25519 key (FEP-d36d
/// Multikey rotation). The actor advertises these alongside its
/// primary `#main-key` as `#key-N` Multikeys so verifiers can find a
/// rotation key. `multibase` is the `z6Mk…` form.
pub const ExtraKey = struct {
    multibase: []const u8,
};

/// Bound on how many extra rotation keys we advertise in one actor
/// document — keeps the output buffer bounded (Tiger Style).
pub const max_extra_keys: usize = 8;

pub const Config = struct {
    hostname: []const u8,
    username: []const u8,
    display_name: []const u8 = "",
    bio: []const u8 = "",
    public_key_pem: []const u8 = "",
    /// True if the account is locked / approves followers manually.
    manually_approves_followers: bool = false,
    discoverable: bool = true,
    indexable: bool = true,
    /// AP-10: per-actor type. Default `Person`.
    actor_type: ActorType = .person,
    /// AP-15: the actor's Ed25519 key as a multibase string
    /// (`z6Mk…` — base58btc of multicodec-prefixed key). When set, the
    /// actor advertises an `assertionMethod` Multikey (FEP-d36d).
    assertion_multibase: []const u8 = "",
    /// AP-15: additional published rotation keys (FEP-d36d). Each is
    /// emitted as a `#key-N` Multikey in both `assertionMethod` and
    /// `verificationMethod`. Bounded by `max_extra_keys`.
    extra_keys: []const ExtraKey = &.{},
};

pub fn writePerson(cfg: Config, out: []u8) WriteError![]const u8 {
    // Build using bufPrint segments to keep within line-length but
    // produce a single contiguous JSON-LD object.
    var w: usize = 0;
    w += try copy(out[w..],
        "{\"@context\":[\"https://www.w3.org/ns/activitystreams\"," ++
        "{\"toot\":\"http://joinmastodon.org/ns#\"," ++
        "\"discoverable\":\"toot:discoverable\"," ++
        "\"indexable\":\"toot:indexable\"," ++
        "\"featured\":{\"@id\":\"toot:featured\",\"@type\":\"@id\"}," ++
        "\"manuallyApprovesFollowers\":\"as:manuallyApprovesFollowers\"}],");
    w += try fmtInto(out[w..], "\"id\":\"https://{s}/users/{s}\",", .{ cfg.hostname, cfg.username });
    w += try fmtInto(out[w..], "\"type\":\"{s}\",", .{cfg.actor_type.asString()});
    w += try fmtInto(out[w..], "\"preferredUsername\":\"{s}\",", .{cfg.username});
    // DUAL-4: advertise the account's AT Protocol identity so an AP
    // consumer can cross to the at:// side. Unified-signup accounts use
    // the AP username as the AT handle.
    w += try fmtInto(out[w..], "\"alsoKnownAs\":[\"at://{s}\"],", .{cfg.username});
    if (cfg.display_name.len > 0) {
        w += try fmtInto(out[w..], "\"name\":\"{s}\",", .{cfg.display_name});
    }
    if (cfg.bio.len > 0) {
        w += try fmtInto(out[w..], "\"summary\":\"{s}\",", .{cfg.bio});
    }
    w += try fmtInto(out[w..],
        "\"inbox\":\"https://{s}/users/{s}/inbox\"," ++
        "\"outbox\":\"https://{s}/users/{s}/outbox\"," ++
        "\"followers\":\"https://{s}/users/{s}/followers\"," ++
        "\"following\":\"https://{s}/users/{s}/following\"," ++
        "\"featured\":\"https://{s}/users/{s}/collections/featured\"," ++
        "\"liked\":\"https://{s}/users/{s}/liked\"," ++ // AP-14
        "\"endpoints\":{{\"sharedInbox\":\"https://{s}/inbox\"}},",
        .{
            cfg.hostname, cfg.username,
            cfg.hostname, cfg.username,
            cfg.hostname, cfg.username,
            cfg.hostname, cfg.username,
            cfg.hostname, cfg.username,
            cfg.hostname, cfg.username,
            cfg.hostname,
        });
    w += try fmtInto(out[w..], "\"manuallyApprovesFollowers\":{s},", .{
        if (cfg.manually_approves_followers) "true" else "false",
    });
    w += try fmtInto(out[w..], "\"discoverable\":{s},", .{
        if (cfg.discoverable) "true" else "false",
    });
    w += try fmtInto(out[w..], "\"indexable\":{s},", .{
        if (cfg.indexable) "true" else "false",
    });
    // publicKey
    w += try fmtInto(out[w..],
        "\"publicKey\":{{\"id\":\"https://{s}/users/{s}#main-key\"," ++
        "\"owner\":\"https://{s}/users/{s}\",\"publicKeyPem\":\"",
        .{ cfg.hostname, cfg.username, cfg.hostname, cfg.username });
    // PEM contains newlines — JSON-escape them to `\n`.
    w += try escapePem(out[w..], cfg.public_key_pem);
    w += try copy(out[w..], "\"}"); // close publicKeyPem string + publicKey object
    // AP-15: advertise the signing key (and any published rotation
    // keys) as Multikeys (FEP-d36d). We emit the same Multikey array
    // under both `assertionMethod` and `verificationMethod` so
    // verifiers that look up either property can find the keys.
    if (cfg.extra_keys.len > max_extra_keys) return error.BufferTooSmall;
    const has_primary = cfg.assertion_multibase.len > 0;
    if (has_primary or cfg.extra_keys.len > 0) {
        // Build the shared Multikey array body once.
        w += try copy(out[w..], ",\"assertionMethod\":");
        w += try writeMultikeyArray(out[w..], cfg, has_primary);
        w += try copy(out[w..], ",\"verificationMethod\":");
        w += try writeMultikeyArray(out[w..], cfg, has_primary);
    }
    w += try copy(out[w..], "}"); // close actor object
    return out[0..w];
}

/// Synthetic-actor variant (A1). Used by the protocol-relay to serve
/// AS Person docs for bridged actors whose canonical URL is
/// `<actor_url>` (e.g. `https://relay.example/ap/users/at:plc:abc`)
/// — i.e. NOT the `<host>/users/<username>` shape of the local user
/// table. Inbox / outbox / followers / following / shared-inbox URLs
/// are derived by appending to `actor_url`; the shared-inbox URL is
/// the local host's root `/inbox` (same shared inbox the AP plugin
/// already serves).
pub const SyntheticConfig = struct {
    actor_url: []const u8,
    preferred_username: []const u8,
    display_name: []const u8 = "",
    bio: []const u8 = "",
    public_key_pem: []const u8 = "",
    shared_inbox_url: []const u8,
};

pub fn writeSyntheticPerson(cfg: SyntheticConfig, out: []u8) WriteError![]const u8 {
    var w: usize = 0;
    w += try copy(out[w..],
        "{\"@context\":[\"https://www.w3.org/ns/activitystreams\"," ++
        "\"https://w3id.org/security/v1\"," ++
        "{\"toot\":\"http://joinmastodon.org/ns#\"," ++
        "\"discoverable\":\"toot:discoverable\"," ++
        "\"indexable\":\"toot:indexable\"," ++
        "\"manuallyApprovesFollowers\":\"as:manuallyApprovesFollowers\"}],");
    w += try fmtInto(out[w..], "\"id\":\"{s}\",", .{cfg.actor_url});
    w += try copy(out[w..], "\"type\":\"Person\",");
    w += try fmtInto(out[w..], "\"preferredUsername\":\"{s}\",", .{cfg.preferred_username});
    if (cfg.display_name.len > 0) {
        w += try fmtInto(out[w..], "\"name\":\"{s}\",", .{cfg.display_name});
    }
    if (cfg.bio.len > 0) {
        w += try fmtInto(out[w..], "\"summary\":\"{s}\",", .{cfg.bio});
    }
    w += try fmtInto(out[w..],
        "\"inbox\":\"{s}/inbox\"," ++
        "\"outbox\":\"{s}/outbox\"," ++
        "\"followers\":\"{s}/followers\"," ++
        "\"following\":\"{s}/following\"," ++
        "\"endpoints\":{{\"sharedInbox\":\"{s}\"}},",
        .{ cfg.actor_url, cfg.actor_url, cfg.actor_url, cfg.actor_url, cfg.shared_inbox_url });
    // Bridge actors approve followers manually (we don't yet do
    // auto-accept on Follow) and are discoverable by default.
    w += try copy(out[w..], "\"manuallyApprovesFollowers\":false,");
    w += try copy(out[w..], "\"discoverable\":true,");
    w += try copy(out[w..], "\"indexable\":true,");
    w += try fmtInto(out[w..],
        "\"publicKey\":{{\"id\":\"{s}#main-key\"," ++
        "\"owner\":\"{s}\",\"publicKeyPem\":\"",
        .{ cfg.actor_url, cfg.actor_url });
    w += try escapePem(out[w..], cfg.public_key_pem);
    w += try copy(out[w..], "\"}}");
    return out[0..w];
}

/// AP-15: write the JSON array of Multikey entries (FEP-d36d). The
/// primary `#main-key` is emitted first when `with_primary`; each
/// extra key is emitted as `#key-N` (1-indexed). Tiger Style: bounded
/// by `max_extra_keys`, fixed output slice.
fn writeMultikeyArray(dest: []u8, cfg: Config, with_primary: bool) WriteError!usize {
    var w: usize = 0;
    w += try copy(dest[w..], "[");
    var wrote_one = false;
    if (with_primary) {
        w += try fmtInto(dest[w..],
            "{{\"id\":\"https://{s}/users/{s}#main-key\"," ++
            "\"type\":\"Multikey\",\"controller\":\"https://{s}/users/{s}\"," ++
            "\"publicKeyMultibase\":\"{s}\"}}",
            .{ cfg.hostname, cfg.username, cfg.hostname, cfg.username, cfg.assertion_multibase });
        wrote_one = true;
    }
    var idx: usize = 0;
    while (idx < cfg.extra_keys.len) : (idx += 1) {
        if (wrote_one) w += try copy(dest[w..], ",");
        w += try fmtInto(dest[w..],
            "{{\"id\":\"https://{s}/users/{s}#key-{d}\"," ++
            "\"type\":\"Multikey\",\"controller\":\"https://{s}/users/{s}\"," ++
            "\"publicKeyMultibase\":\"{s}\"}}",
            .{ cfg.hostname, cfg.username, idx + 1, cfg.hostname, cfg.username, cfg.extra_keys[idx].multibase });
        wrote_one = true;
    }
    w += try copy(dest[w..], "]");
    return w;
}

fn copy(dest: []u8, src: []const u8) WriteError!usize {
    if (src.len > dest.len) return error.BufferTooSmall;
    @memcpy(dest[0..src.len], src);
    return src.len;
}

fn fmtInto(dest: []u8, comptime fmt: []const u8, args: anytype) WriteError!usize {
    const got = std.fmt.bufPrint(dest, fmt, args) catch return error.BufferTooSmall;
    return got.len;
}

fn escapePem(dest: []u8, pem: []const u8) WriteError!usize {
    var w: usize = 0;
    for (pem) |ch| {
        if (ch == '\n') {
            if (w + 2 > dest.len) return error.BufferTooSmall;
            dest[w] = '\\';
            dest[w + 1] = 'n';
            w += 2;
        } else if (ch == '"') {
            if (w + 2 > dest.len) return error.BufferTooSmall;
            dest[w] = '\\';
            dest[w + 1] = '"';
            w += 2;
        } else if (ch == '\\') {
            if (w + 2 > dest.len) return error.BufferTooSmall;
            dest[w] = '\\';
            dest[w + 1] = '\\';
            w += 2;
        } else {
            if (w + 1 > dest.len) return error.BufferTooSmall;
            dest[w] = ch;
            w += 1;
        }
    }
    return w;
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "writePerson includes Mastodon-extension fields" {
    var buf: [4096]u8 = undefined;
    const out = try writePerson(.{
        .hostname = "example.com",
        .username = "alice",
        .display_name = "Alice",
        .public_key_pem = "-----BEGIN PUBLIC KEY-----\nABC\n-----END PUBLIC KEY-----",
        .manually_approves_followers = true,
    }, &buf);
    try testing.expect(std.mem.indexOf(u8, out, "\"type\":\"Person\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"preferredUsername\":\"alice\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"name\":\"Alice\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "https://example.com/users/alice/inbox") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"sharedInbox\":\"https://example.com/inbox\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"manuallyApprovesFollowers\":true") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"discoverable\":true") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"indexable\":true") != null);
    try testing.expect(std.mem.indexOf(u8, out, "publicKey") != null);
    // PEM newlines are escaped.
    try testing.expect(std.mem.indexOf(u8, out, "BEGIN PUBLIC KEY-----\\nABC") != null);
}

test "writePerson with empty optional fields" {
    var buf: [4096]u8 = undefined;
    const out = try writePerson(.{ .hostname = "h", .username = "u" }, &buf);
    try testing.expect(std.mem.indexOf(u8, out, "\"name\"") == null);
    try testing.expect(std.mem.indexOf(u8, out, "\"summary\"") == null);
    try testing.expect(std.mem.indexOf(u8, out, "\"manuallyApprovesFollowers\":false") != null);
}

test "writePerson fails when buffer too small" {
    var tiny: [16]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, writePerson(.{ .hostname = "h", .username = "u" }, &tiny));
}

test "AP-15: writePerson advertises extra Multikeys as #key-N in both methods" {
    // Randomize the count of extra keys (1..max_extra_keys) and the
    // multibase contents to avoid a hardcoded happy path.
    var prng = std.Random.DefaultPrng.init(0xC0FFEE);
    const rnd = prng.random();
    const n: usize = 1 + rnd.uintLessThan(usize, max_extra_keys);

    var mb_storage: [max_extra_keys][24]u8 = undefined;
    var extras: [max_extra_keys]ExtraKey = undefined;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        mb_storage[i][0] = 'z';
        var j: usize = 1;
        while (j < mb_storage[i].len) : (j += 1) {
            // base58btc-ish alphabet subset; content is arbitrary here.
            const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
            mb_storage[i][j] = alphabet[rnd.uintLessThan(usize, alphabet.len)];
        }
        extras[i] = .{ .multibase = mb_storage[i][0..] };
    }

    var buf: [8192]u8 = undefined;
    const out = try writePerson(.{
        .hostname = "h.example",
        .username = "alice",
        .public_key_pem = "",
        .assertion_multibase = "z6MkPRIMARYxxxxxxxxxxxxx",
        .extra_keys = extras[0..n],
    }, &buf);

    // Primary main-key + every extra #key-N appears, under both methods.
    try testing.expect(std.mem.indexOf(u8, out, "\"assertionMethod\":[") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"verificationMethod\":[") != null);
    try testing.expect(std.mem.indexOf(u8, out, "#main-key") != null);
    var k: usize = 0;
    while (k < n) : (k += 1) {
        var idbuf: [32]u8 = undefined;
        const frag = try std.fmt.bufPrint(&idbuf, "#key-{d}", .{k + 1});
        try testing.expect(std.mem.indexOf(u8, out, frag) != null);
    }
    // Multikey type appears (primary + n extras) under both methods:
    // total occurrences = 2 * (1 + n).
    const wanted: usize = 2 * (1 + n);
    var count: usize = 0;
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, out, pos, "\"type\":\"Multikey\"")) |at| {
        count += 1;
        pos = at + 1;
    }
    try testing.expectEqual(wanted, count);
}

test "AP-15: too many extra keys is rejected" {
    var extras: [max_extra_keys + 1]ExtraKey = undefined;
    for (&extras) |*e| e.* = .{ .multibase = "z6Mkxxxx" };
    var buf: [8192]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, writePerson(.{
        .hostname = "h",
        .username = "u",
        .extra_keys = extras[0..],
    }, &buf));
}
