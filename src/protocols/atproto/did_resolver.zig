//! DID resolution — did:plc + did:web.
//!
//! Both methods require an HTTP fetch in production. The fetch is
//! injected via a function pointer (`HttpFetcher`) so tests can supply
//! a stub. In `app/main.zig` the production fetcher will dispatch to
//! `core.workers.Pool` for blocking HTTP I/O.
//!
//! INFRA-6 — pluggable resolver. The fetcher is the seam: call
//! `setFetcher(fn)` at boot to swap in any DID-resolution strategy
//! without touching this module:
//!   * a real PLC client (POST/GET against `https://plc.directory`);
//!   * a caching proxy / CDN in front of PLC + did:web;
//!   * an offline directory (a fixture map) for air-gapped / test runs.
//! The bounded LRU cache below sits in front of whatever fetcher is
//! installed, so a slow upstream is consulted at most once per TTL.
//!
//! Tiger Style:
//!   * Bounded LRU cache. Cache size = `max_cache_entries`; eviction
//!     by oldest-touched.
//!   * No allocator on resolution paths — caller provides scratch.

const std = @import("std");
const core = @import("core");
const AtpError = core.errors.AtpError;
const assertLe = core.assert.assertLe;

const did_mod = @import("did.zig");

pub const max_cache_entries: u32 = 256;
pub const max_did_bytes: usize = 256;
pub const max_handle_bytes: usize = 256;
pub const max_document_bytes: usize = 16 * 1024;

pub const default_plc_directory: []const u8 = "https://plc.directory";

/// DNS-over-HTTPS endpoint used for the DNS-TXT handle-resolution method.
/// The atproto handle→DID spec defines a TXT record at `_atproto.<handle>`
/// whose value is `did=<did>`. The stripped Zig 0.16 std ships no DNS
/// resolver, so rather than reach for libresolv (`res_query`) — which is
/// not mockable through the existing fetcher seam and is awkward to test —
/// we resolve the TXT record over DNS-over-HTTPS, reusing the same
/// `HttpFetcher` hook that already backs did:plc/did:web/well-known.
///
/// The endpoint speaks the Google/Cloudflare DoH JSON API (the
/// `application/dns-json` flavour): a GET to
/// `?name=<name>&type=TXT` returns `{"Answer":[{"data":"\"did=...\""}]}`.
/// This keeps DNS-TXT fully testable via the mock fetcher and adds no new
/// I/O dependency.
pub const default_doh_endpoint: []const u8 = "https://dns.google/resolve";

pub const max_doh_response_bytes: usize = 4 * 1024;

/// Function pointer that performs an HTTP GET. Implementation:
///   * production: submits a job to `core.workers.Pool` that opens a
///     TLS connection and reads the response into `out`.
///   * tests: a stub that fills `out` from an in-memory table.
pub const HttpFetcher = *const fn (
    url: []const u8,
    out: []u8,
) AtpError!usize;

pub const ResolverError = AtpError || error{NotFound};

// ── Module-level fetcher hook ─────────────────────────────────────────
//
// The composition root wires a real HTTP-backed fetcher at boot via
// `setFetcher`. Code paths that don't have a `Resolver` instance handy
// (e.g. firehose plumbing that needs to resolve a DID inline) can call
// `getFetcher` to discover the production fetcher. Tests can override
// per-test by saving and restoring the previous value.

var module_fetcher: ?HttpFetcher = null;

pub fn setFetcher(f: ?HttpFetcher) void {
    module_fetcher = f;
}

pub fn getFetcher() ?HttpFetcher {
    return module_fetcher;
}

pub const Resolver = struct {
    fetcher: HttpFetcher,
    plc_directory: []const u8 = default_plc_directory,
    doh_endpoint: []const u8 = default_doh_endpoint,
    cache: LRU = .{},

    pub fn init(fetcher: HttpFetcher) Resolver {
        return .{ .fetcher = fetcher };
    }

    pub fn setPlcDirectory(self: *Resolver, dir: []const u8) void {
        self.plc_directory = dir;
    }

    pub fn setDohEndpoint(self: *Resolver, endpoint: []const u8) void {
        self.doh_endpoint = endpoint;
    }

    /// Resolve a DID to its DID document body. Returns slice into `out`.
    pub fn resolveDid(self: *Resolver, did_str: []const u8, out: []u8) ResolverError![]const u8 {
        if (self.cache.get(did_str)) |cached| {
            const cap = @min(cached.len, out.len);
            @memcpy(out[0..cap], cached[0..cap]);
            return out[0..cap];
        }
        const parsed = did_mod.parse(did_str) catch return error.BadDid;
        const url_buf_size: usize = 512;
        var url_buf: [url_buf_size]u8 = undefined;
        const url = switch (parsed.method()) {
            .plc => std.fmt.bufPrint(&url_buf, "{s}/{s}", .{ self.plc_directory, did_str }) catch return error.BufferTooSmall,
            .web => blk: {
                const id = parsed.identifier();
                // Replace %3A with :
                break :blk std.fmt.bufPrint(&url_buf, "https://{s}/.well-known/did.json", .{id}) catch return error.BufferTooSmall;
            },
            .other => return error.BadDid,
        };
        const n = self.fetcher(url, out) catch return error.NotFound;
        if (n == 0) return error.NotFound;
        self.cache.put(did_str, out[0..n]);
        return out[0..n];
    }

    /// Resolve a handle to its DID.
    ///
    /// The atproto handle→DID spec defines two resolution methods and
    /// recommends consulting both: a DNS TXT record at `_atproto.<handle>`
    /// (value `did=<did>`) and the HTTPS well-known path
    /// `https://<handle>/.well-known/atproto-did`. Per spec the DNS-TXT
    /// method takes precedence, so we try it first (over DNS-over-HTTPS,
    /// reusing the fetcher seam) and fall back to the well-known path when
    /// the TXT record is absent or malformed. The resolved DID is written
    /// into `out` and the trimmed slice returned.
    pub fn resolveHandle(self: *Resolver, handle: []const u8, out: []u8) ResolverError![]const u8 {
        // Method 1 (precedence): DNS-TXT via DNS-over-HTTPS.
        if (self.resolveHandleDnsTxt(handle, out)) |did| {
            return did;
        } else |err| switch (err) {
            // Treat "no usable TXT record" and any fetch/parse failure as a
            // signal to fall back to the well-known HTTPS path. A genuinely
            // oversized handle (BufferTooSmall) still aborts.
            error.BufferTooSmall => return error.BufferTooSmall,
            else => {},
        }
        // Method 2 (fallback): HTTPS well-known.
        return self.resolveHandleWellKnown(handle, out);
    }

    /// DNS-TXT resolution method, performed over DNS-over-HTTPS so it routes
    /// through the existing `HttpFetcher` hook (and is mockable in tests).
    fn resolveHandleDnsTxt(self: *Resolver, handle: []const u8, out: []u8) ResolverError![]const u8 {
        var url_buf: [512]u8 = undefined;
        const url = std.fmt.bufPrint(
            &url_buf,
            "{s}?name=_atproto.{s}&type=TXT",
            .{ self.doh_endpoint, handle },
        ) catch return error.BufferTooSmall;

        var resp_buf: [max_doh_response_bytes]u8 = undefined;
        const n = self.fetcher(url, &resp_buf) catch return error.NotFound;
        if (n == 0) return error.NotFound;

        const did = parseDohTxtDid(resp_buf[0..n]) orelse return error.NotFound;
        if (did.len == 0) return error.NotFound;
        if (did.len > out.len) return error.BufferTooSmall;
        @memcpy(out[0..did.len], did);
        return out[0..did.len];
    }

    /// HTTPS well-known resolution method.
    fn resolveHandleWellKnown(self: *Resolver, handle: []const u8, out: []u8) ResolverError![]const u8 {
        var url_buf: [512]u8 = undefined;
        const url = std.fmt.bufPrint(&url_buf, "https://{s}/.well-known/atproto-did", .{handle}) catch return error.BufferTooSmall;
        const n = self.fetcher(url, out) catch return error.NotFound;
        if (n == 0) return error.NotFound;
        // Trim whitespace.
        var end: usize = n;
        while (end > 0 and (out[end - 1] == '\n' or out[end - 1] == '\r' or out[end - 1] == ' ' or out[end - 1] == '\t')) : (end -= 1) {}
        if (end == 0) return error.NotFound;
        return out[0..end];
    }
};

/// Parse a DNS-over-HTTPS JSON response (`application/dns-json`) and extract
/// the DID from the first TXT answer whose data is a `did=<did>` value.
///
/// The response shape is:
///   {"Status":0,"Answer":[{"name":"_atproto.h","type":16,"data":"\"did=did:plc:xyz\""}]}
/// TXT data is commonly wrapped in escaped quotes and may be split into
/// multiple quoted chunks; we strip the wrapping quotes and look for the
/// `did=` prefix. Returns the DID slice (borrowing from `body`) or null when
/// no well-formed `did=` TXT value is present.
fn parseDohTxtDid(body: []const u8) ?[]const u8 {
    // Scan every "data":"..." string in the JSON. We do a bounded manual
    // scan rather than a full JSON parse to keep zero-alloc and avoid
    // pulling in a parser on this hot path.
    const data_key = "\"data\"";
    var search_from: usize = 0;
    while (std.mem.indexOfPos(u8, body, search_from, data_key)) |key_pos| {
        var i = key_pos + data_key.len;
        // Skip whitespace and the colon.
        while (i < body.len and (body[i] == ' ' or body[i] == '\t' or body[i] == ':')) : (i += 1) {}
        if (i >= body.len or body[i] != '"') {
            search_from = key_pos + data_key.len;
            continue;
        }
        i += 1; // past opening quote of the JSON string value
        const value_start = i;
        // Find the closing (unescaped) quote of this JSON string.
        var j = value_start;
        while (j < body.len) : (j += 1) {
            if (body[j] == '\\') {
                j += 1; // skip escaped char
                continue;
            }
            if (body[j] == '"') break;
        }
        if (j >= body.len) return null;
        const raw = body[value_start..j];
        search_from = j + 1;

        if (extractDidFromTxtData(raw)) |did| return did;
    }
    return null;
}

/// Given the raw JSON string value of a TXT `data` field (e.g.
/// `\"did=did:plc:xyz\"` with escaped quotes, or a bare `did=did:plc:xyz`),
/// strip surrounding escaped/literal quotes and return the value after the
/// `did=` prefix. Returns null if the field is not a `did=` record or the
/// DID is implausibly long.
fn extractDidFromTxtData(raw_in: []const u8) ?[]const u8 {
    var raw = raw_in;
    // Strip a leading escaped quote (\") or literal quote.
    if (std.mem.startsWith(u8, raw, "\\\"")) {
        raw = raw[2..];
    } else if (raw.len > 0 and raw[0] == '"') {
        raw = raw[1..];
    }
    // Strip a trailing escaped quote (\") or literal quote.
    if (std.mem.endsWith(u8, raw, "\\\"")) {
        raw = raw[0 .. raw.len - 2];
    } else if (raw.len > 0 and raw[raw.len - 1] == '"') {
        raw = raw[0 .. raw.len - 1];
    }
    const prefix = "did=";
    if (!std.mem.startsWith(u8, raw, prefix)) return null;
    const did = raw[prefix.len..];
    if (did.len == 0 or did.len > max_did_bytes) return null;
    // Sanity: a DID must start with the "did:" scheme.
    if (!std.mem.startsWith(u8, did, "did:")) return null;
    return did;
}

const Entry = struct {
    key_buf: [max_did_bytes]u8 = undefined,
    key_len: u16 = 0,
    value_buf: [max_document_bytes]u8 = undefined,
    value_len: u16 = 0,
    touched: u64 = 0,
    used: bool = false,

    fn key(self: *const Entry) []const u8 {
        return self.key_buf[0..self.key_len];
    }
    fn value(self: *const Entry) []const u8 {
        return self.value_buf[0..self.value_len];
    }
};

pub const LRU = struct {
    entries: [max_cache_entries]Entry = undefined,
    touch_counter: u64 = 0,
    count: u32 = 0,

    pub fn get(self: *LRU, k: []const u8) ?[]const u8 {
        var i: u32 = 0;
        while (i < self.entries.len) : (i += 1) {
            const e = &self.entries[i];
            if (!e.used) continue;
            if (std.mem.eql(u8, e.key(), k)) {
                self.touch_counter += 1;
                e.touched = self.touch_counter;
                return e.value();
            }
        }
        return null;
    }

    pub fn put(self: *LRU, k: []const u8, v: []const u8) void {
        if (k.len > max_did_bytes or v.len > max_document_bytes) return;
        // Find vacant or oldest.
        var i: u32 = 0;
        var victim: u32 = 0;
        var oldest: u64 = std.math.maxInt(u64);
        var found_empty = false;
        while (i < self.entries.len) : (i += 1) {
            const e = &self.entries[i];
            if (!e.used) {
                victim = i;
                found_empty = true;
                break;
            }
            if (e.touched < oldest) {
                oldest = e.touched;
                victim = i;
            }
        }
        const e = &self.entries[victim];
        e.used = true;
        @memcpy(e.key_buf[0..k.len], k);
        e.key_len = @intCast(k.len);
        @memcpy(e.value_buf[0..v.len], v);
        e.value_len = @intCast(v.len);
        self.touch_counter += 1;
        e.touched = self.touch_counter;
        if (found_empty) {
            self.count += 1;
            assertLe(self.count, max_cache_entries);
        }
    }
};

// ── Tests ──────────────────────────────────────────────────────────

const testing = std.testing;

const Stub = struct {
    var current: [4096]u8 = undefined;
    var current_len: usize = 0;
    var url_seen: [512]u8 = undefined;
    var url_seen_len: usize = 0;
    var call_count: u32 = 0;

    // URL-routed responses: when `route_match` is non-empty, a URL that
    // contains it receives `route_body`; all other URLs receive `current`.
    // This lets a single stub model "DoH says X, well-known says Y".
    var route_match: [128]u8 = undefined;
    var route_match_len: usize = 0;
    var route_body: [4096]u8 = undefined;
    var route_body_len: usize = 0;

    fn fetch(url: []const u8, out: []u8) AtpError!usize {
        call_count += 1;
        const ul = @min(url.len, url_seen.len);
        @memcpy(url_seen[0..ul], url[0..ul]);
        url_seen_len = ul;
        if (route_match_len > 0 and
            std.mem.indexOf(u8, url, route_match[0..route_match_len]) != null)
        {
            const n = @min(route_body_len, out.len);
            @memcpy(out[0..n], route_body[0..n]);
            return n;
        }
        const n = @min(current_len, out.len);
        @memcpy(out[0..n], current[0..n]);
        return n;
    }
    fn setResponse(body: []const u8) void {
        @memcpy(current[0..body.len], body);
        current_len = body.len;
    }
    fn setRoute(match: []const u8, body: []const u8) void {
        @memcpy(route_match[0..match.len], match);
        route_match_len = match.len;
        @memcpy(route_body[0..body.len], body);
        route_body_len = body.len;
    }
    fn reset() void {
        current_len = 0;
        url_seen_len = 0;
        call_count = 0;
        route_match_len = 0;
        route_body_len = 0;
    }
};

test "resolver: did:web hits well-known/did.json" {
    Stub.reset();
    Stub.setResponse("{\"id\":\"did:web:example.com\"}");
    var r = Resolver.init(Stub.fetch);
    var out: [256]u8 = undefined;
    const doc = try r.resolveDid("did:web:example.com", &out);
    try testing.expect(std.mem.indexOf(u8, doc, "did:web:example.com") != null);
    try testing.expect(std.mem.indexOf(u8, Stub.url_seen[0..Stub.url_seen_len], "/.well-known/did.json") != null);
}

test "resolver: did:plc hits configured directory" {
    Stub.reset();
    Stub.setResponse("{\"id\":\"did:plc:abc\"}");
    var r = Resolver.init(Stub.fetch);
    var out: [256]u8 = undefined;
    _ = try r.resolveDid("did:plc:abc123", &out);
    try testing.expect(std.mem.indexOf(u8, Stub.url_seen[0..Stub.url_seen_len], "plc.directory") != null);
}

test "resolver: cache prevents second fetch" {
    Stub.reset();
    Stub.setResponse("{\"id\":\"did:web:cached.com\"}");
    var r = Resolver.init(Stub.fetch);
    var out: [256]u8 = undefined;
    _ = try r.resolveDid("did:web:cached.com", &out);
    _ = try r.resolveDid("did:web:cached.com", &out);
    try testing.expectEqual(@as(u32, 1), Stub.call_count);
}

test "resolver: handle resolves to DID via well-known (DNS-TXT absent)" {
    Stub.reset();
    // DoH endpoint returns an empty/NXDOMAIN-style answer with no TXT data,
    // so resolution falls back to the well-known HTTPS path.
    Stub.setRoute("dns.google", "{\"Status\":3,\"Answer\":[]}");
    Stub.setResponse("did:web:alice.example.com\n");
    var r = Resolver.init(Stub.fetch);
    var out: [128]u8 = undefined;
    const got = try r.resolveHandle("alice.example.com", &out);
    try testing.expectEqualStrings("did:web:alice.example.com", got);
    // The last fetch must have hit the well-known path.
    try testing.expect(std.mem.indexOf(u8, Stub.url_seen[0..Stub.url_seen_len], "/.well-known/atproto-did") != null);
}

test "resolver: handle resolves via DNS-TXT (DoH) and takes precedence" {
    Stub.reset();
    // DoH returns a valid TXT record; well-known would return a *different*
    // DID, proving DNS-TXT takes precedence and well-known is never consulted.
    Stub.setRoute("dns.google", "{\"Status\":0,\"Answer\":[{\"name\":\"_atproto.bob.example.com\",\"type\":16,\"data\":\"\\\"did=did:plc:xyz\\\"\"}]}");
    Stub.setResponse("did:web:should-not-be-used\n");
    var r = Resolver.init(Stub.fetch);
    var out: [128]u8 = undefined;
    const got = try r.resolveHandle("bob.example.com", &out);
    try testing.expectEqualStrings("did:plc:xyz", got);
    // Exactly one fetch: the DoH query. No fallback.
    try testing.expectEqual(@as(u32, 1), Stub.call_count);
    try testing.expect(std.mem.indexOf(u8, Stub.url_seen[0..Stub.url_seen_len], "_atproto.bob.example.com") != null);
    try testing.expect(std.mem.indexOf(u8, Stub.url_seen[0..Stub.url_seen_len], "type=TXT") != null);
}

test "resolver: DNS-TXT handles unquoted did= TXT data" {
    Stub.reset();
    Stub.setRoute("dns.google", "{\"Answer\":[{\"data\":\"did=did:plc:unquoted\"}]}");
    var r = Resolver.init(Stub.fetch);
    var out: [128]u8 = undefined;
    const got = try r.resolveHandle("c.example.com", &out);
    try testing.expectEqualStrings("did:plc:unquoted", got);
}

test "resolver: malformed DNS-TXT falls back to well-known" {
    Stub.reset();
    // DoH answer present but the TXT data is not a `did=` record (e.g. a
    // stray verification token). Must fall back to well-known.
    Stub.setRoute("dns.google", "{\"Answer\":[{\"data\":\"\\\"v=spf1 -all\\\"\"}]}");
    Stub.setResponse("did:web:fallback.example.com\n");
    var r = Resolver.init(Stub.fetch);
    var out: [128]u8 = undefined;
    const got = try r.resolveHandle("fallback.example.com", &out);
    try testing.expectEqualStrings("did:web:fallback.example.com", got);
    try testing.expect(std.mem.indexOf(u8, Stub.url_seen[0..Stub.url_seen_len], "/.well-known/atproto-did") != null);
}

test "resolver: TXT value that isn't a DID scheme is rejected" {
    Stub.reset();
    // `did=` prefix present but value lacks the `did:` scheme — reject and
    // fall back (well-known here also empty → NotFound).
    Stub.setRoute("dns.google", "{\"Answer\":[{\"data\":\"did=garbage\"}]}");
    Stub.setResponse("");
    var r = Resolver.init(Stub.fetch);
    var out: [128]u8 = undefined;
    try testing.expectError(error.NotFound, r.resolveHandle("bad.example.com", &out));
}

test "resolver: both methods absent yields NotFound" {
    Stub.reset();
    Stub.setRoute("dns.google", "{\"Status\":3,\"Answer\":[]}");
    Stub.setResponse("");
    var r = Resolver.init(Stub.fetch);
    var out: [128]u8 = undefined;
    try testing.expectError(error.NotFound, r.resolveHandle("nothing.example.com", &out));
}

test "parseDohTxtDid: extracts did from quoted multi-answer response" {
    const body = "{\"Answer\":[{\"data\":\"\\\"unrelated\\\"\"},{\"data\":\"\\\"did=did:plc:second\\\"\"}]}";
    const did = parseDohTxtDid(body) orelse unreachable;
    try testing.expectEqualStrings("did:plc:second", did);
}

test "parseDohTxtDid: returns null for no did record" {
    const body = "{\"Answer\":[{\"data\":\"\\\"hello world\\\"\"}]}";
    try testing.expect(parseDohTxtDid(body) == null);
}

test "resolver: empty fetch yields NotFound" {
    Stub.reset();
    Stub.setResponse("");
    var r = Resolver.init(Stub.fetch);
    var out: [128]u8 = undefined;
    try testing.expectError(error.NotFound, r.resolveDid("did:web:gone.example", &out));
}
