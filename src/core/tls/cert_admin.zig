//! Op-B / C4: TLS cert hot-reload admin surface.
//!
//! Reads the cert + key PEMs from the configured paths and calls
//! `IanicInboundBackend.reloadCertKey`. Path source: env vars
//! `TLS_CERT_PATH` + `TLS_KEY_PATH` (the same vars the boot loader
//! consults), or arguments handed in by an admin route at request
//! time.
//!
//! C5 / C2 notes:
//!   * `C2` (multi-SNI cert dispatch) is upstream-blocked — ianic-tls
//!     doesn't expose a server-side `cert_selector` callback in 0.16.
//!     The `CertTable` below is the data-side shape; when the
//!     callback lands, wire `select` into the handshake path.
//!   * `C5` (cert pinning on outbound TLS) requires post-handshake
//!     peer-cert chain inspection. `std.crypto.tls.Client` does not
//!     surface this in Zig 0.16; the pinning hook below stays a
//!     no-op until that lands.

const std = @import("std");
const ianic_inbound = @import("ianic_inbound.zig");

pub const Error = error{
    CertPathUnset,
    CertReadFailed,
    KeyReadFailed,
    ReloadFailed,
    BackendNotConfigured,
};

var current_backend: ?*ianic_inbound.IanicInboundBackend = null;

pub fn registerBackend(backend: *ianic_inbound.IanicInboundBackend) void {
    current_backend = backend;
}

pub fn reloadFromPaths(cert_path: []const u8, key_path: []const u8, allocator: std.mem.Allocator) Error!void {
    const backend = current_backend orelse return error.BackendNotConfigured;
    const cert_pem = readFile(cert_path, allocator) catch return error.CertReadFailed;
    defer allocator.free(cert_pem);
    const key_pem = readFile(key_path, allocator) catch return error.KeyReadFailed;
    defer allocator.free(key_pem);
    backend.reloadCertKey(cert_pem, key_pem) catch return error.ReloadFailed;
}

fn readFile(path: []const u8, allocator: std.mem.Allocator) ![]u8 {
    var path_z_buf: [512]u8 = undefined;
    if (path.len + 1 > path_z_buf.len) return error.PathTooLong;
    @memcpy(path_z_buf[0..path.len], path);
    path_z_buf[path.len] = 0;
    const path_z: [*:0]const u8 = @ptrCast(&path_z_buf);

    const fd = std.c.open(path_z, .{ .ACCMODE = .RDONLY }, @as(std.c.mode_t, 0));
    if (fd < 0) return error.OpenFailed;
    defer _ = std.c.close(fd);
    // Probe size by lseek end.
    const size = std.c.lseek(fd, 0, std.c.SEEK.END);
    if (size <= 0) return error.EmptyFile;
    _ = std.c.lseek(fd, 0, std.c.SEEK.SET);
    const buf = try allocator.alloc(u8, @intCast(size));
    var total: usize = 0;
    while (total < buf.len) {
        const got = std.c.read(fd, buf.ptr + total, buf.len - total);
        if (got <= 0) break;
        total += @intCast(got);
    }
    return buf[0..total];
}

// ──────────────────────────────────────────────────────────────────────
// C2 — SNI cert table (data side; live dispatch awaits ianic upstream).
// ──────────────────────────────────────────────────────────────────────

pub const CertEntry = struct {
    sni_buf: [128]u8 = undefined,
    sni_len: u8 = 0,
    cert_path_buf: [256]u8 = undefined,
    cert_path_len: u16 = 0,
    key_path_buf: [256]u8 = undefined,
    key_path_len: u16 = 0,

    pub fn sni(self: *const CertEntry) []const u8 {
        return self.sni_buf[0..self.sni_len];
    }
    pub fn certPath(self: *const CertEntry) []const u8 {
        return self.cert_path_buf[0..self.cert_path_len];
    }
    pub fn keyPath(self: *const CertEntry) []const u8 {
        return self.key_path_buf[0..self.key_path_len];
    }
};

pub const CertTable = struct {
    pub const max_entries: usize = 16;
    entries: [max_entries]CertEntry = undefined,
    count: u8 = 0,

    pub fn add(self: *CertTable, sni: []const u8, cert_path: []const u8, key_path: []const u8) !void {
        if (self.count >= max_entries) return error.Full;
        var e: CertEntry = .{};
        const sc = @min(sni.len, e.sni_buf.len);
        @memcpy(e.sni_buf[0..sc], sni[0..sc]);
        e.sni_len = @intCast(sc);
        const cc = @min(cert_path.len, e.cert_path_buf.len);
        @memcpy(e.cert_path_buf[0..cc], cert_path[0..cc]);
        e.cert_path_len = @intCast(cc);
        const kc = @min(key_path.len, e.key_path_buf.len);
        @memcpy(e.key_path_buf[0..kc], key_path[0..kc]);
        e.key_path_len = @intCast(kc);
        self.entries[self.count] = e;
        self.count += 1;
    }

    pub fn lookup(self: *const CertTable, sni: []const u8) ?*const CertEntry {
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            if (std.mem.eql(u8, self.entries[i].sni(), sni)) return &self.entries[i];
        }
        return null;
    }

    /// Parse `TLS_SNI_CERTS=host1=cert1.pem:key1.pem,host2=cert2.pem:key2.pem`.
    pub fn parseEnv(self: *CertTable, env_value: []const u8) !void {
        var remaining = env_value;
        while (remaining.len > 0) {
            const comma = std.mem.indexOfScalar(u8, remaining, ',') orelse remaining.len;
            const entry = remaining[0..comma];
            remaining = if (comma < remaining.len) remaining[comma + 1 ..] else &.{};
            const eq = std.mem.indexOfScalar(u8, entry, '=') orelse continue;
            const sni = entry[0..eq];
            const paths = entry[eq + 1 ..];
            const colon = std.mem.indexOfScalar(u8, paths, ':') orelse continue;
            const cert_path = paths[0..colon];
            const key_path = paths[colon + 1 ..];
            try self.add(sni, cert_path, key_path);
        }
    }
};

// ──────────────────────────────────────────────────────────────────────
// C5 — outbound cert-pinning hook (data side; verification deferred).
// ──────────────────────────────────────────────────────────────────────

pub const PinHook = *const fn (host: []const u8, peer_cert_der: []const u8) bool;
var pin_hook: ?PinHook = null;

pub fn setPinHook(hook: PinHook) void {
    pin_hook = hook;
}

pub fn clearPinHook() void {
    pin_hook = null;
}

// ── Env-driven pin store + default hook ────────────────────────────────
//
// Cert pinning is opt-in per host. `TLS_PINS` maps a host to the base64
// SHA-256 of its expected leaf certificate (DER):
//
//   TLS_PINS=mastodon.social=<b64sha256>,bsky.app=<b64sha256>
//
// The default hook allows any host with no configured pin and enforces
// an exact match for hosts that have one. Compute a pin with:
//   openssl x509 -in leaf.pem -outform der | openssl dgst -sha256 -binary | base64

pub const PinTable = struct {
    pub const max_entries: usize = 16;
    /// base64 of a 32-byte SHA-256 is 44 chars (with '=' padding).
    pub const pin_b64_len: usize = 44;

    const Entry = struct {
        host_buf: [128]u8 = undefined,
        host_len: u8 = 0,
        pin_buf: [pin_b64_len]u8 = undefined,
        pin_len: u8 = 0,

        fn host(self: *const Entry) []const u8 {
            return self.host_buf[0..self.host_len];
        }
        fn pin(self: *const Entry) []const u8 {
            return self.pin_buf[0..self.pin_len];
        }
    };

    entries: [max_entries]Entry = undefined,
    count: u8 = 0,

    pub fn add(self: *PinTable, host: []const u8, pin_b64: []const u8) !void {
        if (self.count >= max_entries) return error.Full;
        if (host.len == 0 or host.len > 128) return error.BadHost;
        if (pin_b64.len == 0 or pin_b64.len > pin_b64_len) return error.BadPin;
        var e: Entry = .{};
        @memcpy(e.host_buf[0..host.len], host);
        e.host_len = @intCast(host.len);
        @memcpy(e.pin_buf[0..pin_b64.len], pin_b64);
        e.pin_len = @intCast(pin_b64.len);
        self.entries[self.count] = e;
        self.count += 1;
    }

    pub fn lookup(self: *const PinTable, host: []const u8) ?[]const u8 {
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            if (std.ascii.eqlIgnoreCase(self.entries[i].host(), host)) {
                return self.entries[i].pin();
            }
        }
        return null;
    }

    /// Parse `host1=pin1,host2=pin2`.
    pub fn parseEnv(self: *PinTable, env_value: []const u8) !void {
        var remaining = env_value;
        while (remaining.len > 0) {
            const comma = std.mem.indexOfScalar(u8, remaining, ',') orelse remaining.len;
            const entry = remaining[0..comma];
            remaining = if (comma < remaining.len) remaining[comma + 1 ..] else &.{};
            const eq = std.mem.indexOfScalar(u8, entry, '=') orelse continue;
            try self.add(entry[0..eq], entry[eq + 1 ..]);
        }
    }
};

var pin_table: PinTable = .{};

/// Load `TLS_PINS`-formatted pins into the global table.
pub fn loadPins(env_value: []const u8) !void {
    pin_table = .{};
    try pin_table.parseEnv(env_value);
}

/// Number of configured pins (tests / diagnostics).
pub fn pinCount() u8 {
    return pin_table.count;
}

/// Default pin hook: allow hosts with no pin; require an exact base64
/// SHA-256(leaf DER) match for hosts that have one.
pub fn defaultPinHook(host: []const u8, peer_cert_der: []const u8) bool {
    const want = pin_table.lookup(host) orelse return true;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(peer_cert_der, &digest, .{});
    var b64_buf: [PinTable.pin_b64_len]u8 = undefined;
    const got = std.base64.standard.Encoder.encode(&b64_buf, &digest);
    return std.mem.eql(u8, got, want);
}

pub fn currentPinHook() ?PinHook {
    return pin_hook;
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "C2: CertTable parseEnv round-trips a 2-entry string" {
    var t: CertTable = .{};
    try t.parseEnv("host1=/etc/ssl/cert1.pem:/etc/ssl/key1.pem,host2=/etc/ssl/cert2.pem:/etc/ssl/key2.pem");
    try testing.expectEqual(@as(u8, 2), t.count);
    const e1 = t.lookup("host1").?;
    try testing.expectEqualStrings("/etc/ssl/cert1.pem", e1.certPath());
    try testing.expectEqualStrings("/etc/ssl/key1.pem", e1.keyPath());
    try testing.expect(t.lookup("nope") == null);
}

test "C4: registerBackend stores the pointer" {
    // Don't actually allocate a backend; just toggle the pointer.
    current_backend = null;
    var dummy: ianic_inbound.IanicInboundBackend = undefined;
    registerBackend(&dummy);
    try testing.expect(current_backend != null);
    current_backend = null;
}

test "C5: PinTable parseEnv + defaultPinHook enforce exact SHA-256 match" {
    // Compute the real pin for some random cert bytes, then verify the
    // default hook accepts the match and rejects a tamper.
    var prng = std.Random.DefaultPrng.init(0x91_15_C5_01);
    const rand = prng.random();
    var der: [512]u8 = undefined;
    rand.bytes(&der);

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&der, &digest, .{});
    var pin_b64: [44]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&pin_b64, &digest);

    var env_buf: [128]u8 = undefined;
    const env = try std.fmt.bufPrint(&env_buf, "pinned.example={s}", .{pin_b64});
    try loadPins(env);
    try testing.expectEqual(@as(u8, 1), pinCount());

    // Pinned host: exact match allowed, single-bit tamper rejected.
    try testing.expect(defaultPinHook("pinned.example", &der));
    try testing.expect(defaultPinHook("PINNED.EXAMPLE", &der)); // case-insensitive host
    der[0] ^= 0x01;
    try testing.expect(!defaultPinHook("pinned.example", &der));
    der[0] ^= 0x01;

    // Unpinned host: always allowed (pinning is opt-in).
    try testing.expect(defaultPinHook("other.example", &der));

    // Reset global state for other tests.
    try loadPins("");
    try testing.expectEqual(@as(u8, 0), pinCount());
}

test "C5: setPinHook + currentPinHook round-trips" {
    pin_hook = null;
    const Hook = struct {
        fn check(_: []const u8, _: []const u8) bool {
            return true;
        }
    };
    setPinHook(Hook.check);
    try testing.expect(currentPinHook() != null);
    pin_hook = null;
}
