//! F3 — JSON config file loader.
//!
//! Boot reads `--config /path/to/config.json` (or `CONFIG_PATH`
//! env) and sets process env-vars from the file for every key the
//! existing env-driven boot logic already understands. CLI flags
//! win over env over file (config file is the *floor*).
//!
//! File shape (all keys optional):
//!
//! ```json
//! {
//!   "tls_cert_path": "/etc/speedy/tls/cert.pem",
//!   "tls_key_path":  "/etc/speedy/tls/key.pem",
//!   "media_root":    "/var/lib/speedy/media",
//!   "shutdown_grace_ms": 15000,
//!   "rate_limit": "60:30",
//!   "strict_http_sig": true,
//!   "relay_bridge_ap_target": "https://peer/inbox",
//!   "relay_synthetic_key_pepper": "32-byte-secret",
//!   "relay_outbox_backpressure_cap": 10000
//! }
//! ```
//!
//! We use plain-old `setenv` so the rest of the boot path doesn't
//! need to change — each subsystem still reads via `std.c.getenv`.
//! Tiger Style: bounded, no allocator outside boot.

const std = @import("std");

pub const Error = error{
    FileOpenFailed,
    FileReadFailed,
    FileTooLarge,
    MalformedJson,
};

pub const max_config_bytes: usize = 64 * 1024;

const known_keys = [_][]const u8{
    "tls_cert_path",
    "tls_key_path",
    "media_root",
    "shutdown_grace_ms",
    "rate_limit",
    "strict_http_sig",
    "relay_bridge_ap_target",
    "relay_synthetic_key_pepper",
    "relay_outbox_backpressure_cap",
    "db_path",
};

/// Read `path`, parse each known key, and call `setenv` so the
/// existing env-driven boot wiring picks it up. Keys already set
/// in the process env are NOT overwritten — CLI flags / shell env
/// win.
pub fn loadFromFile(path: []const u8) Error!void {
    var path_buf: [512]u8 = undefined;
    if (path.len + 1 > path_buf.len) return error.FileOpenFailed;
    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;
    const path_z: [*:0]const u8 = @ptrCast(&path_buf);

    const fd = std.c.open(path_z, .{ .ACCMODE = .RDONLY }, @as(std.c.mode_t, 0));
    if (fd < 0) return error.FileOpenFailed;
    defer _ = std.c.close(fd);

    var body: [max_config_bytes]u8 = undefined;
    var total: usize = 0;
    while (total < body.len) {
        const got = std.c.read(fd, body[total..].ptr, body.len - total);
        if (got < 0) return error.FileReadFailed;
        if (got == 0) break;
        total += @intCast(got);
    }
    if (total == body.len) {
        const peek = std.c.read(fd, &[_]u8{0}, 1);
        if (peek > 0) return error.FileTooLarge;
    }
    try applyJson(body[0..total]);
}

fn applyJson(json: []const u8) Error!void {
    for (known_keys) |key| {
        const maybe_value = extractKey(json, key);
        if (maybe_value) |raw| {
            // Decoded values land in a temporary stack buffer; we
            // pass NUL-terminated strings to `setenv` so the libc
            // owns its copy.
            var val_buf: [1024]u8 = undefined;
            const v = decode(raw, &val_buf);
            if (v.len == 0) continue;

            var env_key_buf: [64]u8 = undefined;
            if (key.len >= env_key_buf.len) continue;
            const env_key = upperCopy(key, &env_key_buf);
            var env_key_z_buf: [65]u8 = undefined;
            @memcpy(env_key_z_buf[0..env_key.len], env_key);
            env_key_z_buf[env_key.len] = 0;
            const env_key_z: [*:0]const u8 = @ptrCast(&env_key_z_buf);

            var val_z_buf: [1025]u8 = undefined;
            if (v.len >= val_z_buf.len) continue;
            @memcpy(val_z_buf[0..v.len], v);
            val_z_buf[v.len] = 0;
            const val_z: [*:0]const u8 = @ptrCast(&val_z_buf);

            // overwrite=0 → don't replace if already in env
            _ = setenv(env_key_z, val_z, 0);
        }
    }
}

extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;

fn extractKey(json: []const u8, key: []const u8) ?[]const u8 {
    var needle_buf: [128]u8 = undefined;
    if (key.len + 2 > needle_buf.len) return null;
    needle_buf[0] = '"';
    @memcpy(needle_buf[1..][0..key.len], key);
    needle_buf[1 + key.len] = '"';
    const needle = needle_buf[0 .. 2 + key.len];
    const idx = std.mem.indexOf(u8, json, needle) orelse return null;
    var i = idx + needle.len;
    while (i < json.len and (json[i] == ' ' or json[i] == '\t' or json[i] == ':')) : (i += 1) {}
    if (i >= json.len) return null;
    if (json[i] == '"') {
        i += 1;
        const start = i;
        while (i < json.len and json[i] != '"') : (i += 1) {
            if (json[i] == '\\' and i + 1 < json.len) i += 1;
        }
        return json[start..i];
    }
    // Bare token (number, true, false). Read until comma / brace / whitespace.
    const start = i;
    while (i < json.len) : (i += 1) {
        const ch = json[i];
        if (ch == ',' or ch == '}' or ch == ' ' or ch == '\t' or ch == '\n' or ch == '\r') break;
    }
    return json[start..i];
}

fn decode(raw: []const u8, out: []u8) []const u8 {
    // For "true"/"false" we map to "1"/"0" for env consumers.
    if (std.mem.eql(u8, raw, "true")) return setBuf(out, "1");
    if (std.mem.eql(u8, raw, "false")) return setBuf(out, "0");
    // Strip simple escapes \" \\ \n. Anything else passes through.
    var w: usize = 0;
    var i: usize = 0;
    while (i < raw.len and w < out.len) {
        if (raw[i] == '\\' and i + 1 < raw.len) {
            switch (raw[i + 1]) {
                '"' => out[w] = '"',
                '\\' => out[w] = '\\',
                'n' => out[w] = '\n',
                else => out[w] = raw[i + 1],
            }
            w += 1;
            i += 2;
            continue;
        }
        out[w] = raw[i];
        w += 1;
        i += 1;
    }
    return out[0..w];
}

fn setBuf(out: []u8, src: []const u8) []const u8 {
    const n = @min(src.len, out.len);
    @memcpy(out[0..n], src[0..n]);
    return out[0..n];
}

fn upperCopy(src: []const u8, out: []u8) []const u8 {
    var i: usize = 0;
    while (i < src.len and i < out.len) : (i += 1) {
        out[i] = std.ascii.toUpper(src[i]);
    }
    return out[0..i];
}

// ── Tests ─────────────────────────────────────────────────────────

const testing = std.testing;

test "extractKey: string + number + bool" {
    const json = "{\"tls_cert_path\":\"/etc/foo\",\"shutdown_grace_ms\":15000,\"strict_http_sig\":true}";
    try testing.expectEqualStrings("/etc/foo", extractKey(json, "tls_cert_path").?);
    try testing.expectEqualStrings("15000", extractKey(json, "shutdown_grace_ms").?);
    try testing.expectEqualStrings("true", extractKey(json, "strict_http_sig").?);
    try testing.expectEqual(@as(?[]const u8, null), extractKey(json, "missing"));
}

test "decode: true → 1, false → 0, plain passthrough, escape stripping" {
    var buf: [32]u8 = undefined;
    try testing.expectEqualStrings("1", decode("true", &buf));
    try testing.expectEqualStrings("0", decode("false", &buf));
    try testing.expectEqualStrings("hello", decode("hello", &buf));
    try testing.expectEqualStrings("a\"b", decode("a\\\"b", &buf));
}

test "upperCopy maps keys to env-var names" {
    var buf: [32]u8 = undefined;
    try testing.expectEqualStrings("TLS_CERT_PATH", upperCopy("tls_cert_path", &buf));
}
