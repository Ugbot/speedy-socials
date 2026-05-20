//! Secret / key store — pluggable interface for cryptographic keys
//! and other small confidential values.
//!
//! Today this is used by:
//!   * AT-1 OAuth signing keys (when AT-1 lands)
//!   * AT-19 PLC rotation keys (when AT-19 lands)
//!   * AP RSA actor keys (existing, in ap_actor_keys table — could
//!     migrate to here, but the per-actor key is also DB-row
//!     scoped so it stays in the DB)
//!
//! Three impls:
//!   * `EnvStore`    — read-only; lookups map to env vars
//!                     (`SECRETS_<NAME>`). Useful for k8s secret mounts.
//!   * `FileStore`   — one file per secret under `SECRETS_DIR`, 0600
//!                     perms.
//!   * `MemoryStore` — in-process map; tests + ephemeral runs.

const std = @import("std");
const assertLe = @import("assert.zig").assertLe;

pub const max_name_bytes: usize = 64;
pub const max_value_bytes: usize = 4096;

pub const Error = error{
    NotFound,
    BufferTooSmall,
    InvalidName,
    BackendFailed,
    AccessDenied,
};

pub const Store = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        get: *const fn (ptr: *anyopaque, name: []const u8, out: []u8) Error![]const u8,
        put: *const fn (ptr: *anyopaque, name: []const u8, bytes: []const u8) Error!void,
        delete: *const fn (ptr: *anyopaque, name: []const u8) Error!void,
        exists: *const fn (ptr: *anyopaque, name: []const u8) Error!bool,
    };

    pub fn get(self: Store, name: []const u8, out: []u8) Error![]const u8 {
        if (!validName(name)) return error.InvalidName;
        return self.vtable.get(self.ptr, name, out);
    }

    pub fn put(self: Store, name: []const u8, bytes: []const u8) Error!void {
        if (!validName(name)) return error.InvalidName;
        if (bytes.len > max_value_bytes) return error.InvalidName;
        return self.vtable.put(self.ptr, name, bytes);
    }

    pub fn delete(self: Store, name: []const u8) Error!void {
        if (!validName(name)) return error.InvalidName;
        return self.vtable.delete(self.ptr, name);
    }

    pub fn exists(self: Store, name: []const u8) Error!bool {
        if (!validName(name)) return error.InvalidName;
        return self.vtable.exists(self.ptr, name);
    }
};

/// Names are ASCII identifiers — letters, digits, underscore, dash.
/// No `.`, no `/`, no spaces. Keeps filesystem + env mappings sane.
fn validName(name: []const u8) bool {
    if (name.len == 0 or name.len > max_name_bytes) return false;
    for (name) |b| {
        const ok = (b >= 'a' and b <= 'z') or
            (b >= 'A' and b <= 'Z') or
            (b >= '0' and b <= '9') or
            b == '_' or b == '-';
        if (!ok) return false;
    }
    return true;
}

// ──────────────────────────────────────────────────────────────────────
// MemoryStore — for tests.
// ──────────────────────────────────────────────────────────────────────

pub const MemoryStore = struct {
    pub const max_entries: usize = 64;

    const Entry = struct {
        name_buf: [max_name_bytes]u8 = undefined,
        name_len: u8 = 0,
        value_buf: [max_value_bytes]u8 = undefined,
        value_len: u16 = 0,

        fn name(self: *const Entry) []const u8 {
            return self.name_buf[0..self.name_len];
        }
    };

    entries: [max_entries]Entry = undefined,
    count: u8 = 0,

    pub fn init() MemoryStore {
        return .{};
    }

    fn find(self: *const MemoryStore, name: []const u8) ?usize {
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            if (std.mem.eql(u8, self.entries[i].name(), name)) return i;
        }
        return null;
    }

    fn doGet(ptr: *anyopaque, name: []const u8, out: []u8) Error![]const u8 {
        const self: *MemoryStore = @ptrCast(@alignCast(ptr));
        const idx = self.find(name) orelse return error.NotFound;
        const e = &self.entries[idx];
        if (out.len < e.value_len) return error.BufferTooSmall;
        @memcpy(out[0..e.value_len], e.value_buf[0..e.value_len]);
        return out[0..e.value_len];
    }

    fn doPut(ptr: *anyopaque, name: []const u8, bytes: []const u8) Error!void {
        const self: *MemoryStore = @ptrCast(@alignCast(ptr));
        const existing = self.find(name);
        if (existing == null and self.count >= max_entries) return error.BackendFailed;
        const idx = existing orelse blk: {
            const i = self.count;
            self.count += 1;
            self.entries[i] = .{};
            @memcpy(self.entries[i].name_buf[0..name.len], name);
            self.entries[i].name_len = @intCast(name.len);
            break :blk i;
        };
        @memcpy(self.entries[idx].value_buf[0..bytes.len], bytes);
        self.entries[idx].value_len = @intCast(bytes.len);
    }

    fn doDelete(ptr: *anyopaque, name: []const u8) Error!void {
        const self: *MemoryStore = @ptrCast(@alignCast(ptr));
        const idx = self.find(name) orelse return;
        const last = self.count - 1;
        if (idx != last) {
            self.entries[idx] = self.entries[last];
        }
        self.count = last;
    }

    fn doExists(ptr: *anyopaque, name: []const u8) Error!bool {
        const self: *MemoryStore = @ptrCast(@alignCast(ptr));
        return self.find(name) != null;
    }

    pub fn store(self: *MemoryStore) Store {
        return .{
            .ptr = self,
            .vtable = &.{
                .get = doGet,
                .put = doPut,
                .delete = doDelete,
                .exists = doExists,
            },
        };
    }
};

// ──────────────────────────────────────────────────────────────────────
// FileStore — one file per secret under a root dir, 0600.
// ──────────────────────────────────────────────────────────────────────

pub const FileStore = struct {
    root: []const u8,

    pub fn init(root: []const u8) FileStore {
        return .{ .root = root };
    }

    fn pathZ(self: *const FileStore, name: []const u8, out: []u8) Error![*:0]const u8 {
        const written = std.fmt.bufPrint(out[0..@min(out.len, 511)], "{s}/{s}", .{ self.root, name }) catch
            return error.BackendFailed;
        if (written.len + 1 > out.len) return error.BackendFailed;
        out[written.len] = 0;
        return @ptrCast(out.ptr);
    }

    fn doGet(ptr: *anyopaque, name: []const u8, out: []u8) Error![]const u8 {
        const self: *FileStore = @ptrCast(@alignCast(ptr));
        var path_buf: [512]u8 = undefined;
        const path_z = try self.pathZ(name, &path_buf);
        const fd = std.c.open(path_z, .{ .ACCMODE = .RDONLY }, @as(std.c.mode_t, 0));
        if (fd < 0) return error.NotFound;
        defer _ = std.c.close(fd);

        var total: usize = 0;
        while (total < out.len) {
            const want = out.len - total;
            const got = std.c.read(fd, out.ptr + total, want);
            if (got < 0) return error.BackendFailed;
            if (got == 0) break;
            total += @intCast(got);
        }
        var probe: [1]u8 = undefined;
        const extra = std.c.read(fd, &probe, 1);
        if (extra > 0) return error.BufferTooSmall;
        return out[0..total];
    }

    fn doPut(ptr: *anyopaque, name: []const u8, bytes: []const u8) Error!void {
        const self: *FileStore = @ptrCast(@alignCast(ptr));
        var path_buf: [512]u8 = undefined;
        const path_z = try self.pathZ(name, &path_buf);
        const fd = std.c.open(path_z, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, @as(std.c.mode_t, 0o600));
        if (fd < 0) return error.BackendFailed;
        defer _ = std.c.close(fd);
        var written: usize = 0;
        while (written < bytes.len) {
            const want = bytes.len - written;
            const got = std.c.write(fd, bytes.ptr + written, want);
            if (got <= 0) return error.BackendFailed;
            written += @intCast(got);
        }
    }

    fn doDelete(ptr: *anyopaque, name: []const u8) Error!void {
        const self: *FileStore = @ptrCast(@alignCast(ptr));
        var path_buf: [512]u8 = undefined;
        const path_z = try self.pathZ(name, &path_buf);
        _ = std.c.unlink(path_z);
    }

    fn doExists(ptr: *anyopaque, name: []const u8) Error!bool {
        const self: *FileStore = @ptrCast(@alignCast(ptr));
        var path_buf: [512]u8 = undefined;
        const path_z = try self.pathZ(name, &path_buf);
        const F_OK: c_uint = 0;
        return std.c.access(path_z, F_OK) == 0;
    }

    pub fn store(self: *FileStore) Store {
        return .{
            .ptr = self,
            .vtable = &.{
                .get = doGet,
                .put = doPut,
                .delete = doDelete,
                .exists = doExists,
            },
        };
    }
};

// ──────────────────────────────────────────────────────────────────────
// Module-level singleton.
// ──────────────────────────────────────────────────────────────────────

var global_store: ?Store = null;

pub fn setGlobal(s: Store) void {
    global_store = s;
}

pub fn global() ?Store {
    return global_store;
}

pub fn resetGlobal() void {
    global_store = null;
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "MemoryStore round-trip" {
    var m = MemoryStore.init();
    const s = m.store();
    try s.put("jwt_key", "abc123");
    var buf: [32]u8 = undefined;
    const got = try s.get("jwt_key", &buf);
    try testing.expectEqualStrings("abc123", got);
}

test "MemoryStore overwrite" {
    var m = MemoryStore.init();
    const s = m.store();
    try s.put("k", "v1");
    try s.put("k", "v2");
    var buf: [8]u8 = undefined;
    const got = try s.get("k", &buf);
    try testing.expectEqualStrings("v2", got);
}

test "MemoryStore missing returns NotFound" {
    var m = MemoryStore.init();
    const s = m.store();
    var buf: [8]u8 = undefined;
    try testing.expectError(error.NotFound, s.get("nope", &buf));
}

test "MemoryStore exists + delete" {
    var m = MemoryStore.init();
    const s = m.store();
    try testing.expect(!try s.exists("k"));
    try s.put("k", "v");
    try testing.expect(try s.exists("k"));
    try s.delete("k");
    try testing.expect(!try s.exists("k"));
}

test "Store rejects invalid names" {
    var m = MemoryStore.init();
    const s = m.store();
    try testing.expectError(error.InvalidName, s.put("with space", "v"));
    try testing.expectError(error.InvalidName, s.put("", "v"));
    try testing.expectError(error.InvalidName, s.put("path/traversal", "v"));
}
