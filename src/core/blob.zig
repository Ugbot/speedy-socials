//! Blob storage — pluggable backend for media + atproto blob payloads.
//!
//! Two impls land here:
//!   * `FsStore`     — POSIX filesystem rooted at `MEDIA_ROOT`.
//!                     Default for single-node deployments.
//!   * `MemoryStore` — in-process map. Tests + ephemeral mode.
//!
//! S3 / GCS adapters drop in by implementing the `Store` vtable —
//! they live outside this file when added.
//!
//! Blob CIDs follow the AT Protocol convention: CIDv1 raw codec
//! (0x55) sha2-256. Encoding lives in `protocols/atproto/cid.zig`;
//! callers pass an already-encoded CID string to `put`/`get` (the
//! store doesn't enforce hash matching — it's content-addressed
//! storage, the caller is responsible for the address).

const std = @import("std");
const builtin = @import("builtin");
const assertLe = @import("assert.zig").assertLe;

/// Maximum CID string length we accept. The CIDv1 base32 form is
/// 59 bytes; we cap at 80 for forward-compat.
pub const max_cid_bytes: usize = 80;

pub const Error = error{
    NotFound,
    BufferTooSmall,
    BackendFailed,
    InvalidCid,
    /// Backend ran out of capacity (disk full, S3 quota, etc.).
    OutOfSpace,
};

pub const Store = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Write `bytes` under `cid`. Idempotent: writing the same
        /// CID twice is allowed and a no-op on the second call.
        put: *const fn (ptr: *anyopaque, cid: []const u8, bytes: []const u8) Error!void,
        /// Read into `out`. Returns the slice written.
        /// `error.NotFound` if the CID isn't known. `error.BufferTooSmall`
        /// if `out` can't hold the blob.
        get: *const fn (ptr: *anyopaque, cid: []const u8, out: []u8) Error![]const u8,
        /// Returns size in bytes if present, null if not.
        size: *const fn (ptr: *anyopaque, cid: []const u8) Error!?u64,
        /// Drop the blob. Idempotent: deleting a missing CID is OK.
        delete: *const fn (ptr: *anyopaque, cid: []const u8) Error!void,
        /// Stream blobs starting at `cursor` (empty for the start).
        /// Returns up to `max` CIDs into `out`; writes the new cursor.
        /// Returns the count.
        list: *const fn (ptr: *anyopaque, cursor: []const u8, max: u32, out: [][max_cid_bytes]u8, out_lens: []u8) Error!u32,
    };

    pub fn put(self: Store, cid: []const u8, bytes: []const u8) Error!void {
        if (cid.len == 0 or cid.len > max_cid_bytes) return error.InvalidCid;
        return self.vtable.put(self.ptr, cid, bytes);
    }

    pub fn get(self: Store, cid: []const u8, out: []u8) Error![]const u8 {
        if (cid.len == 0 or cid.len > max_cid_bytes) return error.InvalidCid;
        return self.vtable.get(self.ptr, cid, out);
    }

    pub fn size(self: Store, cid: []const u8) Error!?u64 {
        if (cid.len == 0 or cid.len > max_cid_bytes) return error.InvalidCid;
        return self.vtable.size(self.ptr, cid);
    }

    pub fn delete(self: Store, cid: []const u8) Error!void {
        if (cid.len == 0 or cid.len > max_cid_bytes) return error.InvalidCid;
        return self.vtable.delete(self.ptr, cid);
    }

    pub fn list(self: Store, cursor: []const u8, max: u32, out: [][max_cid_bytes]u8, out_lens: []u8) Error!u32 {
        return self.vtable.list(self.ptr, cursor, max, out, out_lens);
    }
};

// ──────────────────────────────────────────────────────────────────────
// MemoryStore — for tests and small ephemeral deployments.
// ──────────────────────────────────────────────────────────────────────

pub const MemoryStore = struct {
    pub const max_entries: usize = 1024;
    pub const max_blob_bytes: usize = 8 * 1024 * 1024;

    const Entry = struct {
        cid_buf: [max_cid_bytes]u8 = undefined,
        cid_len: u8 = 0,
        data: []u8,
        data_len: usize,

        fn cid(self: *const Entry) []const u8 {
            return self.cid_buf[0..self.cid_len];
        }
    };

    entries: [max_entries]Entry = undefined,
    count: u16 = 0,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) MemoryStore {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *MemoryStore) void {
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            self.allocator.free(self.entries[i].data);
        }
        self.count = 0;
    }

    fn findIndex(self: *const MemoryStore, cid: []const u8) ?usize {
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            if (std.mem.eql(u8, self.entries[i].cid(), cid)) return i;
        }
        return null;
    }

    fn doPut(ptr: *anyopaque, cid: []const u8, bytes: []const u8) Error!void {
        const self: *MemoryStore = @ptrCast(@alignCast(ptr));
        if (bytes.len > max_blob_bytes) return error.OutOfSpace;
        if (self.findIndex(cid)) |_| return; // idempotent
        if (self.count >= max_entries) return error.OutOfSpace;

        const buf = self.allocator.alloc(u8, bytes.len) catch return error.OutOfSpace;
        @memcpy(buf, bytes);

        var e: Entry = .{ .data = buf, .data_len = bytes.len };
        @memcpy(e.cid_buf[0..cid.len], cid);
        e.cid_len = @intCast(cid.len);
        self.entries[self.count] = e;
        self.count += 1;
    }

    fn doGet(ptr: *anyopaque, cid: []const u8, out: []u8) Error![]const u8 {
        const self: *MemoryStore = @ptrCast(@alignCast(ptr));
        const idx = self.findIndex(cid) orelse return error.NotFound;
        const e = &self.entries[idx];
        if (out.len < e.data_len) return error.BufferTooSmall;
        @memcpy(out[0..e.data_len], e.data[0..e.data_len]);
        return out[0..e.data_len];
    }

    fn doSize(ptr: *anyopaque, cid: []const u8) Error!?u64 {
        const self: *MemoryStore = @ptrCast(@alignCast(ptr));
        const idx = self.findIndex(cid) orelse return null;
        return @intCast(self.entries[idx].data_len);
    }

    fn doDelete(ptr: *anyopaque, cid: []const u8) Error!void {
        const self: *MemoryStore = @ptrCast(@alignCast(ptr));
        const idx = self.findIndex(cid) orelse return;
        self.allocator.free(self.entries[idx].data);
        const last = self.count - 1;
        if (idx != last) {
            self.entries[idx] = self.entries[last];
        }
        self.count = last;
    }

    fn doList(ptr: *anyopaque, cursor: []const u8, max: u32, out: [][max_cid_bytes]u8, out_lens: []u8) Error!u32 {
        const self: *MemoryStore = @ptrCast(@alignCast(ptr));
        var n: u32 = 0;
        var i: usize = 0;
        while (i < self.count and n < max and n < out.len) : (i += 1) {
            const e = &self.entries[i];
            const c = e.cid();
            if (cursor.len > 0 and std.mem.lessThan(u8, c, cursor)) continue;
            @memcpy(out[n][0..c.len], c);
            out_lens[n] = @intCast(c.len);
            n += 1;
        }
        return n;
    }

    pub fn store(self: *MemoryStore) Store {
        return .{
            .ptr = self,
            .vtable = &.{
                .put = doPut,
                .get = doGet,
                .size = doSize,
                .delete = doDelete,
                .list = doList,
            },
        };
    }
};

// ──────────────────────────────────────────────────────────────────────
// FsStore — files under a root directory, one file per CID. The
// existing media plugin uses the same pattern; this generalises it.
// ──────────────────────────────────────────────────────────────────────

pub const FsStore = struct {
    root: []const u8,

    pub fn init(root: []const u8) FsStore {
        return .{ .root = root };
    }

    fn buildPath(self: *const FsStore, cid: []const u8, out: []u8) ![]const u8 {
        return std.fmt.bufPrint(out, "{s}/{s}", .{ self.root, cid });
    }

    fn pathZ(self: *const FsStore, cid: []const u8, out: []u8) Error![*:0]const u8 {
        const written = std.fmt.bufPrint(out[0..@min(out.len, 511)], "{s}/{s}", .{ self.root, cid }) catch
            return error.BufferTooSmall;
        if (written.len + 1 > out.len) return error.BufferTooSmall;
        out[written.len] = 0;
        return @ptrCast(out.ptr);
    }

    fn doPut(ptr: *anyopaque, cid: []const u8, bytes: []const u8) Error!void {
        const self: *FsStore = @ptrCast(@alignCast(ptr));
        var path_buf: [512]u8 = undefined;
        const path_z = try self.pathZ(cid, &path_buf);

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

    fn doGet(ptr: *anyopaque, cid: []const u8, out: []u8) Error![]const u8 {
        const self: *FsStore = @ptrCast(@alignCast(ptr));
        var path_buf: [512]u8 = undefined;
        const path_z = try self.pathZ(cid, &path_buf);

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
        // Probe to detect overflow.
        var probe: [1]u8 = undefined;
        const extra = std.c.read(fd, &probe, 1);
        if (extra > 0) return error.BufferTooSmall;
        return out[0..total];
    }

    fn doSize(ptr: *anyopaque, cid: []const u8) Error!?u64 {
        const self: *FsStore = @ptrCast(@alignCast(ptr));
        var path_buf: [512]u8 = undefined;
        const path_z = try self.pathZ(cid, &path_buf);
        // Open + fstat: portable across libc flavours (avoids the
        // platform-specific stat ABI). Worst case: one open+close
        // per size query, which is fine for the low-rate paths
        // (admin tooling, GC sweeper) this is on.
        const fd = std.c.open(path_z, .{ .ACCMODE = .RDONLY }, @as(std.c.mode_t, 0));
        if (fd < 0) return null;
        defer _ = std.c.close(fd);
        // Walk to EOF via lseek(SEEK_END).
        const off = std.c.lseek(fd, 0, std.c.SEEK.END);
        if (off < 0) return error.BackendFailed;
        return @intCast(off);
    }

    fn doDelete(ptr: *anyopaque, cid: []const u8) Error!void {
        const self: *FsStore = @ptrCast(@alignCast(ptr));
        var path_buf: [512]u8 = undefined;
        const path_z = try self.pathZ(cid, &path_buf);
        _ = std.c.unlink(path_z); // missing file → benign
    }

    fn doList(ptr: *anyopaque, cursor: []const u8, max: u32, out: [][max_cid_bytes]u8, out_lens: []u8) Error!u32 {
        // Listing a real filesystem requires a directory iterator,
        // which on most OSes wants a heap allocator. Our use today
        // is "enumerate to find orphans for GC" — keep this stubbed
        // until AT-24 wires it up; the in-memory store is sufficient
        // for tests in the meantime.
        _ = ptr;
        _ = cursor;
        _ = max;
        _ = out;
        _ = out_lens;
        return 0;
    }

    pub fn store(self: *FsStore) Store {
        return .{
            .ptr = self,
            .vtable = &.{
                .put = doPut,
                .get = doGet,
                .size = doSize,
                .delete = doDelete,
                .list = doList,
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

test "MemoryStore put + get round-trip" {
    var m = MemoryStore.init(testing.allocator);
    defer m.deinit();
    const s = m.store();

    try s.put("bafkrei-cid-x", "hello world");
    var buf: [64]u8 = undefined;
    const got = try s.get("bafkrei-cid-x", &buf);
    try testing.expectEqualStrings("hello world", got);
}

test "MemoryStore put is idempotent" {
    var m = MemoryStore.init(testing.allocator);
    defer m.deinit();
    const s = m.store();
    try s.put("c", "v1");
    try s.put("c", "v1"); // same → no-op
    try testing.expectEqual(@as(u16, 1), m.count);
}

test "MemoryStore get returns NotFound for unknown CID" {
    var m = MemoryStore.init(testing.allocator);
    defer m.deinit();
    const s = m.store();
    var buf: [4]u8 = undefined;
    try testing.expectError(error.NotFound, s.get("nope", &buf));
}

test "MemoryStore size reports null for missing CID" {
    var m = MemoryStore.init(testing.allocator);
    defer m.deinit();
    const s = m.store();
    try testing.expect((try s.size("absent")) == null);
    try s.put("present", "data");
    try testing.expectEqual(@as(?u64, 4), try s.size("present"));
}

test "MemoryStore delete drops the entry" {
    var m = MemoryStore.init(testing.allocator);
    defer m.deinit();
    const s = m.store();
    try s.put("c", "v");
    try s.delete("c");
    try testing.expectEqual(@as(u16, 0), m.count);
    try s.delete("c"); // idempotent
}

test "MemoryStore get respects BufferTooSmall" {
    var m = MemoryStore.init(testing.allocator);
    defer m.deinit();
    const s = m.store();
    try s.put("c", "a long blob payload");
    var tiny: [4]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, s.get("c", &tiny));
}

test "Store rejects invalid CID lengths" {
    var m = MemoryStore.init(testing.allocator);
    defer m.deinit();
    const s = m.store();
    try testing.expectError(error.InvalidCid, s.put("", "x"));
    var buf: [4]u8 = undefined;
    try testing.expectError(error.InvalidCid, s.get("", &buf));
}

test "global store set/get/reset" {
    resetGlobal();
    try testing.expect(global() == null);
    var m = MemoryStore.init(testing.allocator);
    defer m.deinit();
    setGlobal(m.store());
    try testing.expect(global() != null);
    resetGlobal();
}
