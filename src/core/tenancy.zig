//! Op-F / H1+H2+H3: multi-tenancy.
//!
//! Maps incoming Host headers to a tenant id. Plugin code that
//! issues storage queries reads the current tenant from
//! `core.tenancy.current()` (typically scoped via a thread-local
//! during request handling) and includes the id in every
//! tenant-scoped table.
//!
//! Today the binding is:
//!   * one-process / one-tenant: the default tenant id `""` covers
//!     every request when no mapping is configured.
//!   * static mapping via env (`TENANTS=host1=t1,host2=t2`).
//!   * lifecycle routes (H3) flip tenants between `active` /
//!     `suspended` / `deleted` states; suspended tenants get 503 on
//!     every request, deleted ones get 404.
//!
//! Tiger Style: fixed-size lookup table (16 tenants), no allocator
//! at request time, atomic state transitions.

const std = @import("std");

pub const max_tenants: usize = 16;
pub const max_id_bytes: usize = 32;
pub const max_host_bytes: usize = 128;

pub const State = enum(u8) {
    active,
    suspended,
    deleted,

    pub fn fromString(s: []const u8) State {
        if (std.mem.eql(u8, s, "suspended")) return .suspended;
        if (std.mem.eql(u8, s, "deleted")) return .deleted;
        return .active;
    }

    pub fn toString(self: State) []const u8 {
        return switch (self) {
            .active => "active",
            .suspended => "suspended",
            .deleted => "deleted",
        };
    }
};

pub const Tenant = struct {
    id_buf: [max_id_bytes]u8 = undefined,
    id_len: u8 = 0,
    host_buf: [max_host_bytes]u8 = undefined,
    host_len: u8 = 0,
    state: State = .active,

    pub fn id(self: *const Tenant) []const u8 {
        return self.id_buf[0..self.id_len];
    }
    pub fn host(self: *const Tenant) []const u8 {
        return self.host_buf[0..self.host_len];
    }
};

pub const Table = struct {
    items: [max_tenants]Tenant = undefined,
    count: u8 = 0,

    pub fn init() Table {
        return .{};
    }

    pub fn add(self: *Table, host: []const u8, id: []const u8) !void {
        if (self.count >= max_tenants) return error.Full;
        if (host.len > max_host_bytes or id.len > max_id_bytes) return error.TooLong;
        var t: Tenant = .{};
        @memcpy(t.host_buf[0..host.len], host);
        t.host_len = @intCast(host.len);
        @memcpy(t.id_buf[0..id.len], id);
        t.id_len = @intCast(id.len);
        self.items[self.count] = t;
        self.count += 1;
    }

    pub fn lookupByHost(self: *const Table, host: []const u8) ?*const Tenant {
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            if (std.mem.eql(u8, self.items[i].host(), host)) return &self.items[i];
        }
        return null;
    }

    pub fn lookupById(self: *Table, id: []const u8) ?*Tenant {
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            if (std.mem.eql(u8, self.items[i].id(), id)) return &self.items[i];
        }
        return null;
    }

    pub fn setState(self: *Table, id: []const u8, new_state: State) !void {
        const t = self.lookupById(id) orelse return error.NotFound;
        t.state = new_state;
    }

    pub fn parseEnv(self: *Table, env_value: []const u8) !void {
        // Format: `host1=tenant1,host2=tenant2`.
        var rem = env_value;
        while (rem.len > 0) {
            const comma = std.mem.indexOfScalar(u8, rem, ',') orelse rem.len;
            const entry = rem[0..comma];
            rem = if (comma < rem.len) rem[comma + 1 ..] else &.{};
            const eq = std.mem.indexOfScalar(u8, entry, '=') orelse continue;
            try self.add(entry[0..eq], entry[eq + 1 ..]);
        }
    }
};

// ──────────────────────────────────────────────────────────────────────
// Process-wide table + the current per-request tenant.
// ──────────────────────────────────────────────────────────────────────

var global_table: Table = .{};
threadlocal var current_id_buf: [max_id_bytes]u8 = undefined;
threadlocal var current_id_len: u8 = 0;

pub fn globalTable() *Table {
    return &global_table;
}

pub fn setGlobalTable(t: Table) void {
    global_table = t;
}

/// Set the current per-request tenant id. The server's dispatcher
/// calls this before handing the request to a plugin.
pub fn setCurrent(id: []const u8) void {
    const n = @min(id.len, max_id_bytes);
    @memcpy(current_id_buf[0..n], id[0..n]);
    current_id_len = @intCast(n);
}

pub fn current() []const u8 {
    return current_id_buf[0..current_id_len];
}

pub fn resetCurrent() void {
    current_id_len = 0;
}

/// Resolve the tenant for an incoming Host header. Falls back to
/// the default empty tenant when no match.
pub fn resolveTenant(host_header: []const u8) State {
    if (global_table.count == 0) return .active;
    // Strip optional port suffix.
    const colon = std.mem.indexOfScalar(u8, host_header, ':');
    const host = if (colon) |p| host_header[0..p] else host_header;
    if (global_table.lookupByHost(host)) |t| {
        setCurrent(t.id());
        return t.state;
    }
    // Unknown host → default tenant, active.
    return .active;
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "H1: tenant lookup by host" {
    var t: Table = .{};
    try t.add("a.example", "tenant-a");
    try t.add("b.example", "tenant-b");
    try testing.expectEqualStrings("tenant-a", t.lookupByHost("a.example").?.id());
    try testing.expectEqualStrings("tenant-b", t.lookupByHost("b.example").?.id());
    try testing.expect(t.lookupByHost("c.example") == null);
}

test "H1: parseEnv populates the table" {
    var t: Table = .{};
    try t.parseEnv("host1=t1,host2=t2,host3=t3");
    try testing.expectEqual(@as(u8, 3), t.count);
    try testing.expectEqualStrings("t2", t.lookupByHost("host2").?.id());
}

test "H2: setCurrent / current round-trips" {
    setCurrent("alice");
    try testing.expectEqualStrings("alice", current());
    resetCurrent();
    try testing.expectEqualStrings("", current());
}

test "H3: setState transitions" {
    var t: Table = .{};
    try t.add("h", "x");
    try t.setState("x", .suspended);
    try testing.expectEqual(State.suspended, t.lookupById("x").?.state);
    try t.setState("x", .active);
    try testing.expectEqual(State.active, t.lookupById("x").?.state);
}

test "Op-F: resolveTenant returns active when no table configured" {
    global_table = .{};
    try testing.expectEqual(State.active, resolveTenant("anywhere.example"));
}

test "Op-F: resolveTenant honours table state" {
    global_table = .{};
    try global_table.add("blocked.example", "blocked-tenant");
    try global_table.setState("blocked-tenant", .suspended);
    const state = resolveTenant("blocked.example");
    try testing.expectEqual(State.suspended, state);
    try testing.expectEqualStrings("blocked-tenant", current());
    resetCurrent();
    global_table = .{};
}