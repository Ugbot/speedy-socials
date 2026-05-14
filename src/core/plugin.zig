//! Plugin contract — the core's only knowledge of any protocol.
//!
//! Plugins implement this struct and hand a `Plugin` value to
//! `core.registry.register`. Each capability (routes, schema, ws, jobs,
//! metrics, signature verification, inbox dispatch) is optional.
//!
//! Tiger Style: plugins do not receive an allocator handle. They get a
//! `*Context` for cross-cutting infrastructure (clock, rng, storage,
//! worker pool, log) and a per-operation arena via the handler context.

const std = @import("std");
const limits = @import("limits.zig");
const errors = @import("errors.zig");
const PluginError = errors.PluginError;
const Router = @import("http/router.zig").Router;
const Clock = @import("clock.zig").Clock;
const Rng = @import("rng.zig").Rng;
const storage_mod = @import("storage.zig");
const Schema = storage_mod.Schema;
const Handle = storage_mod.Handle;
const assert_mod = @import("assert.zig");
const assert = assert_mod.assert;
const assertLe = assert_mod.assertLe;

/// Bumped whenever the Plugin struct adds or rearranges fields in a way
/// that would break ABI / API compatibility. Plugins record the version
/// they were built against; the registry refuses mismatches.
pub const plugin_abi_version: u32 = 2;

/// Cross-cutting handles plugins use at runtime. Stable references —
/// the registry passes the same pointer to every hook.
pub const Context = struct {
    clock: Clock,
    rng: *Rng,
    /// Storage handle wired in Phase 2. Null only during early
    /// bootstrapping (between core.init and storage subsystem start).
    storage: ?*Handle = null,
    // Logger wired in Phase 7 (core/log.zig); until then plugins use
    // std.log directly.
    userdata: ?*anyopaque = null,
};

pub const Plugin = struct {
    /// ABI version this plugin was built against. Must equal
    /// `plugin_abi_version` at registration time.
    abi: u32 = plugin_abi_version,

    /// Plugin identity. `name` is also the key used by other plugins
    /// to look us up via `Registry.find` (only `relay/` should do that).
    name: []const u8,
    version: u32,

    /// Plugin-private state pointer threaded through every callback.
    state: ?*anyopaque = null,

    init: *const fn (state: ?*anyopaque, ctx: *Context) anyerror!void,
    deinit: *const fn (state: ?*anyopaque, ctx: *Context) void,

    register_routes: ?*const fn (state: ?*anyopaque, ctx: *Context, router: *Router, plugin_index: u16) anyerror!void = null,

    /// Called once at boot before migrations run. Plugins push their
    /// `Migration` entries into the shared `Schema`. Phase 2.
    register_schema: ?*const fn (state: ?*anyopaque, ctx: *Context, schema: *Schema) anyerror!void = null,

    // register_ws, register_jobs, register_metrics added when the
    // corresponding subsystems land in later phases.
};

pub const Registry = struct {
    entries: [limits.max_plugins]Plugin = undefined,
    count: u16 = 0,
    initialized: bool = false,

    pub fn init() Registry {
        return .{};
    }

    pub fn register(self: *Registry, plugin: Plugin) PluginError!u16 {
        if (self.initialized) return error.AlreadyInitialized;
        if (self.count >= limits.max_plugins) return error.TooManyPlugins;
        if (plugin.abi != plugin_abi_version) return error.VersionMismatch;
        if (plugin.name.len == 0 or plugin.name.len > limits.max_plugin_name_bytes) {
            return error.NameTooLong;
        }
        var i: u16 = 0;
        while (i < self.count) : (i += 1) {
            if (std.mem.eql(u8, self.entries[i].name, plugin.name)) return error.DuplicateName;
        }
        const idx = self.count;
        self.entries[idx] = plugin;
        self.count += 1;
        assertLe(@as(u32, self.count), limits.max_plugins);
        return idx;
    }

    /// Run init on every registered plugin, in registration order.
    pub fn initAll(self: *Registry, ctx: *Context) !void {
        assert(!self.initialized);
        var i: u16 = 0;
        while (i < self.count) : (i += 1) {
            try self.entries[i].init(self.entries[i].state, ctx);
        }
        self.initialized = true;
    }

    pub fn deinitAll(self: *Registry, ctx: *Context) void {
        assert(self.initialized);
        var i: i32 = @as(i32, @intCast(self.count)) - 1;
        while (i >= 0) : (i -= 1) {
            const e = self.entries[@as(usize, @intCast(i))];
            e.deinit(e.state, ctx);
        }
        self.initialized = false;
    }

    pub fn registerAllSchemas(self: *Registry, ctx: *Context, schema: *Schema) !void {
        var i: u16 = 0;
        while (i < self.count) : (i += 1) {
            const e = self.entries[i];
            if (e.register_schema) |hook| {
                try hook(e.state, ctx, schema);
            }
        }
    }

    pub fn registerAllRoutes(self: *Registry, ctx: *Context, router: *Router) !void {
        var i: u16 = 0;
        while (i < self.count) : (i += 1) {
            const e = self.entries[i];
            if (e.register_routes) |hook| {
                try hook(e.state, ctx, router, i);
            }
        }
        router.freeze();
    }

    pub fn find(self: *const Registry, name: []const u8) ?*const Plugin {
        var i: u16 = 0;
        while (i < self.count) : (i += 1) {
            if (std.mem.eql(u8, self.entries[i].name, name)) return &self.entries[i];
        }
        return null;
    }
};

test "Registry registers + initializes plugins in order" {
    const S = struct {
        var init_calls: [4]u8 = .{ 0, 0, 0, 0 };

        fn initA(_: ?*anyopaque, _: *Context) !void {
            init_calls[0] = 1;
        }
        fn initB(_: ?*anyopaque, _: *Context) !void {
            init_calls[1] = 1;
        }
        fn deinitA(_: ?*anyopaque, _: *Context) void {
            init_calls[2] = 1;
        }
        fn deinitB(_: ?*anyopaque, _: *Context) void {
            init_calls[3] = 1;
        }
    };

    var rng = Rng.init(0xdeadbeef);
    var sim_clock = @import("clock.zig").SimClock.init(0);
    var ctx: Context = .{ .clock = sim_clock.clock(), .rng = &rng };

    var reg = Registry.init();
    _ = try reg.register(.{
        .name = "a",
        .version = 1,
        .init = S.initA,
        .deinit = S.deinitA,
    });
    _ = try reg.register(.{
        .name = "b",
        .version = 1,
        .init = S.initB,
        .deinit = S.deinitB,
    });

    try reg.initAll(&ctx);
    try std.testing.expect(S.init_calls[0] == 1 and S.init_calls[1] == 1);
    reg.deinitAll(&ctx);
    try std.testing.expect(S.init_calls[2] == 1 and S.init_calls[3] == 1);
}

test "Registry rejects duplicate plugin name" {
    const S = struct {
        fn nop(_: ?*anyopaque, _: *Context) !void {}
        fn nopd(_: ?*anyopaque, _: *Context) void {}
    };
    var reg = Registry.init();
    _ = try reg.register(.{ .name = "a", .version = 1, .init = S.nop, .deinit = S.nopd });
    try std.testing.expectError(error.DuplicateName, reg.register(.{
        .name = "a",
        .version = 1,
        .init = S.nop,
        .deinit = S.nopd,
    }));
}

test "Registry rejects ABI mismatch" {
    const S = struct {
        fn nop(_: ?*anyopaque, _: *Context) !void {}
        fn nopd(_: ?*anyopaque, _: *Context) void {}
    };
    var reg = Registry.init();
    try std.testing.expectError(error.VersionMismatch, reg.register(.{
        .abi = plugin_abi_version + 99,
        .name = "weird",
        .version = 1,
        .init = S.nop,
        .deinit = S.nopd,
    }));
}
