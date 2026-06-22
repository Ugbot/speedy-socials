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
const WsUpgradeRouter = @import("ws/upgrade_router.zig").WsUpgradeRouter;
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

    /// Optional: register WebSocket upgrade routes. Plugins use this to
    /// own a path's upgrade handshake + frame codec (AT subscribeRepos,
    /// Mastodon streaming, future bridges). The hook is additive and
    /// optional — its presence does not bump `plugin_abi_version`.
    /// Patterns follow the same syntax as the HTTP router.
    register_ws_upgrade: ?*const fn (state: ?*anyopaque, ctx: *Context, router: *WsUpgradeRouter, plugin_index: u16) anyerror!void = null,

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

    /// Invoke every plugin's optional `register_ws_upgrade` hook and
    /// freeze the upgrade router. Boot must call this before the server
    /// starts accepting; the server treats the router as read-only.
    pub fn registerAllWsUpgrades(self: *Registry, ctx: *Context, router: *WsUpgradeRouter) !void {
        var i: u16 = 0;
        while (i < self.count) : (i += 1) {
            const e = self.entries[i];
            if (e.register_ws_upgrade) |hook| {
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

// ──────────────────────────────────────────────────────────────────────
// C2 / H1: per-vhost (per-tenant) plugin-registry isolation.
//
// The route TABLE is shared — every tenant exposes the same paths — so
// the `Router` stays global. What we isolate is the plugin *state* the
// handlers consult: each tenant can be bound to its own `Registry`, and
// thus to its own set of `Plugin.state` pointers (and the relay's
// `find` view of its siblings).
//
// The default tenant (empty id "") ALWAYS resolves to the shared
// default registry — the one boot already builds and wires into routes.
// A single-tenant deployment never touches the override table, never
// stamps a thread-local, and observes exactly the previous behavior.
//
// Tiger Style: fixed-size override table, linear scan, no allocation at
// request time. The dispatcher stamps a thread-local pointer to the
// active registry before handing the request to a plugin and clears it
// after; pooled threads never leak one tenant's registry into the next
// request.
// ──────────────────────────────────────────────────────────────────────

/// Maps a bounded set of tenant ids to their own `Registry`. The default
/// tenant is held separately and is never an override slot. All registry
/// pointers are owned by the caller (boot); the set only references them.
pub const RegistrySet = struct {
    const Slot = struct {
        id_buf: [limits.max_id_bytes_for_registry]u8 = undefined,
        id_len: u8 = 0,
        registry: *Registry,

        fn id(self: *const Slot) []const u8 {
            return self.id_buf[0..self.id_len];
        }
    };

    /// The shared registry every default-tenant request uses. Must be set
    /// before dispatch; boot points this at its single `Registry`.
    default: *Registry,
    slots: [limits.max_tenant_registries]Slot = undefined,
    count: u8 = 0,

    pub fn init(default: *Registry) RegistrySet {
        return .{ .default = default };
    }

    /// Bind a non-default tenant id to its own registry. The id must be
    /// non-empty (the empty id is reserved for the default tenant) and
    /// fit `max_id_bytes_for_registry`. Duplicate ids are rejected.
    pub fn bind(self: *RegistrySet, tenant_id: []const u8, registry: *Registry) PluginError!void {
        if (tenant_id.len == 0) return error.NameTooLong;
        if (tenant_id.len > limits.max_id_bytes_for_registry) return error.NameTooLong;
        if (self.count >= limits.max_tenant_registries) return error.TooManyPlugins;
        var i: u8 = 0;
        while (i < self.count) : (i += 1) {
            if (std.mem.eql(u8, self.slots[i].id(), tenant_id)) return error.DuplicateName;
        }
        var slot: Slot = .{ .registry = registry };
        @memcpy(slot.id_buf[0..tenant_id.len], tenant_id);
        slot.id_len = @intCast(tenant_id.len);
        self.slots[self.count] = slot;
        self.count += 1;
        assertLe(@as(u32, self.count), limits.max_tenant_registries);
    }

    /// Resolve the registry for a tenant id. The default tenant (empty
    /// id) and any id without an explicit binding map to `default`.
    pub fn resolve(self: *const RegistrySet, tenant_id: []const u8) *Registry {
        if (tenant_id.len == 0) return self.default;
        var i: u8 = 0;
        while (i < self.count) : (i += 1) {
            if (std.mem.eql(u8, self.slots[i].id(), tenant_id)) return self.slots[i].registry;
        }
        return self.default;
    }
};

/// Thread-local pointer to the registry the current request's handlers
/// should consult. Null means "use the global default" — the single
/// tenant case, where nothing was stamped. Plugin code that needs the
/// active registry (today only the relay's sibling `find`) reads it via
/// `currentRegistry`.
threadlocal var current_registry: ?*Registry = null;

/// Stamp the active registry for this request's thread. The dispatcher
/// calls this after resolving the tenant; it is a no-op (clears) for the
/// default tenant so the default path stays exactly as before.
pub fn setCurrentRegistry(reg: ?*Registry) void {
    current_registry = reg;
}

/// The registry the current request should consult, or null when none was
/// stamped (default tenant / outside a request).
pub fn currentRegistry() ?*Registry {
    return current_registry;
}

/// Clear the stamped registry. Called at the end of dispatch so a pooled
/// thread never leaks one tenant's registry into the next request.
pub fn clearCurrentRegistry() void {
    current_registry = null;
}

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

test "C2: RegistrySet resolves default tenant to the default registry" {
    var def = Registry.init();
    var set = RegistrySet.init(&def);
    // Empty id (default tenant) → default registry.
    try std.testing.expect(set.resolve("") == &def);
    // Unknown / unbound id → default registry (no isolation requested).
    try std.testing.expect(set.resolve("nobody") == &def);
}

test "C2: RegistrySet isolates two tenants to their own registries" {
    var def = Registry.init();
    var reg_a = Registry.init();
    var reg_b = Registry.init();
    var set = RegistrySet.init(&def);

    try set.bind("tenant-a", &reg_a);
    try set.bind("tenant-b", &reg_b);

    try std.testing.expect(set.resolve("tenant-a") == &reg_a);
    try std.testing.expect(set.resolve("tenant-b") == &reg_b);
    // Default and unbound still fall through to the default registry.
    try std.testing.expect(set.resolve("") == &def);
    try std.testing.expect(set.resolve("tenant-c") == &def);
}

test "C2: RegistrySet rejects empty id, duplicates, and overflow" {
    var def = Registry.init();
    var other = Registry.init();
    var set = RegistrySet.init(&def);

    // Empty id is reserved for the default tenant.
    try std.testing.expectError(error.NameTooLong, set.bind("", &other));

    try set.bind("dup", &other);
    try std.testing.expectError(error.DuplicateName, set.bind("dup", &other));

    // Fill the remaining slots, then prove the next bind overflows.
    var filled: u32 = 1; // "dup" already bound
    var buf: [limits.max_id_bytes_for_registry]u8 = undefined;
    while (filled < limits.max_tenant_registries) : (filled += 1) {
        const id = std.fmt.bufPrint(&buf, "t{d}", .{filled}) catch unreachable;
        try set.bind(id, &other);
    }
    try std.testing.expectError(error.TooManyPlugins, set.bind("overflow", &other));
}

test "C2: per-tenant plugin state is isolated through the active registry" {
    // Two tenants register the SAME plugin name but distinct state. A
    // handler that reads its plugin's state via the thread-local active
    // registry must observe the tenant it was stamped with — and never
    // the other tenant's state. This is the isolation the dispatcher
    // provides per request.
    const Counter = struct { value: u32 };
    const S = struct {
        fn nop(_: ?*anyopaque, _: *Context) !void {}
        fn nopd(_: ?*anyopaque, _: *Context) void {}

        /// What a handler does at request time: read its plugin's state
        /// from whatever registry the dispatcher stamped for this request.
        fn observe() u32 {
            const reg = currentRegistry() orelse return 0;
            const p = reg.find("counter") orelse return 0;
            const c: *const Counter = @ptrCast(@alignCast(p.state.?));
            return c.value;
        }
    };

    var counter_a = Counter{ .value = 111 };
    var counter_b = Counter{ .value = 222 };

    var reg_a = Registry.init();
    var reg_b = Registry.init();
    _ = try reg_a.register(.{ .name = "counter", .version = 1, .state = &counter_a, .init = S.nop, .deinit = S.nopd });
    _ = try reg_b.register(.{ .name = "counter", .version = 1, .state = &counter_b, .init = S.nop, .deinit = S.nopd });

    var def = Registry.init();
    var set = RegistrySet.init(&def);
    try set.bind("tenant-a", &reg_a);
    try set.bind("tenant-b", &reg_b);

    // Default tenant: nothing stamped → no registry → handler sees 0.
    clearCurrentRegistry();
    try std.testing.expectEqual(@as(u32, 0), S.observe());

    // Tenant A request.
    setCurrentRegistry(set.resolve("tenant-a"));
    try std.testing.expectEqual(@as(u32, 111), S.observe());

    // Tenant B request on the same (reused) thread: must flip cleanly.
    setCurrentRegistry(set.resolve("tenant-b"));
    try std.testing.expectEqual(@as(u32, 222), S.observe());

    // End of request: clear so the next request on this pooled thread
    // does not inherit tenant B's registry.
    clearCurrentRegistry();
    try std.testing.expectEqual(@as(u32, 0), S.observe());
}
