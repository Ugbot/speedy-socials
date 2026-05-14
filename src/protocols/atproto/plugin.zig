//! AT Protocol plugin stub.
//!
//! This plugin exists today so the build system can register the
//! `protocol_atproto` module and the primitive types
//! (`cid`, `tid`, `dag_cbor`, `mst`, `keypair`, `syntax`, `did`) are
//! reachable from app `main.zig`. No routes are registered yet — the
//! repo/firehose/DPoP routes land in a later phase once storage is
//! wired.

const std = @import("std");
const core = @import("core");

pub const cid = @import("cid.zig");
pub const tid = @import("tid.zig");
pub const dag_cbor = @import("dag_cbor.zig");
pub const mst = @import("mst.zig");
pub const keypair = @import("keypair.zig");
pub const syntax = @import("syntax.zig");
pub const did = @import("did.zig");

fn init(_: ?*anyopaque, _: *core.plugin.Context) anyerror!void {}
fn deinit(_: ?*anyopaque, _: *core.plugin.Context) void {}

pub const plugin: core.plugin.Plugin = .{
    .name = "atproto",
    .version = 1,
    .init = init,
    .deinit = deinit,
};

test "atproto plugin registers" {
    var rng = core.rng.Rng.init(0x42);
    var sc = core.clock.SimClock.init(0);
    var ctx: core.plugin.Context = .{ .clock = sc.clock(), .rng = &rng };

    var reg = core.plugin.Registry.init();
    _ = try reg.register(plugin);
    try reg.initAll(&ctx);
    defer reg.deinitAll(&ctx);
}

test {
    // Pull in submodule tests.
    _ = cid;
    _ = tid;
    _ = dag_cbor;
    _ = mst;
    _ = keypair;
    _ = syntax;
    _ = did;
}
