//! Module root for the vendored TigerBeetle simulation primitives.
//! Public surface is re-exported through `core.sim` / `core.testing.fuzz`.

pub const time = @import("time.zig");
pub const io = @import("io.zig");
pub const fuzz = @import("fuzz.zig");
pub const packet_simulator = @import("packet_simulator.zig");

test {
    _ = time;
    _ = io;
    _ = fuzz;
    _ = packet_simulator;
}
