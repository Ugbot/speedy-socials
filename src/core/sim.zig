//! Simulation harness re-exports.
//!
//! These re-export the vendored TigerBeetle testing primitives — a
//! deterministic `TimeSim`, a fault-injecting `SimIo`, and a `PacketSimulator`
//! parameterised on a caller-defined Packet type. They power the federation
//! scenarios under `tests/sim/`.
//!
//! Tiger Style: every test that touches time, IO, or the network goes
//! through one of these — production callers go through `core.clock`,
//! `core.storage`, and the real network stack respectively.

const tb_testing = @import("tb_testing");

pub const TimeSim = tb_testing.time.TimeSim;
pub const OffsetType = tb_testing.time.OffsetType;

pub const SimIo = tb_testing.io.SimIo;
pub const SimFile = tb_testing.io.File;
pub const SimIoOptions = tb_testing.io.Options;

pub const PacketSimulator = tb_testing.packet_simulator.PacketSimulator;
pub const PacketSimulatorOptions = tb_testing.packet_simulator.Options;
pub const Partition = tb_testing.packet_simulator.Partition;
pub const NodeId = tb_testing.packet_simulator.NodeId;

test {
    _ = tb_testing;
}
