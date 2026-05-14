//! Fuzzing helpers — exponential distributions, seed parsing, range helpers.
//! Re-exported from the vendored TB testing/fuzz.zig.

const tb_testing = @import("tb_testing");

pub const random_int_exponential = tb_testing.fuzz.random_int_exponential;
pub const range_inclusive_ms = tb_testing.fuzz.range_inclusive_ms;
pub const parse_seed = tb_testing.fuzz.parse_seed;
pub const FuzzArgs = tb_testing.fuzz.FuzzArgs;

test {
    _ = tb_testing.fuzz;
}
