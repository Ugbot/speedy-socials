//! Speedy-socials shim for vendored TigerBeetle sources.
//!
//! The TigerBeetle files we vendored under `intrusive/` reference two
//! upstream modules that we have not adopted wholesale:
//!
//!   * `constants.zig` — exposes a single boolean `verify` flag that
//!     enables/disables expensive O(n) invariant checks inside the
//!     intrusive collections.
//!
//!   * `stdx.PRNG` — TigerBeetle's seedable PRNG used by their internal
//!     fuzz tests. Tranche 3 will land a richer PRNG; for now the shim
//!     points at `core/rng.zig` (`Rng`).
//!
//! Keeping the shim minimal means we don't have to keep two PRNGs in
//! lockstep, and we can drop the upstream fuzz tests until Tranche 3
//! crystallises the full PRNG surface (push, pop, peek, contains, etc.
//! are still exercised at every adoption site).
//!
//! This file is *not* a faithful upstream port. It contains only what
//! the vendored intrusive collections actually reach for. Adding fields
//! beyond `verify` here would obscure where the project diverges from
//! TigerBeetle.

const std = @import("std");

/// Mirror of `tigerbeetle/src/constants.zig`'s `verify` flag. When true,
/// intrusive containers perform their O(n) invariant checks on every
/// mutation; production must keep this off for hot paths. We default to
/// `std.debug.runtime_safety` so safety builds (Debug/ReleaseSafe) keep
/// the verification and ReleaseFast/ReleaseSmall drop it.
pub const verify: bool = std.debug.runtime_safety;
