pub const mastodon = @import("api/mastodon.zig");
// atproto is temporarily disabled — it depends on httpz which is not available.
// pub const atproto = @import("api/atproto.zig");

// Common types and utilities
pub const types = @import("types.zig");
pub const utils = @import("utils.zig");

// Test all API modules
test {
    _ = mastodon;
    // _ = atproto;
}
