pub const mastodon = @import("api/mastodon.zig");
pub const atproto = @import("api/atproto.zig");

// Common types and utilities
pub const types = @import("types.zig");
pub const utils = @import("utils.zig");

test {
    _ = atproto;
}
