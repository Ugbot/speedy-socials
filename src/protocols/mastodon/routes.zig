//! Route registration for the Mastodon plugin.
//!
//! All Mastodon API v1 endpoints, the OAuth2 endpoints, and the
//! streaming stubs land here. Each handler is implemented in a
//! sibling module under `routes/`.

const std = @import("std");
const core = @import("core");
const Router = core.http.router.Router;

const oauth = @import("oauth.zig");
const accounts = @import("routes/accounts.zig");
const statuses = @import("routes/statuses.zig");
const timelines = @import("routes/timelines.zig");
const notifications = @import("routes/notifications.zig");
const instance = @import("routes/instance.zig");
const media = @import("routes/media.zig");
const apps = @import("routes/apps.zig");
const streaming = @import("routes/streaming.zig");

pub fn register(router: *Router, plugin_index: u16) !void {
    // OAuth2.
    try router.register(.post, "/api/v1/apps", oauth.handleCreateApp, plugin_index);
    try router.register(.get, "/api/v1/apps/verify_credentials", apps.handleVerifyAppCredentials, plugin_index);
    try router.register(.get, "/oauth/authorize", oauth.handleAuthorize, plugin_index);
    try router.register(.post, "/oauth/token", oauth.handleToken, plugin_index);
    try router.register(.post, "/oauth/revoke", oauth.handleRevoke, plugin_index);

    // Accounts.
    try router.register(.get, "/api/v1/accounts/verify_credentials", accounts.handleVerifyCredentials, plugin_index);
    try router.register(.get, "/api/v1/accounts/:id", accounts.handleGetAccount, plugin_index);
    try router.register(.get, "/api/v1/accounts/:id/statuses", accounts.handleAccountStatuses, plugin_index);
    try router.register(.get, "/api/v1/accounts/:id/followers", accounts.handleAccountFollowers, plugin_index);
    try router.register(.get, "/api/v1/accounts/:id/following", accounts.handleAccountFollowing, plugin_index);
    try router.register(.post, "/api/v1/accounts/:id/follow", accounts.handleAccountFollow, plugin_index);
    try router.register(.post, "/api/v1/accounts/:id/unfollow", accounts.handleAccountUnfollow, plugin_index);

    // Statuses.
    try router.register(.post, "/api/v1/statuses", statuses.handleCreateStatus, plugin_index);
    try router.register(.get, "/api/v1/statuses/:id", statuses.handleGetStatus, plugin_index);
    try router.register(.delete, "/api/v1/statuses/:id", statuses.handleDeleteStatus, plugin_index);
    try router.register(.post, "/api/v1/statuses/:id/favourite", statuses.handleFavourite, plugin_index);
    try router.register(.post, "/api/v1/statuses/:id/unfavourite", statuses.handleUnfavourite, plugin_index);
    try router.register(.post, "/api/v1/statuses/:id/reblog", statuses.handleReblog, plugin_index);
    try router.register(.post, "/api/v1/statuses/:id/unreblog", statuses.handleUnreblog, plugin_index);

    // Timelines.
    try router.register(.get, "/api/v1/timelines/home", timelines.handleHome, plugin_index);
    try router.register(.get, "/api/v1/timelines/public", timelines.handlePublic, plugin_index);
    try router.register(.get, "/api/v1/timelines/tag/:hashtag", timelines.handleHashtag, plugin_index);

    // Notifications.
    try router.register(.get, "/api/v1/notifications", notifications.handleList, plugin_index);
    try router.register(.post, "/api/v1/notifications/clear", notifications.handleClear, plugin_index);

    // Instance metadata.
    try router.register(.get, "/api/v1/instance", instance.handleInstance, plugin_index);
    try router.register(.get, "/api/v1/instance/peers", instance.handleInstancePeers, plugin_index);
    try router.register(.get, "/api/v1/instance/activity", instance.handleInstanceActivity, plugin_index);

    // Media (501 stubs — W1.4).
    try router.register(.post, "/api/v1/media", media.handleUploadV1, plugin_index);
    try router.register(.post, "/api/v2/media", media.handleUploadV2, plugin_index);

    // Streaming (501 stubs — W1.1).
    try router.register(.get, "/api/v1/streaming/user", streaming.handleUser, plugin_index);
    try router.register(.get, "/api/v1/streaming/public", streaming.handlePublic, plugin_index);
    try router.register(.get, "/api/v1/streaming/hashtag", streaming.handleHashtag, plugin_index);
    try router.register(.get, "/api/v1/streaming/list", streaming.handleList, plugin_index);
}

const testing = std.testing;

test "Mastodon routes register without duplicates" {
    var r = Router.init();
    try register(&r, 0);
    // 5 oauth+apps + 7 accounts + 7 statuses + 3 timelines + 2 notifications + 3 instance + 2 media + 4 streaming = 33
    try testing.expectEqual(@as(u32, 33), r.count);
}
