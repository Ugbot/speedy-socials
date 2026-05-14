//! sync types - com.atproto.sync.subscribeRepos
//!
//! enums for firehose/event stream consumption.
//! see: https://atproto.com/specs/event-stream

const std = @import("std");

/// repo operation action (create/update/delete)
///
/// from com.atproto.sync.subscribeRepos#repoOp
/// used in firehose commit messages to indicate what happened to a record.
pub const CommitAction = enum {
    create,
    update,
    delete,

    /// parse from string (for manual parsing)
    pub fn parse(s: []const u8) ?CommitAction {
        return std.meta.stringToEnum(CommitAction, s);
    }
};

/// event stream message types
///
/// from com.atproto.sync.subscribeRepos message union
/// the top-level discriminator for firehose messages.
pub const EventKind = enum {
    commit,
    sync,
    identity,
    account,
    info,

    pub fn parse(s: []const u8) ?EventKind {
        return std.meta.stringToEnum(EventKind, s);
    }
};

/// account status reasons
///
/// from com.atproto.sync.subscribeRepos#account status field
/// indicates why an account is inactive.
pub const AccountStatus = enum {
    takendown,
    suspended,
    deleted,
    deactivated,
    desynchronized,
    throttled,

    pub fn parse(s: []const u8) ?AccountStatus {
        return std.meta.stringToEnum(AccountStatus, s);
    }
};

// === tests ===

test "CommitAction parse" {
    try std.testing.expectEqual(CommitAction.create, CommitAction.parse("create").?);
    try std.testing.expectEqual(CommitAction.update, CommitAction.parse("update").?);
    try std.testing.expectEqual(CommitAction.delete, CommitAction.parse("delete").?);
    try std.testing.expect(CommitAction.parse("invalid") == null);
}

test "CommitAction json parsing" {
    const json_str =
        \\{"action": "create", "path": "app.bsky.feed.post/abc"}
    ;

    const Op = struct {
        action: CommitAction,
        path: []const u8,
    };

    const parsed = try std.json.parseFromSlice(Op, std.testing.allocator, json_str, .{});
    defer parsed.deinit();

    try std.testing.expectEqual(CommitAction.create, parsed.value.action);
}

test "EventKind parse" {
    try std.testing.expectEqual(EventKind.commit, EventKind.parse("commit").?);
    try std.testing.expectEqual(EventKind.identity, EventKind.parse("identity").?);
    try std.testing.expect(EventKind.parse("unknown") == null);
}

test "AccountStatus parse" {
    try std.testing.expectEqual(AccountStatus.takendown, AccountStatus.parse("takendown").?);
    try std.testing.expectEqual(AccountStatus.suspended, AccountStatus.parse("suspended").?);
}
