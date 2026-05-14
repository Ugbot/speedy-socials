//! Deterministic inbox state machines.
//!
//! Every activity type has its own `State` enum + `transition()` step
//! function. Each transition reads from an `Envelope` (parsed activity +
//! verified actor + clock/rng) and writes side-effect descriptors into a
//! caller-supplied `SideEffectBuffer`. The machine itself touches *no*
//! I/O — storage, delivery queues, metrics counters are all expressed as
//! `SideEffect` enum values the caller drains.
//!
//! Why this shape: the state machines become pure functions of input.
//! They are unit-testable with no fixtures; the storage and delivery
//! layers (Phase 3 integration) attach later by walking the side-effect
//! buffer with the storage/queue handles in hand.
//!
//! Tiger Style: every transition function is <70 lines, every branch is
//! explicit (no catch-all `else`), `unreachableState` covers
//! impossible terminal transitions, every loop has an asserted bound.

const std = @import("std");
const core = @import("core");
const ApError = core.errors.ApError;
const FedError = core.errors.FedError;
const Clock = core.clock.Clock;
const Rng = core.rng.Rng;
const assert = core.assert.assert;
const assertLe = core.assert.assertLe;
const unreachableState = core.assert.unreachableState;

const activity = @import("activity.zig");
const Activity = activity.Activity;
const ActivityType = activity.ActivityType;

pub const max_side_effects: u8 = 16;

/// Side-effect descriptors emitted by transitions. The caller (the inbox
/// HTTP handler) drains these into the storage + delivery + metrics
/// subsystems.
pub const SideEffect = union(enum) {
    store_activity: struct { id: []const u8, actor: []const u8, kind: ActivityType },
    store_object: struct { id: []const u8, kind: []const u8, actor: []const u8 },
    record_follow: struct { from_actor: []const u8, to_actor: []const u8 },
    accept_follow: struct { from_actor: []const u8, to_actor: []const u8 },
    reject_follow: struct { from_actor: []const u8, to_actor: []const u8 },
    enqueue_delivery: struct { target: []const u8, in_reply_to_id: []const u8 },
    tombstone_object: struct { id: []const u8 },
    update_object: struct { id: []const u8, kind: []const u8 },
    record_announce: struct { actor: []const u8, object: []const u8 },
    record_like: struct { actor: []const u8, object: []const u8 },
    increment_counter: struct { name: []const u8 },
    /// Returned only when the state machine wants to drop the activity
    /// with no other effect (e.g., duplicate Like). Caller logs.
    drop_silently: struct { reason: []const u8 },
};

pub const SideEffectBuffer = struct {
    items: [max_side_effects]SideEffect = undefined,
    len: u8 = 0,

    pub fn push(self: *SideEffectBuffer, eff: SideEffect) ApError!void {
        if (self.len >= max_side_effects) return error.InboxRejected;
        self.items[self.len] = eff;
        self.len += 1;
        assertLe(self.len, max_side_effects);
    }

    pub fn slice(self: *const SideEffectBuffer) []const SideEffect {
        return self.items[0..self.len];
    }
};

/// What the verifier already established about the request.
pub const VerifiedActor = struct {
    /// The IRI of the actor whose key signed the request. Compared
    /// against `activity.actor` per AP §7.1.2.
    iri: []const u8,
    /// Whether the actor is known locally (subscribers / following list
    /// pre-loaded by the caller). Drives whether `Accept`/`Reject` are
    /// surfaced to the relationship-state machine.
    is_known_to_us: bool = false,
};

pub const Envelope = struct {
    activity: Activity,
    verified_actor: VerifiedActor,
    clock: Clock,
    rng: *Rng,
};

// ──────────────────────────────────────────────────────────────────────
// Top-level dispatch
// ──────────────────────────────────────────────────────────────────────

/// Run the state machine for `env.activity.activity_type` to completion
/// (no async; transitions are synchronous). Side effects are appended to
/// `effects`.
pub fn dispatch(env: *const Envelope, effects: *SideEffectBuffer) ApError!void {
    // AP §7.1.2: the keyId actor MUST match `activity.actor`.
    if (!std.mem.eql(u8, env.verified_actor.iri, env.activity.actor)) {
        return error.InboxRejected;
    }
    switch (env.activity.activity_type) {
        .create => try runCreate(env, effects),
        .update => try runUpdate(env, effects),
        .delete => try runDelete(env, effects),
        .follow => try runFollow(env, effects),
        .accept => try runAccept(env, effects),
        .reject => try runReject(env, effects),
        .announce => try runAnnounce(env, effects),
        .like => try runLike(env, effects),
    }
}

// ──────────────────────────────────────────────────────────────────────
// Create
// ──────────────────────────────────────────────────────────────────────

pub const CreateState = enum { start, validate, persist_object, persist_activity, fanout, done };

fn runCreate(env: *const Envelope, eff: *SideEffectBuffer) ApError!void {
    var s: CreateState = .start;
    var guard: u32 = 0;
    while (s != .done) : (guard += 1) {
        assertLe(guard, 16);
        switch (s) {
            .start => s = .validate,
            .validate => {
                if (env.activity.object_id.len == 0) return error.BadObject;
                if (env.activity.object_type.len == 0) return error.BadObject;
                s = .persist_object;
            },
            .persist_object => {
                try eff.push(.{ .store_object = .{
                    .id = env.activity.object_id,
                    .kind = env.activity.object_type,
                    .actor = env.activity.actor,
                } });
                s = .persist_activity;
            },
            .persist_activity => {
                try eff.push(.{ .store_activity = .{
                    .id = env.activity.id,
                    .actor = env.activity.actor,
                    .kind = .create,
                } });
                s = .fanout;
            },
            .fanout => {
                if (env.activity.to_first.len > 0) {
                    try eff.push(.{ .enqueue_delivery = .{
                        .target = env.activity.to_first,
                        .in_reply_to_id = env.activity.object_id,
                    } });
                }
                try eff.push(.{ .increment_counter = .{ .name = "ap.inbox.create" } });
                s = .done;
            },
            .done => unreachableState("Create.done reached in loop body"),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// Update
// ──────────────────────────────────────────────────────────────────────

pub const UpdateState = enum { start, validate, apply, done };

fn runUpdate(env: *const Envelope, eff: *SideEffectBuffer) ApError!void {
    var s: UpdateState = .start;
    var guard: u32 = 0;
    while (s != .done) : (guard += 1) {
        assertLe(guard, 8);
        switch (s) {
            .start => s = .validate,
            .validate => {
                if (env.activity.object_id.len == 0) return error.BadObject;
                s = .apply;
            },
            .apply => {
                try eff.push(.{ .update_object = .{
                    .id = env.activity.object_id,
                    .kind = env.activity.object_type,
                } });
                try eff.push(.{ .store_activity = .{
                    .id = env.activity.id,
                    .actor = env.activity.actor,
                    .kind = .update,
                } });
                try eff.push(.{ .increment_counter = .{ .name = "ap.inbox.update" } });
                s = .done;
            },
            .done => unreachableState("Update.done reached in loop body"),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// Delete (object or actor)
// ──────────────────────────────────────────────────────────────────────

pub const DeleteState = enum { start, validate, tombstone, done };

fn runDelete(env: *const Envelope, eff: *SideEffectBuffer) ApError!void {
    var s: DeleteState = .start;
    var guard: u32 = 0;
    while (s != .done) : (guard += 1) {
        assertLe(guard, 8);
        switch (s) {
            .start => s = .validate,
            .validate => {
                if (env.activity.object_id.len == 0) return error.BadObject;
                s = .tombstone;
            },
            .tombstone => {
                try eff.push(.{ .tombstone_object = .{ .id = env.activity.object_id } });
                try eff.push(.{ .store_activity = .{
                    .id = env.activity.id,
                    .actor = env.activity.actor,
                    .kind = .delete,
                } });
                try eff.push(.{ .increment_counter = .{ .name = "ap.inbox.delete" } });
                s = .done;
            },
            .done => unreachableState("Delete.done reached in loop body"),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// Follow
// ──────────────────────────────────────────────────────────────────────

pub const FollowState = enum { start, validate, record, auto_accept, done };

fn runFollow(env: *const Envelope, eff: *SideEffectBuffer) ApError!void {
    var s: FollowState = .start;
    var guard: u32 = 0;
    while (s != .done) : (guard += 1) {
        assertLe(guard, 8);
        switch (s) {
            .start => s = .validate,
            .validate => {
                if (env.activity.object_id.len == 0) return error.BadObject;
                s = .record;
            },
            .record => {
                try eff.push(.{ .record_follow = .{
                    .from_actor = env.activity.actor,
                    .to_actor = env.activity.object_id,
                } });
                s = .auto_accept;
            },
            .auto_accept => {
                // Auto-Accept policy lives in storage (locked-account
                // flag). Here we emit an accept_follow side-effect and
                // let the caller decide whether to materialize it into
                // an outbound Accept or queue for manual approval.
                try eff.push(.{ .accept_follow = .{
                    .from_actor = env.activity.actor,
                    .to_actor = env.activity.object_id,
                } });
                try eff.push(.{ .store_activity = .{
                    .id = env.activity.id,
                    .actor = env.activity.actor,
                    .kind = .follow,
                } });
                try eff.push(.{ .increment_counter = .{ .name = "ap.inbox.follow" } });
                s = .done;
            },
            .done => unreachableState("Follow.done reached in loop body"),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// Accept (response to our outbound Follow)
// ──────────────────────────────────────────────────────────────────────

pub const AcceptState = enum { start, validate, apply, done };

fn runAccept(env: *const Envelope, eff: *SideEffectBuffer) ApError!void {
    var s: AcceptState = .start;
    var guard: u32 = 0;
    while (s != .done) : (guard += 1) {
        assertLe(guard, 8);
        switch (s) {
            .start => s = .validate,
            .validate => {
                if (env.activity.object_id.len == 0) return error.BadObject;
                if (!env.verified_actor.is_known_to_us) {
                    try eff.push(.{ .drop_silently = .{ .reason = "accept-from-unknown-actor" } });
                    s = .done;
                    continue;
                }
                s = .apply;
            },
            .apply => {
                try eff.push(.{ .accept_follow = .{
                    .from_actor = env.activity.object_id, // we initiated
                    .to_actor = env.activity.actor,
                } });
                try eff.push(.{ .store_activity = .{
                    .id = env.activity.id,
                    .actor = env.activity.actor,
                    .kind = .accept,
                } });
                try eff.push(.{ .increment_counter = .{ .name = "ap.inbox.accept" } });
                s = .done;
            },
            .done => unreachableState("Accept.done reached in loop body"),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// Reject
// ──────────────────────────────────────────────────────────────────────

pub const RejectState = enum { start, validate, apply, done };

fn runReject(env: *const Envelope, eff: *SideEffectBuffer) ApError!void {
    var s: RejectState = .start;
    var guard: u32 = 0;
    while (s != .done) : (guard += 1) {
        assertLe(guard, 8);
        switch (s) {
            .start => s = .validate,
            .validate => {
                if (env.activity.object_id.len == 0) return error.BadObject;
                if (!env.verified_actor.is_known_to_us) {
                    try eff.push(.{ .drop_silently = .{ .reason = "reject-from-unknown-actor" } });
                    s = .done;
                    continue;
                }
                s = .apply;
            },
            .apply => {
                try eff.push(.{ .reject_follow = .{
                    .from_actor = env.activity.object_id,
                    .to_actor = env.activity.actor,
                } });
                try eff.push(.{ .store_activity = .{
                    .id = env.activity.id,
                    .actor = env.activity.actor,
                    .kind = .reject,
                } });
                try eff.push(.{ .increment_counter = .{ .name = "ap.inbox.reject" } });
                s = .done;
            },
            .done => unreachableState("Reject.done reached in loop body"),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// Announce (boost / reblog)
// ──────────────────────────────────────────────────────────────────────

pub const AnnounceState = enum { start, validate, record, done };

fn runAnnounce(env: *const Envelope, eff: *SideEffectBuffer) ApError!void {
    var s: AnnounceState = .start;
    var guard: u32 = 0;
    while (s != .done) : (guard += 1) {
        assertLe(guard, 8);
        switch (s) {
            .start => s = .validate,
            .validate => {
                if (env.activity.object_id.len == 0) return error.BadObject;
                s = .record;
            },
            .record => {
                try eff.push(.{ .record_announce = .{
                    .actor = env.activity.actor,
                    .object = env.activity.object_id,
                } });
                try eff.push(.{ .store_activity = .{
                    .id = env.activity.id,
                    .actor = env.activity.actor,
                    .kind = .announce,
                } });
                try eff.push(.{ .increment_counter = .{ .name = "ap.inbox.announce" } });
                s = .done;
            },
            .done => unreachableState("Announce.done reached in loop body"),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// Like (favourite)
// ──────────────────────────────────────────────────────────────────────

pub const LikeState = enum { start, validate, record, done };

fn runLike(env: *const Envelope, eff: *SideEffectBuffer) ApError!void {
    var s: LikeState = .start;
    var guard: u32 = 0;
    while (s != .done) : (guard += 1) {
        assertLe(guard, 8);
        switch (s) {
            .start => s = .validate,
            .validate => {
                if (env.activity.object_id.len == 0) return error.BadObject;
                s = .record;
            },
            .record => {
                try eff.push(.{ .record_like = .{
                    .actor = env.activity.actor,
                    .object = env.activity.object_id,
                } });
                try eff.push(.{ .store_activity = .{
                    .id = env.activity.id,
                    .actor = env.activity.actor,
                    .kind = .like,
                } });
                try eff.push(.{ .increment_counter = .{ .name = "ap.inbox.like" } });
                s = .done;
            },
            .done => unreachableState("Like.done reached in loop body"),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const SimClock = core.clock.SimClock;

fn buildEnvelope(act: Activity, known: bool, clock: Clock, rng: *Rng) Envelope {
    return .{
        .activity = act,
        .verified_actor = .{ .iri = act.actor, .is_known_to_us = known },
        .clock = clock,
        .rng = rng,
    };
}

test "dispatch rejects mismatched keyId actor" {
    var rng = Rng.init(1);
    var sc = SimClock.init(0);
    const act = try activity.parse(
        \\{"type":"Like","actor":"https://a/u","object":"https://a/p"}
    );
    var env: Envelope = .{
        .activity = act,
        .verified_actor = .{ .iri = "https://other/u", .is_known_to_us = false },
        .clock = sc.clock(),
        .rng = &rng,
    };
    var eff: SideEffectBuffer = .{};
    try std.testing.expectError(error.InboxRejected, dispatch(&env, &eff));
}

test "Create emits store_object + store_activity + delivery + counter" {
    var rng = Rng.init(1);
    var sc = SimClock.init(0);
    const act = try activity.parse(
        \\{"id":"https://a/x/1","type":"Create","actor":"https://a/u",
        \\ "to":["https://w3.org/Public"],
        \\ "object":{"id":"https://a/n/1","type":"Note","content":"hi"}}
    );
    var env = buildEnvelope(act, false, sc.clock(), &rng);
    var eff: SideEffectBuffer = .{};
    try dispatch(&env, &eff);
    try std.testing.expectEqual(@as(u8, 4), eff.len);
    switch (eff.items[0]) {
        .store_object => |so| {
            try std.testing.expectEqualStrings("https://a/n/1", so.id);
            try std.testing.expectEqualStrings("Note", so.kind);
        },
        else => return error.TestExpectedStoreObject,
    }
    switch (eff.items[2]) {
        .enqueue_delivery => |d| try std.testing.expectEqualStrings("https://w3.org/Public", d.target),
        else => return error.TestExpectedDelivery,
    }
}

test "Update with object_id emits update_object" {
    var rng = Rng.init(1);
    var sc = SimClock.init(0);
    const act = try activity.parse(
        \\{"id":"u1","type":"Update","actor":"https://a/u",
        \\ "object":{"id":"https://a/o","type":"Note"}}
    );
    var env = buildEnvelope(act, false, sc.clock(), &rng);
    var eff: SideEffectBuffer = .{};
    try dispatch(&env, &eff);
    switch (eff.items[0]) {
        .update_object => |u| try std.testing.expectEqualStrings("https://a/o", u.id),
        else => return error.TestExpectedUpdate,
    }
}

test "Delete emits tombstone" {
    var rng = Rng.init(1);
    var sc = SimClock.init(0);
    const act = try activity.parse(
        \\{"id":"d1","type":"Delete","actor":"https://a/u","object":"https://a/o"}
    );
    var env = buildEnvelope(act, false, sc.clock(), &rng);
    var eff: SideEffectBuffer = .{};
    try dispatch(&env, &eff);
    switch (eff.items[0]) {
        .tombstone_object => |t| try std.testing.expectEqualStrings("https://a/o", t.id),
        else => return error.TestExpectedTombstone,
    }
}

test "Follow emits record_follow + accept_follow + store_activity" {
    var rng = Rng.init(1);
    var sc = SimClock.init(0);
    const act = try activity.parse(
        \\{"id":"f1","type":"Follow","actor":"https://a/u","object":"https://b/u"}
    );
    var env = buildEnvelope(act, false, sc.clock(), &rng);
    var eff: SideEffectBuffer = .{};
    try dispatch(&env, &eff);
    try std.testing.expectEqual(@as(u8, 4), eff.len);
    switch (eff.items[0]) {
        .record_follow => |r| {
            try std.testing.expectEqualStrings("https://a/u", r.from_actor);
            try std.testing.expectEqualStrings("https://b/u", r.to_actor);
        },
        else => return error.TestExpectedRecordFollow,
    }
    switch (eff.items[1]) {
        .accept_follow => {},
        else => return error.TestExpectedAcceptFollow,
    }
}

test "Accept from unknown actor is dropped silently" {
    var rng = Rng.init(1);
    var sc = SimClock.init(0);
    const act = try activity.parse(
        \\{"id":"a1","type":"Accept","actor":"https://b/u","object":"https://a/u"}
    );
    var env = buildEnvelope(act, false, sc.clock(), &rng);
    var eff: SideEffectBuffer = .{};
    try dispatch(&env, &eff);
    try std.testing.expectEqual(@as(u8, 1), eff.len);
    switch (eff.items[0]) {
        .drop_silently => |d| try std.testing.expectEqualStrings("accept-from-unknown-actor", d.reason),
        else => return error.TestExpectedDrop,
    }
}

test "Accept from known actor records accept_follow" {
    var rng = Rng.init(1);
    var sc = SimClock.init(0);
    const act = try activity.parse(
        \\{"id":"a1","type":"Accept","actor":"https://b/u","object":"https://a/u"}
    );
    var env = buildEnvelope(act, true, sc.clock(), &rng);
    var eff: SideEffectBuffer = .{};
    try dispatch(&env, &eff);
    switch (eff.items[0]) {
        .accept_follow => |a| {
            try std.testing.expectEqualStrings("https://a/u", a.from_actor);
            try std.testing.expectEqualStrings("https://b/u", a.to_actor);
        },
        else => return error.TestExpectedAcceptFollow,
    }
}

test "Reject from known actor records reject_follow" {
    var rng = Rng.init(1);
    var sc = SimClock.init(0);
    const act = try activity.parse(
        \\{"id":"r1","type":"Reject","actor":"https://b/u","object":"https://a/u"}
    );
    var env = buildEnvelope(act, true, sc.clock(), &rng);
    var eff: SideEffectBuffer = .{};
    try dispatch(&env, &eff);
    switch (eff.items[0]) {
        .reject_follow => {},
        else => return error.TestExpectedRejectFollow,
    }
}

test "Announce records announce" {
    var rng = Rng.init(1);
    var sc = SimClock.init(0);
    const act = try activity.parse(
        \\{"id":"an1","type":"Announce","actor":"https://a/u","object":"https://a/p"}
    );
    var env = buildEnvelope(act, false, sc.clock(), &rng);
    var eff: SideEffectBuffer = .{};
    try dispatch(&env, &eff);
    switch (eff.items[0]) {
        .record_announce => |a| try std.testing.expectEqualStrings("https://a/p", a.object),
        else => return error.TestExpectedAnnounce,
    }
}

test "Like records like" {
    var rng = Rng.init(1);
    var sc = SimClock.init(0);
    const act = try activity.parse(
        \\{"id":"l1","type":"Like","actor":"https://a/u","object":"https://a/p"}
    );
    var env = buildEnvelope(act, false, sc.clock(), &rng);
    var eff: SideEffectBuffer = .{};
    try dispatch(&env, &eff);
    switch (eff.items[0]) {
        .record_like => |l| {
            try std.testing.expectEqualStrings("https://a/u", l.actor);
            try std.testing.expectEqualStrings("https://a/p", l.object);
        },
        else => return error.TestExpectedLike,
    }
}

test "SideEffectBuffer overflow is rejected" {
    var eff: SideEffectBuffer = .{};
    var i: u8 = 0;
    while (i < max_side_effects) : (i += 1) {
        try eff.push(.{ .drop_silently = .{ .reason = "x" } });
    }
    try std.testing.expectError(error.InboxRejected, eff.push(.{ .drop_silently = .{ .reason = "y" } }));
}

test "Create with no object_id is rejected" {
    var rng = Rng.init(1);
    var sc = SimClock.init(0);
    const act = try activity.parse(
        \\{"id":"c1","type":"Create","actor":"https://a/u","object":{"type":"Note"}}
    );
    var env = buildEnvelope(act, false, sc.clock(), &rng);
    var eff: SideEffectBuffer = .{};
    try std.testing.expectError(error.BadObject, dispatch(&env, &eff));
}
