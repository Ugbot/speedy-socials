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

// ──────────────────────────────────────────────────────────────────────
// Relay hook (W5.2)
//
// The protocol-relay plugin needs to observe every successfully
// processed inbound activity so it can mirror the activity into the
// AT side of the bridge. Following the established `setRsaVerifyHook`
// pattern (in `keys.zig`), the AP module exposes a single optional
// callback; the relay registers it at boot. Hard imports between AP
// and relay are intentionally avoided — the relay depends on AP, not
// the other way round.
//
// The hook fires *after* `dispatch()` succeeds and the inbox route
// has finished draining side effects. It receives the parsed
// activity and a db handle so the relay can do its own writes. The
// hook MUST NOT throw — relay translation failures are logged at
// the relay; they do not fail the AP inbox response.
// ──────────────────────────────────────────────────────────────────────

const sqlite_c = @import("sqlite").c;

pub const RelayInboxHook = *const fn (
    act: *const Activity,
    raw_body: []const u8,
    db: *sqlite_c.sqlite3,
    clock: Clock,
) void;

var relay_inbox_hook: ?RelayInboxHook = null;

pub fn setRelayInboxHook(hook: ?RelayInboxHook) void {
    relay_inbox_hook = hook;
}

pub fn currentRelayInboxHook() ?RelayInboxHook {
    return relay_inbox_hook;
}

/// Side-effect descriptors emitted by transitions. The caller (the inbox
/// HTTP handler) drains these into the storage + delivery + metrics
/// subsystems.
pub const SideEffect = union(enum) {
    store_activity: struct { id: []const u8, actor: []const u8, kind: ActivityType },
    store_object: struct { id: []const u8, kind: []const u8, actor: []const u8 },
    /// `follow_iri` is the IRI of the Follow activity itself (used by
    /// AP-6 to locate the row on Undo{Follow}). Empty when the
    /// inbound Follow didn't carry an `id`.
    record_follow: struct { from_actor: []const u8, to_actor: []const u8, follow_iri: []const u8 },
    accept_follow: struct { from_actor: []const u8, to_actor: []const u8 },
    reject_follow: struct { from_actor: []const u8, to_actor: []const u8 },
    enqueue_delivery: struct { target: []const u8, in_reply_to_id: []const u8 },
    tombstone_object: struct { id: []const u8, former_type: []const u8 },
    update_object: struct { id: []const u8, kind: []const u8 },
    record_announce: struct { actor: []const u8, object: []const u8 },
    /// FEP-c0e0: `reaction` carries the emoji shortcode when the Like
    /// is an emoji reaction (Pleroma / Misskey `EmojiReact`); empty for
    /// a plain Like. The drainer persists it in `ap_reactions`.
    record_like: struct { actor: []const u8, object: []const u8, reaction: []const u8 = &.{} },
    increment_counter: struct { name: []const u8 },
    /// AP-6: reverse the side-effects of a prior Follow/Like/Announce
    /// referenced by its IRI. The drainer looks up the original
    /// activity row to learn its type, then deletes the
    /// type-appropriate state (ap_follows row by `follow_iri`, or
    /// ap_activities row by ap_id for Likes / Announces).
    undo_by_iri: struct { iri: []const u8 },
    /// AP-8: add `object` to `collection` (e.g. featured posts) or
    /// remove it. The drainer writes / deletes a row in
    /// `ap_collection_items`.
    collection_add: struct { collection: []const u8, object_iri: []const u8, actor: []const u8 },
    collection_remove: struct { collection: []const u8, object_iri: []const u8 },
    /// AP-3: inbox forwarding (AP §7.1.3). When the activity's `cc`
    /// names a local actor's followers collection, we forward the
    /// (verbatim) raw body to that actor's followers. The drainer
    /// expands the collection URL via the local follower index and
    /// enqueues an outbox row per resolved inbox.
    forward_to_followers: struct { collection_url: []const u8, raw_body: []const u8 },
    /// AP-25: block enforcement. Records a (actor → target) pair so
    /// subsequent activities from the blocked actor get 403'd.
    record_block: struct { actor: []const u8, target: []const u8, activity_id: []const u8 },
    /// AP-26: actor move (FEP-fb2a). Records the old→new actor
    /// migration. Follower migration is a downstream worker.
    record_move: struct { old_actor: []const u8, new_actor: []const u8 },
    /// AP-17: tag from `tag[]` — a Mention / Hashtag / Emoji entry.
    record_tag: struct { activity_iri: []const u8, kind: []const u8, name: []const u8, href: []const u8 },
    /// AP-16: a poll vote — a Create{Note} with `name` (option) +
    /// `inReplyTo` (the Question IRI).
    record_poll_vote: struct { activity_iri: []const u8, question_iri: []const u8, actor: []const u8, option_name: []const u8 },
    /// AP-23: a media attachment from the inbound object's `attachment[]`.
    record_attachment: struct { object_iri: []const u8, url: []const u8, media_type: []const u8, name: []const u8 },
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
    /// AP-3: local hostname (so state machines can detect local
    /// followers collections in `cc`). Empty disables forwarding.
    local_host: []const u8 = &.{},
    /// AP-3: raw inbound body, used as the forwarded payload when
    /// `forward_to_followers` fires. Empty disables forwarding.
    raw_body: []const u8 = &.{},
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

    // AP-17: persist any tags attached to the activity body.
    var ti: u8 = 0;
    while (ti < env.activity.tags.len) : (ti += 1) {
        const t = env.activity.tags.items[ti];
        const kind_str: []const u8 = switch (t.kind) {
            .mention => "mention",
            .hashtag => "hashtag",
            .emoji => "emoji",
            .other => "other",
        };
        if (t.name.len == 0) continue;
        try effects.push(.{ .record_tag = .{
            .activity_iri = env.activity.id,
            .kind = kind_str,
            .name = t.name,
            .href = t.href,
        } });
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
        // AP-6: Undo{Follow/Like/Announce}. Emit `undo_by_iri` so the
        // drainer can locate and remove the right state (follow row /
        // activity row); also bump the per-activity counter.
        .undo => try runUndo(env, effects),
        // AP-8: Add{object → collection} / Remove{object → collection}.
        .add => try runAddRemove(env, effects, .add),
        .remove => try runAddRemove(env, effects, .remove),
        // AP-16: Question/Poll. The Question itself is a stored
        // object; vote replies arrive as Create{Note} with
        // `inReplyTo = <question iri>`. For now we count + audit-log
        // the Question; poll-tally aggregation needs an
        // `ap_poll_options` table which is a future ticket.
        .question => try effects.push(.{ .increment_counter = .{ .name = "ap.inbox.question" } }),
        // AP-26: record the old→new mapping; downstream lookups
        // chase via `ap_actor_moves`.
        .move => try runMove(env, effects),
        // AP-25: persist the block so subsequent activities from
        // the blocked actor can be 403'd.
        .block => try runBlock(env, effects),
        .flag => try effects.push(.{ .increment_counter = .{ .name = "ap.inbox.flag" } }),
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
                // AP-16: a Note carrying both `name` (option) and
                // `inReplyTo` (the Question IRI) is a poll vote — record
                // it keyed to the question it replies to.
                if (env.activity.object_name.len > 0 and env.activity.in_reply_to.len > 0) {
                    try eff.push(.{ .record_poll_vote = .{
                        .activity_iri = env.activity.id,
                        .question_iri = env.activity.in_reply_to,
                        .actor = env.activity.actor,
                        .option_name = env.activity.object_name,
                    } });
                }
                // AP-23: capture media attachments on the object.
                var ai: u8 = 0;
                while (ai < env.activity.attachments.len) : (ai += 1) {
                    const att = env.activity.attachments.items[ai];
                    if (att.url.len == 0) continue;
                    eff.push(.{ .record_attachment = .{
                        .object_iri = env.activity.object_id,
                        .url = att.url,
                        .media_type = att.media_type,
                        .name = att.name,
                    } }) catch break; // buffer full — bounded, drop the rest
                }
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
                // Walk the FULL `to` + `cc` addressing arrays to resolve
                // delivery targets. Public addressing (the AS2 public
                // collection in any of its spellings) is recognised and
                // NOT enqueued as a fetchable inbox; local followers
                // collections are handled by the inbox-forwarding pass
                // below, not enqueued as direct targets. Everything else
                // is a concrete recipient. Deduplicated against the
                // delivery targets already emitted in this fanout.
                var delivered: DedupSet = .{};
                inline for (.{ &env.activity.to, &env.activity.cc }) |list| {
                    var di: u8 = 0;
                    while (di < list.len) : (di += 1) {
                        const addr = list.items[di];
                        if (addr.len == 0) continue;
                        if (activity.isPublicAddressing(addr)) continue;
                        if (isLocalFollowersCollection(addr, env.local_host)) continue;
                        if (!delivered.add(addr)) continue; // dup — already enqueued
                        eff.push(.{ .enqueue_delivery = .{
                            .target = addr,
                            .in_reply_to_id = env.activity.object_id,
                        } }) catch break; // buffer full — bounded, drop the rest
                    }
                }
                // AP §7.1.3 inbox forwarding: redistribute to EVERY `to`
                // or `cc` entry that names a local actor's `/followers`
                // collection — not just the first match. Dedupe so the
                // same collection forwarded twice (e.g. in both `to` and
                // `cc`) only enqueues one forward.
                if (env.local_host.len > 0 and env.raw_body.len > 0) {
                    var forwarded: DedupSet = .{};
                    inline for (.{ &env.activity.to, &env.activity.cc }) |list| {
                        var fi: u8 = 0;
                        while (fi < list.len) : (fi += 1) {
                            const addr = list.items[fi];
                            if (!isLocalFollowersCollection(addr, env.local_host)) continue;
                            if (!forwarded.add(addr)) continue; // already forwarded
                            eff.push(.{ .forward_to_followers = .{
                                .collection_url = addr,
                                .raw_body = env.raw_body,
                            } }) catch break; // buffer full — bounded
                        }
                    }
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
                try eff.push(.{ .tombstone_object = .{
                    .id = env.activity.object_id,
                    .former_type = env.activity.object_type,
                } });
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
                    .follow_iri = env.activity.id,
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
                    // FEP-c0e0: carry the emoji shortcode (if any) so the
                    // drainer can persist this Like as an emoji reaction.
                    .reaction = env.activity.reaction_content,
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
// Undo (AP-6)
//
// `Undo` reverses the side effects of a prior `Follow`, `Like`, or
// `Announce` issued by the same actor. The Undo's `object` is the IRI
// of the activity being reversed.
//
// We don't know the original activity's type just from the IRI — and
// inline `object` types may or may not be present. The state machine
// therefore emits a generic `undo_by_iri` effect; the drainer
// dereferences the IRI in `ap_activities` (where we audit-log every
// inbound activity) to learn the original type and run the right
// cleanup.
// ──────────────────────────────────────────────────────────────────────

pub const UndoState = enum { start, validate, emit, done };

fn runUndo(env: *const Envelope, eff: *SideEffectBuffer) ApError!void {
    var s: UndoState = .start;
    var guard: u32 = 0;
    while (s != .done) : (guard += 1) {
        assertLe(guard, 8);
        switch (s) {
            .start => s = .validate,
            .validate => {
                if (env.activity.object_id.len == 0) return error.BadObject;
                s = .emit;
            },
            .emit => {
                try eff.push(.{ .undo_by_iri = .{ .iri = env.activity.object_id } });
                try eff.push(.{ .store_activity = .{
                    .id = env.activity.id,
                    .actor = env.activity.actor,
                    .kind = .undo,
                } });
                try eff.push(.{ .increment_counter = .{ .name = "ap.inbox.undo" } });
                s = .done;
            },
            .done => unreachableState("Undo.done reached in loop body"),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// AP-25: Block
// ──────────────────────────────────────────────────────────────────────

fn runBlock(env: *const Envelope, eff: *SideEffectBuffer) ApError!void {
    if (env.activity.object_id.len == 0) return error.BadObject;
    try eff.push(.{ .record_block = .{
        .actor = env.activity.actor,
        .target = env.activity.object_id,
        .activity_id = env.activity.id,
    } });
    try eff.push(.{ .store_activity = .{
        .id = env.activity.id,
        .actor = env.activity.actor,
        .kind = .block,
    } });
    try eff.push(.{ .increment_counter = .{ .name = "ap.inbox.block" } });
}

// ──────────────────────────────────────────────────────────────────────
// AP-26: Move
// ──────────────────────────────────────────────────────────────────────

fn runMove(env: *const Envelope, eff: *SideEffectBuffer) ApError!void {
    if (env.activity.target.len == 0) return error.BadObject;
    try eff.push(.{ .record_move = .{
        .old_actor = env.activity.actor,
        .new_actor = env.activity.target,
    } });
    try eff.push(.{ .store_activity = .{
        .id = env.activity.id,
        .actor = env.activity.actor,
        .kind = .move,
    } });
    try eff.push(.{ .increment_counter = .{ .name = "ap.inbox.move" } });
}

/// Heap-free dedup set for recipient IRIs. Bounded by the combined
/// `to` + `cc` addressing capacity (2 × `max_addressed`). Linear scan
/// — the sets are tiny (≤32 entries) so this beats hashing on cost and
/// allocation. `add` returns true when the value was newly inserted,
/// false when it was already present (a duplicate).
const max_dedup: u8 = activity.max_addressed * 2;
const DedupSet = struct {
    items: [max_dedup][]const u8 = undefined,
    len: u8 = 0,

    fn add(self: *DedupSet, s: []const u8) bool {
        var i: u8 = 0;
        while (i < self.len) : (i += 1) {
            if (std.mem.eql(u8, self.items[i], s)) return false;
        }
        if (self.len >= max_dedup) return false; // full — treat as dup
        self.items[self.len] = s;
        self.len += 1;
        return true;
    }
};

/// AP-3: detect whether `addr` is a local followers collection URL.
fn isLocalFollowersCollection(addr: []const u8, local_host: []const u8) bool {
    const prefix = "https://";
    if (!std.mem.startsWith(u8, addr, prefix)) return false;
    if (addr.len <= prefix.len + local_host.len) return false;
    if (!std.mem.startsWith(u8, addr[prefix.len..], local_host)) return false;
    return std.mem.endsWith(u8, addr, "/followers");
}

// ──────────────────────────────────────────────────────────────────────
// Add / Remove (AP-8)
// ──────────────────────────────────────────────────────────────────────

pub const AddRemoveKind = enum { add, remove };
pub const AddRemoveState = enum { start, validate, emit, done };

fn runAddRemove(env: *const Envelope, eff: *SideEffectBuffer, kind: AddRemoveKind) ApError!void {
    var s: AddRemoveState = .start;
    var guard: u32 = 0;
    while (s != .done) : (guard += 1) {
        assertLe(guard, 8);
        switch (s) {
            .start => s = .validate,
            .validate => {
                if (env.activity.object_id.len == 0) return error.BadObject;
                if (env.activity.target.len == 0) return error.BadObject;
                s = .emit;
            },
            .emit => {
                switch (kind) {
                    .add => try eff.push(.{ .collection_add = .{
                        .collection = env.activity.target,
                        .object_iri = env.activity.object_id,
                        .actor = env.activity.actor,
                    } }),
                    .remove => try eff.push(.{ .collection_remove = .{
                        .collection = env.activity.target,
                        .object_iri = env.activity.object_id,
                    } }),
                }
                try eff.push(.{ .store_activity = .{
                    .id = env.activity.id,
                    .actor = env.activity.actor,
                    .kind = if (kind == .add) .add else .remove,
                } });
                try eff.push(.{ .increment_counter = .{ .name = if (kind == .add) "ap.inbox.add" else "ap.inbox.remove" } });
                s = .done;
            },
            .done => unreachableState("AddRemove.done reached in loop body"),
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

test "AP-16: Create{Note} with name + inReplyTo records a poll vote" {
    var rng = Rng.init(2);
    var sc = SimClock.init(0);
    const act = try activity.parse(
        \\{"id":"https://a/x/2","type":"Create","actor":"https://a/voter",
        \\ "object":{"id":"https://a/n/2","type":"Note","name":"Option B","inReplyTo":"https://q/poll/1"}}
    );
    var env = buildEnvelope(act, false, sc.clock(), &rng);
    var eff: SideEffectBuffer = .{};
    try dispatch(&env, &eff);
    var found = false;
    for (eff.slice()) |e| switch (e) {
        .record_poll_vote => |v| {
            try std.testing.expectEqualStrings("https://q/poll/1", v.question_iri);
            try std.testing.expectEqualStrings("Option B", v.option_name);
            try std.testing.expectEqualStrings("https://a/voter", v.actor);
            found = true;
        },
        else => {},
    };
    try std.testing.expect(found);
}

test "AP-23: Create{Note} with attachment[] records media attachments" {
    var rng = Rng.init(3);
    var sc = SimClock.init(0);
    const act = try activity.parse(
        \\{"id":"https://a/x/3","type":"Create","actor":"https://a/u",
        \\ "object":{"id":"https://a/n/3","type":"Note","content":"pic",
        \\  "attachment":[{"type":"Document","mediaType":"image/png","url":"https://a/media/1.png","name":"alt"}]}}
    );
    var env = buildEnvelope(act, false, sc.clock(), &rng);
    var eff: SideEffectBuffer = .{};
    try dispatch(&env, &eff);
    var found = false;
    for (eff.slice()) |e| switch (e) {
        .record_attachment => |a| {
            try std.testing.expectEqualStrings("https://a/n/3", a.object_iri);
            try std.testing.expectEqualStrings("https://a/media/1.png", a.url);
            try std.testing.expectEqualStrings("image/png", a.media_type);
            found = true;
        },
        else => {},
    };
    try std.testing.expect(found);
}

test "AP §7.1.3: Public + local followers collection forwards to followers, Public not delivered" {
    var rng = Rng.init(7);
    var sc = SimClock.init(0);
    const raw =
        \\{"id":"https://a/x/4","type":"Create","actor":"https://a/u",
        \\ "to":["https://www.w3.org/ns/activitystreams#Public"],
        \\ "cc":["https://local.test/users/bob/followers"],
        \\ "object":{"id":"https://a/n/4","type":"Note","content":"hi"}}
    ;
    const act = try activity.parse(raw);
    var env: Envelope = .{
        .activity = act,
        .verified_actor = .{ .iri = act.actor, .is_known_to_us = false },
        .clock = sc.clock(),
        .rng = &rng,
        .local_host = "local.test",
        .raw_body = raw,
    };
    var eff: SideEffectBuffer = .{};
    try dispatch(&env, &eff);

    var forwards: u8 = 0;
    var deliveries: u8 = 0;
    for (eff.slice()) |e| switch (e) {
        .forward_to_followers => |f| {
            try std.testing.expectEqualStrings("https://local.test/users/bob/followers", f.collection_url);
            try std.testing.expectEqualStrings(raw, f.raw_body);
            forwards += 1;
        },
        .enqueue_delivery => deliveries += 1,
        else => {},
    };
    // Public addressing must NOT be enqueued as a fetchable target, and
    // the local followers collection is forwarded rather than delivered.
    try std.testing.expectEqual(@as(u8, 0), deliveries);
    try std.testing.expectEqual(@as(u8, 1), forwards);
}

test "AP §7.1.3: multiple cc followers collections all forward (not just first)" {
    var rng = Rng.init(8);
    var sc = SimClock.init(0);
    const raw =
        \\{"id":"https://a/x/5","type":"Create","actor":"https://a/u",
        \\ "to":["https://local.test/users/alice/followers"],
        \\ "cc":["https://www.w3.org/ns/activitystreams#Public",
        \\       "https://local.test/users/bob/followers",
        \\       "https://local.test/users/carol/followers"],
        \\ "object":{"id":"https://a/n/5","type":"Note","content":"hi all"}}
    ;
    const act = try activity.parse(raw);
    var env: Envelope = .{
        .activity = act,
        .verified_actor = .{ .iri = act.actor, .is_known_to_us = false },
        .clock = sc.clock(),
        .rng = &rng,
        .local_host = "local.test",
        .raw_body = raw,
    };
    var eff: SideEffectBuffer = .{};
    try dispatch(&env, &eff);

    var saw_alice = false;
    var saw_bob = false;
    var saw_carol = false;
    var forwards: u8 = 0;
    for (eff.slice()) |e| switch (e) {
        .forward_to_followers => |f| {
            forwards += 1;
            if (std.mem.eql(u8, f.collection_url, "https://local.test/users/alice/followers")) saw_alice = true;
            if (std.mem.eql(u8, f.collection_url, "https://local.test/users/bob/followers")) saw_bob = true;
            if (std.mem.eql(u8, f.collection_url, "https://local.test/users/carol/followers")) saw_carol = true;
        },
        else => {},
    };
    // One follower collection in `to` + two in `cc` → three forwards.
    try std.testing.expectEqual(@as(u8, 3), forwards);
    try std.testing.expect(saw_alice and saw_bob and saw_carol);
}

test "AP §7.1.3: same followers collection in both to and cc forwards once (dedup)" {
    var rng = Rng.init(9);
    var sc = SimClock.init(0);
    const raw =
        \\{"id":"https://a/x/6","type":"Create","actor":"https://a/u",
        \\ "to":["https://local.test/users/dave/followers"],
        \\ "cc":["https://local.test/users/dave/followers"],
        \\ "object":{"id":"https://a/n/6","type":"Note","content":"dup"}}
    ;
    const act = try activity.parse(raw);
    var env: Envelope = .{
        .activity = act,
        .verified_actor = .{ .iri = act.actor, .is_known_to_us = false },
        .clock = sc.clock(),
        .rng = &rng,
        .local_host = "local.test",
        .raw_body = raw,
    };
    var eff: SideEffectBuffer = .{};
    try dispatch(&env, &eff);

    var forwards: u8 = 0;
    for (eff.slice()) |e| switch (e) {
        .forward_to_followers => forwards += 1,
        else => {},
    };
    try std.testing.expectEqual(@as(u8, 1), forwards);
}

test "recipient scan delivers to remote to+cc entries and dedupes" {
    var rng = Rng.init(10);
    var sc = SimClock.init(0);
    const raw =
        \\{"id":"https://a/x/7","type":"Create","actor":"https://a/u",
        \\ "to":["https://remote.test/users/x","https://www.w3.org/ns/activitystreams#Public"],
        \\ "cc":["https://remote.test/users/y","https://remote.test/users/x"],
        \\ "object":{"id":"https://a/n/7","type":"Note","content":"hi"}}
    ;
    const act = try activity.parse(raw);
    var env: Envelope = .{
        .activity = act,
        .verified_actor = .{ .iri = act.actor, .is_known_to_us = false },
        .clock = sc.clock(),
        .rng = &rng,
        .local_host = "local.test",
        .raw_body = raw,
    };
    var eff: SideEffectBuffer = .{};
    try dispatch(&env, &eff);

    var saw_x = false;
    var saw_y = false;
    var deliveries: u8 = 0;
    for (eff.slice()) |e| switch (e) {
        .enqueue_delivery => |d| {
            deliveries += 1;
            if (std.mem.eql(u8, d.target, "https://remote.test/users/x")) saw_x = true;
            if (std.mem.eql(u8, d.target, "https://remote.test/users/y")) saw_y = true;
        },
        else => {},
    };
    // x appears in both `to` and `cc` → delivered once; Public skipped.
    try std.testing.expectEqual(@as(u8, 2), deliveries);
    try std.testing.expect(saw_x and saw_y);
}

test "bto/bcc are not leaked into recipient handling" {
    var rng = Rng.init(11);
    var sc = SimClock.init(0);
    const raw =
        \\{"id":"https://a/x/8","type":"Create","actor":"https://a/u",
        \\ "to":["https://www.w3.org/ns/activitystreams#Public"],
        \\ "bto":["https://secret.test/users/spy"],
        \\ "bcc":["https://local.test/users/hidden/followers"],
        \\ "object":{"id":"https://a/n/8","type":"Note","content":"private routing"}}
    ;
    const act = try activity.parse(raw);
    // The parser must not capture bto/bcc into the addressing lists.
    try std.testing.expectEqual(@as(u8, 0), act.cc.len);
    for (act.to.slice()) |a| {
        try std.testing.expect(!std.mem.eql(u8, a, "https://secret.test/users/spy"));
        try std.testing.expect(!std.mem.eql(u8, a, "https://local.test/users/hidden/followers"));
    }
    var env: Envelope = .{
        .activity = act,
        .verified_actor = .{ .iri = act.actor, .is_known_to_us = false },
        .clock = sc.clock(),
        .rng = &rng,
        .local_host = "local.test",
        .raw_body = raw,
    };
    var eff: SideEffectBuffer = .{};
    try dispatch(&env, &eff);

    for (eff.slice()) |e| switch (e) {
        .enqueue_delivery => |d| {
            try std.testing.expect(!std.mem.eql(u8, d.target, "https://secret.test/users/spy"));
        },
        .forward_to_followers => |f| {
            // The bcc'd hidden followers collection must not be forwarded.
            try std.testing.expect(!std.mem.eql(u8, f.collection_url, "https://local.test/users/hidden/followers"));
        },
        else => {},
    };
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

test "FEP-c0e0: EmojiReact records like with reaction emoji" {
    var rng = Rng.init(7);
    var sc = SimClock.init(0);
    const act = try activity.parse(
        \\{"id":"r1","type":"EmojiReact","actor":"https://a/u","object":"https://a/p","content":"🦊"}
    );
    try std.testing.expect(act.activity_type == .like);
    var env = buildEnvelope(act, false, sc.clock(), &rng);
    var eff: SideEffectBuffer = .{};
    try dispatch(&env, &eff);
    var found = false;
    for (eff.slice()) |e| switch (e) {
        .record_like => |l| {
            try std.testing.expectEqualStrings("https://a/u", l.actor);
            try std.testing.expectEqualStrings("https://a/p", l.object);
            try std.testing.expectEqualStrings("🦊", l.reaction);
            found = true;
        },
        else => {},
    };
    try std.testing.expect(found);
}

test "FEP-c0e0: plain Like carries empty reaction" {
    var rng = Rng.init(8);
    var sc = SimClock.init(0);
    const act = try activity.parse(
        \\{"id":"l9","type":"Like","actor":"https://a/u","object":"https://a/p"}
    );
    var env = buildEnvelope(act, false, sc.clock(), &rng);
    var eff: SideEffectBuffer = .{};
    try dispatch(&env, &eff);
    for (eff.slice()) |e| switch (e) {
        .record_like => |l| try std.testing.expectEqual(@as(usize, 0), l.reaction.len),
        else => {},
    };
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
