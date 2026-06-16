//! Phase 5: pluggable job-queue provider (the Mastodon/Sidekiq analog).
//!
//! A `QueueProvider` is a process-global vtable in the same shape as
//! `core.account.Backend`, `core.email.Sender`, and
//! `core.storage.Backend`: a `setGlobal`/`global`/`resetGlobal` triple
//! plus a small method set. The default implementation
//! (`core.queue.DbQueue`, in `queue/db_queue.zig`) is DB-backed and
//! preserves the exact semantics of the legacy ActivityPub outbox
//! (pending / next_attempt_at / state machine, exponential backoff,
//! dead-letter). A future Redis / NATS / Kafka provider drops in by
//! implementing the same vtable — no caller changes.
//!
//! Topics
//! ------
//! A *topic* is an opaque queue name (e.g. `"ap_outbox"`). The provider
//! maps each topic onto its own backing store. `DbQueue` maps the
//! `ap_outbox` topic onto the existing `ap_federation_outbox` /
//! `ap_federation_dead_letter` tables (see `queue/db_queue.zig` for the
//! full column mapping).
//!
//! Tiger Style
//! -----------
//!   * `Job` is a fixed-size struct — no heap, no slices into provider
//!     memory. The id + key + payload live in inline bounded buffers,
//!     so a claimed job outlives the statement / connection it came
//!     from (the worker can run an arbitrarily long delivery hook
//!     without holding a cursor).
//!   * `dequeueBatch` fills a caller-owned `[]Job` — the worker sizes
//!     the batch with a stack array bounded by
//!     `limits.max_inflight_deliveries`.
//!   * No allocation on enqueue / dequeue / ack / nack / deadLetter.

const std = @import("std");
const limits = @import("limits.zig");
const assert = @import("assert.zig").assert;

/// Errors a queue provider can surface. Kept self-contained (not tied to
/// `FedError`) so non-federation callers and non-SQLite providers can
/// implement the interface cleanly. The AP delivery seam maps these
/// onto `FedError.OutboxFull` at its boundary so existing call sites are
/// unchanged.
pub const Error = error{
    /// The backing store is at capacity / rejected the write.
    QueueFull,
    /// A backend operation failed (prepare/step/connection).
    BackendFailed,
    /// A job / payload exceeded the provider's bounded buffers.
    PayloadTooLarge,
};

/// Maximum inline bytes for a job's topic-routing key. For the AP topic
/// this carries `target_inbox` (the delivery URL). Matches the legacy
/// outbox worker's `max_inbox_bytes`.
pub const max_key_bytes: usize = 512;

/// Maximum inline payload bytes. For the AP topic this is the AP
/// activity JSON (bto/bcc already stripped). Matches the legacy outbox
/// worker's `max_payload_inline_bytes`. Payloads larger than this are
/// rejected at enqueue with `PayloadTooLarge` rather than silently
/// truncated — a dropped recipient is worse than a visible backpressure
/// error.
pub const max_payload_bytes: usize = 8 * 1024;

/// Maximum inline bytes for the provider-specific auxiliary metadata a
/// topic needs threaded through the claim. For the AP topic this is the
/// signing `key_id`. Matches the legacy outbox worker's
/// `max_key_id_bytes`.
pub const max_meta_bytes: usize = 256;

/// A claimed unit of work. Fixed-size: the id identifies the backing
/// row so the provider can ack/nack/dead-letter it, and the bounded
/// inline buffers carry the payload so the worker need not re-read.
///
/// `attempts` is the number of prior delivery attempts (0 on first
/// claim); the worker uses it to compute the next backoff and to decide
/// when to dead-letter. `meta` is provider/topic-specific (the AP topic
/// stores `key_id` here).
pub const Job = struct {
    /// Backing-store row id (SQLite rowid for `DbQueue`). Opaque to
    /// callers other than as a handle passed back to ack/nack/deadLetter.
    id: i64 = 0,
    attempts: u32 = 0,

    key_buf: [max_key_bytes]u8 = undefined,
    key_len: u16 = 0,
    payload_buf: [max_payload_bytes]u8 = undefined,
    payload_len: u32 = 0,
    meta_buf: [max_meta_bytes]u8 = undefined,
    meta_len: u16 = 0,

    pub fn key(self: *const Job) []const u8 {
        return self.key_buf[0..self.key_len];
    }
    pub fn payload(self: *const Job) []const u8 {
        return self.payload_buf[0..self.payload_len];
    }
    pub fn meta(self: *const Job) []const u8 {
        return self.meta_buf[0..self.meta_len];
    }

    /// Populate the bounded buffers from caller slices. Returns
    /// `PayloadTooLarge` if any slice overflows its buffer — providers
    /// call this when materializing a claimed row so the bound is
    /// enforced in one place.
    pub fn set(self: *Job, k: []const u8, p: []const u8, m: []const u8) Error!void {
        if (k.len > max_key_bytes) return error.PayloadTooLarge;
        if (p.len > max_payload_bytes) return error.PayloadTooLarge;
        if (m.len > max_meta_bytes) return error.PayloadTooLarge;
        @memcpy(self.key_buf[0..k.len], k);
        self.key_len = @intCast(k.len);
        @memcpy(self.payload_buf[0..p.len], p);
        self.payload_len = @intCast(p.len);
        @memcpy(self.meta_buf[0..m.len], m);
        self.meta_len = @intCast(m.len);
    }
};

// Compile-time guard: the worker batches jobs on the stack, so a single
// `Job` must stay reasonably bounded. (8 KiB payload + ~768 B overhead.)
comptime {
    assert(@sizeOf(Job) <= 16 * 1024);
}

/// The provider vtable. Same erased-pointer shape as `storage.Backend`.
pub const QueueProvider = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Append a job to `topic`. `key`/`payload`/`meta` are copied by
        /// the provider; the caller retains ownership. `not_before_unix`
        /// is the earliest Unix-seconds time the job may be claimed
        /// (`now` for "eligible immediately").
        enqueue: *const fn (
            ptr: *anyopaque,
            topic: []const u8,
            key: []const u8,
            payload: []const u8,
            meta: []const u8,
            not_before_unix: i64,
        ) Error!void,

        /// Claim up to `out.len` due jobs from `topic` (those whose
        /// not-before time is `<= now_unix`), oldest-first. Fills `out`
        /// and returns the count claimed.
        dequeueBatch: *const fn (
            ptr: *anyopaque,
            topic: []const u8,
            now_unix: i64,
            out: []Job,
        ) Error!usize,

        /// Mark a successfully processed job done (or delete it).
        ack: *const fn (ptr: *anyopaque, topic: []const u8, job: *const Job) Error!void,

        /// Reschedule a failed job for retry at `retry_at_unix`,
        /// recording one more attempt.
        nack: *const fn (
            ptr: *anyopaque,
            topic: []const u8,
            job: *const Job,
            retry_at_unix: i64,
        ) Error!void,

        /// Move a job to the dead-letter store with a reason string.
        deadLetter: *const fn (
            ptr: *anyopaque,
            topic: []const u8,
            job: *const Job,
            reason: []const u8,
        ) Error!void,
    };

    pub fn enqueue(
        self: QueueProvider,
        topic: []const u8,
        key: []const u8,
        payload: []const u8,
        meta: []const u8,
        not_before_unix: i64,
    ) Error!void {
        return self.vtable.enqueue(self.ptr, topic, key, payload, meta, not_before_unix);
    }

    pub fn dequeueBatch(
        self: QueueProvider,
        topic: []const u8,
        now_unix: i64,
        out: []Job,
    ) Error!usize {
        return self.vtable.dequeueBatch(self.ptr, topic, now_unix, out);
    }

    pub fn ack(self: QueueProvider, topic: []const u8, job: *const Job) Error!void {
        return self.vtable.ack(self.ptr, topic, job);
    }

    pub fn nack(self: QueueProvider, topic: []const u8, job: *const Job, retry_at_unix: i64) Error!void {
        return self.vtable.nack(self.ptr, topic, job, retry_at_unix);
    }

    pub fn deadLetter(self: QueueProvider, topic: []const u8, job: *const Job, reason: []const u8) Error!void {
        return self.vtable.deadLetter(self.ptr, topic, job, reason);
    }
};

// ──────────────────────────────────────────────────────────────────────
// Well-known topics
// ──────────────────────────────────────────────────────────────────────

/// The ActivityPub federation delivery outbox topic. `DbQueue` routes
/// this onto `ap_federation_outbox` / `ap_federation_dead_letter`.
pub const topic_ap_outbox: []const u8 = "ap_outbox";

// ──────────────────────────────────────────────────────────────────────
// Process global
// ──────────────────────────────────────────────────────────────────────

var global_provider: ?QueueProvider = null;

/// Install the process-global queue provider. The composition root calls
/// this once at boot before any worker starts.
pub fn setGlobal(p: QueueProvider) void {
    global_provider = p;
}

/// The installed global provider, or `null` if none is wired. Callers on
/// the enqueue path treat `null` as a configuration error.
pub fn global() ?QueueProvider {
    return global_provider;
}

pub fn resetGlobal() void {
    global_provider = null;
}

// Re-export the default DB-backed implementation + its schema migration.
pub const DbQueue = @import("queue/db_queue.zig").DbQueue;
pub const db_queue_migration = @import("queue/db_queue.zig").migration;

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "Job.set rejects oversized slices and round-trips" {
    var j: Job = .{};
    try j.set("https://a/inbox", "{\"id\":\"x\"}", "kid1");
    try testing.expectEqualStrings("https://a/inbox", j.key());
    try testing.expectEqualStrings("{\"id\":\"x\"}", j.payload());
    try testing.expectEqualStrings("kid1", j.meta());

    var big: [max_payload_bytes + 1]u8 = undefined;
    @memset(&big, 'x');
    try testing.expectError(error.PayloadTooLarge, j.set("k", &big, "m"));
}

test "global set/get/reset" {
    resetGlobal();
    try testing.expect(global() == null);
    const Dummy = struct {
        fn enq(_: *anyopaque, _: []const u8, _: []const u8, _: []const u8, _: []const u8, _: i64) Error!void {}
        fn deq(_: *anyopaque, _: []const u8, _: i64, _: []Job) Error!usize {
            return 0;
        }
        fn ack(_: *anyopaque, _: []const u8, _: *const Job) Error!void {}
        fn nack(_: *anyopaque, _: []const u8, _: *const Job, _: i64) Error!void {}
        fn dead(_: *anyopaque, _: []const u8, _: *const Job, _: []const u8) Error!void {}
    };
    const vt = QueueProvider.VTable{
        .enqueue = Dummy.enq,
        .dequeueBatch = Dummy.deq,
        .ack = Dummy.ack,
        .nack = Dummy.nack,
        .deadLetter = Dummy.dead,
    };
    var dummy: u8 = 0;
    setGlobal(.{ .ptr = &dummy, .vtable = &vt });
    try testing.expect(global() != null);
    resetGlobal();
    try testing.expect(global() == null);
}

test {
    _ = @import("queue/db_queue.zig");
    // zorm messaging bridges (stream.Sink -> zorm.Sink, this -> zorm.Queue).
    _ = @import("zorm_messaging.zig");
}
