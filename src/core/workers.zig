//! Bounded worker pool for blocking I/O.
//!
//! Tiger Style philosophy: the request hot path never blocks on I/O that
//! could take more than a few microseconds. Anything that may stall —
//! HTTP key fetches (ActivityPub HTTP-signature key resolution), DID
//! document resolution, blocking DNS, RSA signature verification — gets
//! handed to this pool. The producer (a handler or plugin callback)
//! either polls the returned `Completion` or blocks on it via the
//! `wait` helper, depending on whether the call site can spare the
//! thread.
//!
//! Shape:
//!
//!   * A `Pool(N)` owns `N` worker threads (capped at
//!     `limits.worker_pool_size`) plus a single
//!     `BoundedMpsc(Job, limits.max_queued_jobs)`.
//!
//!   * Each worker thread reserves its own `WorkerArena` of
//!     `limits.worker_arena_bytes` bytes that the job receives as a
//!     scratch allocator. The arena is `reset()` between jobs — the
//!     job sees a fresh, zeroed allocator with predictable capacity.
//!
//!   * Jobs are plain `Job` values: a function pointer, a context
//!     pointer, and an optional `*Completion` the worker signals when
//!     the job finishes (or fails). Errors are caught and reported
//!     through the completion result.
//!
//!   * `submit` is non-blocking: it returns `error.Full` if the queue
//!     is saturated. Callers MUST surface this to the user (429, retry,
//!     dead-letter) rather than spinning silently.
//!
//!   * `stop()` closes the queue, wakes every worker, waits for them to
//!     drain in-flight jobs, joins them. Idempotent — a second call is
//!     a no-op.
//!
//! No allocator is required at runtime — the pool's storage is part of
//! its type, sized at comptime. The composition root heap-allocates the
//! Pool struct (its arenas push the size above stack limits) but no
//! per-job allocations occur after `start()` returns.

const std = @import("std");
const builtin = @import("builtin");

const limits = @import("limits.zig");
const errors = @import("errors.zig");
const static = @import("static.zig");
const arena_mod = @import("arena.zig");
const assert_mod = @import("assert.zig");

const Arena = arena_mod.Arena;
const assert = assert_mod.assert;
const assertLe = assert_mod.assertLe;
const BoundedMpsc = static.BoundedMpsc;

/// `std.Thread.sleep` was removed in Zig 0.16. Use the libc syscall
/// directly. Tiger Style: every place a thread parks is bounded.
fn sleepNs(ns: u64) void {
    var req: std.c.timespec = .{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    _ = std.c.nanosleep(&req, &req);
}

/// Signature every job runs as. `arena` is freshly reset before the
/// call; allocations made here are valid only until the job returns.
pub const RunFn = *const fn (ctx: *anyopaque, arena: *Arena) anyerror!void;

/// The error a job's `Completion.result` can hold. Workers wrap any
/// non-`anyerror` returns from the user's `RunFn` into this set so
/// callers can pattern-match exhaustively.
pub const JobError = error{
    /// The job ran, but its `RunFn` returned an error. The wrapped
    /// error name is recorded in `Completion.error_name` for logging.
    JobFailed,
    /// The pool was stopped before the job could run.
    Cancelled,
    /// The submitter waited longer than `pool_completion_timeout_ns`.
    Timeout,
};

/// Backpressure surface when `submit` cannot enqueue.
pub const SubmitError = error{
    /// The job queue is at `limits.max_queued_jobs`. Caller must retry
    /// or shed.
    Full,
    /// The pool is stopped / shutting down.
    Stopped,
};

/// One-shot completion signal. The submitter creates this on its own
/// stack (or in its arena) and threads a pointer through the `Job`.
/// The worker fills `result` and flips `done` exactly once.
pub const Completion = struct {
    done: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    /// Set by the worker before flipping `done`. `null` on success,
    /// `JobError` on failure.
    err: ?JobError = null,
    /// Best-effort copy of the user error name. Truncated to 32 bytes
    /// to keep `Completion` stack-friendly.
    error_name_buf: [32]u8 = undefined,
    error_name_len: u8 = 0,

    pub fn init() Completion {
        return .{};
    }

    pub fn isDone(self: *const Completion) bool {
        return self.done.load(.acquire);
    }

    /// Return the worker's result. Must only be called after `isDone()`
    /// is true (or `waitFor` returned `null`).
    pub fn result(self: *const Completion) JobError!void {
        assert(self.done.load(.acquire));
        if (self.err) |e| return e;
    }

    pub fn errorName(self: *const Completion) []const u8 {
        return self.error_name_buf[0..self.error_name_len];
    }

    /// Block until `done` flips or `timeout_ns` elapses (whichever first).
    /// Returns `error.Timeout` when the deadline expires; otherwise
    /// propagates `result()`.
    pub fn waitFor(self: *Completion, timeout_ns: u64) JobError!void {
        // Use a bounded back-off spin. The pool generally completes a
        // job in well under a millisecond; we start at 1 µs and ramp.
        var slept: u64 = 0;
        var backoff_ns: u64 = 1_000;
        while (slept < timeout_ns) {
            if (self.done.load(.acquire)) return self.result();
            sleepNs(backoff_ns);
            slept += backoff_ns;
            if (backoff_ns < 1_000_000) backoff_ns *= 2; // cap at 1 ms
        }
        return error.Timeout;
    }

    /// Convenience wrapper around `waitFor` with the default timeout.
    pub fn wait(self: *Completion) JobError!void {
        return self.waitFor(limits.pool_completion_timeout_ns);
    }

    fn fail(self: *Completion, kind: JobError, name: []const u8) void {
        assert(!self.done.load(.acquire));
        self.err = kind;
        const copy_len: u8 = @intCast(@min(name.len, self.error_name_buf.len));
        @memcpy(self.error_name_buf[0..copy_len], name[0..copy_len]);
        self.error_name_len = copy_len;
        self.done.store(true, .release);
    }

    fn succeed(self: *Completion) void {
        assert(!self.done.load(.acquire));
        self.err = null;
        self.error_name_len = 0;
        self.done.store(true, .release);
    }
};

/// A single unit of work enqueued onto the pool.
pub const Job = struct {
    run: RunFn,
    ctx: *anyopaque,
    completion: ?*Completion,
};

/// The compile-time-sized pool. `size_const` is the number of worker
/// threads — capped at `limits.worker_pool_size`. Each worker owns a
/// `worker_arena_bytes` slab.
pub fn Pool(comptime size_const: u32) type {
    comptime {
        if (size_const == 0) @compileError("Pool size must be > 0");
        if (size_const > limits.worker_pool_size) {
            @compileError("Pool size exceeds limits.worker_pool_size");
        }
    }

    return struct {
        const Self = @This();
        pub const worker_count: u32 = size_const;

        const Queue = BoundedMpsc(Job, limits.max_queued_jobs);

        queue: Queue = Queue.init(),
        workers: [size_const]Worker = undefined,
        threads: [size_const]?std.Thread = [_]?std.Thread{null} ** size_const,
        running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        // Diagnostic counter — total jobs successfully drained from the
        // queue across all workers. Useful in tests to assert progress.
        jobs_completed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

        pub const Worker = struct {
            id: u32,
            arena_buf: [limits.worker_arena_bytes]u8 = undefined,
            arena: Arena = undefined,
            owner: *Self = undefined,
        };

        /// Prime the worker structs in place. Call once on the heap-
        /// allocated `Pool` before `start()`.
        pub fn initInPlace(self: *Self) void {
            self.queue = Queue.init();
            self.running = std.atomic.Value(bool).init(false);
            self.jobs_completed = std.atomic.Value(u64).init(0);
            var i: u32 = 0;
            while (i < size_const) : (i += 1) {
                self.workers[i] = .{ .id = i };
                self.workers[i].arena = Arena.init(&self.workers[i].arena_buf);
                self.workers[i].owner = self;
                self.threads[i] = null;
            }
        }

        /// Spawn the worker threads. Must be called exactly once after
        /// `initInPlace`. Subsequent calls panic.
        pub fn start(self: *Self) !void {
            assert(!self.running.load(.acquire));
            self.running.store(true, .release);
            var i: u32 = 0;
            while (i < size_const) : (i += 1) {
                self.threads[i] = try std.Thread.spawn(.{}, workerMain, .{&self.workers[i]});
            }
        }

        /// Submit a job. Returns `error.Full` when the queue is at
        /// capacity, `error.Stopped` when the pool has begun shutdown.
        /// Never blocks.
        pub fn submit(self: *Self, job: Job) SubmitError!void {
            if (!self.running.load(.acquire)) return error.Stopped;
            self.queue.push(job) catch |err| switch (err) {
                error.Full => return error.Full,
                error.Closed => return error.Stopped,
            };
        }

        /// Stop the pool. Closes the queue (no further submits), waits
        /// for in-flight jobs to drain, joins worker threads. Pending
        /// jobs that have not yet been picked up have their completions
        /// (if any) cancelled. Idempotent.
        pub fn stop(self: *Self) void {
            if (!self.running.swap(false, .acq_rel)) return;
            self.queue.close();
            // Cancel undelivered jobs so submitters waiting on their
            // completions don't deadlock. Bounded by queue capacity.
            var drained: u32 = 0;
            while (drained <= limits.max_queued_jobs) : (drained += 1) {
                const maybe = self.queue.tryPop();
                if (maybe == null) break;
                const j = maybe.?;
                if (j.completion) |c| c.fail(error.Cancelled, "Cancelled");
            }
            assertLe(drained, limits.max_queued_jobs);
            // Join. Worker loops exit when `running` is false AND queue
            // is empty.
            var i: u32 = 0;
            while (i < size_const) : (i += 1) {
                if (self.threads[i]) |t| {
                    t.join();
                    self.threads[i] = null;
                }
            }
        }

        /// Diagnostic: total jobs the pool has completed since start.
        pub fn completedCount(self: *const Self) u64 {
            return self.jobs_completed.load(.acquire);
        }

        fn workerMain(w: *Worker) void {
            const pool = w.owner;
            // Tiger Style: bounded outer loop. Outer iterations are not
            // a "real" loop bound — workers run as long as the pool is
            // up — but every step inside is bounded.
            while (true) {
                const maybe = pool.queue.tryPop();
                if (maybe) |job| {
                    runOne(w, job);
                    _ = pool.jobs_completed.fetchAdd(1, .release);
                    continue;
                }
                if (!pool.running.load(.acquire)) {
                    // Final drain on shutdown: another producer may have
                    // raced an item in just before `close()`. Try once
                    // more, then exit.
                    if (pool.queue.tryPop()) |job| {
                        runOne(w, job);
                        _ = pool.jobs_completed.fetchAdd(1, .release);
                        continue;
                    }
                    return;
                }
                // No work right now. Sleep briefly. Tiger Style: bounded
                // sleep, not unbounded park — gives the event loop a
                // predictable upper bound on wake-up latency.
                sleepNs(100 * std.time.ns_per_us);
            }
        }

        fn runOne(w: *Worker, job: Job) void {
            // Fresh arena for every job. Reset before, not after — this
            // way a panicking worker leaves the arena empty for the
            // next job.
            w.arena.reset();
            const res = job.run(job.ctx, &w.arena);
            if (job.completion) |c| {
                if (res) |_| {
                    c.succeed();
                } else |err| {
                    c.fail(error.JobFailed, @errorName(err));
                }
            } else {
                // Fire-and-forget. We swallow the error; the user opted
                // out of receiving it by passing a null completion.
                _ = res catch {};
            }
        }
    };
}

// ──────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────

const testing = std.testing;

const TestPool = Pool(2);

const Counter = struct {
    value: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
};

fn incJob(ctx: *anyopaque, _: *Arena) anyerror!void {
    const c: *Counter = @ptrCast(@alignCast(ctx));
    _ = c.value.fetchAdd(1, .acq_rel);
}

fn failingJob(_: *anyopaque, _: *Arena) anyerror!void {
    return error.SomethingBroke;
}

const AllocCheck = struct {
    written: ?[]u8 = null,
    last_used: usize = 0,
};

fn allocJob(ctx: *anyopaque, arena: *Arena) anyerror!void {
    const ac: *AllocCheck = @ptrCast(@alignCast(ctx));
    const alloc = arena.allocator();
    const buf = try alloc.alloc(u8, 1024);
    for (buf, 0..) |*b, i| b.* = @intCast(i & 0xff);
    ac.written = buf;
    ac.last_used = arena.used();
}

test "Pool runs a single job and signals completion" {
    var pool: TestPool = undefined;
    pool.initInPlace();
    try pool.start();
    defer pool.stop();

    var counter: Counter = .{};
    var c: Completion = .init();
    try pool.submit(.{ .run = incJob, .ctx = &counter, .completion = &c });
    try c.wait();
    try testing.expectEqual(@as(u32, 1), counter.value.load(.acquire));
}

test "Pool failure: completion records JobFailed + error name" {
    var pool: TestPool = undefined;
    pool.initInPlace();
    try pool.start();
    defer pool.stop();

    var c: Completion = .init();
    try pool.submit(.{ .run = failingJob, .ctx = @ptrFromInt(0xcafe), .completion = &c });
    const got = c.wait();
    try testing.expectError(error.JobFailed, got);
    try testing.expectEqualStrings("SomethingBroke", c.errorName());
}

test "Pool fire-and-forget swallows errors" {
    var pool: TestPool = undefined;
    pool.initInPlace();
    try pool.start();
    defer pool.stop();

    // Submit a failing job with no completion. Should not crash.
    try pool.submit(.{ .run = failingJob, .ctx = @ptrFromInt(0xfe), .completion = null });
    // Submit a successful job we *can* wait on, to be sure the worker
    // is still processing.
    var counter: Counter = .{};
    var c: Completion = .init();
    try pool.submit(.{ .run = incJob, .ctx = &counter, .completion = &c });
    try c.wait();
    try testing.expectEqual(@as(u32, 1), counter.value.load(.acquire));
}

test "Pool concurrent producers all see jobs run" {
    var pool: TestPool = undefined;
    pool.initInPlace();
    try pool.start();
    defer pool.stop();

    var counter: Counter = .{};
    const producer = struct {
        fn run(p: *TestPool, ctr: *Counter, n: u32) void {
            var i: u32 = 0;
            while (i < n) : (i += 1) {
                // Spin on Full; never on Stopped.
                while (true) {
                    if (p.submit(.{ .run = incJob, .ctx = ctr, .completion = null })) |_| {
                        break;
                    } else |err| switch (err) {
                        error.Full => sleepNs(10 * std.time.ns_per_us),
                        error.Stopped => return,
                    }
                }
            }
        }
    };

    const t1 = try std.Thread.spawn(.{}, producer.run, .{ &pool, &counter, @as(u32, 100) });
    const t2 = try std.Thread.spawn(.{}, producer.run, .{ &pool, &counter, @as(u32, 100) });
    t1.join();
    t2.join();

    // Drain — wait until both producers' inserts have been processed.
    var spin: u32 = 0;
    while (counter.value.load(.acquire) < 200 and spin < 10_000) : (spin += 1) {
        sleepNs(100 * std.time.ns_per_us);
    }
    try testing.expectEqual(@as(u32, 200), counter.value.load(.acquire));
}

test "Pool stop drains in-flight and cancels queued" {
    // Use a sleeping job so we can observe the queue building up.
    const Slow = struct {
        delay_ns: u64,
        seen: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
        fn job(ctx: *anyopaque, _: *Arena) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            sleepNs(self.delay_ns);
            _ = self.seen.fetchAdd(1, .acq_rel);
        }
    };

    var pool: Pool(1) = undefined;
    pool.initInPlace();
    try pool.start();

    var s: Slow = .{ .delay_ns = 5 * std.time.ns_per_ms };

    // Enqueue more than one job so at least one sits in the queue when
    // we stop. Use bounded loop.
    var completions: [4]Completion = .{ .init(), .init(), .init(), .init() };
    var i: u8 = 0;
    while (i < completions.len) : (i += 1) {
        try pool.submit(.{ .run = Slow.job, .ctx = &s, .completion = &completions[i] });
    }

    // Give the single worker time to pick up the first job (the job
    // sleeps 5ms — we wait 1ms before stopping so we observe a queue
    // with at least one cancelled entry).
    sleepNs(1 * std.time.ns_per_ms);
    pool.stop();

    // After stop returns, every completion must be signalled: the job
    // the worker picked before stop runs to completion; the rest get
    // Cancelled.
    var ran: u32 = 0;
    var cancelled: u32 = 0;
    for (&completions) |*c| {
        if (!c.isDone()) return error.TestExpectedAllDone;
        if (c.result()) |_| ran += 1 else |e| switch (e) {
            error.Cancelled => cancelled += 1,
            else => return error.TestUnexpectedError,
        }
    }
    try testing.expect(ran >= 1);
    try testing.expect(cancelled >= 1);
    try testing.expectEqual(@as(u32, completions.len), ran + cancelled);
}

test "Pool worker arena resets between jobs" {
    var pool: Pool(1) = undefined;
    pool.initInPlace();
    try pool.start();
    defer pool.stop();

    var ac1: AllocCheck = .{};
    var ac2: AllocCheck = .{};
    var c1: Completion = .init();
    var c2: Completion = .init();

    try pool.submit(.{ .run = allocJob, .ctx = &ac1, .completion = &c1 });
    try c1.wait();
    try pool.submit(.{ .run = allocJob, .ctx = &ac2, .completion = &c2 });
    try c2.wait();

    // Both jobs allocated 1024 bytes from a fresh arena. Without a
    // reset between jobs, the second job's `used` would be ≥ 2048.
    try testing.expect(ac1.last_used >= 1024);
    try testing.expect(ac2.last_used >= 1024);
    try testing.expect(ac2.last_used == ac1.last_used);
}

test "Pool submit rejects with Stopped after stop" {
    var pool: TestPool = undefined;
    pool.initInPlace();
    try pool.start();
    pool.stop();

    var ctr: Counter = .{};
    const got = pool.submit(.{ .run = incJob, .ctx = &ctr, .completion = null });
    try testing.expectError(error.Stopped, got);
}

test "Pool stop is idempotent" {
    var pool: TestPool = undefined;
    pool.initInPlace();
    try pool.start();
    pool.stop();
    pool.stop(); // must not crash, must not double-join.
}

test "Pool completion timeout returns Timeout" {
    var pool: Pool(1) = undefined;
    pool.initInPlace();
    try pool.start();
    defer pool.stop();

    const Slow = struct {
        fn job(_: *anyopaque, _: *Arena) anyerror!void {
            sleepNs(50 * std.time.ns_per_ms);
        }
    };

    var c: Completion = .init();
    try pool.submit(.{ .run = Slow.job, .ctx = @ptrFromInt(0x1), .completion = &c });
    // 1 ms timeout — much shorter than the job. Expect Timeout.
    const r = c.waitFor(1 * std.time.ns_per_ms);
    try testing.expectError(error.Timeout, r);
    // Eventually the job *does* finish; drain so `defer pool.stop()`
    // doesn't race with an in-flight job's completion.
    try c.wait();
}

test "Pool completedCount tracks drained jobs" {
    var pool: Pool(2) = undefined;
    pool.initInPlace();
    try pool.start();
    defer pool.stop();

    var counter: Counter = .{};
    const n: u32 = 50;
    var completions: [50]Completion = undefined;
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        completions[i] = .init();
        try pool.submit(.{ .run = incJob, .ctx = &counter, .completion = &completions[i] });
    }
    // Wait on every completion. After this loop the pool has drained
    // all n jobs.
    i = 0;
    while (i < n) : (i += 1) {
        try completions[i].wait();
    }
    try testing.expectEqual(@as(u64, n), pool.completedCount());
    try testing.expectEqual(@as(u32, n), counter.value.load(.acquire));
}
