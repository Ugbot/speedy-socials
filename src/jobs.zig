const std = @import("std");
const database = @import("database.zig");
const activitypub = @import("activitypub.zig");

pub const JobType = enum {
    deliver_activity, // Deliver ActivityPub activities to remote servers
    process_inbox, // Process incoming federation messages
    send_email, // Send email notifications
    update_search_index, // Update search indexes
    cleanup_media, // Clean up old media files
    process_media, // Process uploaded media (resize, etc.)
    calculate_trends, // Calculate trending hashtags
};

pub const JobPriority = enum {
    low,
    normal,
    high,
    critical,
};

pub const JobStatus = enum {
    pending,
    running,
    completed,
    failed,
    cancelled,
};

pub const Job = struct {
    id: []const u8,
    type: JobType,
    priority: JobPriority,
    status: JobStatus,
    payload: []const u8, // JSON payload
    created_at: i64,
    scheduled_for: i64,
    started_at: ?i64 = null,
    completed_at: ?i64 = null,
    attempts: u32 = 0,
    max_attempts: u32 = 3,
    last_error: ?[]const u8 = null,

    pub fn deinit(self: *Job, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.payload);
        if (self.last_error) |err| allocator.free(err);
    }
};

// Job queue implementation
pub const JobQueue = struct {
    allocator: std.mem.Allocator,
    db: *database.Database,
    workers: std.array_list.AlignedManaged(JobWorker, null),
    mutex: std.Thread.Mutex,
    cond: std.Thread.Condition,

    pub const JobWorker = struct {
        thread: std.Thread,
        running: bool = true,
    };

    pub fn init(allocator: std.mem.Allocator, db: *database.Database) JobQueue {
        return JobQueue{
            .allocator = allocator,
            .db = db,
            .workers = std.array_list.AlignedManaged(JobWorker, null).init(allocator),
            .mutex = std.Thread.Mutex{},
            .cond = std.Thread.Condition{},
        };
    }

    pub fn deinit(self: *JobQueue) void {
        self.mutex.lock();
        for (self.workers.items) |*worker| {
            worker.running = false;
        }
        self.cond.broadcast();
        self.mutex.unlock();

        // Wait for workers to finish
        for (self.workers.items) |worker| {
            worker.thread.join();
        }

        self.workers.deinit();
    }

    // Start worker threads
    pub fn startWorkers(self: *JobQueue, num_workers: u32) !void {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (0..num_workers) |_| {
            const worker = JobWorker{
                .thread = try std.Thread.spawn(.{}, JobQueue.workerLoop, .{self}),
            };
            try self.workers.append(worker);
        }

        std.debug.print("Started {} job workers\n", .{num_workers});
    }

    // Enqueue a new job
    pub fn enqueue(self: *JobQueue, job_type: JobType, priority: JobPriority, payload: []const u8) ![]const u8 {
        const job_id = try generateJobId(self.allocator);
        defer self.allocator.free(job_id);

        const now = std.time.timestamp();

        // Insert job into database
        try self.db.exec(
            \\INSERT INTO jobs (id, type, priority, status, payload, created_at, scheduled_for, max_attempts)
            \\VALUES (?, ?, ?, 'pending', ?, ?, ?, 3)
        , .{}, .{
            job_id,
            @tagName(job_type),
            @tagName(priority),
            payload,
            now,
            now,
        });

        // Signal workers that there's work to do
        self.cond.signal();

        return self.allocator.dupe(u8, job_id);
    }

    // Schedule a job for later execution
    pub fn schedule(self: *JobQueue, job_type: JobType, priority: JobPriority, payload: []const u8, delay_seconds: i64) ![]const u8 {
        const job_id = try generateJobId(self.allocator);
        defer self.allocator.free(job_id);

        const now = std.time.timestamp();
        const scheduled_for = now + delay_seconds;

        try self.db.exec(
            \\INSERT INTO jobs (id, type, priority, status, payload, created_at, scheduled_for, max_attempts)
            \\VALUES (?, ?, ?, 'pending', ?, ?, ?, 3)
        , .{}, .{
            job_id,
            @tagName(job_type),
            @tagName(priority),
            payload,
            now,
            scheduled_for,
        });

        return self.allocator.dupe(u8, job_id);
    }

    // Worker thread function
    fn workerLoop(self: *JobQueue) void {
        while (true) {
            self.mutex.lock();

            // Check if we should stop
            var should_run = false;
            for (self.workers.items) |worker| {
                if (worker.running) {
                    should_run = true;
                    break;
                }
            }

            if (!should_run) {
                self.mutex.unlock();
                break;
            }

            // Get next job
            const job = self.getNextJob() catch |err| {
                std.debug.print("Error getting next job: {}\n", .{err});
                self.mutex.unlock();
                std.Thread.sleep(1000000000); // 1 second
                continue;
            };

            self.mutex.unlock();

            if (job) |j| {
                // Process the job
                self.processJob(j) catch |err| {
                    std.debug.print("Error processing job {s}: {any}\n", .{ j.id, err });
                    self.failJob(j.id, @errorName(err)) catch {};
                };
            } else {
                // No jobs available, wait
                self.mutex.lock();
                self.cond.timedWait(&self.mutex, 5000000000) catch {}; // 5 second timeout
                self.mutex.unlock();
            }
        }

        std.debug.print("Job worker exiting\n", .{});
    }

    fn getNextJob(self: *JobQueue) !?Job {
        const now = std.time.timestamp();

        const row = try self.db.oneAlloc(struct { id: []const u8, type_str: []const u8, priority_str: []const u8, payload: []const u8, attempts: u32 }, self.allocator,
            \\SELECT id, type, priority, payload, attempts
            \\FROM jobs
            \\WHERE status = 'pending'
            \\  AND scheduled_for <= ?
            \\  AND attempts < max_attempts
            \\ORDER BY
            \\  CASE priority
            \\    WHEN 'critical' THEN 1
            \\    WHEN 'high' THEN 2
            \\    WHEN 'normal' THEN 3
            \\    WHEN 'low' THEN 4
            \\  END,
            \\  created_at ASC
            \\LIMIT 1
        , .{}, .{now});

        if (row) |r| {
            defer self.allocator.free(r.id);
            defer self.allocator.free(r.type_str);
            defer self.allocator.free(r.priority_str);
            defer self.allocator.free(r.payload);

            const job_type = std.meta.stringToEnum(JobType, r.type_str) orelse return null;
            const priority = std.meta.stringToEnum(JobPriority, r.priority_str) orelse .normal;

            // Mark job as running
            try self.db.exec("UPDATE jobs SET status = 'running', started_at = ? WHERE id = ?", .{}, .{ now, r.id });

            return Job{
                .id = try self.allocator.dupe(u8, r.id),
                .type = job_type,
                .priority = priority,
                .status = .running,
                .payload = try self.allocator.dupe(u8, r.payload),
                .created_at = now,
                .scheduled_for = now,
                .started_at = now,
                .attempts = r.attempts,
            };
        }

        return null;
    }

    fn processJob(self: *JobQueue, job: Job) !void {
        var job_copy = job;
        defer job_copy.deinit(self.allocator);

        std.debug.print("Processing job {s} of type {s}\n", .{ job_copy.id, @tagName(job_copy.type) });

        const result = switch (job.type) {
            .deliver_activity => try self.processDeliverActivity(job.payload),
            .process_inbox => try self.processInboxMessage(job.payload),
            .send_email => try self.processSendEmail(job.payload),
            .update_search_index => try self.processUpdateSearchIndex(job.payload),
            .cleanup_media => try self.processCleanupMedia(job.payload),
            .process_media => try self.processMediaJob(job.payload),
            .calculate_trends => try self.processCalculateTrends(job.payload),
        };

        // Mark job as completed
        if (result) {
            try self.completeJob(job.id);
        } else {
            // Job failed, will be retried
            try self.retryJob(job.id);
        }
    }

    fn processDeliverActivity(self: *JobQueue, payload: []const u8) !bool {
        // Parse payload as activity delivery request
        var parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, payload, .{});
        defer parsed.deinit();

        const activity_str = parsed.value.object.get("activity") orelse return false;
        const inbox_url = parsed.value.object.get("inbox_url") orelse return false;

        if (activity_str != .string or inbox_url != .string) return false;

        // TODO: Parse activity and deliver to inbox
        std.debug.print("Delivering activity to {s}\n", .{inbox_url.string});

        // Simulate delivery success
        return true;
    }

    fn processInboxMessage(_: *JobQueue, payload: []const u8) !bool {
        // Process incoming ActivityPub message
        std.debug.print("Processing inbox message: {s}\n", .{payload});
        return true;
    }

    fn processSendEmail(_: *JobQueue, payload: []const u8) !bool {
        // Send email notification
        std.debug.print("Sending email: {s}\n", .{payload});
        return true;
    }

    fn processUpdateSearchIndex(_: *JobQueue, payload: []const u8) !bool {
        // Update search indexes
        std.debug.print("Updating search index: {s}\n", .{payload});
        return true;
    }

    fn processCleanupMedia(_: *JobQueue, payload: []const u8) !bool {
        // Clean up old media files
        std.debug.print("Cleaning up media: {s}\n", .{payload});
        return true;
    }

    fn processMediaJob(_: *JobQueue, payload: []const u8) !bool {
        // Process uploaded media (resize, etc.)
        std.debug.print("Processing media: {s}\n", .{payload});
        return true;
    }

    fn processCalculateTrends(_: *JobQueue, payload: []const u8) !bool {
        // Calculate trending hashtags
        std.debug.print("Calculating trends: {s}\n", .{payload});
        return true;
    }

    fn completeJob(self: *JobQueue, job_id: []const u8) !void {
        const now = std.time.timestamp();
        try self.db.exec("UPDATE jobs SET status = 'completed', completed_at = ? WHERE id = ?", .{}, .{ now, job_id });
    }

    fn failJob(self: *JobQueue, job_id: []const u8, error_msg: []const u8) !void {
        try self.db.exec("UPDATE jobs SET status = 'failed', last_error = ? WHERE id = ?", .{}, .{ error_msg, job_id });
    }

    fn retryJob(self: *JobQueue, job_id: []const u8) !void {
        try self.db.exec(
            \\UPDATE jobs SET
            \\  status = 'pending',
            \\  attempts = attempts + 1,
            \\  scheduled_for = ? + (attempts * 300) -- exponential backoff
            \\WHERE id = ?
        , .{}, .{ std.time.timestamp(), job_id });
    }
};

fn generateJobId(allocator: std.mem.Allocator) ![]u8 {
    var id_buf: [16]u8 = undefined;
    std.crypto.random.bytes(&id_buf);
    return std.fmt.allocPrint(allocator, "job_{x}", .{std.fmt.fmtSliceHexLower(&id_buf)});
}

// Initialize job tables
pub fn initJobTables(db: *database.Database) !void {
    try db.exec(
        \\CREATE TABLE IF NOT EXISTS jobs (
        \\    id TEXT PRIMARY KEY,
        \\    type TEXT NOT NULL,
        \\    priority TEXT NOT NULL,
        \\    status TEXT NOT NULL,
        \\    payload TEXT NOT NULL,
        \\    created_at INTEGER NOT NULL,
        \\    scheduled_for INTEGER NOT NULL,
        \\    started_at INTEGER,
        \\    completed_at INTEGER,
        \\    attempts INTEGER DEFAULT 0,
        \\    max_attempts INTEGER DEFAULT 3,
        \\    last_error TEXT
        \\)
    , .{}, .{});

    // Create indexes
    try db.exec("CREATE INDEX IF NOT EXISTS idx_jobs_status_priority ON jobs(status, priority)", .{}, .{});
    try db.exec("CREATE INDEX IF NOT EXISTS idx_jobs_scheduled ON jobs(scheduled_for) WHERE status = 'pending'", .{}, .{});
}

// Helper functions for enqueuing common jobs
pub fn enqueueActivityDelivery(queue: *JobQueue, activity: activitypub.Activity, inbox_url: []const u8) ![]const u8 {
    const payload = try std.json.stringifyAlloc(queue.allocator, .{
        .activity = activity,
        .inbox_url = inbox_url,
    }, .{});
    defer queue.allocator.free(payload);

    return try queue.enqueue(.deliver_activity, .high, payload);
}

pub fn enqueueEmailNotification(queue: *JobQueue, to: []const u8, subject: []const u8, body: []const u8) ![]const u8 {
    const payload = try std.json.stringifyAlloc(queue.allocator, .{
        .to = to,
        .subject = subject,
        .body = body,
    }, .{});
    defer queue.allocator.free(payload);

    return try queue.enqueue(.send_email, .normal, payload);
}

pub fn enqueueSearchIndexUpdate(queue: *JobQueue, content_type: []const u8, content_id: i64) ![]const u8 {
    const payload = try std.json.stringifyAlloc(queue.allocator, .{
        .content_type = content_type,
        .content_id = content_id,
    }, .{});
    defer queue.allocator.free(payload);

    return try queue.enqueue(.update_search_index, .low, payload);
}

pub fn enqueueMediaCleanup(queue: *JobQueue, max_age_days: u32) ![]const u8 {
    const payload = try std.json.stringifyAlloc(queue.allocator, .{
        .max_age_days = max_age_days,
    }, .{});
    defer queue.allocator.free(payload);

    return try queue.schedule(.cleanup_media, .low, payload, 86400); // Daily
}

pub fn enqueueTrendCalculation(queue: *JobQueue) ![]const u8 {
    const payload = try std.json.stringifyAlloc(queue.allocator, .{}, .{});
    defer queue.allocator.free(payload);

    return try queue.schedule(.calculate_trends, .normal, payload, 3600); // Hourly
}
