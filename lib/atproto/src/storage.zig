const std = @import("std");

/// Errors returned by storage operations.
pub const StorageError = error{
    NotFound,
    AlreadyExists,
    StorageFailure,
    InvalidInput,
    Conflict,
};

/// A stored record entry.
pub const RecordEntry = struct {
    collection: []const u8,
    rkey: []const u8,
    cid: []const u8,
    value: []const u8,
    created_at: i64,
};

/// A stored commit entry.
pub const CommitEntry = struct {
    did: []const u8,
    rev: []const u8,
    data_cid: []const u8,
    prev_rev: ?[]const u8,
    sig: []const u8,
    created_at: i64,
};

/// A stored session entry.
pub const SessionEntry = struct {
    did: []const u8,
    handle: []const u8,
    access_jwt: []const u8,
    refresh_jwt: []const u8,
    created_at: i64,
    access_expires_at: i64,
    refresh_expires_at: i64,
};

/// A stored account entry.
pub const AccountEntry = struct {
    did: []const u8,
    handle: []const u8,
    email: ?[]const u8,
    password_hash: []const u8,
    signing_key_seed: []const u8,
    created_at: i64,
};

/// A stored blob entry.
pub const BlobEntry = struct {
    cid: []const u8,
    mime_type: []const u8,
    size: u64,
    data: []const u8,
};

/// Storage interface for AT Protocol PDS data.
/// Modeled after std.mem.Allocator — a thin vtable wrapper over any backing store.
///
/// Implementations may back this with SQLite, PostgreSQL, in-memory maps, etc.
/// The library provides `MemoryStorage` for testing.
pub const Storage = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        // Record operations
        putRecord: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, did: []const u8, collection: []const u8, rkey: []const u8, cid: []const u8, value: []const u8) anyerror!void,
        getRecord: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, did: []const u8, collection: []const u8, rkey: []const u8) anyerror!?RecordEntry,
        deleteRecord: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, did: []const u8, collection: []const u8, rkey: []const u8) anyerror!void,
        listRecords: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, did: []const u8, collection: []const u8, limit: u32, cursor: ?[]const u8) anyerror![]RecordEntry,

        // Commit operations
        putCommit: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, entry: CommitEntry) anyerror!void,
        getLatestCommit: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, did: []const u8) anyerror!?CommitEntry,

        // Session operations
        createSession: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, entry: SessionEntry) anyerror!void,
        getSessionByToken: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, access_jwt: []const u8) anyerror!?SessionEntry,
        getSessionByRefreshToken: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, refresh_jwt: []const u8) anyerror!?SessionEntry,
        deleteSession: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, access_jwt: []const u8) anyerror!void,

        // Account operations
        createAccount: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, entry: AccountEntry) anyerror!void,
        getAccountByIdentifier: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, identifier: []const u8) anyerror!?AccountEntry,
        getAccountByDid: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, did: []const u8) anyerror!?AccountEntry,

        // Blob operations
        putBlob: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, entry: BlobEntry) anyerror!void,
        getBlob: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, cid: []const u8) anyerror!?BlobEntry,
        listBlobs: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, did: []const u8, limit: u32, cursor: ?[]const u8) anyerror![]BlobEntry,
    };

    // Forwarding methods

    pub fn putRecord(self: Storage, allocator: std.mem.Allocator, did: []const u8, collection: []const u8, rkey: []const u8, cid: []const u8, value: []const u8) anyerror!void {
        return self.vtable.putRecord(self.ptr, allocator, did, collection, rkey, cid, value);
    }

    pub fn getRecord(self: Storage, allocator: std.mem.Allocator, did: []const u8, collection: []const u8, rkey: []const u8) anyerror!?RecordEntry {
        return self.vtable.getRecord(self.ptr, allocator, did, collection, rkey);
    }

    pub fn deleteRecord(self: Storage, allocator: std.mem.Allocator, did: []const u8, collection: []const u8, rkey: []const u8) anyerror!void {
        return self.vtable.deleteRecord(self.ptr, allocator, did, collection, rkey);
    }

    pub fn listRecords(self: Storage, allocator: std.mem.Allocator, did: []const u8, collection: []const u8, limit: u32, cursor: ?[]const u8) anyerror![]RecordEntry {
        return self.vtable.listRecords(self.ptr, allocator, did, collection, limit, cursor);
    }

    pub fn putCommit(self: Storage, allocator: std.mem.Allocator, entry: CommitEntry) anyerror!void {
        return self.vtable.putCommit(self.ptr, allocator, entry);
    }

    pub fn getLatestCommit(self: Storage, allocator: std.mem.Allocator, did: []const u8) anyerror!?CommitEntry {
        return self.vtable.getLatestCommit(self.ptr, allocator, did);
    }

    pub fn createSession(self: Storage, allocator: std.mem.Allocator, entry: SessionEntry) anyerror!void {
        return self.vtable.createSession(self.ptr, allocator, entry);
    }

    pub fn getSessionByToken(self: Storage, allocator: std.mem.Allocator, access_jwt: []const u8) anyerror!?SessionEntry {
        return self.vtable.getSessionByToken(self.ptr, allocator, access_jwt);
    }

    pub fn getSessionByRefreshToken(self: Storage, allocator: std.mem.Allocator, refresh_jwt: []const u8) anyerror!?SessionEntry {
        return self.vtable.getSessionByRefreshToken(self.ptr, allocator, refresh_jwt);
    }

    pub fn deleteSession(self: Storage, allocator: std.mem.Allocator, access_jwt: []const u8) anyerror!void {
        return self.vtable.deleteSession(self.ptr, allocator, access_jwt);
    }

    pub fn createAccount(self: Storage, allocator: std.mem.Allocator, entry: AccountEntry) anyerror!void {
        return self.vtable.createAccount(self.ptr, allocator, entry);
    }

    pub fn getAccountByIdentifier(self: Storage, allocator: std.mem.Allocator, identifier: []const u8) anyerror!?AccountEntry {
        return self.vtable.getAccountByIdentifier(self.ptr, allocator, identifier);
    }

    pub fn getAccountByDid(self: Storage, allocator: std.mem.Allocator, did: []const u8) anyerror!?AccountEntry {
        return self.vtable.getAccountByDid(self.ptr, allocator, did);
    }

    pub fn putBlob(self: Storage, allocator: std.mem.Allocator, entry: BlobEntry) anyerror!void {
        return self.vtable.putBlob(self.ptr, allocator, entry);
    }

    pub fn getBlob(self: Storage, allocator: std.mem.Allocator, cid: []const u8) anyerror!?BlobEntry {
        return self.vtable.getBlob(self.ptr, allocator, cid);
    }

    pub fn listBlobs(self: Storage, allocator: std.mem.Allocator, did: []const u8, limit: u32, cursor: ?[]const u8) anyerror![]BlobEntry {
        return self.vtable.listBlobs(self.ptr, allocator, did, limit, cursor);
    }
};

/// In-memory storage implementation for testing.
pub const MemoryStorage = struct {
    allocator: std.mem.Allocator,
    records: std.ArrayList(StoredRecord),
    commits: std.ArrayList(StoredCommit),
    sessions: std.ArrayList(StoredSession),
    accounts: std.ArrayList(StoredAccount),
    blobs: std.ArrayList(StoredBlob),

    const StoredRecord = struct {
        did: []const u8,
        collection: []const u8,
        rkey: []const u8,
        cid: []const u8,
        value: []const u8,
        created_at: i64,
    };

    const StoredCommit = struct {
        did: []const u8,
        rev: []const u8,
        data_cid: []const u8,
        prev_rev: ?[]const u8,
        sig: []const u8,
        created_at: i64,
    };

    const StoredSession = struct {
        did: []const u8,
        handle: []const u8,
        access_jwt: []const u8,
        refresh_jwt: []const u8,
        created_at: i64,
        access_expires_at: i64,
        refresh_expires_at: i64,
    };

    const StoredAccount = struct {
        did: []const u8,
        handle: []const u8,
        email: ?[]const u8,
        password_hash: []const u8,
        signing_key_seed: []const u8,
        created_at: i64,
    };

    const StoredBlob = struct {
        cid: []const u8,
        mime_type: []const u8,
        size: u64,
        data: []const u8,
    };

    pub fn init(allocator: std.mem.Allocator) MemoryStorage {
        return .{
            .allocator = allocator,
            .records = .empty,
            .commits = .empty,
            .sessions = .empty,
            .accounts = .empty,
            .blobs = .empty,
        };
    }

    pub fn deinit(self: *MemoryStorage) void {
        for (self.records.items) |r| {
            self.allocator.free(r.did);
            self.allocator.free(r.collection);
            self.allocator.free(r.rkey);
            self.allocator.free(r.cid);
            self.allocator.free(r.value);
        }
        self.records.deinit(self.allocator);

        for (self.commits.items) |c| {
            self.allocator.free(c.did);
            self.allocator.free(c.rev);
            self.allocator.free(c.data_cid);
            if (c.prev_rev) |pr| self.allocator.free(pr);
            self.allocator.free(c.sig);
        }
        self.commits.deinit(self.allocator);

        for (self.sessions.items) |s| {
            self.allocator.free(s.did);
            self.allocator.free(s.handle);
            self.allocator.free(s.access_jwt);
            self.allocator.free(s.refresh_jwt);
        }
        self.sessions.deinit(self.allocator);

        for (self.accounts.items) |a| {
            self.allocator.free(a.did);
            self.allocator.free(a.handle);
            if (a.email) |e| self.allocator.free(e);
            self.allocator.free(a.password_hash);
            self.allocator.free(a.signing_key_seed);
        }
        self.accounts.deinit(self.allocator);

        for (self.blobs.items) |bl| {
            self.allocator.free(bl.cid);
            self.allocator.free(bl.mime_type);
            self.allocator.free(bl.data);
        }
        self.blobs.deinit(self.allocator);
    }

    pub fn storage(self: *MemoryStorage) Storage {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable = Storage.VTable{
        .putRecord = &memPutRecord,
        .getRecord = &memGetRecord,
        .deleteRecord = &memDeleteRecord,
        .listRecords = &memListRecords,
        .putCommit = &memPutCommit,
        .getLatestCommit = &memGetLatestCommit,
        .createSession = &memCreateSession,
        .getSessionByToken = &memGetSessionByToken,
        .getSessionByRefreshToken = &memGetSessionByRefreshToken,
        .deleteSession = &memDeleteSession,
        .createAccount = &memCreateAccount,
        .getAccountByIdentifier = &memGetAccountByIdentifier,
        .getAccountByDid = &memGetAccountByDid,
        .putBlob = &memPutBlob,
        .getBlob = &memGetBlob,
        .listBlobs = &memListBlobs,
    };

    fn castSelf(ptr: *anyopaque) *MemoryStorage {
        return @ptrCast(@alignCast(ptr));
    }

    fn memPutRecord(ptr: *anyopaque, allocator: std.mem.Allocator, did: []const u8, collection: []const u8, rkey: []const u8, cid: []const u8, value: []const u8) anyerror!void {
        const s = castSelf(ptr);
        _ = allocator;
        // Remove existing record with same key
        var i: usize = 0;
        while (i < s.records.items.len) {
            const r = s.records.items[i];
            if (std.mem.eql(u8, r.did, did) and std.mem.eql(u8, r.collection, collection) and std.mem.eql(u8, r.rkey, rkey)) {
                s.allocator.free(r.did);
                s.allocator.free(r.collection);
                s.allocator.free(r.rkey);
                s.allocator.free(r.cid);
                s.allocator.free(r.value);
                _ = s.records.orderedRemove(i);
            } else {
                i += 1;
            }
        }
        try s.records.append(s.allocator, .{
            .did = try s.allocator.dupe(u8, did),
            .collection = try s.allocator.dupe(u8, collection),
            .rkey = try s.allocator.dupe(u8, rkey),
            .cid = try s.allocator.dupe(u8, cid),
            .value = try s.allocator.dupe(u8, value),
            .created_at = std.time.timestamp(),
        });
    }

    fn memGetRecord(ptr: *anyopaque, _: std.mem.Allocator, did: []const u8, collection: []const u8, rkey: []const u8) anyerror!?RecordEntry {
        const s = castSelf(ptr);
        for (s.records.items) |r| {
            if (std.mem.eql(u8, r.did, did) and std.mem.eql(u8, r.collection, collection) and std.mem.eql(u8, r.rkey, rkey)) {
                return RecordEntry{
                    .collection = r.collection,
                    .rkey = r.rkey,
                    .cid = r.cid,
                    .value = r.value,
                    .created_at = r.created_at,
                };
            }
        }
        return null;
    }

    fn memDeleteRecord(ptr: *anyopaque, _: std.mem.Allocator, did: []const u8, collection: []const u8, rkey: []const u8) anyerror!void {
        const s = castSelf(ptr);
        var i: usize = 0;
        while (i < s.records.items.len) {
            const r = s.records.items[i];
            if (std.mem.eql(u8, r.did, did) and std.mem.eql(u8, r.collection, collection) and std.mem.eql(u8, r.rkey, rkey)) {
                s.allocator.free(r.did);
                s.allocator.free(r.collection);
                s.allocator.free(r.rkey);
                s.allocator.free(r.cid);
                s.allocator.free(r.value);
                _ = s.records.orderedRemove(i);
                return;
            }
            i += 1;
        }
    }

    fn memListRecords(ptr: *anyopaque, allocator: std.mem.Allocator, did: []const u8, collection: []const u8, limit: u32, _: ?[]const u8) anyerror![]RecordEntry {
        const s = castSelf(ptr);
        var results: std.ArrayList(RecordEntry) = .empty;
        errdefer results.deinit(allocator);

        for (s.records.items) |r| {
            if (results.items.len >= limit) break;
            if (std.mem.eql(u8, r.did, did) and std.mem.eql(u8, r.collection, collection)) {
                try results.append(allocator, .{
                    .collection = r.collection,
                    .rkey = r.rkey,
                    .cid = r.cid,
                    .value = r.value,
                    .created_at = r.created_at,
                });
            }
        }
        return results.toOwnedSlice(allocator);
    }

    fn memPutCommit(ptr: *anyopaque, _: std.mem.Allocator, entry: CommitEntry) anyerror!void {
        const s = castSelf(ptr);
        try s.commits.append(s.allocator, .{
            .did = try s.allocator.dupe(u8, entry.did),
            .rev = try s.allocator.dupe(u8, entry.rev),
            .data_cid = try s.allocator.dupe(u8, entry.data_cid),
            .prev_rev = if (entry.prev_rev) |pr| try s.allocator.dupe(u8, pr) else null,
            .sig = try s.allocator.dupe(u8, entry.sig),
            .created_at = entry.created_at,
        });
    }

    fn memGetLatestCommit(ptr: *anyopaque, _: std.mem.Allocator, did: []const u8) anyerror!?CommitEntry {
        const s = castSelf(ptr);
        var latest: ?StoredCommit = null;
        for (s.commits.items) |c| {
            if (std.mem.eql(u8, c.did, did)) {
                if (latest == null or c.created_at > latest.?.created_at) {
                    latest = c;
                }
            }
        }
        if (latest) |l| {
            return CommitEntry{
                .did = l.did,
                .rev = l.rev,
                .data_cid = l.data_cid,
                .prev_rev = l.prev_rev,
                .sig = l.sig,
                .created_at = l.created_at,
            };
        }
        return null;
    }

    fn memCreateSession(ptr: *anyopaque, _: std.mem.Allocator, entry: SessionEntry) anyerror!void {
        const s = castSelf(ptr);
        try s.sessions.append(s.allocator, .{
            .did = try s.allocator.dupe(u8, entry.did),
            .handle = try s.allocator.dupe(u8, entry.handle),
            .access_jwt = try s.allocator.dupe(u8, entry.access_jwt),
            .refresh_jwt = try s.allocator.dupe(u8, entry.refresh_jwt),
            .created_at = entry.created_at,
            .access_expires_at = entry.access_expires_at,
            .refresh_expires_at = entry.refresh_expires_at,
        });
    }

    fn memGetSessionByToken(ptr: *anyopaque, _: std.mem.Allocator, access_jwt: []const u8) anyerror!?SessionEntry {
        const s = castSelf(ptr);
        for (s.sessions.items) |sess| {
            if (std.mem.eql(u8, sess.access_jwt, access_jwt)) {
                return SessionEntry{
                    .did = sess.did,
                    .handle = sess.handle,
                    .access_jwt = sess.access_jwt,
                    .refresh_jwt = sess.refresh_jwt,
                    .created_at = sess.created_at,
                    .access_expires_at = sess.access_expires_at,
                    .refresh_expires_at = sess.refresh_expires_at,
                };
            }
        }
        return null;
    }

    fn memGetSessionByRefreshToken(ptr: *anyopaque, _: std.mem.Allocator, refresh_jwt: []const u8) anyerror!?SessionEntry {
        const s = castSelf(ptr);
        for (s.sessions.items) |sess| {
            if (std.mem.eql(u8, sess.refresh_jwt, refresh_jwt)) {
                return SessionEntry{
                    .did = sess.did,
                    .handle = sess.handle,
                    .access_jwt = sess.access_jwt,
                    .refresh_jwt = sess.refresh_jwt,
                    .created_at = sess.created_at,
                    .access_expires_at = sess.access_expires_at,
                    .refresh_expires_at = sess.refresh_expires_at,
                };
            }
        }
        return null;
    }

    fn memDeleteSession(ptr: *anyopaque, _: std.mem.Allocator, access_jwt: []const u8) anyerror!void {
        const s = castSelf(ptr);
        var i: usize = 0;
        while (i < s.sessions.items.len) {
            const sess = s.sessions.items[i];
            if (std.mem.eql(u8, sess.access_jwt, access_jwt)) {
                s.allocator.free(sess.did);
                s.allocator.free(sess.handle);
                s.allocator.free(sess.access_jwt);
                s.allocator.free(sess.refresh_jwt);
                _ = s.sessions.orderedRemove(i);
                return;
            }
            i += 1;
        }
    }

    fn memCreateAccount(ptr: *anyopaque, _: std.mem.Allocator, entry: AccountEntry) anyerror!void {
        const s = castSelf(ptr);
        // Check for duplicate handle or DID
        for (s.accounts.items) |a| {
            if (std.mem.eql(u8, a.handle, entry.handle) or std.mem.eql(u8, a.did, entry.did)) {
                return StorageError.AlreadyExists;
            }
        }
        try s.accounts.append(s.allocator, .{
            .did = try s.allocator.dupe(u8, entry.did),
            .handle = try s.allocator.dupe(u8, entry.handle),
            .email = if (entry.email) |e| try s.allocator.dupe(u8, e) else null,
            .password_hash = try s.allocator.dupe(u8, entry.password_hash),
            .signing_key_seed = try s.allocator.dupe(u8, entry.signing_key_seed),
            .created_at = entry.created_at,
        });
    }

    fn memGetAccountByIdentifier(ptr: *anyopaque, _: std.mem.Allocator, identifier: []const u8) anyerror!?AccountEntry {
        const s = castSelf(ptr);
        for (s.accounts.items) |a| {
            if (std.mem.eql(u8, a.handle, identifier) or
                (a.email != null and std.mem.eql(u8, a.email.?, identifier)) or
                std.mem.eql(u8, a.did, identifier))
            {
                return AccountEntry{
                    .did = a.did,
                    .handle = a.handle,
                    .email = a.email,
                    .password_hash = a.password_hash,
                    .signing_key_seed = a.signing_key_seed,
                    .created_at = a.created_at,
                };
            }
        }
        return null;
    }

    fn memGetAccountByDid(ptr: *anyopaque, _: std.mem.Allocator, did: []const u8) anyerror!?AccountEntry {
        const s = castSelf(ptr);
        for (s.accounts.items) |a| {
            if (std.mem.eql(u8, a.did, did)) {
                return AccountEntry{
                    .did = a.did,
                    .handle = a.handle,
                    .email = a.email,
                    .password_hash = a.password_hash,
                    .signing_key_seed = a.signing_key_seed,
                    .created_at = a.created_at,
                };
            }
        }
        return null;
    }

    fn memPutBlob(ptr: *anyopaque, _: std.mem.Allocator, entry: BlobEntry) anyerror!void {
        const s = castSelf(ptr);
        try s.blobs.append(s.allocator, .{
            .cid = try s.allocator.dupe(u8, entry.cid),
            .mime_type = try s.allocator.dupe(u8, entry.mime_type),
            .size = entry.size,
            .data = try s.allocator.dupe(u8, entry.data),
        });
    }

    fn memGetBlob(ptr: *anyopaque, _: std.mem.Allocator, cid: []const u8) anyerror!?BlobEntry {
        const s = castSelf(ptr);
        for (s.blobs.items) |bl| {
            if (std.mem.eql(u8, bl.cid, cid)) {
                return BlobEntry{
                    .cid = bl.cid,
                    .mime_type = bl.mime_type,
                    .size = bl.size,
                    .data = bl.data,
                };
            }
        }
        return null;
    }

    fn memListBlobs(ptr: *anyopaque, allocator: std.mem.Allocator, _: []const u8, limit: u32, _: ?[]const u8) anyerror![]BlobEntry {
        const s = castSelf(ptr);
        var results: std.ArrayList(BlobEntry) = .empty;
        errdefer results.deinit(allocator);

        for (s.blobs.items) |bl| {
            if (results.items.len >= limit) break;
            try results.append(allocator, .{
                .cid = bl.cid,
                .mime_type = bl.mime_type,
                .size = bl.size,
                .data = bl.data,
            });
        }
        return results.toOwnedSlice(allocator);
    }
};

test "memory storage basic operations" {
    const allocator = std.testing.allocator;
    var mem = MemoryStorage.init(allocator);
    defer mem.deinit();
    const store = mem.storage();

    // Put and get a record
    try store.putRecord(allocator, "did:web:test", "app.bsky.feed.post", "abc123", "cidxyz", "{\"text\":\"hello\"}");
    const rec = try store.getRecord(allocator, "did:web:test", "app.bsky.feed.post", "abc123");
    try std.testing.expect(rec != null);
    try std.testing.expectEqualStrings("abc123", rec.?.rkey);
    try std.testing.expectEqualStrings("{\"text\":\"hello\"}", rec.?.value);

    // Delete
    try store.deleteRecord(allocator, "did:web:test", "app.bsky.feed.post", "abc123");
    const deleted = try store.getRecord(allocator, "did:web:test", "app.bsky.feed.post", "abc123");
    try std.testing.expect(deleted == null);
}

test "memory storage account operations" {
    const allocator = std.testing.allocator;
    var mem = MemoryStorage.init(allocator);
    defer mem.deinit();
    const store = mem.storage();

    try store.createAccount(allocator, .{
        .did = "did:web:test",
        .handle = "alice.test",
        .email = "alice@test.com",
        .password_hash = "hashed",
        .signing_key_seed = "seed",
        .created_at = 1000,
    });

    const by_handle = try store.getAccountByIdentifier(allocator, "alice.test");
    try std.testing.expect(by_handle != null);
    try std.testing.expectEqualStrings("did:web:test", by_handle.?.did);

    const by_email = try store.getAccountByIdentifier(allocator, "alice@test.com");
    try std.testing.expect(by_email != null);

    const by_did = try store.getAccountByDid(allocator, "did:web:test");
    try std.testing.expect(by_did != null);
}
