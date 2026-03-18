//! SQLite-backed implementation of the atproto.Storage interface.
//! Uses the project's existing sqlite.Db connection.

const std = @import("std");
const sqlite = @import("sqlite");
const atproto = @import("atproto");
const Storage = atproto.storage.Storage;
const RecordEntry = atproto.storage.RecordEntry;
const CommitEntry = atproto.storage.CommitEntry;
const SessionEntry = atproto.storage.SessionEntry;
const AccountEntry = atproto.storage.AccountEntry;
const BlobEntry = atproto.storage.BlobEntry;

pub const SqliteStorage = struct {
    db: *sqlite.Db,

    pub fn init(db: *sqlite.Db) SqliteStorage {
        return .{ .db = db };
    }

    /// Run AT Protocol table migrations.
    pub fn migrate(self: *SqliteStorage) !void {
        try self.db.exec(
            \\CREATE TABLE IF NOT EXISTS at_records (
            \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
            \\    did TEXT NOT NULL,
            \\    collection TEXT NOT NULL,
            \\    rkey TEXT NOT NULL,
            \\    cid TEXT NOT NULL,
            \\    value TEXT NOT NULL,
            \\    created_at INTEGER NOT NULL,
            \\    UNIQUE(did, collection, rkey)
            \\)
        , .{}, .{});

        try self.db.exec(
            \\CREATE TABLE IF NOT EXISTS at_commits (
            \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
            \\    did TEXT NOT NULL,
            \\    rev TEXT NOT NULL,
            \\    data_cid TEXT NOT NULL,
            \\    prev_rev TEXT,
            \\    sig TEXT NOT NULL,
            \\    created_at INTEGER NOT NULL
            \\)
        , .{}, .{});

        try self.db.exec(
            \\CREATE TABLE IF NOT EXISTS at_sessions (
            \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
            \\    did TEXT NOT NULL,
            \\    handle TEXT NOT NULL,
            \\    access_jwt TEXT NOT NULL UNIQUE,
            \\    refresh_jwt TEXT NOT NULL UNIQUE,
            \\    created_at INTEGER NOT NULL,
            \\    access_expires_at INTEGER NOT NULL,
            \\    refresh_expires_at INTEGER NOT NULL
            \\)
        , .{}, .{});

        try self.db.exec(
            \\CREATE TABLE IF NOT EXISTS at_accounts (
            \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
            \\    did TEXT NOT NULL UNIQUE,
            \\    handle TEXT NOT NULL UNIQUE,
            \\    email TEXT,
            \\    password_hash TEXT NOT NULL,
            \\    signing_key_seed TEXT NOT NULL,
            \\    created_at INTEGER NOT NULL
            \\)
        , .{}, .{});

        try self.db.exec(
            \\CREATE TABLE IF NOT EXISTS at_blobs (
            \\    id INTEGER PRIMARY KEY AUTOINCREMENT,
            \\    cid TEXT NOT NULL UNIQUE,
            \\    mime_type TEXT NOT NULL,
            \\    size INTEGER NOT NULL,
            \\    data BLOB NOT NULL,
            \\    created_at INTEGER DEFAULT (strftime('%s','now'))
            \\)
        , .{}, .{});

        // Indexes for common lookups
        try self.db.exec("CREATE INDEX IF NOT EXISTS idx_at_records_did_coll ON at_records(did, collection)", .{}, .{});
        try self.db.exec("CREATE INDEX IF NOT EXISTS idx_at_commits_did ON at_commits(did, created_at DESC)", .{}, .{});
        try self.db.exec("CREATE INDEX IF NOT EXISTS idx_at_sessions_refresh ON at_sessions(refresh_jwt)", .{}, .{});
    }

    pub fn storage(self: *SqliteStorage) Storage {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    const vtable = Storage.VTable{
        .putRecord = &sqlPutRecord,
        .getRecord = &sqlGetRecord,
        .deleteRecord = &sqlDeleteRecord,
        .listRecords = &sqlListRecords,
        .putCommit = &sqlPutCommit,
        .getLatestCommit = &sqlGetLatestCommit,
        .createSession = &sqlCreateSession,
        .getSessionByToken = &sqlGetSessionByToken,
        .getSessionByRefreshToken = &sqlGetSessionByRefreshToken,
        .deleteSession = &sqlDeleteSession,
        .createAccount = &sqlCreateAccount,
        .getAccountByIdentifier = &sqlGetAccountByIdentifier,
        .getAccountByDid = &sqlGetAccountByDid,
        .putBlob = &sqlPutBlob,
        .getBlob = &sqlGetBlob,
        .listBlobs = &sqlListBlobs,
    };

    fn castSelf(ptr: *anyopaque) *SqliteStorage {
        return @ptrCast(@alignCast(ptr));
    }

    // --- Record operations ---

    fn sqlPutRecord(ptr: *anyopaque, _: std.mem.Allocator, did: []const u8, collection: []const u8, rkey: []const u8, cid: []const u8, value: []const u8) anyerror!void {
        const self = castSelf(ptr);
        // Upsert: delete existing then insert
        try self.db.exec(
            \\DELETE FROM at_records WHERE did = ? AND collection = ? AND rkey = ?
        , .{}, .{ did, collection, rkey });
        try self.db.exec(
            \\INSERT INTO at_records (did, collection, rkey, cid, value, created_at)
            \\VALUES (?, ?, ?, ?, ?, ?)
        , .{}, .{ did, collection, rkey, cid, value, std.time.timestamp() });
    }

    fn sqlGetRecord(ptr: *anyopaque, allocator: std.mem.Allocator, did: []const u8, collection: []const u8, rkey: []const u8) anyerror!?RecordEntry {
        const self = castSelf(ptr);
        const Row = struct { collection: []const u8, rkey: []const u8, cid: []const u8, value: []const u8, created_at: i64 };
        const row = try self.db.oneAlloc(Row, allocator,
            \\SELECT collection, rkey, cid, value, created_at FROM at_records
            \\WHERE did = ? AND collection = ? AND rkey = ?
        , .{}, .{ did, collection, rkey });
        if (row) |r| {
            return RecordEntry{
                .collection = r.collection,
                .rkey = r.rkey,
                .cid = r.cid,
                .value = r.value,
                .created_at = r.created_at,
            };
        }
        return null;
    }

    fn sqlDeleteRecord(ptr: *anyopaque, _: std.mem.Allocator, did: []const u8, collection: []const u8, rkey: []const u8) anyerror!void {
        const self = castSelf(ptr);
        try self.db.exec(
            \\DELETE FROM at_records WHERE did = ? AND collection = ? AND rkey = ?
        , .{}, .{ did, collection, rkey });
    }

    fn sqlListRecords(ptr: *anyopaque, allocator: std.mem.Allocator, did: []const u8, collection: []const u8, limit: u32, _: ?[]const u8) anyerror![]RecordEntry {
        const self = castSelf(ptr);
        const Row = struct { collection: []const u8, rkey: []const u8, cid: []const u8, value: []const u8, created_at: i64 };

        var stmt = try self.db.prepare(
            \\SELECT collection, rkey, cid, value, created_at FROM at_records
            \\WHERE did = ? AND collection = ?
            \\ORDER BY created_at DESC
            \\LIMIT ?
        );
        defer stmt.deinit();

        const rows = try stmt.all(Row, allocator, .{}, .{ did, collection, @as(i64, @intCast(limit)) });
        defer allocator.free(rows);

        var results: std.ArrayList(RecordEntry) = .empty;
        errdefer results.deinit(allocator);

        for (rows) |r| {
            try results.append(allocator, .{
                .collection = r.collection,
                .rkey = r.rkey,
                .cid = r.cid,
                .value = r.value,
                .created_at = r.created_at,
            });
        }
        return results.toOwnedSlice(allocator);
    }

    // --- Commit operations ---

    fn sqlPutCommit(ptr: *anyopaque, _: std.mem.Allocator, entry: CommitEntry) anyerror!void {
        const self = castSelf(ptr);
        try self.db.exec(
            \\INSERT INTO at_commits (did, rev, data_cid, prev_rev, sig, created_at)
            \\VALUES (?, ?, ?, ?, ?, ?)
        , .{}, .{ entry.did, entry.rev, entry.data_cid, entry.prev_rev, entry.sig, entry.created_at });
    }

    fn sqlGetLatestCommit(ptr: *anyopaque, allocator: std.mem.Allocator, did: []const u8) anyerror!?CommitEntry {
        const self = castSelf(ptr);
        const Row = struct { did: []const u8, rev: []const u8, data_cid: []const u8, prev_rev: ?[]const u8, sig: []const u8, created_at: i64 };
        const row = try self.db.oneAlloc(Row, allocator,
            \\SELECT did, rev, data_cid, prev_rev, sig, created_at FROM at_commits
            \\WHERE did = ? ORDER BY created_at DESC LIMIT 1
        , .{}, .{did});
        if (row) |r| {
            return CommitEntry{
                .did = r.did,
                .rev = r.rev,
                .data_cid = r.data_cid,
                .prev_rev = r.prev_rev,
                .sig = r.sig,
                .created_at = r.created_at,
            };
        }
        return null;
    }

    // --- Session operations ---

    fn sqlCreateSession(ptr: *anyopaque, _: std.mem.Allocator, entry: SessionEntry) anyerror!void {
        const self = castSelf(ptr);
        try self.db.exec(
            \\INSERT INTO at_sessions (did, handle, access_jwt, refresh_jwt, created_at, access_expires_at, refresh_expires_at)
            \\VALUES (?, ?, ?, ?, ?, ?, ?)
        , .{}, .{ entry.did, entry.handle, entry.access_jwt, entry.refresh_jwt, entry.created_at, entry.access_expires_at, entry.refresh_expires_at });
    }

    fn sqlGetSessionByToken(ptr: *anyopaque, allocator: std.mem.Allocator, access_jwt: []const u8) anyerror!?SessionEntry {
        const self = castSelf(ptr);
        const Row = struct { did: []const u8, handle: []const u8, access_jwt: []const u8, refresh_jwt: []const u8, created_at: i64, access_expires_at: i64, refresh_expires_at: i64 };
        const row = try self.db.oneAlloc(Row, allocator,
            \\SELECT did, handle, access_jwt, refresh_jwt, created_at, access_expires_at, refresh_expires_at
            \\FROM at_sessions WHERE access_jwt = ?
        , .{}, .{access_jwt});
        if (row) |r| {
            return SessionEntry{
                .did = r.did,
                .handle = r.handle,
                .access_jwt = r.access_jwt,
                .refresh_jwt = r.refresh_jwt,
                .created_at = r.created_at,
                .access_expires_at = r.access_expires_at,
                .refresh_expires_at = r.refresh_expires_at,
            };
        }
        return null;
    }

    fn sqlGetSessionByRefreshToken(ptr: *anyopaque, allocator: std.mem.Allocator, refresh_jwt: []const u8) anyerror!?SessionEntry {
        const self = castSelf(ptr);
        const Row = struct { did: []const u8, handle: []const u8, access_jwt: []const u8, refresh_jwt: []const u8, created_at: i64, access_expires_at: i64, refresh_expires_at: i64 };
        const row = try self.db.oneAlloc(Row, allocator,
            \\SELECT did, handle, access_jwt, refresh_jwt, created_at, access_expires_at, refresh_expires_at
            \\FROM at_sessions WHERE refresh_jwt = ?
        , .{}, .{refresh_jwt});
        if (row) |r| {
            return SessionEntry{
                .did = r.did,
                .handle = r.handle,
                .access_jwt = r.access_jwt,
                .refresh_jwt = r.refresh_jwt,
                .created_at = r.created_at,
                .access_expires_at = r.access_expires_at,
                .refresh_expires_at = r.refresh_expires_at,
            };
        }
        return null;
    }

    fn sqlDeleteSession(ptr: *anyopaque, _: std.mem.Allocator, access_jwt: []const u8) anyerror!void {
        const self = castSelf(ptr);
        try self.db.exec("DELETE FROM at_sessions WHERE access_jwt = ?", .{}, .{access_jwt});
    }

    // --- Account operations ---

    fn sqlCreateAccount(ptr: *anyopaque, _: std.mem.Allocator, entry: AccountEntry) anyerror!void {
        const self = castSelf(ptr);
        self.db.exec(
            \\INSERT INTO at_accounts (did, handle, email, password_hash, signing_key_seed, created_at)
            \\VALUES (?, ?, ?, ?, ?, ?)
        , .{}, .{ entry.did, entry.handle, entry.email, entry.password_hash, entry.signing_key_seed, entry.created_at }) catch {
            return atproto.storage.StorageError.AlreadyExists;
        };
    }

    fn sqlGetAccountByIdentifier(ptr: *anyopaque, allocator: std.mem.Allocator, identifier: []const u8) anyerror!?AccountEntry {
        const self = castSelf(ptr);
        const Row = struct { did: []const u8, handle: []const u8, email: ?[]const u8, password_hash: []const u8, signing_key_seed: []const u8, created_at: i64 };
        // Search by handle, email, or DID
        const row = try self.db.oneAlloc(Row, allocator,
            \\SELECT did, handle, email, password_hash, signing_key_seed, created_at
            \\FROM at_accounts WHERE handle = ? OR email = ? OR did = ?
        , .{}, .{ identifier, identifier, identifier });
        if (row) |r| {
            return AccountEntry{
                .did = r.did,
                .handle = r.handle,
                .email = r.email,
                .password_hash = r.password_hash,
                .signing_key_seed = r.signing_key_seed,
                .created_at = r.created_at,
            };
        }
        return null;
    }

    fn sqlGetAccountByDid(ptr: *anyopaque, allocator: std.mem.Allocator, did: []const u8) anyerror!?AccountEntry {
        const self = castSelf(ptr);
        const Row = struct { did: []const u8, handle: []const u8, email: ?[]const u8, password_hash: []const u8, signing_key_seed: []const u8, created_at: i64 };
        const row = try self.db.oneAlloc(Row, allocator,
            \\SELECT did, handle, email, password_hash, signing_key_seed, created_at
            \\FROM at_accounts WHERE did = ?
        , .{}, .{did});
        if (row) |r| {
            return AccountEntry{
                .did = r.did,
                .handle = r.handle,
                .email = r.email,
                .password_hash = r.password_hash,
                .signing_key_seed = r.signing_key_seed,
                .created_at = r.created_at,
            };
        }
        return null;
    }

    // --- Blob operations ---

    fn sqlPutBlob(ptr: *anyopaque, _: std.mem.Allocator, entry: BlobEntry) anyerror!void {
        const self = castSelf(ptr);
        try self.db.exec(
            \\INSERT OR REPLACE INTO at_blobs (cid, mime_type, size, data)
            \\VALUES (?, ?, ?, ?)
        , .{}, .{ entry.cid, entry.mime_type, @as(i64, @intCast(entry.size)), entry.data });
    }

    fn sqlGetBlob(ptr: *anyopaque, allocator: std.mem.Allocator, cid: []const u8) anyerror!?BlobEntry {
        const self = castSelf(ptr);
        const Row = struct { cid: []const u8, mime_type: []const u8, size: i64, data: []const u8 };
        const row = try self.db.oneAlloc(Row, allocator,
            \\SELECT cid, mime_type, size, data FROM at_blobs WHERE cid = ?
        , .{}, .{cid});
        if (row) |r| {
            return BlobEntry{
                .cid = r.cid,
                .mime_type = r.mime_type,
                .size = @intCast(r.size),
                .data = r.data,
            };
        }
        return null;
    }

    fn sqlListBlobs(ptr: *anyopaque, allocator: std.mem.Allocator, _: []const u8, limit: u32, _: ?[]const u8) anyerror![]BlobEntry {
        const self = castSelf(ptr);
        const Row = struct { cid: []const u8, mime_type: []const u8, size: i64, data: []const u8 };

        var stmt = try self.db.prepare(
            \\SELECT cid, mime_type, size, data FROM at_blobs
            \\ORDER BY rowid DESC LIMIT ?
        );
        defer stmt.deinit();

        const rows = try stmt.all(Row, allocator, .{}, .{@as(i64, @intCast(limit))});
        defer allocator.free(rows);

        var results: std.ArrayList(BlobEntry) = .empty;
        errdefer results.deinit(allocator);

        for (rows) |r| {
            try results.append(allocator, .{
                .cid = r.cid,
                .mime_type = r.mime_type,
                .size = @intCast(r.size),
                .data = r.data,
            });
        }
        return results.toOwnedSlice(allocator);
    }
};
