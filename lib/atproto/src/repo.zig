const std = @import("std");
const zat = @import("zat");
const storage_mod = @import("storage.zig");
const commit_mod = @import("commit.zig");
const record_mod = @import("record.zig");
const Storage = storage_mod.Storage;
const Commit = commit_mod.Commit;

/// AT Protocol repository — manages records, MST, and commits for a single DID.
pub const Repository = struct {
    allocator: std.mem.Allocator,
    did: []const u8,
    signing_key_seed: []const u8,
    store: Storage,

    pub fn init(allocator: std.mem.Allocator, did: []const u8, signing_key_seed: []const u8, store: Storage) Repository {
        return .{
            .allocator = allocator,
            .did = did,
            .signing_key_seed = signing_key_seed,
            .store = store,
        };
    }

    /// Create a new record in the repository.
    pub fn createRecord(
        self: *Repository,
        collection: []const u8,
        rkey_opt: ?[]const u8,
        value: []const u8,
    ) !struct { uri: []const u8, cid: []const u8, rev: []const u8 } {
        // Generate record key if not provided
        const rkey = if (rkey_opt) |r|
            try self.allocator.dupe(u8, r)
        else
            try commit_mod.generateRkey(self.allocator);
        defer self.allocator.free(rkey);

        // Generate CID from record content (SHA-256 hash, hex encoded for now)
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(value, &hash, .{});
        const cid_hex = std.fmt.bytesToHex(&hash, .lower);
        const cid_owned = try self.allocator.dupe(u8, &cid_hex);
        errdefer self.allocator.free(cid_owned);

        // Store the record
        try self.store.putRecord(self.allocator, self.did, collection, rkey, cid_owned, value);

        // Create and store a commit
        const prev_commit = try self.store.getLatestCommit(self.allocator, self.did);
        const prev_rev = if (prev_commit) |pc| pc.rev else null;

        const new_commit = try commit_mod.createCommit(
            self.allocator,
            self.did,
            cid_owned,
            prev_rev,
            self.signing_key_seed,
        );
        defer commit_mod.freeCommit(self.allocator, new_commit);

        try self.store.putCommit(self.allocator, .{
            .did = new_commit.did,
            .rev = new_commit.rev,
            .data_cid = new_commit.data_cid,
            .prev_rev = new_commit.prev,
            .sig = new_commit.sig,
            .created_at = std.time.timestamp(),
        });

        // Build AT-URI
        const uri = try record_mod.buildAtUri(self.allocator, self.did, collection, rkey);

        return .{
            .uri = uri,
            .cid = cid_owned,
            .rev = try self.allocator.dupe(u8, new_commit.rev),
        };
    }

    /// Get a record from the repository.
    pub fn getRecord(self: *Repository, collection: []const u8, rkey: []const u8) !?struct { cid: []const u8, value: []const u8 } {
        const entry = try self.store.getRecord(self.allocator, self.did, collection, rkey);
        if (entry) |e| {
            return .{ .cid = e.cid, .value = e.value };
        }
        return null;
    }

    /// Delete a record from the repository.
    pub fn deleteRecord(self: *Repository, collection: []const u8, rkey: []const u8) !void {
        try self.store.deleteRecord(self.allocator, self.did, collection, rkey);
    }

    /// List records in a collection.
    pub fn listRecords(
        self: *Repository,
        collection: []const u8,
        limit: u32,
        cursor: ?[]const u8,
    ) ![]storage_mod.RecordEntry {
        return self.store.listRecords(self.allocator, self.did, collection, limit, cursor);
    }

    /// Put (upsert) a record.
    pub fn putRecord(
        self: *Repository,
        collection: []const u8,
        rkey: []const u8,
        value: []const u8,
    ) !struct { uri: []const u8, cid: []const u8, rev: []const u8 } {
        return self.createRecord(collection, rkey, value);
    }

    /// Get the latest commit for this repository.
    pub fn getLatestCommit(self: *Repository) !?storage_mod.CommitEntry {
        return self.store.getLatestCommit(self.allocator, self.did);
    }
};

test "repository create and get record" {
    const allocator = std.testing.allocator;
    var mem = storage_mod.MemoryStorage.init(allocator);
    defer mem.deinit();

    var repo = Repository.init(allocator, "did:web:test", "testseedtestseedtestseedtestseed", mem.storage());

    const result = try repo.createRecord("app.bsky.feed.post", null, "{\"text\":\"hello world\",\"createdAt\":\"2024-01-01T00:00:00Z\"}");
    defer allocator.free(result.uri);
    defer allocator.free(result.cid);
    defer allocator.free(result.rev);

    try std.testing.expect(std.mem.startsWith(u8, result.uri, "at://did:web:test/app.bsky.feed.post/"));
    try std.testing.expect(result.cid.len > 0);
    try std.testing.expect(result.rev.len == 13);

    const got = try repo.getRecord("app.bsky.feed.post", result.uri["at://did:web:test/app.bsky.feed.post/".len..]);
    try std.testing.expect(got != null);
    try std.testing.expectEqualStrings("{\"text\":\"hello world\",\"createdAt\":\"2024-01-01T00:00:00Z\"}", got.?.value);
}
