//! Direct SQL helpers against the shared AP/Mastodon tables.
//!
//! Each helper is a thin wrapper over `sqlite3_prepare_v2` + `sqlite3_step`
//! that the route handlers call synchronously. No allocator is used; all
//! string outputs are written into caller-supplied buffers.

const std = @import("std");
const c = @import("sqlite").c;

const Transient = c.sqliteTransientAsDestructor;

pub const max_username_bytes: usize = 64;
pub const max_display_bytes: usize = 128;
pub const max_bio_bytes: usize = 512;

pub const UserRow = struct {
    id: i64 = 0,
    username_buf: [max_username_bytes]u8 = undefined,
    username_len: usize = 0,
    display_buf: [max_display_bytes]u8 = undefined,
    display_len: usize = 0,
    bio_buf: [max_bio_bytes]u8 = undefined,
    bio_len: usize = 0,
    is_locked: bool = false,
    created_at: i64 = 0,

    pub fn username(self: *const UserRow) []const u8 {
        return self.username_buf[0..self.username_len];
    }
    pub fn displayName(self: *const UserRow) []const u8 {
        if (self.display_len == 0) return self.username();
        return self.display_buf[0..self.display_len];
    }
    pub fn bio(self: *const UserRow) []const u8 {
        return self.bio_buf[0..self.bio_len];
    }
};

fn copyText(stmt: *c.sqlite3_stmt, idx: c_int, buf: []u8, len_out: *usize) void {
    const ptr = c.sqlite3_column_text(stmt, idx);
    const n: usize = @intCast(c.sqlite3_column_bytes(stmt, idx));
    const copy_n = @min(n, buf.len);
    if (ptr != null and copy_n > 0) @memcpy(buf[0..copy_n], ptr[0..copy_n]);
    len_out.* = copy_n;
}

pub fn findUserById(db: *c.sqlite3, id: i64) ?UserRow {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql =
        \\SELECT id, username, COALESCE(display_name,''), COALESCE(bio,''), is_locked, created_at
        \\FROM ap_users WHERE id = ? LIMIT 1
    ;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return null;
    }
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_int64(stmt, 1, id);
    if (c.sqlite3_step(stmt) != c.SQLITE_ROW) return null;
    var u: UserRow = .{ .id = c.sqlite3_column_int64(stmt, 0) };
    copyText(stmt.?, 1, &u.username_buf, &u.username_len);
    copyText(stmt.?, 2, &u.display_buf, &u.display_len);
    copyText(stmt.?, 3, &u.bio_buf, &u.bio_len);
    u.is_locked = c.sqlite3_column_int(stmt, 4) != 0;
    u.created_at = c.sqlite3_column_int64(stmt, 5);
    return u;
}

pub fn findUserByUsername(db: *c.sqlite3, username: []const u8) ?UserRow {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql =
        \\SELECT id, username, COALESCE(display_name,''), COALESCE(bio,''), is_locked, created_at
        \\FROM ap_users WHERE username = ? LIMIT 1
    ;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return null;
    }
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, username.ptr, @intCast(username.len), Transient());
    if (c.sqlite3_step(stmt) != c.SQLITE_ROW) return null;
    var u: UserRow = .{ .id = c.sqlite3_column_int64(stmt, 0) };
    copyText(stmt.?, 1, &u.username_buf, &u.username_len);
    copyText(stmt.?, 2, &u.display_buf, &u.display_len);
    copyText(stmt.?, 3, &u.bio_buf, &u.bio_len);
    u.is_locked = c.sqlite3_column_int(stmt, 4) != 0;
    u.created_at = c.sqlite3_column_int64(stmt, 5);
    return u;
}

pub fn insertUser(db: *c.sqlite3, username: []const u8, display_name: []const u8, bio: []const u8, now_unix: i64) !i64 {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql =
        \\INSERT INTO ap_users(username, display_name, bio, is_locked, discoverable, indexable, created_at)
        \\VALUES (?, ?, ?, 0, 1, 1, ?)
    ;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, username.ptr, @intCast(username.len), Transient());
    _ = c.sqlite3_bind_text(stmt, 2, display_name.ptr, @intCast(display_name.len), Transient());
    _ = c.sqlite3_bind_text(stmt, 3, bio.ptr, @intCast(bio.len), Transient());
    _ = c.sqlite3_bind_int64(stmt, 4, now_unix);
    if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.StepFailed;
    return c.sqlite3_last_insert_rowid(db);
}

pub fn countUsers(db: *c.sqlite3) i64 {
    return scalarInt(db, "SELECT COUNT(*) FROM ap_users");
}

pub fn countStatuses(db: *c.sqlite3) i64 {
    return scalarInt(db, "SELECT COUNT(*) FROM ap_activities WHERE type='Create'");
}

fn scalarInt(db: *c.sqlite3, sql: [*:0]const u8) i64 {
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return 0;
    }
    defer _ = c.sqlite3_finalize(stmt);
    if (c.sqlite3_step(stmt) != c.SQLITE_ROW) return 0;
    return c.sqlite3_column_int64(stmt, 0);
}

// ── Apps + tokens ────────────────────────────────────────────────

pub const AppRow = struct {
    id: i64,
    client_id_buf: [64]u8 = undefined,
    client_id_len: usize = 0,
    client_secret_buf: [64]u8 = undefined,
    client_secret_len: usize = 0,
    name_buf: [128]u8 = undefined,
    name_len: usize = 0,
    redirect_buf: [256]u8 = undefined,
    redirect_len: usize = 0,
    scopes_buf: [128]u8 = undefined,
    scopes_len: usize = 0,
    website_buf: [256]u8 = undefined,
    website_len: usize = 0,

    pub fn clientId(self: *const AppRow) []const u8 {
        return self.client_id_buf[0..self.client_id_len];
    }
    pub fn clientSecret(self: *const AppRow) []const u8 {
        return self.client_secret_buf[0..self.client_secret_len];
    }
    pub fn name(self: *const AppRow) []const u8 {
        return self.name_buf[0..self.name_len];
    }
    pub fn redirectUri(self: *const AppRow) []const u8 {
        return self.redirect_buf[0..self.redirect_len];
    }
    pub fn scopes(self: *const AppRow) []const u8 {
        return self.scopes_buf[0..self.scopes_len];
    }
    pub fn website(self: *const AppRow) []const u8 {
        return self.website_buf[0..self.website_len];
    }
};

pub fn insertApp(db: *c.sqlite3, app: AppRow, now_unix: i64) !i64 {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql =
        \\INSERT INTO mastodon_apps(client_id, client_secret, name, redirect_uri, scopes, website, vapid_key, created_at)
        \\VALUES (?, ?, ?, ?, ?, ?, '', ?)
    ;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, app.clientId().ptr, @intCast(app.clientId().len), Transient());
    _ = c.sqlite3_bind_text(stmt, 2, app.clientSecret().ptr, @intCast(app.clientSecret().len), Transient());
    _ = c.sqlite3_bind_text(stmt, 3, app.name().ptr, @intCast(app.name().len), Transient());
    _ = c.sqlite3_bind_text(stmt, 4, app.redirectUri().ptr, @intCast(app.redirectUri().len), Transient());
    _ = c.sqlite3_bind_text(stmt, 5, app.scopes().ptr, @intCast(app.scopes().len), Transient());
    _ = c.sqlite3_bind_text(stmt, 6, app.website().ptr, @intCast(app.website().len), Transient());
    _ = c.sqlite3_bind_int64(stmt, 7, now_unix);
    if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.StepFailed;
    return c.sqlite3_last_insert_rowid(db);
}

pub fn findAppByClientId(db: *c.sqlite3, client_id: []const u8) ?AppRow {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql =
        \\SELECT id, client_id, client_secret, name, redirect_uri, scopes, COALESCE(website,'')
        \\FROM mastodon_apps WHERE client_id = ? LIMIT 1
    ;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return null;
    }
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, client_id.ptr, @intCast(client_id.len), Transient());
    if (c.sqlite3_step(stmt) != c.SQLITE_ROW) return null;
    var a: AppRow = .{ .id = c.sqlite3_column_int64(stmt, 0) };
    copyText(stmt.?, 1, &a.client_id_buf, &a.client_id_len);
    copyText(stmt.?, 2, &a.client_secret_buf, &a.client_secret_len);
    copyText(stmt.?, 3, &a.name_buf, &a.name_len);
    copyText(stmt.?, 4, &a.redirect_buf, &a.redirect_len);
    copyText(stmt.?, 5, &a.scopes_buf, &a.scopes_len);
    copyText(stmt.?, 6, &a.website_buf, &a.website_len);
    return a;
}

pub fn insertToken(db: *c.sqlite3, jti: []const u8, app_id: i64, user_id: i64, scopes: []const u8, expires_at: i64, now_unix: i64) !void {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql =
        \\INSERT INTO mastodon_tokens(jti, app_id, user_id, scopes, expires_at, revoked, created_at)
        \\VALUES (?, ?, ?, ?, ?, 0, ?)
    ;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, jti.ptr, @intCast(jti.len), Transient());
    _ = c.sqlite3_bind_int64(stmt, 2, app_id);
    if (user_id == 0) {
        _ = c.sqlite3_bind_null(stmt, 3);
    } else {
        _ = c.sqlite3_bind_int64(stmt, 3, user_id);
    }
    _ = c.sqlite3_bind_text(stmt, 4, scopes.ptr, @intCast(scopes.len), Transient());
    _ = c.sqlite3_bind_int64(stmt, 5, expires_at);
    _ = c.sqlite3_bind_int64(stmt, 6, now_unix);
    if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.StepFailed;
}

pub fn revokeToken(db: *c.sqlite3, jti: []const u8) !void {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "UPDATE mastodon_tokens SET revoked = 1 WHERE jti = ?";
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, jti.ptr, @intCast(jti.len), Transient());
    if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.StepFailed;
}

// ── Statuses (read from ap_activities) ────────────────────────────

pub const StatusRow = struct {
    id: i64,
    actor_id: i64,
    published: i64,
    content_buf: [4096]u8 = undefined,
    content_len: usize = 0,

    pub fn content(self: *const StatusRow) []const u8 {
        return self.content_buf[0..self.content_len];
    }
};

pub fn insertStatus(db: *c.sqlite3, actor_id: i64, ap_id: []const u8, content: []const u8, now_unix: i64) !i64 {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql =
        \\INSERT INTO ap_activities(ap_id, actor_id, type, object_id, published, raw)
        \\VALUES (?, ?, 'Create', NULL, ?, ?)
    ;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, ap_id.ptr, @intCast(ap_id.len), Transient());
    _ = c.sqlite3_bind_int64(stmt, 2, actor_id);
    _ = c.sqlite3_bind_int64(stmt, 3, now_unix);
    _ = c.sqlite3_bind_blob(stmt, 4, content.ptr, @intCast(content.len), Transient());
    if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.StepFailed;
    return c.sqlite3_last_insert_rowid(db);
}

pub fn findStatusById(db: *c.sqlite3, id: i64) ?StatusRow {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "SELECT id, actor_id, published, raw FROM ap_activities WHERE id = ? AND type='Create' LIMIT 1";
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return null;
    }
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_int64(stmt, 1, id);
    if (c.sqlite3_step(stmt) != c.SQLITE_ROW) return null;
    var s: StatusRow = .{
        .id = c.sqlite3_column_int64(stmt, 0),
        .actor_id = c.sqlite3_column_int64(stmt, 1),
        .published = c.sqlite3_column_int64(stmt, 2),
    };
    const ptr = c.sqlite3_column_blob(stmt, 3);
    const n: usize = @intCast(c.sqlite3_column_bytes(stmt, 3));
    const copy_n = @min(n, s.content_buf.len);
    if (ptr != null and copy_n > 0) @memcpy(s.content_buf[0..copy_n], @as([*]const u8, @ptrCast(ptr))[0..copy_n]);
    s.content_len = copy_n;
    return s;
}

pub fn deleteStatus(db: *c.sqlite3, id: i64, actor_id: i64) !bool {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "DELETE FROM ap_activities WHERE id = ? AND actor_id = ? AND type='Create'";
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_int64(stmt, 1, id);
    _ = c.sqlite3_bind_int64(stmt, 2, actor_id);
    if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.StepFailed;
    return c.sqlite3_changes(db) > 0;
}

pub const StatusIter = struct {
    stmt: ?*c.sqlite3_stmt,

    pub fn deinit(self: *StatusIter) void {
        if (self.stmt != null) _ = c.sqlite3_finalize(self.stmt);
        self.stmt = null;
    }

    pub fn next(self: *StatusIter, out: *StatusRow) bool {
        if (self.stmt == null) return false;
        const stmt = self.stmt.?;
        if (c.sqlite3_step(stmt) != c.SQLITE_ROW) return false;
        out.* = .{
            .id = c.sqlite3_column_int64(stmt, 0),
            .actor_id = c.sqlite3_column_int64(stmt, 1),
            .published = c.sqlite3_column_int64(stmt, 2),
        };
        const ptr = c.sqlite3_column_blob(stmt, 3);
        const n: usize = @intCast(c.sqlite3_column_bytes(stmt, 3));
        const copy_n = @min(n, out.content_buf.len);
        if (ptr != null and copy_n > 0) @memcpy(out.content_buf[0..copy_n], @as([*]const u8, @ptrCast(ptr))[0..copy_n]);
        out.content_len = copy_n;
        return true;
    }
};

/// Build a paginated status iterator. Caller must `deinit`.
/// Uses a single SQL shape and lets `? = 0` short-circuit unused filters.
/// Parameter order: actor_filter (0=any), since_id, max_filter (0=any), limit.
pub fn queryStatuses(db: *c.sqlite3, actor_id: i64, since_id: i64, max_id: i64, limit: i64) StatusIter {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql =
        \\SELECT id, actor_id, published, raw FROM ap_activities
        \\WHERE type='Create'
        \\  AND (?1 = 0 OR actor_id = ?1)
        \\  AND id > ?2
        \\  AND (?3 = 0 OR id < ?3)
        \\ORDER BY id DESC LIMIT ?4
    ;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return .{ .stmt = null };
    }
    _ = c.sqlite3_bind_int64(stmt, 1, actor_id);
    _ = c.sqlite3_bind_int64(stmt, 2, since_id);
    _ = c.sqlite3_bind_int64(stmt, 3, max_id);
    _ = c.sqlite3_bind_int64(stmt, 4, if (limit <= 0) 20 else limit);
    return .{ .stmt = stmt };
}

// ── Favourites / reblogs ──────────────────────────────────────────

pub fn addFavourite(db: *c.sqlite3, status_id: i64, user_id: i64, now_unix: i64) !void {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "INSERT OR IGNORE INTO mastodon_favourites(status_id,user_id,created_at) VALUES (?,?,?)";
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_int64(stmt, 1, status_id);
    _ = c.sqlite3_bind_int64(stmt, 2, user_id);
    _ = c.sqlite3_bind_int64(stmt, 3, now_unix);
    if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.StepFailed;
}

pub fn removeFavourite(db: *c.sqlite3, status_id: i64, user_id: i64) !void {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "DELETE FROM mastodon_favourites WHERE status_id=? AND user_id=?";
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_int64(stmt, 1, status_id);
    _ = c.sqlite3_bind_int64(stmt, 2, user_id);
    if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.StepFailed;
}

pub fn countFavourites(db: *c.sqlite3, status_id: i64) i64 {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "SELECT COUNT(*) FROM mastodon_favourites WHERE status_id=?";
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return 0;
    }
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_int64(stmt, 1, status_id);
    if (c.sqlite3_step(stmt) != c.SQLITE_ROW) return 0;
    return c.sqlite3_column_int64(stmt, 0);
}

pub fn isFavourited(db: *c.sqlite3, status_id: i64, user_id: i64) bool {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "SELECT 1 FROM mastodon_favourites WHERE status_id=? AND user_id=?";
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return false;
    }
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_int64(stmt, 1, status_id);
    _ = c.sqlite3_bind_int64(stmt, 2, user_id);
    return c.sqlite3_step(stmt) == c.SQLITE_ROW;
}

pub fn addReblog(db: *c.sqlite3, status_id: i64, user_id: i64, now_unix: i64) !void {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "INSERT OR IGNORE INTO mastodon_reblogs(status_id,user_id,created_at) VALUES (?,?,?)";
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_int64(stmt, 1, status_id);
    _ = c.sqlite3_bind_int64(stmt, 2, user_id);
    _ = c.sqlite3_bind_int64(stmt, 3, now_unix);
    if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.StepFailed;
}

pub fn removeReblog(db: *c.sqlite3, status_id: i64, user_id: i64) !void {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "DELETE FROM mastodon_reblogs WHERE status_id=? AND user_id=?";
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_int64(stmt, 1, status_id);
    _ = c.sqlite3_bind_int64(stmt, 2, user_id);
    if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.StepFailed;
}

pub fn countReblogs(db: *c.sqlite3, status_id: i64) i64 {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "SELECT COUNT(*) FROM mastodon_reblogs WHERE status_id=?";
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return 0;
    }
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_int64(stmt, 1, status_id);
    if (c.sqlite3_step(stmt) != c.SQLITE_ROW) return 0;
    return c.sqlite3_column_int64(stmt, 0);
}

// ── Follows (against ap_follows) ──────────────────────────────────

pub fn upsertFollow(db: *c.sqlite3, follower: []const u8, followee: []const u8, state: []const u8, now_unix: i64) !void {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql =
        \\INSERT INTO ap_follows(follower, followee, state, accepted_at)
        \\VALUES (?, ?, ?, ?)
        \\ON CONFLICT(follower, followee) DO UPDATE SET state = excluded.state
    ;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, follower.ptr, @intCast(follower.len), Transient());
    _ = c.sqlite3_bind_text(stmt, 2, followee.ptr, @intCast(followee.len), Transient());
    _ = c.sqlite3_bind_text(stmt, 3, state.ptr, @intCast(state.len), Transient());
    _ = c.sqlite3_bind_int64(stmt, 4, now_unix);
    if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.StepFailed;
}

pub fn removeFollow(db: *c.sqlite3, follower: []const u8, followee: []const u8) !void {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "DELETE FROM ap_follows WHERE follower = ? AND followee = ?";
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, follower.ptr, @intCast(follower.len), Transient());
    _ = c.sqlite3_bind_text(stmt, 2, followee.ptr, @intCast(followee.len), Transient());
    if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.StepFailed;
}

pub fn isFollowing(db: *c.sqlite3, follower: []const u8, followee: []const u8) bool {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "SELECT 1 FROM ap_follows WHERE follower=? AND followee=? AND state='accepted'";
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return false;
    }
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, follower.ptr, @intCast(follower.len), Transient());
    _ = c.sqlite3_bind_text(stmt, 2, followee.ptr, @intCast(followee.len), Transient());
    return c.sqlite3_step(stmt) == c.SQLITE_ROW;
}

pub fn countFollows(db: *c.sqlite3, column: []const u8, value: []const u8) i64 {
    var buf: [128]u8 = undefined;
    const sql = std.fmt.bufPrintZ(&buf,
        "SELECT COUNT(*) FROM ap_follows WHERE {s} = ? AND state='accepted'",
        .{column},
    ) catch return 0;
    var stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, sql.ptr, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return 0;
    }
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_text(stmt, 1, value.ptr, @intCast(value.len), Transient());
    if (c.sqlite3_step(stmt) != c.SQLITE_ROW) return 0;
    return c.sqlite3_column_int64(stmt, 0);
}

// ── Notifications ────────────────────────────────────────────────

pub fn insertNotification(db: *c.sqlite3, user_id: i64, ntype: []const u8, from_account: []const u8, status_id: i64, now_unix: i64) !void {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql =
        \\INSERT INTO mastodon_notifications(user_id, type, from_account, status_id, created_at, read)
        \\VALUES (?, ?, ?, ?, ?, 0)
    ;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_int64(stmt, 1, user_id);
    _ = c.sqlite3_bind_text(stmt, 2, ntype.ptr, @intCast(ntype.len), Transient());
    _ = c.sqlite3_bind_text(stmt, 3, from_account.ptr, @intCast(from_account.len), Transient());
    if (status_id == 0) {
        _ = c.sqlite3_bind_null(stmt, 4);
    } else {
        _ = c.sqlite3_bind_int64(stmt, 4, status_id);
    }
    _ = c.sqlite3_bind_int64(stmt, 5, now_unix);
    if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.StepFailed;
}

pub fn clearNotifications(db: *c.sqlite3, user_id: i64) !void {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql = "DELETE FROM mastodon_notifications WHERE user_id = ?";
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) return error.PrepareFailed;
    defer _ = c.sqlite3_finalize(stmt);
    _ = c.sqlite3_bind_int64(stmt, 1, user_id);
    if (c.sqlite3_step(stmt) != c.SQLITE_DONE) return error.StepFailed;
}

pub const NotificationRow = struct {
    id: i64 = 0,
    type_buf: [16]u8 = undefined,
    type_len: usize = 0,
    from_buf: [256]u8 = undefined,
    from_len: usize = 0,
    status_id: i64 = 0,
    created_at: i64 = 0,

    pub fn typeStr(self: *const NotificationRow) []const u8 {
        return self.type_buf[0..self.type_len];
    }
    pub fn fromAccount(self: *const NotificationRow) []const u8 {
        return self.from_buf[0..self.from_len];
    }
};

pub const NotificationIter = struct {
    stmt: ?*c.sqlite3_stmt,

    pub fn deinit(self: *NotificationIter) void {
        if (self.stmt != null) _ = c.sqlite3_finalize(self.stmt);
        self.stmt = null;
    }

    pub fn next(self: *NotificationIter, out: *NotificationRow) bool {
        if (self.stmt == null) return false;
        const stmt = self.stmt.?;
        if (c.sqlite3_step(stmt) != c.SQLITE_ROW) return false;
        out.* = .{ .id = c.sqlite3_column_int64(stmt, 0) };
        copyText(stmt, 1, &out.type_buf, &out.type_len);
        copyText(stmt, 2, &out.from_buf, &out.from_len);
        if (c.sqlite3_column_type(stmt, 3) == c.SQLITE_NULL) {
            out.status_id = 0;
        } else {
            out.status_id = c.sqlite3_column_int64(stmt, 3);
        }
        out.created_at = c.sqlite3_column_int64(stmt, 4);
        return true;
    }
};

pub fn queryNotifications(db: *c.sqlite3, user_id: i64, limit: i64) NotificationIter {
    var stmt: ?*c.sqlite3_stmt = null;
    const sql =
        \\SELECT id, type, from_account, status_id, created_at
        \\FROM mastodon_notifications WHERE user_id = ? ORDER BY id DESC LIMIT ?
    ;
    if (c.sqlite3_prepare_v2(db, sql, -1, &stmt, null) != c.SQLITE_OK) {
        if (stmt != null) _ = c.sqlite3_finalize(stmt);
        return .{ .stmt = null };
    }
    _ = c.sqlite3_bind_int64(stmt, 1, user_id);
    _ = c.sqlite3_bind_int64(stmt, 2, if (limit <= 0) 20 else limit);
    return .{ .stmt = stmt };
}
