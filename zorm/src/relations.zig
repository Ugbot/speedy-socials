//! Relations — BelongsTo / HasMany / HasOne — as comptime-generated entity
//! field types. A relation field carries the `zorm_relation` marker so the
//! reflection layer skips it (it owns no column; the foreign key is a
//! separate scalar column on the child). Loading is lazy and explicit:
//! `load(...)` runs the query the first time. `BelongsTo` caches its parent
//! (one query, then zero). Collections (`HasMany`/`HasOne`) fill a
//! caller-owned bounded slice — no lazy collection proxies (a v1 non-goal),
//! so they re-query each call by design.
//!
//! Example:
//!   const User = struct {
//!       pub const zorm_table = "users";
//!       id: zorm.Pk(64) = .{}, name: zorm.Text(64) = .{},
//!       posts: zorm.HasMany(Post, "author_id") = .{},
//!   };
//!   const Post = struct {
//!       pub const zorm_table = "posts";
//!       id: zorm.Pk(64) = .{}, author_id: zorm.Text(64) = .{},
//!       author: zorm.BelongsTo(User, "author_id", .{ .on_delete = .cascade }) = .{},
//!   };

const std = @import("std");
const contract = @import("contract.zig");
const reflect = @import("reflect.zig");
const fields = @import("fields.zig");
const bind = @import("bind.zig");
const crud = @import("crud.zig");
const query = @import("query.zig");
const ddl = @import("ddl.zig");

const Backend = contract.Backend;
const BindValue = contract.BindValue;
const Error = contract.Error;

pub const Kind = enum { belongs_to, has_many, has_one };

/// Referential action for a foreign key's ON DELETE / ON UPDATE clause.
pub const Action = enum {
    no_action,
    restrict,
    cascade,
    set_null,
    set_default,

    /// SQL clause text (empty for the default `no_action`, which needs no
    /// clause). Valid on SQLite, Postgres, and MySQL alike.
    pub fn sql(self: Action) []const u8 {
        return switch (self) {
            .no_action => "",
            .restrict => "RESTRICT",
            .cascade => "CASCADE",
            .set_null => "SET NULL",
            .set_default => "SET DEFAULT",
        };
    }
};

/// Foreign-key policy carried by a `BelongsTo` relation. Drives the DDL
/// `FOREIGN KEY … ON DELETE/UPDATE …` clause that `ddl.createTable` emits.
pub const FkOpts = struct {
    on_delete: Action = .no_action,
    on_update: Action = .no_action,
};

/// Resolve a child's foreign-key field (BY POINTER — a text FK's slice must
/// reference the owner's stable field, not a temporary copy) to the parent's
/// PK value type.
fn fkToPk(comptime Parent: type, fk_ptr: anytype) bind.PkValue(Parent) {
    return if (comptime bind.PkValue(Parent) == []const u8) fk_ptr.slice() else fk_ptr.*;
}

/// The owner entity's PK as a `BindValue` (for a child's FK match).
fn ownerPkBind(owner: anytype) BindValue {
    const P = @TypeOf(owner.*);
    return bind.bindPk(P, owner);
}

/// A child→parent reference. `fk_field` is the child's foreign-key column
/// (a `Text(N)`/`Pk(N)` for a text parent PK, or an `i64` for an auto PK).
/// `opts` sets the ON DELETE / ON UPDATE policy emitted into the table DDL.
pub fn BelongsTo(comptime Parent: type, comptime fk_field: []const u8, comptime opts: FkOpts) type {
    return struct {
        const Self = @This();
        pub const zorm_relation = {};
        pub const kind: Kind = .belongs_to;
        pub const Target = Parent;
        pub const foreign_key = fk_field;
        pub const fk_opts: FkOpts = opts;

        cached: Parent = .{},
        state: enum { unloaded, present, absent } = .unloaded,

        /// Load (once) and cache the parent referenced by `owner`'s FK.
        /// Returns the cached pointer on subsequent calls (zero queries).
        /// Null if the FK points at no row.
        pub fn load(self: *Self, owner: anytype, backend: Backend) Error!?*Parent {
            switch (self.state) {
                .present => return &self.cached,
                .absent => return null,
                .unloaded => {},
            }
            const pk = fkToPk(Parent, &@field(owner.*, fk_field));
            if (try crud.findByPk(Parent, backend, pk, &self.cached)) {
                self.state = .present;
                return &self.cached;
            }
            self.state = .absent;
            return null;
        }

        /// The cached parent without loading (null if not yet loaded or absent).
        pub fn get(self: *Self) ?*Parent {
            return if (self.state == .present) &self.cached else null;
        }

        /// Drop the cache so the next `load` re-queries.
        pub fn invalidate(self: *Self) void {
            self.state = .unloaded;
        }

        pub fn isLoaded(self: *const Self) bool {
            return self.state != .unloaded;
        }
    };
}

/// A parent→children collection. `fk_field` is the child's foreign-key
/// column referencing this parent's PK.
pub fn HasMany(comptime Child: type, comptime fk_field: []const u8) type {
    return struct {
        const Self = @This();
        pub const zorm_relation = {};
        pub const kind: Kind = .has_many;
        pub const Target = Child;
        pub const foreign_key = fk_field;

        /// Load this parent's children into `out` (bounded by its length).
        /// Returns the count. Re-queries each call (no cached collection).
        pub fn load(self: *const Self, owner: anytype, backend: Backend, out: []Child) Error!usize {
            _ = self;
            var q = query.Query(Child).init(backend.dialect);
            _ = q.where(fk_field, ownerPkBind(owner));
            return q.all(backend, out);
        }

        /// Load children routed through `sess`'s identity map (dedup).
        pub fn loadManaged(self: *const Self, owner: anytype, sess: anytype, out: []*Child) Error!usize {
            _ = self;
            var q = query.Query(Child).init(sess.backend.dialect);
            _ = q.where(fk_field, ownerPkBind(owner));
            return q.allManaged(sess, out);
        }
    };
}

/// A parent→single-child reference (the inverse of a unique BelongsTo).
pub fn HasOne(comptime Child: type, comptime fk_field: []const u8) type {
    return struct {
        const Self = @This();
        pub const zorm_relation = {};
        pub const kind: Kind = .has_one;
        pub const Target = Child;
        pub const foreign_key = fk_field;

        /// Load the single child for this parent into `out`. False if none.
        pub fn load(self: *const Self, owner: anytype, backend: Backend, out: *Child) Error!bool {
            _ = self;
            var q = query.Query(Child).init(backend.dialect);
            _ = q.where(fk_field, ownerPkBind(owner));
            return q.first(backend, out);
        }
    };
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;
const mock = @import("testing.zig");
const session = @import("session.zig");

const User = struct {
    pub const zorm_table = "users";
    id: fields.Pk(64) = .{},
    name: fields.Text(64) = .{},
    posts: HasMany(Post, "author_id") = .{},
    profile: HasOne(Profile, "user_id") = .{},
};

const Post = struct {
    pub const zorm_table = "posts";
    id: fields.Pk(64) = .{},
    author_id: fields.Text(64) = .{},
    title: fields.Text(64) = .{},
    author: BelongsTo(User, "author_id", .{ .on_delete = .cascade }) = .{},
};

const Profile = struct {
    pub const zorm_table = "profiles";
    id: fields.Pk(64) = .{},
    user_id: fields.Text(64) = .{},
    bio: fields.Text(64) = .{},
};

fn mkUser(backend: Backend, id: []const u8, name: []const u8) !void {
    var u = User{ .id = fields.Pk(64).from(id), .name = fields.Text(64).from(name) };
    try crud.insert(User, backend, &u);
}
fn mkPost(backend: Backend, id: []const u8, author: []const u8, title: []const u8) !void {
    var p = Post{
        .id = fields.Pk(64).from(id),
        .author_id = fields.Text(64).from(author),
        .title = fields.Text(64).from(title),
    };
    try crud.insert(Post, backend, &p);
}

test "relation fields are not persisted columns" {
    const info = reflect.TableInfo(User);
    try testing.expectEqual(@as(usize, 2), info.column_count); // id, name only
    const pinfo = reflect.TableInfo(Post);
    try testing.expectEqual(@as(usize, 3), pinfo.column_count); // id, author_id, title
}

test "BelongsTo loads parent and caches (1 query then 0)" {
    var db = mock.MockBackend.init();
    const backend = db.backend(.sqlite);
    try mkUser(backend, "u1", "alice");
    try mkPost(backend, "p1", "u1", "hello");

    var post: Post = .{};
    try testing.expect(try crud.findByPk(Post, backend, "p1", &post));
    try testing.expect(!post.author.isLoaded());

    const author = (try post.author.load(&post, backend)).?;
    try testing.expectEqualStrings("alice", author.name.slice());
    try testing.expect(post.author.isLoaded());

    // Second load returns the SAME cached pointer.
    const again = (try post.author.load(&post, backend)).?;
    try testing.expectEqual(author, again);
    try testing.expectEqual(author, post.author.get().?);
}

test "BelongsTo returns null when the FK points nowhere" {
    var db = mock.MockBackend.init();
    const backend = db.backend(.sqlite);
    var post = Post{ .id = fields.Pk(64).from("p9"), .author_id = fields.Text(64).from("ghost") };
    try testing.expect((try post.author.load(&post, backend)) == null);
    try testing.expect(post.author.isLoaded()); // loaded == "we tried"
}

test "HasMany fills a bounded slice with the parent's children" {
    var db = mock.MockBackend.init();
    const backend = db.backend(.sqlite);
    try mkUser(backend, "u2", "bob");
    try mkPost(backend, "a", "u2", "first");
    try mkPost(backend, "b", "u2", "second");
    try mkPost(backend, "c", "other", "nope");

    var user: User = .{};
    try testing.expect(try crud.findByPk(User, backend, "u2", &user));

    var out: [8]Post = undefined;
    const n = try user.posts.load(&user, backend, &out);
    try testing.expectEqual(@as(usize, 2), n);
    for (out[0..n]) |p| try testing.expectEqualStrings("u2", p.author_id.slice());
}

test "HasMany loadManaged dedups through the session" {
    var db = mock.MockBackend.init();
    const backend = db.backend(.sqlite);
    try mkUser(backend, "u3", "carol");
    try mkPost(backend, "x", "u3", "t1");

    var s = session.Session(Post, 8).init(backend);
    const preloaded = (try s.get("x")).?;
    preloaded.title = fields.Text(64).from("edited-in-flight");

    var user = User{ .id = fields.Pk(64).from("u3") };
    var out: [8]*Post = undefined;
    const n = try user.posts.loadManaged(&user, &s, &out);
    try testing.expectEqual(@as(usize, 1), n);
    try testing.expectEqual(preloaded, out[0]); // same managed pointer
    try testing.expectEqualStrings("edited-in-flight", out[0].title.slice());
}

test "HasOne loads the single related child" {
    var db = mock.MockBackend.init();
    const backend = db.backend(.sqlite);
    try mkUser(backend, "u4", "dan");
    var prof = Profile{ .id = fields.Pk(64).from("pr1"), .user_id = fields.Text(64).from("u4"), .bio = fields.Text(64).from("hi") };
    try crud.insert(Profile, backend, &prof);

    var user = User{ .id = fields.Pk(64).from("u4") };
    var got: Profile = .{};
    try testing.expect(try user.profile.load(&user, backend, &got));
    try testing.expectEqualStrings("hi", got.bio.slice());

    var none = User{ .id = fields.Pk(64).from("nobody") };
    var got2: Profile = .{};
    try testing.expect(!try none.profile.load(&none, backend, &got2));
}

test "foreignKeys: BelongsTo yields an FkSpec; HasMany/HasOne do not" {
    const fks = reflect.foreignKeys(Post);
    try testing.expectEqual(@as(usize, 1), fks.len);
    try testing.expectEqualStrings("author_id", fks[0].local_col);
    try testing.expectEqualStrings("users", fks[0].ref_table);
    try testing.expectEqualStrings("id", fks[0].ref_col);
    try testing.expectEqualStrings("CASCADE", fks[0].on_delete_sql);
    try testing.expectEqualStrings("", fks[0].on_update_sql);

    // The parent's HasMany/HasOne are not foreign keys on the parent table.
    try testing.expectEqual(@as(usize, 0), reflect.foreignKeys(User).len);
}

test "createTable emits the FOREIGN KEY clause for every dialect" {
    inline for (.{ .sqlite, .postgres, .mysql }) |d| {
        const sql = ddl.createTable(Post, d);
        try testing.expect(std.mem.indexOf(u8, sql, "FOREIGN KEY (author_id) REFERENCES users (id) ON DELETE CASCADE") != null);
    }
}

test "createIndex + foreignKeyIndexes" {
    try testing.expectEqualStrings(
        "CREATE INDEX IF NOT EXISTS ix_posts_author_id ON posts (author_id)",
        ddl.createIndex(Post, &.{"author_id"}, false, .sqlite),
    );
    try testing.expectEqualStrings(
        "CREATE UNIQUE INDEX IF NOT EXISTS ix_profiles_user_id ON profiles (user_id)",
        ddl.createIndex(Profile, &.{"user_id"}, true, .sqlite),
    );
    // T-SQL has no IF NOT EXISTS — guarded via sys.indexes.
    try testing.expectEqualStrings(
        "IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'ix_posts_author_id' AND object_id = OBJECT_ID(N'posts')) CREATE INDEX ix_posts_author_id ON posts (author_id)",
        ddl.createIndex(Post, &.{"author_id"}, false, .mssql),
    );
    const ix = ddl.foreignKeyIndexes(Post, .sqlite);
    try testing.expectEqual(@as(usize, 1), ix.len);
    try testing.expectEqualStrings("CREATE INDEX IF NOT EXISTS ix_posts_author_id ON posts (author_id)", ix[0]);

    // MySQL + T-SQL drop-index form names the table.
    try testing.expectEqualStrings("DROP INDEX ix_posts_author_id ON posts", ddl.dropIndex(Post, &.{"author_id"}, .mysql));
    try testing.expectEqualStrings("DROP INDEX ix_posts_author_id ON posts", ddl.dropIndex(Post, &.{"author_id"}, .mssql));
    try testing.expectEqualStrings("DROP INDEX IF EXISTS ix_posts_author_id", ddl.dropIndex(Post, &.{"author_id"}, .sqlite));
}
