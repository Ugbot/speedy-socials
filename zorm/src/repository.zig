//! Repository — the public, ActiveRecord-style handle for an entity type.
//!
//! `Repository(T)` bundles an identity-mapped `Session` (default capacity)
//! with its backend and exposes the everyday API: `find`/`add`/`delete`/
//! `flush` (session-managed, unit-of-work) plus `findByPk`/`insertNow`/
//! `deleteNow` (stateless, immediate — no session bookkeeping) for simple
//! read or fire-and-forget paths. Tiger Style: the session's slot array is
//! the only storage; no per-row heap.

const std = @import("std");
const contract = @import("contract.zig");
const fields = @import("fields.zig");
const bind = @import("bind.zig");
const crud = @import("crud.zig");
const session = @import("session.zig");

const Backend = contract.Backend;
const Error = contract.Error;

/// Default managed-entity capacity for a `Repository`'s session. Override
/// by using `session.Session(T, N)` directly when a request touches more.
pub const default_capacity: usize = 64;

pub fn Repository(comptime T: type) type {
    return struct {
        const Self = @This();
        pub const Session = session.Session(T, default_capacity);

        sess: Session,

        pub fn init(backend: Backend) Self {
            return .{ .sess = Session.init(backend) };
        }

        // ── session-managed (unit of work) ──────────────────────────────

        /// Find (and cache) the entity with primary key `pk`. Returns the
        /// same pointer on repeated calls; null if absent.
        pub fn find(self: *Self, pk: bind.PkValue(T)) Error!?*T {
            return self.sess.get(pk);
        }

        /// Stage `value` for insertion; returns a managed pointer.
        pub fn add(self: *Self, value: T) Error!*T {
            return self.sess.add(value);
        }

        /// Stage a managed entity for deletion.
        pub fn delete(self: *Self, entity: *T) void {
            self.sess.remove(entity);
        }

        /// Commit all staged inserts/updates/deletes in one transaction.
        pub fn flush(self: *Self) Error!void {
            return self.sess.flush();
        }

        /// Forget all managed entities (does not touch the database).
        pub fn clear(self: *Self) void {
            self.sess.reset();
        }

        pub fn isDirty(self: *Self, entity: *const T) bool {
            return self.sess.isDirty(entity);
        }

        // ── stateless / immediate ───────────────────────────────────────

        /// Load a row directly into `out` (no session caching). Returns
        /// false if absent.
        pub fn findByPk(self: *Self, pk: bind.PkValue(T), out: *T) Error!bool {
            return crud.findByPk(T, self.sess.backend, pk, out);
        }

        /// Insert `value` immediately (auto PK written back into `value`).
        pub fn insertNow(self: *Self, value: *T) Error!void {
            return crud.insert(T, self.sess.backend, value);
        }

        /// Update all non-PK columns of `value` immediately.
        pub fn updateNow(self: *Self, value: *const T) Error!void {
            return crud.update(T, self.sess.backend, value);
        }

        /// Delete the row with primary key `pk` immediately.
        pub fn deleteNow(self: *Self, pk: bind.PkValue(T)) Error!void {
            return crud.deleteByPk(T, self.sess.backend, pk);
        }
    };
}

// ── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;
const mock = @import("testing.zig");

const Role = enum { member, admin };
const Account = struct {
    pub const zorm_table = "atp_accounts";
    id: fields.Pk(64) = .{},
    handle: fields.Text(64) = .{},
    role: Role = .member,
};

test "Repository: managed find/add/flush" {
    var db = mock.MockBackend.init();
    var repo = Repository(Account).init(db.backend(.sqlite));

    _ = try repo.add(.{ .id = fields.Pk(64).from("r1"), .handle = fields.Text(64).from("ann"), .role = .admin });
    try repo.flush();
    repo.clear();

    const a = (try repo.find("r1")).?;
    try testing.expectEqualStrings("ann", a.handle.slice());
    try testing.expectEqual(Role.admin, a.role);
    // identity map: same pointer.
    try testing.expectEqual(a, (try repo.find("r1")).?);
}

test "Repository: stateless immediate path" {
    var db = mock.MockBackend.init();
    var repo = Repository(Account).init(db.backend(.sqlite));

    var a = Account{ .id = fields.Pk(64).from("r2"), .handle = fields.Text(64).from("bob") };
    try repo.insertNow(&a);

    var got: Account = .{};
    try testing.expect(try repo.findByPk("r2", &got));
    try testing.expectEqualStrings("bob", got.handle.slice());

    try repo.deleteNow("r2");
    try testing.expect(!try repo.findByPk("r2", &got));
}
