//! Session / unit-of-work / identity map for one entity type.
//!
//! A `Session(T, capacity)` is a typed, bounded work unit: it caches loaded
//! entities (identity map — `get` returns the SAME pointer for the same PK),
//! tracks pending inserts/deletes, and snapshot-diffs managed entities so
//! `flush` emits the minimal set of UPDATEs and runs the whole batch in one
//! transaction. Tiger Style: a fixed slot array (linear scan, no hashmap),
//! no per-row heap — the whole map lives in the session's own storage.
//!
//! Heterogeneous (multi-type) sessions are a v1 non-goal; one Session per
//! entity type keeps the map fully comptime and allocation-free. Dirty
//! detection compares only *logical* field values (active text/blob slices,
//! scalar values) — never raw struct bytes, whose fixed-buffer tails are
//! undefined.

const std = @import("std");
const contract = @import("contract.zig");
const reflect = @import("reflect.zig");
const fields = @import("fields.zig");
const bind = @import("bind.zig");
const crud = @import("crud.zig");

const Backend = contract.Backend;
const Error = contract.Error;

/// Lifecycle state of a managed slot.
const State = enum { empty, clean, new, deleted };

/// The free-standing value type of one PK column: `[]const u8` for a text
/// PK, `i64` for an int/auto PK.
fn PkPartType(comptime col: reflect.ColumnSpec) type {
    return if (col.bind_kind == .text) []const u8 else i64;
}

/// A bounded, identity-mapped unit of work over entity `T`.
pub fn Session(comptime T: type, comptime capacity: usize) type {
    const info = reflect.TableInfo(T);

    return struct {
        const Self = @This();

        const Slot = struct {
            live: T = .{},
            snapshot: T = .{},
            state: State = .empty,
        };

        backend: Backend,
        slots: [capacity]Slot = [_]Slot{.{}} ** capacity,
        count: usize = 0,

        pub fn init(backend: Backend) Self {
            return .{ .backend = backend };
        }

        /// Drop all managed entities (does not touch the database).
        pub fn reset(self: *Self) void {
            self.count = 0;
            for (self.slots[0..]) |*s| s.state = .empty;
        }

        /// Number of currently managed (non-empty) slots.
        pub fn managed(self: *const Self) usize {
            var n: usize = 0;
            for (self.slots[0..]) |s| {
                if (s.state != .empty and s.state != .deleted) n += 1;
            }
            return n;
        }

        fn freeSlot(self: *Self) Error!*Slot {
            for (self.slots[0..]) |*s| {
                if (s.state == .empty) return s;
            }
            return Error.BackendFailed; // session capacity exceeded
        }

        fn findSlot(self: *Self, pk: bind.PkValue(T)) ?*Slot {
            for (self.slots[0..]) |*s| {
                if (s.state == .empty or s.state == .deleted) continue;
                if (pkEql(&s.live, pk)) return s;
            }
            return null;
        }

        /// Load (or return the already-managed) entity with primary key `pk`.
        /// Returns the SAME pointer on repeated calls (identity map). Null if
        /// no such row exists.
        pub fn get(self: *Self, pk: bind.PkValue(T)) Error!?*T {
            if (self.findSlot(pk)) |s| return &s.live;

            var loaded: T = .{};
            if (!try crud.findByPk(T, self.backend, pk, &loaded)) return null;

            return self.materialize(loaded);
        }

        /// Merge a freshly-fetched row into the identity map: if its PK is
        /// already managed, return the existing pointer (preserving any
        /// in-flight edits — the DB copy is discarded); otherwise adopt it
        /// as a clean managed entity. This is how the query builder dedups
        /// results against already-loaded entities.
        pub fn materialize(self: *Self, loaded: T) Error!*T {
            if (self.findSlot(pkValue(&loaded))) |s| return &s.live;
            const slot = try self.freeSlot();
            slot.live = loaded;
            slot.snapshot = loaded;
            slot.state = .clean;
            self.count += 1;
            return &slot.live;
        }

        /// Register a brand-new entity for insertion on the next `flush`.
        /// Returns a managed pointer (mutations to it are tracked).
        pub fn add(self: *Self, value: T) Error!*T {
            const slot = try self.freeSlot();
            slot.live = value;
            slot.state = .new;
            self.count += 1;
            return &slot.live;
        }

        /// Insert `value`, or update its non-PK columns on a PK collision
        /// (an upsert), executed immediately against the backend — it does
        /// NOT go through the unit-of-work batch. This bypasses the identity
        /// map and dirty tracking (the conflict resolution happens in the
        /// engine), so it is a direct, side-effecting write distinct from the
        /// `add`/`flush` path; existing flush semantics are untouched.
        pub fn upsert(self: *Self, value: *T) Error!void {
            return crud.upsert(T, self.backend, value);
        }

        /// Mark a managed entity for deletion on the next `flush`.
        pub fn remove(self: *Self, entity: *T) void {
            for (self.slots[0..]) |*s| {
                if (&s.live == entity) {
                    s.state = .deleted;
                    return;
                }
            }
        }

        /// Is the managed entity logically changed since it was loaded?
        pub fn isDirty(self: *Self, entity: *const T) bool {
            for (self.slots[0..]) |*s| {
                if (&s.live == entity) {
                    return s.state == .new or (s.state == .clean and !entityEql(T, &s.live, &s.snapshot));
                }
            }
            return false;
        }

        // ── flush (unit of work) ────────────────────────────────────────

        fn flushBody(ctx: *anyopaque) Error!void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            for (self.slots[0..]) |*s| {
                switch (s.state) {
                    .new => try crud.insert(T, self.backend, &s.live),
                    .clean => if (!entityEql(T, &s.live, &s.snapshot))
                        try crud.update(T, self.backend, &s.live),
                    .deleted => try crud.delete(T, self.backend, &s.live),
                    .empty => {},
                }
            }
        }

        /// Persist every pending change in ONE transaction: inserts, minimal
        /// UPDATEs for dirty rows, and deletes. On any failure the whole
        /// batch rolls back and the session is left unchanged (the caller
        /// may retry or `reset`). On success, snapshots are re-synced and
        /// deleted slots freed.
        pub fn flush(self: *Self) Error!void {
            if (self.count == 0) return;
            try self.backend.transaction(self, flushBody);

            // Commit succeeded — reconcile in-memory state.
            for (self.slots[0..]) |*s| {
                switch (s.state) {
                    .new, .clean => {
                        s.snapshot = s.live;
                        s.state = .clean;
                    },
                    .deleted => {
                        s.state = .empty;
                        if (self.count > 0) self.count -= 1;
                    },
                    .empty => {},
                }
            }
        }

        /// One PK part's free-standing value (its `slice()` for text, its
        /// `.value` for int/auto).
        fn pkPart(comptime col: reflect.ColumnSpec, entity: *const T) PkPartType(col) {
            const f = &@field(entity.*, col.name);
            return if (col.bind_kind == .text) f.slice() else f.value;
        }

        /// PK value of `entity` as a free-standing key. Single PK → the lone
        /// value; composite → the `{ part0, part1, … }` tuple.
        fn pkValue(entity: *const T) bind.PkValue(T) {
            if (comptime !info.composite_pk) return pkPart(info.pk_column, entity);
            var key: bind.PkValue(T) = undefined;
            inline for (0..info.pk_count) |k| {
                key[k] = pkPart(info.pkColumn(k), entity);
            }
            return key;
        }

        /// Compare `entity`'s PK against a free-standing key — ALL PK columns
        /// for a composite key (every part must match).
        fn pkEql(entity: *const T, pk: bind.PkValue(T)) bool {
            if (comptime !info.composite_pk) return pkPartEql(info.pk_column, entity, pk);
            inline for (0..info.pk_count) |k| {
                if (!pkPartEql(info.pkColumn(k), entity, pk[k])) return false;
            }
            return true;
        }

        fn pkPartEql(comptime col: reflect.ColumnSpec, entity: *const T, part: anytype) bool {
            const f = &@field(entity.*, col.name);
            return if (col.bind_kind == .text)
                std.mem.eql(u8, f.slice(), part)
            else
                f.value == part;
        }
    };
}

/// Logical field-by-field equality for dirty tracking. Compares active
/// text/blob slices and scalar values — NOT raw struct bytes (whose
/// fixed-buffer tails past `len` are undefined).
pub fn entityEql(comptime T: type, a: *const T, b: *const T) bool {
    const info = reflect.TableInfo(T);
    inline for (info.columns) |col| {
        if (!fieldEql(col, a, b)) return false;
    }
    return true;
}

fn fieldEql(comptime col: reflect.ColumnSpec, a: anytype, b: anytype) bool {
    const fa = @field(a.*, col.name);
    const fb = @field(b.*, col.name);
    if (col.nullable) {
        const a_set = fa != null;
        const b_set = fb != null;
        if (a_set != b_set) return false;
        if (!a_set) return true;
        return scalarEql(col, &fa.?, &fb.?);
    }
    return scalarEql(col, &fa, &fb);
}

fn scalarEql(comptime col: reflect.ColumnSpec, pa: anytype, pb: anytype) bool {
    const V = @TypeOf(pa.*);
    return switch (col.bind_kind) {
        .text => if (col.is_enum)
            pa.* == pb.*
        else
            std.mem.eql(u8, pa.slice(), pb.slice()),
        .blob => std.mem.eql(u8, pa.slice(), pb.slice()),
        .int => blk: {
            if (@typeInfo(V) == .@"struct") {
                if (@hasField(V, "unix")) break :blk pa.unix == pb.unix;
                if (@hasField(V, "value")) break :blk pa.value == pb.value;
            }
            break :blk pa.* == pb.*;
        },
        .real => pa.* == pb.*,
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
    email: ?fields.Text(64) = null,
    role: Role = .member,
    score: f64 = 0,
};

fn newAccount(id: []const u8, handle: []const u8) Account {
    return .{ .id = fields.Pk(64).from(id), .handle = fields.Text(64).from(handle) };
}

test "identity map: get returns the same pointer twice" {
    var db = mock.MockBackend.init();
    var s = Session(Account, 16).init(db.backend(.sqlite));

    _ = try s.add(newAccount("u1", "alice"));
    try s.flush();
    s.reset();

    const p1 = (try s.get("u1")).?;
    const p2 = (try s.get("u1")).?;
    try testing.expectEqual(p1, p2);
    try testing.expectEqual(@as(usize, 1), s.managed());
}

test "insert via add + flush, then load back" {
    var db = mock.MockBackend.init();
    var s = Session(Account, 16).init(db.backend(.sqlite));

    var a = try s.add(newAccount("u2", "bob"));
    a.role = .admin;
    try testing.expect(s.isDirty(a)); // new => dirty
    try s.flush();
    try testing.expect(!s.isDirty(a)); // clean after flush

    s.reset();
    const loaded = (try s.get("u2")).?;
    try testing.expectEqualStrings("bob", loaded.handle.slice());
    try testing.expectEqual(Role.admin, loaded.role);
}

test "dirty tracking: mutating a loaded entity emits an UPDATE on flush" {
    var db = mock.MockBackend.init();
    var s = Session(Account, 16).init(db.backend(.sqlite));
    _ = try s.add(newAccount("u3", "carol"));
    try s.flush();
    s.reset();

    const a = (try s.get("u3")).?;
    try testing.expect(!s.isDirty(a));
    a.handle = fields.Text(64).from("caroline");
    a.score = 9.5;
    try testing.expect(s.isDirty(a));
    try s.flush();

    s.reset();
    const reloaded = (try s.get("u3")).?;
    try testing.expectEqualStrings("caroline", reloaded.handle.slice());
    try testing.expectEqual(@as(f64, 9.5), reloaded.score);
}

test "no-op flush when nothing changed (clean entity)" {
    var db = mock.MockBackend.init();
    var s = Session(Account, 16).init(db.backend(.sqlite));
    _ = try s.add(newAccount("u4", "dan"));
    try s.flush();
    s.reset();

    const a = (try s.get("u4")).?;
    try testing.expect(!s.isDirty(a));
    // flush with no changes must not corrupt the row.
    try s.flush();
    s.reset();
    const again = (try s.get("u4")).?;
    try testing.expectEqualStrings("dan", again.handle.slice());
}

test "delete via remove + flush" {
    var db = mock.MockBackend.init();
    var s = Session(Account, 16).init(db.backend(.sqlite));
    _ = try s.add(newAccount("u5", "eve"));
    try s.flush();
    s.reset();

    const a = (try s.get("u5")).?;
    s.remove(a);
    try s.flush();

    s.reset();
    try testing.expect((try s.get("u5")) == null);
}

test "unit of work: insert + update + delete batched in one flush" {
    var db = mock.MockBackend.init();
    var s = Session(Account, 16).init(db.backend(.sqlite));

    // Seed two rows.
    _ = try s.add(newAccount("keep", "k"));
    _ = try s.add(newAccount("drop", "d"));
    try s.flush();
    s.reset();

    const keep = (try s.get("keep")).?;
    keep.handle = fields.Text(64).from("kept");
    const drop = (try s.get("drop")).?;
    s.remove(drop);
    _ = try s.add(newAccount("fresh", "f"));
    try s.flush();

    s.reset();
    try testing.expectEqualStrings("kept", (try s.get("keep")).?.handle.slice());
    try testing.expect((try s.get("drop")) == null);
    try testing.expectEqualStrings("f", (try s.get("fresh")).?.handle.slice());
}

test "Session.upsert: insert then upsert the same PK updates, no duplicate" {
    var db = mock.MockBackend.init();
    var s = Session(Account, 16).init(db.backend(.sqlite));

    var a = newAccount("dup", "before");
    a.role = .member;
    try s.upsert(&a);

    var a2 = newAccount("dup", "after");
    a2.role = .admin;
    a2.score = 4.25;
    try s.upsert(&a2);

    // Reload through the session's identity map: the row is updated.
    const got = (try s.get("dup")).?;
    try testing.expectEqualStrings("after", got.handle.slice());
    try testing.expectEqual(Role.admin, got.role);
    try testing.expectEqual(@as(f64, 4.25), got.score);
    // Exactly one physical row for that PK.
    try testing.expectEqual(@as(usize, 1), db.rowCount("atp_accounts"));
}

// ── Composite primary key (Z4) ──────────────────────────────────────────

const TenantDoc = struct {
    pub const zorm_table = "tenant_docs";
    tenant: fields.Pk(32) = .{},
    doc_id: fields.Pk(32) = .{},
    title: fields.Text(64) = .{},
};

fn tdoc(tenant: []const u8, doc: []const u8, title: []const u8) TenantDoc {
    return .{
        .tenant = fields.Pk(32).from(tenant),
        .doc_id = fields.Pk(32).from(doc),
        .title = fields.Text(64).from(title),
    };
}

test "composite PK identity map: same pointer for the same composite key" {
    var db = mock.MockBackend.init();
    var s = Session(TenantDoc, 16).init(db.backend(.sqlite));

    _ = try s.add(tdoc("acme", "readme", "A"));
    _ = try s.add(tdoc("acme", "guide", "B")); // shares tenant, distinct key
    try s.flush();
    s.reset();

    // get with the composite tuple returns the SAME pointer on repeat calls.
    const p1 = (try s.get(.{ "acme", "readme" })).?;
    const p2 = (try s.get(.{ "acme", "readme" })).?;
    try testing.expectEqual(p1, p2);
    try testing.expectEqualStrings("A", p1.title.slice());

    // A different second key-part is a DISTINCT identity (different slot).
    const q = (try s.get(.{ "acme", "guide" })).?;
    try testing.expect(p1 != q);
    try testing.expectEqualStrings("B", q.title.slice());
    try testing.expectEqual(@as(usize, 2), s.managed());

    // A wholly absent composite key → null.
    try testing.expect((try s.get(.{ "acme", "missing" })) == null);
}

test "composite PK: dirty-track + flush updates by the full key" {
    var db = mock.MockBackend.init();
    var s = Session(TenantDoc, 16).init(db.backend(.sqlite));
    _ = try s.add(tdoc("acme", "readme", "orig"));
    _ = try s.add(tdoc("acme", "guide", "sib"));
    try s.flush();
    s.reset();

    const a = (try s.get(.{ "acme", "readme" })).?;
    try testing.expect(!s.isDirty(a));
    a.title = fields.Text(64).from("edited");
    try testing.expect(s.isDirty(a));
    try s.flush();
    s.reset();

    try testing.expectEqualStrings("edited", (try s.get(.{ "acme", "readme" })).?.title.slice());
    // Sibling under the same tenant is unaffected.
    try testing.expectEqualStrings("sib", (try s.get(.{ "acme", "guide" })).?.title.slice());
}

test "entityEql compares logical values, ignoring buffer tails" {
    var a = newAccount("x", "same");
    var b = newAccount("x", "same");
    try testing.expect(entityEql(Account, &a, &b));
    // Same logical handle written two different ways → still equal.
    a.handle = fields.Text(64).from("same");
    b.handle.set("same");
    try testing.expect(entityEql(Account, &a, &b));
    b.handle = fields.Text(64).from("different");
    try testing.expect(!entityEql(Account, &a, &b));
}
