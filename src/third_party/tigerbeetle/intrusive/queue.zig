// Vendored from tigerbeetle/src/queue.zig @ 44544ee11057bbc8fe826cb7f93e8e00a57f2fc1.
// Modifications: replaced `@import("./constants.zig")` with the local
//   `_shim.zig` (provides `verify`), and dropped the stdx + testing/fuzz
//   based fuzz test pending TB Tranche 3's PRNG landing. The deterministic
//   push/pop/peek/remove/empty test is preserved.
//   TB upstream fuzz is commented out with
//   `// TODO: re-enable when core.prng lands (TB Tranche 3)`.
// TigerBeetle is licensed under Apache 2.0; see src/third_party/tigerbeetle/LICENSE.

const std = @import("std");
const assert = std.debug.assert;

const constants = @import("_shim.zig");

const QueueLink = extern struct {
    next: ?*QueueLink = null,
};

/// An intrusive first in/first out linked list.
/// The element type T must have a field called "link" of type QueueType(T).Link.
pub fn QueueType(comptime T: type) type {
    return struct {
        any: QueueAny,

        pub const Link = QueueLink;
        const Queue = @This();

        pub inline fn init(options: struct {
            name: ?[]const u8,
            verify_push: bool = true,
        }) Queue {
            return .{ .any = .{
                .name = options.name,
                .verify_push = options.verify_push,
            } };
        }

        pub inline fn push(self: *Queue, link: *T) void {
            self.any.push(&link.link);
        }

        pub inline fn pop(self: *Queue) ?*T {
            const link = self.any.pop() orelse return null;
            return @alignCast(@fieldParentPtr("link", link));
        }

        pub inline fn peek_last(self: *const Queue) ?*T {
            const link = self.any.peek_last() orelse return null;
            return @alignCast(@fieldParentPtr("link", link));
        }

        pub inline fn peek(self: *const Queue) ?*T {
            const link = self.any.peek() orelse return null;
            return @alignCast(@fieldParentPtr("link", link));
        }

        pub fn count(self: *const Queue) u64 {
            return self.any.count;
        }

        pub fn name(self: *const Queue) ?[]const u8 {
            return self.any.name;
        }

        pub inline fn empty(self: *const Queue) bool {
            return self.any.empty();
        }

        /// Returns whether the linked list contains the given *exact element* (pointer comparison).
        pub inline fn contains(self: *const Queue, elem_needle: *const T) bool {
            return self.any.contains(&elem_needle.link);
        }

        /// Remove an element from the Queue. Asserts that the element is
        /// in the Queue. This operation is O(N), if this is done often you
        /// probably want a different data structure.
        pub inline fn remove(self: *Queue, to_remove: *T) void {
            self.any.remove(&to_remove.link);
        }

        pub inline fn reset(self: *Queue) void {
            self.any.reset();
        }

        pub inline fn iterate(self: *const Queue) Iterator {
            return .{ .any = self.any.iterate() };
        }

        pub const Iterator = struct {
            any: QueueAny.Iterator,

            pub inline fn next(iterator: *@This()) ?*T {
                const link = iterator.any.next() orelse return null;
                return @alignCast(@fieldParentPtr("link", link));
            }
        };
    };
}

// Non-generic implementation for smaller binary and faster compile times.
const QueueAny = struct {
    in: ?*QueueLink = null,
    out: ?*QueueLink = null,
    count: u64 = 0,

    // This should only be null if you're sure we'll never want to monitor `count`.
    name: ?[]const u8,

    // If the number of elements is large, the constants.verify check in push() can be too
    // expensive. Allow the user to gate it. Could also be a comptime param?
    verify_push: bool = true,

    pub fn push(self: *QueueAny, link: *QueueLink) void {
        if (constants.verify and self.verify_push) assert(!self.contains(link));

        assert(link.next == null);
        if (self.in) |in| {
            in.next = link;
            self.in = link;
        } else {
            assert(self.out == null);
            self.in = link;
            self.out = link;
        }
        self.count += 1;
    }

    pub fn pop(self: *QueueAny) ?*QueueLink {
        const result = self.out orelse return null;
        self.out = result.next;
        result.next = null;
        if (self.in == result) self.in = null;
        self.count -= 1;
        return result;
    }

    pub fn peek_last(self: *const QueueAny) ?*QueueLink {
        return self.in;
    }

    pub fn peek(self: *const QueueAny) ?*QueueLink {
        return self.out;
    }

    pub fn empty(self: *const QueueAny) bool {
        return self.peek() == null;
    }

    pub fn contains(self: *const QueueAny, needle: *const QueueLink) bool {
        var iterator = self.peek();
        while (iterator) |link| : (iterator = link.next) {
            if (link == needle) return true;
        }
        return false;
    }

    pub fn remove(self: *QueueAny, to_remove: *QueueLink) void {
        if (to_remove == self.out) {
            _ = self.pop();
            return;
        }
        var it = self.out;
        while (it) |link| : (it = link.next) {
            if (to_remove == link.next) {
                if (to_remove == self.in) self.in = link;
                link.next = to_remove.next;
                to_remove.next = null;
                self.count -= 1;
                break;
            }
        } else unreachable;
    }

    pub fn reset(self: *QueueAny) void {
        self.* = .{
            .name = self.name,
            .verify_push = self.verify_push,
        };
    }

    pub fn iterate(self: *const QueueAny) Iterator {
        return .{
            .head = self.out,
        };
    }

    const Iterator = struct {
        head: ?*QueueLink,

        fn next(iterator: *Iterator) ?*QueueLink {
            const head = iterator.head orelse return null;
            iterator.head = head.next;
            return head;
        }
    };
};

test "Queue: push/pop/peek/remove/empty" {
    const testing = @import("std").testing;

    const Item = struct { link: QueueType(@This()).Link = .{} };

    var one: Item = .{};
    var two: Item = .{};
    var three: Item = .{};

    var fifo = QueueType(Item).init(.{
        .name = null,
        .verify_push = true,
    });
    try testing.expect(fifo.empty());

    fifo.push(&one);
    try testing.expect(!fifo.empty());
    try testing.expectEqual(@as(?*Item, &one), fifo.peek());
    try testing.expect(fifo.contains(&one));
    try testing.expect(!fifo.contains(&two));
    try testing.expect(!fifo.contains(&three));

    fifo.push(&two);
    fifo.push(&three);
    try testing.expect(!fifo.empty());
    try testing.expectEqual(@as(?*Item, &one), fifo.peek());
    try testing.expect(fifo.contains(&one));
    try testing.expect(fifo.contains(&two));
    try testing.expect(fifo.contains(&three));

    fifo.remove(&one);
    try testing.expect(!fifo.empty());
    try testing.expectEqual(@as(?*Item, &two), fifo.pop());
    try testing.expectEqual(@as(?*Item, &three), fifo.pop());
    try testing.expectEqual(@as(?*Item, null), fifo.pop());
    try testing.expect(fifo.empty());
    try testing.expect(!fifo.contains(&one));
    try testing.expect(!fifo.contains(&two));
    try testing.expect(!fifo.contains(&three));

    fifo.push(&one);
    fifo.push(&two);
    fifo.push(&three);
    fifo.remove(&two);
    try testing.expect(!fifo.empty());
    try testing.expectEqual(@as(?*Item, &one), fifo.pop());
    try testing.expectEqual(@as(?*Item, &three), fifo.pop());
    try testing.expectEqual(@as(?*Item, null), fifo.pop());
    try testing.expect(fifo.empty());

    fifo.push(&one);
    fifo.push(&two);
    fifo.push(&three);
    fifo.remove(&three);
    try testing.expect(!fifo.empty());
    try testing.expectEqual(@as(?*Item, &one), fifo.pop());
    try testing.expect(!fifo.empty());
    try testing.expectEqual(@as(?*Item, &two), fifo.pop());
    try testing.expect(fifo.empty());
    try testing.expectEqual(@as(?*Item, null), fifo.pop());
    try testing.expect(fifo.empty());

    fifo.push(&one);
    fifo.push(&two);
    fifo.remove(&two);
    fifo.push(&three);
    try testing.expectEqual(@as(?*Item, &one), fifo.pop());
    try testing.expectEqual(@as(?*Item, &three), fifo.pop());
    try testing.expectEqual(@as(?*Item, null), fifo.pop());
    try testing.expect(fifo.empty());
}

// PRNG-driven differential fuzz: mirror the Queue's contents in an
// ArrayList model (FIFO order, front == index 0) and assert
// push/pop/peek/contains/remove agree across many random operations.
// Re-enabled now that `tb_prng` is vendored.
test "Queue: fuzz against ArrayList model" {
    const testing = std.testing;
    const PRNG = @import("tb_prng");

    const Item = struct { id: u32, link: QueueType(@This()).Link = .{} };
    const cap: u32 = 24;
    var pool: [cap]Item = undefined;
    for (&pool, 0..) |*it, i| it.* = .{ .id = @intCast(i) };

    var q = QueueType(Item).init(.{ .name = "fuzz", .verify_push = true });
    var model: std.ArrayList(*Item) = .empty;
    defer model.deinit(testing.allocator);

    var prng = PRNG.from_seed(0xCAFEBABE_DEADD00D);
    var op: u32 = 0;
    const ops_total: u32 = 4_000;
    while (op < ops_total) : (op += 1) {
        const choice = prng.int_inclusive(u32, 99);
        if (choice < 50 and model.items.len < cap) {
            // Pick an item not in queue.
            const start = prng.int_inclusive(u32, cap - 1);
            var picked: ?*Item = null;
            var k: u32 = 0;
            while (k < cap) : (k += 1) {
                const idx = (start + k) % cap;
                const c = &pool[idx];
                if (c.link.next == null and !q.contains(c)) {
                    picked = c;
                    break;
                }
            }
            if (picked) |p| {
                q.push(p);
                try model.append(testing.allocator, p);
                try testing.expect(q.contains(p));
            }
        } else if (choice < 80 and model.items.len > 0) {
            // pop (FIFO: front is first element).
            const expected = model.items[0];
            const got = q.pop().?;
            try testing.expectEqual(expected, got);
            _ = model.orderedRemove(0);
        } else if (model.items.len > 0) {
            // remove arbitrary element.
            const idx = prng.int_inclusive(u32, @as(u32, @intCast(model.items.len - 1)));
            const victim = model.items[idx];
            q.remove(victim);
            _ = model.orderedRemove(idx);
        }
        try testing.expectEqual(@as(u64, model.items.len), q.count());
        try testing.expectEqual(model.items.len == 0, q.empty());
        if (model.items.len > 0) {
            try testing.expectEqual(@as(?*Item, model.items[0]), q.peek());
            try testing.expectEqual(@as(?*Item, model.items[model.items.len - 1]), q.peek_last());
        }
    }
    while (q.pop() != null) {}
}
