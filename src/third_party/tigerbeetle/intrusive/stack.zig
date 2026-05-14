// Vendored from tigerbeetle/src/stack.zig @ 44544ee11057bbc8fe826cb7f93e8e00a57f2fc1.
// Modifications: replaced `@import("./constants.zig")` with the local
//   `_shim.zig` (provides `verify`), and dropped the `stdx`-based fuzz test
//   pending TB Tranche 3's PRNG landing. TB tests are commented out with
//   `// TODO: re-enable when core.prng lands (TB Tranche 3)`.
// TigerBeetle is licensed under Apache 2.0; see src/third_party/tigerbeetle/LICENSE.

const std = @import("std");
const assert = std.debug.assert;

const constants = @import("_shim.zig");

pub const StackLink = extern struct {
    next: ?*StackLink = null,
};

/// An intrusive last in/first out linked list (LIFO).
/// The element type T must have a field called "next" of type StackType(T).Link.
pub fn StackType(comptime T: type) type {
    return struct {
        any: StackAny,

        pub const Link = StackLink;
        const Stack = @This();

        pub inline fn init(options: struct {
            capacity: u32,
            verify_push: bool,
        }) Stack {
            return .{ .any = .{
                .capacity = options.capacity,
                .verify_push = options.verify_push,
            } };
        }

        pub inline fn count(self: *Stack) u32 {
            return self.any.count;
        }

        pub inline fn capacity(self: *Stack) u32 {
            return self.any.capacity;
        }

        /// Pushes a new node to the first position of the Stack.
        pub inline fn push(self: *Stack, node: *T) void {
            self.any.push(&node.link);
        }

        /// Returns the first element of the Stack list, and removes it.
        pub inline fn pop(self: *Stack) ?*T {
            const link = self.any.pop() orelse return null;
            return @fieldParentPtr("link", link);
        }

        /// Returns the first element of the Stack list, but does not remove it.
        pub inline fn peek(self: *const Stack) ?*T {
            const link = self.any.peek() orelse return null;
            return @fieldParentPtr("link", link);
        }

        /// Checks if the Stack is empty.
        pub inline fn empty(self: *const Stack) bool {
            return self.any.empty();
        }

        /// Returns whether the linked list contains the given *exact element* (pointer comparison).
        pub inline fn contains(self: *const Stack, needle: *const T) bool {
            return self.any.contains(&needle.link);
        }
    };
}

// Non-generic implementation for smaller binary and faster compile times.
const StackAny = struct {
    head: ?*StackLink = null,

    count: u32 = 0,
    capacity: u32,

    // If the number of elements is large, the constants.verify check in push() can be too
    // expensive. Allow the user to gate it.
    verify_push: bool,

    fn push(self: *StackAny, link: *StackLink) void {
        if (constants.verify and self.verify_push) assert(!self.contains(link));

        assert((self.count == 0) == (self.head == null));
        assert(link.next == null);
        assert(self.count < self.capacity);

        // Insert the new element at the head.
        link.next = self.head;
        self.head = link;
        self.count += 1;
    }

    fn pop(self: *StackAny) ?*StackLink {
        assert((self.count == 0) == (self.head == null));

        const link = self.head orelse return null;
        self.head = link.next;
        link.next = null;
        self.count -= 1;
        return link;
    }

    fn peek(self: *const StackAny) ?*StackLink {
        return self.head;
    }

    fn empty(self: *const StackAny) bool {
        assert((self.count == 0) == (self.head == null));
        return self.head == null;
    }

    fn contains(self: *const StackAny, needle: *const StackLink) bool {
        assert(self.count <= self.capacity);
        var next = self.head;
        for (0..self.count + 1) |_| {
            const link = next orelse return false;
            if (link == needle) return true;
            next = link.next;
        } else unreachable;
    }
};

test "Stack: push/pop/peek/empty" {
    const testing = @import("std").testing;
    const Item = struct { link: StackLink = .{} };

    var one: Item = .{};
    var two: Item = .{};
    var three: Item = .{};

    var stack: StackType(Item) = StackType(Item).init(.{
        .capacity = 3,
        .verify_push = true,
    });

    try testing.expect(stack.empty());

    // Push one element and verify
    stack.push(&one);
    try testing.expect(!stack.empty());
    try testing.expectEqual(@as(?*Item, &one), stack.peek());
    try testing.expect(stack.contains(&one));
    try testing.expect(!stack.contains(&two));
    try testing.expect(!stack.contains(&three));

    // Push two more elements
    stack.push(&two);
    stack.push(&three);
    try testing.expect(!stack.empty());
    try testing.expectEqual(@as(?*Item, &three), stack.peek());
    try testing.expect(stack.contains(&one));
    try testing.expect(stack.contains(&two));
    try testing.expect(stack.contains(&three));

    // Pop elements and check Stack order
    try testing.expectEqual(@as(?*Item, &three), stack.pop());
    try testing.expectEqual(@as(?*Item, &two), stack.pop());
    try testing.expectEqual(@as(?*Item, &one), stack.pop());
    try testing.expect(stack.empty());
    try testing.expectEqual(@as(?*Item, null), stack.pop());
}

// PRNG-driven differential fuzz: mirror the Stack's contents in an
// ArrayList model and assert push/pop/peek/contains agree across N random
// operations. Re-enabled now that `tb_prng` is vendored.
test "Stack: fuzz against ArrayList model" {
    const testing = std.testing;
    const PRNG = @import("tb_prng");

    const Item = struct {
        id: u32,
        link: StackLink = .{},
    };
    const cap: u32 = 32;
    var pool: [cap]Item = undefined;
    for (&pool, 0..) |*it, i| it.* = .{ .id = @intCast(i) };

    var stack = StackType(Item).init(.{ .capacity = cap, .verify_push = true });

    // Mirror: each entry is either null (not in stack) or its position in
    // the stack from the top. We use an ArrayList of pointers as the model.
    var model: std.ArrayList(*Item) = .empty;
    defer model.deinit(testing.allocator);

    var prng = PRNG.from_seed(0xABCD_1234_5678_9ABC);
    var op: u32 = 0;
    const ops_total: u32 = 4_000;
    while (op < ops_total) : (op += 1) {
        const choose_push = prng.boolean();
        if (choose_push and model.items.len < cap) {
            // Pick an item not currently in the stack.
            // Linear scan is fine — cap is small.
            const start = prng.int_inclusive(u32, cap - 1);
            var picked: ?*Item = null;
            var k: u32 = 0;
            while (k < cap) : (k += 1) {
                const idx = (start + k) % cap;
                const candidate = &pool[idx];
                if (candidate.link.next == null) {
                    // Confirm not the head either.
                    if (!stack.contains(candidate)) {
                        picked = candidate;
                        break;
                    }
                }
            }
            if (picked) |p| {
                stack.push(p);
                try model.append(testing.allocator, p);
                try testing.expect(stack.contains(p));
                try testing.expectEqual(@as(?*Item, p), stack.peek());
            }
        } else if (model.items.len > 0) {
            const expected = model.items[model.items.len - 1];
            const got = stack.pop().?;
            try testing.expectEqual(expected, got);
            _ = model.pop();
            try testing.expect(!stack.contains(expected));
        } else {
            try testing.expect(stack.empty());
            try testing.expectEqual(@as(?*Item, null), stack.pop());
        }
        try testing.expectEqual(@as(u32, @intCast(model.items.len)), stack.count());
        try testing.expectEqual(model.items.len == 0, stack.empty());
    }
    // Drain so the test's debug allocator doesn't see lingering links.
    while (stack.pop() != null) {}
}
