// Vendored from tigerbeetle/src/list.zig @ 44544ee11057bbc8fe826cb7f93e8e00a57f2fc1.
// Modifications: replaced `@import("constants.zig")` with the local
//   `_shim.zig` (provides `verify`), and dropped the `stdx`-based fuzz test
//   pending TB Tranche 3's PRNG landing. The basic LIFO test is preserved.
//   TB upstream tests are commented out with
//   `// TODO: re-enable when core.prng lands (TB Tranche 3)`.
// TigerBeetle is licensed under Apache 2.0; see src/third_party/tigerbeetle/LICENSE.

const std = @import("std");
const assert = std.debug.assert;

const constants = @import("_shim.zig");

/// An intrusive doubly-linked list.
/// Currently it is LIFO for simplicity because its consumer (IO.awaiting) doesn't care about order.
pub fn DoublyLinkedListType(
    comptime Node: type,
    comptime field_back_enum: std.meta.FieldEnum(Node),
    comptime field_next_enum: std.meta.FieldEnum(Node),
) type {
    assert(@typeInfo(Node) == .@"struct");
    assert(field_back_enum != field_next_enum);

    const field_back = @tagName(field_back_enum);
    const field_next = @tagName(field_next_enum);
    assert(@FieldType(Node, field_back) == ?*Node);
    assert(@FieldType(Node, field_next) == ?*Node);

    return struct {
        const DoublyLinkedList = @This();

        tail: ?*Node = null,
        count: u32 = 0,

        pub fn verify(list: *const DoublyLinkedList) void {
            assert((list.count == 0) == (list.tail == null));

            var count: u32 = 0;
            var iterator = list.tail;

            if (iterator) |node| {
                assert(@field(node, field_next) == null);
            }

            while (iterator) |node| {
                const back = @field(node, field_back);
                if (back) |back_node| {
                    assert(back_node != node); // There are no cycles.
                    assert(@field(back_node, field_next) == node);
                }
                count += 1;
                iterator = back;
            }
            assert(count == list.count);
        }

        fn contains(list: *const DoublyLinkedList, target: *const Node) bool {
            var count: u32 = 0;

            var iterator = list.tail;
            while (iterator) |node| {
                if (node == target) return true;
                iterator = @field(node, field_back);
                count += 1;
            }

            assert(count == list.count);
            return false;
        }

        pub fn empty(list: *const DoublyLinkedList) bool {
            assert((list.count == 0) == (list.tail == null));
            return list.count == 0;
        }

        pub fn push(list: *DoublyLinkedList, node: *Node) void {
            if (constants.verify) assert(!list.contains(node));
            if (constants.verify) list.verify();
            assert(@field(node, field_back) == null);
            assert(@field(node, field_next) == null);

            if (list.tail) |tail| {
                assert(list.count > 0);
                assert(@field(tail, field_next) == null);

                @field(node, field_back) = tail;
                @field(tail, field_next) = node;
            } else {
                assert(list.count == 0);
            }

            list.tail = node;
            list.count += 1;
        }

        pub fn pop(list: *DoublyLinkedList) ?*Node {
            if (constants.verify) list.verify();

            if (list.tail) |tail_old| {
                assert(list.count > 0);
                assert(@field(tail_old, field_next) == null);

                list.tail = @field(tail_old, field_back);
                list.count -= 1;

                if (list.tail) |tail_new| {
                    assert(@field(tail_new, field_next) == tail_old);
                    @field(tail_new, field_next) = null;
                }

                @field(tail_old, field_back) = null;
                return tail_old;
            } else {
                assert(list.count == 0);
                return null;
            }
        }

        pub fn remove(list: *DoublyLinkedList, node: *Node) void {
            if (constants.verify) assert(list.contains(node));
            if (constants.verify) list.verify();
            assert(list.count > 0);
            assert(list.tail != null);

            const tail = list.tail.?;

            if (node == tail) {
                // Pop the last element of the list.
                assert(@field(node, field_next) == null);
                list.tail = @field(node, field_back);
            }
            if (@field(node, field_back)) |node_back| {
                assert(@field(node_back, field_next).? == node);
                @field(node_back, field_next) = @field(node, field_next);
            }
            if (@field(node, field_next)) |node_next| {
                assert(@field(node_next, field_back).? == node);
                @field(node_next, field_back) = @field(node, field_back);
            }
            @field(node, field_back) = null;
            @field(node, field_next) = null;
            list.count -= 1;

            if (constants.verify) list.verify();
            assert((list.count == 0) == (list.tail == null));
        }
    };
}

test "DoublyLinkedList LIFO" {
    const Node = struct { id: u32, back: ?*@This() = null, next: ?*@This() = null };
    const List = DoublyLinkedListType(Node, .back, .next);

    var nodes: [3]Node = undefined;
    for (&nodes, 0..) |*node, i| node.* = .{ .id = @intCast(i) };

    var list = List{};
    list.push(&nodes[0]);
    list.push(&nodes[1]);
    list.push(&nodes[2]);

    try std.testing.expectEqual(&nodes[2], list.pop().?);
    try std.testing.expectEqual(&nodes[1], list.pop().?);
    try std.testing.expectEqual(&nodes[0], list.pop().?);
    try std.testing.expectEqual(null, list.pop());
}

// PRNG-driven differential fuzz: mirror the DoublyLinkedList's contents
// in an ArrayList model and assert push/pop/remove agree across many
// random operations. Re-enabled now that `tb_prng` is vendored.
test "DoublyLinkedList: fuzz against ArrayList model" {
    const testing = std.testing;
    const PRNG = @import("tb_prng");

    const Node = struct { id: u32, back: ?*@This() = null, next: ?*@This() = null };
    const List = DoublyLinkedListType(Node, .back, .next);

    const cap: u32 = 24;
    var pool: [cap]Node = undefined;
    for (&pool, 0..) |*n, i| n.* = .{ .id = @intCast(i) };

    var list = List{};
    var model: std.ArrayList(*Node) = .empty;
    defer model.deinit(testing.allocator);

    var prng = PRNG.from_seed(0xDEAD_BEEF_FACE_F00D);
    var op: u32 = 0;
    const ops_total: u32 = 4_000;
    while (op < ops_total) : (op += 1) {
        // Choose: 0=push, 1=pop, 2=remove (if non-empty).
        const choice = prng.int_inclusive(u32, 99);
        if (choice < 45 and model.items.len < cap) {
            // Pick an item not in list. Linear scan over pool.
            const start = prng.int_inclusive(u32, cap - 1);
            var picked: ?*Node = null;
            var k: u32 = 0;
            while (k < cap) : (k += 1) {
                const idx = (start + k) % cap;
                const c = &pool[idx];
                if (c.back == null and c.next == null and list.tail != c) {
                    picked = c;
                    break;
                }
            }
            if (picked) |p| {
                list.push(p);
                try model.append(testing.allocator, p);
            }
        } else if (choice < 80 and model.items.len > 0) {
            const expected = model.items[model.items.len - 1];
            const got = list.pop().?;
            try testing.expectEqual(expected, got);
            _ = model.pop();
        } else if (model.items.len > 0) {
            // Middle-remove.
            const idx = prng.int_inclusive(u32, @as(u32, @intCast(model.items.len - 1)));
            const victim = model.items[idx];
            list.remove(victim);
            _ = model.orderedRemove(idx);
        }
        try testing.expectEqual(@as(u32, @intCast(model.items.len)), list.count);
        try testing.expectEqual(model.items.len == 0, list.empty());
    }
    while (list.pop() != null) {}
}
