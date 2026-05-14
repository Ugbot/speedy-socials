//! Re-exports of TigerBeetle's intrusive collections, vendored under
//! `src/third_party/tigerbeetle/intrusive/`.
//!
//! Speedy-socials uses these collections at four hot paths:
//!   * MST tree walker        — `Stack(Frame)` (LIFO)
//!   * AP key cache LRU       — `List(KeyEntry)` (doubly-linked, O(1) remove)
//!   * AP outbox in-flight    — `Queue(Delivery)` (named FIFO)
//!   * Per-worker job tracker — `Queue(Job)` (named FIFO, one per thread)
//!
//! TigerBeetle exposes type generators called `StackType`, `QueueType`,
//! and `DoublyLinkedListType`. We keep the upstream names available via
//! direct re-exports so anyone reading TB code finds the same surface,
//! and add the friendlier `Stack`, `Queue`, `List` aliases the speedy-
//! socials adoption sites use.
//!
//! For `List` we add a thin convention: the element type must expose
//! `back: ?*Self = null, next: ?*Self = null` link fields. The underlying
//! TB type accepts arbitrary field names; pinning the convention keeps
//! every call site readable and rules out the "which field is forward?"
//! footgun.

const tb = @import("tb_intrusive");

// Upstream-faithful names (use these when reading TB literature).
pub const StackType = tb.StackType;
pub const DoublyLinkedListType = tb.DoublyLinkedListType;
pub const QueueType = tb.QueueType;

// Link types (re-exported for callers embedding a link field in their
// element type).
pub const StackLink = tb.StackLink;

/// Friendlier `Stack(T)` alias. `T` must have a `link: Stack(T).Link` field.
pub fn Stack(comptime T: type) type {
    return StackType(T);
}

/// Friendlier `Queue(T)` alias. `T` must have a `link: Queue(T).Link` field.
pub fn Queue(comptime T: type) type {
    return QueueType(T);
}

/// Friendlier `List(T)` alias. `T` must expose
/// `back: ?*T = null, next: ?*T = null` link fields. This is a doubly-
/// linked list with O(1) push/pop at the tail and O(1) remove of any
/// node — used by the AP key-cache LRU.
pub fn List(comptime T: type) type {
    return DoublyLinkedListType(T, .back, .next);
}

test {
    // Pull the upstream tests into the test runner.
    _ = tb;
}

const std = @import("std");
const testing = std.testing;

test "intrusive: Stack alias matches StackType" {
    const Item = struct { id: u32, link: Stack(@This()).Link = .{} };
    var a: Item = .{ .id = 1 };
    var b: Item = .{ .id = 2 };
    var s = Stack(Item).init(.{ .capacity = 2, .verify_push = true });
    s.push(&a);
    s.push(&b);
    try testing.expectEqual(@as(u32, 2), s.count());
    try testing.expectEqual(@as(u32, 2), s.pop().?.id);
    try testing.expectEqual(@as(u32, 1), s.pop().?.id);
    try testing.expect(s.empty());
}

test "intrusive: List alias enforces back/next fields" {
    const Node = struct { id: u32, back: ?*@This() = null, next: ?*@This() = null };
    var nodes: [3]Node = .{
        .{ .id = 0 }, .{ .id = 1 }, .{ .id = 2 },
    };
    var l = List(Node){};
    l.push(&nodes[0]);
    l.push(&nodes[1]);
    l.push(&nodes[2]);
    try testing.expectEqual(@as(u32, 3), l.count);

    // Remove from the middle — the property that buys us O(1) LRU eviction.
    l.remove(&nodes[1]);
    try testing.expectEqual(@as(u32, 2), l.count);
    try testing.expectEqual(@as(u32, 2), l.pop().?.id);
    try testing.expectEqual(@as(u32, 0), l.pop().?.id);
    try testing.expectEqual(@as(?*Node, null), l.pop());
}

test "intrusive: Queue alias preserves name diagnostic" {
    const Item = struct { id: u32, link: Queue(@This()).Link = .{} };
    var q = Queue(Item).init(.{ .name = "intrusive_test", .verify_push = true });
    try testing.expectEqualStrings("intrusive_test", q.name().?);
    var a: Item = .{ .id = 7 };
    var b: Item = .{ .id = 8 };
    q.push(&a);
    q.push(&b);
    try testing.expectEqual(@as(u64, 2), q.count());
    try testing.expectEqual(@as(u32, 7), q.pop().?.id);
    try testing.expectEqual(@as(u32, 8), q.pop().?.id);
    try testing.expect(q.empty());
}
