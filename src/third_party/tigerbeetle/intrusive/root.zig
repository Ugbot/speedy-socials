//! Module root for the vendored TigerBeetle intrusive collections.
//!
//! Exposed to the rest of speedy-socials as the `tb_intrusive` module
//! (see build.zig). Speedy-socials code should NOT import this module
//! directly — go through `core.intrusive`, which adds friendlier
//! aliases (`Stack`, `List`, `Queue`) and the field-name convention for
//! `List`.

pub const stack = @import("stack.zig");
pub const list = @import("list.zig");
pub const queue = @import("queue.zig");

pub const StackLink = stack.StackLink;
pub const StackType = stack.StackType;
pub const DoublyLinkedListType = list.DoublyLinkedListType;
pub const QueueType = queue.QueueType;

test {
    _ = stack;
    _ = list;
    _ = queue;
}
