//! merkle search tree (MST)
//!
//! the AT Protocol repository data structure. a deterministic search tree
//! where each key's tree layer is derived from the leading zero bits of
//! SHA-256(key). keys are stored sorted within each node, with subtree
//! pointers interleaved between entries.
//!
//! supports partial trees for sync 1.1: nodes not present in a CAR are
//! represented as stubs (known CID, no block data). operations that need
//! to descend into a stub return error.PartialTree.
//!
//! see: https://atproto.com/specs/repository#mst-structure

const std = @import("std");
const cbor = @import("cbor.zig");
const car = @import("car.zig");
const multibase = @import("../crypto/multibase.zig");
const Allocator = std.mem.Allocator;

/// compute MST tree layer for a key.
/// layer = count leading zero bits in SHA-256(key), divided by 2, rounded down.
pub fn keyHeight(key: []const u8) u32 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(key, &digest, .{});
    var leading_zeros: u32 = 0;
    for (digest) |byte| {
        if (byte == 0) {
            leading_zeros += 8;
        } else {
            leading_zeros += @clz(byte);
            break;
        }
    }
    return leading_zeros / 2;
}

/// byte-level common prefix length between two strings
pub fn commonPrefixLen(a: []const u8, b: []const u8) usize {
    const min_len = @min(a.len, b.len);
    var i: usize = 0;
    while (i < min_len) : (i += 1) {
        if (a[i] != b[i]) break;
    }
    return i;
}

/// parse a CID string (base32lower multibase, e.g. "bafyrei...")
pub fn parseCidString(allocator: Allocator, s: []const u8) !cbor.Cid {
    if (s.len == 0) return error.InvalidCid;
    // strip 'b' multibase prefix and decode base32lower
    if (s[0] != 'b') return error.UnsupportedEncoding;
    const raw = try multibase.base32lower.decode(allocator, s[1..]);
    return .{ .raw = raw };
}

/// reference to a child subtree — either a loaded node, a stub (CID only), or absent.
pub const ChildRef = union(enum) {
    none,
    node: *Node,
    stub: cbor.Cid, // known CID, block not in CAR

    fn toNode(self: ChildRef) ?*Node {
        return switch (self) {
            .node => |n| n,
            else => null,
        };
    }

    fn isPresent(self: ChildRef) bool {
        return self != .none;
    }
};

/// MST node. stores a left subtree pointer and a list of entries.
/// each entry has a key, CID value, and optional right subtree.
pub const Node = struct {
    left: ChildRef,
    entries: std.ArrayList(Entry),

    pub const Entry = struct {
        key: []const u8,
        value: cbor.Cid,
        right: ChildRef,
    };

    fn init() Node {
        return .{
            .left = .none,
            .entries = .{},
        };
    }
};

/// an operation on the MST (create, update, or delete a record)
pub const Operation = struct {
    path: []const u8, // "collection/rkey"
    value: ?[]const u8, // raw CID bytes — non-null for create/update
    prev: ?[]const u8, // raw CID bytes — non-null for update/delete

    fn isCreate(self: Operation) bool {
        return self.value != null and self.prev == null;
    }

    fn isDelete(self: Operation) bool {
        return self.value == null and self.prev != null;
    }

    fn isUpdate(self: Operation) bool {
        return self.value != null and self.prev != null;
    }
};

/// merkle search tree
pub const Mst = struct {
    allocator: Allocator,
    root: ?*Node,
    root_layer: ?u32,

    pub fn init(allocator: Allocator) Mst {
        return .{
            .allocator = allocator,
            .root = null,
            .root_layer = null,
        };
    }

    /// insert or update a key-value pair
    pub fn put(self: *Mst, key: []const u8, value: cbor.Cid) !void {
        _ = try self.putReturn(key, value);
    }

    /// insert or update a key-value pair, returning the previous value CID if it existed
    pub fn putReturn(self: *Mst, key: []const u8, value: cbor.Cid) !?cbor.Cid {
        const height = keyHeight(key);

        if (self.root == null) {
            // empty tree: create root at key's height
            const node = try self.createNode();
            try node.entries.append(self.allocator, .{
                .key = try self.allocator.dupe(u8, key),
                .value = value,
                .right = .none,
            });
            self.root = node;
            self.root_layer = height;
            return null;
        }

        const root_layer = self.root_layer.?;

        if (height > root_layer) {
            // key belongs above the current root — lift (new key, never an update)
            self.root = try self.insertAbove(self.root.?, root_layer, key, value, height);
            self.root_layer = height;
            return null;
        } else if (height == root_layer) {
            // key belongs at root layer
            var prev: ?cbor.Cid = null;
            self.root = try self.insertAtLayer(self.root.?, key, value, height, &prev);
            return prev;
        } else {
            // key belongs below — recurse into subtree
            return try self.insertBelow(self.root.?, root_layer, key, value, height);
        }
    }

    /// look up a key, returning its CID value if present
    pub fn get(self: *const Mst, key: []const u8) ?cbor.Cid {
        return findKey(self.root, self.root_layer orelse return null, key, keyHeight(key));
    }

    fn findKey(maybe_node: ?*Node, layer: u32, key: []const u8, height: u32) ?cbor.Cid {
        const node = maybe_node orelse return null;

        if (height == layer) {
            for (node.entries.items) |entry| {
                const cmp = std.mem.order(u8, key, entry.key);
                if (cmp == .eq) return entry.value;
                if (cmp == .lt) return null;
            }
            return null;
        }

        // height < layer: recurse into the subtree gap containing key
        for (node.entries.items, 0..) |entry, i| {
            if (std.mem.order(u8, key, entry.key) == .lt) {
                const child = if (i == 0) node.left else node.entries.items[i - 1].right;
                return findKey(child.toNode(), layer - 1, key, height);
            }
        }
        // after all entries
        const last_right = if (node.entries.items.len > 0)
            node.entries.items[node.entries.items.len - 1].right
        else
            node.left;
        return findKey(last_right.toNode(), layer - 1, key, height);
    }

    /// delete a key from the tree
    pub fn delete(self: *Mst, key: []const u8) !void {
        _ = try self.deleteReturn(key);
    }

    /// delete a key from the tree, returning the removed value CID if it existed
    pub fn deleteReturn(self: *Mst, key: []const u8) !?cbor.Cid {
        if (self.root == null) return null;
        const prev = try self.deleteFromNode(self.root.?, self.root_layer.?, key);
        // trim: if root has no entries and only left subtree, collapse
        while (self.root) |root| {
            if (root.entries.items.len == 0) {
                switch (root.left) {
                    .node => |left| {
                        self.root = left;
                        if (self.root_layer.? > 0) {
                            self.root_layer = self.root_layer.? - 1;
                        } else {
                            self.root = null;
                            self.root_layer = null;
                            break;
                        }
                    },
                    .stub => return error.PartialTree,
                    .none => {
                        self.root = null;
                        self.root_layer = null;
                        break;
                    },
                }
            } else break;
        }
        return prev;
    }

    fn deleteFromNode(self: *Mst, node: *Node, layer: u32, key: []const u8) !?cbor.Cid {
        const height = keyHeight(key);

        if (height == layer) {
            // find and remove the entry
            for (node.entries.items, 0..) |entry, i| {
                if (std.mem.eql(u8, entry.key, key)) {
                    const prev_value = entry.value;
                    // merge left and right subtrees around the deleted entry
                    const left_sub = if (i == 0) node.left else node.entries.items[i - 1].right;
                    const right_sub = entry.right;
                    const merged = try self.mergeSubtrees(left_sub, right_sub);

                    if (i == 0) {
                        node.left = merged;
                    } else {
                        node.entries.items[i - 1].right = merged;
                    }

                    self.allocator.free(entry.key);
                    _ = node.entries.orderedRemove(i);
                    return prev_value;
                }
            }
            return null; // key not found
        }

        // height < layer: recurse into the appropriate gap
        if (node.entries.items.len == 0) {
            switch (node.left) {
                .node => |left| return try self.deleteFromNode(left, layer - 1, key),
                .stub => return error.PartialTree,
                .none => return null,
            }
        }

        for (node.entries.items, 0..) |entry, i| {
            if (std.mem.order(u8, key, entry.key) == .lt) {
                const child_ref = if (i == 0) &node.left else &node.entries.items[i - 1].right;
                switch (child_ref.*) {
                    .node => |sub| return try self.deleteFromNode(sub, layer - 1, key),
                    .stub => return error.PartialTree,
                    .none => return null,
                }
            }
        }
        // after all entries
        const last = &node.entries.items[node.entries.items.len - 1].right;
        switch (last.*) {
            .node => |sub| return try self.deleteFromNode(sub, layer - 1, key),
            .stub => return error.PartialTree,
            .none => return null,
        }
    }

    /// merge two subtrees that were separated by a deleted entry.
    /// both nodes are at the same layer. concatenate their entries
    /// and recursively merge if the junction creates adjacent children.
    /// follows the Go reference `appendMerge` / `mergeNodes` algorithm.
    fn mergeSubtrees(self: *Mst, left: ChildRef, right: ChildRef) !ChildRef {
        if (left == .none) return right;
        if (right == .none) return left;

        const l = switch (left) {
            .node => |n| n,
            .stub => return error.PartialTree,
            .none => unreachable,
        };
        const r = switch (right) {
            .node => |n| n,
            .stub => return error.PartialTree,
            .none => unreachable,
        };

        // create merged node: takes left's `left` pointer and all entries from both
        const merged = try self.createNode();
        merged.left = l.left;

        // copy left entries
        for (l.entries.items) |entry| {
            try merged.entries.append(self.allocator, entry);
        }

        // check junction: last entry of left's `right` vs right's `left`
        if (merged.entries.items.len > 0) {
            const last = &merged.entries.items[merged.entries.items.len - 1];
            if (last.right.isPresent() and r.left.isPresent()) {
                // both sides of the junction are subtrees — recursively merge
                last.right = try self.mergeSubtrees(last.right, r.left);
            } else if (!last.right.isPresent() and r.left.isPresent()) {
                last.right = r.left;
            }
            // if last.right is present and r.left is not, keep last.right as-is
        } else {
            // left has no entries: junction is merged.left vs r.left
            if (merged.left.isPresent() and r.left.isPresent()) {
                merged.left = try self.mergeSubtrees(merged.left, r.left);
            } else if (!merged.left.isPresent()) {
                merged.left = r.left;
            }
        }

        // copy right entries
        for (r.entries.items) |entry| {
            try merged.entries.append(self.allocator, entry);
        }

        return .{ .node = merged };
    }

    pub const MstError = error{PartialTree} || Allocator.Error;

    /// compute the root CID of the tree
    pub fn rootCid(self: *Mst) MstError!cbor.Cid {
        if (self.root) |root| {
            return self.nodeCid(.{ .node = root });
        }
        return self.nodeCid(.none);
    }

    fn nodeCid(self: *Mst, child: ChildRef) MstError!cbor.Cid {
        switch (child) {
            .stub => |cid| return cid,
            .none => {
                // empty node: { "l": null, "e": [] }
                const encoded = try cbor.encodeAlloc(self.allocator, .{ .map = &.{
                    .{ .key = "e", .value = .{ .array = &.{} } },
                    .{ .key = "l", .value = .null },
                } });
                defer self.allocator.free(encoded);
                return cbor.Cid.forDagCbor(self.allocator, encoded);
            },
            .node => |node| {
                const encoded = try self.serializeNode(node);
                defer self.allocator.free(encoded);
                return cbor.Cid.forDagCbor(self.allocator, encoded);
            },
        }
    }

    fn serializeNode(self: *Mst, node: *Node) MstError![]u8 {
        // compute left subtree CID
        const left_value: cbor.Value = switch (node.left) {
            .node => |left| blk: {
                const left_cid = try self.nodeCid(.{ .node = left });
                break :blk .{ .cid = left_cid };
            },
            .stub => |cid| .{ .cid = cid },
            .none => .null,
        };

        // build entry array with prefix compression
        var entry_values: std.ArrayList(cbor.Value) = .{};
        defer entry_values.deinit(self.allocator);

        var prev_key: []const u8 = "";
        for (node.entries.items) |entry| {
            const prefix_len = commonPrefixLen(prev_key, entry.key);
            const suffix = entry.key[prefix_len..];

            // right subtree CID
            const tree_val: cbor.Value = switch (entry.right) {
                .node => |right| blk: {
                    const right_cid = try self.nodeCid(.{ .node = right });
                    break :blk .{ .cid = right_cid };
                },
                .stub => |cid| .{ .cid = cid },
                .none => .null,
            };

            // allocate map entries on heap (stack-local &.{...} would alias across iterations)
            const map_entries = try self.allocator.alloc(cbor.Value.MapEntry, 4);
            map_entries[0] = .{ .key = "k", .value = .{ .bytes = suffix } };
            map_entries[1] = .{ .key = "p", .value = .{ .unsigned = prefix_len } };
            map_entries[2] = .{ .key = "t", .value = tree_val };
            map_entries[3] = .{ .key = "v", .value = .{ .cid = entry.value } };

            try entry_values.append(self.allocator, .{ .map = map_entries });

            prev_key = entry.key;
        }

        const entries_slice = try self.allocator.dupe(cbor.Value, entry_values.items);
        defer self.allocator.free(entries_slice);

        return cbor.encodeAlloc(self.allocator, .{ .map = &.{
            .{ .key = "e", .value = .{ .array = entries_slice } },
            .{ .key = "l", .value = left_value },
        } });
    }

    /// deep copy the tree. shares key slices and CID raw slices (immutable).
    /// stubs stay as stubs.
    pub fn copy(self: *Mst) !Mst {
        var new = Mst.init(self.allocator);
        if (self.root) |root| {
            new.root = try self.copyNode(root);
        }
        new.root_layer = self.root_layer;
        return new;
    }

    fn copyNode(self: *Mst, node: *Node) !*Node {
        const new_node = try self.createNode();
        new_node.left = try self.copyChild(node.left);
        for (node.entries.items) |entry| {
            try new_node.entries.append(self.allocator, .{
                .key = try self.allocator.dupe(u8, entry.key),
                .value = entry.value,
                .right = try self.copyChild(entry.right),
            });
        }
        return new_node;
    }

    fn copyChild(self: *Mst, child: ChildRef) Allocator.Error!ChildRef {
        return switch (child) {
            .none => .none,
            .stub => |cid| .{ .stub = cid },
            .node => |n| .{ .node = try self.copyNode(n) },
        };
    }

    /// load a partial MST from CAR blocks. nodes present in the CAR are
    /// fully loaded; child CIDs not present become stubs.
    pub fn loadFromBlocks(allocator: Allocator, repo_car: car.Car, root_cid_raw: []const u8) !Mst {
        const root_data = car.findBlock(repo_car, root_cid_raw) orelse return error.CommitBlockNotFound;
        const root_node_data = try decodeMstNode(allocator, root_data);

        if (root_node_data.entries.len == 0 and root_node_data.left == null) {
            return Mst.init(allocator);
        }

        const root_node = try loadNodeFromData(allocator, repo_car, root_node_data);

        // root layer = key height of first entry
        var key_buf: [512]u8 = undefined;
        const first = root_node_data.entries[0];
        @memcpy(key_buf[0..first.key_suffix.len], first.key_suffix);
        const root_layer = keyHeight(key_buf[0..first.key_suffix.len]);

        return .{
            .allocator = allocator,
            .root = root_node,
            .root_layer = root_layer,
        };
    }

    fn loadNodeFromData(allocator: Allocator, repo_car: car.Car, data: MstNodeData) !*Node {
        const node = try allocator.create(Node);
        node.* = Node.init();

        // load left child
        node.left = if (data.left) |left_cid_raw|
            try loadChild(allocator, repo_car, left_cid_raw)
        else
            .none;

        // load entries, reconstructing full keys from prefix compression
        var prev_key: []const u8 = "";
        for (data.entries) |entry_data| {
            // reconstruct full key
            const full_key = try allocator.alloc(u8, entry_data.prefix_len + entry_data.key_suffix.len);
            if (entry_data.prefix_len > 0) {
                @memcpy(full_key[0..entry_data.prefix_len], prev_key[0..entry_data.prefix_len]);
            }
            @memcpy(full_key[entry_data.prefix_len..], entry_data.key_suffix);

            const right_child = if (entry_data.tree) |tree_cid_raw|
                try loadChild(allocator, repo_car, tree_cid_raw)
            else
                ChildRef.none;

            try node.entries.append(allocator, .{
                .key = full_key,
                .value = .{ .raw = entry_data.value },
                .right = right_child,
            });

            prev_key = full_key;
        }

        return node;
    }

    fn loadChild(allocator: Allocator, repo_car: car.Car, cid_raw: []const u8) (MstDecodeError || error{CommitBlockNotFound})!ChildRef {
        if (car.findBlock(repo_car, cid_raw)) |block_data| {
            const child_data = try decodeMstNode(allocator, block_data);
            return .{ .node = try loadNodeFromData(allocator, repo_car, child_data) };
        }
        // block not in CAR — stub
        return .{ .stub = .{ .raw = cid_raw } };
    }

    // === internal helpers ===

    fn createNode(self: *Mst) !*Node {
        const node = try self.allocator.create(Node);
        node.* = Node.init();
        return node;
    }

    /// insert a key that belongs above the current root.
    /// splits the tree at its own layer, wraps each half in parent nodes
    /// to bridge the layer gap, then assembles the new root.
    fn insertAbove(self: *Mst, node: *Node, node_layer: u32, key: []const u8, value: cbor.Cid, target_layer: u32) !*Node {
        // 1. split the tree at its current layer around the key
        const splits = try self.splitNode(node, key);
        var left = splits.left;
        var right = splits.right;

        // 2. wrap each half in parent layers (bridge the gap)
        const extra_layers = target_layer - node_layer;
        var i: u32 = 1;
        while (i < extra_layers) : (i += 1) {
            if (left.isPresent()) {
                const parent = try self.createNode();
                parent.left = left;
                left = .{ .node = parent };
            }
            if (right.isPresent()) {
                const parent = try self.createNode();
                parent.left = right;
                right = .{ .node = parent };
            }
        }

        // 3. assemble new root: [left_tree, key_leaf, right_tree]
        const new_root = try self.createNode();
        new_root.left = left;
        try new_root.entries.append(self.allocator, .{
            .key = try self.allocator.dupe(u8, key),
            .value = value,
            .right = right,
        });
        return new_root;
    }

    /// insert a key at the same layer as the node
    fn insertAtLayer(self: *Mst, node: *Node, key: []const u8, value: cbor.Cid, layer: u32, prev_out: *?cbor.Cid) !*Node {
        _ = layer;
        // find insertion position
        var insert_idx: usize = node.entries.items.len;
        for (node.entries.items, 0..) |entry, i| {
            const cmp = std.mem.order(u8, key, entry.key);
            if (cmp == .eq) {
                // update existing — return previous value
                prev_out.* = node.entries.items[i].value;
                node.entries.items[i].value = value;
                return node;
            }
            if (cmp == .lt) {
                insert_idx = i;
                break;
            }
        }

        // split the subtree that spans the insertion gap
        const gap_child = if (insert_idx == 0) node.left else node.entries.items[insert_idx - 1].right;

        var left_split: ChildRef = .none;
        var right_split: ChildRef = .none;

        switch (gap_child) {
            .node => |subtree| {
                const splits = try self.splitNode(subtree, key);
                left_split = splits.left;
                right_split = splits.right;
            },
            .stub => return error.PartialTree,
            .none => {},
        }

        // update the pointer before the gap
        if (insert_idx == 0) {
            node.left = left_split;
        } else {
            node.entries.items[insert_idx - 1].right = left_split;
        }

        // insert the new entry
        try node.entries.insert(self.allocator, insert_idx, .{
            .key = try self.allocator.dupe(u8, key),
            .value = value,
            .right = right_split,
        });

        return node;
    }

    /// insert a key below the current node's layer
    fn insertBelow(self: *Mst, node: *Node, node_layer: u32, key: []const u8, value: cbor.Cid, target_height: u32) !?cbor.Cid {
        // find which gap the key falls into
        for (node.entries.items, 0..) |entry, i| {
            const cmp = std.mem.order(u8, key, entry.key);
            if (cmp == .eq) {
                // update existing
                const prev = node.entries.items[i].value;
                node.entries.items[i].value = value;
                return prev;
            }
            if (cmp == .lt) {
                // key goes in the gap before this entry
                const subtree_ptr = if (i == 0) &node.left else &node.entries.items[i - 1].right;
                return try self.insertIntoGap(subtree_ptr, node_layer - 1, key, value, target_height);
            }
        }
        // key goes after all entries
        const last_ptr = if (node.entries.items.len > 0)
            &node.entries.items[node.entries.items.len - 1].right
        else
            &node.left;
        return try self.insertIntoGap(last_ptr, node_layer - 1, key, value, target_height);
    }

    fn insertIntoGap(self: *Mst, subtree_ptr: *ChildRef, gap_layer: u32, key: []const u8, value: cbor.Cid, target_height: u32) MstError!?cbor.Cid {
        if (target_height == gap_layer) {
            // insert at this layer
            switch (subtree_ptr.*) {
                .node => |existing| {
                    var prev: ?cbor.Cid = null;
                    subtree_ptr.* = .{ .node = try self.insertAtLayer(existing, key, value, gap_layer, &prev) };
                    return prev;
                },
                .stub => return error.PartialTree,
                .none => {
                    const new_node = try self.createNode();
                    try new_node.entries.append(self.allocator, .{
                        .key = try self.allocator.dupe(u8, key),
                        .value = value,
                        .right = .none,
                    });
                    subtree_ptr.* = .{ .node = new_node };
                    return null;
                },
            }
        } else if (target_height > gap_layer) {
            // need to lift — split and wrap
            switch (subtree_ptr.*) {
                .node => |existing| {
                    subtree_ptr.* = .{ .node = try self.insertAbove(existing, gap_layer, key, value, target_height) };
                    return null;
                },
                .stub => return error.PartialTree,
                .none => {
                    const new_node = try self.createNode();
                    try new_node.entries.append(self.allocator, .{
                        .key = try self.allocator.dupe(u8, key),
                        .value = value,
                        .right = .none,
                    });
                    subtree_ptr.* = .{ .node = new_node };
                    return null;
                },
            }
        } else {
            // target_height < gap_layer: recurse deeper
            switch (subtree_ptr.*) {
                .node => |existing| return try self.insertBelow(existing, gap_layer, key, value, target_height),
                .stub => return error.PartialTree,
                .none => {
                    // create node at gap_layer and recurse
                    const new_node = try self.createNode();
                    subtree_ptr.* = .{ .node = new_node };
                    return try self.insertBelow(new_node, gap_layer, key, value, target_height);
                },
            }
        }
    }

    /// split a subtree around a key: everything < key goes left, everything >= key goes right.
    fn splitNode(self: *Mst, node: *Node, key: []const u8) !struct { left: ChildRef, right: ChildRef } {
        // find the first entry >= key
        var split_idx: usize = node.entries.items.len;
        for (node.entries.items, 0..) |entry, i| {
            if (std.mem.order(u8, key, entry.key) != .gt) {
                split_idx = i;
                break;
            }
        }

        // left gets entries [0..split_idx), right gets entries [split_idx..]
        var left_node = try self.createNode();
        var right_node = try self.createNode();

        // left node takes the original node's left subtree
        left_node.left = node.left;

        // copy entries to left
        for (node.entries.items[0..split_idx]) |entry| {
            try left_node.entries.append(self.allocator, entry);
        }

        // copy entries to right
        for (node.entries.items[split_idx..]) |entry| {
            try right_node.entries.append(self.allocator, entry);
        }

        // split the gap subtree between the two halves
        if (left_node.entries.items.len > 0) {
            const last_left = &left_node.entries.items[left_node.entries.items.len - 1];
            switch (last_left.right) {
                .node => |gap_subtree| {
                    const sub_split = try self.splitNode(gap_subtree, key);
                    last_left.right = sub_split.left;
                    right_node.left = sub_split.right;
                },
                .stub => return error.PartialTree,
                .none => {},
            }
        } else if (left_node.left.isPresent() and split_idx == 0) {
            // all entries went right — the gap is the original node's left subtree
            switch (left_node.left) {
                .node => |gap_subtree| {
                    const sub_split = try self.splitNode(gap_subtree, key);
                    left_node.left = sub_split.left;
                    right_node.left = sub_split.right;
                },
                .stub => return error.PartialTree,
                .none => {},
            }
        }

        const left_result: ChildRef = if (left_node.entries.items.len > 0 or left_node.left.isPresent())
            .{ .node = left_node }
        else
            .none;
        const right_result: ChildRef = if (right_node.entries.items.len > 0 or right_node.left.isPresent())
            .{ .node = right_node }
        else
            .none;

        return .{ .left = left_result, .right = right_result };
    }
};

// === inversion primitives ===

/// normalize operations: check for duplicate paths, sort deletions first then by path
pub fn normalizeOps(allocator: Allocator, ops: []const Operation) ![]Operation {
    if (ops.len == 0) return try allocator.alloc(Operation, 0);

    const sorted = try allocator.dupe(Operation, ops);
    errdefer allocator.free(sorted);

    // sort: deletions first, then by path
    std.mem.sort(Operation, sorted, {}, struct {
        fn lessThan(_: void, a: Operation, b: Operation) bool {
            // deletions before creates/updates
            const a_del: u1 = if (a.isDelete()) 0 else 1;
            const b_del: u1 = if (b.isDelete()) 0 else 1;
            if (a_del != b_del) return a_del < b_del;
            return std.mem.order(u8, a.path, b.path) == .lt;
        }
    }.lessThan);

    // check for duplicate paths
    var i: usize = 1;
    while (i < sorted.len) : (i += 1) {
        if (std.mem.eql(u8, sorted[i].path, sorted[i - 1].path)) {
            allocator.free(sorted);
            return error.DuplicatePath;
        }
    }

    return sorted;
}

/// invert a single operation against the tree.
/// create → delete, update → reverse update, delete → put back
pub fn invertOp(tree: *Mst, op: Operation) !void {
    if (op.isCreate()) {
        // create → delete: remove the path, verify removed CID matches op.value
        const removed = try tree.deleteReturn(op.path) orelse return error.InversionMismatch;
        if (!std.mem.eql(u8, removed.raw, op.value.?)) return error.InversionMismatch;
    } else if (op.isUpdate()) {
        // update → reverse: put op.prev back, verify displaced CID matches op.value
        const displaced = try tree.putReturn(op.path, .{ .raw = op.prev.? }) orelse return error.InversionMismatch;
        if (!std.mem.eql(u8, displaced.raw, op.value.?)) return error.InversionMismatch;
    } else if (op.isDelete()) {
        // delete → put back: insert op.prev, verify path didn't already exist
        const displaced = try tree.putReturn(op.path, .{ .raw = op.prev.? });
        if (displaced != null) return error.InversionMismatch;
    } else {
        return error.InversionMismatch;
    }
}

// === specialized MST node decoder ===
//
// parses the known MST node CBOR schema directly, avoiding generic Value
// union construction. all byte data is zero-copy (slices into input buffer).
// only allocation: the entries array.
//
// MST node schema:
//   map(2) { "e": array [ map(4) {k,p,t,v}, ... ], "l": CID|null }

pub const MstNodeData = struct {
    left: ?[]const u8, // raw CID bytes, or null
    entries: []const MstEntryData,
};

pub const MstEntryData = struct {
    key_suffix: []const u8,
    prefix_len: usize,
    tree: ?[]const u8, // raw CID bytes, or null
    value: []const u8, // raw CID bytes
};

pub fn decodeMstNode(allocator: Allocator, data: []const u8) !MstNodeData {
    var r = MstReader{ .data = data, .pos = 0 };

    const map_count = try r.expectMap();
    if (map_count != 2) return error.InvalidMstNode;

    // "e" key
    const key_e = try r.readTextString();
    if (!std.mem.eql(u8, key_e, "e")) return error.InvalidMstNode;

    // entries array
    const entries_count = try r.expectArray();
    const entries = try allocator.alloc(MstEntryData, entries_count);
    for (entries) |*entry| {
        entry.* = try readMstEntry(&r);
    }

    // "l" key
    const key_l = try r.readTextString();
    if (!std.mem.eql(u8, key_l, "l")) return error.InvalidMstNode;

    const left = try r.readCidOrNull();

    return .{ .left = left, .entries = entries };
}

fn readMstEntry(r: *MstReader) !MstEntryData {
    const map_count = try r.expectMap();
    if (map_count != 4) return error.InvalidMstNode;

    // "k" → key suffix (byte string)
    _ = try r.readTextString();
    const key_suffix = try r.readByteString();

    // "p" → prefix length (unsigned int)
    _ = try r.readTextString();
    const prefix_len = try r.readUnsigned();

    // "t" → right subtree CID or null
    _ = try r.readTextString();
    const tree = try r.readCidOrNull();

    // "v" → value CID
    _ = try r.readTextString();
    const value = try r.readCid();

    return .{
        .key_suffix = key_suffix,
        .prefix_len = @intCast(prefix_len),
        .tree = tree,
        .value = value,
    };
}

const MstReader = struct {
    data: []const u8,
    pos: usize,

    fn expectMap(self: *MstReader) !usize {
        return self.readMajorWithArg(5);
    }

    fn expectArray(self: *MstReader) !usize {
        return self.readMajorWithArg(4);
    }

    fn readTextString(self: *MstReader) ![]const u8 {
        const len = try self.readMajorWithArg(3);
        if (self.pos + len > self.data.len) return error.InvalidMstNode;
        const result = self.data[self.pos .. self.pos + len];
        self.pos += len;
        return result;
    }

    fn readByteString(self: *MstReader) ![]const u8 {
        const len = try self.readMajorWithArg(2);
        if (self.pos + len > self.data.len) return error.InvalidMstNode;
        const result = self.data[self.pos .. self.pos + len];
        self.pos += len;
        return result;
    }

    fn readUnsigned(self: *MstReader) !u64 {
        return self.readMajorWithArg(0);
    }

    fn readCidOrNull(self: *MstReader) !?[]const u8 {
        if (self.pos >= self.data.len) return error.InvalidMstNode;
        if (self.data[self.pos] == 0xf6) {
            self.pos += 1;
            return null;
        }
        return try self.readCid();
    }

    fn readCid(self: *MstReader) ![]const u8 {
        // tag(42) encodes as 0xd8 0x2a
        if (self.pos + 1 >= self.data.len) return error.InvalidMstNode;
        if (self.data[self.pos] != 0xd8 or self.data[self.pos + 1] != 0x2a)
            return error.InvalidMstNode;
        self.pos += 2;
        const bytes = try self.readByteString();
        if (bytes.len < 1 or bytes[0] != 0x00) return error.InvalidMstNode;
        return bytes[1..]; // skip 0x00 identity multibase prefix
    }

    fn readMajorWithArg(self: *MstReader, expected_major: u3) !usize {
        if (self.pos >= self.data.len) return error.InvalidMstNode;
        const b = self.data[self.pos];
        self.pos += 1;
        const major: u3 = @truncate(b >> 5);
        if (major != expected_major) return error.InvalidMstNode;
        const additional: u5 = @truncate(b);
        return self.readArgValue(additional);
    }

    fn readArgValue(self: *MstReader, additional: u5) !usize {
        if (additional < 24) return @as(usize, additional);
        if (additional == 24) {
            if (self.pos >= self.data.len) return error.InvalidMstNode;
            const val = self.data[self.pos];
            self.pos += 1;
            return @as(usize, val);
        }
        if (additional == 25) {
            if (self.pos + 2 > self.data.len) return error.InvalidMstNode;
            const val = std.mem.readInt(u16, self.data[self.pos..][0..2], .big);
            self.pos += 2;
            return @as(usize, val);
        }
        if (additional == 26) {
            if (self.pos + 4 > self.data.len) return error.InvalidMstNode;
            const val = std.mem.readInt(u32, self.data[self.pos..][0..4], .big);
            self.pos += 4;
            return @as(usize, val);
        }
        return error.InvalidMstNode;
    }
};

pub const MstDecodeError = error{InvalidMstNode} || Allocator.Error;

// === tests ===

test "keyHeight" {
    // values from interop test fixtures
    try std.testing.expectEqual(@as(u32, 0), keyHeight(""));
    try std.testing.expectEqual(@as(u32, 0), keyHeight("asdf"));
    try std.testing.expectEqual(@as(u32, 1), keyHeight("blue"));
    try std.testing.expectEqual(@as(u32, 0), keyHeight("2653ae71"));
    try std.testing.expectEqual(@as(u32, 2), keyHeight("88bfafc7"));
    try std.testing.expectEqual(@as(u32, 4), keyHeight("2a92d355"));
    try std.testing.expectEqual(@as(u32, 6), keyHeight("884976f5"));
    try std.testing.expectEqual(@as(u32, 4), keyHeight("app.bsky.feed.post/454397e440ec"));
    try std.testing.expectEqual(@as(u32, 8), keyHeight("app.bsky.feed.post/9adeb165882c"));
}

test "commonPrefixLen" {
    try std.testing.expectEqual(@as(usize, 0), commonPrefixLen("", ""));
    try std.testing.expectEqual(@as(usize, 3), commonPrefixLen("abc", "abc"));
    try std.testing.expectEqual(@as(usize, 0), commonPrefixLen("", "abc"));
    try std.testing.expectEqual(@as(usize, 2), commonPrefixLen("ab", "abc"));
    try std.testing.expectEqual(@as(usize, 3), commonPrefixLen("abcde", "abc"));
    try std.testing.expectEqual(@as(usize, 0), commonPrefixLen("abcde", "qbb"));
}

test "put and get" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    var tree = Mst.init(a);

    const cid1 = try cbor.Cid.forDagCbor(a, "value1");
    const cid2 = try cbor.Cid.forDagCbor(a, "value2");

    try tree.put("key1", cid1);
    try tree.put("key2", cid2);

    const got1 = tree.get("key1") orelse return error.NotFound;
    try std.testing.expectEqualSlices(u8, cid1.raw, got1.raw);

    const got2 = tree.get("key2") orelse return error.NotFound;
    try std.testing.expectEqualSlices(u8, cid2.raw, got2.raw);

    try std.testing.expect(tree.get("nonexistent") == null);
}

test "put and delete" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    var tree = Mst.init(a);
    const cid = try cbor.Cid.forDagCbor(a, "value");

    try tree.put("key1", cid);
    try tree.put("key2", cid);

    try std.testing.expect(tree.get("key1") != null);
    try tree.delete("key1");
    try std.testing.expect(tree.get("key1") == null);
    try std.testing.expect(tree.get("key2") != null);
}

test "putReturn and deleteReturn" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    var tree = Mst.init(a);
    const cid1 = try cbor.Cid.forDagCbor(a, "v1");
    const cid2 = try cbor.Cid.forDagCbor(a, "v2");

    // first insert returns null (no previous)
    const prev1 = try tree.putReturn("key1", cid1);
    try std.testing.expect(prev1 == null);

    // update returns old value
    const prev2 = try tree.putReturn("key1", cid2);
    try std.testing.expect(prev2 != null);
    try std.testing.expectEqualSlices(u8, cid1.raw, prev2.?.raw);

    // delete returns removed value
    const removed = try tree.deleteReturn("key1");
    try std.testing.expect(removed != null);
    try std.testing.expectEqualSlices(u8, cid2.raw, removed.?.raw);

    // delete nonexistent returns null
    const removed2 = try tree.deleteReturn("key1");
    try std.testing.expect(removed2 == null);
}

test "copy produces independent tree" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    var tree = Mst.init(a);
    const cid1 = try cbor.Cid.forDagCbor(a, "v1");
    const cid2 = try cbor.Cid.forDagCbor(a, "v2");

    try tree.put("key1", cid1);
    try tree.put("key2", cid1);

    var tree2 = try tree.copy();

    // modify copy
    try tree2.put("key1", cid2);
    try tree2.delete("key2");

    // original unchanged
    const got1 = tree.get("key1") orelse return error.NotFound;
    try std.testing.expectEqualSlices(u8, cid1.raw, got1.raw);
    try std.testing.expect(tree.get("key2") != null);

    // copy has changes
    const got1_copy = tree2.get("key1") orelse return error.NotFound;
    try std.testing.expectEqualSlices(u8, cid2.raw, got1_copy.raw);
    try std.testing.expect(tree2.get("key2") == null);
}

test "rootCid is deterministic" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const cid_val = try cbor.Cid.forDagCbor(a, "leaf");

    // build tree 1
    var tree1 = Mst.init(a);
    try tree1.put("a", cid_val);
    try tree1.put("b", cid_val);
    const root1 = try tree1.rootCid();

    // build tree 2 (same keys, same order)
    var tree2 = Mst.init(a);
    try tree2.put("a", cid_val);
    try tree2.put("b", cid_val);
    const root2 = try tree2.rootCid();

    try std.testing.expectEqualSlices(u8, root1.raw, root2.raw);
}

test "empty tree rootCid matches reference" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    var tree = Mst.init(a);
    const root = try tree.rootCid();
    try std.testing.expectEqual(@as(u64, 1), root.version().?);

    // known empty tree CID from Go reference implementation
    const expected = try parseCidString(a, "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm");
    try std.testing.expectEqualSlices(u8, expected.raw, root.raw);
}

test "single key rootCid matches reference" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    var tree = Mst.init(a);
    // use a known CID value (the leaf CID from commit-proof fixtures)
    const leaf_cid = try parseCidString(a, "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454");

    // single layer-0 key
    try tree.put("com.example.record/3jqfcqzm3fo2j", leaf_cid);

    const root = try tree.rootCid();
    const expected = try parseCidString(a, "bafyreibj4lsc3aqnrvphp5xmrnfoorvru4wynt6lwidqbm2623a6tatzdu");
    try std.testing.expectEqualSlices(u8, expected.raw, root.raw);
}

test "single layer-2 key rootCid matches reference" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    var tree = Mst.init(a);
    const leaf_cid = try parseCidString(a, "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454");

    // single layer-2 key
    try tree.put("com.example.record/3jqfcqzm3fx2j", leaf_cid);

    const root = try tree.rootCid();
    const expected = try parseCidString(a, "bafyreih7wfei65pxzhauoibu3ls7jgmkju4bspy4t2ha2qdjnzqvoy33ai");
    try std.testing.expectEqualSlices(u8, expected.raw, root.raw);
}

test "5 key tree matches reference" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    var tree = Mst.init(a);
    const leaf_cid = try parseCidString(a, "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454");

    // 5 keys from Go test (note: last key has 4fc not 3ft)
    const keys = [_][]const u8{
        "com.example.record/3jqfcqzm3fp2j",
        "com.example.record/3jqfcqzm3fr2j",
        "com.example.record/3jqfcqzm3fs2j",
        "com.example.record/3jqfcqzm3ft2j",
        "com.example.record/3jqfcqzm4fc2j",
    };

    for (keys) |key| {
        try tree.put(key, leaf_cid);
    }

    const root = try tree.rootCid();
    const expected = try parseCidString(a, "bafyreicmahysq4n6wfuxo522m6dpiy7z7qzym3dzs756t5n7nfdgccwq7m");
    try std.testing.expectEqualSlices(u8, expected.raw, root.raw);
}

test "two deep split fixture" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const leaf_cid = try parseCidString(a, "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454");

    var tree = Mst.init(a);
    const initial_keys = [_][]const u8{
        "A0/374913", "B1/986427", "C0/451630",
        "E0/670489", "F1/085263", "G0/765327",
    };
    for (initial_keys) |key| {
        try tree.put(key, leaf_cid);
    }

    const expected_before = try parseCidString(a, "bafyreicraprx2xwnico4tuqir3ozsxpz46qkcpox3obf5bagicqwurghpy");
    try std.testing.expectEqualSlices(u8, expected_before.raw, (try tree.rootCid()).raw);

    try tree.put("D2/269196", leaf_cid);

    const expected_after = try parseCidString(a, "bafyreihvay6pazw3dfa47u5d2tn3rd6pa57sr37bo5bqyvjuqc73ib65my");
    try std.testing.expectEqualSlices(u8, expected_after.raw, (try tree.rootCid()).raw);
}

test "complex multi-op commit" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const leaf_cid = try parseCidString(a, "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454");

    var tree = Mst.init(a);
    const initial_keys = [_][]const u8{
        "B0/601692", "C2/014073", "D0/952776",
        "E2/819540", "F0/697858", "H0/131238",
    };
    for (initial_keys) |key| {
        try tree.put(key, leaf_cid);
    }

    const expected_before = try parseCidString(a, "bafyreigr3plnts7dax6yokvinbhcqpyicdfgg6npvvyx6okc5jo55slfqi");
    try std.testing.expectEqualSlices(u8, expected_before.raw, (try tree.rootCid()).raw);

    // adds
    try tree.put("A2/827942", leaf_cid);
    try tree.put("G2/611528", leaf_cid);
    // del
    try tree.delete("C2/014073");

    const expected_after = try parseCidString(a, "bafyreiftrcrbhrwmi37u4egedlg56gk3jeh3tvmqvwgowoifuklfysyx54");
    try std.testing.expectEqualSlices(u8, expected_after.raw, (try tree.rootCid()).raw);
}

test "inversion: create then invert" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const cid1 = try cbor.Cid.forDagCbor(a, "record1");

    var tree = Mst.init(a);
    const root_before = try tree.rootCid();

    // apply forward: create
    try tree.put("col/rkey1", cid1);

    // invert: should remove it
    try invertOp(&tree, .{
        .path = "col/rkey1",
        .value = cid1.raw,
        .prev = null,
    });

    const root_after = try tree.rootCid();
    try std.testing.expectEqualSlices(u8, root_before.raw, root_after.raw);
}

test "inversion: update then invert" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const cid1 = try cbor.Cid.forDagCbor(a, "v1");
    const cid2 = try cbor.Cid.forDagCbor(a, "v2");

    var tree = Mst.init(a);
    try tree.put("col/rkey1", cid1);
    const root_before = try tree.rootCid();

    // apply forward: update cid1 → cid2
    try tree.put("col/rkey1", cid2);

    // invert
    try invertOp(&tree, .{
        .path = "col/rkey1",
        .value = cid2.raw,
        .prev = cid1.raw,
    });

    const root_after = try tree.rootCid();
    try std.testing.expectEqualSlices(u8, root_before.raw, root_after.raw);
}

test "inversion: delete then invert" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const cid1 = try cbor.Cid.forDagCbor(a, "v1");

    var tree = Mst.init(a);
    try tree.put("col/rkey1", cid1);
    const root_before = try tree.rootCid();

    // apply forward: delete
    try tree.delete("col/rkey1");

    // invert
    try invertOp(&tree, .{
        .path = "col/rkey1",
        .value = null,
        .prev = cid1.raw,
    });

    const root_after = try tree.rootCid();
    try std.testing.expectEqualSlices(u8, root_before.raw, root_after.raw);
}

test "inversion: multi-op commit round-trip" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const cid1 = try cbor.Cid.forDagCbor(a, "v1");
    const cid2 = try cbor.Cid.forDagCbor(a, "v2");
    const cid3 = try cbor.Cid.forDagCbor(a, "v3");

    // build initial tree
    var tree = Mst.init(a);
    try tree.put("col/existing", cid1);
    try tree.put("col/to_update", cid1);
    try tree.put("col/to_delete", cid2);
    const root_before = try tree.rootCid();

    // apply forward ops
    try tree.put("col/new_record", cid3); // create
    try tree.put("col/to_update", cid2); // update
    try tree.delete("col/to_delete"); // delete

    // normalize and invert
    const ops = [_]Operation{
        .{ .path = "col/new_record", .value = cid3.raw, .prev = null }, // create
        .{ .path = "col/to_update", .value = cid2.raw, .prev = cid1.raw }, // update
        .{ .path = "col/to_delete", .value = null, .prev = cid2.raw }, // delete
    };
    const sorted = try normalizeOps(a, &ops);

    for (sorted) |op| {
        try invertOp(&tree, op);
    }

    const root_after = try tree.rootCid();
    try std.testing.expectEqualSlices(u8, root_before.raw, root_after.raw);
}

test "normalizeOps rejects duplicates" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const ops = [_]Operation{
        .{ .path = "col/same", .value = "cid1", .prev = null },
        .{ .path = "col/same", .value = "cid2", .prev = null },
    };

    try std.testing.expectError(error.DuplicatePath, normalizeOps(a, &ops));
}

test "parseCidString" {
    const alloc = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const a = arena.allocator();

    const cid = try parseCidString(a, "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454");
    try std.testing.expectEqual(@as(u64, 1), cid.version().?);
    try std.testing.expectEqual(@as(u64, 0x71), cid.codec().?);
    try std.testing.expectEqual(@as(u64, 0x12), cid.hashFn().?);
    try std.testing.expectEqual(@as(usize, 32), cid.digest().?.len);
}
