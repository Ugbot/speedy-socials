//! interop tests against bluesky-social/atproto-interop-tests fixtures
//!
//! validates zat's parsers and crypto against the official test vectors.

const std = @import("std");

// types under test
const Tid = @import("../syntax/tid.zig").Tid;
const Did = @import("../syntax/did.zig").Did;
const Handle = @import("../syntax/handle.zig").Handle;
const Nsid = @import("../syntax/nsid.zig").Nsid;
const Rkey = @import("../syntax/rkey.zig").Rkey;
const AtUri = @import("../syntax/at_uri.zig").AtUri;

// crypto
const jwt = @import("../crypto/jwt.zig");
const Keypair = @import("../crypto/keypair.zig").Keypair;
const multibase = @import("../crypto/multibase.zig");
const multicodec = @import("../crypto/multicodec.zig");

// repo
const mst = @import("../repo/mst.zig");
const cbor = @import("../repo/cbor.zig");

// === helpers ===

fn LineIterator(comptime sentinel: ?u8) type {
    return struct {
        inner: std.mem.SplitIterator(u8, .scalar),

        const Self = @This();

        fn init(data: []const u8) Self {
            // strip trailing sentinel if present (some files end with \n)
            const trimmed = if (sentinel) |s|
                if (data.len > 0 and data[data.len - 1] == s) data[0 .. data.len - 1] else data
            else
                data;
            return .{ .inner = std.mem.splitScalar(u8, trimmed, '\n') };
        }

        fn next(self: *Self) ?[]const u8 {
            while (self.inner.next()) |line| {
                // skip blank lines and comments
                if (line.len == 0) continue;
                if (line[0] == '#') continue;
                // strip trailing \r for windows line endings
                const trimmed = if (line.len > 0 and line[line.len - 1] == '\r')
                    line[0 .. line.len - 1]
                else
                    line;
                if (trimmed.len == 0) continue;
                return trimmed;
            }
            return null;
        }
    };
}

fn testLinesSentinel(comptime data: [:0]const u8) LineIterator(0) {
    return LineIterator(0).init(data);
}

/// run syntax validation tests for a parser type
fn syntaxTest(
    comptime valid_data: [:0]const u8,
    comptime invalid_data: [:0]const u8,
    comptime parseFn: anytype,
) !void {
    // test valid lines
    var valid_lines = testLinesSentinel(valid_data);
    var valid_count: usize = 0;
    while (valid_lines.next()) |line| {
        if (parseFn(line) == null) {
            std.debug.print("FAIL: expected valid, got null for: '{s}'\n", .{line});
            return error.ExpectedValid;
        }
        valid_count += 1;
    }
    if (valid_count == 0) return error.NoTestCases;

    // test invalid lines
    var invalid_lines = testLinesSentinel(invalid_data);
    var invalid_count: usize = 0;
    while (invalid_lines.next()) |line| {
        if (parseFn(line) != null) {
            std.debug.print("FAIL: expected null, got valid for: '{s}'\n", .{line});
            return error.ExpectedInvalid;
        }
        invalid_count += 1;
    }
    if (invalid_count == 0) return error.NoTestCases;
}

// === tier 1: syntax validation ===

test "interop: tid syntax" {
    try syntaxTest(
        @embedFile("tid_syntax_valid"),
        @embedFile("tid_syntax_invalid"),
        Tid.parse,
    );
}

test "interop: did syntax" {
    try syntaxTest(
        @embedFile("did_syntax_valid"),
        @embedFile("did_syntax_invalid"),
        Did.parse,
    );
}

test "interop: handle syntax" {
    try syntaxTest(
        @embedFile("handle_syntax_valid"),
        @embedFile("handle_syntax_invalid"),
        Handle.parse,
    );
}

test "interop: nsid syntax" {
    try syntaxTest(
        @embedFile("nsid_syntax_valid"),
        @embedFile("nsid_syntax_invalid"),
        Nsid.parse,
    );
}

test "interop: rkey syntax" {
    try syntaxTest(
        @embedFile("recordkey_syntax_valid"),
        @embedFile("recordkey_syntax_invalid"),
        Rkey.parse,
    );
}

test "interop: aturi syntax" {
    try syntaxTest(
        @embedFile("aturi_syntax_valid"),
        @embedFile("aturi_syntax_invalid"),
        AtUri.parse,
    );
}

// === tier 2: crypto signature verification ===

fn base64StdDecode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    // try standard (padded) first, fall back to no-pad
    const decoder = if (input.len > 0 and input[input.len - 1] == '=')
        &std.base64.standard.Decoder
    else
        &std.base64.standard_no_pad.Decoder;

    const size = decoder.calcSizeForSlice(input) catch return error.InvalidBase64;
    const output = try allocator.alloc(u8, size);
    errdefer allocator.free(output);
    decoder.decode(output, input) catch return error.InvalidBase64;
    return output;
}

test "interop: crypto signature verification" {
    const allocator = std.testing.allocator;

    const fixture_json = @embedFile("signature_fixtures");
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, fixture_json, .{});
    defer parsed.deinit();

    const fixtures = parsed.value.array.items;
    var tested: usize = 0;

    for (fixtures) |fixture| {
        const obj = fixture.object;

        const comment = if (obj.get("comment")) |v| switch (v) {
            .string => |s| s,
            else => "?",
        } else "?";

        const message_b64 = obj.get("messageBase64").?.string;
        const algorithm = obj.get("algorithm").?.string;
        const pub_key_did = obj.get("publicKeyDid").?.string;
        const sig_b64 = obj.get("signatureBase64").?.string;
        const valid = obj.get("validSignature").?.bool;

        // extract multibase key from did:key (strip "did:key:" prefix)
        const did_key_prefix = "did:key:";
        if (!std.mem.startsWith(u8, pub_key_did, did_key_prefix)) return error.InvalidDidKey;
        const multibase_key = pub_key_did[did_key_prefix.len..];

        // decode message and signature
        const message = try base64StdDecode(allocator, message_b64);
        defer allocator.free(message);

        const sig_bytes = base64StdDecode(allocator, sig_b64) catch |err| {
            // DER-encoded sigs may fail to decode at expected length — that's fine for invalid
            if (!valid) {
                tested += 1;
                continue;
            }
            return err;
        };
        defer allocator.free(sig_bytes);

        // decode public key from multibase+multicodec (did:key format)
        const key_bytes = try multibase.decode(allocator, multibase_key);
        defer allocator.free(key_bytes);

        const parsed_key = try multicodec.parsePublicKey(key_bytes);

        // verify signature
        const verify_result = if (std.mem.eql(u8, algorithm, "ES256K"))
            jwt.verifySecp256k1(message, sig_bytes, parsed_key.raw)
        else if (std.mem.eql(u8, algorithm, "ES256"))
            jwt.verifyP256(message, sig_bytes, parsed_key.raw)
        else
            error.UnsupportedAlgorithm;

        if (valid) {
            verify_result catch |err| {
                std.debug.print("FAIL: expected valid signature but got {s}: {s}\n", .{ @errorName(err), comment });
                return error.ExpectedValidSignature;
            };
        } else {
            if (verify_result) |_| {
                std.debug.print("FAIL: expected invalid signature but verified OK: {s}\n", .{comment});
                return error.ExpectedInvalidSignature;
            } else |_| {}
        }

        tested += 1;
    }

    // should have tested all 6 fixtures
    try std.testing.expect(tested == fixtures.len);
}

// === tier 2b: did:key derivation ===

test "interop: did:key derivation K256" {
    const allocator = std.testing.allocator;

    const fixture_json = @embedFile("w3c_didkey_K256");
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, fixture_json, .{});
    defer parsed.deinit();

    const fixtures = parsed.value.array.items;
    var tested: usize = 0;

    for (fixtures) |fixture| {
        const obj = fixture.object;
        const hex_str = obj.get("privateKeyBytesHex").?.string;
        const expected_did = obj.get("publicDidKey").?.string;

        var sk_bytes: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&sk_bytes, hex_str) catch return error.InvalidHex;

        const kp = try Keypair.fromSecretKey(.secp256k1, sk_bytes);
        const actual_did = try kp.did(allocator);
        defer allocator.free(actual_did);

        if (!std.mem.eql(u8, actual_did, expected_did)) {
            std.debug.print("FAIL K256: expected {s}, got {s}\n", .{ expected_did, actual_did });
            return error.DidKeyMismatch;
        }
        tested += 1;
    }

    try std.testing.expectEqual(@as(usize, 5), tested);
}

test "interop: did:key derivation P256" {
    const allocator = std.testing.allocator;

    const fixture_json = @embedFile("w3c_didkey_P256");
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, fixture_json, .{});
    defer parsed.deinit();

    const fixtures = parsed.value.array.items;
    var tested: usize = 0;

    for (fixtures) |fixture| {
        const obj = fixture.object;
        const b58_str = obj.get("privateKeyBytesBase58").?.string;
        const expected_did = obj.get("publicDidKey").?.string;

        // raw base58 (no multibase 'z' prefix)
        const decoded = try multibase.base58btc.decode(allocator, b58_str);
        defer allocator.free(decoded);
        if (decoded.len < 32) return error.KeyTooShort;

        const kp = try Keypair.fromSecretKey(.p256, decoded[0..32].*);
        const actual_did = try kp.did(allocator);
        defer allocator.free(actual_did);

        if (!std.mem.eql(u8, actual_did, expected_did)) {
            std.debug.print("FAIL P256: expected {s}, got {s}\n", .{ expected_did, actual_did });
            return error.DidKeyMismatch;
        }
        tested += 1;
    }

    try std.testing.expectEqual(@as(usize, 1), tested);
}

// === tier 2c: data model round-trip ===

/// convert AT Protocol JSON to CBOR value
/// handles $link (CID) and $bytes (byte string) special types
fn jsonToCbor(allocator: std.mem.Allocator, json: std.json.Value) !cbor.Value {
    switch (json) {
        .object => |obj| {
            // check for $link → CID
            if (obj.get("$link")) |link_val| {
                const link_str = switch (link_val) {
                    .string => |s| s,
                    else => return error.InvalidLink,
                };
                // bafyrei... is base32lower multibase (without 'b' prefix in the $link value,
                // but CID strings in AT Protocol use the full multibase-prefixed form)
                // actually the fixture CIDs start with "bafyrei" which is base32lower with 'b' prefix
                const raw = try multibase.base32lower.decode(allocator, link_str[1..]);
                return .{ .cid = .{ .raw = raw } };
            }
            // check for $bytes → byte string
            if (obj.get("$bytes")) |bytes_val| {
                const b64_str = switch (bytes_val) {
                    .string => |s| s,
                    else => return error.InvalidBytes,
                };
                const decoded = try base64StdDecode(allocator, b64_str);
                return .{ .bytes = decoded };
            }
            // regular object → map
            const entries = try allocator.alloc(cbor.Value.MapEntry, obj.count());
            var i: usize = 0;
            var it = obj.iterator();
            while (it.next()) |kv| {
                entries[i] = .{
                    .key = kv.key_ptr.*,
                    .value = try jsonToCbor(allocator, kv.value_ptr.*),
                };
                i += 1;
            }
            return .{ .map = entries };
        },
        .array => |arr| {
            const items = try allocator.alloc(cbor.Value, arr.items.len);
            for (arr.items, 0..) |item, i| {
                items[i] = try jsonToCbor(allocator, item);
            }
            return .{ .array = items };
        },
        .string => |s| return .{ .text = s },
        .integer => |n| {
            if (n >= 0) return .{ .unsigned = @intCast(n) };
            return .{ .negative = n };
        },
        .float => |f| {
            // DAG-CBOR has no floats; coerce integer-valued floats
            const int_val: i64 = @intFromFloat(f);
            if (@as(f64, @floatFromInt(int_val)) != f) return error.UnsupportedFloat;
            if (int_val >= 0) return .{ .unsigned = @intCast(int_val) };
            return .{ .negative = int_val };
        },
        .null => return .null,
        .bool => |b| return .{ .boolean = b },
        .number_string => return error.UnsupportedNumberString,
    }
}

test "interop: data model fixtures" {
    const allocator = std.testing.allocator;

    const fixture_json = @embedFile("data_model_fixtures");
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, fixture_json, .{});
    defer parsed.deinit();

    const fixtures = parsed.value.array.items;
    var tested: usize = 0;

    for (fixtures) |fixture| {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();

        const obj = fixture.object;
        const json_val = obj.get("json").?;
        const expected_cbor_b64 = obj.get("cbor_base64").?.string;
        const expected_cid_str = obj.get("cid").?.string;

        // convert JSON → CBOR value → encoded bytes
        const cbor_val = try jsonToCbor(a, json_val);
        const encoded = try cbor.encodeAlloc(a, cbor_val);

        // compare encoded bytes with expected
        const expected_bytes = try base64StdDecode(a, expected_cbor_b64);
        if (!std.mem.eql(u8, encoded, expected_bytes)) {
            std.debug.print("FAIL data model: CBOR encoding mismatch for fixture {d}\n", .{tested});
            std.debug.print("  expected ({d} bytes): ", .{expected_bytes.len});
            for (expected_bytes) |b| std.debug.print("{x:0>2}", .{b});
            std.debug.print("\n  actual   ({d} bytes): ", .{encoded.len});
            for (encoded) |b| std.debug.print("{x:0>2}", .{b});
            std.debug.print("\n", .{});
            return error.CborEncodingMismatch;
        }

        // compute CID and compare
        const cid = try cbor.Cid.forDagCbor(a, encoded);
        // format as base32lower multibase string: "b" + base32lower(raw)
        const cid_str = try multibase.base32lower.encode(a, cid.raw);
        if (!std.mem.eql(u8, cid_str, expected_cid_str)) {
            std.debug.print("FAIL data model: CID mismatch for fixture {d}\n", .{tested});
            std.debug.print("  expected: {s}\n  actual:   {s}\n", .{ expected_cid_str, cid_str });
            return error.CidMismatch;
        }

        tested += 1;
    }

    try std.testing.expectEqual(@as(usize, 3), tested);
}

// === tier 3: MST ===

test "interop: mst key heights" {
    const allocator = std.testing.allocator;

    const fixture_json = @embedFile("mst_key_heights");
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, fixture_json, .{});
    defer parsed.deinit();

    const fixtures = parsed.value.array.items;
    var tested: usize = 0;

    for (fixtures) |fixture| {
        const obj = fixture.object;
        const key = obj.get("key").?.string;
        const expected_height: u32 = @intCast(obj.get("height").?.integer);

        const actual = mst.keyHeight(key);
        if (actual != expected_height) {
            std.debug.print("FAIL: key '{s}': expected height {d}, got {d}\n", .{ key, expected_height, actual });
            return error.WrongHeight;
        }
        tested += 1;
    }

    try std.testing.expect(tested > 0);
}

test "interop: mst common prefix" {
    const allocator = std.testing.allocator;

    const fixture_json = @embedFile("common_prefix");
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, fixture_json, .{});
    defer parsed.deinit();

    const fixtures = parsed.value.array.items;
    var tested: usize = 0;

    for (fixtures) |fixture| {
        const obj = fixture.object;
        const left = obj.get("left").?.string;
        const right = obj.get("right").?.string;
        const expected_len: usize = @intCast(obj.get("len").?.integer);

        const actual = mst.commonPrefixLen(left, right);
        if (actual != expected_len) {
            std.debug.print("FAIL: commonPrefixLen('{s}', '{s}'): expected {d}, got {d}\n", .{ left, right, expected_len, actual });
            return error.WrongPrefixLen;
        }
        tested += 1;
    }

    try std.testing.expect(tested == 13);
}

test "interop: mst commit proofs" {
    const allocator = std.testing.allocator;

    const fixture_json = @embedFile("commit_proofs");
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, fixture_json, .{});
    defer parsed.deinit();

    const fixtures = parsed.value.array.items;
    var tested: usize = 0;

    for (fixtures) |fixture| {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();

        const obj = fixture.object;
        const comment = if (obj.get("comment")) |v| switch (v) {
            .string => |s| s,
            else => "?",
        } else "?";

        // parse leaf value CID
        const leaf_value_str = obj.get("leafValue").?.string;
        const leaf_cid = try mst.parseCidString(a, leaf_value_str);

        // build initial tree from keys
        var tree = mst.Mst.init(a);
        const keys = obj.get("keys").?.array.items;
        for (keys) |key_val| {
            try tree.put(key_val.string, leaf_cid);
        }

        // verify root before commit
        const root_before_str = obj.get("rootBeforeCommit").?.string;
        const expected_before = try mst.parseCidString(a, root_before_str);

        const actual_before = try tree.rootCid();
        if (!std.mem.eql(u8, actual_before.raw, expected_before.raw)) {
            std.debug.print("FAIL [{s}]: rootBeforeCommit mismatch\n", .{comment});
            std.debug.print("  expected: {s}\n", .{root_before_str});
            // print hex for debugging
            std.debug.print("  expected raw ({d}): ", .{expected_before.raw.len});
            for (expected_before.raw) |b| std.debug.print("{x:0>2}", .{b});
            std.debug.print("\n  actual raw ({d}):   ", .{actual_before.raw.len});
            for (actual_before.raw) |b| std.debug.print("{x:0>2}", .{b});
            std.debug.print("\n", .{});
            return error.RootBeforeMismatch;
        }

        // apply adds
        const adds = obj.get("adds").?.array.items;
        for (adds) |add_val| {
            try tree.put(add_val.string, leaf_cid);
        }

        // apply dels
        const dels = obj.get("dels").?.array.items;
        for (dels) |del_val| {
            try tree.delete(del_val.string);
        }

        // verify root after commit
        const root_after_str = obj.get("rootAfterCommit").?.string;
        const expected_after = try mst.parseCidString(a, root_after_str);

        const actual_after = try tree.rootCid();
        if (!std.mem.eql(u8, actual_after.raw, expected_after.raw)) {
            std.debug.print("FAIL [{s}]: rootAfterCommit mismatch\n", .{comment});
            std.debug.print("  expected: {s}\n", .{root_after_str});
            std.debug.print("  expected raw ({d}): ", .{expected_after.raw.len});
            for (expected_after.raw) |b| std.debug.print("{x:0>2}", .{b});
            std.debug.print("\n  actual raw ({d}):   ", .{actual_after.raw.len});
            for (actual_after.raw) |b| std.debug.print("{x:0>2}", .{b});
            std.debug.print("\n", .{});
            return error.RootAfterMismatch;
        }

        tested += 1;
    }

    try std.testing.expect(tested == 6);
}
