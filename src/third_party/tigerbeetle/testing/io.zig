// Vendored from tigerbeetle/src/testing/io.zig @ 44544ee11057bbc8fe826cb7f93e8e00a57f2fc1.
// Modifications:
//   * Removed dependencies on TB's QueueType (intrusive completion queue),
//     `io/common.NextTickSource`, `constants.sector_size`, and stdx.PRNG.
//     speedy-socials's storage layer does not yet use io_uring — for now,
//     SimIo is a minimal byte-addressable backing store with optional
//     sector-fault injection for testing storage paths and federation
//     outbox queue persistence under disk fault.
//   * Sector size is now a parameter (default 4096 bytes) instead of a
//     compile-time constant from TB.
//   * Drops the async `Completion`/`submit` abstraction (TB uses it because
//     it mocks the same surface as the real io_uring driver). We expose
//     synchronous `read`/`write`/`fsync` that match what speedy-socials
//     callers actually invoke.
// TigerBeetle is licensed under Apache 2.0; see src/third_party/tigerbeetle/LICENSE.

const std = @import("std");
const assert = std.debug.assert;

pub const default_sector_size: u32 = 4096;

pub const File = struct {
    buffer: []u8,
    /// Each bit of the fault map represents a sector that will fault
    /// consistently. Length must be `ceil(buffer.len / sector_size / 8)`.
    fault_map: ?[]const u8 = null,
    closed: bool = false,
    offset: u32 = 0,
};

pub const Options = struct {
    seed: u64 = 0,
    sector_size: u32 = default_sector_size,
    /// Probability in [0, 1] that a read larger than one sector returns
    /// `error.InputOutput`. Used to model torn or partial reads.
    larger_than_logical_sector_read_fault_probability: f32 = 0.0,
};

pub const ReadError = error{
    InputOutput,
    OutOfBounds,
    NotOpen,
};

pub const WriteError = error{
    OutOfBounds,
    NotOpen,
};

pub const SimIo = struct {
    files: []File,
    options: Options,
    prng: std.Random.Xoshiro256,

    pub fn init(files: []File, options: Options) SimIo {
        assert(options.sector_size > 0);
        // sector_size must be a power of two so address/sector arithmetic
        // matches real block storage.
        assert(std.math.isPowerOfTwo(options.sector_size));
        return .{
            .files = files,
            .options = options,
            .prng = std.Random.Xoshiro256.init(options.seed),
        };
    }

    pub fn deinit(self: *SimIo) void {
        // All files must be explicitly closed; this catches descriptor leaks
        // in tests, matching TB's contract.
        for (self.files) |file| assert(file.closed);
    }

    pub fn read(self: *SimIo, fd: u32, buffer: []u8, offset: u64) ReadError!usize {
        if (fd >= self.files.len) return error.NotOpen;
        const file = &self.files[fd];
        if (file.closed) return error.NotOpen;
        if (offset + buffer.len > file.buffer.len) return error.OutOfBounds;

        const sector_size = self.options.sector_size;
        // Sector fault map: each bit corresponds to one sector. We must
        // probe every sector the read spans.
        if (file.fault_map) |fmap| {
            const first_sector = offset / sector_size;
            const last_sector = (offset + buffer.len - 1) / sector_size;
            var s: u64 = first_sector;
            while (s <= last_sector) : (s += 1) {
                const byte_idx = s / 8;
                const bit_idx: u3 = @intCast(s % 8);
                if (byte_idx < fmap.len and ((fmap[byte_idx] >> bit_idx) & 1) == 1) {
                    return error.InputOutput;
                }
            }
        }

        if (buffer.len > sector_size and self.prng.random().float(f32) <
            self.options.larger_than_logical_sector_read_fault_probability)
        {
            return error.InputOutput;
        }

        @memcpy(buffer, file.buffer[offset..][0..buffer.len]);
        return buffer.len;
    }

    pub fn write(self: *SimIo, fd: u32, buffer: []const u8, offset: u64) WriteError!usize {
        if (fd >= self.files.len) return error.NotOpen;
        const file = &self.files[fd];
        if (file.closed) return error.NotOpen;
        if (offset + buffer.len > file.buffer.len) return error.OutOfBounds;

        @memcpy(file.buffer[offset..][0..buffer.len], buffer);
        return buffer.len;
    }

    pub fn fsync(self: *SimIo, fd: u32) WriteError!void {
        if (fd >= self.files.len) return error.NotOpen;
        if (self.files[fd].closed) return error.NotOpen;
    }

    pub fn close(self: *SimIo, fd: u32) void {
        assert(fd < self.files.len);
        self.files[fd].closed = true;
    }
};

test "SimIo round-trip" {
    var backing: [4096]u8 = undefined;
    var files = [_]File{.{ .buffer = &backing }};
    var io = SimIo.init(&files, .{});
    defer {
        io.close(0);
        io.deinit();
    }

    var payload: [16]u8 = undefined;
    var prng = std.Random.Xoshiro256.init(0x123);
    prng.random().bytes(&payload);

    _ = try io.write(0, &payload, 1024);
    var readback: [16]u8 = undefined;
    const n = try io.read(0, &readback, 1024);
    try std.testing.expectEqual(@as(usize, 16), n);
    try std.testing.expectEqualSlices(u8, &payload, &readback);
}

test "SimIo sector fault returns InputOutput" {
    var backing: [4096 * 4]u8 = undefined;
    // Sector 2 (offset 8192..12288) is faulted.
    var fault_map = [_]u8{0b00000100};
    var files = [_]File{.{ .buffer = &backing, .fault_map = &fault_map }};
    var io = SimIo.init(&files, .{});
    defer {
        io.close(0);
        io.deinit();
    }

    // Read from sector 0 succeeds.
    var buf: [4096]u8 = undefined;
    _ = try io.read(0, &buf, 0);

    // Read from sector 2 (offset 8192) faults.
    try std.testing.expectError(error.InputOutput, io.read(0, &buf, 8192));

    // Read straddling sector 1 and sector 2 also faults.
    var spanning: [4096]u8 = undefined;
    try std.testing.expectError(error.InputOutput, io.read(0, &spanning, 4096 + 1024));
}

test "SimIo out-of-bounds rejected" {
    var backing: [128]u8 = undefined;
    var files = [_]File{.{ .buffer = &backing }};
    var io = SimIo.init(&files, .{});
    defer {
        io.close(0);
        io.deinit();
    }

    var buf: [64]u8 = undefined;
    try std.testing.expectError(error.OutOfBounds, io.read(0, &buf, 100));
    try std.testing.expectError(error.OutOfBounds, io.write(0, &buf, 100));
}
