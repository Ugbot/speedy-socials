//! Echo handler microbenchmark.
//!
//! Drives the echo `GET /echo` hot path in-process: build a `Request`,
//! match it through the `Router`, invoke the handler, serialize a
//! `Response`. No sockets — this measures the per-request CPU cost the
//! server's accept loop would pay once a connection is established, plus
//! the request/response object lifecycle.
//!
//! Note: a true cross-process loopback bench requires the full async
//! server stack which is owned by W1.1 (server-upgrades). We document
//! that follow-up in `bench/baseline.json` so the threshold can be
//! tightened once that lands.
//!
//! Records:
//!   * rps (single-core, in-process)
//!   * p50, p99, p999 latency in nanoseconds
//!   * alloc_delta_per_request — must be zero (`StaticAllocator` tripwire)
//!
//! Asserts: rps and p99 stay within thresholds loaded from
//! `bench/baseline.json` (parsed by `bench_runner.zig`).

const std = @import("std");
const core = @import("core");

const Method = core.http.request.Method;
const Request = core.http.request.Request;
const Response = core.http.response;
const Router = core.http.router.Router;
const HandlerContext = core.http.router.HandlerContext;
const PathParams = core.http.router.PathParams;

const N: u64 = 10_000;

// In-process handler — identical body to the real echo plugin's GET handler.
fn echoGet(hc: *HandlerContext) anyerror!void {
    try hc.response.simple(.ok, "text/plain", "echo\n");
}

fn realNs() u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(std.c.CLOCK.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

fn cmpU64(_: void, a: u64, b: u64) bool {
    return a < b;
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();

    // Allocator tripwire: any alloc/free during the hot loop panics.
    var static_alloc = core.alloc.StaticAllocator.init(gpa.allocator());
    defer static_alloc.deinit();

    // ── boot: build a router and freeze it ────────────────────────────
    var router = Router.init();
    try router.register(.get, "/echo", echoGet, 0);
    router.freeze();

    const empty_headers: []const core.http.request.Header = &.{};
    const req: Request = .{
        .method = .get,
        .method_raw = "GET",
        .target = "/echo",
        .version = "HTTP/1.1",
        .headers = empty_headers,
        .body = "",
    };

    // Pre-allocate per-request buffers and a fake plugin context.
    var resp_buf: [256]u8 = undefined;
    var sim_clock = core.clock.SimClock.init(0);
    var rng = core.rng.Rng.init(1);
    var plugin_ctx: core.plugin.Context = .{
        .clock = sim_clock.clock(),
        .rng = &rng,
    };

    var latencies = try gpa.allocator().alloc(u64, N);
    defer gpa.allocator().free(latencies);

    // ── arm the tripwire — nothing past this should alloc ─────────────
    static_alloc.transition_from_init_to_static();

    const t0 = realNs();
    var i: u64 = 0;
    while (i < N) : (i += 1) {
        const r_t0 = realNs();
        // Match.
        var params: PathParams = .{};
        const handler = router.match(req.method, "/echo", &params) orelse return error.MatchFailed;
        // Build response builder fresh per request (same lifecycle the
        // server uses: a per-connection Builder reset on each request).
        var rb = Response.Builder.init(&resp_buf);
        var hc: HandlerContext = .{
            .plugin_ctx = &plugin_ctx,
            .request = &req,
            .response = &rb,
            .params = params,
        };
        try handler(&hc);
        // Sanity-check that the response bytes were produced.
        if (rb.bytes().len == 0) return error.EmptyResponse;
        const r_t1 = realNs();
        latencies[i] = r_t1 - r_t0;
    }
    const t1 = realNs();

    static_alloc.transition_from_static_to_deinit();

    const total_ns = t1 - t0;
    const rps: f64 = @as(f64, @floatFromInt(N)) / (@as(f64, @floatFromInt(total_ns)) / 1e9);

    // Percentile computation: sort latencies in place.
    std.mem.sort(u64, latencies, {}, cmpU64);
    const p50 = latencies[@divTrunc(N, 2)];
    const p99 = latencies[(N * 99) / 100];
    const p999 = latencies[@min(N - 1, (N * 999) / 1000)];

    std.debug.print("\necho-bench: N={d}\n", .{N});
    std.debug.print("  rps         : {d:.0}\n", .{rps});
    std.debug.print("  p50 ns      : {d}\n", .{p50});
    std.debug.print("  p99 ns      : {d}\n", .{p99});
    std.debug.print("  p999 ns     : {d}\n", .{p999});
    std.debug.print("  alloc_delta : 0 (StaticAllocator tripwire)\n", .{});

    // Write to a side file for bench_runner.zig to splice into results.json.
    var buf: [512]u8 = undefined;
    const json = try std.fmt.bufPrint(&buf,
        \\{{"rps":{d:.0},"p50_ns":{d},"p99_ns":{d},"p999_ns":{d},"alloc_delta":0,"N":{d}}}
    , .{ rps, p50, p99, p999, N });
    try writeFileC("bench/.echo_bench_results.json", json);
}

const libc = @cImport({
    @cInclude("stdio.h");
});

fn writeFileC(path: [:0]const u8, contents: []const u8) !void {
    const f = libc.fopen(path.ptr, "w") orelse return error.OpenFailed;
    defer _ = libc.fclose(f);
    const written = libc.fwrite(contents.ptr, 1, contents.len, f);
    if (written != contents.len) return error.WriteFailed;
}
