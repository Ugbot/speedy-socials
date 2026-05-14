//! Static bounds for every collection, buffer, and queue in the system.
//!
//! Tiger Style invariant: every loop and data structure has an explicit
//! upper bound declared here. If you find yourself wanting an "unbounded"
//! anything, add a bound here and audit the failure mode when it fills.
//!
//! Philosophy — ring buffers vs pools vs fixed buffers:
//!
//!  * Ring buffer (rolls around, overwrites oldest):
//!      - log lines, recent-events streams, broadcast fan-out where it is
//!        acceptable to drop the oldest entry when a slow consumer falls
//!        behind. Prefer this when there is *no* hard failure mode for
//!        "we ran out" — sized large enough that overwrite is rare under
//!        normal load.
//!
//!  * Bounded queue with backpressure (refuses new on full):
//!      - work units that must not be silently dropped: SQLite writes,
//!        federation deliveries, inbox jobs. Producer gets `Full` and
//!        decides (retry, 429, dead-letter).
//!
//!  * Static pool (stable slot identity, LIFO):
//!      - long-lived objects with handles held outside the pool:
//!        connections, prepared statements, plugin slots.
//!
//!  * Fixed linear buffer (known length, hard ceiling):
//!      - one HTTP request head, one response head when Content-Length
//!        is known up front. Overflow is a 413 / 500.
//!
//!  * Ring-backed streaming response (opt-in unknown length):
//!      - chunked transfer encoding writing into a ring buffer the I/O
//!        writer drains. Producer can write more than ring size as long
//!        as the writer keeps up. See `core/http/response_stream.zig`.
//!
//! When in doubt, size the ring or buffer slightly larger than worst
//! case. Memory is cheap; surprise failure modes are not.
//!
//! Numbers here are sized for a single-instance social server (10k DAU,
//! low thousands of concurrent connections). Tune via Config at startup;
//! these are the compile-time ceilings.

/// Maximum simultaneous TCP connections. Each connection costs one slot
/// in the Connection pool (request arena + fixed read/write buffers).
pub const max_connections: u32 = 4096;

/// Per-connection request arena size. One full HTTP request lives here
/// from parse through response serialization. ActivityPub Notes + Mastodon
/// API payloads should comfortably fit in 64 KiB.
pub const request_arena_bytes: usize = 64 * 1024;

/// Per-connection inbound read buffer. Sized for the largest expected
/// HTTP request head plus a generous body slack. Anything larger is
/// rejected with 413 Payload Too Large.
pub const conn_read_buffer_bytes: usize = 16 * 1024;

/// Per-connection outbound write buffer.
pub const conn_write_buffer_bytes: usize = 16 * 1024;

/// Maximum number of registered plugins. Static — bumping this is a
/// recompile.
pub const max_plugins: u32 = 16;

/// Maximum number of HTTP routes registered across all plugins.
pub const max_routes: u32 = 256;

/// Maximum length of a single HTTP route pattern (e.g. "/users/:u/inbox").
pub const max_route_pattern_bytes: usize = 128;

/// Maximum length of a plugin name.
pub const max_plugin_name_bytes: usize = 32;

/// Worker pool size for blocking work (SQLite writes, signature
/// verification, DNS). Each worker has its own arena.
pub const worker_pool_size: u32 = 8;

/// Per-worker arena size.
pub const worker_arena_bytes: usize = 64 * 1024;

/// Maximum queued jobs across the worker pool.
pub const max_queued_jobs: u32 = 1024;

/// Maximum SQLite prepared statements registered at startup.
pub const max_prepared_stmts: u32 = 256;

/// Maximum in-flight SQLite queries the channel will accept before
/// applying backpressure.
pub const max_inflight_queries: u32 = 256;

/// Federation outbox: maximum concurrent in-flight deliveries per
/// instance.
pub const max_inflight_deliveries: u32 = 64;

/// Federation: maximum delivery attempts before moving to dead-letter.
pub const max_delivery_attempts: u32 = 8;

/// Public-key LRU cache for HTTP-signature verification.
pub const max_cached_pubkeys: u32 = 4096;

/// WebSocket subscription registry — total subscriptions across all
/// streams/users.
pub const max_subscriptions: u32 = 8192;

/// WebSocket subscription shards — partitions the registry by
/// `hash(stream) % shards` so the event loop owns disjoint shards.
pub const ws_subscription_shards: u32 = 16;

/// Per-tick caps on the event loop. Each step asserts it processed
/// at most this many ops, then yields to the next step.
pub const max_accepts_per_tick: u32 = 64;
pub const max_reads_per_tick: u32 = 256;
pub const max_writes_per_tick: u32 = 256;

/// Maximum HTTP header count per request. Anything beyond → 400.
pub const max_http_headers: u32 = 64;

/// Maximum header line length (name + value).
pub const max_http_header_bytes: usize = 4096;

/// Maximum HTTP method length ("PROPPATCH" is 9, give some slack).
pub const max_http_method_bytes: usize = 16;

/// Maximum HTTP request-target length.
pub const max_http_target_bytes: usize = 2048;

/// Listen backlog passed to the OS.
pub const tcp_listen_backlog: u31 = 1024;
