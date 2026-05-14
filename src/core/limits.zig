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

/// Maximum number of WebSocket upgrade routes registered across all
/// plugins. Each WS upgrade route is owned by one plugin and dispatches
/// the connection after a successful 101 handshake. See
/// `core/ws/upgrade_router.zig`.
pub const max_ws_routes: u32 = 32;

/// Maximum number of HTTP/1.1 requests served over a single TCP
/// connection before the server closes it. Bounds the keep-alive
/// inner loop in `core/server.zig`. Beyond this we send
/// `Connection: close` on the final response and tear the socket down.
pub const max_requests_per_connection: u32 = 100;

/// Maximum length of a single HTTP route pattern (e.g. "/users/:u/inbox").
pub const max_route_pattern_bytes: usize = 128;

/// Maximum length of a plugin name.
pub const max_plugin_name_bytes: usize = 32;

/// Worker pool size for blocking work (SQLite writes, signature
/// verification, DNS). Each worker has its own arena.
pub const worker_pool_size: u32 = 8;

/// Per-worker arena size.
pub const worker_arena_bytes: usize = 64 * 1024;

/// Maximum queued jobs across the worker pool. Must be a power of two
/// because the underlying queue is backed by `static.BoundedMpsc` which
/// uses `static.FixedRingBuffer` (requires power-of-two capacity for fast
/// index masking).
pub const max_queued_jobs: u32 = 1024;

/// Maximum time a submitter will block in `Completion.wait` before
/// declaring the job stuck. 5 seconds covers the longest reasonable
/// blocking I/O operation (HTTP key fetch with redirects, DNS retry).
pub const pool_completion_timeout_ns: u64 = 5 * 1_000_000_000;

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

// ── Observability (Phase 7) ─────────────────────────────────────────
//
// Logs are the canonical Tiger Style ring-buffer use case: lossy by
// design. When the drain thread falls behind, the producer overwrites
// the oldest pending entry rather than blocking the hot path. The ring
// is sized large enough that overwrite under normal load is rare; a
// burst that overflows is preferable to back-pressuring a request
// handler. See `core/log.zig` for the full philosophy.

/// Capacity of the in-memory log ring. Must be a power of two so the
/// ring can use fast index masking. 4096 entries × ~512 bytes ≈ 2 MiB
/// worst-case in-memory log buffer.
pub const log_ring_capacity: u32 = 4096;

/// Maximum length in bytes of a single log message body. Messages
/// longer than this are truncated, never reallocated.
pub const max_log_msg_bytes: usize = 256;

/// Maximum structured key-value pairs attached to a single log entry.
pub const max_log_kv: u32 = 8;

/// Maximum length of a single log KV key or value (UTF-8 bytes).
pub const max_log_kv_bytes: usize = 64;

/// Maximum log scope label length ("storage", "http", "ap.inbox", ...).
pub const max_log_scope_bytes: usize = 32;

/// Metrics registry capacity. Each metric is a stable handle assigned
/// at registration time.
pub const max_metrics: u32 = 256;

/// Maximum length of a metric name including any plugin prefix.
pub const max_metric_name_bytes: usize = 64;

/// Maximum length of a metric help string (Prometheus HELP line).
pub const max_metric_help_bytes: usize = 128;

/// Maximum histogram buckets (LE bucket bounds) per histogram metric.
pub const max_histogram_buckets: u32 = 16;

/// Maximum phases registered with the shutdown coordinator. Each phase
/// runs sequentially in registration order on shutdown.
pub const max_shutdown_phases: u32 = 16;

/// Maximum readiness hooks plugins may register with the health module.
pub const max_health_hooks: u32 = 16;

// ── Media (W1.4) ───────────────────────────────────────────────────
//
// Bounded ceilings for the media plugin. Anything larger → HTTP 413.
// These caps apply to *both* the raw POST body and the per-part body
// inside a multipart/form-data envelope.

/// Maximum size in bytes of an uploaded media blob. 16 MiB lets a
/// typical hi-res still image / short voice clip through while keeping
/// the per-connection arena pressure bounded.
pub const max_upload_bytes: usize = 16 * 1024 * 1024;

/// Maximum number of parts in a single multipart/form-data request.
/// Tiger Style: assert a small constant; clients don't legitimately
/// need more than this for media uploads (file + optional description
/// + focus + form field slack).
pub const max_multipart_parts: u32 = 8;

/// Maximum number of header lines per multipart part.
pub const max_multipart_headers_per_part: u32 = 16;

/// Maximum length of a multipart boundary string. RFC 7578 allows up
/// to 70; we add slack for delimiter framing.
pub const max_multipart_boundary_bytes: usize = 80;

/// Blob inline threshold: blobs strictly larger than this are stored
/// on the filesystem under `media_root`, and the DB row holds an
/// "fs:<relative-path>" pointer in place of the bytes. Smaller blobs
/// live inline in the BLOB column.
pub const media_inline_threshold_bytes: usize = 1 * 1024 * 1024;

/// Maximum length of a shutdown phase / health hook label.
pub const max_phase_name_bytes: usize = 32;
