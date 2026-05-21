# WSS data plane (C1)

speedy-socials runs its WebSocket frame loops (atproto `subscribeRepos`,
Mastodon `streaming/user` etc.) through a unified `core.ws.stream.Stream`
abstraction. The abstraction owns the non-blocking semantics so the same
handler code works over plain TCP and over TLS without changes.

_Last updated: 2026-05-21._

## Why

Pre-C1, both handlers (`sync_firehose.zig`, `streaming_ws.zig`) did
direct `poll(2) + read(2)` against the raw socket fd. That worked for
plain HTTP/WS but broke under HTTPS/WSS because the bytes coming off
the fd are TLS ciphertext, not WS frame data. The handler would
interpret ciphertext as garbage frames and close the connection.

Three options were considered:
1. **Patch ianic-tls upstream** so its blocking `Connection.read`
   distinguishes WouldBlock from EOF. Out of our hands.
2. **Buffer ciphertext at the server level**. Simpler integration but
   doubles every byte through a server-wide ring.
3. **Per-connection decrypted-plaintext ring driven by a small
   reader thread.** Ours.

We picked (3) because:
- The frame loop stays single-threaded + non-blocking.
- The reader thread blocks safely on `tls.Connection.read`.
- The ring decouples the two so backpressure / packet pacing on
  either side doesn't impact the other.

## Architecture

```
                         ┌──────────────────────┐
                         │ WS handler thread    │
                         │ (sync_firehose etc.) │
                         │                      │
                         │  ┌────────────────┐  │
                         │  │ frame loop     │  │
                         │  │ readNB(buf) ←──┼──┘
                         │  │ writeAll(buf)─┐│
                         │  └────────────────┘
                         └──┬───────────────┬──┘
                            │               │
       ┌────────────────────┘               └─────────────┐
       │                                                  ▼
       │                            ┌────────────────────────┐
       ▼                            │ TlsStream.doWrite      │
┌─────────────────┐                 │ (encrypt + socket-write│
│ ws plaintext    │                 │  on handler thread)    │
│ ring buffer     │◄──┐             └──────────┬─────────────┘
└─────────────────┘   │                        │
                      │                        ▼
              ┌───────┴──────────┐    ┌─────────────────┐
              │ TLS reader thread│    │ TCP socket      │
              │ pulls plaintext  │◄───┤ (raw fd)        │
              │ from ianic       │    └─────────────────┘
              └──────────────────┘
```

For plain HTTP the picture collapses: `PlainStream.doRead` calls
`poll(2) + read(2)` directly on the fd; no reader thread, no ring.

## Public API

`src/core/ws/stream.zig`:

```zig
pub const Stream = struct {
    pub fn readNonblocking(self: Stream, dst: []u8) Error!usize;
    pub fn writeAll(self: Stream, bytes: []const u8) Error!void;
    pub fn close(self: Stream) void;
};

pub const PlainStream = struct {
    pub fn init(fd: fd_t) PlainStream;
    pub fn stream(self: *PlainStream) Stream;
};

pub const TlsStream = struct {
    pub fn init(adapter: TlsAdapter) TlsStream;
    pub fn start(self: *TlsStream) !void; // spawns reader thread
    pub fn stream(self: *TlsStream) Stream;
};

pub const TlsAdapter = struct {
    ptr: *anyopaque,
    read_blocking: *const fn (*anyopaque, []u8) Error!usize,
    write_all: *const fn (*anyopaque, []const u8) Error!void,
    close: *const fn (*anyopaque) void,
};
```

The `TlsAdapter` is what plugs into a concrete TLS implementation.
The current default wraps an `ianic-tls.Connection` — see
`src/core/tls/ianic_inbound.zig`.

## Handler integration

`WsUpgradeContext` carries an optional `ws_stream: ?Stream`. The
server's upgrade dispatcher fills it in (PlainStream for HTTP boot,
TlsStream for HTTPS boot). Handlers check `ctx.ws_stream` first and
fall back to the legacy direct-fd path when null — so plain-HTTP
deployments that haven't migrated the dispatcher keep working.

```zig
fn writeAll(ctx: *WsUpgradeContext, payload: []const u8) !void {
    if (ctx.ws_stream) |s| {
        s.writeAll(payload) catch return error.WriteFailed;
        return;
    }
    // legacy plain-fd path …
}
```

The same pattern covers `pumpInbound`.

## Threading + lifecycles

- `PlainStream` runs entirely on the handler thread.
- `TlsStream.start()` spawns one reader thread per connection. The
  reader thread joins on `Stream.close()` — so closing the WS handler
  cleanly tears down both threads.
- Ring buffer is 16 KiB; bounded by Tiger Style. Overflow drops the
  oldest plaintext (the same drop-oldest policy as `ws.event_ring`).
- Producer + consumer share the ring through a `core.static.Spinlock`.

## What's still open

- The composition root (`src/app/main.zig`) doesn't yet mint a
  `TlsStream` when TLS is configured — the upgrade dispatcher in
  `core/ws/upgrade_router.zig` will set `ws_stream` once the
  server-side boot wiring lands. Today both paths run plain.
- `ianic_inbound` exposes the cipher state via `Connection` only;
  the `TlsAdapter` impl that wraps it lives in a follow-up so the
  C1 architecture is committable independently.
- A WSS loopback test that brings up a TLS server + a TLS client
  end-to-end is gated on the boot-wiring above; the
  `stream.zig`-level loopback test (PlainStream carrying a real WS
  frame) is in place today.
