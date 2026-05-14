# `core.tls` — TLS backends

speedy-socials separates **outbound TLS** (we are the client; we talk to
Mastodon, Bluesky, key servers) from **inbound TLS** (we are the server;
external peers connect to us). The two have different vtables in
different modules:

| Direction | Vtable                          | Defined in                |
|-----------|---------------------------------|---------------------------|
| Inbound   | `core.tls.TlsBackend`           | `src/core/tls.zig`        |
| Outbound  | `core.http_client.TlsBackend`   | `src/core/http_client.zig`|

This split exists because outbound TLS needs to do DNS + TCP + handshake
as one unit (so it owns the whole transport), whereas inbound TLS is
handed a raw accepted stream and only wraps it.

## Backends

| Backend                            | Direction | Status   | What it does                                                                 |
|------------------------------------|-----------|----------|------------------------------------------------------------------------------|
| `core.tls.PlainBackend`            | inbound   | shipped  | Pass-through (process speaks plain HTTP behind a terminating LB)             |
| `core.tls.StubTlsBackend`          | inbound   | shipped  | Pass-through with a noisy warning, for ops scripts wiring the TLS flag      |
| `core.tls.native_outbound`         | outbound  | **shipped** | Real TLS 1.2/1.3 client via `std.crypto.tls.Client` + OS CA bundle      |
| `core.tls.native_inbound`          | inbound   | **stub** | Always errors `TlsServerNotImplementedInThisZig`; 0.16 stdlib has no server |

The default boot wiring (`src/app/main.zig`) installs
`NativeOutboundBackend` on `http_client` so federation requests reach
real Mastodon and Bluesky peers. Inbound listeners run with
`PlainBackend` (terminate TLS in a sidecar / LB).

## Zig 0.16 `std.crypto.tls` verdict

- **Client-side: works.** `std.crypto.tls.Client.init(input, output, options)`
  performs a TLS 1.2 / 1.3 handshake against any `Io.Reader` / `Io.Writer`
  pair, using `std.crypto.Certificate.Bundle` for trust anchors. The
  `Bundle.rescan` helper loads the OS trust store on macOS and Linux.
- **Server-side: missing.** There is no `tls.Server.init` in 0.16; the
  stdlib only exposes the client path. Server-side handshake, cert chain
  building from a private key, and SNI fan-out are all unimplemented.

## Known gaps

- **Inbound TLS** — needs an external library (BoringSSL is the planned
  replacement). Today the recommended deployment shape is to terminate
  TLS in a sidecar (Caddy, nginx, a load balancer) and run speedy-socials
  on plain HTTP behind it.
- **Socket-level timeouts on outbound connect** — `std.Io.net` does not
  yet expose per-socket connect / read timeouts in a portable way. The
  `timeout_ms` parameter on `http_client.TlsBackend.connect` is recorded
  but not yet enforced. Track upstream.
- **Cert pinning** — not implemented. The native outbound backend uses
  the OS trust store wholesale. Pinning slots into the same vtable when
  needed.

## BoringSSL backend (deferred)

The follow-up replaces `native_inbound` (and optionally `native_outbound`
in FIPS-sensitive deployments) with a vendored BoringSSL build. The shape
is identical to the native backends:

```zig
pub const BoringInboundBackend = struct {
    // ... cert chain, private key, SNI table ...

    pub fn backend(self: *@This()) core.tls.TlsBackend {
        return .{ .ptr = self, .vtable = &vtable };
    }

    pub const vtable: core.tls.TlsBackend.VTable = .{ .wrap_stream = wrap };
};
```

Because callers in `core.server` and `core.http_client` only see the
vtable, no other code changes when the BoringSSL backend lands.
