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
| `core.tls.boring_inbound`          | inbound   | **shipped (W3.1)** | Real TLS 1.2/1.3 server via system OpenSSL link; cert+key from in-memory PEM, fd-keyed slot pool |

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

## BoringSSL backend (W3.1 — shipped via system OpenSSL link)

W3.1 wired in `core.tls.boring_inbound.BoringInboundBackend`, which
plugs into the existing `core.tls.TlsBackend` vtable. We did **not**
vendor the BoringSSL source tree — the build links the system / Homebrew
`libssl` + `libcrypto` instead. The C-ABI surface (`SSL_*`, `EVP_*`,
`RSA_*`, `PEM_*`) is stable across OpenSSL 3, BoringSSL, and LibreSSL,
so the same Zig wrapper (`src/core/crypto/openssl.zig`) works across
all three. See `third_party/boringssl/README.md` for the rationale +
re-vendor procedure if we ever decide to absorb the source.

The vtable picked up three new **optional** fields (additions only —
existing backends untouched): `read_some`, `write_all`, `close_conn`.
When a backend sets them, the server (`src/core/server.zig`) routes its
data plane through them instead of `net.Stream.Reader/Writer`.
`PlainBackend` / `StubTlsBackend` leave them null and keep the fast
path.

Boot wiring lives in `src/app/main.zig` (see `loadInboundTlsIfConfigured`).
Set `TLS_CERT_PATH` and `TLS_KEY_PATH` to enable inbound HTTPS:

```
TLS_CERT_PATH=./tests/fixtures/test.crt \
TLS_KEY_PATH=./tests/fixtures/test.key \
./zig-out/bin/speedy-socials
```

Multi-SNI dispatch is intentionally deferred — single-cert support
matches Mastodon defaults and covers v1 deployments.

## BoringSSL backend shape (reference)

The shape of any future BoringSSL / LibreSSL / Rustls inbound backend
remains identical to the existing native backends:

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
