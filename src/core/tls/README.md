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
| `core.tls.ianic_inbound`           | inbound   | **shipped (W3.2, default)** | Pure-Zig TLS 1.3 server via vendored `ianic/tls.zig`; cert+key from in-memory PEM; fd-keyed slot pool sized at `limits.tls_inbound_max_connections` |
| `core.tls.boring_inbound`          | inbound   | shipped (W3.1, alternative) | Same shape, backed by system OpenSSL. Retained for FIPS-sensitive deployments and TLS 1.2 server support. Not the default. |

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

- **Server-side TLS 1.2** — the default `ianic_inbound` backend is
  TLS 1.3 only. Mastodon and Bluesky negotiate TLS 1.3 by default, so
  this is fine for federation. Deployments that need TLS 1.2 inbound
  can opt into the OpenSSL-backed `boring_inbound` at boot.
- **HTTPS-fronted WebSocket data plane** — the WS handshake fires
  through the TLS backend, but the per-handler frame loop reads /
  writes via the bare socket. Run WS over plain HTTP behind a
  terminating LB for now.
- **Socket-level timeouts on outbound connect** — `std.Io.net` does not
  yet expose per-socket connect / read timeouts in a portable way. The
  `timeout_ms` parameter on `http_client.TlsBackend.connect` is recorded
  but not yet enforced. Track upstream.
- **Cert pinning** — not implemented. The native outbound backend uses
  the OS trust store wholesale. Pinning slots into the same vtable when
  needed.
- **Multi-SNI fan-out** — both inbound backends serve a single
  cert/key pair. SNI dispatch lands when a multi-domain deployment
  actually appears.

## `ianic_inbound` (W3.2 — default, pure Zig)

Backed by [`ianic/tls.zig`](https://github.com/ianic/tls.zig), vendored
as a git submodule under `third_party/ianic-tls/`. TLS 1.3 only on the
server side; no system OpenSSL link needed for inbound. The slot pool
is heap-allocated at boot (size: `limits.tls_inbound_max_connections`,
default 1024). Each slot carries ~33 KiB of TLS record buffers plus
the per-connection `tls.Connection` value; sized smaller than
`max_connections` so plain-HTTP deployments don't pay the BSS cost.

## `boring_inbound` (W3.1 — alternative via system OpenSSL link)

`core.tls.boring_inbound.BoringInboundBackend` plugs into the same
`core.tls.TlsBackend` vtable. The build links system / Homebrew
`libssl` + `libcrypto`; the C-ABI surface (`SSL_*`, `EVP_*`, `RSA_*`,
`PEM_*`) is stable across OpenSSL 3, BoringSSL, and LibreSSL, so the
same Zig wrapper (`src/core/crypto/openssl.zig`) covers all three. The
OpenSSL link also provides the RSA-PKCS1v15-SHA256 *signing* primitive
used by ActivityPub federation outbound delivery — that path stays
linked even when the inbound backend is the pure-Zig `ianic_inbound`.

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

To force the OpenSSL-backed `boring_inbound` (e.g. for TLS 1.2 server
support), edit the `InboundTlsHolder` wiring in `src/app/main.zig` to
construct `core.tls.boring_inbound.BoringInboundBackend.init(...)`
instead of the ianic variant.
