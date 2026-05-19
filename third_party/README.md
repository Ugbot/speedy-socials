# third_party/

External code consumed by speedy-socials. The vendor strategy per
entry is documented inline.

## Inventory

### `boringssl/`
**System OpenSSL link** — no source vendor. The Zig build links the
host OS's libssl/libcrypto via `linkSystemLibrary`. See
`third_party/boringssl/README.md` for the full rationale and the
re-vendor procedure for FIPS-sensitive deployments.

### `ianic-tls/`
**Real git submodule** — pure-Zig TLS 1.2/1.3 client + TLS 1.3 server
([ianic/tls.zig](https://github.com/ianic/tls.zig)). The default
inbound TLS backend (`core.tls.ianic_inbound`) uses this; `boringssl`
remains an alternative for TLS 1.2 server / FIPS deployments.
Tracked in `.gitmodules`; bump by checking out the desired SHA in
`third_party/ianic-tls/` and committing the submodule pointer.

### `zig-sqlite/`
**Vendored copy** — sqlite C amalgamation + a thin Zig wrapper. Not
yet a submodule. Tracked as plain files for now; upgrade by
replacing the contents with a newer release tarball.

## TickStream (referenced but not vendored)

[TickStream](https://github.com/Ugbot/tickstream) is a sibling Zig
project. During W4 we considered vendoring its
`lockfree_queue_refactored.zig` and `codec_toolbox/connection_state.zig`
modules. We ended up using TigerBeetle's `RingBufferType` instead —
the relay's firehose consumer is single-producer single-consumer, so
the TB primitive (already vendored) fit better than the
mpmc lockfree queue. No TickStream code is currently included in
speedy-socials. Future use would land here under
`third_party/tickstream/` either as a submodule or vendored copy.
