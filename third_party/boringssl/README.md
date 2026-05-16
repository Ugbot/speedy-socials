# third_party/boringssl — system OpenSSL link (no source vendor)

speedy-socials links the operating system's OpenSSL / LibreSSL / BoringSSL
**at the C-ABI level**, rather than vendoring the BoringSSL source tree.
The C surface we depend on (`EVP_*`, `RSA_*`, `SSL_*`, `PEM_*`) is
historically stable across these forks and trivially compatible at the
linker boundary.

## Why no source-vendor

Vendoring even a minimal BoringSSL slice means dragging in roughly 200
`.c` files across `bn/`, `asn1/`, `evp/`, `x509/`, `ec/`, `pem/`, `rand/`,
plus the entire `ssl/` directory and its asm fan-out per arch. Realistic
effort to bring up a vendored build under `build.zig` (including
generated `err_data.c`, perlasm artifacts, and the no-CRT paths) is well
over a working day — outside the time budget for W3.1, which calls out
a 4-hour cap and an explicit escape hatch:

> **Pragmatic alternative**: skip the full BoringSSL vendor and instead
> `linkSystemLibrary("crypto")` + `linkSystemLibrary("ssl")` (i.e. link
> the OS-provided OpenSSL/BoringSSL/LibreSSL). The C ABI is compatible
> at the level we need.

This directory exists so the audit trail is clear: the *intent* was to
vendor BoringSSL, and a future maintainer can drop in the source under
this path without changing the build wiring above the `core.crypto.openssl`
module boundary.

## Origin (target if we ever do vendor)

* Repository: https://boringssl.googlesource.com/boringssl
* License:    Apache-2.0 + ISC (full text in `LICENSE` once vendored)
* Suggested pinned commit: see upstream `HEAD` at vendor time; record
  here and in `NOTICE`.

## What the build actually links

`build.zig` calls `linkSystemLibrary("crypto")` and
`linkSystemLibrary("ssl")` on the `core` module plus the executable, and
adds the homebrew OpenSSL include / lib paths on macOS aarch64. On
Linux x86_64 the system pkg-config-discoverable `libcrypto.so` /
`libssl.so` are used.

| Platform        | Provider                      | Header path                                |
|-----------------|-------------------------------|--------------------------------------------|
| macOS aarch64   | Homebrew OpenSSL 3            | `/opt/homebrew/opt/openssl@3/include`      |
| macOS x86_64    | Homebrew OpenSSL 3            | `/usr/local/opt/openssl@3/include`         |
| Linux x86_64    | System OpenSSL (apt/dnf/pacman) | `/usr/include/openssl`                   |
| Alpine / musl   | OpenSSL 3 (`openssl-dev`)     | `/usr/include/openssl`                     |

Apple's own `libssl` and `libcrypto` shipped under `/usr/lib/` are a
wrapped LibreSSL — they exist for system processes only and Apple
explicitly tells third-party software not to link them. We therefore
require Homebrew OpenSSL 3 on macOS for development and CI.

## Wrapper

The C interop lives in **`src/core/crypto/openssl.zig`**. It is the
*only* file in the repository that names the `c.OpenSSL_*` / `c.SSL_*` /
`c.EVP_*` symbols. Everything else goes through:

* `core.crypto.rsa.signPkcs1v15Sha256` (RSA-PKCS1v15-SHA256 signing for
  ActivityPub HTTP signatures with `algorithm=rsa-sha256`).
* `core.crypto.tls_boring.BoringInboundBackend` (server-side TLS
  handshake; the vtable is `core.tls.TlsBackend`).

Both surfaces are usable without OpenSSL present — they degrade to
returning errors. The only build-time hard requirement is the presence
of `libssl` + `libcrypto` headers and libraries.

## Re-vendor procedure (if/when we move to source vendor)

1. `git clone https://boringssl.googlesource.com/boringssl third_party/boringssl/src`
2. Pin a commit; record in `NOTICE` and at the top of this file.
3. Generate `err_data.c` per upstream's `util/pregenerate/`.
4. Replace the `linkSystemLibrary` calls in `build.zig` with a
   `b.addStaticLibrary` that compiles the `.c` files; set the include
   path to `third_party/boringssl/src/include`.
5. Preserve Apache-2.0 + ISC headers verbatim on every vendored file.
6. Add the full `LICENSE` text from upstream alongside this README.

The `core.crypto.openssl` Zig wrapper does **not** change in a vendor
switch — it's already written against the BoringSSL-compatible C ABI.

## Multi-SNI

The W3.1 inbound backend supports a **single** certificate / key pair
(matching Mastodon defaults). Multi-hostname SNI dispatch is left as
follow-up work; the `SSL_CTX` already loads the cert + key and the
hook for `SSL_CTX_set_tlsext_servername_callback` is documented in
`src/core/tls/boring_inbound.zig`.
