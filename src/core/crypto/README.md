# `core.crypto` — consolidated cryptographic primitives

This directory consolidates every cryptographic primitive speedy-socials
needs into one place. Higher-level protocol modules (ActivityPub, AT
Protocol, OAuth/DPoP) re-export from here so the same wire-compatible
implementation is used everywhere.

## Modules

| File                | What it does                                          |
| ------------------- | ----------------------------------------------------- |
| `ed25519.zig`       | Ed25519 sign / verify / SPKI-PEM I/O.                 |
| `multibase.zig`     | base58btc + base32 codecs (no allocator).             |
| `multicodec.zig`    | multicodec varint table (Ed25519, secp256k1, P-256).  |
| `rsa.zig`           | RSA-PKCS1-v1.5 SHA-256 verify (and parsing helpers).  |
| `secp256k1.zig`     | secp256k1 ECDSA sign / verify with low-S normalisation. |
| `argon2id.zig`      | Argon2id password hashing (PHC-encoded).              |

## Choice of implementation

### RSA: pure-Zig, layered on `std.crypto.Certificate.rsa`

The plan for W1.2 contemplated vendoring BoringSSL for RSA-2048/4096
verify. Zig 0.16's stdlib already ships RSA-{2048,3072,4096} modular
exponentiation through `std.crypto.ff.Modulus`, plus the
PKCS1-v1.5 EMSA encoder, plus a fully-working SPKI DER parser
(`Certificate.rsa.PublicKey.parseDer`). It even handles the
constant-time guards we'd otherwise need to hand-roll. Vendoring
BoringSSL would have added ~140 KLOC of C and a non-trivial CMake or
zig-cc build for a single function call, and would not have been
faster than the stdlib's path on the hot side (federation key verify
is a few hundred operations per second per instance, not millions).

We therefore use the stdlib. `core.crypto.rsa.verifyPkcs1v15Sha256` is
wired into ActivityPub's RSA verify hook at boot.

Signing is not implemented in this module. We mint our own identity as
Ed25519, never as RSA — federation peers may publish RSA keys, but the
local server never does.

### TLS: `std.crypto.tls.Client` (outbound only)

The outbound HTTPS client (`core.http_client`) uses `std.crypto.tls.Client`
plus the system root bundle (`Certificate.Bundle`). Inbound TLS (server
side) is the responsibility of W1.1 (`src/core/server.zig`) and is not
provided here.

### Argon2id, ECDSA (P-256 / secp256k1)

Direct stdlib wrappers. `secp256k1.zig` adds the low-S normalisation
the AT Protocol spec mandates.

## Why not put the algorithms in their protocol modules?

Phase 0–4 originally placed Ed25519 + base58btc in both
`protocols/activitypub/keys.zig` and `protocols/atproto/keypair.zig`.
That duplication invited drift (and almost did, twice). Consolidating
here gives:

- one canonical implementation reviewers can audit,
- one place to update when a CVE drops or stdlib drifts,
- and a clean seam for tests + benchmarks.
