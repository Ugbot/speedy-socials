# ADR-001: Ed25519 for ActivityPub HTTP Signatures

## Status

Accepted

## Date

2026-03-19

## Context

ActivityPub federation requires HTTP Signatures (draft-cavage-http-signatures-12) for authenticating server-to-server requests. The traditional algorithm is RSA-SHA256 with 2048+ bit keys.

speedy-socials is written in Zig 0.15. The Zig standard library provides:
- Ed25519 (`std.crypto.sign.Ed25519`) — full signing and verification
- ECDSA P-256 and secp256k1 (`std.crypto.ecdsa`) — full signing and verification
- SHA-256, HMAC-SHA256 — available
- **No RSA support** — not in std, no vendored implementation

We need to choose a signing algorithm for HTTP Signatures that works within Zig's crypto capabilities while maintaining interoperability with the fediverse.

## Decision

Use **Ed25519** for HTTP Signatures with the algorithm identifier `hs2019`.

### Why Ed25519

1. **Available natively in Zig 0.15** — `std.crypto.sign.Ed25519` provides key generation, signing, and verification. Already used in our AT Protocol commit signing (`lib/atproto/src/commit.zig`).

2. **Growing fediverse adoption** — Ed25519 HTTP Signatures are supported by:
   - Mastodon 4.3+ (released 2024)
   - GoToSocial
   - Misskey / Sharkey / Firefish
   - Pleroma / Akkoma
   - Hubzilla

3. **Performance** — Ed25519 signing is ~50x faster than RSA-2048 and verification is ~5x faster. Signatures are 64 bytes vs 256 bytes for RSA-2048.

4. **Security** — Ed25519 provides 128-bit security with 32-byte keys, equivalent to RSA-3072. No padding oracle attacks. Deterministic signing eliminates nonce-reuse vulnerabilities.

5. **Simplicity** — Key generation produces 32-byte seed + 32-byte public key. PEM encoding uses a fixed 12-byte ASN.1 SPKI prefix (`302a300506032b6570032100`) — no ASN.1 library needed.

### Why `hs2019` algorithm identifier

The `hs2019` value comes from the HTTP Signatures specification update (draft-ietf-httpbis-message-signatures). It means "determine the algorithm from the key type referenced by keyId." This is the recommended identifier for new implementations because:
- It decouples the signature header from the algorithm, allowing key rotation without changing the signature format
- Mastodon 4.3+ recognizes it and determines Ed25519 from the key type
- It avoids the non-standard `ed25519` algorithm string that some servers may reject

### PEM Format

Ed25519 public keys are served in SubjectPublicKeyInfo (SPKI) PEM format, which is the standard format for the `publicKeyPem` field in ActivityPub actor documents:

```
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA<base64-encoded-32-byte-public-key>
-----END PUBLIC KEY-----
```

The DER encoding is always exactly 44 bytes: 12-byte OID header + 32-byte key.

## Consequences

### Positive
- Zero external crypto dependencies — pure Zig implementation
- Fast key generation and signing for high-throughput federation
- Consistent with AT Protocol's crypto approach (also Ed25519-based)
- Small key/signature sizes reduce storage and bandwidth

### Negative
- **Incompatible with RSA-only servers** — servers that only support `rsa-sha256` HTTP Signatures will not be able to verify our requests. This primarily affects very old or unmaintained ActivityPub implementations. All major actively-maintained implementations support Ed25519.
- **No fallback** — without RSA support in Zig std, we cannot offer RSA as a fallback. If RSA compatibility becomes critical in the future, options include:
  - Vendoring a C RSA library (e.g., BearSSL, libsodium)
  - Waiting for Zig std to add RSA
  - Using a Zig RSA implementation if one becomes available

### Mitigation for RSA-only servers
- Log when signature verification fails due to algorithm mismatch
- Document the Ed25519 requirement in instance NodeInfo
- Monitor fediverse compatibility and add RSA if needed

## References

- [HTTP Signatures (draft-cavage-12)](https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12)
- [HTTP Message Signatures (RFC 9421)](https://www.rfc-editor.org/rfc/rfc9421)
- [Mastodon HTTP Signatures](https://docs.joinmastodon.org/spec/security/)
- [Ed25519 (RFC 8032)](https://www.rfc-editor.org/rfc/rfc8032)
- [Zig std.crypto.sign.Ed25519](https://ziglang.org/documentation/0.15.0/std/crypto/sign/Ed25519.html)
