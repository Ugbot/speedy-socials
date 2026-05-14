# changelog

## 0.2.17

- **feat**: `Keypair.jwk()`, `Keypair.jwkThumbprint()`, `Keypair.uncompressedPublicKey()` — JWK export and RFC 7638 thumbprints for both P-256 and secp256k1
- **feat**: `oauth` module — stateless PKCE, DPoP proofs, client assertions, form encoding, and related helpers for AT Protocol OAuth flows (based on OAuth 2.1)
- **feat**: `jwt.base64UrlEncode`, `jwt.base64UrlDecode` now public
- **test**: interop tests for did:key derivation and data model fixtures

## 0.2.16

- **fix**: bump websocket.zig to `395d0f4` — reads full HTTP body on TCP split writes (fixes empty body when headers and body arrive in separate TCP segments)

## 0.2.15

- **feat**: `parseDidKey`, `verifyDidKeySignature` — parse `did:key` strings back to key type + raw bytes, verify signatures by `did:key` with automatic curve dispatch
- **feat**: `Keypair` struct — unified abstraction over secp256k1/P-256 for sign, publicKey, did:key formatting
- **feat**: optional `onConnect` callback on `JetstreamClient` — exposes which host the client connected to

## 0.2.14

- **fix**: memory leak in `HttpTransport.fetch()` — `toArrayList()` transferred buffer ownership without freeing; use `written()` instead to keep ownership with the deferred `deinit()`

## 0.2.13

- **docs**: devlog 007 — up and to the right (corrections to 006, sync 1.1 verification, lightrail collection index)

## 0.2.12

- **feat**: configurable `keep_alive` on `HttpTransport` and `DidResolver.initWithOptions` — allows disabling HTTP connection reuse for memory leak investigation

## 0.2.11

- **fix**: enable TCP keepalive on websocket connections — detect dead peers in ~20s instead of blocking forever

## 0.2.10

- **deps**: bump websocket.zig to fork commit `9e6d732` — TCP split guard for HTTP body reads behind reverse proxies

## 0.2.9

- **fix**: SPA fallback routing for standard.site deep links — `_redirects`, `<base href="/">`, devlog short-name aliases
- **fix**: add glibc to nixery deps for wisp-cli patchelf in CI
- **docs**: devlog 006 — building a relay in zig (zlay architecture, deployment war stories, backfill)
- **fix**: publish-docs.zig missing devlog entries 004-006

## 0.2.8

- **feat**: sync 1.1 — `ChildRef` union, `loadFromBlocks`, `putReturn`/`deleteReturn`, `verifyCommitDiff`
- **feat**: `loadCommitFromCAR` returns unsigned commit bytes

## 0.2.7

- **feat**: `Value.getUint()` — extract unsigned integers as `?u64` from CBOR maps. `getInt()` truncates values > `i64` max; upstream AT Protocol firehose seq numbers now exceed this limit.

## 0.2.6

- **feat**: specialized MST decoder — `decodeMstNode()` parses known MST CBOR schema directly, zero-copy byte slicing, avoids generic `Value` union construction
- **feat**: in-walk MST structure verification — `walkAndVerifyMst` checks key heights during traversal instead of full tree rebuild. MST step: 218ms → 39ms (5.5x), compute total: 300ms → 123ms (2.4x)
- **docs**: devlog 005 — updated benchmark numbers and chart

## 0.2.5

- **feat**: O(1) block lookup in CAR parser — `StringHashMap` index built during `read()`/`readWithOptions()`, `findBlock()` uses index instead of linear scan
- **fix**: `verifyRepo` bypasses default 2 MB / 10k block limits so large repos (e.g. pfrazee.com at 70 MB / 243k blocks) actually work
- **docs**: devlog 005 — clarify Rust ecosystem (rsky, jacquard, hand-rolled RustCrypto)

## 0.2.4

- **feat**: configurable CAR size limits — `max_size` and `max_blocks` options in `readWithOptions` for large repo verification
- **feat**: export `jwt` module (not just `Jwt` type) for direct access to `verifySecp256k1`/`verifyP256`
- **docs**: devlog 005 — three-way trust chain verification (zig vs Go vs Rust)
- **docs**: README rewrite — added CBOR, CAR, MST, firehose, jetstream, signing, repo verification

## 0.2.3

- **docs**: devlog 004 — the sig-verify saga (k256 5×52-bit field, Fermat scalar inversion, three-way bench with rsky)
- changelog backfill for 0.2.1 and 0.2.2

## 0.2.2

- **feat**: CAR parser enforces size limits — 2MB max on blocks field, max block count. matches indigo's limits for production parity.

## 0.2.1

- **feat**: CID hash verification in CAR parser — `car.read()` SHA-256 hashes each block and compares against the CID digest. proves block content wasn't corrupted or tampered with. `readWithOptions(.{ .verify_block_hashes = false })` to skip for trusted local data.
- **fix**: remove pfrazee.com from default test suite (network-dependent)

## 0.2.0

- **feat**: end-to-end repo verification — `verifyRepo(allocator, identifier)` exercises the full AT Protocol trust chain: handle → DID → DID document → signing key → fetch repo CAR → verify commit signature → walk MST → rebuild tree → CID match
- **refactor**: organize `src/internal/` into domain subdirectories following the [TypeScript SDK](https://github.com/bluesky-social/atproto/tree/main/packages): `syntax/`, `crypto/`, `identity/`, `repo/`, `xrpc/`, `streaming/`, `testing/`

## 0.1.9

- **feat**: merkle search tree (MST) — `mst.Mst` with `put`, `get`, `delete`, `rootCid`
- **feat**: ECDSA signing — `signSecp256k1`, `signP256` with low-S normalization (RFC 6979)
- **feat**: `did:key` construction — `multicodec.formatDidKey`, `multicodec.encodePublicKey`
- **feat**: multibase encoding — base58btc encode, base32lower encode/decode
- interop tests: MST common prefix (13 vectors), commit proofs (6 fixtures)

## 0.1.8

- **fix**: NSID parser rejects TLD starting with digit (e.g. `1.0.0.127.record`)
- **fix**: AT-URI parser validates authority (DID/handle), collection (NSID), and rkey components; rejects `#`, `?`, spaces
- **fix**: reject high-S ECDSA signatures — atproto requires low-S normalization (BIP-62 style)
- `verifySecp256k1` and `verifyP256` are now `pub`
- atproto interop test suite: syntax validation (6 types), crypto signature verification (6 vectors), MST key heights (9 vectors)

## 0.1.7

- slim `Cid` struct from 56 to 16 bytes — store only raw bytes, parse version/codec/digest lazily on demand
- `Value` union shrinks from 64 to 24 bytes, `MapEntry` from 80 to 40 bytes
- zero-cost CID decode — tag 42 handler stores a byte slice reference instead of parsing varint fields
- inline map key reading in CBOR decoder — skips full `decodeAt` + union construction per key
- comptime size assertions for `Value` and `MapEntry`
- **breaking**: `Cid` fields (`version`, `codec`, `hash_fn`, `digest`) are now accessor methods returning optionals — e.g. `cid.version` → `cid.version().?`
- `parseCid` simplified to a trivial raw-bytes wrapper

## 0.1.6

- round-robin host rotation for jetstream and firehose clients
- `Options.host` → `Options.hosts` with sensible defaults (bsky + community relays)
- backoff resets on host switch, jetstream rewinds cursor by 10s
- default jetstream hosts: 4 official bsky, waow.tech, fire.hose.cam, 6 firehose.stream regions
- default firehose hosts: bsky.network + 3 firehose.network regions

## 0.1.5

- align firehose event types with AT Protocol sync spec

## 0.1.4

- firehose support: DAG-CBOR codec, CAR codec, CID creation, firehose client
- encode and decode `com.atproto.sync.subscribeRepos` binary frames

## 0.1.3

- jetstream WebSocket client with typed events, reconnection, and cursor tracking
- `extractAt` ignores unknown JSON fields by default
- HTTP I/O isolated behind `HttpTransport` for 0.16 prep
- websocket dependency pinned to specific commit

## 0.1.2

- `extractAt` logs diagnostic info on parse failures (enable with `.zat` debug scope)

## 0.1.1

- xrpc client sets `Content-Type: application/json` for POST requests
- docs published as `site.standard.document` records on tag releases

## 0.1.0

sync types for firehose consumption:

- `CommitAction` - `.create`, `.update`, `.delete`
- `EventKind` - `.commit`, `.sync`, `.identity`, `.account`, `.info`
- `AccountStatus` - `.takendown`, `.suspended`, `.deleted`, `.deactivated`, `.desynchronized`, `.throttled`

these integrate with `std.json` for automatic parsing.

## 0.0.2

- xrpc client with gzip workaround for zig 0.15.x deflate bug
- jwt parsing and verification

## 0.0.1

- string primitives (Tid, Did, Handle, Nsid, Rkey, AtUri)
- did/handle resolution
- json helpers
