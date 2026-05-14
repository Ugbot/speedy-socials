# verifying the trust chain

since the last devlog (firehose benchmarks), zat picked up a bunch of correctness work — interop test suites, signature fixes, a full MST implementation — and now ties it all together: given a handle, verify everything about a repo from scratch.

## what happened since last time

### correctness first (0.1.8)

we joined the [atproto interop test suite](https://github.com/bluesky-social/atproto-interop-tests). this is bluesky's official cross-implementation test vectors — the same fixtures that the TypeScript SDK, Go SDK, and others validate against. zat now passes all of them:

- **syntax**: 6 types (TID, DID, Handle, NSID, RecordKey, AT-URI), valid + invalid vectors
- **crypto**: 6 signature verification vectors (P-256 and secp256k1)
- **MST**: 9 key height vectors, 13 common prefix vectors, 6 commit proof fixtures

this also surfaced two bugs:
- NSID parser wasn't rejecting TLDs starting with a digit (`1.0.0.127.record` should fail)
- AT-URI parser wasn't validating its components (authority, collection, rkey) — it was just splitting on `/`

and a spec compliance issue: ECDSA signature verification wasn't rejecting high-S values. atproto requires low-S normalization (BIP-62 style), and we were accepting both. fixed with explicit half-order checks in `verifyP256` and `verifySecp256k1`.

### MST and crypto signing (0.1.9)

the merkle search tree is the core data structure of an atproto repo. each key's tree layer is derived from the leading zero bits of SHA-256(key), and nodes are serialized with prefix compression. `mst.Mst` supports `put`, `get`, `delete`, and `rootCid` (serialize → hash → CID).

alongside that: ECDSA signing (`signSecp256k1`, `signP256` with RFC 6979 deterministic nonces), `did:key` construction, and multibase encoding. these round out the crypto layer — zat can now both sign and verify.

### code organization (0.2.0)

22 files in a flat `src/internal/` was getting unwieldy. we reorganized into domain subdirectories following bluesky's own boundaries (from the [TypeScript SDK](https://github.com/bluesky-social/atproto/tree/main/packages)):

```
internal/
  syntax/     — tid, did, handle, nsid, rkey, at_uri
  crypto/     — jwt, multibase, multicodec
  identity/   — did_document, did_resolver, handle_resolver
  repo/       — cbor, car, mst, repo_verifier
  xrpc/       — transport, xrpc, json
  streaming/  — firehose, jetstream, sync
  testing/    — interop_tests
```

the groupings aren't arbitrary. the TypeScript SDK has `syntax`, `crypto`, `identity`, `repo`, and `xrpc` as distinct packages — `syntax` is pure parsing with zero deps, `identity` handles network resolution, `crypto` is P-256 + K-256, and `repo` contains the MST, CAR, and CBOR together (CBOR isn't a standalone package — it lives with the types that need it).

## the repo verifier

`verifyRepo(allocator, "pfrazee.com")` exercises the entire trust chain in one call:

```
handle → DID → DID document → signing key
                                    ↓
repo CAR → commit → signature ← verified against key
                ↓
         MST root CID → walk nodes → rebuild tree → CID match
```

the pipeline:

1. **resolve handle** — HTTP well-known or DNS TXT → DID string
2. **resolve DID** — did:plc via plc.directory, did:web via .well-known/did.json → DID document
3. **extract signing key** — find the `#atproto` verification method, multibase decode, multicodec parse → key type + raw bytes
4. **extract PDS endpoint** — find the `#atproto_pds` service
5. **fetch repo** — HTTP GET `{pds}/xrpc/com.atproto.sync.getRepo?did={did}` → raw CAR bytes
6. **parse CAR** — extract roots and blocks
7. **find + decode commit** — the root block is the signed commit (DAG-CBOR map with `did`, `version`, `rev`, `data`, `sig`)
8. **verify signature** — strip `sig` from the commit map, re-encode to DAG-CBOR (deterministic key ordering), verify with the signing key
9. **walk MST** — starting from the commit's `data` CID, recursively decode MST nodes with prefix decompression, collect all (key, value_cid) pairs
10. **rebuild MST** — insert every record into a fresh `mst.Mst`, compute root CID, compare against the commit's `data` CID

if any step fails, you know exactly where the trust chain breaks.

### what this exercises

every major module in zat participates:

| step | modules used |
|------|-------------|
| handle resolution | `HandleResolver`, `Handle` |
| DID resolution | `DidResolver`, `Did`, `DidDocument` |
| key extraction | `multibase`, `multicodec` |
| HTTP fetch | `HttpTransport` |
| repo parsing | `car`, `cbor` |
| signature verification | `jwt.verifyP256` / `jwt.verifySecp256k1` |
| MST walk + rebuild | `mst.Mst`, `cbor.Value` |

it's the first feature that crosses all the domain boundaries — identity, crypto, repo, and network all working together.

### the integration tests

two accounts, two PDS backends:

- **zzstoatzz.io** — self-hosted PDS (`pds.zzstoatzz.io`), ~12k records. verifies the self-hosting path works.
- **pfrazee.com** — bluesky CTO, hosted on `bsky.network`, ~192k records. verifies against the canonical infrastructure.

both use the graceful-catch pattern: if the network isn't available (CI, offline), the test prints a message and passes. when the network is there, it runs the full chain and asserts on the DID and record count.

## what's next

this is the first "full pipeline" feature — it validates that the primitives compose correctly end to end. from here, the natural next steps are incremental: repo diffing (compare two commits), record-level verification (check a specific record's inclusion proof), or sync protocol support.

but following the pattern: we ship when something real needs it, not before.
