# three-way trust chain verification

the previous devlogs covered decode throughput and signature verification as isolated benchmarks. this one puts it all together: given a handle, resolve identity, fetch the full repo, and cryptographically verify everything — zig vs Go vs Rust.

## what we're measuring

the full AT Protocol trust chain:

```
handle → DID → DID document → signing key
                                    ↓
repo CAR → commit → signature ← verified against key
                ↓
         MST root CID → walk nodes → verify key heights → structure proven
```

all three implementations do the same work: resolve the handle, resolve the DID, extract the signing key, fetch the repo CAR, parse every block with SHA-256 CID verification, verify the commit signature, and walk the MST to count records and verify structure.

## the implementations

**zig (zat)** — uses zat's own primitives end to end: `HandleResolver`, `DidResolver`, `car.read()` with CID verification + O(1) block index, `jwt.verifySecp256k1`, specialized `decodeMstNode` for walk + in-walk key height verification.

**go (indigo)** — uses bluesky's official Go SDK: `identity.BaseDirectory` for handle/DID resolution, `repo.LoadRepoFromCAR` for parsing, `commit.VerifySignature` for sig verify, `MST.Walk()` + `MST.RootCID()` for MST.

**rust ([rsky](https://github.com/blacksky-algorithms/rsky) stack)** — uses the same low-level crates that [rsky](https://github.com/blacksky-algorithms/rsky) (Rudy Fraser / BlackSky) uses internally: k256/p256 for ECDSA, serde_ipld_dagcbor for CBOR, sha2 for hashing. rsky is a full AT Protocol implementation in Rust (PDS, relay, feed generator, labeler) plus library crates (rsky-repo, rsky-crypto, rsky-identity). [jacquard](https://tangled.sh/@nonbinary.computer/jacquard) (@nonbinary.computer) also has MST/CAR/identity support. the end-to-end verify pipeline here is assembled manually from the low-level crates — no equivalent of indigo's all-in-one `LoadRepoFromCAR` exists yet. skips MST rebuild (no crate for it in either rsky or jacquard yet).

## the O(n) bug

first run against pfrazee.com (192k records, 243k blocks): zig's MST walk took **79 seconds**. go finished in 6ms.

the cause: `findBlock()` was doing a linear scan through 243k blocks on every lookup. MST walk calls `findBlock()` once per node (~50k nodes). that's ~12 billion comparisons.

Go's `TinyBlockstore` uses a `map[string]blocks.Block` — O(1) by CID key. replaced the flat block slice with `std.StringHashMapUnmanaged([]const u8)` in zig and `HashMap<Vec<u8>, Vec<u8>>` in rust.

result: 79s → 48ms (zig), 14s → 125ms (rust).

## results

_pfrazee.com — 192,161 records, 243,491 blocks, 70.6 MB CAR, macOS arm64 (M3 Max)_

<img src="https://tangled.org/zat.dev/zat/raw/main/devlog/img/verify-compute.svg" alt="trust chain compute breakdown" width="790">

| SDK | CAR parse | sig verify | MST walk+verify | compute total |
|-----|----------:|----------:|----------------:|-------------:|
| zig (zat) | 82.8ms | 0.6ms | 39.3ms | **122.7ms** |
| rust (rsky stack) | 301.0ms | 0.2ms | 120.9ms | **422.1ms** |
| go (indigo) | 424.7ms | 0.2ms | 9.3ms | **434.2ms** |

network time (handle + DID resolution + repo fetch) dominates total wall clock — 8-20 seconds depending on PDS response time. compute is under 500ms for all three.

zig's compute total is 3.5x faster than Go and 3.4x faster than Rust. the gap comes from two places: CAR parsing (zig's inline varint + SHA-256 pipeline vs Go's reflection-heavy CBOR and Rust's serde overhead), and MST verification (specialized decoder + in-walk key height checks vs Go's cached-struct walk).

go's MST walk is still fastest in isolation (9.3ms vs zig's 39.3ms) because indigo's MST nodes are decoded from CBOR once on first access and cached as Go structs — subsequent traversal is pure pointer chasing. but zig's specialized `decodeMstNode` is much closer than the old generic CBOR approach was (previously 45.5ms walk + 172.6ms rebuild = 218ms). the key insight: a full MST rebuild is unnecessary when you can verify each key's tree layer is deterministically correct during the walk — combined with CAR block CID verification (which proves data integrity), this is equivalent.

## what changed in zat

**O(1) block lookup** — CAR blocks are now indexed in a `StringHashMap` during parse. the old `findBlock()` was a linear scan through 243k blocks; MST walk calls it once per node (~50k nodes). this was the 79s → 48ms fix.

**specialized MST decoder** — `decodeMstNode()` parses the known MST node CBOR schema directly (`map(2) { "e": array[...], "l": CID|null }`), avoiding the generic `cbor.decodeAll()` path that builds `Value` unions and `MapEntry` arrays. all byte data is zero-copy (slices into the input buffer). only allocation: the entries array.

**in-walk structure verification** — instead of collecting all records and rebuilding the tree from scratch (192k `tree.put()` calls + serialize + hash), `walkAndVerifyMst` checks each key's `keyHeight()` against the node's expected layer during traversal. combined with the CAR parser's per-block SHA-256 CID verification (which proves data integrity), this is equivalent to a full rebuild for proving canonical structure. result: MST walk+rebuild went from 218ms → 39ms (5.5x).

**size limit fix** — `verifyRepo` now bypasses the default 2 MB / 10k block limits so large repos like pfrazee's 70 MB actually work.

the three-way comparison and chart tooling live in [atproto-bench](https://tangled.sh/@zzstoatzz.io/atproto-bench).
