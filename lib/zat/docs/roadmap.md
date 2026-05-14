# roadmap

zat started as a small set of string primitives for AT Protocol - the types everyone reimplements (`Tid`, `Did`, `Handle`, `Nsid`, `Rkey`, `AtUri`). the scope grew based on real usage.

## history

**initial scope** - string primitives with parsing and validation. the philosophy: primitives not frameworks, layered design, zig idioms, minimal scope.

**what grew from usage:**
- DID/handle resolution — real projects needed it, so `DidResolver`, `DidDocument`, `HandleResolver` got added
- XRPC client and JSON helpers — same story
- JWT verification for service auth
- jetstream client — typed JSON event stream with reconnection (0.1.3)
- firehose client — raw CBOR event stream, DAG-CBOR codec, CAR codec, CID creation (0.1.4)
- MST, ECDSA signing, `did:key` construction, multibase encoding (0.1.9)
- full repo verification — end-to-end trust chain from handle to MST root CID match (0.2.0)
- CID hash verification in CAR parser (0.2.1), size limits (0.2.2)

this pattern - start minimal, expand based on real pain - continues.

## now

the library covers the full AT Protocol verification pipeline: identity resolution, repo parsing, signature verification, and MST validation. benchmarked against Go (indigo) and Rust (rsky) in [atproto-bench](https://tangled.sh/@zzstoatzz.io/atproto-bench).

what's missing will show up when people build things. until then, no speculative features.

## maybe later

these stay out of scope unless real demand emerges:

- lexicon codegen - probably a separate project
- higher-level clients/frameworks - too opinionated
- token refresh/session management - app-specific
- feed generator scaffolding - each feed is unique

## non-goals

zat is not trying to be:

- a "one true SDK" that does everything
- an opinionated app framework
- a replacement for understanding the protocol
