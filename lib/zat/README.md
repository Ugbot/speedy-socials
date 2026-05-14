# [zat](https://zat.dev)

AT Protocol building blocks for zig.

<details>
<summary><strong>this readme is an ATProto record</strong></summary>

> [view in zat.dev's repository](https://at-me.zzstoatzz.io/view?handle=zat.dev)

zat publishes these docs as [`site.standard.document`](https://standard.site) records, signed by its DID.

</details>

## install

```bash
zig fetch --save https://tangled.sh/zat.dev/zat/archive/main
```

then in `build.zig`:

```zig
const zat = b.dependency("zat", .{}).module("zat");
exe.root_module.addImport("zat", zat);
```

## what's here

<details>
<summary><strong>string primitives</strong> - parsing and validation for atproto identifiers</summary>

- **Tid** - timestamp identifiers (base32-sortable)
- **Did** - decentralized identifiers
- **Handle** - domain-based handles
- **Nsid** - namespaced identifiers (lexicon types)
- **Rkey** - record keys
- **AtUri** - `at://` URIs

```zig
const zat = @import("zat");

if (zat.AtUri.parse(uri_string)) |uri| {
    const authority = uri.authority();
    const collection = uri.collection();
    const rkey = uri.rkey();
}
```

</details>

<details>
<summary><strong>identity resolution</strong> - resolve handles and DIDs to documents</summary>

```zig
// handle → DID
var handle_resolver = zat.HandleResolver.init(allocator);
defer handle_resolver.deinit();
const did = try handle_resolver.resolve(zat.Handle.parse("bsky.app").?);
defer allocator.free(did);

// DID → document
var did_resolver = zat.DidResolver.init(allocator);
defer did_resolver.deinit();
var doc = try did_resolver.resolve(zat.Did.parse("did:plc:z72i7hdynmk6r22z27h6tvur").?);
defer doc.deinit();

const pds = doc.pdsEndpoint();       // "https://..."
const key = doc.signingKey();         // verification method
```

supports did:plc (via plc.directory) and did:web. handle resolution via HTTP well-known and DNS TXT.

</details>

<details>
<summary><strong>CBOR codec</strong> - DAG-CBOR encoding and decoding</summary>

```zig
// decode
const decoded = try zat.cbor.decode(allocator, bytes);
defer decoded.deinit();

// navigate values
const text = decoded.value.getStr("text");
const cid = decoded.value.getCid("data");

// encode (deterministic key ordering)
const encoded = try zat.cbor.encodeAlloc(allocator, value);
defer allocator.free(encoded);
```

full DAG-CBOR support: maps, arrays, byte strings, text strings, integers, floats, booleans, null, CID tags (tag 42). deterministic encoding with sorted keys for signature verification.

</details>

<details>
<summary><strong>CAR codec</strong> - Content Addressable aRchive parsing with CID verification</summary>

```zig
// parse with SHA-256 CID verification (default)
const parsed = try zat.car.read(allocator, car_bytes);
defer parsed.deinit();

const root_cid = parsed.roots[0];
for (parsed.blocks.items) |block| {
    // block.cid_raw, block.data
}

// skip verification for trusted local data
const fast = try zat.car.readWithOptions(allocator, car_bytes, .{
    .verify_block_hashes = false,
});
```

enforces size limits (configurable `max_size`, `max_blocks`) matching indigo's production defaults.

</details>

<details>
<summary><strong>MST</strong> - Merkle Search Tree</summary>

```zig
var tree = zat.mst.Mst.init(allocator);
defer tree.deinit();

try tree.put(allocator, "app.bsky.feed.post/abc123", value_cid);
const found = tree.get("app.bsky.feed.post/abc123");
try tree.delete(allocator, "app.bsky.feed.post/abc123");

// compute root CID (serialize → hash → CID)
const root = try tree.rootCid(allocator);
```

the core data structure of an atproto repo. key layer derived from leading zero bits of SHA-256(key), nodes serialized with prefix compression.

</details>

<details>
<summary><strong>crypto</strong> - signing, verification, key encoding</summary>

```zig
// JWT verification
var token = try zat.Jwt.parse(allocator, token_string);
defer token.deinit();
try token.verify(public_key_multibase);

// ECDSA signature verification (P-256 and secp256k1)
try zat.jwt.verifySecp256k1(hash, signature, public_key);
try zat.jwt.verifyP256(hash, signature, public_key);

// multibase/multicodec key parsing
const key_bytes = try zat.multibase.decode(allocator, "zQ3sh...");
defer allocator.free(key_bytes);
const parsed = try zat.multicodec.parsePublicKey(key_bytes);
// parsed.key_type: .secp256k1 or .p256
// parsed.raw: 33-byte compressed public key
```

ES256 (P-256) and ES256K (secp256k1) with low-S normalization. RFC 6979 deterministic signing. `did:key` construction and multibase encoding.

</details>

<details>
<summary><strong>repo verification</strong> - full AT Protocol trust chain</summary>

```zig
const result = try zat.verifyRepo(allocator, "pfrazee.com");
defer result.deinit();

// result.did, result.signing_key, result.pds_endpoint
// result.record_count, result.block_count
// result.commit_verified (signature check passed)
// result.root_cid_match (MST rebuild matches commit)
```

given a handle or DID, resolves identity, fetches the repo, parses every CAR block with SHA-256 verification, verifies the commit signature, walks the MST, and rebuilds the tree to verify the root CID.

</details>

<details>
<summary><strong>firehose client</strong> - raw CBOR event stream from relay</summary>

```zig
var client = zat.FirehoseClient.init(allocator, .{});
defer client.deinit();

try client.connect();
while (try client.next()) |event| {
    switch (event.header.type) {
        .commit => {
            const car_data = try zat.car.read(allocator, event.body.blocks);
            // process blocks...
        },
        else => {},
    }
}
```

connects to `com.atproto.sync.subscribeRepos` via WebSocket. decodes binary CBOR frames into typed events. round-robin host rotation with backoff.

</details>

<details>
<summary><strong>jetstream client</strong> - typed JSON event stream</summary>

```zig
var client = zat.JetstreamClient.init(allocator, .{
    .wanted_collections = &.{"app.bsky.feed.post"},
});
defer client.deinit();

try client.connect();
while (try client.next()) |event| {
    if (event.commit) |commit| {
        const record = commit.record;
        // process...
    }
}
```

connects to jetstream (bluesky's JSON event stream). typed events, automatic reconnection with cursor tracking, round-robin across community relays.

</details>

<details>
<summary><strong>xrpc client</strong> - call AT Protocol endpoints</summary>

```zig
var client = zat.XrpcClient.init(allocator, "https://bsky.social");
defer client.deinit();

const nsid = zat.Nsid.parse("app.bsky.actor.getProfile").?;
var response = try client.query(nsid, params);
defer response.deinit();

if (response.ok()) {
    var json = try response.json();
    defer json.deinit();
    // use json.value
}
```

</details>

<details>
<summary><strong>json helpers</strong> - navigate nested json without verbose if-chains</summary>

```zig
// runtime paths for one-offs:
const uri = zat.json.getString(value, "embed.external.uri");
const count = zat.json.getInt(value, "meta.count");

// comptime extraction for complex structures:
const FeedPost = struct {
    uri: []const u8,
    cid: []const u8,
    record: struct {
        text: []const u8 = "",
    },
};
const post = try zat.json.extractAt(FeedPost, allocator, value, .{"post"});
```

</details>

## benchmarks

zat is benchmarked against Go (indigo), Rust (rsky), and Python (atproto) in [atproto-bench](https://tangled.sh/@zzstoatzz.io/atproto-bench):

- **decode**: 290k frames/sec (zig) vs 39k (rust) vs 15k (go) — with CID hash verification
- **sig-verify**: 15k–19k verifies/sec across all three — ECDSA is table stakes
- **trust chain**: full repo verification in ~300ms compute (zig) vs ~410ms (go) vs ~422ms (rust)

## specs

validation follows [atproto.com/specs](https://atproto.com/specs/atp). passes the [atproto interop test suite](https://github.com/bluesky-social/atproto-interop-tests) (syntax, crypto, MST vectors).

## versioning

pre-1.0 semver:
- `0.x.0` - new features (backwards compatible)
- `0.x.y` - bug fixes

breaking changes bump the minor version and are documented in commit messages.

## license

MIT

---

[devlog](devlog/) · [changelog](CHANGELOG.md)
