# archived: expanded plan (partially implemented)

This file is preserved for context/history. Current direction lives in `docs/roadmap.md`.

# zat - expanded scope

the initial release delivered string primitives (Tid, Did, Handle, Nsid, Rkey, AtUri). this plan expands toward a usable AT Protocol sdk.

## motivation

real-world usage shows repeated implementations of:
- DID resolution (plc.directory lookups, did:web fetches)
- JWT parsing and signature verification
- ECDSA verification (P256, secp256k1)
- base58/base64url decoding
- XRPC calls with manual json navigation

this is shared infrastructure across any atproto app. zat can absorb it incrementally.

## next: did resolution

```zig
pub const DidResolver = struct {
    /// resolve a did to its document
    pub fn resolve(self: *DidResolver, did: Did) !DidDocument

    /// resolve did:plc via plc.directory
    fn resolvePlc(self: *DidResolver, id: []const u8) !DidDocument

    /// resolve did:web via .well-known
    fn resolveWeb(self: *DidResolver, domain: []const u8) !DidDocument
};

pub const DidDocument = struct {
    id: Did,
    also_known_as: [][]const u8,  // handles
    verification_methods: []VerificationMethod,
    services: []Service,

    pub fn pdsEndpoint(self: DidDocument) ?[]const u8
    pub fn handle(self: DidDocument) ?[]const u8
};
```

## next: cid (content identifiers)

```zig
pub const Cid = struct {
    raw: []const u8,

    pub fn parse(s: []const u8) ?Cid
    pub fn version(self: Cid) u8
    pub fn codec(self: Cid) u64
    pub fn hash(self: Cid) []const u8
};
```

## later: xrpc client

```zig
pub const XrpcClient = struct {
    pds: []const u8,
    access_token: ?[]const u8,

    pub fn query(self: *XrpcClient, nsid: Nsid, params: anytype) !JsonValue
    pub fn procedure(self: *XrpcClient, nsid: Nsid, input: anytype) !JsonValue
};
```

## later: jwt verification

```zig
pub const Jwt = struct {
    header: JwtHeader,
    payload: JwtPayload,
    signature: []const u8,

    pub fn parse(token: []const u8) ?Jwt
    pub fn verify(self: Jwt, public_key: PublicKey) bool
};
```

## out of scope

- lexicon codegen (separate project)
- session management / token refresh (app-specific)
- jetstream client (websocket.zig + json is enough)
- application frameworks (too opinionated)

## design principles

1. **layered** - each piece usable independently (use Did without DidResolver)
2. **explicit** - no hidden allocations, pass allocators where needed
3. **borrowing** - parse returns slices into input where possible
4. **fallible** - return errors/optionals, don't panic
5. **protocol-focused** - AT Protocol primitives, not app-specific features

## open questions

- should DidResolver cache? or leave that to caller?
- should XrpcClient handle auth refresh? or just expose tokens?
- how to handle json parsing without imposing a specific json library?
