# archived: initial plan (out of date)

This file is preserved for context/history. Current direction lives in `docs/roadmap.md`.

# zat - zig atproto primitives

low-level building blocks for atproto applications in zig. not a full sdk - just the pieces that everyone reimplements.

## philosophy

from studying the wishlists: the pain is real, but the suggested solutions often over-engineer. we want:

1. **primitives, not frameworks** - types and parsers, not http clients or feed scaffolds
2. **layered design** - each piece usable independently
3. **zig idioms** - explicit buffers, comptime validation, no hidden allocations
4. **minimal scope** - solve the repeated pain, not every possible need

## scope

### in scope (v0.1)

**tid** - timestamp identifiers
- parse tid string to timestamp (microseconds)
- generate tid from timestamp
- extract clock id
- comptime validation of format

**at-uri** - `at://did:plc:xyz/collection/rkey`
- parse to components (did, collection, rkey)
- construct from components
- validation

**did** - decentralized identifiers
- parse did:plc and did:web
- validate format
- type-safe wrapper (not just `[]const u8`)

### maybe v0.2

**facets** - extract links/mentions/tags from post records
- given a json value with `text` and `facets`, extract urls
- byte-offset handling for utf-8

**cid** - content identifiers
- parse cid strings
- validate format

### out of scope (for now)

- lexicon codegen (too big, could be its own project)
- xrpc client (std.http.Client is fine)
- session management (app-specific)
- jetstream client (websocket.zig exists, just wire it)
- feed generator framework (each feed is unique)
- did resolution (requires http, out of primitive scope)

## design

### tid.zig

```zig
pub const Tid = struct {
    raw: [13]u8,

    /// parse a tid string. returns null if invalid.
    pub fn parse(s: []const u8) ?Tid

    /// timestamp in microseconds since unix epoch
    pub fn timestamp(self: Tid) u64

    /// clock identifier (lower 10 bits)
    pub fn clockId(self: Tid) u10

    /// generate tid for current time
    pub fn now() Tid

    /// generate tid for specific timestamp
    pub fn fromTimestamp(ts: u64, clock_id: u10) Tid

    /// format to string
    pub fn format(self: Tid, buf: *[13]u8) void
};
```

encoding: base32-sortable (chars `234567abcdefghijklmnopqrstuvwxyz`), 13 chars, first 11 encode 53-bit timestamp, last 2 encode 10-bit clock id.

### at_uri.zig

```zig
pub const AtUri = struct {
    /// the full uri string (borrowed, not owned)
    raw: []const u8,

    /// offsets into raw for each component
    did_end: usize,
    collection_end: usize,

    pub fn parse(s: []const u8) ?AtUri

    pub fn did(self: AtUri) []const u8
    pub fn collection(self: AtUri) []const u8
    pub fn rkey(self: AtUri) []const u8

    /// construct a new uri. caller owns the buffer.
    pub fn format(
        buf: []u8,
        did: []const u8,
        collection: []const u8,
        rkey: []const u8,
    ) ?[]const u8
};
```

### did.zig

```zig
pub const Did = union(enum) {
    plc: [24]u8,  // the identifier after "did:plc:"
    web: []const u8,  // the domain after "did:web:"

    pub fn parse(s: []const u8) ?Did

    /// format to string
    pub fn format(self: Did, buf: []u8) ?[]const u8

    /// check if this is a plc did
    pub fn isPlc(self: Did) bool
};
```

## structure

```
zat/
├── build.zig
├── build.zig.zon
├── src/
│   ├── root.zig           # public API (stable exports)
│   ├── internal.zig       # internal API (experimental)
│   └── internal/
│       ├── tid.zig
│       ├── at_uri.zig
│       └── did.zig
└── docs/
    └── plan.md
```

## internal → public promotion

new features start in `internal` where we can iterate freely. when an API stabilizes:

```zig
// in root.zig, uncomment to promote:
pub const Tid = internal.Tid;
```

users who need bleeding-edge access can always use:

```zig
const zat = @import("zat");
const tid = zat.internal.Tid.parse("...");
```

this pattern exists indefinitely - even after 1.0, new experimental features start in internal.

## decisions

### why not typed lexicons?

codegen from lexicon json is a big project on its own. the core pain (json navigation) can be partially addressed by documenting patterns, and the sdk should work regardless of how people parse json.

### why not an http client wrapper?

zig 0.15's `std.http.Client` with `Io.Writer.Allocating` works well. wrapping it doesn't add much value. the real pain is around auth token refresh and rate limiting - those are better solved at the application level where retry logic is domain-specific.

### why not websocket/jetstream?

websocket.zig already exists and works well. the jetstream protocol is simple json messages. a thin wrapper doesn't justify a dependency.

### borrowing vs owning

for parse operations, we borrow slices into the input rather than allocating. callers who need owned data can dupe. this matches zig's explicit memory style.

## next steps

1. ~~implement tid.zig with tests~~ done
2. ~~implement at_uri.zig with tests~~ done
3. ~~implement did.zig with tests~~ done
4. ~~wire up build.zig as a module~~ done
5. try using it in find-bufo or music-atmosphere-feed to validate the api
6. iterate on internal APIs based on real usage
7. promote stable APIs to root.zig
