# zat publishes its own docs to ATProto

zat uses itself to publish these docs as `site.standard.document` records. here's how.

## the idea

i'm working on [search for leaflet](https://leaflet-search.pages.dev/) and more generally, search for [standard.site](https://standard.site/) records. many are [currently thinking about how to facilitate better idea sharing on atproto right now](https://bsky.app/profile/eugenevinitsky.bsky.social/post/3mbpqpylv3s2e).

this is me doing a rep of shipping a "standard.site", so i know what i'll be searching through, and to better understand why blogging platforms choose their schema extensions etc for i start indexing/searching their record types.

## what we built

a zig script ([`scripts/publish-docs.zig`](https://tangled.sh/zat.dev/zat/tree/main/scripts/publish-docs.zig)) that:

1. authenticates with the PDS via `com.atproto.server.createSession`
2. creates a `site.standard.publication` record
3. publishes each doc as a `site.standard.document` pointing to that publication
4. uses deterministic TIDs so records get the same rkey every time (idempotent updates)

## the mechanics

### TIDs

timestamp identifiers. base32-sortable. we use a fixed base timestamp with incrementing clock_id so each doc gets a stable rkey:

```zig
const pub_tid = zat.Tid.fromTimestamp(1704067200000000, 0);  // publication
const doc_tid = zat.Tid.fromTimestamp(1704067200000000, i + 1);  // docs get 1, 2, 3...
```

### CI

[`.tangled/workflows/publish-docs.yml`](https://tangled.sh/zat.dev/zat/tree/main/.tangled/workflows/publish-docs.yml) triggers on `v*` tags. tag a release, docs publish automatically.

`putRecord` with the same rkey overwrites, so the CI job overwrites `standard.site` records when you cut a tag.