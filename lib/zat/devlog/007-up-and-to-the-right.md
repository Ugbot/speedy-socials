# up and to the right

the last devlog said "2 MB is generous" for thread stacks and "per-thread RSS is modest (~1-2 MiB when active)." both claims survived about 48 hours. this is the correction.

## corrections

[zlay](https://tangled.org/zzstoatzz.io/zlay) went from first commit to production in ~5 days. 46 commits in the relay, 42 in the deploy repo, 9 in zat. the previous devlog was written midway through that, and it shows. some things we got wrong:

**"2 MB is generous."** production value is 8 MB. ReleaseSafe's inlining flattens TLS handshake + CBOR + crypto call chains into stack frames that touch far more memory pages than you'd expect. `tls.Client.init` alone is ~134 KiB. 2 MB overflowed. 4 MB overflowed. 8 MB holds.

**"per-thread RSS is modest (~1-2 MiB when active)."** measured: 3.9 MiB per thread in ReleaseSafe, vs 0.4 MiB in debug. a 10x delta from a compiler flag. 2,750 threads × 3.9 MiB = ~10.7 GiB theoretical. the relay OOM-killed at 3 GiB after spawning only 875 threads.

**"2,750 threads is fine."** the architecture had to be redesigned. the per-PDS thread no longer decodes, validates, or broadcasts — it reads a websocket and queues raw bytes. a shared pool of 16 workers handles the heavy work. this is, functionally, a manual version of what goroutines give you for free.

**"~2.9 GiB (~2,750 hosts)."** current RSS is ~1.1 GiB at ~2,255 hosts — but only because the thread pool cut per-reader RSS from 3.9 MiB to ~0.45 MiB. the 2.9 GiB number was for an architecture that no longer exists.

the incident report (in zlay's docs/) is worth reading. the most honest line: "presented theories as facts — claimed ReleaseSafe stack inflation was understood and 8 MiB fixed it, when it didn't."

## what actually happened

the ReleaseSafe build produces correct code (no double-free, unlike ReleaseFast) but inlines aggressively. deep call chains — TLS cipher dispatch, CBOR map decode, ECDSA verify — flatten into frames that touch stack pages the debug build never reaches. more touched pages = more RSS per thread. RSS graph goes up and to the right. this is not the good kind.

the fix was architectural, not tuning. reader threads (one per PDS) now do only: websocket read, CBOR header peek, cursor track, submit to pool. the 16-worker pool handles: full CBOR decode, DID lookup, ECDSA verify, postgres persist, broadcast. reader RSS dropped from 3.9 MiB to ~0.45 MiB. the pool threads are large but there are only 16 of them.

## sync 1.1 verification

with the relay stable, the next step was wiring the inductive proof chain — the spec's mechanism for verifying that a commit's operations actually explain its state transition.

zat has had the primitives since v0.2.8: `verifyCommitDiff` inverts each operation on the new partial MST and checks whether the result matches the previous commit's root CID. if it does, the diff is proven. each commit chains to the last — inductive.

zlay wires this in observation mode. chain continuity checks (incoming `since` vs stored `rev`, incoming `prevData` vs stored MST root CID) run on every commit and increment a prometheus counter on mismatch, but don't drop the frame. `verifyCommitDiff` itself is behind a config flag. the path: observe, measure, then enforce.

the first integration attempt failed silently — `extractOps` was reading wrong field names from the CBOR payload (`collection`+`rkey` instead of `path`). the operations array arrived empty, and verification with zero ops trivially passed. a documentation problem at the firehose/MST boundary, not an SDK problem.

the function we thought the SDK was missing — `loadCommitFromCAR`, for parsing commit metadata without full verification — turned out to already be public since v0.2.8. the relay uses it on every validator cache miss: parse the commit to get the DID, queue key resolution, verify later. parsing separable from validation. the decomposition was already right.

## lightrail and the collection index

fig's [lightrail](https://tangled.org/microcosm.blue/lightrail) implements `listReposByCollection` by inspecting CAR blocks to detect collection membership changes — a deeper use of the partial MST than pure verification. it reads adjacent keys in the CAR slice to determine when the first record appears in (or last disappears from) a collection.

zlay's collection index drew on this design: dual RocksDB column families (`rbc` for the query, `cbr` for per-DID deletion), inline indexing from the firehose, no sidecar. where they diverge: zlay currently tracks at the operation level (any `create` op → index that DID+collection), while lightrail aims for MST adjacency analysis. accurate removal — knowing when the last record is gone — is deferred.

backfill: collectiondir calls `describeRepo` on every account (O(N) calls, N ≈ 30M+). zlay calls `listReposByCollection` on an upstream relay that already has the data. 1,287 collections, 61M DIDs.

## what this means for zat

~90 commits across 3 repos in 5 days. the SDK's module composition held — CBOR → CAR → commit parsing → verification → multibase all chain correctly. the API surface held — `loadCommitFromCAR` was already right, `verifyCommitDiff` works as designed, nothing needed to be added.

the friction was at the boundary between the firehose wire format and the MST internal types, and it cost exactly one bug. we considered adding bridging functions but decided against it: for a pre-1.0 library, no is temporary.
