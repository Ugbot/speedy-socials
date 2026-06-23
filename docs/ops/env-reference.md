# Environment variable reference

Consolidated reference of every operator-facing environment variable found in
the source tree. All are read via `std.c.getenv`. Unless noted, an unset
variable uses the listed default and "boolean" vars accept `1` / `t` / `true`
(some also `yes`). File:line points at where the variable is read.

> Configuration precedence: `CONFIG_PATH` loads a config file **first** so
> existing env-driven boot logic picks up file-supplied values, but a
> pre-existing env var **overrides** the file (the file is the floor)
> (`src/app/main.zig:360-363`).

## Storage

| Var | Values / format | Default | Effect | File:line |
|-----|-----------------|---------|--------|-----------|
| `STORAGE_BACKEND` | `sqlite` \| `postgres` \| `mysql` \| `mssql` | `sqlite` | Selects the primary storage backend. | `app/main.zig:636` |
| `DATABASE_URL` | scheme per backend (see storage-backends.md) | (empty) | Connection URL for postgres/mysql/mssql. Empty → falls back to SQLite. | `app/main.zig:638,652,666` |
| `TENANT_DB_ROOT` | directory path | `./tenants` | Directory for per-tenant SQLite files (`<root>/<id>.db`). | `app/main.zig:583` |
| `ACCOUNT_BACKEND` | `memory` (any other = sqlite) | sqlite | `memory` = EPHEMERAL in-memory accounts (do not survive restart). | `app/main.zig:525` |

## Multi-tenancy / admin

| Var | Values / format | Default | Effect | File:line |
|-----|-----------------|---------|--------|-----------|
| `ADMIN_TOKEN` | shared secret string | (empty) | Bearer token gating `/admin/*` routes. **Empty disables all admin routes (401).** | `app/main.zig:1019,1024` |
| `TENANTS` | `host1=id1,host2=id2` | (empty) | Static Host→tenant mapping loaded at boot. | `app/main.zig:1030` |

## Streaming / queue

| Var | Values / format | Default | Effect | File:line |
|-----|-----------------|---------|--------|-----------|
| `STREAM_BACKEND` | `null` \| `log` \| `redis` \| `nats` \| `kafka` | null sink (no-op) | Event stream sink. Unknown value → null sink + warning. | `app/main.zig:241` |
| `REDIS_URL` | `host:port` | `127.0.0.1:6379` | Redis Streams sink target. | `app/main.zig:259` |
| `NATS_URL` | `nats://host:port` | `nats://127.0.0.1:4222` | NATS sink target. | `app/main.zig:269` |
| `KAFKA_BROKERS` | `host:port[,...]` | `127.0.0.1:9092` | Kafka bootstrap brokers (first is used). | `app/main.zig:280` |
| `QUEUE_BACKEND` | (documented; defaults to durable DbQueue) | DbQueue | Job-queue backend; DbQueue over the writer handle is the default. | `app/main.zig:601-606` |

## Relay / AP↔AT bridge

| Var | Values / format | Default | Effect | File:line |
|-----|-----------------|---------|--------|-----------|
| `RELAY_SYNTHETIC_KEY_PEPPER` | secret string | dev default (warns) | Pepper for synthetic actor keys. Set in production. | `app/main.zig:693` |
| `RELAY_BRIDGE_AP_TARGET` | AP inbox URL | (unset → disabled) | Enables AT→AP delivery; translated records enqueue to this inbox. | `app/main.zig:707` |
| `RELAY_OUTBOX_BACKPRESSURE_CAP` | integer | (unset → disabled) | Pauses translation when outbox pending rows exceed this. | `app/main.zig:718` |
| `RELAY_DOWNSTREAM_ENABLE` | `1` \| `true` \| `yes` | off | Master enable for downstream relay subscription (needs URL too). | `relay/downstream_subscriber.zig:85` |
| `RELAY_DOWNSTREAM_RELAY_URL` | WebSocket URL | (none) | Upstream AT relay firehose URL. Empty forces enable off. | `relay/downstream_subscriber.zig:82` |
| `RELAY_DOWNSTREAM_RELAY_HOST` | hostname | `speedy-socials.local` | Local AP host for synthesising actor IRIs from DIDs. | `relay/downstream_subscriber.zig:91` |

## ActivityPub / AT protocol

| Var | Values / format | Default | Effect | File:line |
|-----|-----------------|---------|--------|-----------|
| `STRICT_HTTP_SIG` | boolean (`1`/`t`/`T`) | off | AP inbox rejects unverified HTTP signatures. | `app/main.zig:788` |
| `AP_OUTBOUND_SIG` | `rfc9421` (else cavage) | cavage | Outbound HTTP-signature scheme. | `app/main.zig:799` |
| `AP_LD_PROOF` | boolean (`1`/`t`/`T`) | off | Enables inbound LD-proof verification. | `activitypub/ld_proof.zig:34` |
| `AT_MST_CACHE` | boolean (`1`/`t`/`T`) | off | Enables the AT repo MST cache. | `atproto/repo.zig:217` |
| `PLC_DIRECTORY` | base URL | `https://plc.directory` | PLC directory base URL. | `atproto/plc_routes.zig:82` |

## TLS / transport

| Var | Values / format | Default | Effect | File:line |
|-----|-----------------|---------|--------|-----------|
| `TLS_CERT_PATH` | file path | (none) | Server TLS certificate. | `app/main.zig:147,1135` |
| `TLS_KEY_PATH` | file path | (none) | Server TLS private key. | `app/main.zig:148,1136` |
| `TLS_SNI_CERTS` | `host=cert.pem:key.pem,...` | (none) | Per-SNI-host certificate map. | `app/main.zig:172` |
| `TLS_OUTBOUND` | `openssl` (else std.crypto.tls) | std tls | Outbound TLS backend selection. | `app/main.zig:826` |
| `TLS_PINS` | per-host pin spec | (none) | Opt-in per-host certificate pinning (only with `TLS_OUTBOUND=openssl`). | `app/main.zig:837` |

## Operations / runtime

| Var | Values / format | Default | Effect | File:line |
|-----|-----------------|---------|--------|-----------|
| `CONFIG_PATH` | file path | (none) | Config file loaded first; env overrides file. | `app/main.zig:363` |
| `SECRETS_DIR` | directory path | (none) | File-backed secrets store directory. | `app/main.zig:548` |
| `MEDIA_ROOT` | directory path | (computed) | Media/blob storage root. | `app/main.zig:967` |
| `BLOB_GC_INTERVAL_SECS` | integer seconds | (unset → no GC worker) | Blob GC worker interval. | `app/main.zig:930` |
| `RATE_LIMIT` | `<capacity>:<refill_per_sec>` (e.g. `60:30`) | (unset → disabled) | Per-IP token-bucket rate limiting. | `app/main.zig:1075` |
| `TRACE_ENABLE` | `1` | off | Enables Chrome-format tracing (only in a `-Dtrace` build); dump via `GET /debug/trace`. | `app/main.zig:1065` |
| `SHUTDOWN_GRACE_MS` | integer ms | `10000` | Soft shutdown grace budget; warns on overrun. | `app/main.zig:1204` |

## Test-only

These gate integration/e2e tests; unset → the test is skipped, so
`zig build test` stays green without external services.

| Var | Used by | File:line |
|-----|---------|-----------|
| `PG_TEST_URL` | Postgres backend + account-zorm tests | `storage/postgres_backend.zig:235`, `account_zorm.zig:397` |
| `MYSQL_TEST_URL` | MySQL backend test | `storage/mysql_backend.zig:263` |
| `MSSQL_TEST_URL` | MSSQL backend test | `storage/mssql/mssql_backend.zig:314` |
| `MASTODON_E2E_URL` | Mastodon round-trip e2e (`error.SkipZigTest` when unset) | `tests/e2e/mastodon_roundtrip.zig:248` |
| `MASTODON_E2E_ACCT` | Target acct for the Mastodon e2e | `tests/e2e/mastodon_roundtrip.zig:259` |
| `MASTODON_E2E_LOCAL_ORIGIN` | Local origin override for the Mastodon e2e (default `https://speedy.local`) | `tests/e2e/mastodon_roundtrip.zig:255` |

## Notes on the operator surface

- There is **no `AP_HOSTNAME`** env var (the task brief mentioned it, but the
  AP/relay host comes from config + `relay.setRelayHost` /
  `RELAY_DOWNSTREAM_RELAY_HOST`, not an `AP_HOSTNAME` env var).
- Failure modes for `STORAGE_BACKEND`/`DATABASE_URL` are **silent fallbacks to
  SQLite** — always confirm the boot log line `storage provider: <backend>`.
