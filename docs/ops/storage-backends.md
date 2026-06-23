# Storage backends

speedy-socials selects its primary storage backend at boot from the
`STORAGE_BACKEND` environment variable. SQLite is the default and the only
fully-migrated backend; Postgres, MySQL, and MSSQL are pure-Zig drivers wired
through the same `DbProvider`/`Backend` seam.

## Selection

The boot block lives in `src/app/main.zig:635-682`.

```
STORAGE_BACKEND = sqlite | postgres | mysql | mssql        (default: sqlite)
DATABASE_URL    = <connection URL>   (required for postgres/mysql/mssql)
```

- `STORAGE_BACKEND` unset or any unrecognised value → **sqlite**
  (`src/app/main.zig:636`, `:679-681`).
- For `postgres` / `mysql` / `mssql`, if `DATABASE_URL` is **empty or unset**,
  the boot logs a warning and **silently falls back to SQLite**
  (`src/app/main.zig:640`, `:654`, `:668`). There is no hard failure — check
  the boot log line `storage provider: <backend>` to confirm what is actually
  in use.
- If the connection attempt fails, boot logs `<backend> connect failed — using
  sqlite` and continues on SQLite (`src/app/main.zig:646-650`, `:660-664`,
  `:674-678`).

The SQLite provider is always installed first as the default; the selected
non-SQLite provider then *overrides* the global provider and `Backend`
(`src/app/main.zig:593-682`).

## DATABASE_URL formats

All three networked drivers parse the URL with Zig's `std.Uri`. Exact accepted
schemes:

| Backend  | URL scheme / shape                                  | Default port | Parser |
|----------|-----------------------------------------------------|--------------|--------|
| sqlite   | (no URL — file path, see below)                     | n/a          | — |
| postgres | `postgresql://user:pass@host:port/db`               | (driver)     | `PostgresProvider.init` `src/core/storage/postgres_provider.zig:34-39` |
| mysql    | `mysql://user:pass@host:port/db`                    | 3306         | `parseMysqlUrl` `src/core/storage/mysql_backend.zig:268-293` |
| mssql    | `mssql://user:pass@host:port/db`                    | 1433         | `parseUri` `src/core/storage/mssql/mssql_provider.zig:112-141` |

Notes on parsing:
- **MySQL**: host/port/user/password/db all optional; missing port defaults to
  `3306`, missing db → empty (`mysql_backend.zig:295-307`).
- **MSSQL**: `host`, `user`, and `password` are **required** — a URL missing any
  of them returns null and the backend falls back to SQLite. `mssql://host:1433/db`
  (no credentials) is rejected (`mssql_provider.zig:114-141`, `:165`). Missing
  port defaults to `1433`.
- **Postgres**: the URL is handed straight to `pg.Pool.initUri` (pool size 8,
  5000 ms timeout — `postgres_provider.zig:37`). It accepts the libpq-style
  `postgresql://…` URI.

### SQLite

SQLite does not use `DATABASE_URL`. The primary DB path is the configured
DB path (writer handle, opened in `src/app/main.zig`). Per-tenant SQLite files
live under `TENANT_DB_ROOT` (default `./tenants`, `src/app/main.zig:583`).

## Per-backend status and caveats

| Backend  | Migrations applied by provider | Per-tenant DBs | TLS | Notes |
|----------|-------------------------------|----------------|-----|-------|
| sqlite   | **Yes** (full schema)          | **Yes** (`<root>/<id>.db`) | n/a | Default, fully supported. |
| postgres | **No** — `migrate` is a no-op  | No (single shared DB) | via pg.zig | Provision the PG schema out-of-band. |
| mysql    | (driver runs query sites)      | No (single shared DB) | **No TLS** | `mysql_native_password` only. |
| mssql    | (driver runs query sites)      | No (single shared DB) | — | **Live-pending** (pure-Zig TDS, not fully live). |

### Postgres — migrations are deferred

`PostgresProvider.doMigrate` is intentionally a **no-op**
(`src/core/storage/postgres_provider.zig:57-63`). The registered migrations are
SQLite-dialect. Operators must provision the Postgres schema out-of-band for
now; the provider still wires the pure-Zig pg `Backend` so dialect-neutral query
sites run against Postgres. `ensureTenant` is also a no-op — a single shared
database serves all tenants (`postgres_provider.zig:65-70`).

### MySQL — auth and TLS

The pure-Zig MySQL wire driver implements **only `mysql_native_password`**.
A server offering `caching_sha2_password` (the MySQL 8 default) or any other
auth plugin returns `error.UnsupportedAuth` and boot falls back to SQLite
(`src/core/storage/mysql/conn.zig:129-134`). An empty plugin name (very old
servers) is treated as native-password.

- **caching_sha2_password: not supported.** Configure the MySQL user with
  `ALTER USER … IDENTIFIED WITH mysql_native_password BY '…'` (or set
  `default_authentication_plugin=mysql_native_password`).
- **TLS: not implemented** — the connection is plaintext over the socket
  (`src/core/storage/mysql/conn.zig`). Do not send credentials over an
  untrusted network; tunnel or co-locate.
- Per-tenant MySQL databases are a follow-on; `ensureTenant` is a no-op
  (`src/core/storage/mysql_provider.zig:70-75`).

### MSSQL — live-pending

The MSSQL provider speaks a pure-Zig TDS dialect. Boot logs it as
`storage provider: mssql (pure-Zig TDS; live-pending)`
(`src/app/main.zig:673`). Treat MSSQL as **experimental / not fully live** for
production traffic. `ensureTenant` is a no-op (single shared connection,
`src/core/storage/mssql/mssql_provider.zig:87-92`).

## Test-only DB URLs

The backend integration tests connect only when their env var is set; they skip
otherwise (so `zig build test` is green without a live DB):

| Env var          | Used by | File:line |
|------------------|---------|-----------|
| `PG_TEST_URL`    | Postgres backend / account zorm tests | `src/core/storage/postgres_backend.zig:235`, `src/core/account_zorm.zig:397` |
| `MYSQL_TEST_URL` | MySQL backend test  | `src/core/storage/mysql_backend.zig:263` |
| `MSSQL_TEST_URL` | MSSQL backend test  | `src/core/storage/mssql/mssql_backend.zig:314` |
| `MASTODON_E2E_URL` | Mastodon end-to-end federation test | (e2e harness) |

All use the same URL shapes as `DATABASE_URL` for the matching backend.
