# Multi-tenancy

speedy-socials maps an incoming HTTP `Host` header to a **tenant id**, scopes
storage to that tenant, and can suspend or tombstone tenants at runtime through
admin routes. A single-tenant deployment never configures any of this and runs
exactly as before (the empty tenant id `""` covers every request).

## Host → tenant resolution

Core logic: `src/core/tenancy.zig`.

- The process holds a fixed-size table of up to `max_tenants = 16` tenants
  (`tenancy.zig:22`), each binding a `host` (≤128 bytes) to an `id` (≤32 bytes)
  with a `State` of `active` / `suspended` / `deleted` (`tenancy.zig:26-59`).
- `resolveTenant(host_header)` (`tenancy.zig:149-160`):
  1. If the table is empty, returns `active` (single-tenant default — no
     mapping configured).
  2. Strips an optional `:port` suffix from the Host header.
  3. Looks up the host. On a match it stamps the current tenant
     (`setCurrent`, a thread-local) and returns that tenant's state.
  4. **Unknown host → default tenant, `active`** (no 404 for unknown hosts;
     they fall through to the empty/default tenant).
- `current()` returns the per-request tenant id; plugin/storage code reads it to
  scope queries (`tenancy.zig:139-141`).

### Static mapping at boot

Set the `TENANTS` env var to a comma-separated `host=id` list
(`src/app/main.zig:1030`, parsed by `Table.parseEnv`, `tenancy.zig:102-112`):

```
TENANTS=a.example=tenant-a,b.example=tenant-b
```

### Request dispatch

`src/core/server.zig:435-458` invokes resolution per request:

- Reads the `Host` header, calls `resolveTenant`, and branches on state:
  - `active` → proceed.
  - `suspended` → **503 Service Unavailable** (`server.zig:438-441`).
  - `deleted` → **404 Not Found** (`server.zig:442-445`).
- On `active` it binds storage to the tenant (`storage.setCurrentTenant`,
  `server.zig:448`) and, if a per-vhost registry set is configured, stamps the
  active plugin registry (`server.zig:455-457`).
- The thread-local tenant + registry stamps are cleared at the top and on exit
  of every request so pooled threads never leak one tenant into the next
  (`server.zig:427-434`).

## Tenant lifecycle admin routes

There are **two** route groups, both gated by the same `ADMIN_TOKEN`.

### CRUD-style (`src/core/tenancy_routes.zig`)

Registered at `tenancy_routes.zig:255-259`:

| Method   | Path                   | Body                                  | Success |
|----------|------------------------|---------------------------------------|---------|
| `POST`   | `/admin/tenants`       | `{"id":"<id>","host":"<host>"}`       | 201 |
| `PATCH`  | `/admin/tenants/:id`   | `{"state":"active"\|"suspended"}`     | 200 |
| `DELETE` | `/admin/tenants/:id`   | (none)                                | 200 |

- **POST** registers the tenant in the table *and* calls the storage provider's
  `ensureTenant(id)` to open + migrate its per-tenant DB
  (`tenancy_routes.zig:162-182`). Errors map to: duplicate id → **409**, table
  full → **500**, length out of range → **400**, provider failures → **500**.
- **PATCH** only flips between `active` and `suspended`. Sending
  `{"state":"deleted"}` is rejected with **400** — use DELETE to tombstone
  (`tenancy_routes.zig:209-216`). Unknown tenant → **404**.
- **DELETE** marks the tenant `deleted` (state flip). **The on-disk DB file is
  intentionally left in place** — deletion is not a destructive drop
  (`tenancy_routes.zig:231-251`). Unknown tenant → **404**.
- JSON parsing is a bounded, allocation-free scan; bodies over 1024 bytes →
  **413** (`tenancy_routes.zig:135`, `:104-131`).

### Verb-style transitions (`src/core/tls/admin_routes.zig`)

Registered at `admin_routes.zig:203-209`:

| Method | Path                              |
|--------|-----------------------------------|
| `POST` | `/admin/tenants/:id/suspend`      |
| `POST` | `/admin/tenants/:id/activate`     |
| `POST` | `/admin/tenants/:id/delete`       |

These complement the PATCH/DELETE routes with explicit verbs.

## The `ADMIN_TOKEN` gate

Both route groups use a shared-secret bearer token taken from `ADMIN_TOKEN` at
boot (`src/app/main.zig:1019` wires `admin_routes`, `:1024` wires
`tenancy_routes`). Auth (`tenancy_routes.zig:65-96`):

- Present the token via **`Authorization: Bearer <token>`** *or*
  **`X-Admin-Token: <token>`**.
- Comparison is length-checked then constant-time over the bytes
  (`tenancy_routes.zig:65-71`).
- **An empty/unset `ADMIN_TOKEN` disables the routes entirely** — every request
  returns **401**. There is no implicit "anyone can administer" mode
  (`tenancy_routes.zig:16-18`, `:65`).

Tenant lifecycle mutations are audit-logged when an audit DB is wired
(`tenancy_routes.zig:184-186`, `:222-224`, `:244-246`).

## Per-tenant databases (`ensureTenant`)

`ensureTenant` is defined per provider in `src/core/storage/provider.zig` and
the backend providers:

- **SQLite** (`provider.zig:205-233`): opens `<TENANT_DB_ROOT>/<id>.db`
  (default root `./tenants`, `provider.zig:150`), applies the full schema, and
  registers a per-tenant handle/backend. This is the only backend with real
  per-tenant isolation. Up to `max_tenants = 16` (`provider.zig:40`,
  `:209`). `handleFor(id)` returns the tenant's handle, falling back to the
  default DB for unknown ids (`provider.zig:235-238`).
- **Postgres / MySQL / MSSQL**: `ensureTenant` is a **no-op** — a single shared
  database/connection serves every tenant
  (`postgres_provider.zig:65-70`, `mysql_provider.zig:70-75`,
  `mssql/mssql_provider.zig:87-92`). Per-tenant DBs on these backends are a
  follow-on. With these backends, tenancy still works for *routing/state*
  (suspend/delete), but data is not physically isolated per tenant.

`TENANT_DB_ROOT` (`src/app/main.zig:583`) sets the directory for per-tenant
SQLite files; it is created best-effort at boot.

## Per-vhost plugin registry (H1)

`src/core/plugin.zig:169-258` (`RegistrySet`) isolates plugin *state* per
tenant. The route **table** is shared (every tenant exposes the same paths);
what is isolated is the `Plugin.state` pointers the handlers consult.

- The default tenant (empty id `""`) always resolves to the shared default
  registry (`plugin.zig:177-180`, `:205`).
- `bind(tenant_id, registry)` maps a non-default tenant to its own `Registry`;
  duplicates rejected, empty id rejected, bounded by `max_tenant_registries`
  (`plugin.zig:216-230`).
- `bindAllTenants(table, shared)` is the v1 boot wiring: it binds every known
  tenant to **one shared** registry so the dispatch path stamps a concrete
  non-null active registry per request (the actual per-tenant isolation in v1
  lives in storage routing, not plugin state) (`plugin.zig:232-258`).
- The dispatcher stamps `Plugin.setCurrentRegistry(set.resolve(current()))`
  before handing the request to a plugin and clears it after
  (`server.zig:433-434`, `:455-457`).
