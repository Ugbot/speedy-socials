# Operator / deployment docs

Operator-facing documentation for speedy-socials. All facts are derived from
the source (file:line citations throughout); confirm the boot log at startup,
which prints the resolved storage/stream backends.

- [storage-backends.md](storage-backends.md) — `STORAGE_BACKEND` selection,
  `DATABASE_URL` formats per backend, MySQL auth/TLS status, MSSQL live-pending
  caveat, per-tenant support per provider.
- [multi-tenancy.md](multi-tenancy.md) — Host→tenant resolution,
  `/admin/tenants` lifecycle routes, the `ADMIN_TOKEN` gate, per-tenant DBs, and
  the per-vhost plugin registry (H1).
- [relay-bridge.md](relay-bridge.md) — AP↔AT bridge, the `RELAY_*` env vars,
  both-direction modes, downstream relay subscription, and the translated
  activity/record types.
- [zorm-guide.md](zorm-guide.md) — the in-tree comptime ORM: entity declaration,
  field types, createTable/Migrator, Session/Repository/Query, the four
  dialects, standalone status.
- [env-reference.md](env-reference.md) — consolidated table of every
  operator-facing environment variable.

See also [runbook.md](runbook.md) for operational procedures.
