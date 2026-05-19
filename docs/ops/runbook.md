# speedy-socials operator runbook

This runbook covers production operation: startup, shutdown, key
rotation, cert renewal, backup / restore, and the most common
failure modes.

## Startup

Minimum env to bring the binary up in plain-HTTP mode:

```
./zig-out/bin/speedy-socials
```

Production-ish env (HTTPS direct, federation against a real peer):

```
TLS_CERT_PATH=/etc/speedy-socials/tls/fullchain.pem \
TLS_KEY_PATH=/etc/speedy-socials/tls/privkey.pem \
MEDIA_ROOT=/var/lib/speedy-socials/media \
RELAY_BRIDGE_AP_TARGET=https://upstream-relay.example/inbox \
RELAY_SYNTHETIC_KEY_PEPPER="$(cat /etc/speedy-socials/secrets/relay-pepper)" \
STRICT_HTTP_SIG=1 \
SHUTDOWN_GRACE_MS=15000 \
RELAY_OUTBOX_BACKPRESSURE_CAP=10000 \
./zig-out/bin/speedy-socials
```

Startup is complete once both lines appear in stdout:

```
{"scope":"boot","msg":"listening on 127.0.0.1:8080 (HTTPS via ianic TLS 1.3)"}
{"scope":"boot","msg":"relay firehose consumer started (dedicated db handle)"}
```

Smoke-test:

```
curl -fsS http://127.0.0.1:8080/readyz
# process: ready
# storage_writer: ready
# ap_outbox_worker: ready
# relay_firehose_consumer: ready
```

## Shutdown

SIGTERM or SIGINT flips the shutdown flag. The accept loop stops
taking new connections; in-flight requests run to completion; the
firehose consumer drains its ring; the AP outbox worker drains its
nearest-due deliveries; logs flush.

`SHUTDOWN_GRACE_MS` (default 10000) is the wall-clock budget. If
the drain overruns we log a warning but do not force-kill — phases
are not preemptible in this codebase (single-threaded server, no
async cancellation).

## Key rotation

### TLS

1. Place the new cert + key on disk (typical: same paths as the
   current ones).
2. SIGHUP the process. _Currently not wired automatically_ —
   the in-tree primitive
   `core.tls.ianic_inbound.IanicInboundBackend.reloadCertKey(cert, key)`
   exists but no admin endpoint or signal handler invokes it yet
   (PUNCHLIST C4).
3. In-flight TLS sessions are unaffected (the cert is used only
   during handshake). New accepts pick up the fresh cert.

### Relay synthetic-key pepper

Rotating `RELAY_SYNTHETIC_KEY_PEPPER` rotates every synthetic
actor's signing key in lockstep. This is the audit / escape hatch
for compromised material. Downstream peers will fail to verify
signatures from the bridge until they re-resolve the actor doc
(which serves the new key under the same `<actor>#main-key` id).

## Backup / restore

The on-disk state is:

| Path | Contents |
|------|----------|
| `./speedy_socials.db` (or `DB_PATH`) | SQLite primary db + WAL |
| `MEDIA_ROOT` (default `./media`) | Filesystem-spilled blobs (>16 KiB) |

Both must be backed up together — a media row references a blob
file by content-addressed cid.

### Snapshot

```
# Stop the binary OR use SQLite's online-backup API.
sqlite3 ./speedy_socials.db ".backup ./snapshot/snap.db"
tar -czf snapshot/media.tar.gz -C $MEDIA_ROOT .
```

### Restore

```
mv ./snapshot/snap.db ./speedy_socials.db
mkdir -p $MEDIA_ROOT
tar -xzf snapshot/media.tar.gz -C $MEDIA_ROOT
./zig-out/bin/speedy-socials  # boot
```

## Common failure modes

### "/readyz returns 503"

Look at the body — every hook lists its status. The first
`not_ready` line is the blocker.

- `storage_writer: not_ready` → the writer thread crashed. Restart
  the process; investigate `[storage]` ring-log lines.
- `ap_outbox_worker: not_ready` → the outbox worker thread didn't
  start. Same investigation.
- `relay_firehose_consumer: not_ready` → the relay consumer
  failed to spin up its dedicated db handle. Likely disk-full or
  permissions; check ring log.

### "AT firehose subscriber sees the live ring drop oldest events"

The WS subscription registry has bounded per-shard queues. Under
burst the oldest pending entry is dropped. Subscribers detect the
gap (cursor < oldest available seq) and replay from
`atp_firehose_events` via `readSince`. No data loss — the
persistent table is append-only.

### "AP federation outbox depth growing"

`ap_federation_outbox_enqueued_total` counter increments faster
than the worker delivers. Causes:

1. **Peer down** — retries with exponential backoff. Confirm via
   ring-log `[outbox_worker]` lines.
2. **Strict-verify peers** rejecting our deliveries because the
   synthetic actor's key isn't fetchable. Confirm via
   `curl https://<relay_host>/ap/users/at:<did_tail>` and check
   the `publicKey` block is present + the PEM is valid.
3. **Outbox backpressure cap reached** —
   `RELAY_OUTBOX_BACKPRESSURE_CAP` is causing the consumer to pause
   translation. This is intentional: firehose events are durable.
   Raise the cap or fix the upstream delivery issue.

### "Sqlite WAL grew large"

WAL doesn't auto-checkpoint when the db is constantly written.
Manual: `sqlite3 ./speedy_socials.db "PRAGMA wal_checkpoint(TRUNCATE);"`
A scheduled checkpoint cron is documented in F-tier of PUNCHLIST.

## Observability

- `/healthz` — liveness (200 if process is up + accepting)
- `/readyz` — per-subsystem readiness body
- `/metrics` — Prometheus exposition; key series:
  - `http_request_duration_seconds_*`
  - `relay_translated_total_at_to_ap`
  - `relay_translated_total_ap_to_at`
  - `relay_firehose_consumer_dropped_total`
  - `ap_federation_outbox_enqueued_total`
- `/admin/relay/log?direction=ap_to_at` — translation audit trail
- `/admin/relay/subscriptions` — subscription state
- `/admin/relay/followers?actor=<synth>` — per-actor follower list

All `/admin/*` routes require `X-Relay-Admin: 1` (placeholder —
real auth is on the roadmap).

## Audit log

Sensitive operations write to `core_audit_log`. Query:

```
sqlite3 ./speedy_socials.db "SELECT ts, actor, action, target FROM core_audit_log ORDER BY ts DESC LIMIT 20;"
```

Currently logged: follower-table writes via the admin route.
Future events documented in PUNCHLIST G2.
