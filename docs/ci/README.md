# CI templates

GitHub Actions workflow lives here as a template because the OAuth
credential currently used for automated commits lacks the `workflow`
scope. To activate Actions:

```bash
mkdir -p .github/workflows
cp docs/ci/github-actions.yml.template .github/workflows/ci.yml
git add .github/workflows/ci.yml
git commit -m "ci: enable GitHub Actions"
git push  # requires a credential with the `workflow` scope
```

The template is functional as-is; only the path is non-standard.

## Mastodon end-to-end federation job

`mastodon-e2e.yml` (J5) is a self-contained, runnable GitHub Actions job
that brings up a real Mastodon dev pod, boots speedy-socials against it,
and exercises one federation round trip — a Follow + a Create(Note) + a
Like delivered from the bridge to the pod, plus a pod->bridge reachability
check. The round trip itself is the gated Zig integration test
`tests/e2e/mastodon_roundtrip.zig`.

It is **skippable for offline branches** three ways: it only runs on
`workflow_dispatch` or a PR carrying the `e2e-mastodon` label, and only when
the repo variable `RUN_E2E_MASTODON == "1"`. The Zig test is also inert
under the normal `zig build test` job — it self-skips (`error.SkipZigTest`)
whenever `MASTODON_E2E_URL` is unset.

Activate the same way as the main workflow:

```bash
mkdir -p .github/workflows
cp docs/ci/mastodon-e2e.yml .github/workflows/mastodon-e2e.yml
git add .github/workflows/mastodon-e2e.yml
git commit -m "ci: enable Mastodon e2e job"
git push  # requires a credential with the `workflow` scope
```

### Running the round trip locally (podman)

Bring up a Mastodon dev pod and point the gated test at it:

```bash
podman network create mastonet
podman run -d --name masto-pg --network mastonet \
    -e POSTGRES_USER=mastodon -e POSTGRES_PASSWORD=mastodon \
    -e POSTGRES_DB=mastodon_development docker.io/library/postgres:16
podman run -d --name masto-redis --network mastonet docker.io/library/redis:7
podman run -d --name masto-web --network mastonet -p 3000:3000 \
    -e DB_HOST=masto-pg -e DB_USER=mastodon -e DB_PASS=mastodon \
    -e REDIS_HOST=masto-redis -e LOCAL_DOMAIN=localhost:3000 \
    -e LOCAL_HTTPS=false \
    -e OTP_SECRET=dummy_otp_secret_for_local_dev_only \
    -e SECRET_KEY_BASE=dummy_secret_key_base_for_local_dev_only \
    docker.io/tootsuite/mastodon:v4.5 \
    bash -c 'bundle exec rails db:setup && rails s -b 0.0.0.0'
podman exec masto-web bin/tootctl accounts create admin \
    --email admin@localhost --confirmed --role Owner

# Run just the gated test against the pod:
MASTODON_E2E_URL=http://localhost:3000 \
MASTODON_E2E_ACCT=admin@localhost:3000 \
    zig build test
```

The full set of env knobs (`MASTODON_E2E_URL`, `MASTODON_E2E_ACCT`,
`MASTODON_E2E_LOCAL_ORIGIN`) is documented in the header of
`tests/e2e/mastodon_roundtrip.zig`.
