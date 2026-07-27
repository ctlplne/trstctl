# Troubleshooting

Fixes for the issues people hit first. When in doubt, start with:

```bash
trstctl -check-config     # prints the effective configuration; exits non-zero if it is invalid
trstctl --version         # confirms which build you are running
```

## The control plane exits immediately on start

trstctl validates its configuration on boot and **fails fast** on a bad
combination rather than starting half-configured. The error on stderr names the
problem. The most common causes:

- **`postgres.dsn is required when postgres.mode is external`** — you set
  `TRSTCTL_POSTGRES_MODE=external` but no `TRSTCTL_POSTGRES_DSN`. Provide the DSN,
  or switch back to `bundled`.
- **`nats.url is required when nats.mode is external`** — same, for
  `TRSTCTL_NATS_URL`.
- **`telemetry.endpoint … must be an absolute https URL`** — you enabled
  telemetry with a non-`https` endpoint. Use an `https://` URL or leave telemetry
  off.

Run `trstctl -check-config` to see exactly what was resolved.

## `docker compose up` starts Postgres/NATS but trstctl restarts

The control plane only starts once Postgres and NATS report healthy
(`depends_on … condition: service_healthy`). If trstctl keeps restarting:

- Check the datastore health: `docker compose -f deploy/docker/docker-compose.yml ps`.
- Inspect the control-plane logs: `docker compose -f deploy/docker/docker-compose.yml logs trstctl`.
- A configuration error (see above) will show in those logs; the container's
  health check runs `trstctl -check-config`.

## The agent never registers in the wizard

The **Install an agent** step polls for the agent to appear. If it does not:

- Confirm the agent can reach the control plane URL shown in the install command
  (network/firewall).
- Confirm the bootstrap token was used **once** — tokens are one-time. Generate a
  fresh one (`trstctl-cli agents enroll-token`) and re-run enrollment.
- Check the agent's own logs; an enrollment rejection (`403`) means the token is
  unknown or already used.

## CLI commands return 401 or 403

- **401** — the token is missing or unknown. Set `TRSTCTL_TOKEN` (or `--token`)
  to a valid trstctl API token.
- **403** — the token is valid but lacks the scope for the operation (for
  example, a read-only token attempting a write). Use a token with the required
  scope. See the [CLI reference](cli.md).

## The web UI shows "the web UI has not been built"

You are running a binary built without the bundled web assets. Build them and
rebuild the binary:

```bash
make web      # builds the SPA into the embed directory
make build
```

## Telemetry — am I sending anything?

No, unless you turned it on. Confirm with:

```bash
trstctl -check-config | grep telemetry
# telemetry.enabled: false
```

See [Telemetry](telemetry.md) for what is collected when it is enabled.

## Still stuck?

Create one bounded artifact:

```bash
trstctl support-bundle --output trstctl-support.tar.gz --log-file ./control-plane.log
```

The command works even when configuration validation or HTTP startup fails. It
includes build/configuration posture, categorical PostgreSQL, NATS, and signer
health, migration state, aggregate outbox/bulkhead counts, and at most 200 recent
log lines. It never copies raw environment/configuration values or endpoint,
path, tenant, subject, or destination identifiers. Logs pass through secret and
PII redaction followed by a residual fail-closed scan. Review the archive before
sharing it; if the scan cannot make it safe, the command refuses to write it.
