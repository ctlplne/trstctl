# Troubleshooting

Fixes for the issues people hit first. When in doubt, start with:

```bash
certctl -check-config     # prints the effective configuration; exits non-zero if it is invalid
certctl --version         # confirms which build you are running
```

## The control plane exits immediately on start

certctl validates its configuration on boot and **fails fast** on a bad
combination rather than starting half-configured. The error on stderr names the
problem. The most common causes:

- **`postgres.dsn is required when postgres.mode is external`** — you set
  `CERTCTL_POSTGRES_MODE=external` but no `CERTCTL_POSTGRES_DSN`. Provide the DSN,
  or switch back to `bundled`.
- **`nats.url is required when nats.mode is external`** — same, for
  `CERTCTL_NATS_URL`.
- **`telemetry.endpoint … must be an absolute https URL`** — you enabled
  telemetry with a non-`https` endpoint. Use an `https://` URL or leave telemetry
  off.

Run `certctl -check-config` to see exactly what was resolved.

## `docker compose up` starts Postgres/NATS but certctl restarts

The control plane only starts once Postgres and NATS report healthy
(`depends_on … condition: service_healthy`). If certctl keeps restarting:

- Check the datastore health: `docker compose -f deploy/docker/docker-compose.yml ps`.
- Inspect the control-plane logs: `docker compose -f deploy/docker/docker-compose.yml logs certctl`.
- A configuration error (see above) will show in those logs; the container's
  health check runs `certctl -check-config`.

## The agent never registers in the wizard

The **Install an agent** step polls for the agent to appear. If it does not:

- Confirm the agent can reach the control plane URL shown in the install command
  (network/firewall).
- Confirm the bootstrap token was used **once** — tokens are one-time. Generate a
  fresh one (`certctl-cli agents enroll-token`) and re-run enrollment.
- Check the agent's own logs; an enrollment rejection (`403`) means the token is
  unknown or already used.

## CLI commands return 401 or 403

- **401** — the token is missing or unknown. Set `CERTCTL_TOKEN` (or `--token`)
  to a valid certctl API token.
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
certctl -check-config | grep telemetry
# telemetry.enabled: false
```

See [Telemetry](telemetry.md) for what is collected when it is enabled.

## Still stuck?

Capture `certctl --version` and the redacted output of `certctl -check-config`,
plus the relevant logs, and open an issue. Never paste a Postgres DSN or token —
`-check-config` already redacts credentials for you.
