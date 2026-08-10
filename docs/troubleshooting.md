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
- `discovery finding identity conflict` is a fail-closed event-history diagnostic,
  not permission to delete PostgreSQL rows. The message names the tenant, run/natural
  key, existing and incoming payload IDs, and every differing immutable field. Preserve
  PostgreSQL and NATS, export the named events for support, and correct the producer;
  an identical legacy duplicate is canonicalized automatically and does not block
  startup.
- An older container may log that it is `recovering missing agent CA certificate
  from retained signer handle`. That is the safe AUD-100 upgrade path: the signer
  still owns the exact `agent-ca` key, and trstctl writes only a new self-signed
  public wrapper to `/data/ca/agent-ca.crt`. It does not rotate the key. Preserve
  both the signer-key and `trstctldata` volumes.
- `agent CA certificate ... is invalid`, `does not match signer handle`, or
  `signer handle ... is missing` is deliberately fatal. Do not delete the key or
  certificate to clear it. Restore the matching pair from backup, or perform an
  explicit agent trust rotation and re-enrollment; the named file is left intact
  for recovery inspection.

## The agent never registers in the wizard

The **Install an agent** step polls for the agent to appear. If it does not:

- Confirm the agent can reach the control plane URL shown in the install command
  (network/firewall).
- Confirm the bootstrap token was used **once** — tokens are one-time. Generate a
  fresh one (`trstctl-cli agents enroll-token`) and re-run enrollment.
- Check the agent's own logs; an enrollment rejection (`403`) means the token is
  unknown or already used.

## `/readyz` says the projection tail is degraded

The event log is the source notebook; PostgreSQL read tables are its lookup
index. A healthy database and NATS connection are not enough if that index stopped
at one immutable event, so `/readyz` returns 503 while the persisted failed
sequence is still ahead of the projection checkpoint.

1. Read `/readyz` and note the safe failed sequence and lag. The endpoint does not
   expose the stored SQL error or event payload.
2. Inspect the control-plane log for that sequence. Fix the named database,
   schema, or producer incompatibility; do not delete the event, truncate a read
   table, or advance `projection_checkpoint` by hand.
3. Watch `trstctl_projection_lag_events`. The leader retries the projection tail;
   after the event applies, it advances the projection checkpoint and clears the
   failure marker atomically. `/readyz` and the Platform dependency readout return
   to green without restarting the process.

If every retry reports the same immutable binding mismatch, preserve PostgreSQL
and JetStream and collect a support bundle. That is a code or history-compatibility
incident, not a transient health check to silence.

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
