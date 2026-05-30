# Configuration

certctl resolves its configuration from, in increasing precedence: built-in
defaults, an optional JSON config file (`CERTCTL_CONFIG_FILE`), and environment
variables. The configuration is validated on boot — a bad combination **fails
fast** rather than starting half-configured.

Inspect the effective configuration at any time (credentials are redacted):

```bash
certctl -check-config
```

## Server

| Variable | Default | Meaning |
| --- | --- | --- |
| `CERTCTL_SERVER_ADDR` | `:8443` | Address the control plane listens on. |
| `CERTCTL_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error`. |
| `CERTCTL_LOG_FORMAT` | `json` | `json` or `text`. |

## Datastores

certctl stores its read state in **PostgreSQL** (the source-of-truth event log
lives in **NATS JetStream**). Both can run **bundled** for single-node evaluation
or **external** for production. PostgreSQL is the datastore in every deployment
mode — there is no SQLite path.

| Variable | Default | Meaning |
| --- | --- | --- |
| `CERTCTL_POSTGRES_MODE` | `bundled` | `bundled` or `external`. |
| `CERTCTL_POSTGRES_DSN` | — | Connection string; **required** when external. |
| `CERTCTL_POSTGRES_DATA_DIR` | `data/postgres` | Data directory when bundled. |
| `CERTCTL_NATS_MODE` | `embedded` | `embedded` or `external`. |
| `CERTCTL_NATS_URL` | — | NATS URL; **required** when external. |
| `CERTCTL_NATS_STORE_DIR` | `data/nats` | JetStream store directory when embedded. |

### External datastores

To point certctl at managed PostgreSQL and NATS, switch both to external mode and
supply their connection strings:

```bash
export CERTCTL_POSTGRES_MODE=external
export CERTCTL_POSTGRES_DSN='postgres://user:pass@db.internal:5432/certctl?sslmode=require'
export CERTCTL_NATS_MODE=external
export CERTCTL_NATS_URL='nats://nats.internal:4222'
```

When a mode is `external`, its connection string is mandatory; certctl refuses to
start without it. This is the same wiring the Compose stack uses, so the
evaluation path and a production deployment exercise identical code.

## Lifecycle

How far ahead of expiry certctl renews and alerts. Values are Go durations.

| Variable | Default | Meaning |
| --- | --- | --- |
| `CERTCTL_LIFECYCLE_RENEW_BEFORE` | `720h` (30 days) | Renew this far before expiry. |
| `CERTCTL_LIFECYCLE_ALERT_BEFORE` | `336h` (14 days) | Alert this far before expiry. |

## Telemetry

Telemetry is **off by default** and never sends anything unless you opt in. When
enabled, it sends only coarse, anonymized, non-PII data.

| Variable | Default | Meaning |
| --- | --- | --- |
| `CERTCTL_TELEMETRY_ENABLED` | `false` | Set `true` to opt in. A malformed value is ignored (stays off). |
| `CERTCTL_TELEMETRY_ENDPOINT` | `https://telemetry.certctl.io/v1/usage` | Where reports go; must be `https`. |
| `CERTCTL_TELEMETRY_INTERVAL` | `24h` | Reporting interval. |

See [Telemetry](telemetry.md) for exactly what is and is not collected.

## Config file

Any of the above can also be set in a JSON file named by `CERTCTL_CONFIG_FILE`;
environment variables override file values, which override defaults.

```json
{
  "server": { "addr": ":8443" },
  "postgres": { "mode": "external", "dsn": "postgres://..." },
  "nats": { "mode": "external", "url": "nats://..." },
  "telemetry": { "enabled": false }
}
```
