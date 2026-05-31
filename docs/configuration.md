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
| `CERTCTL_SERVER_TLS_MODE` | `internal` | `internal` (self-signed), `file` (operator cert), or `disabled` (plaintext, dev only). |
| `CERTCTL_SERVER_TLS_CERT_FILE` | — | Server certificate chain (PEM); **required** when `mode=file`. |
| `CERTCTL_SERVER_TLS_KEY_FILE` | — | Server private key (PEM); **required** when `mode=file`. |
| `CERTCTL_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error`. |
| `CERTCTL_LOG_FORMAT` | `json` | `json` or `text`. |

### Transport encryption (TLS)

The control plane serves over **TLS by default** so no credential, token, or
session ever travels in cleartext.

- **`internal`** (default) — the control plane presents a self-signed certificate
  it generates at startup, covering `localhost`, `127.0.0.1`, the container
  hostname, and the Compose service name `certctl`. Clients must trust it (or use
  `curl -k`); suitable for evaluation and internal/air-gapped use.
- **`file`** — the control plane presents an operator-provided certificate and
  key. Use this in production with a certificate from your CA. A missing or
  malformed file fails fast at startup rather than falling back to plaintext.
- **`disabled`** — plaintext HTTP. **Local development only**; the server logs a
  loud warning at startup. If you terminate TLS at a reverse proxy instead,
  configure the proxy to **strip inbound `X-*` identity headers** — certctl does
  not trust them (R1.2), so a proxy cannot reintroduce a header-auth bypass.

The mutual-TLS transport between the control plane and the isolated signing
service (AN-4) is independent of this setting and always enabled.

## Datastores

certctl stores its read state in **PostgreSQL** (the source-of-truth event log
lives in **NATS JetStream**). PostgreSQL is the datastore in every deployment mode
— there is no SQLite path.

!!! important "Datastores: bundled single-node for eval, external for production"
    The serving binary (`certctl`, via `server.Run`) runs a complete single-node
    stack **out of the box**: bundled PostgreSQL (`CERTCTL_POSTGRES_MODE=bundled`,
    the default — the binary starts and supervises an embedded single-node Postgres
    using the version-pinned binary, with data under `CERTCTL_POSTGRES_DATA_DIR` on
    `CERTCTL_POSTGRES_PORT`, default 5432) and embedded NATS
    (`CERTCTL_NATS_MODE=embedded`, the default — in-process file-backed JetStream).
    For **production**, use `external` for both: `CERTCTL_POSTGRES_MODE=external`
    with `CERTCTL_POSTGRES_DSN` and `CERTCTL_NATS_MODE=external` with
    `CERTCTL_NATS_URL`, which the Compose stack and Helm chart wire up. There is **no
    silently-failing default**: an invalid mode — or `external` without a DSN —
    fails fast at startup. (Bundled mode downloads the pinned Postgres binary once
    on first run; external mode never downloads anything. `--migrate` / `--backup`
    target a managed datastore and require `external`.)

| Variable | Default | Meaning |
| --- | --- | --- |
| `CERTCTL_POSTGRES_MODE` | `bundled` | `bundled` (embedded single-node eval — **serves out of the box**) or `external` (managed cluster; recommended for production). |
| `CERTCTL_POSTGRES_DSN` | — | Connection string; **required** when mode is `external`. |
| `CERTCTL_POSTGRES_DATA_DIR` | `data/postgres` | Data directory for the **bundled** datastore; eval data persists here across restarts. |
| `CERTCTL_POSTGRES_PORT` | `5432` | Loopback port for the **bundled** datastore (override if 5432 is taken). |
| `CERTCTL_NATS_MODE` | `embedded` | `embedded` (in-process file-backed JetStream — serves out of the box) or `external` (NATS cluster; recommended for production). |
| `CERTCTL_NATS_URL` | — | NATS URL; **required** when external (i.e. to serve). |
| `CERTCTL_NATS_STORE_DIR` | `data/nats` | JetStream store directory for the embedded datastore (roadmap; not yet served). |

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

## Audit

The audit trail is a projection of the event log; these settings govern its
evidence **export** and **retention** policy. See [Audit trail &
compliance](compliance.md) for the trust model and what certctl enables vs. what
you must operate.

| Variable | Default | Meaning |
| --- | --- | --- |
| `CERTCTL_AUDIT_SIGNING_KEY_FILE` | `data/audit/signing-key.pem` | PEM path for the evidence-export signing key. It is **persisted** (created `0600` on first boot) so signed bundles verify across restarts; the key no longer rotates each restart. |
| `CERTCTL_AUDIT_RETENTION` | — (indefinite) | Retention window, a Go duration (e.g. `8760h`). Empty means **indefinite** (no pruning, the default). When set **and** `CERTCTL_AUDIT_ARCHIVE_DIR` is given, a background worker **enforces** it: records older than the window are archived to signed bundles, a checkpoint is sealed, and the records are pruned from the hot event log — the chain stays verifiable across the prune. |
| `CERTCTL_AUDIT_ARCHIVE_DIR` | — | Cold-storage directory for the signed archive bundles (`<dir>/<tenant>/audit-<seq>.jws`, `0600`). **Required to enable retention pruning** (without it, retention is documentation only). Point it at WORM-backed storage you protect. See [Audit retention and archive lifecycle](compliance.md#audit-retention-and-archive-lifecycle). |

The audit query (`/api/v1/audit/events`) and signed export (`/api/v1/audit/export`)
endpoints are wired into the serving binary, so they return real data — not an
error — out of the box. Protect the signing key file and back it up; distribute
its public half to auditors out of band.

## Secrets (credentials at rest)

Upstream CA and connector credentials — API keys, passwords, client secrets — are
stored **encrypted at rest** using envelope encryption (R3.1): a fresh random
data-encryption key (DEK) encrypts each credential with AES-256-GCM, and the
**key-encryption key (KEK)** wraps the DEK. Only ciphertext is ever persisted; the
plaintext never appears in the database, in config dumps, or in logs. The
cryptography lives behind the single crypto boundary (AN-3, `internal/crypto/seal`).

| Variable | Default | Meaning |
| --- | --- | --- |
| `CERTCTL_SECRETS_KEK_FILE` | `data/secrets/kek.bin` | Path to the 256-bit KEK that wraps every stored credential. It is **created `0600` on first boot** if absent, and is the root of trust for credentials at rest. |

Treat the KEK like the audit signing key: **protect it and back it up** (a lost KEK
means sealed credentials cannot be opened) with the same care described in the
[disaster-recovery runbook](disaster-recovery.md). The KEK is reached through a
wrapper interface, so an **HSM/KMS** can wrap and unwrap DEKs without the KEK ever
leaving the device — the local key file is the default, not the only, option.

## Signer topology & CA custody

The private-key operations run in a separate, sacred process (AN-4). Its issuing
**CA key is persisted, sealed at rest** (R3.2) so a restart preserves the CA
instead of silently rotating it. The signer can run two ways:

| Variable | Default | Meaning |
| --- | --- | --- |
| `CERTCTL_SIGNER_MODE` | `child` | `child`: the control plane supervises `certctl-signer` as a child process (single binary). `external`: it connects to a **separately deployed** signer service (the Compose/topology isolation). |
| `CERTCTL_SIGNER_SOCKET` | — | The signer's Unix-domain socket. **Required** in `external` mode; in `child` mode a temp socket is used if unset. |
| `CERTCTL_SIGNER_KEY_STORE_DIR` | `data/signer/keys` | Directory where the signer **seals its keys at rest** (child mode passes it to the signer; in external mode set it on the signer service). |
| `CERTCTL_CA_CERT_FILE` | `data/ca/issuing-ca.crt` | Where the issuing CA's self-signed certificate is persisted, so the control plane **reuses the same CA cert** across restarts. |

The signer seals its keys with the **same KEK** as credentials
(`CERTCTL_SECRETS_KEK_FILE`). Back up the sealed key store, the KEK, and the CA cert
together (the CA-key recovery set) per the
[disaster-recovery runbook](disaster-recovery.md). The
[`docker-compose.yml`](https://github.com/imfeelingtheagi/certctl/blob/main/deploy/docker/docker-compose.yml)
runs the signer as its **own service** in `external` mode.

## Rate limiting

A per-tenant, PostgreSQL-backed rate limiter sheds load on the guarded routes
(429 + `Retry-After`). See [Operations & resilience](operations.md) for the model
and the bulkheads it complements.

| Variable | Default | Meaning |
| --- | --- | --- |
| `CERTCTL_RATE_LIMIT_ENABLED` | `true` | Turn per-tenant rate limiting on/off. |
| `CERTCTL_RATE_LIMIT_REQUESTS` | `600` | Burst/budget per window, per tenant. |
| `CERTCTL_RATE_LIMIT_WINDOW` | `1m` | The refill window (Go duration). |

When enabled, `requests` must be positive and `window` a valid positive duration,
or the control plane fails fast at startup.

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
