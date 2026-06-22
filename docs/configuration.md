# Configuration

trstctl resolves its configuration from, in increasing precedence: built-in
defaults, an optional JSON config file (`TRSTCTL_CONFIG_FILE`), and environment
variables. The configuration is validated on boot — a bad combination **fails
fast** rather than starting half-configured.

Inspect the effective configuration at any time (credentials are redacted):

```bash
trstctl -check-config
```

## Server

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_SERVER_ADDR` | `:8443` | Address the control plane listens on. |
| `TRSTCTL_SERVER_TLS_MODE` | `internal` | `internal` (self-signed), `file` (operator cert), or `disabled` (plaintext, dev only). |
| `TRSTCTL_SERVER_TLS_CERT_FILE` | — | Server certificate chain (PEM); **required** when `mode=file`. |
| `TRSTCTL_SERVER_TLS_KEY_FILE` | — | Server private key (PEM); **required** when `mode=file`. |
| `TRSTCTL_DEV_ALLOW_PLAINTEXT` | `false` | Explicit local-dev override required when `TRSTCTL_SERVER_TLS_MODE=disabled`; `TRSTCTL_SERVER_ADDR` must also bind loopback only. |
| `TRSTCTL_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error`. |
| `TRSTCTL_LOG_FORMAT` | `json` | `json` or `text`. |

### Transport encryption (TLS)

The control plane serves over **TLS by default** so no credential, token, or
session ever travels in cleartext.

- **`internal`** (default) — the control plane presents a self-signed certificate
  it generates at startup, covering `localhost`, `127.0.0.1`, the container
  hostname, and the Compose service name `trstctl`. Clients must trust it (or use
  `curl -k`); suitable for evaluation and internal/air-gapped use.
- **`file`** — the control plane presents an operator-provided certificate and
  key. Use this in production with a certificate from your CA. A missing or
  malformed file fails fast at startup rather than falling back to plaintext.
- **`disabled`** — plaintext HTTP. **Local development only** and mechanically
  bounded: startup fails unless `TRSTCTL_DEV_ALLOW_PLAINTEXT=true` and
  `TRSTCTL_SERVER_ADDR` is loopback-only (`localhost`, `127.0.0.1`, or `::1`).
  Production TLS termination should use `server.tls.mode=file` at trstctl or a
  TLS-terminating proxy in front of a TLS-enabled trstctl listener; disabled mode
  is not the production proxy pattern.

The control-plane↔signer channel (AN-4) is independent of this setting. The
**default** (single-binary `child` mode, and `external` mode with `signer.socket`)
is a **peer-authenticated Unix domain socket** — a `0600` socket in a `0700`
directory, restricted to the signer's own uid via `SO_PEERCRED` on Linux — not a
TLS channel. For a **separately-hosted signer across nodes**, set
`signer.mtls_address` (with the `signer.mtls_*` certificate material): the control
plane then reaches the signer over **mTLS** — TLS 1.3, AEAD-only, with the control
plane and the signer each **pinning** the other's certificate (an untrusted or
merely CA-signed-but-unpinned peer is rejected, fail-closed). Exactly one of
`signer.socket` or `signer.mtls_address` is used in `external` mode; a partial mTLS
block fails closed at startup (SIGNER-005).

## Datastores

trstctl stores its read state in **PostgreSQL** (the source-of-truth event log
lives in **NATS JetStream**). PostgreSQL is the datastore in every deployment mode
— there is no SQLite path.

!!! important "Datastores: bundled single-node for eval, external for production"
    The serving binary (`trstctl`, via `server.Run`) can run a single-node eval
    stack: bundled PostgreSQL (`TRSTCTL_POSTGRES_MODE=bundled`, the default — the
    binary starts and supervises an embedded single-node Postgres with data under
    `TRSTCTL_POSTGRES_DATA_DIR` on `TRSTCTL_POSTGRES_PORT`, default 5432) and
    embedded NATS (`TRSTCTL_NATS_MODE=embedded`, the default — in-process
    file-backed JetStream). Bundled PostgreSQL is available only for host archives
    with committed runtime pins in `deploy/supply-chain/embedded-postgres.json`
    (summarized in [Supply chain](supply-chain.md)):
    currently `linux-amd64`, `linux-arm64v8`, and `darwin-arm64v8`. It downloads
    that pinned PostgreSQL runtime once on first use, verifies the cached archive
    before execution, and fails closed if the host archive is unsupported, unpinned,
    or hash-mismatched. For **production**, use `external` for both:
    `TRSTCTL_POSTGRES_MODE=external` with `TRSTCTL_POSTGRES_DSN` and
    `TRSTCTL_NATS_MODE=external` with `TRSTCTL_NATS_URL`, which the Compose stack
    and Helm chart wire up. There is **no silently-failing default**: an invalid
    mode — or `external` without a DSN — fails fast at startup. (External mode
    never downloads anything. `--migrate` / `--backup` target a managed datastore
    and require `external`.)

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_POSTGRES_MODE` | `bundled` | `bundled` (embedded single-node eval on a manifest-pinned host archive; downloads once and fails closed if unpinned) or `external` (managed cluster; recommended for production). |
| `TRSTCTL_POSTGRES_DSN` | — | Connection string; **required** when mode is `external`. |
| `TRSTCTL_POSTGRES_DATA_DIR` | `data/postgres` | Data directory for the **bundled** datastore; eval data persists here across restarts. |
| `TRSTCTL_POSTGRES_PORT` | `5432` | Loopback port for the **bundled** datastore (override if 5432 is taken). |
| `TRSTCTL_NATS_MODE` | `embedded` | `embedded` (in-process file-backed JetStream for single-node eval) or `external` (NATS cluster; recommended for production). |
| `TRSTCTL_NATS_URL` | — | NATS URL; **required** when external (i.e. to serve). |
| `TRSTCTL_NATS_STORE_DIR` | `data/nats` | JetStream store directory for the embedded datastore (roadmap; not yet served). |
| `TRSTCTL_NATS_REPLICAS` | `3` in external, `1` embedded | Required JetStream replicas for the source-of-truth event stream. External startup/readiness fail if NATS cannot honor the requested count. |
| `TRSTCTL_NATS_ALLOW_SINGLE_REPLICA` | `false` | Eval-only opt-in that permits `TRSTCTL_NATS_REPLICAS=1` in external mode. Do not enable it for production HA/RPO. |

### External datastores

To point trstctl at managed PostgreSQL and NATS, switch both to external mode and
supply their connection strings:

```bash
export TRSTCTL_POSTGRES_MODE=external
export TRSTCTL_POSTGRES_DSN='postgres://user:pass@db.internal:5432/trstctl?sslmode=require'
export TRSTCTL_NATS_MODE=external
export TRSTCTL_NATS_URL='nats://nats.internal:4222'
export TRSTCTL_NATS_REPLICAS=3
```

When a mode is `external`, its connection string is mandatory; trstctl refuses to
start without it. External NATS also refuses to serve under-replicated: the event
stream defaults to three replicas, startup fails on a non-clustered single NATS
server, and `/readyz` reports degraded if the observed stream later has fewer
replicas than configured. The Docker Compose eval stack uses the same external code
path but explicitly sets `TRSTCTL_NATS_REPLICAS=1` and
`TRSTCTL_NATS_ALLOW_SINGLE_REPLICA=true`; keep that opt-in out of production.

## Lifecycle

How far ahead of expiry trstctl renews and alerts. Values are Go durations.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_LIFECYCLE_RENEW_BEFORE` | `720h` (30 days) | Renew this far before expiry. |
| `TRSTCTL_LIFECYCLE_ALERT_BEFORE` | `336h` (14 days) | Alert this far before expiry. |

## Telemetry

Telemetry is **off by default** and never sends anything unless you opt in. When
enabled, it sends only coarse, anonymized, non-PII data.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_TELEMETRY_ENABLED` | `false` | Set `true` to opt in. A malformed value is ignored (stays off). |
| `TRSTCTL_TELEMETRY_ENDPOINT` | `https://telemetry.trstctl.com/v1/usage` | Where reports go; must be `https`. |
| `TRSTCTL_TELEMETRY_INTERVAL` | `24h` | Reporting interval. |

See [Telemetry](telemetry.md) for exactly what is and is not collected.

## Audit

The audit trail is a projection of the event log; these settings govern its
evidence **export** and **retention** policy. See [Audit trail &
compliance](compliance.md) for the trust model and what trstctl enables vs. what
you must operate.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_AUDIT_SIGNING_KEY_FILE` | `data/audit/signing-key.pem` | PEM path for the evidence-export signing key. It is **persisted** (created `0600` on first boot) so signed bundles verify across restarts; the key no longer rotates each restart. |
| `TRSTCTL_AUDIT_RETENTION` | — (indefinite) | Retention window, a Go duration (e.g. `8760h`). Empty means **indefinite** (no pruning, the default). When set **and** `TRSTCTL_AUDIT_ARCHIVE_DIR` is given, a background worker **enforces** it: records older than the window are archived to signed bundles, a checkpoint is sealed, and the records are pruned from the hot event log — the chain stays verifiable across the prune. |
| `TRSTCTL_AUDIT_ARCHIVE_DIR` | — | Cold-storage directory for the signed archive bundles (`<dir>/<tenant>/audit-<seq>.jws`, `0600`). **Required to enable retention pruning** (without it, retention is documentation only). Point it at WORM-backed storage you protect. See [Audit retention and archive lifecycle](compliance.md#audit-retention-and-archive-lifecycle). |

The audit query (`/api/v1/audit/events`) and signed export (`/api/v1/audit/export`)
endpoints are wired into the serving binary, so they return real data — not an
error — out of the box. Protect the signing key file and back it up; distribute
its public half to auditors out of band.

## Privacy Retention

Non-audit personal data is retained by class, then pseudonymized after the
operational need ends. This is separate from audit retention: the immutable event
trail remains the source of truth, while tenant read surfaces stop carrying stale
names, emails, subjects, SANs, comments, profile authors, approval actors, and
free-form evidence. The worker emits `privacy.retention.enforced` and projects the
anonymization from that event, so rebuilds replay the same result.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_PRIVACY_RETENTION_ENABLED` | `true` | Runs the leader-only non-audit PII retention worker. Set `false` only when an external privacy job enforces the same policy. |
| `TRSTCTL_PRIVACY_RETENTION_INTERVAL` | `24h` | Worker cadence. It also runs once on startup. |
| `TRSTCTL_PRIVACY_RETENTION_OWNERS` | `17520h` (730 days) | Pseudonymize owner name/email when the owner is older than this and no identity references it. |
| `TRSTCTL_PRIVACY_RETENTION_IDENTITIES` | `9528h` (397 days) | Pseudonymize terminal or expired identity metadata. |
| `TRSTCTL_PRIVACY_RETENTION_CERTIFICATES` | `9528h` (397 days) | Pseudonymize expired/revoked/superseded certificate subject, SAN, deployment location, and source metadata. |
| `TRSTCTL_PRIVACY_RETENTION_SSH_KEYS` | `4320h` (180 days) | Clear orphaned stale SSH key comments and locations. |
| `TRSTCTL_PRIVACY_RETENTION_ACCESS` | `2160h` (90 days) | Pseudonymize offboarded tenant members and expired/revoked API-token subjects. |
| `TRSTCTL_PRIVACY_RETENTION_APPROVALS` | `9528h` (397 days) | Pseudonymize old requester/approver subject values while preserving resource/action evidence. |
| `TRSTCTL_PRIVACY_RETENTION_PROFILES` | `9528h` (397 days) | Pseudonymize old certificate-profile author values. |
| `TRSTCTL_PRIVACY_RETENTION_ATTESTATIONS` | `9528h` (397 days) | Clear stale free-form attestation evidence JSON. |
| `TRSTCTL_PRIVACY_RETENTION_AGENTS` | `4320h` (180 days) | Pseudonymize stale agent names while preserving agent id, status, version, and heartbeat timestamps. |

Operators can trigger and inspect the same served path with
`POST /api/v1/privacy/retention-runs`, `GET /api/v1/privacy/retention-runs`, or
the matching `trstctl privacy retention run/list` CLI commands.

## Secrets (credentials at rest)

Upstream CA and connector credentials — API keys, passwords, client secrets — are
stored **encrypted at rest** using envelope encryption (R3.1): a fresh random
data-encryption key (DEK) encrypts each credential with AES-256-GCM, and the
**key-encryption key (KEK)** wraps the DEK. Only ciphertext is ever persisted; the
plaintext never appears in the database, in config dumps, or in logs. The
cryptography lives behind the single crypto boundary (AN-3, `internal/crypto/seal`).

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_SECRETS_KEK_FILE` | `data/secrets/kek.bin` | Path to the 256-bit KEK that wraps every stored credential. It is **created `0600` on first boot** if absent, and is the root of trust for credentials at rest. |

Treat the KEK like the audit signing key: **protect it and back it up** (a lost KEK
means sealed credentials cannot be opened) with the same care described in the
[disaster-recovery runbook](disaster-recovery.md). The KEK is reached through a
wrapper interface, so an **HSM/KMS** can wrap and unwrap DEKs without the KEK ever
leaving the device — the local key file is the default, not the only, option.
On reload, local KEK, auth-secret, and session-secret files are accepted only if
they are regular files, not symlinks, owned by the process user with
`0600`-or-stricter permissions or mounted as root-owned Kubernetes Secret files
readable by the pod's `fsGroup`, and all parent directories reject group/world
writes. Unsafe restored files fail startup instead of silently weakening key
custody.

## Signer topology & CA custody

The private-key operations run in a separate, sacred process (AN-4). Its issuing
**CA key is persisted, sealed at rest** (R3.2) so a restart preserves the CA
instead of silently rotating it. The signer can run two ways:

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_SIGNER_MODE` | `child` | `child`: the control plane supervises `trstctl-signer` as a child process (single binary). `external`: it connects to a **separately deployed** signer service over a UDS (`TRSTCTL_SIGNER_SOCKET`) or, across nodes, mTLS (`TRSTCTL_SIGNER_MTLS_ADDRESS`). |
| `TRSTCTL_SIGNER_SOCKET` | — | The signer's Unix-domain socket. In `external` mode set **either** this **or** `TRSTCTL_SIGNER_MTLS_ADDRESS`; in `child` mode a temp socket is used if unset. |
| `TRSTCTL_SIGNER_KEY_STORE_DIR` | `data/signer/keys` | Directory where the signer **seals its keys at rest** (child mode passes it to the signer; in external mode set it on the signer service). |
| `TRSTCTL_SIGNER_AUTH_SECRET_FILE` | `data/signer/sign-auth.bin` | Signer-side content-authorization verifier secret. The signer uses it to verify dual-control tokens before using privileged handles. Do not mount it into the control plane in production. |
| `TRSTCTL_SIGNER_AUTH_TOKEN_COMMAND` | — | Independent approval-token command used by the control plane in production. The command receives sign-intent JSON on stdin and returns the raw token as base64 on stdout. |
| `TRSTCTL_SIGNER_ALLOW_CO_RESIDENT_AUTHORIZER` | `true` in single-node eval defaults | Evaluation-only escape hatch that lets the control plane mint signer tokens from `TRSTCTL_SIGNER_AUTH_SECRET_FILE`. Production-like external NATS deployments reject it; use `TRSTCTL_SIGNER_AUTH_TOKEN_COMMAND` instead. |
| `TRSTCTL_SIGNER_ALLOW_INSECURE_DEV_NONLINUX` | `false` | Local-development-only escape hatch for running child signer mode on non-Linux hosts. Without it, `trstctl-signer` refuses startup when process hardening, UDS peer UID checks, and locked memory are unavailable. Do not set it in production. |
| `TRSTCTL_SIGNER_MTLS_ADDRESS` | — | `host:port` of a separately-hosted signer's **mTLS** listener (SIGNER-005). When set (in `external` mode), the control plane reaches the signer over TLS 1.3 mutual auth with **both-ways certificate pinning** instead of a UDS. Mutually exclusive with `TRSTCTL_SIGNER_SOCKET`. |
| `TRSTCTL_SIGNER_MTLS_SERVER_NAME` | — | The signer certificate's expected SAN, verified by the control plane. **Required** when `TRSTCTL_SIGNER_MTLS_ADDRESS` is set. |
| `TRSTCTL_SIGNER_MTLS_CERT_FILE` / `…_KEY_FILE` | — | The control plane's own **client** certificate and key (PEM) presented on the mTLS channel. Required with `…_MTLS_ADDRESS`. |
| `TRSTCTL_SIGNER_MTLS_PEER_CA_FILE` | — | PEM CA bundle anchoring the **signer's** certificate. Required with `…_MTLS_ADDRESS`. |
| `TRSTCTL_SIGNER_MTLS_PEER_PIN` | — | Hex SHA-256 of the **signer** certificate's public key, pinned by the control plane. Required with `…_MTLS_ADDRESS`. |
| `TRSTCTL_CA_CERT_FILE` | `data/ca/issuing-ca.crt` | Where the issuing CA's self-signed certificate is persisted, so the control plane **reuses the same CA cert** across restarts. |

The signer seals its keys with the **same KEK** as credentials
(`TRSTCTL_SECRETS_KEK_FILE`). Back up the sealed key store, the KEK, and the CA cert
together (the CA-key recovery set) per the
[disaster-recovery runbook](disaster-recovery.md). The
[`docker-compose.yml`](https://github.com/imfeelingtheagi/trstctl/blob/main/deploy/docker/docker-compose.yml)
runs the signer as its **own service** in `external` mode.

## Regulated CA governance mode

The individual issuance controls — the OPA/Rego policy gate, four-eyes dual
control, a bound default certificate profile, revocation publication, and FIPS — can
each be enabled on their own. For a compliance deployment that is error-prone: a
single missing control silently weakens the posture. `ca.governance_mode=regulated`
is the **one coherent switch** that closes that gap. In regulated mode the binary
**fails startup** unless **all** of these are present together, each with an
actionable error naming the field to set:

- the **OPA policy gate** is on (`ca.policy.enabled=true`);
- **four-eyes dual control** is on (`ca.policy.require_approval=true`) with at least
  **two** distinct approvers (`ca.policy.required_approvals` unset, defaulting to 2,
  or `>= 2`) — a single approver is rejected;
- a **default certificate profile** is bound (`ca.default_profile`);
- **revocation publication** is configured — at least one of
  `ca.crl_distribution_points` or `ca.ocsp_servers` — so issued leaves carry a
  status pointer (composing with the served-leaf profile, PKIGOV-002);
- and, when `ca.require_fips=true` is declared, the **FIPS 140-3 module is active**
  (the binary was built with `GOFIPS140=latest` / `make fips-build`, or run with
  `GODEBUG=fips140=on`).

A **complete** regulated config boots normally. The default posture
(`ca.governance_mode` unset, or `standard`) imposes no coupling, so existing
single-node deployments are unaffected.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_CA_GOVERNANCE_MODE` | `standard` | `standard` (or unset): the controls are independent. `regulated`: fail startup unless the policy gate, four-eyes dual control, a bound default profile, revocation publication, and any declared FIPS requirement are **all** present together. |
| `TRSTCTL_CA_REQUIRE_FIPS` | `false` | In `regulated` mode, additionally require the FIPS 140-3 module to be active (build with `GOFIPS140=latest` or run with `GODEBUG=fips140=on`); otherwise startup fails closed. Ignored outside regulated mode. |

## Served AI surface and model adapter

The AI/RCA/MCP surface is off by default and read-only when enabled. The model
adapter is separately off by default: with `TRSTCTL_AI_MODEL_MODE=off` (or unset),
query/RCA still return grounded citations, but no prompt leaves the process.
`GET /api/v1/ai/status` reports the live enabled state, model mode, endpoint host,
egress class, and redaction/refusal posture without echoing the full endpoint URL.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_AI_ENABLE_API` | `false` | Serve `/api/v1/ai/status`, `/api/v1/ai/query`, `/api/v1/ai/rca`, and `/api/v1/mcp/tools*` behind auth/RBAC. |
| `TRSTCTL_AI_MCP_IDENTITY` | — | Workload identity label the read-only MCP server presents. |
| `TRSTCTL_AI_RATE_MAX` | `60` | Per-caller MCP tool-call budget per window. |
| `TRSTCTL_AI_RATE_WINDOW_SECONDS` | `60` | MCP tool-call rate window in seconds. |
| `TRSTCTL_AI_MODEL_MODE` | `off` | `off`, `local`, or `cloud`. `off` means no model adapter and no prompt egress. |
| `TRSTCTL_AI_MODEL_RUNTIME` | — | Local runtime label, required with `mode=local`: `ollama` or `vllm`. |
| `TRSTCTL_AI_MODEL_PROVIDER` | — | Cloud/gateway provider label, required with `mode=cloud`. |
| `TRSTCTL_AI_MODEL_ENDPOINT` | — | Completion endpoint. Local `http://` endpoints must be loopback; otherwise use HTTPS. Cloud endpoints must be HTTPS. URL userinfo is rejected so credentials are not stored in config. |
| `TRSTCTL_AI_MODEL_NAME` | — | Model name sent to the configured endpoint. Required with `mode=local` or `mode=cloud`. |
| `TRSTCTL_AI_MODEL_ALLOW_EGRESS` | `false` | Required as `true` with `mode=cloud`; invalid for `off` and `local`. |

Ollama local mode sends the native generate shape to the endpoint. vLLM and cloud
mode send an OpenAI-compatible chat-completions shape. Every model path goes
through the boundary redactor and residual-secret refusal gate before the HTTP
request is made; if no model is configured, the answer remains citation-grounded
and air-gapped.

## Served enrollment protocols

ACME, EST, SCEP, CMP, SPIFFE, and SSH protocol surfaces are opt-in until they are
explicitly bound to a tenant. That startup check is intentional: a public enrollment
endpoint must know the tenant it mints into before it is exposed (AN-1).

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_PROTOCOLS_ACME_ENABLED` / `…_TENANT_ID` | `false` / — | Serve ACME at `/directory` + `/acme/...` for the named tenant. |
| `TRSTCTL_PROTOCOLS_ACME_MAX_NONCES` | `4096` | Maximum outstanding ACME replay nonces retained by the tenant-bound ACME mount. |
| `TRSTCTL_PROTOCOLS_ACME_MAX_ACCOUNTS` | `2048` | Maximum ACME accounts retained by the tenant-bound ACME mount. |
| `TRSTCTL_PROTOCOLS_ACME_MAX_PENDING_ORDERS` | `4096` | Maximum pending ACME orders retained before the server returns ACME `rateLimited` (429). |
| `TRSTCTL_PROTOCOLS_ACME_MAX_PENDING_AUTHORIZATIONS` | `8192` | Maximum pending ACME authorizations retained across pending orders. |
| `TRSTCTL_PROTOCOLS_ACME_MAX_PENDING_CHALLENGES` | `24576` | Maximum pending ACME challenge records retained across pending authorizations. |
| `TRSTCTL_PROTOCOLS_ACME_MAX_PENDING_ORDERS_PER_ACCOUNT` | `128` | Per-account pending-order cap, independent from source-IP budgets. |
| `TRSTCTL_PROTOCOLS_ACME_MAX_NEW_NONCES_PER_SOURCE` | `120` | Per-source newNonce budget per source window. |
| `TRSTCTL_PROTOCOLS_ACME_MAX_NEW_ACCOUNTS_PER_SOURCE` | `20` | Per-source account-creation budget per source window. |
| `TRSTCTL_PROTOCOLS_ACME_MAX_NEW_ORDERS_PER_SOURCE` | `60` | Per-source order-creation budget per source window. |
| `TRSTCTL_PROTOCOLS_ACME_SOURCE_WINDOW_SECONDS` | `600` | Source-budget window for ACME nonce/account/order creation. |
| `TRSTCTL_PROTOCOLS_ACME_NONCE_TTL_SECONDS` | `600` | TTL for unused ACME replay nonces before the request-time janitor drops them. |
| `TRSTCTL_PROTOCOLS_ACME_STATE_TTL_SECONDS` | `86400` | TTL for pending ACME order/authorization/challenge state before the request-time janitor drops it. |
| `TRSTCTL_PROTOCOLS_EST_ENABLED` / `…_TENANT_ID` | `false` / — | Serve EST at `/.well-known/est/...` for the named tenant. |
| `TRSTCTL_PROTOCOLS_SCEP_ENABLED` / `…_TENANT_ID` | `false` / — | Serve SCEP at `/scep` for the named tenant. |
| `TRSTCTL_PROTOCOLS_CMP_ENABLED` / `…_TENANT_ID` | `false` / — | Serve CMP at `/cmp` for the named tenant. |
| `TRSTCTL_PROTOCOLS_RA_KEY_FILE` | `data/protocols/ra-transport.key` | Sealed SCEP/CMP RSA transport identity. Put this on shared persistent storage in HA so replicas use the same cached-client RA material. |
| `TRSTCTL_PROTOCOLS_SPIFFE_ENABLED` / `…_TENANT_ID` | `false` / — | Serve the SPIFFE Workload API UDS for the named tenant. Requires `TRSTCTL_PROTOCOLS_SPIFFE_TRUST_DOMAIN`. |
| `TRSTCTL_PROTOCOLS_SPIFFE_SOCKET_PATH` | `/tmp/trstctl-spiffe-workload.sock` | UDS path for the SPIFFE Workload API when enabled. |
| `TRSTCTL_PROTOCOLS_SPIFFE_TRUST_DOMAIN` | — | SPIFFE trust domain, for example `example.org`. Required when SPIFFE is enabled. |
| `TRSTCTL_PROTOCOLS_SSH_ENABLED` / `…_TENANT_ID` | `false` / — | Serve the SSH CA JSON endpoints and KRL for the named tenant. |

## Rate limiting

A per-tenant, PostgreSQL-backed rate limiter sheds load on the guarded routes
(429 + `Retry-After`). See [Operations & resilience](operations.md) for the model
and the bulkheads it complements.

ACME also has protocol-local abuse budgets above because its public nonce/account/order
routes are not REST API routes. The protocol bulkhead limits concurrent work; the
ACME quota knobs bound retained ACME protocol state.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_RATE_LIMIT_ENABLED` | `true` | Turn per-tenant rate limiting on/off. |
| `TRSTCTL_RATE_LIMIT_REQUESTS` | `600` | Burst/budget per window, per tenant. |
| `TRSTCTL_RATE_LIMIT_WINDOW` | `1m` | The refill window (Go duration). |

When enabled, `requests` must be positive and `window` a valid positive duration,
or the control plane fails fast at startup.

## Bulkheads

Each subsystem runs on its own bounded worker pool (AN-7). `workers` caps concurrent
work; `queue` caps accepted backlog before trstctl rejects fast with structured
backpressure. Every value must be positive. Defaults are conservative for a
single-node or small HA deployment; larger fleets should raise only the subsystem
that is actually saturating.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_BULKHEAD_API_WORKERS` / `TRSTCTL_BULKHEAD_API_QUEUE` | `8` / `256` | Cheap REST/API work. Keep this protected from heavy query, protocol, and agent waves. |
| `TRSTCTL_BULKHEAD_PROJECTIONS_WORKERS` / `TRSTCTL_BULKHEAD_PROJECTIONS_QUEUE` | `2` / `128` | Event-log projection work. Raise workers only when PostgreSQL and NATS have headroom. |
| `TRSTCTL_BULKHEAD_OUTBOX_WORKERS` / `TRSTCTL_BULKHEAD_OUTBOX_QUEUE` | `4` / `256` | External side effects: CA calls, connector deploys, webhooks, notifications. |
| `TRSTCTL_BULKHEAD_SIGNING_WORKERS` / `TRSTCTL_BULKHEAD_SIGNING_QUEUE` | `4` / `64` | Control-plane work waiting on signer RPC. Do not set this above signer capacity. |
| `TRSTCTL_BULKHEAD_QUERY_WORKERS` / `TRSTCTL_BULKHEAD_QUERY_QUEUE` | `4` / `64` | Heavy graph/risk/read queries that scale with inventory size. |
| `TRSTCTL_BULKHEAD_POLICY_WORKERS` / `TRSTCTL_BULKHEAD_POLICY_QUEUE` | `4` / `64` | OPA/Rego policy gate work. Saturation fails closed rather than blocking issuance. |
| `TRSTCTL_BULKHEAD_PROTOCOLS_WORKERS` / `TRSTCTL_BULKHEAD_PROTOCOLS_QUEUE` | `8` / `256` | ACME/EST/SCEP/CMP/SPIFFE/SSH/TSA enrollment protocol work. |
| `TRSTCTL_BULKHEAD_AGENT_WORKERS` / `TRSTCTL_BULKHEAD_AGENT_QUEUE` | `16` / `1024` | Agent heartbeat and renewal fan-in. Raise this first for large agent fleets. |

Fleet-size guidance:

| Shape | Starting point |
| --- | --- |
| Single-node eval or small production | Use defaults; tune only after `trstctl_*_bulkhead_*` rejection metrics show pressure. |
| About 1k agents | Increase agent queue first (for example 2048), then agent workers if PostgreSQL/signing have headroom. |
| Very large fleets | Scale agent, protocols, and outbox independently; keep API workers modest so operator traffic stays responsive while waves shed elsewhere. |

`trstctl --check-config` prints the effective `bulkheads.<subsystem>.workers` and
`bulkheads.<subsystem>.queue` values, so CI/CD can diff the resolved runtime limits
before a rollout.

## Config file

Any of the above can also be set in a JSON file named by `TRSTCTL_CONFIG_FILE`;
environment variables override file values, which override defaults.

```json
{
  "server": { "addr": ":8443" },
  "postgres": { "mode": "external", "dsn": "postgres://..." },
  "nats": { "mode": "external", "url": "nats://..." },
  "telemetry": { "enabled": false }
}
```
