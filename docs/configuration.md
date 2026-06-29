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
  `curl -k`); suitable for evaluation and internal or air-gapped use.
- **`file`** — the control plane presents an operator-provided certificate and
  key. Use this in production with a certificate from your CA. A missing or
  malformed file fails fast at startup rather than falling back to plaintext.
- **`disabled`** — plaintext HTTP. **Local development only** and mechanically
  bounded: startup fails unless `TRSTCTL_DEV_ALLOW_PLAINTEXT=true` and
  `TRSTCTL_SERVER_ADDR` is loopback-only (`localhost`, `127.0.0.1`, or `::1`).
  Production TLS termination should use `server.tls.mode=file` at trstctl or a
  TLS-terminating proxy in front of a TLS-enabled trstctl listener; disabled mode
  is not the production proxy pattern.

The control-plane↔signer channel (the private keys live in a separate, isolated
process) is independent of this setting. The
**default** (single-binary `child` mode, and `external` mode with `signer.socket`)
is a **peer-authenticated Unix domain socket** — a `0600` socket in a `0700`
directory, restricted to the signer's own uid via `SO_PEERCRED` on Linux — not a
TLS channel. For a **separately-hosted signer across nodes**, set
`signer.mtls_address` (with the `signer.mtls_*` certificate material): the control
plane then reaches the signer over **mTLS** — TLS 1.3, AEAD-only, with the control
plane and the signer each **pinning** the other's certificate (an untrusted or
merely CA-signed-but-unpinned peer is rejected, fail-closed). Exactly one of
`signer.socket` or `signer.mtls_address` is used in `external` mode; a partial mTLS
block fails closed at startup.

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
| `TRSTCTL_NATS_STORE_DIR` | `data/nats` | JetStream store directory for the embedded datastore. |
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

### Cross-cluster federation

Federation is disabled by default. When enabled on a passive cluster, the leader
worker imports a peer's event log into the local event log, advances a durable peer
cursor, and projects the imported events locally. The passive region therefore serves
from its own PostgreSQL and NATS after failover; it does not read the primary region's
PostgreSQL tables.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_FEDERATION_ENABLED` | `false` | Enable the leader-only peer import worker. |
| `TRSTCTL_FEDERATION_CLUSTER_ID` | — | Stable id for this cluster, for example `us-west-passive`; required when enabled. |
| `TRSTCTL_FEDERATION_REGION` | — | Human/operator region label for this cluster. |
| `TRSTCTL_FEDERATION_PEER_ID` | — | Stable id of the source cluster; required for env-configured single-peer federation. |
| `TRSTCTL_FEDERATION_PEER_REGION` | — | Human/operator region label for the source cluster. |
| `TRSTCTL_FEDERATION_PEER_NATS_URL` | — | Source cluster NATS URL. The source must expose its trstctl event stream over external NATS. |
| `TRSTCTL_FEDERATION_INTERVAL` | `1s` | How often the passive cluster polls the peer log. This is the main operator-tuned RPO knob. |
| `TRSTCTL_FEDERATION_RPO` | `5s` | Operator target for maximum accepted replication lag. Use this in runbooks and monitoring. |
| `TRSTCTL_FEDERATION_RTO` | `30s` | Operator target for passive-region promotion after traffic moves. |

JSON config can declare multiple peers under `federation.peers`; the environment
overlay above configures one common peer. Keep `ha.leader_election` on so one replica
owns imports while all replicas serve the replicated read state.

## Lifecycle

How far ahead of expiry trstctl renews and alerts. Values are Go durations.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_LIFECYCLE_RENEW_BEFORE` | `720h` (30 days) | Renew this far before expiry. |
| `TRSTCTL_LIFECYCLE_ALERT_BEFORE` | `336h` (14 days) | Alert this far before expiry. |

## Notifications

Notification channels are off until an operator configures them. When enabled, lifecycle
expiry alerts are written to the `notification.*` outbox first, then delivered by the
registered channel workers. Tenant-scoped routing policy authoring and channel-test
delivery are served from the console; channel secrets remain in operator-managed secret
references or files.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_NOTIFICATIONS_EMAIL_ENABLED` | `false` | Enable SMTP email delivery. |
| `TRSTCTL_NOTIFICATIONS_EMAIL_SMTP_ADDR` | empty | SMTP relay `host:port`. |
| `TRSTCTL_NOTIFICATIONS_EMAIL_FROM` | empty | RFC 5322 From address. |
| `TRSTCTL_NOTIFICATIONS_EMAIL_TO` | empty | Comma-separated recipient addresses. |
| `TRSTCTL_NOTIFICATIONS_EMAIL_USERNAME` | empty | Optional SMTP username. |
| `TRSTCTL_NOTIFICATIONS_EMAIL_PASSWORD` / `TRSTCTL_NOTIFICATIONS_EMAIL_PASSWORD_FILE` | empty | Optional SMTP password as bytes or a file. |
| `TRSTCTL_NOTIFICATIONS_SLACK_ENABLED` | `false` | Enable Slack incoming-webhook delivery. |
| `TRSTCTL_NOTIFICATIONS_SLACK_WEBHOOK_URL` | empty | Slack incoming-webhook URL. |
| `TRSTCTL_NOTIFICATIONS_TEAMS_ENABLED` | `false` | Enable Microsoft Teams incoming-webhook delivery. |
| `TRSTCTL_NOTIFICATIONS_TEAMS_WEBHOOK_URL` | empty | Teams webhook URL. |
| `TRSTCTL_NOTIFICATIONS_SMS_ENABLED` | `false` | Enable SMS gateway delivery. |
| `TRSTCTL_NOTIFICATIONS_SMS_ENDPOINT` | empty | HTTPS endpoint for the operator SMS gateway. |
| `TRSTCTL_NOTIFICATIONS_SMS_FROM` | empty | Optional sender label or number. |
| `TRSTCTL_NOTIFICATIONS_SMS_TO` | empty | Comma-separated SMS recipients. |
| `TRSTCTL_NOTIFICATIONS_SMS_TOKEN` / `TRSTCTL_NOTIFICATIONS_SMS_TOKEN_FILE` | empty | Optional gateway bearer token as bytes or a file. |
| `TRSTCTL_NOTIFICATIONS_SIEM_ENABLED` | `false` | Enable SIEM collector delivery. |
| `TRSTCTL_NOTIFICATIONS_SIEM_ENDPOINT` | empty | HTTPS endpoint for the SIEM collector or forwarding gateway. |
| `TRSTCTL_NOTIFICATIONS_SIEM_TOKEN` / `TRSTCTL_NOTIFICATIONS_SIEM_TOKEN_FILE` | empty | Optional collector bearer token as bytes or a file. |
| `TRSTCTL_NOTIFICATIONS_SIEM_SOURCE` | `trstctl` | Source label in SIEM events. |

## Telemetry

Telemetry is **off by default** and never sends anything unless you opt in. When
enabled, it sends only coarse, anonymized, non-PII data.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_TELEMETRY_ENABLED` | `false` | Set `true` to opt in. A malformed value is ignored (stays off). |
| `TRSTCTL_TELEMETRY_ENDPOINT` | `https://telemetry.trstctl.com/v1/usage` | Where reports go; must be `https`. |
| `TRSTCTL_TELEMETRY_INTERVAL` | `24h` | Reporting interval. |
| `TRSTCTL_TELEMETRY_INSTANCE_ID_FILE` | `data/telemetry/instance-id` | Local file holding the random anonymous instance ID. Required when telemetry is enabled. |

See [Telemetry](telemetry.md) for exactly what is and is not collected.

## Air-gap and outbound egress

Air-gap mode arms the no-phone-home outbound HTTP(S) guard. It is off by default;
when enabled, public destinations are blocked unless you explicitly allow a host
or CIDR. It is intended for disconnected networks and is paired with the Helm
`values-airgap.yaml` overlay described in [Air-gapped install](airgap.md).

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_AIRGAP_ENABLED` | `false` | Set `true` to deny public outbound HTTP(S) unless a host or CIDR is allowlisted. |
| `TRSTCTL_AIRGAP_ALLOW_PRIVATE` | `true` | Allows loopback, private, and link-local IP destinations. Leave true for private PostgreSQL/NATS/OTLP/local model endpoints. |
| `TRSTCTL_AIRGAP_ALLOW_HOSTS` | — | Comma-separated host allowlist for operator-owned local services such as `otel-collector.observability.svc`. Hosts only; URLs are rejected. |
| `TRSTCTL_AIRGAP_ALLOW_CIDRS` | — | Comma-separated CIDR allowlist for private service ranges, e.g. `10.0.0.0/8,172.16.0.0/12`. Invalid CIDRs fail startup. |

When `TRSTCTL_AIRGAP_ENABLED=true`, trstctl rejects
`TRSTCTL_TELEMETRY_ENABLED=true` and `TRSTCTL_AI_MODEL_MODE=cloud` at startup.
Local OTLP collectors and local AI runtimes are still allowed when their hosts or
CIDRs are private or explicitly allowlisted.

## OpenTelemetry export

OTLP export is **off by default** and sends data only to the collector endpoint you
configure. It is separate from product telemetry: use it to feed your own
OpenTelemetry Collector, Splunk, Datadog, or SIEM pipeline with served HTTP traces
and audit-event log records.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_OTLP_ENABLED` | `false` | Set `true` to enable OTLP/HTTP protobuf export. |
| `TRSTCTL_OTLP_ENDPOINT` | — | Absolute collector URL. HTTPS is required unless `TRSTCTL_OTLP_INSECURE=true`; the exporter posts to `/v1/traces` and `/v1/logs` under this base. |
| `TRSTCTL_OTLP_INSECURE` | `false` | Allows plaintext `http://` collector endpoints for local or private-network deployments. |
| `TRSTCTL_OTLP_BEARER_TOKEN` | — | Optional collector bearer token. Prefer the file setting for production secret mounts. |
| `TRSTCTL_OTLP_BEARER_TOKEN_FILE` | — | Optional file containing the collector bearer token. Mutually exclusive with `TRSTCTL_OTLP_BEARER_TOKEN`. |
| `TRSTCTL_OTLP_TIMEOUT` | `5s` | Per-export HTTP timeout. |
| `TRSTCTL_OTLP_QUEUE_SIZE` | `1024` | Bounded trace-export queue size. Full queues drop spans rather than slowing served API requests. |
| `TRSTCTL_OTLP_SERVICE_NAME` | `trstctl` | `service.name` resource attribute sent to the collector. |

In air-gap mode, point OTLP at an operator-owned collector on a private address or
add the collector host to `TRSTCTL_AIRGAP_ALLOW_HOSTS`; public collector SaaS
endpoints are blocked by the egress guard.

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

Subject erasure also pseudonymizes matching raw subject bytes in the hot JetStream
event store: the control plane records `privacy.subject.erased`, secure-deletes the
old hot stream messages, and republishes the same envelopes with the erased subject
replaced by its tenant-bound `erased:<subject_ref>` placeholder. This keeps future
hot-log replay, audit queries, and full backups taken after the erasure from carrying
the raw subject. Backups and signed audit archives created before the erasure are not
rewritten automatically; apply your legal-hold, WORM, and backup-deletion procedure
to those artifacts separately.

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

## Browser SSO

Browser sign-on is optional. Scoped API tokens still work when browser sign-on is off.
When it is on, each verified OIDC, SAML, or LDAP / Active Directory user must map to
exactly one trstctl tenant by subject, tenant claim, directory group, or an explicit
single-tenant fallback. Missing mappings fail the login closed instead of silently
dropping a user into the wrong tenant.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_AUTH_OIDC_ENABLED` | `false` | Enables served OIDC login at `/auth/login` and `/auth/callback`. |
| `TRSTCTL_AUTH_OIDC_ISSUER` | unset | Expected OIDC issuer. |
| `TRSTCTL_AUTH_OIDC_AUTHORIZATION_RESPONSE_ISS_PARAMETER_SUPPORTED` | `false` | Requires the callback `iss` parameter to match the issuer when the IdP advertises RFC 9207 support. |
| `TRSTCTL_AUTH_OIDC_CLIENT_ID` | unset | Expected OIDC audience / client id. |
| `TRSTCTL_AUTH_OIDC_CLIENT_SECRET_TENANT` / `TRSTCTL_AUTH_OIDC_CLIENT_SECRET_REF` | unset | Reads a confidential-client secret from the encrypted tenant-scoped credential store at `(tenant, auth.oidc, ref, client_secret)`. |
| `TRSTCTL_AUTH_OIDC_REDIRECT_URI` | unset | External callback URL, usually `https://trstctl.example.com/auth/callback`. |
| `TRSTCTL_AUTH_OIDC_JWKS_FILE` / `TRSTCTL_AUTH_OIDC_JWKS_JSON` | unset | IdP signing keys used for offline id_token verification. |
| `TRSTCTL_AUTH_SAML_ENABLED` | `false` | Enables the served SAML 2.0 SP. |
| `TRSTCTL_AUTH_SAML_ENTITY_ID` | unset | Stable SP entity ID, often the metadata URL. |
| `TRSTCTL_AUTH_SAML_METADATA_URL` | unset | External URL for `/auth/saml/metadata`. |
| `TRSTCTL_AUTH_SAML_ACS_URL` | unset | External assertion consumer service URL for `/auth/saml/acs`. |
| `TRSTCTL_AUTH_SAML_IDP_METADATA_FILE` / `TRSTCTL_AUTH_SAML_IDP_METADATA_XML` | unset | IdP metadata XML containing the signing certificate. |
| `TRSTCTL_AUTH_SAML_SESSION_SECRET_FILE` | unset | HMAC secret file used to sign browser sessions. |
| `TRSTCTL_AUTH_SAML_TENANT_CLAIM` | unset | SAML attribute whose value feeds tenant mapping. |
| `TRSTCTL_AUTH_SAML_GROUPS_CLAIM` | unset | SAML attribute whose values feed group-to-tenant mapping. |
| `TRSTCTL_AUTH_LDAP_ENABLED` | `false` | Enables served LDAP / Active Directory login at `POST /auth/ldap/login`. |
| `TRSTCTL_AUTH_LDAP_URL` | unset | Directory URL. Use `ldaps://` for production; `ldap://` is accepted only on loopback. |
| `TRSTCTL_AUTH_LDAP_USER_DN_TEMPLATE` | unset | Direct-bind DN template such as `uid={username},ou=people,dc=example,dc=org`. |
| `TRSTCTL_AUTH_LDAP_BIND_DN` / `TRSTCTL_AUTH_LDAP_BIND_PASSWORD_FILE` | unset | Optional read-only service bind for user and group searches. |
| `TRSTCTL_AUTH_LDAP_USER_SEARCH_BASE_DN` / `TRSTCTL_AUTH_LDAP_USER_FILTER` | unset | User lookup when no direct-bind template is used. |
| `TRSTCTL_AUTH_LDAP_GROUP_SEARCH_BASE_DN` / `TRSTCTL_AUTH_LDAP_GROUP_FILTER` | unset | Group lookup; `{user_dn}` and `{username}` are escaped before search. |
| `TRSTCTL_AUTH_LDAP_GROUP_NAME_ATTRIBUTE` | unset | Group attribute mapped to `tenant_mappings[].group`, usually `cn`. |
| `TRSTCTL_AUTH_LDAP_SESSION_SECRET_FILE` | unset | HMAC secret file used to sign browser sessions. |

## SCIM provisioning

SCIM 2.0 provisioning is optional and separate from browser sign-on. Enable it when
your identity provider should push users and groups into trstctl instead of an
operator maintaining role membership by hand. The served endpoint is `/scim/v2`:
IdPs use `POST /scim/v2/Users`, `PATCH /scim/v2/Users/{id}`,
`POST /scim/v2/Groups`, and `PATCH /scim/v2/Groups/{id}`.

Each SCIM bearer token is bound to exactly one tenant in config. trstctl reads the raw
token from `auth.scim.tokens[].token_file`, hashes it at startup, wipes the raw bytes,
and keeps only the hash. The token selects the tenant for every SCIM request; tenant
ids in SCIM payloads are ignored. Groups map to configured RBAC role names, so an IdP
group with display name `viewer` grants the built-in `viewer` role to its members.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_AUTH_SCIM_ENABLED` | `false` | Enables the served SCIM 2.0 provisioning surface under `/scim/v2`. |
| `TRSTCTL_AUTH_SCIM_TOKEN_NAME` | `scim` | Human label used in audit actor metadata for the single env-configured token. |
| `TRSTCTL_AUTH_SCIM_TOKEN_TENANT_ID` | unset | Tenant this SCIM token may provision. Required when SCIM is enabled through env. |
| `TRSTCTL_AUTH_SCIM_TOKEN_FILE` | unset | File containing the raw bearer token. Required when SCIM is enabled through env. |

Example multi-token SCIM config:

```yaml
auth:
  scim:
    enabled: true
    tokens:
      - name: okta-payments
        tenant_id: 22222222-2222-2222-2222-222222222222
        token_file: /etc/trstctl/scim/okta-payments.token
      - name: entra-platform
        tenant_id: 33333333-3333-3333-3333-333333333333
        token_file: /etc/trstctl/scim/entra-platform.token
```

Example SAML config:

```yaml
auth:
  saml:
    enabled: true
    entity_id: https://trstctl.example.com/auth/saml/metadata
    metadata_url: https://trstctl.example.com/auth/saml/metadata
    acs_url: https://trstctl.example.com/auth/saml/acs
    idp_metadata_file: /etc/trstctl/idp-metadata.xml
    session_secret_file: /var/lib/trstctl/saml-session.secret
    tenant_claim: tenant
    groups_claim: groups
    tenant_mappings:
      - subject: alice@example.com
        tenant_id: 11111111-1111-1111-1111-111111111111
        roles: [admin]
```

Example LDAP / Active Directory config:

```yaml
auth:
  ldap:
    enabled: true
    url: ldaps://ad.example.com:636
    bind_dn: cn=trstctl-reader,ou=service-accounts,dc=example,dc=com
    bind_password_file: /etc/trstctl/ldap-bind.secret
    user_search_base_dn: ou=people,dc=example,dc=com
    user_filter: "(sAMAccountName={username})"
    group_search_base_dn: ou=groups,dc=example,dc=com
    group_filter: "(member={user_dn})"
    group_name_attribute: cn
    email_attribute: mail
    session_secret_file: /var/lib/trstctl/ldap-session.secret
    tenant_mappings:
      - group: payments-trstctl-admins
        tenant_id: 22222222-2222-2222-2222-222222222222
        roles: [admin]
```

## ABAC deny overlay

ABAC is an optional deny-only overlay on top of RBAC. RBAC must grant the permission
first; the ABAC Rego module can then block the request using request attributes,
identity tags, operator-provided environment state, and time. This is useful for rules
such as "prod certs may issue only during change windows" or "break-glass actions may
run only from the platform project."

The module must declare `package trstctl.abac`, define boolean `deny`, and may define
string `reason`. Bad Rego fails startup. Runtime evaluation errors deny the request, and
policy-worker saturation returns `503` instead of allowing.

In a config file, the keys are `auth.abac.enabled`, `auth.abac.module`, and
`auth.abac.environment`.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_AUTH_ABAC_ENABLED` | `false` | Enables the ABAC deny overlay after RBAC on guarded API routes and on served issue/deploy/revoke lifecycle decisions. |
| `TRSTCTL_AUTH_ABAC_MODULE` | unset | Inline Rego module with `package trstctl.abac`, boolean `deny`, and optional string `reason`. Required when ABAC is enabled. |
| `TRSTCTL_AUTH_ABAC_ENVIRONMENT` | unset | Comma-separated operator state copied into `input.env`, for example `change_window=true,region=us-east-1`. |

Example ABAC config:

```yaml
auth:
  abac:
    enabled: true
    environment:
      change_window: "false"
    module: |
      package trstctl.abac
      default deny := false
      default reason := ""

      deny if {
        input.permission == "certs:issue"
        input.resource.env == "prod"
        input.env.change_window != "true"
      }

      reason := "prod certificates may issue only during a change window" if {
        deny
      }
```

## Break-glass reconciliation

Break-glass emergency issuance is an offline m-of-n operator ceremony. The served
control plane handles the recovery side: `POST /api/v1/breakglass/reconcile` accepts
signed offline bundles, verifies them against trust anchors pinned in process config,
and records verified facts as `breakglass.issued` events in the hash-chained audit log.
The request cannot supply its own verifier keys.

In a config file, the keys are `breakglass.enabled`, `breakglass.ca_cert_file`, and
`breakglass.public_key_file`. The files may be DER, or PEM with `CERTIFICATE` and
`PUBLIC KEY` blocks. If `breakglass.enabled=true`, both files are required and startup
fails closed when either is missing or unreadable.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_BREAKGLASS_ENABLED` | `false` | Enables `POST /api/v1/breakglass/reconcile`; offline issuance is still an operator ceremony. |
| `TRSTCTL_BREAKGLASS_CA_CERT_FILE` | unset | DER or PEM CA certificate that emergency bundle certificates must chain to. Required when enabled. |
| `TRSTCTL_BREAKGLASS_PUBLIC_KEY_FILE` | unset | DER or PEM public key that verifies the emergency bundle manifest signature. Required when enabled. |

Example break-glass reconciliation config:

```yaml
breakglass:
  enabled: true
  ca_cert_file: /etc/trstctl/breakglass-ca.pem
  public_key_file: /etc/trstctl/breakglass-public-key.pem
```

## Secrets (credentials at rest)

Upstream CA and connector credentials — API keys, passwords, client secrets — are
stored **encrypted at rest** using envelope encryption (R3.1): a fresh random
data-encryption key (DEK) encrypts each credential with AES-256-GCM, and the
**key-encryption key (KEK)** wraps the DEK. Only ciphertext is ever persisted; the
plaintext never appears in the database, in config dumps, or in logs. The
cryptography lives behind the platform's single crypto boundary.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_SECRETS_KEK_FILE` | `data/secrets/kek.bin` | Path to the 256-bit KEK that wraps every stored credential. It is **created `0600` on first boot** if absent, and is the root of trust for credentials at rest. |
| `TRSTCTL_SECRETS_ENABLE_API` | `false` | Enables the served `/api/v1/secrets/*` surface, including store, dynamic leases, sharing, PKI secret issuance, machine login, sync, and Gitleaks scans. It also enables the Vault/OpenBao-compatible common aliases under `/v1/auth/token/lookup-self`, `/v1/secret/data/*`, and `/v1/pki/issue/*`. |
| `TRSTCTL_SECRETS_AUTH_SECRET_FILE` | unset | Optional HMAC key file for machine-login token credentials. When unset, the login method fails closed while other secrets routes continue to work. |
| `TRSTCTL_SECRETS_GITLEAKS_BIN` | auto-detect | Path to the pinned Gitleaks `v8.27.2` binary used by `POST /api/v1/secrets/scans`. Empty resolves `TRSTCTL_GITLEAKS_BIN`, `tools/bin/gitleaks`, then `PATH`. Run `tools/gitleaks/install.sh` during image build or host provisioning to install the supported binary. A missing binary makes scan requests fail closed with `503`. |

Machine-auth methods beyond the HMAC token are configured in the JSON/YAML config
file under `secrets.machine_auth`. Each entry names one method: `kubernetes`,
`aws-iam`, `gcp`, `azure`, `oidc`, or `jwt`. JWT-family methods require
`audience` plus `jwks_file` or `jwks_json`, and must set either `tenant_claim`
(credential-bound tenancy) or `tenant_id` (tenant-pinned config). AWS IAM must set
`tenant_id` and `allowed_accounts` or `allowed_arns` because STS does not carry a
trstctl tenant claim.

Treat the credential-store KEK like the audit signing key: **protect it and back it
up** (a lost KEK means sealed credentials cannot be opened) with the same care
described in the [disaster-recovery runbook](disaster-recovery.md). This
credential-store KEK is still a local key file. Do not confuse it with Helm
`externalKMS`, which applies to the signer's CA key-store DEK wrapping described in
[Signer topology & CA custody](#signer-topology--ca-custody).
On reload, local KEK, auth-secret, and session-secret files are accepted only if
they are regular files, not symlinks, owned by the process user with
`0600`-or-stricter permissions or mounted as root-owned Kubernetes Secret files
readable by the pod's `fsGroup`, and all parent directories reject group/world
writes. Unsafe restored files fail startup instead of silently weakening key
custody.

## Managed-key custody (AWS KMS, Azure Key Vault HSM, GCP Cloud KMS, and PKCS#11 HSMs)

The managed-key lifecycle is off by default. When enabled, the control plane exposes
`/api/v1/managed-keys` for keys whose private material is born in and stays inside an
external custodian. The served custody providers are AWS KMS, Azure Key Vault /
Managed HSM, GCP Cloud KMS, and PKCS#11 HSM modules such as SoftHSM, nShield, and
Luna. AWS KMS uses the official AWS SDK v2 KMS client, with the SDK HTTP client
option pointed at LocalStack, a VPC endpoint, or regional AWS as configured. Azure
and GCP use their data-plane KMS APIs over bounded HTTP clients with startup-supplied
bearer tokens. PKCS#11 uses a cgo-enabled build to open the native module, log in to
a named token, and generate non-extractable signing keys on the token.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_MANAGED_KEYS_ENABLED` | `false` | Enables the served managed-key lifecycle. When false, the routes fail closed with `501`. |
| `TRSTCTL_MANAGED_KEYS_PROVIDER` | `aws` | Custody provider: `aws`, `azure-key-vault`, `gcp-kms`, or `pkcs11`. The provider is selected at startup and injected into the control plane; it is not a runtime plugin engine. |
| `TRSTCTL_MANAGED_KEYS_AWS_REGION` | unset | AWS region for KMS, for example `us-east-1`. Required when enabled. |
| `TRSTCTL_MANAGED_KEYS_AWS_ENDPOINT` | unset | Optional absolute `http(s)` endpoint override, used for LocalStack, VPC endpoints, or partitions. Leave unset for regional AWS KMS. |
| `TRSTCTL_MANAGED_KEYS_AWS_ACCESS_KEY_ID` | unset | AWS access key id. Required for the current served AWS KMS backend. |
| `TRSTCTL_MANAGED_KEYS_AWS_SECRET_ACCESS_KEY` | unset | AWS secret access key supplied from the environment as bytes at startup. Prefer the file variant for production. |
| `TRSTCTL_MANAGED_KEYS_AWS_SECRET_ACCESS_KEY_FILE` | unset | File containing the AWS secret access key. Startup reads it, constructs the backend, and wipes the temporary file buffer. |
| `TRSTCTL_MANAGED_KEYS_AWS_SESSION_TOKEN` | unset | Optional temporary session token. |
| `TRSTCTL_MANAGED_KEYS_AWS_SESSION_TOKEN_FILE` | unset | Optional file containing the temporary session token. |
| `TRSTCTL_MANAGED_KEYS_AZURE_VAULT_URL` | unset | Azure Key Vault or Managed HSM vault URL, for example `https://trstctl-prod.managedhsm.azure.net`. Required when provider is `azure-key-vault`. |
| `TRSTCTL_MANAGED_KEYS_AZURE_ENDPOINT` | unset | Optional absolute `http(s)` endpoint override for private endpoints or tests. Leave unset for the vault URL. |
| `TRSTCTL_MANAGED_KEYS_AZURE_BEARER_TOKEN` | unset | Azure AD access token supplied from the environment as bytes at startup. Prefer the file variant for production. |
| `TRSTCTL_MANAGED_KEYS_AZURE_BEARER_TOKEN_FILE` | unset | File containing the Azure bearer token. Startup reads it, constructs the backend, and wipes the temporary file buffer. |
| `TRSTCTL_MANAGED_KEYS_GCP_PARENT` | unset | GCP Cloud KMS key-ring resource, for example `projects/P/locations/L/keyRings/R`. Required when provider is `gcp-kms`. |
| `TRSTCTL_MANAGED_KEYS_GCP_ENDPOINT` | unset | Optional absolute `http(s)` endpoint override for private service endpoints or tests. Leave unset for `https://cloudkms.googleapis.com/v1`. |
| `TRSTCTL_MANAGED_KEYS_GCP_BEARER_TOKEN` | unset | GCP OAuth2 access token supplied from the environment as bytes at startup. Prefer the file variant for production. |
| `TRSTCTL_MANAGED_KEYS_GCP_BEARER_TOKEN_FILE` | unset | File containing the GCP bearer token. Startup reads it, constructs the backend, and wipes the temporary file buffer. |
| `TRSTCTL_MANAGED_KEYS_PKCS11_MODULE_PATH` | unset | Native PKCS#11 module path, for example `libsofthsm2.so`, nShield `cknfast`, or Luna `Cryptoki`. Required when provider is `pkcs11`. |
| `TRSTCTL_MANAGED_KEYS_PKCS11_TOKEN_LABEL` | unset | Initialized token label to log in to. Required when provider is `pkcs11`. |
| `TRSTCTL_MANAGED_KEYS_PKCS11_USER_PIN` | unset | PKCS#11 user PIN supplied from the environment as bytes at startup. Prefer the file variant for production. |
| `TRSTCTL_MANAGED_KEYS_PKCS11_USER_PIN_FILE` | unset | File containing the PKCS#11 user PIN. Startup reads it, constructs the backend, and wipes the temporary file buffer. |
| `TRSTCTL_MANAGED_KEYS_PKCS11_KEY_LABEL_PREFIX` | `trstctl-pkcs11` | Label prefix for generated token objects. |

Example LocalStack configuration:

```bash
export TRSTCTL_MANAGED_KEYS_ENABLED=true
export TRSTCTL_MANAGED_KEYS_PROVIDER=aws
export TRSTCTL_MANAGED_KEYS_AWS_REGION=us-east-1
export TRSTCTL_MANAGED_KEYS_AWS_ENDPOINT=http://127.0.0.1:4566
export TRSTCTL_MANAGED_KEYS_AWS_ACCESS_KEY_ID=test
export TRSTCTL_MANAGED_KEYS_AWS_SECRET_ACCESS_KEY=test
```

Example production shape:

```yaml
managed_keys:
  enabled: true
  provider: aws
  aws:
    region: us-east-1
    access_key_id: AKIA...
    secret_access_key_file: /etc/trstctl/aws-kms-secret-access-key
```

Example Azure Key Vault HSM shape:

```yaml
managed_keys:
  enabled: true
  provider: azure-key-vault
  azure:
    vault_url: https://trstctl-prod.managedhsm.azure.net
    bearer_token_file: /etc/trstctl/azure-kv-token
```

Example GCP Cloud KMS shape:

```yaml
managed_keys:
  enabled: true
  provider: gcp-kms
  gcp:
    parent: projects/prod/locations/us/keyRings/trstctl
    bearer_token_file: /etc/trstctl/gcp-kms-token
```

Example PKCS#11 HSM shape:

```yaml
managed_keys:
  enabled: true
  provider: pkcs11
  pkcs11:
    module_path: /usr/lib/softhsm/libsofthsm2.so
    token_label: trstctl-prod
    user_pin_file: /etc/trstctl/pkcs11-user-pin
    key_label_prefix: trstctl-ca
```

Static no-cgo builds fail closed if `provider: pkcs11` is selected. Build the
managed-key package with cgo enabled for local HSM custody so the native module can
be loaded.

After startup, operators with `keys:write` can call `POST /api/v1/managed-keys` to
generate an HSM/KMS-resident signing key, then rotate, revoke, or zeroize it through the
matching served routes and `trstctl managed-keys` CLI commands. Requests are
tenant-scoped, require `Idempotency-Key`, and emit immutable lifecycle events that
contain key id, version, algorithm, state, and public key only.

## Signer topology & CA custody

The private-key operations run in a separate, sacred process, so the CA keys never
live in the API process. Its issuing **CA key is persisted, sealed at rest** (R3.2)
so a restart preserves the CA instead of silently rotating it. The signer can run
two ways:

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_SIGNER_MODE` | `child` | `child`: the control plane supervises `trstctl-signer` as a child process (single binary). `external`: it connects to a **separately deployed** signer service over a UDS (`TRSTCTL_SIGNER_SOCKET`) or, across nodes, mTLS (`TRSTCTL_SIGNER_MTLS_ADDRESS`). |
| `TRSTCTL_SIGNER_SOCKET` | — | The signer's Unix-domain socket. In `external` mode set **either** this **or** `TRSTCTL_SIGNER_MTLS_ADDRESS`; in `child` mode a temp socket is used if unset. |
| `TRSTCTL_SIGNER_KEY_STORE_DIR` | `data/signer/keys` | Directory where the signer **seals its keys at rest** (child mode passes it to the signer; in external mode set it on the signer service). |
| `TRSTCTL_SIGNER_AUTH_SECRET_FILE` | `data/signer/sign-auth.bin` | Signer-side content-authorization verifier secret. The signer uses it to verify dual-control tokens before using privileged handles. Do not mount it into the control plane in production. |
| `TRSTCTL_SIGNER_AUTH_TOKEN_COMMAND` | — | Independent approval-token command used by the control plane in production. The command receives sign-intent JSON on stdin and returns the raw token as base64 on stdout. |
| `TRSTCTL_SIGNER_ALLOW_CO_RESIDENT_AUTHORIZER` | `true` in single-node eval defaults | Evaluation-only escape hatch that lets the control plane mint signer tokens from `TRSTCTL_SIGNER_AUTH_SECRET_FILE`. Production-like external NATS deployments reject it; use `TRSTCTL_SIGNER_AUTH_TOKEN_COMMAND` instead. |
| `TRSTCTL_SIGNER_ALLOW_INSECURE_DEV_NONLINUX` | `false` | Local-development-only escape hatch for running child signer mode on non-Linux hosts. Without it, `trstctl-signer` refuses startup when process hardening, UDS peer UID checks, and locked memory are unavailable. Do not set it in production. |
| `TRSTCTL_SIGNER_MTLS_ADDRESS` | — | `host:port` of a separately-hosted signer's **mTLS** listener. When set (in `external` mode), the control plane reaches the signer over TLS 1.3 mutual auth with **both-ways certificate pinning** instead of a UDS. Mutually exclusive with `TRSTCTL_SIGNER_SOCKET`. |
| `TRSTCTL_SIGNER_MTLS_SERVER_NAME` | — | The signer certificate's expected SAN, verified by the control plane. **Required** when `TRSTCTL_SIGNER_MTLS_ADDRESS` is set. |
| `TRSTCTL_SIGNER_MTLS_CERT_FILE` / `…_KEY_FILE` | — | The control plane's own **client** certificate and key (PEM) presented on the mTLS channel. Required with `…_MTLS_ADDRESS`. |
| `TRSTCTL_SIGNER_MTLS_PEER_CA_FILE` | — | PEM CA bundle anchoring the **signer's** certificate. Required with `…_MTLS_ADDRESS`. |
| `TRSTCTL_SIGNER_MTLS_PEER_PIN` | — | Hex SHA-256 of the **signer** certificate's public key, pinned by the control plane. Required with `…_MTLS_ADDRESS`. |
| `TRSTCTL_CA_CERT_FILE` | `data/ca/issuing-ca.crt` | Where the issuing CA's self-signed certificate is persisted, so the control plane **reuses the same CA cert** across restarts. |

In Helm deployments, the signer key store uses local KEK custody by default:
`kek.existingSecret` or eval-only `kek.generate=true` mounts
`/etc/trstctl/kek/kek.bin` and the chart passes `--kek` to `trstctl-signer`.
Regulated deployments can instead set:

```yaml
externalKMS:
  enabled: true
  provider: awskms        # awskms | gcpkms | azurekv | pkcs11
  keyRef: arn:aws:kms:us-east-1:111122223333:key/trstctl-signer
  wrapCommand: /usr/local/bin/trstctl-kms-wrap
  timeout: 10s
```

With `externalKMS.enabled=true`, the chart passes `--kms-provider`,
`--kms-key-ref`, `--kms-wrap-command`, and `--kms-timeout` to the signer and does
not mount the local KEK Secret. The signer invokes the adapter without a shell as
`<wrapCommand> wrap|unwrap <provider> <keyRef>`, with DEK bytes only on
stdin/stdout. Missing provider/keyRef/command values, unsupported provider names,
or a relative command path fail at template time.

Back up the sealed key store, the signer custody input, and the CA cert together
(the CA-key recovery set) per the [disaster-recovery runbook](disaster-recovery.md).
For local-KEK mode that custody input is the signer KEK Secret; for externalKMS
mode it is access to the same provider keyRef plus the wrapper adapter and provider
credentials. The
[`docker-compose.yml`](https://github.com/ctlplne/trstctl/blob/main/deploy/docker/docker-compose.yml)
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
  status pointer (composing with the served-leaf profile);
- and, when `ca.require_fips=true` is declared, the **FIPS 140-3 module is active**
  (the binary was built with `GOFIPS140=v1.0.0` / `make fips-build`, or run with
  `GODEBUG=fips140=on`).

A **complete** regulated config boots normally. The default posture
(`ca.governance_mode` unset, or `standard`) imposes no coupling, so existing
single-node deployments are unaffected.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_CA_GOVERNANCE_MODE` | `standard` | `standard` (or unset): the controls are independent. `regulated`: fail startup unless the policy gate, four-eyes dual control, a bound default profile, revocation publication, and any declared FIPS requirement are **all** present together. |
| `TRSTCTL_CA_REQUIRE_FIPS` | `false` | In `regulated` mode, additionally require the FIPS 140-3 module to be active (build with `GOFIPS140=v1.0.0` or run with `GODEBUG=fips140=on`); otherwise startup fails closed. Ignored outside regulated mode. |

## Served AI surface and model adapter

The AI/RCA/MCP surface is off by default. MCP investigation tools are read-only when
enabled; MCP write tools require the separate `TRSTCTL_AI_MCP_WRITE_TOOLS=true`
operator opt-in. The model adapter is separately off by default: with
`TRSTCTL_AI_MODEL_MODE=off` (or unset), query/RCA still return grounded citations, but
no prompt leaves the process.
`GET /api/v1/ai/status` reports the live enabled state, model mode, endpoint host,
egress class, and redaction/refusal posture without echoing the full endpoint URL.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_AI_ENABLE_API` | `false` | Serve `/api/v1/ai/status`, `/api/v1/ai/query`, `/api/v1/ai/rca`, and `/api/v1/mcp/tools*` behind auth/RBAC. |
| `TRSTCTL_AI_MCP_IDENTITY` | — | Workload identity label the MCP server presents. |
| `TRSTCTL_AI_MCP_WRITE_TOOLS` | `false` | Expose guarded MCP write tools (`issue_certificate`, `rotate_certificate`). Calls still require `certs:issue`, an `Idempotency-Key`, and are audited as `mcp.tool.write`. |
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

## Served protocol listeners

ACME, EST, SCEP, CMP, SPIFFE, SSH, and KMIP protocol surfaces are opt-in until they are
explicitly bound to a tenant. That startup check is intentional: a public protocol
endpoint must know the tenant it acts for before it is exposed. KMIP is a raw mTLS TCP
listener, not an HTTP route, so it additionally requires server certificate/key files
and a client CA trust anchor.

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
| `TRSTCTL_PROTOCOLS_KMIP_ENABLED` / `…_TENANT_ID` | `false` / — | Serve the KMIP mTLS listener for the named tenant. The current served profile supports AES-256 SymmetricKey Create/Get. |
| `TRSTCTL_PROTOCOLS_KMIP_ADDR` | `:5696` | TCP listen address for KMIP. |
| `TRSTCTL_PROTOCOLS_KMIP_CERT_FILE` | — | PEM server certificate chain for the KMIP listener. Required when KMIP is enabled. |
| `TRSTCTL_PROTOCOLS_KMIP_KEY_FILE` | — | PEM private key for the KMIP listener certificate. Required when KMIP is enabled. |
| `TRSTCTL_PROTOCOLS_KMIP_CLIENT_CA_FILE` | — | PEM CA bundle used to verify KMIP client certificates. Required when KMIP is enabled. |
| `TRSTCTL_PROTOCOLS_SPIFFE_ENABLED` / `…_TENANT_ID` | `false` / — | Serve the SPIFFE Workload API UDS for the named tenant. Requires `TRSTCTL_PROTOCOLS_SPIFFE_TRUST_DOMAIN`. |
| `TRSTCTL_PROTOCOLS_SPIFFE_SOCKET_PATH` | `/tmp/trstctl-spiffe-workload.sock` | UDS path for the SPIFFE Workload API when enabled. |
| `TRSTCTL_PROTOCOLS_SPIFFE_TRUST_DOMAIN` | — | SPIFFE trust domain, for example `example.org`. Required when SPIFFE is enabled. |
| `TRSTCTL_PROTOCOLS_SSH_ENABLED` / `…_TENANT_ID` | `false` / — | Serve the SSH CA JSON endpoints and KRL for the named tenant. |

## WASM plugins

The WASM plugin surface is off by default. When enabled, the binary admits only signed
modules whose detached Ed25519 signature verifies against the configured trusted keys.
CA plugins become external CA entries of type `wasm-ca`; connector plugins handle
matching deployment work from the outbox.

| Variable | Default | Meaning |
| --- | --- | --- |
| `TRSTCTL_PLUGINS_ENABLED` | `false` | Load signed WASM plugins at startup. |
| `TRSTCTL_PLUGINS_CA_DIR` | — | Directory containing signed CA plugin pairs: `<name>.wasm` and `<name>.wasm.sig`. |
| `TRSTCTL_PLUGINS_CONNECTOR_DIR` | — | Directory containing signed connector plugin pairs. |
| `TRSTCTL_PLUGINS_DIR` | — | Legacy connector-plugin directory alias. Ignored when `TRSTCTL_PLUGINS_CONNECTOR_DIR` is set. |
| `TRSTCTL_PLUGINS_TRUSTED_KEY_FILES` | — | Comma-separated PEM Ed25519 public keys trusted to sign plugin artifacts. Required when plugins are enabled. |
| `TRSTCTL_PLUGINS_PINNED_DIGESTS` | — | Optional comma-separated SHA-256 artifact digests that must match admitted modules exactly. |
| `TRSTCTL_PLUGINS_CAPABILITIES` | — | Comma-separated capabilities granted to loaded plugins, such as `fs.write` or `net.dial`. Empty grants no privileged host operation. |
| `TRSTCTL_PLUGINS_PATH_PREFIXES` | — | Optional comma-separated filesystem prefixes constraining `fs.read` and `fs.write`. |

## SPIRE upstream authority plugin

When SPIRE should keep serving workload SVIDs but trstctl should own the upstream CA,
configure SPIRE's `UpstreamAuthority "trstctl"` plugin. SPIRE passes this as HCL
`plugin_data` to the `trstctl-spire-upstream-authority` process; these are not trstctl
environment variables.

| Field | Required | Meaning |
| --- | --- | --- |
| `endpoint` | yes | Base URL of the trstctl control plane, for example `https://trstctl.example.com:8443`. The plugin calls `/api/v1/ca/authorities/{id}/intermediates/csr`. |
| `ca_authority_id` | yes | The trstctl CA authority that signs SPIRE's intermediate CA CSR. |
| `token_file` | yes | File containing a trstctl API token with `certs:issue`. Mount it as a secret file readable only by the SPIRE server process. |
| `common_name` | no | Subject common name for the SPIRE intermediate; defaults to `SPIRE Server CA`. |
| `ttl_seconds` | no | Intermediate CA TTL. If SPIRE sends a preferred TTL, the plugin honors SPIRE's value for that mint. |
| `max_path_len` | no | Path length for the SPIRE intermediate; use `0` so it can sign workload leaves but not another CA below it. |
| `permitted_dns_domains` | no | Optional DNS name constraints copied into the intermediate CA profile. |
| `extended_key_usages` | no | Optional extended key usages to request for the intermediate profile. |
| `idempotency_prefix` | no | Prefix for the stable `Idempotency-Key`; defaults to `spire-upstream`. |

Example:

```hcl
UpstreamAuthority "trstctl" {
  plugin_cmd = "/opt/spire/plugins/trstctl-spire-upstream-authority"
  plugin_data {
    endpoint = "https://trstctl.example.com:8443"
    ca_authority_id = "11111111-1111-1111-1111-111111111111"
    token_file = "/run/secrets/trstctl-spire-token"
    common_name = "SPIRE Server CA"
    ttl_seconds = 3600
    max_path_len = 0
    permitted_dns_domains = ["example.org"]
  }
}
```

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

Each subsystem runs on its own bounded worker pool. `workers` caps concurrent
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
| `TRSTCTL_BULKHEAD_CBOM_WORKERS` / `TRSTCTL_BULKHEAD_CBOM_QUEUE` | `4` / `64` | CBOM TLS/config scans. Raise only when broad crypto-inventory sweeps are saturating and PostgreSQL/NATS have headroom. |

Fleet-size guidance:

| Shape | Starting point |
| --- | --- |
| Single-node eval or small production | Use defaults; tune only after `trstctl_*_bulkhead_*` rejection metrics show pressure. |
| About 1k agents | Increase agent queue first (for example 2048), then agent workers if PostgreSQL/signing have headroom. |
| Very large fleets | Scale agent, protocols, CBOM, and outbox independently; keep API workers modest so operator traffic stays responsive while waves shed elsewhere. |

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
  "telemetry": { "enabled": false, "instance_id_file": "data/telemetry/instance-id" }
}
```
