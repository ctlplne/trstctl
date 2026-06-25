# Secrets — store, issue, rotate, and encrypt the credentials machines use

## What it is

A [secret](../glossary.md) is any sensitive value software needs but shouldn't expose:
a database password, an API token, an encryption key. trstctl is a full secrets
platform alongside its certificate work — it stores secrets encrypted, hands out
short-lived ones on demand, rotates them safely, encrypts data on behalf of apps,
syncs secrets to other platforms, and governs who can read or change them.

The mental model: think of a bank. The **vault** stores valuables encrypted (the secret
store). The **safe-deposit clerk** issues a temporary key that self-destructs after an
hour (dynamic secrets). The **armored-car service** moves valuables to other branches
(secret sync). The **teller window** encrypts your deposit without you ever seeing the
master key (encryption-as-a-service). And every action needs ID and is logged
(auth + approvals + audit).

> **One honest note up front.** Most of the *secrets* domain is now **served**: the
> **secret store** (CRUD + rotation), **dynamic secret leases**, **one-time secret
> sharing**, the **dynamic PKI secret**, **machine login**, **secret-sync**, **secret
> scanning**, and **ephemeral API keys** are mounted on the running control plane.
> The `/api/v1/secrets/*` surface is off by default (`secrets.enable_api`) and
> fail-closed when off; ephemeral API keys live under `/api/v1/ephemeral/api-keys`
> because they mint tenant API credentials, not stored secret values. **Transit/KMIP**
> remains built-and-tested library code with no served encrypt/decrypt listener yet.
> See [Current limitations](../limitations.md). This page is honest about that
> throughout.

## Why it exists

Leaked secrets are one of the most common breach causes, because the traditional
approach — long-lived secrets copied into config files, environment variables, images,
and CI — spreads them everywhere and never expires them. trstctl attacks the problem
from every side: encrypt them properly at rest, prefer short-lived/dynamic secrets that
can't be hoarded, rotate the long-lived ones automatically, never let a secret value
touch a log or a disk it shouldn't, and put approvals and a tamper-evident audit trail
around access. Secret material is always held in wipeable `[]byte` buffers that are
zeroed after use, never a Go `string` (Go can copy strings freely, so a value placed in
one can linger in memory beyond your control).

## How it works

### How every secret is encrypted at rest

trstctl uses **[envelope encryption](../glossary.md)**, and all of it runs through the
single isolated cryptography path. Each secret is encrypted with a fresh per-secret data
key (DEK, AES-256-GCM), and that DEK is itself encrypted under a master key-encryption key
(KEK). The encryption is bound to the secret's tenant and path, so a sealed blob can't be
moved elsewhere. The KEK is loaded at startup from `TRSTCTL_SECRETS_KEK_FILE` (0600),
held only transiently, and zeroized. To rotate protection you re-wrap small DEKs, not all
your data.

### The native secret store (F63)

A served, tenant-isolated key-value store for application secrets. `POST
/api/v1/secrets/store` creates version 1, `PUT /api/v1/secrets/store/{name}` writes the
next version, and `GET /api/v1/secrets/store/{name}` explicitly reveals only the latest
value to a caller with `secrets:read`. Metadata responses list names, versions, and
timestamps only; they never carry values.

SEC-01 adds durable sealed version history. Every create, rotation, and recovery stores a
row in `secret_store_versions` under PostgreSQL row-level security, and emits
`secret.version.written` without plaintext. Operators can read a prior version with
`GET /api/v1/secrets/store/history/{name}?version=N`, then recover the version that was
current at a timestamp with `POST /api/v1/secrets/store/recover/{name}` and body
`{"at":"2026-06-25T12:00:00Z"}`. Recovery creates the next monotonic version, so
rollbacks are auditable instead of overwriting history. `DELETE
/api/v1/secrets/store/{name}` purges the current row and its sealed history for that
tenant; another tenant still gets a 404 because both tables are RLS-scoped.

SEC-02 adds explicit reference resolution and imports to that same served path.
Secret values may contain `${secret.path}` placeholders. A normal read returns the
literal stored value, so callers do not accidentally expand more secret material than
they asked for; `GET /api/v1/secrets/store/{name}?resolve=true` expands references
for the same tenant and permission scope. Cycles such as `a -> b -> a` are rejected
with a structured `409` problem response that includes the cycle path. Missing
references return a normal `404`.

Bulk imports use `POST /api/v1/secrets/store/import` with a body like
`{"prefix":"app","values":{"db/user":"svc","db/dsn":"postgres://${secret.app/db/user}@db"}}`.
Each imported value is sealed independently as version 1, the response contains only
metadata, and if any imported name already exists the whole import is rejected so a
tree cannot half-land.

The credential store the running control plane mounts is the **served seal path**: it
seals through a versioned binary container, and its key-encryption key is loaded into
locked, zeroizable memory at startup — never held as a raw byte slice on the heap.

An older store core is retained for **legacy event replay and compatibility**. It now also
holds its KEK behind the same locked-memory boundary and seals with the binary container,
and its reconstruction still replays both the current container and earlier
JSON-envelope history; new production writes go through the served seal path above, not
here.

### The developer secrets experience (F64)

Two pieces make secrets pleasant *and* safe for developers. `trstctl-cli run` fetches
named secrets from the served store and runs your program with those values in the
child environment without writing them to disk. The fetch goes through the normal
`GET /api/v1/secrets/store/{name}` RBAC path; only variable names and secret paths are
audited, never values. An **SDK** caches secrets and auto-refreshes them before expiry,
and on a revocation it evicts the cache and fails safe rather than serving a stale,
revoked secret.

```sh
trstctl-cli run --secret DB_PASSWORD=db/password -- env
trstctl-cli run --resolve --secret DATABASE_URL=app/db/dsn -- ./payments-api
```

The `--resolve` flag deliberately maps to `?resolve=true`; without it, a stored value
such as `${secret.app/db/password}` is passed through literally instead of expanding
more material than the operator asked for. After the child exits, trstctl wipes the
byte-backed secret copies it fetched. The operating-system environment itself is still
an edge string API, so operators should use `run` for trusted child processes and avoid
debug commands that print their full environment.

Developers can also load application configuration as a tree with `trstctl-cli secrets
store import --body-file import.json` and can ask for an explicit resolved read with
`trstctl-cli secrets store get NAME --resolve=true`. This is intentionally opt-in:
plain reads show the stored value, while resolved reads expand `${secret.path}`
references, detect cycles, and stay within the caller's tenant/RBAC scope.

### Dynamic secrets (F65) and PKI-as-a-secrets-engine (F67)

Instead of a long-lived secret to steal, **dynamic secrets** are minted on demand,
scoped, and time-limited by a [lease](../glossary.md); when the lease expires trstctl
revokes the underlying credential automatically — even across a restart, because the
revocation intent is journaled first to a durable [outbox](../glossary.md) and delivered
at-least-once, so a crash can't silently drop it. Eight concrete backends ship behind
one interface: PostgreSQL, MySQL, MongoDB, AWS IAM, GCP IAM, Azure Entra, Kubernetes
ServiceAccount tokens, and Redis ACL users. PostgreSQL is exercised against a real
database process in CI; Redis, Kubernetes, and the cloud IAM providers speak their real
wire protocols against in-process emulators; MySQL and MongoDB expose driver-facing
admin seams so production adapters create and revoke actual scoped users.

The running control plane mounts the dynamic lease lifecycle when `secrets.enable_api`
is on and the operator wires provider backends:

- `POST /api/v1/secrets/leases` issues exactly one credential copy for a provider,
  role, and TTL, guarded by `secrets:write` plus `Idempotency-Key`.
- `GET /api/v1/secrets/leases/{lease_id}` returns lease metadata only; it does not
  replay the credential value after first issue.
- `POST /api/v1/secrets/leases/{lease_id}/renew` extends an active lease without
  returning the credential again.
- `POST /api/v1/secrets/leases/{lease_id}/revoke` closes the lease and queues backend
  revocation through the outbox-backed worker.

**PKI-as-a-secrets-engine** plugs the
same lease machinery into certificate issuance — a developer requests a short-lived
certificate exactly like a database password, and the leaf key is generated in wipeable
memory and zeroed immediately after use.

### Secret rotation (F37)

The rotation engine replaces a long-lived secret in **four rollback-safe phases**: stage
the new version, cut consumers over, verify they're healthy, retire the old one. If
cutover or verification fails, it **automatically rolls back** so the application is never
left broken. If backend rollback itself fails, the report sets `RollbackAttempted` and
`RollbackFailed`, leaves `RolledBack` false, and audits `rotation.rollback_failed` so
operators know the consumer may be on the new secret and needs intervention.

The running control plane serves that workflow at `POST /api/v1/secrets/rotations`.
The request names a provider, the consumer key, and the current backend reference; the
response returns only non-secret rotation evidence (`old_ref`, `new_ref`, completed /
rolled-back flags, and failure phase). PostgreSQL, MySQL, and AWS IAM rotators ship as
concrete backends. PostgreSQL is verified against a real database process: stage creates
a new login, cutover publishes the new credential to the configured consumer pointer,
verify logs in with it, retire drops the old login, and rollback restores the old
credential while revoking the staged login.

### Ephemeral API keys (F38)

For high-churn automation, trstctl issues short-lived API keys through the served
control plane:

- `POST /api/v1/ephemeral/api-keys` mints a tenant API token with `subject`, `scopes`,
  and `ttl_seconds`.
- `trstctl-cli ephemeral api-keys issue -f body.json` drives the same route.
- The route is guarded by `access:write` and still requires `Idempotency-Key`, so a
  retry returns the original response instead of minting twice.
- The response returns the raw `trst_...` token once. The event log stores only the
  token hash in `api_token.created`; the raw token is never persisted or emitted.
- The served leaseworker sweeps expired keys and emits `api_token.revoked`, so the
  read model shows `revoked_at` evidence and authentication rejects the key after TTL.

Example body:

```json
{
  "subject": "ci-preview-deploy",
  "scopes": ["access:read"],
  "ttl_seconds": 900
}
```

Use this for short CI jobs, deploy previews, partner imports, and other machine
workflows that need a narrow bearer credential for minutes rather than a reusable
long-lived API key.

### Encryption-as-a-service & KMIP (F66)

The **transit** library encrypts, decrypts, HMACs, and signs data using named keys the
application *never sees* — ciphertexts are versioned (`trv:<version>:...`) so a key
rotation can re-wrap old data, and intermediate plaintext is held in wipeable memory and
zeroed after use. For legacy enterprise gear (databases, storage arrays), the **KMIP**
library has a bounded TTLV RequestMessage parser plus TLS client-cert-authenticated
operation model with key material zeroed on destroy. No served transit or KMIP API/CLI
surface exists yet; the console marks it library-only until a listener is mounted.

### Secret sync (F68)

trstctl can push secrets *outward* to the platforms that need them — Kubernetes, GitHub
Actions, AWS Secrets Manager, GitLab CI, Terraform Cloud, Vercel, Azure Key Vault, GCP
Secret Manager, or a generic webhook-style target — via the durable outbox (journaled
first, delivered at-least-once, no half-writes). The running control plane serves this
at `POST /api/v1/secrets/syncs`: it reads a stored secret, writes a sealed outbox row in
the same tenant-scoped transaction path, delivers through the configured target pusher,
and returns metadata only (`name`, `target`, `remote_key`, enqueued/delivered flags).
The shipped concrete pushers cover GitHub Actions, AWS Secrets Manager, and Kubernetes;
the JSON pusher covers Vercel/GitLab/Terraform/GCP/Azure style fixtures and manual
integrations until those providers grow deeper native APIs.

### The auth-method framework (F58)

Before a workload can read a secret, it has to authenticate *to* trstctl. The auth-method
framework is that login layer: a workload presents a credential (a token, an OIDC JWT, a
Kubernetes SA token, cloud IAM, etc.), trstctl verifies it through the single isolated
cryptography path (timing-safe), and issues a scoped, time-bounded **session**. Credential
bytes are never logged (held in wipeable memory, never a copyable string); every attempt
is recorded as an immutable event in the tamper-evident log.

`POST /api/v1/secrets/login` now serves the six high-demand machine methods:
`token`, `kubernetes`, `aws-iam`, `gcp`, `azure`, `oidc`, and `jwt`. JWT-family
methods verify against an operator-supplied JWKS, check issuer/audience/expiry, and
either bind a tenant claim or pin the method to one tenant. AWS IAM uses the
Vault-style signed `sts:GetCallerIdentity` request, so trstctl verifies the caller
with STS without ever receiving the AWS secret access key.

```yaml
secrets:
  enable_api: true
  machine_auth:
    - name: kubernetes
      tenant_claim: trstctl.io/tenant
      issuer: https://kubernetes.default.svc
      audience: trstctl
      jwks_file: /etc/trstctl/k8s-sa-jwks.json
      allowed_namespaces: ["payments"]
      allowed_service_accounts: ["payments/api"]
      scopes: ["secrets:read"]
    - name: aws-iam
      tenant_id: 11111111-1111-1111-1111-111111111111
      allowed_accounts: ["123456789012"]
      scopes: ["secrets:read"]
```

### Secret scanning bridge (F39) and sharing & approvals (F60)

The **scanning bridge** runs the pinned Gitleaks scanner from the served control plane
and records redacted findings into [discovery](discovery-and-inventory.md), the
[credential graph](graph-query-ai.md), and the risk view. Operators point
`TRSTCTL_SECRETS_GITLEAKS_BIN` at Gitleaks `v8.27.2`; `POST /api/v1/secrets/scans`
then scans a repo or build workspace with the pinned default rule set (`213` rules,
well above the 140-rule acceptance floor). The API response and recorded discovery
finding carry rule id, file, line, scanner version, and fingerprint metadata only. The
secret value is redacted by Gitleaks and never written to the API response, event log,
graph, or audit output.

CI systems use the matching CLI bridge:

```bash
cat > secret-scan.json <<'JSON'
{"path":"."}
JSON
trstctl-cli --idempotency-key ci-secret-scan-1 secrets scans run -f secret-scan.json
```

The returned `run_id` can be inspected with `GET /api/v1/discovery/findings?run_id=...`
or the graph view. TruffleHog JSON ingestion remains available for offline import and
contract tests, but the served scanner path uses Gitleaks as the execution engine.
**Secret sharing** creates one-time, self-destructing shares with durable server-side
state. `POST /api/v1/secrets/shares` returns the bearer token once, but PostgreSQL
stores only `SHA-256(token)` plus the envelope-encrypted value in `secret_shares`.
That means a valid share survives an API restart, while a stolen database backup still
does not contain the token or plaintext. `POST /api/v1/secrets/shares/redeem` deletes
the row and returns the value exactly once; a second redeem, an expired token, or a
wrong tenant is a normal `404`.

**Change approvals** reuse the same dual-control [approval](incident-and-jit.md)
store as privileged issuance. When `ca.policy.require_approval` is enabled for the
deployment, sensitive secret-store mutations — `rotate`, `recover`, and `delete` —
open a tenant-scoped approval request and fail with `403` until the configured number
of distinct approvers approve it. A requester cannot approve their own secret change.
Approvers call `POST /api/v1/secrets/store/approvals/{name}` with
`{"action":"rotate"}`, `{"action":"recover"}`, or `{"action":"delete"}`. The response
contains only `resource`, `action`, `approver`, and the current distinct approval
count.

## Use it

The served pieces run through the API/CLI; the remaining library-only pieces are still
available through their Go APIs. The shapes:

```go
// Native store: versioned, envelope-encrypted put/get
store.Put(ctx, "db/password", []byte("s3cr3t"), "idem-key")   // -> version 1
val, _ := store.Get(ctx, "db/password")                        // latest live version

// Dynamic secret: a 1-hour Postgres credential, auto-revoked at lease end
lease, _ := dyn.Issue(ctx, "postgresql", "readonly", time.Hour, "req-1")

// Transit: encrypt without the app ever holding the key
ct, _ := keyring.Encrypt(ctx, "app-key", []byte("hello"), nil) // -> "trv:1:..."
```

The `secretstore.APIServer` exposes the store over HTTP (`PUT/GET /secrets/<path>`, with
`Idempotency-Key` and tenant headers) once mounted.

```bash
cat > secret-sync.json <<'JSON'
{"name":"sync/source","target":"github-actions","remote_key":"DB_PASSWORD"}
JSON
trstctl-cli --idempotency-key sync-db-password-1 secrets syncs run -f secret-sync.json

cat > secret-scan.json <<'JSON'
{"path":"."}
JSON
trstctl-cli --idempotency-key ci-secret-scan-1 secrets scans run -f secret-scan.json
```

## Pitfalls & limits

- **Serving status:** the secret store, rollback-safe static secret rotations, dynamic
  secret leases, one-time sharing, the dynamic PKI secret, machine login, outbound
  secret sync, and Gitleaks secret scanning are **served** on the running control plane
  under `/api/v1/secrets/*` (enable with `secrets.enable_api`, off by default and
  fail-closed). Secret sync needs named targets configured by the operator; an
  unconfigured target fails closed with `503` instead of dropping the write. Secret
  scanning needs the pinned Gitleaks binary; a missing binary fails closed with `503`.
- **Machine login tenant binding:** token credentials MAC-bind the tenant, the
  `machine-login` audience, principal, and expiry. `X-Tenant-ID` is a lookup hint on
  the public login route; a token for tenant A is rejected if presented with tenant B.
- **Protect the KEK.** Everything at rest is only as safe as `TRSTCTL_SECRETS_KEK_FILE`;
  in production back it with an [HSM/KMS](issuance-and-cas.md).
- **Dynamic beats static.** Prefer dynamic/ephemeral secrets over long-lived ones; if you
  must store a long-lived secret, put it on a rotation schedule.
- **Transit/KMIP serving status:** the KMIP TTLV parser is fuzzed and covered by an
  operation-level interop fixture, but no KMIP listener/API/CLI is mounted yet. Treat
  appliance profile validation as future served-endpoint work, not as a currently
  available network surface.
- **Sync is push + drift-detect**, not a two-way merge — trstctl is the source of truth.

## Reference

- **At rest:** envelope encryption (AES-256-GCM DEK wrapped by KEK); config
  `TRSTCTL_SECRETS_KEK_FILE`.
- **Store:** `Put/Get/GetVersion/Versions/Rollback/Delete/Purge`; `APIServer`
  (`PUT/GET /secrets/<path>`, `Idempotency-Key`).
- **Developer run wrapper:** `trstctl-cli run --secret ENV=secret/path -- <cmd>`
  fetches via `/api/v1/secrets/store/{name}` and injects only into the child env.
- **Dynamic backends:** `postgresql`, `mysql`, `mongodb`, `aws-iam`, `gcp-iam`,
  `azure-entra`, `kubernetes`, `redis`, plus `pki`.
- **Transit:** `Encrypt/Decrypt/Rewrap/HMAC/Sign/Verify`, versioned `trv:<n>:` ciphertext.
- **Sync targets:** Kubernetes, GitHub Actions, GitLab CI, Terraform, Vercel, AWS
  Parameter Store, webhook.
- **Scanning:** `POST /api/v1/secrets/scans`, `trstctl-cli secrets scans run`,
  Gitleaks `v8.27.2`, `213` default rules active, redacted findings only.
- **Events:** `secret.version.written`, `rotation.*`, `rotation.rollback_failed`,
  `auth.session.issued`, `discovery.finding.recorded`, `discovery.run.completed`.

## See also

[Workload identity](workload-identity.md) (attestation behind ephemeral secrets) ·
[Issuance & certificate authorities](issuance-and-cas.md) (HSM-backed KEK; PKI engine) ·
[Incident response & JIT](incident-and-jit.md) (compromise + approvals) ·
[Discovery & inventory](discovery-and-inventory.md) (finding existing secrets) ·
[Current limitations](../limitations.md) ·
glossary: [secret](../glossary.md), [envelope encryption](../glossary.md),
[KEK/DEK](../glossary.md), [dynamic secret](../glossary.md), [lease](../glossary.md),
[transit](../glossary.md), [KMIP](../glossary.md)

**Covers:** F37, F38, F39, F63, F64, F65, F66, F67, F68, F58, F60
