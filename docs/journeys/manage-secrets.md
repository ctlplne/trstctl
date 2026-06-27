# Manage application secrets

## Goal

You will give your applications a safer way to hold the sensitive values they need —
database passwords, API tokens, encryption keys — by storing them encrypted, handing
out short-lived ones that expire on their own, and sharing one-off secrets through
links that self-destruct after a single view. The outcome is fewer long-lived secrets
copied into config files and CI, each one encrypted at rest and recorded in a
tamper-evident log. This is for a developer or platform engineer who wants their
services to stop hard-coding secrets. It is also honest about which pieces the running
binary serves today and which are library code you drive in Go.

> **In the console:** the `/secrets` workspace presents the same store as a folder
> tree with a reference resolver, an environment diff, version history, bulk import, and
> a transit (encrypt / decrypt / HMAC) sub-console. See [The web console](../web-console.md).

## Before you start

- A running control plane and an API token from
  [Getting started](../getting-started.md) (`trstctl token create`).
- The CLI/API pointed at your server via `TRSTCTL_SERVER` and `TRSTCTL_TOKEN` — see
  [Getting started](../getting-started.md).
- The secrets surface is **off by default**. Enable it with `secrets.enable_api`, and
  set the master key-encryption key file (`TRSTCTL_SECRETS_KEK_FILE`, mode 0600) — the
  surface fails closed without it. See [Secrets](../features/secrets.md).

## What is served vs library-only

Be precise here (see [Current limitations](../limitations.md) and
[Secrets](../features/secrets.md)):

- **Served** on the running binary under `/api/v1/secrets/*`: the secret store
  (create, read, **rotate**, delete, recover, and dual-control approvals for sensitive changes),
  dynamic secret leases, one-time secret sharing,
  the dynamic PKI secret (a short-lived certificate *and* its key), machine login
  (`token`, Kubernetes SAT, AWS IAM, GCP, Azure, OIDC, and generic JWT),
  outbound **secret-sync** to configured external stores, and Gitleaks-backed
  code/CI secret scanning. Short-lived API keys are served at
  `/api/v1/ephemeral/api-keys`. Transit encryption-as-a-service is served separately
  at `/api/v1/transit/*` and `trstctl-cli transit`. A Vault/OpenBao-compatible
  common subset is served at `/v1/auth/token/lookup-self`, `/v1/secret/data/*`, and
  `/v1/pki/issue/*` for stock `vault` CLI migration. KMIP is served as an opt-in
  mTLS listener for AES-256 SymmetricKey Create/Get.
- **Still outside this journey:** broader KMIP appliance profiles and secret-store /
  API-key *discovery* of actual values. Discovery records references only and stays
  covered by the discovery journey.

## Steps

1. Point your client at the control plane and confirm the secrets surface is enabled.

   ```yaml
   secrets:
     enable_api: true
     machine_auth:
       - name: kubernetes
         tenant_claim: trstctl.io/tenant
         issuer: https://kubernetes.default.svc
         audience: trstctl
         jwks_file: /etc/trstctl/k8s-sa-jwks.json
       - name: aws-iam
         tenant_id: 11111111-1111-1111-1111-111111111111
         allowed_accounts: ["123456789012"]
   ```

   ```sh
   export TRSTCTL_SERVER=https://localhost:8443
   export TRSTCTL_TOKEN=trst_...
   export TRSTCTL_SECRETS_KEK_FILE=/etc/trstctl/secrets-kek
   ```

   -> the `/api/v1/secrets/*` routes answer for your tenant; with the key file absent
   they fail closed.

2. Store a secret. Each value is sealed under envelope encryption (a fresh per-secret
   data key wrapped by the master key), bound to your tenant and path, and held only in
   wipeable memory — never as a copyable string. Every write is an immutable
   `secret.version.written` event. See [Secrets](../features/secrets.md).

   ```sh
   curl -fksS -X POST https://localhost:8443/api/v1/secrets/store/db/password \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Idempotency-Key: $(uuidgen)" \
     -H 'Content-Type: application/json' \
     -d '{"name":"db/password","value":"s3cr3t"}'
   ```

   -> the secret is stored as version 1; reading it back returns the latest live
   version.

   **Vault/OpenBao migration shortcut:** if your scripts already use the stock
   `vault` CLI, point it at the same server and use your trstctl API token as
   `VAULT_TOKEN`. The shim is intentionally limited to token lookup, KV v2 under
   `secret/`, and PKI issue under `pki/issue/*`; native trstctl routes remain the
   complete API.

   ```sh
   export VAULT_ADDR=https://localhost:8443
   export VAULT_TOKEN="$TRSTCTL_TOKEN"

   vault login -no-store "$VAULT_TOKEN"
   vault kv put secret/db username=payments password=s3cr3t
   vault kv get -format=json secret/db
   vault write -format=json pki/issue/default common_name=payments.internal ttl=1h
   ```

   -> `vault kv` writes the same sealed, versioned store as `/api/v1/secrets/store`,
   and `vault write pki/issue/...` returns a short-lived certificate plus private key
   from the signer-backed dynamic PKI secret. The shim accepts `Idempotency-Key`; when
   the stock CLI omits it, trstctl derives a replay key from method, path, and body so
   retries do not mint duplicates.

3. Import a small tree and resolve references deliberately. Imports are all-or-nothing:
   every value is sealed as version 1, and if one path already exists the import is
   rejected. References use `${secret.path}` and expand only when the caller asks for
   `resolve=true`, so a normal read does not fan out across hidden dependencies.

   ```sh
   curl -fksS -X POST https://localhost:8443/api/v1/secrets/store/import \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Idempotency-Key: $(uuidgen)" \
     -H 'Content-Type: application/json' \
     -d '{"prefix":"app","values":{"db/user":"payments","db/dsn":"postgres://${secret.app/db/user}@db.service.local/payments"}}'

   curl -fksS "https://localhost:8443/api/v1/secrets/store/app/db/dsn?resolve=true" \
     -H "Authorization: Bearer $TRSTCTL_TOKEN"
   ```

   -> the first response lists only imported metadata; the second response expands the
   referenced value for this tenant. A circular reference is a `409` problem response
   with a `cycle` field.

4. Rotate a long-lived secret to a new version. The served store creates a new version
   on write (old versions stay queryable), so a `PUT` rolls forward without losing
   history. If dual-control approvals are enabled, this first `PUT` opens the
   approval request and returns `403` until distinct approvers authorize the exact
   secret/action. For backend static credentials, the served rotation API stages a
   new credential, cuts the consumer pointer over, verifies the new login, retires the
   old reference, and rolls back automatically if cutover or verification fails. See
   [Secrets](../features/secrets.md).

   ```sh
   curl -fksS -X PUT https://localhost:8443/api/v1/secrets/store/db/password \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Idempotency-Key: $(uuidgen)" \
     -H 'Content-Type: application/json' \
     -d '{"value":"r0tat3d"}'
   ```

   -> if approvals are disabled, a new native-store version is recorded. If approvals
   are enabled, the requester gets `403` and approvers continue:

   ```sh
   curl -fksS -X POST https://localhost:8443/api/v1/secrets/store/approvals/db/password \
     -H "Authorization: Bearer $APPROVER_TOKEN" \
     -H "Idempotency-Key: $(uuidgen)" \
     -H 'Content-Type: application/json' \
     -d '{"action":"rotate"}'

   cat > approval.json <<'JSON'
   {"action":"rotate"}
   JSON
   trstctl-cli --idempotency-key approve-db-password secrets approvals approve db/password -f approval.json
   ```

   -> the response shows `resource:"secret:db/password"` and the distinct approval
   count. After quorum, the original requester retries the `PUT` with a fresh
   `Idempotency-Key` and the rotate succeeds. The requester cannot approve their own
   request.

   ```sh
   curl -fksS -X POST https://localhost:8443/api/v1/secrets/rotations \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Idempotency-Key: $(uuidgen)" \
     -H 'Content-Type: application/json' \
     -d '{"provider":"postgresql","key":"db/reporting","old_ref":"sec05_old"}'
   ```

   -> a rollback-safe static credential rotation runs through the served API. The
   response contains only metadata such as `old_ref`, `new_ref`, `completed`,
   `rolled_back`, and `failed_phase`; it never returns the new credential value.

5. Read history or recover to a timestamp. Historical reads are explicit value reads,
   and point-in-time recovery republishes the version that was current at `at` as the
   next monotonic version.

   ```sh
   curl -fksS "https://localhost:8443/api/v1/secrets/store/history/db/password?version=1" \
     -H "Authorization: Bearer $TRSTCTL_TOKEN"

   curl -fksS -X POST https://localhost:8443/api/v1/secrets/store/recover/db/password \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Idempotency-Key: $(uuidgen)" \
     -H 'Content-Type: application/json' \
     -d '{"at":"2026-06-25T12:00:00Z"}'
   ```

   -> the recovered value becomes the latest version; metadata and audit records do not
   contain plaintext secret material.

6. Run a developer process with secrets injected at start. `trstctl-cli run` reads each
   mapped secret through the served store, places it in the child process environment,
   streams the child stdout/stderr/stdin, and returns the child's exit code. trstctl
   audits the variable names and store paths, not the values, and wipes the fetched
   byte buffers after the child exits.

   ```sh
   trstctl-cli run --secret DB_PASSWORD=db/password -- env
   trstctl-cli run --resolve --secret DATABASE_URL=app/db/dsn -- ./payments-api
   ```

   -> `env` is useful as a smoke test because it proves the child can see
   `DB_PASSWORD`. In production, point `run` at the application process itself and
   avoid commands that dump the whole environment into CI logs.

7. Hand an application a short-lived backend credential it cannot hoard. Dynamic leases
   return the credential once, then later reads show only metadata. When the TTL expires,
   the served leaseworker queues backend revocation through the outbox, so a crash does
   not silently drop the revoke. Operators must wire the named provider backend before a
   tenant can issue from it. The built-in backend names are `postgresql`, `mysql`,
   `mongodb`, `aws-iam`, `gcp-iam`, `azure-entra`, `kubernetes`, and `redis`; each
   creates a scoped credential in the target system and revokes it when the lease
   closes.

   ```sh
   curl -fksS -X POST https://localhost:8443/api/v1/secrets/leases \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Idempotency-Key: $(uuidgen)" \
     -H 'Content-Type: application/json' \
     -d '{"provider":"postgresql","role":"readonly","ttl_seconds":900}'

   curl -fksS https://localhost:8443/api/v1/secrets/leases/<lease-id> \
     -H "Authorization: Bearer $TRSTCTL_TOKEN"

   curl -fksS -X POST https://localhost:8443/api/v1/secrets/leases/<lease-id>/renew \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Idempotency-Key: $(uuidgen)" \
     -H 'Content-Type: application/json' \
     -d '{"extend_seconds":900}'

   curl -fksS -X POST https://localhost:8443/api/v1/secrets/leases/<lease-id>/revoke \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Idempotency-Key: $(uuidgen)"
   ```

   -> the issue response contains the credential; the get, renew, and revoke responses
   contain only lease id, provider, role, state, and timestamps.

8. Mint a short-lived API key for automation that should not keep a reusable bearer
   credential. The route returns the raw token once, stores only its hash, and the
   served leaseworker records `api_token.revoked` when the TTL passes.

   ```sh
   curl -fksS -X POST https://localhost:8443/api/v1/ephemeral/api-keys \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Idempotency-Key: $(uuidgen)" \
     -H 'Content-Type: application/json' \
     -d '{"subject":"ci-preview-deploy","scopes":["access:read"],"ttl_seconds":900}'

   cat > ephemeral-api-key.json <<'JSON'
   {"subject":"ci-preview-deploy","scopes":["access:read"],"ttl_seconds":900}
   JSON
   trstctl-cli --idempotency-key ci-preview-key ephemeral api-keys issue -f ephemeral-api-key.json
   ```

   -> the response includes `token` exactly once, plus metadata such as `id`,
   `subject`, `scopes`, and `expires_at`. After expiry, the same token receives
   `401`, and `GET /api/v1/access/api-tokens?subject=ci-preview-deploy&include_revoked=true`
   shows `revoked_at`.

9. Hand an application a short-lived certificate identity it cannot hoard. The dynamic
   PKI secret issues a usable TLS identity — a certificate **and** its private key —
   through the issuing authority in the separate signing service, recorded on the
   revocation pipeline so a revoked one stops validating. See [Secrets](../features/secrets.md).

   ```sh
   curl -fksS -X POST https://localhost:8443/api/v1/secrets/pki \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Idempotency-Key: $(uuidgen)" \
     -H 'Content-Type: application/json' \
     -d '{}'
   ```

   -> you get back a short-lived certificate and key your app can load directly, with no
   long-lived secret to steal.

10. Share a one-off secret that destroys itself after a single read.

   ```sh
   curl -fksS -X POST https://localhost:8443/api/v1/secrets/shares \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Idempotency-Key: $(uuidgen)" \
     -H 'Content-Type: application/json' \
     -d '{"value":"one-time-token"}'
   ```

   -> the API returns the bearer token once. The server stores only the token hash and
   the sealed value, so the share survives an API restart but a database reader still
   cannot redeem it.

   ```sh
   curl -fksS -X POST https://localhost:8443/api/v1/secrets/shares/redeem \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Idempotency-Key: $(uuidgen)" \
     -H 'Content-Type: application/json' \
     -d '{"token":"<returned-token>"}'
   ```

   -> the share redeems exactly once; a second redeem fails, and the bearer token is
   never written to the audit log.

11. Push a stored secret to a configured external target when a platform needs a copy.
   The served sync path writes a sealed outbox row first, then delivers through the
   configured pusher. GitHub Actions, AWS Secrets Manager, and Kubernetes have concrete
   pushers; Vercel/GitLab/Terraform/GCP/Azure style targets can use the JSON/manual
   pusher until deeper native APIs are configured.

   ```sh
   cat > secret-sync.json <<'JSON'
   {"name":"sync/source","target":"github-actions","remote_key":"DB_PASSWORD"}
   JSON
   trstctl-cli --idempotency-key sync-db-password-1 secrets syncs run -f secret-sync.json
   ```

   -> the response returns only metadata and delivery flags; it never echoes the secret
   value.

12. Scan a repository or CI workspace for committed secrets. Install Gitleaks `v8.27.2`
    on the control-plane host and set `TRSTCTL_SECRETS_GITLEAKS_BIN` to that binary.
    The served scan uses the pinned default rule set (`213` rules), redacts the match,
    and records only rule/file/line/fingerprint metadata into discovery and graph.

   ```sh
   cat > secret-scan.json <<'JSON'
   {"path":"."}
   JSON
   trstctl-cli --idempotency-key ci-secret-scan-1 secrets scans run -f secret-scan.json

   curl -fksS "https://localhost:8443/api/v1/discovery/findings?run_id=<run-id>" \
     -H "Authorization: Bearer $TRSTCTL_TOKEN"
   ```

   -> the scan response shows the `run_id`, `rules_active`, and redacted findings.
   The secret value itself is not returned and is not written to the event log.

13. Know the edges before you rely on them. Transit encryption-as-a-service is now
    served through `/api/v1/transit/*` and `trstctl-cli transit`, and KMIP is served
    through a separate `protocols.kmip.*` mTLS listener for AES-256 SymmetricKey
    Create/Get. Broader appliance profiles and KMIP operations are still future work.
    Finding secrets already scattered across your estate (secret-store and API-key
    discovery) records references only, never values — see
    [Discovery & inventory](../features/discovery-and-inventory.md) and
    [Current limitations](../limitations.md).

## Where next

- [migrate-from-existing-ca.md](migrate-from-existing-ca.md) — consolidate your
  certificates the same way.
- [onboard-a-team.md](onboard-a-team.md) — isolate each team's secrets in its own
  tenant.

**Journey:** J7
**Steps through:** F37, F38, F39, F35, F36, F63, F64, F65, F66, F67, F68, F60
