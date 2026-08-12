# Manage application secrets

<!-- trstctl:journey-census:start -->
!!! success "Served path — wiring census 81/81"

    The Definition-of-Done census reports **81/81 required capabilities served**: **12 of 81 census rows launch the shipped binary** and **69 of 81 are proved through the production-assembled handler**.
    Production-assembled means production `buildRunDeps` output driving the assembled `Server.Handler` in-process, with a hand-built `Deps` rejected; only the process launch differs.
    Independently proof-gated capability rows used by this journey (all `required`, all `served`): `dynamic_secret.registry`, `secret_sync.registry`, `secrets_residuals.kmip_wrapping_profile_negotiation`, `secrets_residuals.terraform_opentofu_native_sync`, `secrets_residuals.vault_kv_outbound_sync`, `secrets_residuals.vault_shim_acl_transit`.
    Core surfaces guarded by route and journey tests: `encrypted_secret_store`, `one_time_sharing`, `secret_scanning`.
    This badge is generated from `wiring-census.json`; `make journey-census-check` fails closed if the census or this page drifts.
<!-- trstctl:journey-census:end -->

## Goal

You will give your applications a safer way to hold the sensitive values they need —
database passwords, API tokens, encryption keys — by storing them encrypted, handing
out short-lived ones that expire on their own, and sharing one-off secrets through
links that self-destruct after a single view. The outcome is fewer long-lived secrets
copied into config files and CI, each one encrypted at rest and recorded in a
tamper-evident log. This is for a developer or platform engineer who wants their
services to stop hard-coding secrets.

> **In the console:** the `/secrets` workspace presents the same store as a folder
> tree with a reference resolver, an environment diff, version history, a disabled
> bulk-import disclosure, and a transit (encrypt / decrypt / HMAC) sub-console. The
> import route returns `501` without writing. See [The web console](../web-console.md).

## Before you start

- A running control plane and an API token from
  [Getting started](../getting-started.md) (`trstctl token create`).
- The CLI/API pointed at your server via `TRSTCTL_SERVER` and `TRSTCTL_TOKEN` — see
  [Getting started](../getting-started.md).
- The secrets surface is **off by default**. Enable it with `secrets.enable_api`, and
  set the master key-encryption key file (`TRSTCTL_SECRETS_KEK_FILE`, mode 0600) — the
  surface fails closed without it. See [Secrets](../features/secrets.md).

## Served scope and deliberate boundaries

Every command below stays on a route or listener the running binary serves
today (see [Current limitations](../limitations.md) and
[Secrets](../features/secrets.md)):

- Served under `/api/v1/secrets/*`: the secret store (create, read, rotate,
  delete, recover, dual-control approvals), dynamic secret leases, one-time
  sharing, the dynamic PKI secret (CSR-first certificate-only by default, with an
  explicit deprecated certificate-and-key compatibility mode),
  machine login (`token`, Kubernetes SAT, AWS IAM, GCP, Azure, OIDC, generic
  JWT), outbound secret-sync, and Gitleaks-backed secret scanning. Short-lived
  API keys: `/api/v1/ephemeral/api-keys`. Transit encryption-as-a-service:
  `/api/v1/transit/*` and `trstctl-cli transit`. A Vault/OpenBao-compatible
  subset (`/v1/auth/token/lookup-self`, `/v1/secret/data/*`, `/v1/pki/sign/*`, `/v1/pki/issue/*`)
  serves stock `vault` CLI migration. KMIP is an opt-in mTLS listener for
  AES-256 SymmetricKey Create/Register/Get/Locate/Revoke/Destroy, KMIP 1.4
  Query/DiscoverVersions negotiation, and AES-GCM wrapped Get/Register.
- Deliberately outside this journey: appliance-specific KMIP templates, tenant
  self-service listener provisioning, and secret-store / API-key *discovery*
  of actual values — discovery records references only, never values
  ([Discovery & inventory](../features/discovery-and-inventory.md)).

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

   The console's Secrets → **Access** tab covers the same grant flow in the
   browser — token minting, auth-method administration, and the machine-login
   session ledger; the CLI equivalents are `trstctl-cli access tokens create`,
   `secrets auth-methods list|disable|enable`, `secrets sessions list|revoke`,
   and `secrets login`.

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
   `secret/`, CSR signing under `pki/sign/*`, and deprecated keypair generation
   under `pki/issue/*`; native trstctl routes remain the complete API.

   ```sh
   export VAULT_ADDR=https://localhost:8443
   export VAULT_TOKEN="$TRSTCTL_TOKEN"

   vault login -no-store "$VAULT_TOKEN"
   vault kv put secret/db username=payments password=s3cr3t
   vault kv get -format=json secret/db
   openssl ecparam -name prime256v1 -genkey -noout -out payments.key
   openssl req -new -key payments.key -subj '/CN=payments.internal' -out payments.csr
   vault write -format=json pki/sign/default csr=@payments.csr ttl=1h
   ```

   -> `vault kv` writes the same sealed, versioned store as `/api/v1/secrets/store`,
   and `vault write pki/sign/...` returns a short-lived certificate without the
   requester key. `pki/issue/...` remains available as a deprecated key-returning
   compatibility path and records its custody choice first. The shim accepts `Idempotency-Key`; when
   the stock CLI omits it, trstctl derives a replay key from method, path, and body so
   retries do not mint duplicates.

3. Create a small tree one secret at a time, then resolve references deliberately.
   Bulk import is currently unavailable: `/api/v1/secrets/store/import` returns `501`
   without writing because an atomic event-sourced batch command is not implemented.
   References use `${secret.path}` and expand only when the caller asks for
   `resolve=true`, so a normal read does not fan out across hidden dependencies.

   ```sh
   curl -fksS -X POST https://localhost:8443/api/v1/secrets/store \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Idempotency-Key: $(uuidgen)" \
     -H 'Content-Type: application/json' \
     -d '{"name":"app/db/user","value":"payments"}'

   curl -fksS -X POST https://localhost:8443/api/v1/secrets/store \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Idempotency-Key: $(uuidgen)" \
     -H 'Content-Type: application/json' \
     -d '{"name":"app/db/dsn","value":"postgres://${secret.app/db/user}@db.service.local/payments"}'

   curl -fksS "https://localhost:8443/api/v1/secrets/store/app/db/dsn?resolve=true" \
     -H "Authorization: Bearer $TRSTCTL_TOKEN"
   ```

   -> each create response contains metadata only; the final response expands the
   referenced value for this tenant. A circular reference is a `409` problem response
   with a `cycle` field.

4. Rotate a long-lived secret to a new version. The served store creates a new version
   on write (old versions stay queryable), so a `PUT` rolls forward without losing
   history. If dual-control approvals are enabled, this first `PUT` opens the
   approval request and returns `403` until distinct approvers authorize the exact
   secret/action. This native-store `PUT` only records the next sealed value in
   trstctl; it does not rotate a credential at its backend. Manual static-provider and
   dynamic-lease provider rotations fail before making any provider effect. See
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

   Beyond in-store version rotation, the provider route currently runs only
   connector-backed rotation (`secrets rotations run` with
   `provider":"connector:<target>"`, atomically
   committing the local version plus sealed outbox command and returning
   `queued:true` until the worker delivers) — plus event-sourced schedules
   (`POST /api/v1/secrets/rotation-schedules`, then `/run-due`). Every
   response is metadata-only; no variant returns the new credential value.
   Static providers such as `postgresql` and `dynamic-lease:<backend>` deliberately
   return a stable `503` before any provider effect until their complete effect and
   rollback chains share one durable worker command.
   Payload shapes and the rotation-mode taxonomy are on the
   [Secrets feature page](../features/secrets.md).

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

9. Hand an application a short-lived certificate while its private key stays where it
   will run. Generate the CSR beside the workload, then send only that public request
   to the separate signing service. The issued serial is recorded on the revocation
   pipeline so a revoked certificate stops validating. See [Secrets](../features/secrets.md).

   ```sh
   openssl ecparam -name prime256v1 -genkey -noout -out payments.key
   openssl req -new -key payments.key -subj '/CN=payments.internal' -out payments.csr
   curl -fksS -X POST https://localhost:8443/api/v1/secrets/pki \
     -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     -H "Idempotency-Key: $(uuidgen)" \
     -H 'Content-Type: application/json' \
     --data-binary "$(jq -n --rawfile csr payments.csr '{csr_pem:$csr,ttl_seconds:900}')"
   ```

   -> you get back a short-lived certificate and no private key; `payments.key` never
   left the workload environment. Supplying `common_name` instead is the deprecated
   key-returning mode and creates an `issuance.server_side_keygen` Audit receipt first.

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
   configured pusher. The served catalog covers AWS Secrets Manager, GCP Secret
   Manager, Azure Key Vault, GitHub Actions, GitLab CI/CD variables, Vercel project
   environment variables, generic CI JSON endpoints, and Kubernetes Secrets. Use
   `GET /api/v1/secrets/syncs/targets` to see which targets are configured on the
   current control plane.

   ```sh
   curl -fsS -H "Authorization: Bearer $TRSTCTL_TOKEN" \
     "$TRSTCTL_URL/api/v1/secrets/syncs/targets"

   cat > secret-sync.json <<'JSON'
   {"name":"sync/source","target":"github-actions","remote_key":"DB_PASSWORD"}
   JSON
   trstctl-cli --idempotency-key sync-db-password-1 secrets syncs run -f secret-sync.json
   ```

   -> the response returns only metadata and delivery flags; it never echoes the
   secret value.

   Four read-only posture commands map the wider sync/injection estate before
   you rely on it: `trstctl-cli secrets cloud-secret-managers` (cloud
   discovery + sync coverage), `secrets kubernetes-operator` (the
   `TrstctlSecretSync` CRD and its Helm-owned residual limits),
   `secrets workload-injection` (the `TrstctlSecretInjection` CRD and the
   `trstctl-agent --secret-inject` sidecar), and `secrets unvaulted`
   (leaked-secret findings and multi-vault visibility). Their response shapes
   are on the [Secrets feature page](../features/secrets.md); none return
   secret values.

12. Scan a repository or CI workspace for committed secrets. Run
    `tools/gitleaks/install.sh` during image build or host provisioning to install the
    checksum-verified Gitleaks `v8.27.2` release tarball, then set
    `TRSTCTL_SECRETS_GITLEAKS_BIN` to that binary. The served scan uses the pinned
    default rule set (`213` rules), redacts the match, and records only
    rule/file/line/fingerprint metadata into discovery and graph.

   ```sh
   cat > secret-scan.json <<'JSON'
   {"path":"."}
   JSON
   trstctl-cli --idempotency-key ci-secret-scan-1 secrets scans run -f secret-scan.json

   cat > deep-secret-scan.json <<'JSON'
   {"path":".","mode":"git_history","custom_rules_path":"./gitleaks-custom-rules.toml"}
   JSON
   trstctl-cli --idempotency-key ci-secret-scan-deep-1 secrets scans run -f deep-secret-scan.json

   trstctl-cli secrets scans staged-diff --repo .
   trstctl-cli secrets scans pre-commit install --repo .
   trstctl-cli secrets scans staged-diff --repo . --base origin/main --head HEAD --advisory

   trstctl-cli secrets scans third-party
   cat > third-party-scan.json <<'JSON'
   {"source":"acme/slack","artifact_path":"/var/lib/trstctl/exports/slack.jsonl","event":"message_export"}
   JSON
   trstctl-cli --idempotency-key third-party-scan-1 \
     secrets scans third-party ingest slack -f third-party-scan.json

   curl -fksS "https://localhost:8443/api/v1/discovery/findings?run_id=<run-id>" \
     -H "Authorization: Bearer $TRSTCTL_TOKEN"
   ```

   -> the served scan response shows the `run_id`, `mode`, `capabilities`,
   `rules_active`, and redacted findings. Deep mode scans full Git history with
   the default Gitleaks rules plus additive custom `[[rules]]` fragments.
   Third-party artifact mode covers CI logs, container-registry metadata, and
   Slack/Jira exports through artifact-path ingest; native provider polling
   and signature validation remain documented shortfalls. The local
   staged-diff scanner needs no server, scans only staged Git blobs or the
   head side of an explicit CI diff, and also drops the raw secret value.

## Where next

- [migrate-from-existing-ca.md](migrate-from-existing-ca.md) — consolidate your
  certificates the same way.
- [onboard-a-team.md](onboard-a-team.md) — isolate each team's secrets in its own
  tenant.

**Journey:** J7
**Steps through:** F37, F38, F39, F35, F36, F63, F64, F65, F66, F67, F68, F60
