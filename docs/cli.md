# CLI

`trstctl-cli` is a command-line interface at parity with the REST API, built for
scripts and CI: machine-readable JSON output and a CI-friendly API token. The CLI
itself is table-driven — one row in `internal/cli/command.go` per API operation,
proven complete by a parity test against the route table. This reference page,
however, is maintained by hand, not generated; treat `internal/cli/command.go` as
the ground truth if the two ever disagree.

The running control plane also publishes its full **OpenAPI 3.1** specification at
`/api/v1/openapi.json` — fetch it to generate clients or import the API into your
tooling.

Prefer a typed library? trstctl ships supported **client SDKs for Go and
TypeScript** (with auth, `Idempotency-Key`, cursor iterators, problem+json
errors, and retries) pinned to that same served contract. See
[Client SDKs](features/client-sdks.md).

Prefer infrastructure-as-code? trstctl also ships
[`terraform-provider-trstctl`](terraform-provider.md) for certificate profiles,
short-lived PKI credentials, and application secrets, backed by the same served
OpenAPI routes.

Every command documented below is `trstctl-cli`. The `trstctl` server binary is a
separate program with exactly three admin verbs of its own — `token create` (see
"Bootstrapping the first API token" below), `connector target ...`, and `ssh ...`
— for direct calls against a running control plane, using their own `--flag`
arguments and `TRSTCTL_URL` rather than the `-f <file>` bodies and
`TRSTCTL_SERVER` used everywhere else on this page.

## Global flags

Every command accepts these, each with a `TRSTCTL_*` environment fallback:

| Flag                | Env                       | Meaning                                                   |
| ------------------- | ------------------------- | --------------------------------------------------------- |
| `--server`          | `TRSTCTL_SERVER`          | Base URL of the control plane.                            |
| `--token`           | `TRSTCTL_TOKEN`           | API token, sent as `Authorization: Bearer`.               |
| `--tenant`          | `TRSTCTL_TENANT`          | Tenant id (`X-Tenant-ID`) for header/dev auth.            |
| `--idempotency-key` | `TRSTCTL_IDEMPOTENCY_KEY` | Stable key for safe retries; generated per call if unset. |

A trstctl API token carries its own tenant and scopes, so with `--token` you
usually need nothing else. Mutations always send an `Idempotency-Key` so a
retried command can never execute twice.

## Output and exit codes

Responses are pretty-printed JSON on stdout. Exit code is **0** on success, **1**
on a request/response error (the status is written to stderr), and **2** on a
usage error — scriptable end to end.

## Commands

One row per command group — covering every core API operation — plus the local
`run` wrapper for developer secret injection (kept in sync by hand, per the note
above). Each row gives a one-line purpose plus representative verbs, not an
exhaustive subcommand list:

| Group                              | Purpose (representative verbs)                                                                                                                              |
| ---------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `access`                           | Tenant membership, API tokens, JIT privileged-access sessions, and NHI access-change requests/reviews (`roles` · `oidc-mapping` · `members` · `tokens` · `sessions` · `requests` · `reviews`) |
| `acme`                             | ACME DNS-01 provider coverage, secret-referenced provider configs, and propagation/CAA/wildcard preflight (`dns-01 providers` · `dns-01 provider-configs` · `dns-01 preflight`) |
| `agents`                           | In-network agent inventory, enrollment tokens, cert revocation, offboarding (`list` · `enroll-token` · `revoke-cert` · `offboard`)                          |
| `ai`                               | AI assistant status, question answering, root-cause analysis (`status` · `query` · `rca`)                                                                   |
| `audit`                            | Query and export the signed audit log (`events` · `export`)                                                                                                 |
| `breakglass`                       | Ceremony-gated online break-glass issuance, rotation, cross-signing, and offline-bundle reconciliation (`issue-ceremony` · `issue` · `rotation-ceremony` · `rotate` · `cross-sign-ceremony` · `cross-sign` · `reconcile`) |
| `broker agent-identities`          | Issue a policy-gated AI/MCP agent identity (`issue`)                                                                                                         |
| `ca ceremonies`                    | Start, inspect, and approve m-of-n CA key ceremonies (`start` · `get` · `approve`)                                                                           |
| `ca authorities`                   | Private CA authority lifecycle — create/import roots and intermediates, rotate, rekey, cross-sign, issue leaf certs (`list` · `create-root` · `import-offline-root` · `import-existing` · `create-intermediate` · `rotate` · `rekey` · `cross-sign` · `issue`) |
| `ca discovery`                     | List public and private CA discovery inventory (`list`)                                                                                                      |
| `cbom`                             | Cryptographic bill of materials: scan TLS endpoints/configs, list assets (`scan` · `assets`)                                                                 |
| `certificates`                     | Certificate inventory: ingest, list, get, health, bulk-revoke (`ingest` · `list` · `get` · `health` · `bulk-revoke`)                                         |
| `code-signing`                     | Sign artifact digests with a managed key or a keyless Sigstore/Fulcio identity (`identities` · `sign` · `keyless`)                                                          |
| `compliance`                       | Compliance/inventory reporting and signed evidence-pack export (`inventory-report` · `nhi-report` · `report-schedules` · `evidence-pack`)                   |
| `connector target`                 | Deployment connector targets: create, bind, test, deploy, roll back (`create` · `list` · `get` · `update` · `delete` · `bind` · `test` · `deploy` · `rollback`) |
| `connectors`                       | Connector catalog, outbox circuit-breaker state, delivery receipts (`catalog` · `outbox-circuits` · `deliveries`)                                            |
| `discovery`                        | Discovery sources, schedules, runs, findings, CT monitoring, drift remediation, continuous monitoring (`sources` · `schedules` · `runs` · `findings` · `ct-monitoring` · `drift-remediation` · `monitoring`) |
| `editions`                         | Show edition, license, and FIPS posture (`status`)                                                                                                           |
| `ephemeral`                        | Approval-gated JIT credentials and short-TTL API keys (`issue` · `api-keys issue` · `approve`)                                                               |
| `external-cas`                     | List and issue through configured upstream CA integrations (`list` · `issue`)                                                                                |
| `graph`                            | Query the credential graph, reachability, and blast radius (`nodes` · `reachable` · `blast-radius` · `query`)                                                |
| `identities`                       | Identity lifecycle: create, list, transition, dual-control approvals, bulk-revoke (`create` · `list` · `get` · `transition` · `approve` · `approve issue` · `approve rotate` · `approve revoke` · `bulk-revoke`) |
| `incidents executions`             | Execute credential-compromise remediation and inspect evidence packs (`execute` · `list` · `get`)                                                            |
| `incidents response-integrations`  | Dispatch an incident packet to SIEM/SOAR/chat/ITSM integrations (`dispatch`)                                                                                  |
| `incidents fleet-reissuance`       | Compromised-issuer fleet reissuance: start, list, get, pause, resume, rollback, evidence (`start` · `list` · `get` · `pause` · `resume` · `rollback` · `evidence`) |
| `issuers`                          | Create, list, get certificate issuers (`create` · `list` · `get`)                                                                                            |
| `itsm servicenow tickets`          | Queue a ServiceNow ITSM ticket through the outbox (`create`)                                                                                                 |
| `kubernetes`                       | Native Kubernetes CertificateSigningRequest and trust-bundle distribution support (`csr` · `trust-bundles`)                                                  |
| `lifecycle`                        | Automated endpoint bindings and rotation-run history (`endpoint-bindings create` · `rotation-runs list` · `rotation-runs get`)                               |
| `managed-keys`                     | BYOK/HSM-resident key lifecycle: generate, dual-control approve, rotate, revoke, zeroize (`generate` · `approve` · `rotate` · `revoke` · `zeroize`)          |
| `managed-offering`                 | Managed-offering/provider-plane posture and hosted-tenant provisioning (`status` · `tenants provision`)                                                      |
| `mcp`                              | List and invoke the MCP tools the server exposes (`tools` · `call`)                                                                                          |
| `mdm`                              | MDM SCEP policy/challenge status and enrollment-policy management (`scep status` · `scep policies`)                                                          |
| `migration`                        | Licensed crypto-migration runs over CBOM findings — Enterprise PQC only (`plan` · `start` · `status` · `rollback`)                                                    |
| `nhi`                              | Unified NHI inventory, posture findings, policy compliance, decommissioning (`inventory` · `posture shadow/stale/overprivilege/static-credentials/exposure` · `policy compliance` · `decommission`) |
| `notifications`                    | Notification channels, routing policies, inbox/dead-letter management (`channels` · `routing-policies` · `list` · `get` · `read` · `requeue`)               |
| `operations`                       | Operational telemetry for the bounded worker pools that carry backpressure (`bulkheads`)                                                                    |
| `owners`                           | Owner CRUD and NHI ownership attribution (`create` · `list` · `get` · `update` · `delete` · `attribution`)                                                   |
| `platform`                         | Show self-hostable run-anywhere distribution posture (`distribution`)                                                                                        |
| `platform`                         | Running build, uptime, signer topology, and spine reachability (`system`)                                                                                    |
| `policy`                           | Author, list, activate, and roll back lifecycle policy versions; dry-run a candidate module (`versions create/list/activate/rollback` · `dry-run`)           |
| `privacy`                          | Subject erasure, retention runs, archive-erasure attestations, export, personal-data catalog (`erasures` · `retention` · `archives` · `export` · `catalog`)  |
| `profiles`                         | Certificate profile versions (`create` · `list` · `get-version`)                                                                                             |
| `remediation`                      | Automated remediation playbooks/runs and owner-driven self-remediation actions (`playbooks` · `playbooks run` · `playbook-runs list/get` · `owner-actions list/accept`) |
| `revocation`                       | Published CRLs, rogue-certificate findings, CT-log submission (`crls` · `rogue-certificates` · `ct-submit`)                                                  |
| `risk`                             | Rank credentials by risk score, with blast-radius-aware prioritization (`credentials` · `contextual-priorities`)                                             |
| `run`                              | Local wrapper: run a child process with fetched secrets injected into its environment                                                                        |
| `scale`                            | High-volume orchestration and multi-region HA issuance posture (`orchestration` · `ha-issuance`)                                                             |
| `secrets store`                    | Stored secrets: put, list, import, get, history, recover, update, delete (`put` · `list` · `import` · `get` · `history` · `recover` · `update` · `delete`)   |
| `secrets leases`                   | Dynamic secret leases: issue, get, renew, revoke (`issue` · `get` · `renew` · `revoke`)                                                                      |
| `secrets rotations`                | Run a rollback-safe static/connector/dynamic-lease secret rotation (`run`)                                                                                   |
| `secrets rotation-schedules`       | Scheduled dual-phase secret rotations (`create` · `list` · `run-due`)                                                                                        |
| `secrets syncs`                    | Push a stored secret to an external sync target (`run` · `targets`)                                                                                          |
| `secrets scans`                    | Gitleaks scanning: CI runs, repository/third-party webhooks, local pre-commit and staged-diff (`run` · `repositories` · `repositories webhook` · `third-party` · `third-party ingest` · `staged-diff` · `pre-commit install`) |
| `secrets shares`                   | Create and redeem a secret share (`create` · `redeem`)                                                                                                       |
| `secrets approvals`                | Approve a pending secret-store change (`approve`)                                                                                                            |
| `secrets`                          | Machine-auth login methods, machine-login sessions, credential exchange, dynamic PKI secrets, cloud/Kubernetes/workload integration status (`auth-methods` · `sessions` · `login` · `pki` · `cloud-secret-managers` · `kubernetes-operator` · `workload-injection` · `unvaulted`) |
| `setup`                            | Tenant-bound eval protocol profile status and activation (`protocols status` · `protocols activate`)                                                         |
| `ssh`                              | SSH CA/KRL/attestation workflow status, trust rollout, attested user-cert issuance, revoke, host retirement (`fleet` · `status` · `trust-rollout` · `issue-attested-user` · `revoke` · `retire-host`) |
| `support`                          | Show enterprise support, SLA, and services posture (`enterprise`)                                                                                            |
| `transit keys`                     | Create and rotate a tenant-scoped transit key (`create` · `rotate`)                                                                                          |
| `transit`                          | Encrypt, decrypt, rewrap, HMAC, sign, verify with a transit key (`encrypt` · `decrypt` · `rewrap` · `hmac` · `sign` · `verify`)                              |
| `workloads`                        | Workload attester trust sources and attested X.509-SVID issuance (`attester-trust-sources create/list/get/update/rotate/revoke/delete` · `attested-issuance`) |

Plus `version`. `trstctl` (the server binary) additionally serves `token`,
`connector`, and `ssh` under its own conventions — see the callout above.

## Run with secrets

`trstctl-cli run` fetches one or more stored secrets through the same served
`GET /api/v1/secrets/store/{name}` path as `secrets store get`, then starts a child
process with those values added to its environment. It is a wrapper, not a JSON API
command: stdout, stderr, stdin, and the child's exit code are passed through.

```bash
trstctl-cli run --secret DB_PASSWORD=db/password -- env
trstctl-cli run --resolve --secret DATABASE_URL=app/db/dsn -- ./payments-api
```

- `--secret ENV=secret/path` is repeatable. `ENV` must be a normal environment
  variable name, and `secret/path` may contain `/` path segments.
- `--resolve` maps to `?resolve=true`, so referenced values such as
  `${secret.app/db/password}` expand only when the caller asks for it.
- trstctl never logs injected values and wipes its byte-backed fetched copies after
  the child exits. The operating-system environment is still a string boundary, so
  use this with trusted commands and avoid debug commands that print all env vars
  outside a test.

Secret-store approvals use the same m-of-n dual-control store as privileged
issuance. A distinct approver records a pending secret change like this:

```bash
cat > approval.json <<'JSON'
{"action":"rotate"}
JSON
trstctl-cli --idempotency-key approve-db-password secrets approvals approve db/password -f approval.json
```

Identity approvals can be sent with either an explicit JSON body or the fixed-action
aliases. The aliases post the same served approval route with the action body filled in:

```bash
trstctl-cli --idempotency-key approve-web-issue identities approve issue 11111111-1111-1111-1111-111111111111
trstctl-cli --idempotency-key approve-web-rotate identities approve rotate 11111111-1111-1111-1111-111111111111
trstctl-cli --idempotency-key approve-web-revoke identities approve revoke 11111111-1111-1111-1111-111111111111
```

## Access-change approvals

`trstctl-cli access requests` opens and decides NHI entitlement changes against PR,
ticket, or CAB evidence. The create and decide commands are mutating API calls and send an
`Idempotency-Key`; retrying the same key returns the original request or decision instead
of recording a duplicate.

```bash
cat > access-request.json <<'JSON'
{
  "requested_action": "grant",
  "nhi_id": "github-app:prod-deployer",
  "nhi_kind": "oauth_app",
  "display_name": "Prod deployer GitHub App",
  "resource": "github:org/prod-infra",
  "entitlement": "repo:contents:write",
  "change_ref": "github:org/prod-infra#4821",
  "change_url": "https://github.com/org/prod-infra/pull/4821",
  "risk": "high",
  "required_approvals": 2,
  "reason": "Scoped deployment automation access",
  "evidence_refs": ["pull:4821/checks", "ticket:CAB-4821"]
}
JSON

trstctl-cli --idempotency-key access-4821-open access requests create -f access-request.json
trstctl-cli access requests list --status pending
trstctl-cli access requests get 77777777-7777-4777-8777-777777777777

cat > access-decision.json <<'JSON'
{
  "decision": "approved",
  "reason": "PR checks and CAB ticket match the requested entitlement.",
  "decision_evidence_refs": ["github-review:security-reviewer"]
}
JSON

trstctl-cli --idempotency-key access-4821-approval-1 access requests decide 77777777-7777-4777-8777-777777777777 -f access-decision.json
```

The requester cannot approve their own request, and the same approver cannot be counted
twice. Any denial makes the request terminal; approvals move it to `approved` only after
the required count is met.

## Ephemeral API keys

`trstctl-cli ephemeral api-keys issue` mints a narrow, short-TTL bearer token through
`POST /api/v1/ephemeral/api-keys`. The response prints the raw `trst_...` token once;
the server stores only the token hash and the leaseworker records `api_token.revoked`
after `ttl_seconds`.

```bash
cat > ephemeral-api-key.json <<'JSON'
{"subject":"ci-preview-deploy","scopes":["access:read"],"ttl_seconds":900}
JSON
trstctl-cli --idempotency-key ci-preview-key ephemeral api-keys issue -f ephemeral-api-key.json
```

## Bootstrapping the first API token

`trstctl-cli` authenticates with an API token, but a freshly deployed control
plane has none and fails closed (every route `401`s). Mint the first one with the
**server** binary's first-run bootstrap verb, run on the control-plane host — it
writes straight to the datastore (no existing credential, no network trust
required) and prints a tenant-scoped token once:

```bash
trstctl token create --tenant <uuid> [--subject <name>] [--scopes a,b,c] [--tenant-name <label>]
```

- `--tenant` (required) is the UUID the token is scoped to; the tenant is
  registered through the event log if it does not exist yet.
- The default scope set is full operator control **excluding** certificate
  issuance (`certs:issue`) — bootstrapping a credential never grants self-issue.
- The raw `trst_…` token is printed once to stdout (only its hash is stored); save
  it immediately. Then export it as `TRSTCTL_TOKEN` for `trstctl-cli`.

## Examples

```bash
export TRSTCTL_SERVER=https://localhost:8443
export TRSTCTL_TOKEN=trst_...

# Create an owner from a JSON body on stdin.
echo '{"kind":"workload","name":"payments"}' | trstctl-cli owners create -f -

# Show managed and discovered NHI attribution by human owner, team, vendor, or orphan state.
trstctl-cli owners attribution

# Decommission NHIs selected from departure, vendor-term, or inactivity signals.
trstctl-cli nhi decommission -f nhi-decommission.json --force

# List shadow, unmanaged, and unregistered NHI posture findings.
trstctl-cli nhi posture shadow

# List governed NHI policy violations for rotation, scope, geography, expiry, and purpose.
trstctl-cli nhi policy compliance

# Author, activate, list, and roll back lifecycle policy versions served by the mutation gate.
trstctl-cli policy versions create -f lifecycle-policy-version.json
trstctl-cli policy versions list
trstctl-cli policy versions activate <version-id> -f policy-activation.json
trstctl-cli policy versions rollback <version-id> -f policy-rollback.json

# List usage-backed NHI over-privilege findings and least-privilege recommendations.
trstctl-cli nhi posture overprivilege

# List stale, unused, orphaned, and dormant NHI posture findings.
trstctl-cli nhi posture stale

# List long-lived and static NHI credential posture findings.
trstctl-cli nhi posture static-credentials

# List internet-exposed and insecure-deployment NHI posture findings.
trstctl-cli nhi posture exposure

# List and run automated remediation playbooks.
trstctl-cli remediation playbooks
trstctl-cli remediation playbooks run nhi-right-size -f right-size.json --force
trstctl-cli remediation playbook-runs list --playbook_id nhi-right-size
trstctl-cli remediation owner-actions list --owner_id 11111111-1111-1111-1111-111111111111
trstctl-cli remediation owner-actions accept right-size-aWRlbnRpdHkvMTEx -f accept-owner-action.json --force

# Dispatch one incident response packet to SIEM, SOAR, chat, and ITSM sinks.
trstctl-cli incidents response-integrations dispatch -f response-dispatch.json

# List the certificate inventory.
trstctl-cli certificates list --limit 50

# Show full, sharded, and delta CRL distribution artifacts for the tenant.
trstctl-cli revocation crls

# List rogue and non-compliant certificate posture findings.
trstctl-cli revocation rogue-certificates

# Queue a precertificate and final certificate for RFC 6962 CT log submission.
trstctl-cli revocation ct-submit -f ct-submission.json

# Show the regional HA issuance posture and write fences.
trstctl-cli scale ha-issuance

# Start a root CA ceremony, collect two approvals, then create the root.
cat > root-ceremony.json <<'JSON'
{"operation":"create_root","threshold":2,"spec":{"common_name":"Example Root CA","ttl_seconds":315360000,"signature_algorithm":"ECDSA-P256","max_path_len":1,"permitted_dns_domains":["example.internal"]}}
JSON
trstctl-cli ca ceremonies start -f root-ceremony.json
# Run each approval with a distinct custodian token.
trstctl-cli ca ceremonies approve <ceremony-id>
trstctl-cli ca ceremonies approve <ceremony-id>

cat > root-create.json <<'JSON'
{"ceremony_id":"<ceremony-id>","spec":{"common_name":"Example Root CA","ttl_seconds":315360000,"signature_algorithm":"ECDSA-P256","max_path_len":1,"permitted_dns_domains":["example.internal"]}}
JSON
trstctl-cli ca authorities create-root -f root-create.json

# Import an offline root, generate a signer-held intermediate CSR, sign it offline,
# then import the signed intermediate.
cat > offline-root-ceremony.json <<'JSON'
{"operation":"import_offline_root","threshold":2,"certificate_pem":"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n","spec":{"common_name":"Example Offline Root CA","ttl_seconds":315360000,"signature_algorithm":"ECDSA-P256","max_path_len":1,"permitted_dns_domains":["example.internal"]}}
JSON
trstctl-cli ca ceremonies start -f offline-root-ceremony.json
trstctl-cli ca ceremonies approve <offline-root-ceremony-id>
trstctl-cli ca ceremonies approve <offline-root-ceremony-id>

cat > offline-root-import.json <<'JSON'
{"ceremony_id":"<offline-root-ceremony-id>","certificate_pem":"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n","spec":{"common_name":"Example Offline Root CA","ttl_seconds":315360000,"signature_algorithm":"ECDSA-P256","max_path_len":1,"permitted_dns_domains":["example.internal"]}}
JSON
trstctl-cli ca authorities import-offline-root -f offline-root-import.json

# Import an existing root/intermediate chain bound to a signer-held key handle.
cat > existing-ca-ceremony.json <<'JSON'
{"operation":"import_existing_ca","threshold":2,"certificate_pem":"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n","signer_handle":"customer-existing-ca","spec":{"common_name":"Example Imported Issuing CA","ttl_seconds":71280000,"signature_algorithm":"ECDSA-P256","max_path_len":0,"permitted_dns_domains":["example.internal"]}}
JSON
trstctl-cli ca ceremonies start -f existing-ca-ceremony.json
trstctl-cli ca ceremonies approve <existing-ca-ceremony-id>
trstctl-cli ca ceremonies approve <existing-ca-ceremony-id>

cat > existing-ca-import.json <<'JSON'
{"ceremony_id":"<existing-ca-ceremony-id>","certificate_pem":"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n","signer_handle":"customer-existing-ca","spec":{"common_name":"Example Imported Issuing CA","ttl_seconds":71280000,"signature_algorithm":"ECDSA-P256","max_path_len":0,"permitted_dns_domains":["example.internal"]}}
JSON
trstctl-cli ca authorities import-existing -f existing-ca-import.json

cat > offline-intermediate-ceremony.json <<'JSON'
{"operation":"create_offline_intermediate","parent_id":"<offline-root-authority-id>","threshold":2,"spec":{"common_name":"Example Issuing Intermediate","ttl_seconds":71280000,"signature_algorithm":"ECDSA-P256","max_path_len":0,"permitted_dns_domains":["example.internal"]}}
JSON
trstctl-cli ca ceremonies start -f offline-intermediate-ceremony.json
trstctl-cli ca ceremonies approve <offline-intermediate-ceremony-id>
trstctl-cli ca ceremonies approve <offline-intermediate-ceremony-id>

cat > offline-intermediate-csr.json <<'JSON'
{"ceremony_id":"<offline-intermediate-ceremony-id>","spec":{"common_name":"Example Issuing Intermediate","ttl_seconds":71280000,"signature_algorithm":"ECDSA-P256","max_path_len":0,"permitted_dns_domains":["example.internal"]}}
JSON
trstctl-cli ca authorities offline-intermediate-csr <offline-root-authority-id> -f offline-intermediate-csr.json

cat > offline-intermediate-import.json <<'JSON'
{"ceremony_id":"<offline-intermediate-ceremony-id>","certificate_pem":"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n","spec":{"common_name":"Example Issuing Intermediate","ttl_seconds":71280000,"signature_algorithm":"ECDSA-P256","max_path_len":0,"permitted_dns_domains":["example.internal"]}}
JSON
trstctl-cli ca authorities import-offline-intermediate <offline-root-authority-id> -f offline-intermediate-import.json

# Sign an external intermediate CA CSR, for example SPIRE's local server CA.
cat > spire-intermediate.json <<'JSON'
{"csr_pem":"-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----\n","spec":{"common_name":"SPIRE Server CA","ttl_seconds":3600,"max_path_len":0,"permitted_dns_domains":["example.org"]}}
JSON
trstctl-cli --idempotency-key spire-upstream-root-1 ca authorities issue-intermediate-csr <ca-authority-id> -f spire-intermediate.json

# Re-key a signer-backed CA authority after a purpose-bound ceremony.
cat > ca-rekey-ceremony.json <<'JSON'
{"operation":"rekey_ca","authority_id":"<ca-authority-id>","threshold":2,"spec":{"common_name":"Reviewed CA re-key"}}
JSON
trstctl-cli ca ceremonies start -f ca-rekey-ceremony.json

cat > ca-rekey.json <<'JSON'
{"ceremony_id":"<rekey-ceremony-id>","ttl_seconds":7776000,"reason":"planned CA renewal"}
JSON
trstctl-cli ca authorities rekey <ca-authority-id> -f ca-rekey.json

# Cross-sign one exact public target CA after a cross_sign_ca ceremony reaches quorum.
printf '{"ceremony_id":"<cross-sign-ceremony-id>","certificate_pem":"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"}' > ca-cross-sign.json
trstctl-cli ca authorities cross-sign <issuer-authority-id> -f ca-cross-sign.json

# Import an offline-root successor and both public cross-certificates. The private
# root keys never enter these files or trstctl.
trstctl-cli ca authorities rekey-offline-root <offline-root-authority-id> -f offline-root-rekey.json
trstctl-cli ca authorities import-offline-cross-sign <successor-authority-id> -f offline-target-cross.json

# Online break-glass uses an exact intent ceremony and authenticated CA approvals;
# the execution body carries ceremony_id but never approver names.
trstctl-cli breakglass issue-ceremony -f breakglass-issue-intent.json
trstctl-cli ca ceremonies approve <breakglass-ceremony-id> # distinct operator token A
trstctl-cli ca ceremonies approve <breakglass-ceremony-id> # distinct operator token B
trstctl-cli breakglass issue -f breakglass-issue.json

# Rotation and target cross-signing use the same ceremony -> approvals -> execute pattern.
trstctl-cli breakglass rotation-ceremony -f breakglass-rotation-intent.json
trstctl-cli breakglass rotate -f breakglass-rotation.json
trstctl-cli breakglass cross-sign-ceremony -f breakglass-cross-sign-intent.json
trstctl-cli breakglass cross-sign -f breakglass-cross-sign.json

# List configured upstream CAs and issue through one of them.
trstctl-cli external-cas list
cat > upstream-issue.json <<'JSON'
{"csr_pem":"-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----\n","dns_names":["payments.example.com"],"ttl_seconds":86400}
JSON
trstctl-cli external-cas issue digicert -f upstream-issue.json

# Rank credentials by risk — what to rotate first.
trstctl-cli risk credentials --sort score
trstctl-cli risk contextual-priorities

# Export a signed SOC 2 evidence pack from audit, access, and change evidence.
trstctl-cli compliance evidence-pack soc2

# Export FIPS 140 and Common Criteria evidence posture.
trstctl-cli compliance evidence-pack fips-140
trstctl-cli compliance evidence-pack common-criteria

# Export regulatory framework evidence mappings.
trstctl-cli compliance evidence-pack nist-800-53
trstctl-cli compliance evidence-pack fedramp
trstctl-cli compliance evidence-pack cmmc-2.0
trstctl-cli compliance evidence-pack eidas
trstctl-cli compliance evidence-pack nis2

# Export CA/Browser Forum Baseline Requirements evidence posture.
trstctl-cli compliance evidence-pack cabf-br

# Show CAP-OBS-02 compliance/inventory reporting coverage and served report routes.
trstctl-cli compliance inventory-report

# Show CAP-CMP-06 NHI compliance mappings for NIST 800-53/CSF, PCI DSS 4.0,
# DORA, ISO 27001, FedRAMP, CMMC, eIDAS, and NIS2 evidence refs.
trstctl-cli compliance nhi-report

# Record and list an audit-export report schedule definition. The delivery value is
# metadata for the audit-export workflow; email/webhook delivery is not implied.
cat > compliance-schedule.json <<'JSON'
{"framework":"soc2","name":"weekly-soc2-pack","report_type":"framework_evidence_pack","interval_seconds":604800,"delivery":"audit_export","recipient_ref":"audit-archive"}
JSON
trstctl-cli --idempotency-key weekly-soc2 compliance report-schedules create -f compliance-schedule.json
trstctl-cli compliance report-schedules list

# Scan TLS endpoints/config files into the cryptographic bill of materials.
cat > cbom-scan.json <<'JSON'
{"tls_endpoints":["payments.internal.example:443"],"host_configs":["/etc/nginx/sites-enabled/payments.conf"]}
JSON
trstctl-cli cbom scan -f cbom-scan.json
trstctl-cli cbom assets

# Migrate what the CBOM found (Enterprise PQC license required; an unlicensed
# server answers 404 because it does not serve these routes). Start returns a
# run id, status reports per-finding progress, and rollback reverses an applied
# run.
cat > migration-start.json <<'JSON'
{"finding_ids":["<cbom-finding-id>"],"rollback_on_failure":true}
JSON
trstctl-cli --idempotency-key migrate-payments-1 migration start -f migration-start.json
trstctl-cli migration status <run-id>
trstctl-cli --idempotency-key migrate-payments-1-rollback migration rollback <run-id>

# Mint a one-time agent bootstrap token. Pass allowed_identity when the token
# should redeem only for one node or host identity.
trstctl-cli agents enroll-token
printf '{"allowed_identity":"node-a"}\n' | trstctl-cli agents enroll-token -f -
trstctl-cli agents list
printf '{"reason":"host decommissioned"}\n' | trstctl-cli --idempotency-key agent-node-a-offboard-1 agents offboard <agent-id> -f - --force

# Issue a policy-gated short-lived credential for an AI/MCP agent.
cat > broker-agent.json <<'JSON'
{"agent_id":"agent-7","method":"k8s_sat","payload_base64":"<proof-base64>","public_key_pem":"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n","scopes":["mcp:graph.read","tool:inventory.read"],"ttl_seconds":600}
JSON
trstctl-cli --idempotency-key agent-7-issue-1 broker agent-identities issue -f broker-agent.json

# Open an attestation-gated JIT credential request, approve it, then mint it.
cat > ephemeral-jit.json <<'JSON'
{"request_id":"jit-agent-7","method":"k8s_sat","payload_base64":"<proof-base64>","public_key_pem":"-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n","ttl_seconds":120}
JSON
trstctl-cli --idempotency-key jit-agent-7-request-1 ephemeral issue -f ephemeral-jit.json
printf '{"action":"issue"}' | trstctl-cli --idempotency-key jit-agent-7-approve-1 ephemeral approve jit-agent-7 -f -
trstctl-cli --idempotency-key jit-agent-7-issue-1 ephemeral issue -f ephemeral-jit.json

# Issue, renew, read, and revoke a dynamic secret lease from a configured provider.
cat > dynamic-lease.json <<'JSON'
{"provider":"postgresql","role":"readonly","ttl_seconds":900}
JSON
trstctl-cli --idempotency-key lease-issue-1 secrets leases issue -f dynamic-lease.json
trstctl-cli secrets leases get <lease-id>
printf '{"extend_seconds":900}' | trstctl-cli --idempotency-key lease-renew-1 secrets leases renew <lease-id> -f -
trstctl-cli --idempotency-key lease-revoke-1 secrets leases revoke <lease-id> --force

# Generate and retire an HSM/KMS-backed managed key after managed_keys is enabled.
cat > managed-key.json <<'JSON'
{"algorithm":"RSA-2048"}
JSON
trstctl-cli --idempotency-key kms-key-1 managed-keys generate -f managed-key.json
printf '{"key_id":"<key-id>","action":"rotate"}' | trstctl-cli --idempotency-key kms-key-1-approve-a managed-keys approve -f -
printf '{"key_id":"<key-id>","action":"rotate"}' | trstctl-cli --idempotency-key kms-key-1-approve-b managed-keys approve -f -
printf '{"key_id":"<key-id>"}' | trstctl-cli --idempotency-key kms-key-1-rotate managed-keys rotate -f - --force
printf '{"key_id":"<rotated-key-id>","action":"zeroize"}' | trstctl-cli --idempotency-key kms-key-1-zeroize-approve-a managed-keys approve -f -
printf '{"key_id":"<rotated-key-id>","action":"zeroize"}' | trstctl-cli --idempotency-key kms-key-1-zeroize-approve-b managed-keys approve -f -
printf '{"key_id":"<rotated-key-id>"}' | trstctl-cli --idempotency-key kms-key-1-zeroize managed-keys zeroize -f - --force

# Run rollback-safe static, connector-backed, or dynamic-lease rotation.
cat > static-rotation.json <<'JSON'
{"provider":"postgresql","key":"db/reporting","old_ref":"sec05_old"}
JSON
trstctl-cli --idempotency-key static-rotation-1 secrets rotations run -f static-rotation.json
printf '{"provider":"connector:ci","key":"db/password","old_ref":"version:2","remote_key":"DB_PASSWORD"}' \
  | trstctl-cli --idempotency-key connector-rotation-1 secrets rotations run -f -
printf '{"provider":"dynamic-lease:postgresql","key":"readonly","old_ref":"lease-abc","target":"ci","remote_key":"DB_READONLY_DSN","ttl_seconds":600}' \
  | trstctl-cli --idempotency-key dynamic-rotation-1 secrets rotations run -f -

# Schedule the same dual-phase rotation and run due schedules from the served path.
cat > static-rotation-schedule.json <<'JSON'
{"name":"reporting-hourly","provider":"postgresql","key":"db/reporting","old_ref":"sec05_old","interval_seconds":3600}
JSON
trstctl-cli --idempotency-key static-rotation-schedule-1 secrets rotation-schedules create -f static-rotation-schedule.json
trstctl-cli secrets rotation-schedules list
trstctl-cli --idempotency-key static-rotation-due-1 secrets rotation-schedules run-due

# Push a stored secret to a configured external sync target. The response contains
# metadata only; the secret value is never echoed back.
cat > secret-sync.json <<'JSON'
{"name":"sync/source","target":"github-actions","remote_key":"DB_PASSWORD"}
JSON
trstctl-cli --idempotency-key secret-sync-1 secrets syncs run -f secret-sync.json

# Discover supported and configured target IDs before choosing the target field.
trstctl-cli secrets syncs targets

# Inspect CAP-SEC-04 cloud secret-manager discovery and sync posture.
trstctl-cli secrets cloud-secret-managers

# Inspect the Kubernetes SecretSync CRD, Secret projection, and reload posture.
trstctl-cli secrets kubernetes-operator

# Inspect the no-code workload secret-injection CRD, sidecar, and env/file posture.
trstctl-cli secrets workload-injection

# Inspect unvaulted-secret detection, visible vaults, and augmentation targets.
trstctl-cli secrets unvaulted

# Inspect native Kubernetes CertificateSigningRequest support, signer names, and RBAC.
trstctl-cli kubernetes csr

# Inspect Kubernetes TrustBundle CRD, ConfigMap distribution, status fields, and RBAC.
trstctl-cli kubernetes trust-bundles

# Run a Gitleaks code scan from CI and record redacted findings in discovery/graph.
cat > secret-scan.json <<'JSON'
{"path":"."}
JSON
trstctl-cli --idempotency-key secret-scan-1 secrets scans run -f secret-scan.json

# Scan full Git history with the default 213-rule floor plus additive custom rules.
cat > deep-secret-scan.json <<'JSON'
{"path":".","mode":"git_history","custom_rules_path":"./gitleaks-custom-rules.toml"}
JSON
trstctl-cli --idempotency-key secret-scan-deep-1 secrets scans run -f deep-secret-scan.json

# Block local commits on staged Git blobs without requiring a running control plane.
trstctl-cli secrets scans staged-diff --repo .
trstctl-cli secrets scans pre-commit install --repo .

# Run the same local scanner over the head side of a base/head CI diff.
trstctl-cli secrets scans staged-diff --repo . --base origin/main --head HEAD

# Inspect repository secret-scanning posture, then queue a normalized provider event.
trstctl-cli secrets scans repositories
cat > repo-webhook.json <<'JSON'
{"repository":"acme/payments","checkout_path":".","ref":"refs/heads/main","event":"push"}
JSON
trstctl-cli --idempotency-key repo-scan-1 secrets scans repositories webhook github -f repo-webhook.json

# Inspect CI-log, container-registry, Slack, and Jira artifact scanning posture,
# then queue a redacted third-party artifact scan through the discovery outbox.
trstctl-cli secrets scans third-party
cat > third-party-scan.json <<'JSON'
{"source":"acme/slack","artifact_path":"/var/lib/trstctl/exports/slack.jsonl","event":"message_export"}
JSON
trstctl-cli --idempotency-key third-party-scan-1 secrets scans third-party ingest slack -f third-party-scan.json

# Create a transit AEAD key, encrypt data, rotate, and rewrap to the newest version.
cat > transit-key.json <<'JSON'
{"name":"payments","kind":"aead"}
JSON
trstctl-cli --idempotency-key transit-payments-create transit keys create -f transit-key.json

cat > transit-encrypt.json <<'JSON'
{"key":"payments","plaintext":"Y2FyZC10b2tlbi0xMjM=","aad":"dGVuYW50PXBheW1lbnRz"}
JSON
trstctl-cli --idempotency-key transit-payments-encrypt transit encrypt -f transit-encrypt.json
trstctl-cli --idempotency-key transit-payments-rotate transit keys rotate -f transit-key.json

cat > transit-rewrap.json <<'JSON'
{"key":"payments","ciphertext":"trv:1:<ciphertext-from-encrypt>","aad":"dGVuYW50PXBheW1lbnRz"}
JSON
trstctl-cli --idempotency-key transit-payments-rewrap transit rewrap -f transit-rewrap.json

# Sign an artifact digest with a configured code-signing key. The response contains
# the signature, public key, algorithm, and transparency outbox destination.
cat > code-sign.json <<'JSON'
{"key_id":"release-key","artifact_type":"oci-image","digest":"4EW4IfBBkDngEwN3v+ChO06PV2er4tF7nEVmFev3x1g="}
JSON
trstctl-cli --idempotency-key release-sign-1 code-signing sign -f code-sign.json

# Sign keylessly with a verified Fulcio/Sigstore identity proof. identity_payload is
# base64 JSON bytes; the served attestor verifies it before the signature is issued.
cat > code-sign-keyless.json <<'JSON'
{"artifact_type":"oci-image","digest":"4EW4IfBBkDngEwN3v+ChO06PV2er4tF7nEVmFev3x1g=","identity_method":"github_oidc","identity_payload":"eyJqd3QiOiJleGFtcGxlIn0=","fulcio_san":"repo:acme/payments:ref:refs/heads/main","fulcio_issuer":"https://token.actions.githubusercontent.com"}
JSON
trstctl-cli --idempotency-key release-keyless-1 code-signing keyless -f code-sign-keyless.json

# On an enrolled host, report local public certificate files over the agent channel.
trstctl-agent --enroll-url https://localhost:8443 \
  --bootstrap-token-file ./trstctl-bootstrap-token \
  --server localhost:9443 \
  --name edge-agent-1 \
  --ca-bundle ./trstctl-ca.pem \
  --inventory-cert-roots /etc/ssl,/etc/pki/tls/certs \
  --inventory-os-trust-roots /etc/ssl/certs \
  --inventory-java-trust-stores "$JAVA_HOME/lib/security/cacerts" \
  --inventory-private-key-roots /etc/ssl/private,/etc/ssh
trstctl-cli discovery findings list

# Run a graph query.
trstctl-cli graph query "MATCH (c:Certificate)-[:SIGNED_BY]->(i:Issuer) RETURN c,i"
```

Run the two managed-key `approve` commands with tokens for two different
authenticated principals holding `keys:approve`. The requester cannot approve their
own action, even if that principal also holds `keys:approve`. Approval bodies keep
`key_id` in JSON so opaque cloud-KMS URLs and HSM handles containing `/` are
preserved exactly; `action` is one of `rotate`, `revoke`, or `zeroize`.

`--inventory-private-key-roots` locates and classifies private-key files on the host
but reports only metadata: path, key format, algorithm, file-mode status, and a
public-key-derived fingerprint when one can be computed. The agent wipes file buffers
after inspection and never sends PEM/DER key bytes to the control plane.

Path parameters are positional; list filters (`--limit`, `--cursor`, `--sort`,
…) are flags; request bodies come from `-f <file>` or `-f -` (stdin).
