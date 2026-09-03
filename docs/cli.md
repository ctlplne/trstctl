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
separate program with four admin command families of its own — `token create` (see
"Bootstrapping the first API token" below), `connector target ...`, `ssh ...`, and
the offline `support-bundle`
— for direct calls against a running control plane, using their own `--flag`
arguments and `TRSTCTL_URL` rather than the `-f <file>` bodies and
`TRSTCTL_SERVER` used everywhere else on this page. Those direct operational
commands also honor `TRSTCTL_CA_FILE`; set it to the inspected public CA or
self-signed public certificate for a private/self-hosted control plane. They do
not provide an option that disables TLS verification. A private control-plane
hostname may additionally need a narrow comma-separated
`TRSTCTL_EGRESS_ALLOW_PRIVATE_CIDRS` value (for example, the one internal subnet
that owns it); localhost needs no exception, and metadata/link-local ranges stay
blocked.

The exception is `trstctl support-bundle`: it deliberately does not require a
running HTTP server. Use
`trstctl support-bundle --output support.tar.gz --log-file <local-log>` during
cold-start failures. The archive is bounded, contains posture and aggregate counts
instead of raw configuration, and refuses residual secret/PII data after redaction.
It stays offline by default. `--include-enrollment-diagnostics` is the explicit
exception: it requires `TRSTCTL_URL` and `TRSTCTL_TOKEN`, fetches the authorized
aggregate-only addendum, and still excludes tenant, operation, identity, endpoint,
diagnostic, and timestamp references.

## Global flags

Every command accepts these, each with a `TRSTCTL_*` environment fallback:

| Flag                | Env                       | Meaning                                                   |
| ------------------- | ------------------------- | --------------------------------------------------------- |
| `--server`          | `TRSTCTL_SERVER`          | Base URL of the control plane.                            |
| `--token`           | `TRSTCTL_TOKEN`           | API token, sent as `Authorization: Bearer`.               |
| `--tenant`          | `TRSTCTL_TENANT`          | Tenant id (`X-Tenant-ID`) for header/dev auth.            |
| `--ca-file`         | `TRSTCTL_CA_FILE`         | PEM CA bundle used to verify the control plane.           |
| `--idempotency-key` | `TRSTCTL_IDEMPOTENCY_KEY` | Stable key for safe retries; generated per call if unset. |

A trstctl API token carries its own tenant and scopes, so with `--token` you
usually need nothing else. Mutations always send an `Idempotency-Key` so a
retried command can never execute twice.

For an evaluation server using its self-signed internal certificate, point
`--ca-file` at the public certificate you inspected and chose to trust. Internal
mode persists its private identity in `data/tls/internal-server.pem`, so a normal
restart with the same data volume keeps that pin valid. Never copy that combined
private state file to a client; capture only the public certificate from the TLS
endpoint. A missing data volume is a new identity and must be inspected again.
Production deployments should use the operator-managed CA bundle for
`server.tls.mode=file`. The CLI deliberately has no switch that disables
certificate verification.

## Output and exit codes

Responses are pretty-printed JSON on stdout. Exit code is **0** on success, **1**
on a request/response error (the status is written to stderr), and **2** on a
usage error — scriptable end to end.

## Verify audit exports offline

Search and export accept the same optional filters: `--tool`, `--feature_id`,
`--action`, `--type`, `--since`, `--until`, `--as_of`, `--q`, and `--limit`.
The server intersects them before applying the limit. `--tool` accepts `discover`,
`certificates`, `workloads_machines`, `secrets`, `software_trust`, `operations`,
or the supporting `platform_integrations` area. Omit it for the whole tenant
stream; an unknown tool is an error, not an unfiltered result. Shared lifecycle
records can appear in more than one tool without creating another audit stream.

```bash
trstctl-cli audit events --tool workloads_machines --limit 100
trstctl-cli audit export --tool workloads_machines --as_of 120 --limit 100 --format ndjson > workload-audit.ndjson
```

Here `--as_of 120` means “up to tenant-local event sequence 120,” not the newest
120 events. A retained export carries its archived-prefix hash so the verifier
can check the surviving chain. A tool filter never overrides tenant permissions,
privacy redaction or the configured retention window.

`trstctl-cli audit verify` is a local command: it opens no HTTP connection and
does not need `TRSTCTL_SERVER`, a token, or a running control plane. It verifies
the canonical JWS envelope and the exact CSV, NDJSON, Splunk HEC (`splunk-hec`),
and Microsoft Sentinel (`sentinel`) record-stream shapes served by `audit export`.

Bootstrap trust **before disconnecting** from the deployment:

```bash
# This authenticated read returns only the current audit signer's public RSA JWK.
trstctl-cli audit verification-keys > audit.jwks.json

# Obtain this out of band from the deployment PKI operator. Use the root CA that
# issued the configured TSA certificate, not the TSA leaf carried by an export.
cp /trusted/pki/trstctl-tsa-root.pem tsa-root.pem
```

Pin those two files in the auditor's trust inventory. The verification command
never trusts a JWK, TSA root, or replacement authority supplied only by the saved
artifact: an attacker who can replace evidence could replace embedded trust too.
The TSA root may be PEM or DER. The JWK set is required for `jws`; record-stream
formats rely on the hash chain plus the separately trusted RFC 3161 authority.

Download any served shape while the control plane is online, then verify it after
the server is gone:

```bash
trstctl-cli audit export --format jws > audit.jws.json
trstctl-cli audit export --format csv > audit.csv
trstctl-cli audit export --format ndjson > audit.ndjson
trstctl-cli audit export --format splunk-hec > audit.splunk.ndjson
trstctl-cli audit export --format sentinel > audit.sentinel.ndjson

trstctl-cli audit verify \
  --artifact audit.jws.json \
  --format auto \
  --audit-jwks audit.jwks.json \
  --tsa-root tsa-root.pem \
  --max-anchor-delay 24h

# A record stream does not use the audit JWK, but gets the same chain/TSA checks.
trstctl-cli audit verify --artifact audit.csv --format auto \
  --tsa-root tsa-root.pem --max-anchor-delay 24h

# Pipe a saved artifact instead of naming a file.
trstctl-cli audit verify --artifact - --format ndjson \
  --tsa-root tsa-root.pem < audit.ndjson
```

`auto` identifies only the five pinned served grammars; use an explicit format for
an empty or otherwise ambiguous JSON stream. Verification starts from the trailer
or signed bundle's `prev_hash`, so a live suffix after an archived prefix is checked
as a continuation rather than incorrectly treated as a new genesis. It recomputes
every record link and chain head, verifies the audit JWS domain where applicable,
verifies the domain-separated RFC 3161 timestamp imprint and TSA chain, and applies
the optional maximum anchor delay from the newest record to authority time.

Success prints a non-secret JSON receipt with format, tenant when present, record
count, archived-prefix hash, chain head, anchor kind/time, and newest-record time.
Malformed input, duplicate authority fields, tamper, truncation, wrong trust, head
mismatch, cross-tenant records, excessive input, or a delay-policy violation returns
exit code 1 and writes a stable `audit verification failed` diagnostic to stderr.
Invalid flags return exit code 2.

## Commands

One row per command group — covering every core API operation — plus the local
`run` wrapper for developer secret injection (kept in sync by hand, per the note
above). Each row gives a one-line purpose plus representative verbs, not an
exhaustive subcommand list:

| Group                             | Purpose (representative verbs)                                                                                                                                                                                                                                                                                      |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `access`                          | Tenant membership, API tokens, JIT privileged-access sessions, and NHI access-change requests/reviews (`roles` · `oidc-mapping` · `members` · `tokens` · `sessions` · `requests` · `reviews`)                                                                                                                       |
| `acme`                            | ACME ARI publication/scheduler posture plus DNS-01 provider coverage, secret-referenced provider configs, and propagation/CAA/wildcard preflight (`ari posture` · `dns-01 providers` · `dns-01 provider-configs` · `dns-01 preflight`)                                                                              |
| `agents`                          | In-network agent inventory, enrollment tokens, cert revocation, offboarding (`list` · `enroll-token` · `revoke-cert` · `offboard`)                                                                                                                                                                                  |
| `ai`                              | AI assistant status, question answering, root-cause analysis (`status` · `query` · `rca`)                                                                                                                                                                                                                           |
| `approval-requests`               | Review immutable certificate, secret, and managed-key operation requests within the caller's real permission domains (`list` · `approve` · `deny`)                                                                                                                                                                  |
| `audit`                           | Query/export the signed audit log, pin public verification keys, verify every saved format offline, and configure native collector feeds (`events` · `export` · `verification-keys` · `verify` · `feeds set` · `feeds list`)                                                                                        |
| `breakglass`                      | Ceremony-gated online break-glass issuance, rotation, cross-signing, and offline-bundle reconciliation (`issue-ceremony` · `issue` · `rotation-ceremony` · `rotate` · `cross-sign-ceremony` · `cross-sign` · `reconcile`)                                                                                           |
| `broker agent-identities`         | Issue a policy-gated AI/MCP agent identity (`issue`)                                                                                                                                                                                                                                                                |
| `ca ceremonies`                   | Effect-free review, start, inspect, and approve m-of-n CA key ceremonies (`preview` · `start` · `get` · `approve`)                                                                                                                                                                                                  |
| `ca authorities`                  | Private CA authority lifecycle — create/import roots and intermediates, preview/activate rotation, rekey, cross-sign, issue leaf certs (`list` · `create-root` · `import-offline-root` · `import-existing` · `create-intermediate` · `rotate-preview` · `rotate` · `rekey` · `cross-sign` · `issue`)                |
| `ca discovery`                    | List public and private CA discovery inventory (`list`)                                                                                                                                                                                                                                                             |
| `cbom`                            | Cryptographic bill of materials: effect-free plan review, bounded scan, inventory (`preview` · `scan` · `assets`)                                                                                                                                                                                                   |
| `pqc campaigns`                   | Core PQC migration ownership and evidence workflow (`create` · `list` · `get` · `update` · `readiness` · `disposition` · `close` · `evidence`)                                                                                                                                                                      |
| `certificates`                    | Certificate inventory: ingest, list, get, health, bulk-revoke (`ingest` · `list` · `get` · `health` · `bulk-revoke`)                                                                                                                                                                                                |
| `code-signing`                    | Review and sign artifact digests with a managed key or a keyless Sigstore/Fulcio identity (`identities` · `preview` · `sign` · `keyless-preview` · `keyless`)                                                                                                                                                                               |
| `compliance`                      | Compliance/inventory reporting and signed evidence-pack export (`inventory-report` · `nhi-report` · `report-schedules` · `evidence-pack`)                                                                                                                                                                           |
| `connector target`                | Deployment connector targets: create, bind, test, deploy, roll back (`create` · `list` · `get` · `update` · `delete` · `bind` · `test` · `deploy` · `rollback`)                                                                                                                                                     |
| `connectors`                      | Connector catalog, outbox circuit-breaker state, delivery receipts (`catalog` · `outbox-circuits` · `deliveries`)                                                                                                                                                                                                   |
| `discovery`                       | Discovery segments, sources, schedules, runs, findings, CT monitoring, drift remediation, continuous monitoring (`segments create` · `sources` · `schedules` · `runs` · `findings` · `ct-monitoring` · `drift-remediation` · `monitoring`)                                                                          |
| `editions`                        | Show edition, license, and FIPS posture (`status`)                                                                                                                                                                                                                                                                  |
| `ephemeral`                       | Approval-gated JIT credentials and reviewed short-TTL API keys (`issue` · `api-keys preview` · `api-keys issue` · `approve`)                                                                                                                                                                                        |
| `endpoints`                       | Read live endpoint identity and key-custody evidence, including one exact signed verification (`verifications` · `verifications get` · `key-custody`)                                                                                                                                                               |
| `enrollment diagnostics`          | Read exact tenant refusal evidence, export aggregate-only support counts, and queue signed proof after a successful retry (`list` · `support-addendum` · `prove-fixed`)                                                                                                                                             |
| `external-cas`                    | List and issue through configured upstream CA integrations (`list` · `issue`)                                                                                                                                                                                                                                       |
| `graph`                           | Query the credential graph and operate its canonical crypto-readiness workflow (`nodes` · `reachable` · `blast-radius` · `crypto-readiness` · `crypto-readiness actions create` · `crypto-readiness export` · `query`)                                                                                              |
| `identities`                      | Identity lifecycle: create, list, review an exact transition plan, execute it, approve dual-control actions, or bulk-revoke (`create` · `list` · `get` · `transition-preview` · `transition` · `approve` · `approve issue` · `approve rotate` · `approve revoke` · `bulk-revoke`)                                   |
| `incidents executions`            | Execute credential-compromise remediation and inspect evidence packs (`execute` · `list` · `get`)                                                                                                                                                                                                                   |
| `incidents response-integrations` | Dispatch an incident packet to SIEM/SOAR/chat/ITSM integrations (`dispatch`)                                                                                                                                                                                                                                        |
| `incidents fleet-reissuance`      | Exact-H1, signed-gate H2 compromised-issuer cohorts: start, list, get, pause, resume, current-cohort rollback, evidence (`start` · `list` · `get` · `pause` · `resume` · `rollback` · `evidence`)                                                                                                                   |
| `issuers`                         | Create, list, get certificate issuers (`create` · `list` · `get`)                                                                                                                                                                                                                                                   |
| `itsm servicenow tickets`         | Queue a ServiceNow ITSM ticket through the outbox (`create`)                                                                                                                                                                                                                                                        |
| `kubernetes`                      | Native Kubernetes CertificateSigningRequest and trust-bundle distribution support (`csr` · `trust-bundles`)                                                                                                                                                                                                         |
| `lifecycle`                       | Automated endpoint bindings and rotation-run history (`endpoint-bindings create` · `rotation-runs list` · `rotation-runs get`)                                                                                                                                                                                      |
| `managed-keys`                    | BYOK/HSM-resident key lifecycle: generate, dual-control approve, rotate, revoke, zeroize (`generate` · `approve` · `rotate` · `revoke` · `zeroize`)                                                                                                                                                                 |
| `managed-offering`                | Managed-offering/provider-plane posture and hosted-tenant provisioning (`status` · `tenants provision`)                                                                                                                                                                                                             |
| `mcp`                             | List and invoke the MCP tools the server exposes (`tools` · `call`)                                                                                                                                                                                                                                                 |
| `mdm`                             | MDM SCEP policy/challenge status and enrollment-policy management (`scep status` · `scep policies`)                                                                                                                                                                                                                 |
| `migration`                       | Licensed crypto-migration runs over CBOM findings — Enterprise PQC only (`plan` · `start` · `status` · `rollback`)                                                                                                                                                                                                  |
| `nhi`                             | Unified NHI inventory, posture findings, policy compliance, decommissioning (`inventory` · `posture shadow/stale/overprivilege/static-credentials/exposure` · `policy compliance` · `decommission`)                                                                                                                 |
| `notifications`                   | Notification channels, routing policies, inbox/dead-letter management (`channels` · `routing-policies` · `list` · `get` · `read` · `requeue`)                                                                                                                                                                       |
| `operations`                      | Operational telemetry for the bounded worker pools that carry backpressure (`bulkheads`)                                                                                                                                                                                                                            |
| `owners`                          | Owner CRUD, event-backed contextual/bulk assignment, application-model readiness, explicit attestation, expiring identity exceptions, and NHI attribution (`create` · `list` · `get` · `update` · `delete` · `assign` · `attest` · `exceptions list/grant/revoke` · `attribution`)                                  |
| `platform`                        | Show self-hostable run-anywhere distribution posture (`distribution`)                                                                                                                                                                                                                                               |
| `platform`                        | Running build, uptime, signer topology, and spine reachability (`system`)                                                                                                                                                                                                                                           |
| `policy`                          | Author, list, activate, and roll back lifecycle policy versions; dry-run a candidate module (`versions create/list/activate/rollback` · `dry-run`)                                                                                                                                                                  |
| `privacy`                         | Subject erasure, retention runs, archive-erasure attestations, export, personal-data catalog (`erasures` · `retention` · `archives` · `export` · `catalog`)                                                                                                                                                         |
| `profiles`                        | Certificate profile versions and append-only recovery (`create` · `list` · `get-version` · `restore-preview` · `restore`)                                                                                                                                                                                           |
| `remediation`                     | Automated remediation playbooks/runs and owner-driven self-remediation actions (`playbooks` · `playbooks run` · `playbook-runs list/get` · `owner-actions list/accept`)                                                                                                                                             |
| `revocation`                      | Published CRLs, signed relay endpoint health, rogue-certificate findings, CT-log submission (`crls` · `health` · `rogue-certificates` · `ct-submit`)                                                                                                                                                                |
| `risk`                            | Rank credentials by risk score, with blast-radius-aware prioritization (`credentials` · `contextual-priorities`)                                                                                                                                                                                                    |
| `run`                             | Local wrapper: run a child process with fetched secrets injected into its environment                                                                                                                                                                                                                               |
| `scale`                           | High-volume orchestration and multi-region HA issuance posture (`orchestration` · `ha-issuance`)                                                                                                                                                                                                                    |
| `secrets store`                   | Stored secrets: effect-free create review, then put, list, get, history, recover, update, delete (`preview` · `put` · `list` · `get` · `history` · `recover` · `update` · `delete`); bulk import is unavailable until an atomic event-sourced batch command exists                                                  |
| `secrets leases`                  | Dynamic secret leases: list safe provider setup/readiness, effect-free exact preview, then issue, get, renew, revoke (`providers` · `preview` · `issue` · `get` · `renew` · `revoke`)                                                                                                                                |
| `secrets rotations`               | Effect-free exact review, then worker-owned connector rotation; static and dynamic provider modes fail closed before effects (`preview` · `run`)                                                                                                                                                                    |
| `secrets rotation-schedules`      | Scheduled connector rotations with bounded durable due-run receipts (`create` · `list` · `run-due`)                                                                                                                                                                                                                 |
| `secrets syncs`                   | Push a stored secret to an external sync target (`run` · `targets`)                                                                                                                                                                                                                                                 |
| `secrets scans`                   | Gitleaks scanning: CI runs, repository/third-party webhooks, local pre-commit and staged-diff (`run` · `repositories` · `repositories webhook` · `third-party` · `third-party ingest` · `staged-diff` · `pre-commit install`)                                                                                       |
| `secrets shares`                  | Review without sending the value, create with safe same-key recovery, and redeem a one-time share (`preview` · `create` · `redeem`)                                                                                                                                                                                   |
| `secrets approvals`               | Approve a pending secret-store change (`approve`)                                                                                                                                                                                                                                                                   |
| `secrets`                         | Machine-auth login methods, machine-login sessions, credential exchange, preview-bound dynamic PKI secrets, cloud/Kubernetes/workload integration status (`auth-methods` · `sessions` · `login` · `pki preview` · `pki` · `cloud-secret-managers` · `kubernetes-operator` · `workload-injection` · `unvaulted`)                 |
| `setup`                           | Tenant-bound eval protocol profile status and activation (`protocols status` · `protocols activate`)                                                                                                                                                                                                                |
| `ssh`                             | SSH CA/KRL/attestation workflow status, trust rollout, exact effect-free previews, direct and attested issuance, safe unchanged-request recovery, revoke, host retirement (`fleet` · `status` · `trust-rollout` · `preview` · `issue` · `preview-attested-user` · `issue-attested-user` · `revoke` · `retire-host`) |
| `support`                         | Show enterprise support, SLA, and services posture (`enterprise`)                                                                                                                                                                                                                                                   |
| `transit keys`                    | List safe metadata, inspect full version history, create, and rotate a tenant-scoped Transit key (`list` · `versions` · `create` · `rotate`)                                                                                                                                                                       |
| `transit`                         | Read effect-free restore/KMIP status or encrypt, decrypt, rewrap, HMAC, sign, and verify with a transit key (`status` · `encrypt` · `decrypt` · `rewrap` · `hmac` · `sign` · `verify`)                                                                                                                              |
| `workloads`                       | Workload attester trust sources and attested X.509-SVID issuance (`attester-trust-sources create/list/get/update/rotate/revoke/delete` · `attested-issuance`)                                                                                                                                                       |

Plus `version`. `trstctl` (the server binary) additionally serves `token`,
`connector`, and `ssh` under its own conventions — see the callout above.

Before creating a native-store value, ask the same server oracle used by the
console to validate the exact name, owner, and transient value without writing it:

```bash
chmod 600 secret-create.json
# {"name":"app/payments/api","owner_id":"11111111-1111-4111-8111-111111111111","value":"..."}
trstctl-cli secrets store preview -f secret-create.json
trstctl-cli --idempotency-key secret-create-2026-09-01 secrets store put -f secret-create.json
```

`preview` returns a ready/blocked plan, zero-effect boundary, execution writes,
recovery guidance, and a server-keyed request fingerprint. It never returns the
secret value and does not take an `Idempotency-Key`, because it does not mutate
state. Changing any input requires a new preview; `put` always rechecks current
server authority and state.

## Run with secrets

Review the exact access plan before wiring a secret into an application:

```bash
cat > secret-access.json <<'JSON'
{"name":"app/db/dsn","env_var":"DATABASE_URL","resolve":true}
JSON
trstctl-cli secrets access preview -f secret-access.json
```

`secrets access preview` calls the read-only
`POST /api/v1/secrets/access/preview` operation. It returns the current version,
least-privilege permission, exact `run` argument vector, HTTP path, TypeScript
example, recovery and verification instructions, and a server-keyed request
fingerprint. It returns no secret value, writes no state, makes no external call,
and requires no `Idempotency-Key`. A missing secret or reference, reference cycle,
or invalid environment variable returns a blocked plan or validation error instead
of a runnable command.

`trstctl-cli run` fetches one or more stored secrets through the same served
`GET /api/v1/secrets/store/{name}` path as `secrets store get`, then starts a child
process with those values added to its environment. It is a wrapper, not a JSON API
command: stdout, stderr, stdin, and the child's exit code are passed through.

## Preview and issue a PKI certificate

Keep the private key beside the workload and put only its public CSR in the request:

```bash
chmod 600 pki-request.json
# {"csr_pem":"-----BEGIN CERTIFICATE REQUEST-----\n...","ttl_seconds":900}
trstctl-cli secrets pki preview -f pki-request.json
trstctl-cli --idempotency-key payments-pki-1 secrets pki -f pki-request.json
```

`secrets pki preview` uses the same subject, SAN, public-key strength, certificate
rule, and TTL validator as issuance. It reports the issuing CA, custody boundary,
revocation/audit prerequisites, exact effects, recovery, verification, Vault/OpenBao
path, and a server-keyed fingerprint. It does not sign, write, enqueue, audit, or
contact another service, so it intentionally sends no `Idempotency-Key`. Add that
returned fingerprint as `preview_fingerprint` to bind automated execution to the
reviewed tenant, principal, CA, CSR/name, profile, and TTL. The server returns `409`
if that reviewed plan is stale.

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
- The web console’s `/secrets/developer` workspace requests this same server plan,
  invalidates it when an input or secret version changes, and shows only a
  name/version/fingerprint receipt after its real access test.

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

The cross-resource review queue is permission-filtered: `certs:issue` can review
certificate operations, `secrets:write` can review secret operations, and
`keys:approve` can review managed-key operations. It does not grant a new standalone
approval permission. The list command uses an opaque newest-first cursor, so callers
can continue beyond the first page without skipping requests that share a timestamp:

```bash
trstctl-cli approval-requests list --status pending --limit 100
trstctl-cli approval-requests list --status pending --limit 100 --cursor '<next_cursor>'
trstctl-cli --idempotency-key approve-request-42 approval-requests approve <request-id> <sha256>
trstctl-cli --idempotency-key deny-request-42 approval-requests deny <request-id> <sha256> 'change window closed'
```

Approve and deny bind to the request's exact kind, action, resource, and intent
digest. A denial is an immutable terminal decision on the request; it never revokes,
retires, deletes, or otherwise mutates the target resource.

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

`trstctl-cli ephemeral api-keys preview` first asks the server to normalize and check
one exact subject, permission set, and lifetime. This is a read-only `POST`: it mints
no bearer, creates no idempotency row, appends no event, and calls no external system.
It also refuses permission escalation—a caller can grant only scopes it already has.

The preview returns a server-keyed `request_fingerprint`. Put that value in the issue
body. `trstctl-cli ephemeral api-keys issue` then fails closed if the tenant, caller,
subject, scopes, or lifetime no longer match the review. The successful response
prints the raw `trst_...` bearer once; the server stores only its one-way hash. The
leaseworker records `api_token.revoked` after `ttl_seconds`.

```bash
cat > ephemeral-api-key.json <<'JSON'
{"subject":"ci-preview-deploy","scopes":["access:read"],"ttl_seconds":900}
JSON
trstctl-cli ephemeral api-keys preview -f ephemeral-api-key.json > ephemeral-api-key.preview.json

# Copy request_fingerprint from the preview into the exact reviewed body.
jq --slurpfile review ephemeral-api-key.preview.json \
  '. + {preview_fingerprint: $review[0].request_fingerprint}' \
  ephemeral-api-key.json > ephemeral-api-key.reviewed.json

# Keep this recovery key stable until the response is certain. Retrying this exact
# command recovers the original response instead of minting another bearer.
trstctl-cli --idempotency-key ci-preview-key ephemeral api-keys issue -f ephemeral-api-key.reviewed.json
```

Observe or revoke the key by id with `access api-tokens list` and
`access api-tokens revoke`. For an `access:read` key, prove the bearer works by using
it against a metadata-only access endpoint, then revoke it and prove the same bearer
receives `401`. Never place the raw bearer in a URL, log, screenshot, or committed
file.

## Bootstrapping or recovering a local API token

`trstctl-cli` authenticates with an API token, but a freshly deployed control
plane has none and fails closed (every route `401`s). Mint the first one with the
**server** binary's local bootstrap verb, run inside the control-plane custody
boundary. It writes straight to the datastore (no existing HTTP credential or
network trust required) and prints a tenant-scoped token once:

```bash
trstctl token create --tenant <uuid> [--subject <name>] [--scopes a,b,c] [--tenant-name <label>]
```

For the shipped evaluation Compose stack, run that server binary inside the
control-plane container so it reaches the Compose-only PostgreSQL service:

```bash
docker compose -f deploy/docker/docker-compose.yml exec -T trstctl \
  /usr/local/bin/trstctl token create --tenant <uuid> --subject <name>
```

Running an unconfigured host binary can bootstrap a different local datastore;
it does not recover the Compose deployment.

- `--tenant` (required) is the UUID the token is scoped to. If it is new, the
  tenant is registered through the event log. If it already exists, the command
  first proves that the read model points to the exact retained
  `tenant.registered` event; it does not rename or register the tenant again.
- The default scope set is full operator control **excluding** certificate
  issuance (`certs:issue`) — bootstrapping a credential never grants self-issue.
- The raw `trst_…` token is printed once to stdout (only its hash is stored); save
  it immediately. Then export it as `TRSTCTL_TOKEN` for `trstctl-cli`.
- Because this command can recover access without an existing HTTP token, run it
  only with direct PostgreSQL plus signer/audit custody on the control-plane host.
  Possession of the public server binary alone is not enough.

## Examples

```bash
export TRSTCTL_SERVER=https://localhost:8443
export TRSTCTL_TOKEN=trst_...

# Read this tenant's ARI publication windows and scheduler-consumption evidence.
# The API token needs lifecycle:read; the command is read-only JSON output.
trstctl-cli acme ari posture

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

# Show signed network-relay CRL and OCSP endpoint health evidence.
trstctl-cli revocation health

# Show signed per-segment relay-local CRL and OCSP cache freshness metadata.
# Cached protocol bytes and upstream locations remain inside the segment.
trstctl-cli revocation caches

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
# Preview is effect-free: it validates and fingerprints this exact body without
# creating a ceremony, key, certificate, event, or external request.
trstctl-cli ca ceremonies preview -f root-ceremony.json
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

# Review a zero-downtime rotation first. The preview applies the same eligibility
# rules but changes neither CA; use the exact same body for activation.
cat > ca-rotation.json <<'JSON'
{"successor_id":"<successor-ca-authority-id>","reason":"planned overlap"}
JSON
trstctl-cli ca authorities rotate-preview <predecessor-ca-authority-id> -f ca-rotation.json
trstctl-cli ca authorities rotate <predecessor-ca-authority-id> -f ca-rotation.json

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
# The contextual response includes the canonical urgent_summary: both named
# tenant projections, per-source counts, and a credential_id-deduplicated total.
# If either projection read fails, the command returns the API error, not zero.
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

# Configure one tenant-scoped Splunk HEC schedule. token_ref is an
# operator-allowlisted pointer; the credential value never enters the request.
cat > audit-feed.json <<'JSON'
{"name":"production-soc","provider":"splunk-hec","endpoint_url":"https://splunk.example.com/services/collector/event","token_ref":"env:SPLUNK_HEC_TOKEN","interval_seconds":300,"batch_size":100,"enabled":true}
JSON
# Validate the exact destination and see writes, later effects, proof, and recovery.
# This POST-shaped read sends no Idempotency-Key and performs no write or network call.
trstctl-cli audit feeds preview 52525252-5252-4525-8525-525252525252 -f audit-feed.json

# Save only after the preview matches the intended collector configuration.
trstctl-cli --idempotency-key audit-feed-production audit feeds set 52525252-5252-4525-8525-525252525252 -f audit-feed.json

# Read schedule, cursor, exact record lag, retry/failure, and collector receipt
# state. This is read-only and sends no Idempotency-Key.
trstctl-cli audit feeds list

# Record and list an audit-export report schedule definition. The delivery value is
# metadata for the audit-export workflow; email/webhook delivery is not implied.
cat > compliance-schedule.json <<'JSON'
{"framework":"soc2","name":"weekly-soc2-pack","report_type":"framework_evidence_pack","interval_seconds":604800,"delivery":"audit_export","recipient_ref":"audit-archive"}
JSON
trstctl-cli --idempotency-key weekly-soc2 compliance report-schedules create -f compliance-schedule.json
trstctl-cli compliance report-schedules list

# Review the exact normalized targets and read/write ceilings without touching them.
cat > cbom-scan.json <<'JSON'
{"tls_endpoints":["https://payments.internal.example"],"host_configs":["/etc/nginx/sites-enabled/payments.conf"]}
JSON
trstctl-cli cbom preview -f cbom-scan.json

# Run only after reviewing the plan. Preview sends no Idempotency-Key; scan does.
trstctl-cli cbom scan -f cbom-scan.json
trstctl-cli cbom assets

# Track migration work in Community without attaching the licensed fleet engine.
# Operators may remediate manually or with any external tool, then record evidence.
cat > pqc-campaign.json <<'JSON'
{"name":"Payments PQC migration","owner":"team:payments","deadline":"2026-12-01T00:00:00Z","wave":"wave-1","readiness_criteria":["owner approved","rollback documented"],"finding_ids":["<cbom-finding-id>"]}
JSON
trstctl-cli --idempotency-key pqc-payments-create pqc campaigns create -f pqc-campaign.json
printf '{"status":"passed","evidence_refs":["change:CAB-2048"]}\n' | trstctl-cli --idempotency-key pqc-payments-ready pqc campaigns readiness <campaign-id> -f -
printf '{"disposition":"remediated","method":"manual","reason":"replaced through the existing CA workflow","evidence_refs":["audit:certificate.issued:replacement"],"evidence_digests":["sha256:<64-lowercase-hex>"]}\n' | trstctl-cli --idempotency-key pqc-payments-finding pqc campaigns disposition <campaign-id> <finding-id> -f -
trstctl-cli --idempotency-key pqc-payments-close pqc campaigns close <campaign-id> --force
trstctl-cli pqc campaigns evidence <campaign-id>

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
trstctl-cli ephemeral preview -f ephemeral-jit.json
trstctl-cli --idempotency-key jit-agent-7-request-1 ephemeral issue -f ephemeral-jit.json
cat > ephemeral-approval.json <<'JSON'
{"action":"issue","request_id":"<approval_request_id>","intent_digest":"<intent_digest>"}
JSON
trstctl-cli --idempotency-key jit-agent-7-approve-1 ephemeral approve <approval_request_id> -f ephemeral-approval.json
trstctl-cli --idempotency-key jit-agent-7-issue-1 ephemeral issue -f ephemeral-jit.json

# Discover, review, issue, renew, read, and revoke a dynamic secret lease.
trstctl-cli secrets leases providers
cat > dynamic-lease.json <<'JSON'
{"provider":"payments-db","role":"readonly","ttl_seconds":900}
JSON
trstctl-cli secrets leases preview -f dynamic-lease.json
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

# Review the exact plan first. Preview has no Idempotency-Key because it makes no
# writes, generates no secret material, and contacts no connector.
printf '{"provider":"connector:ci","key":"db/password","old_ref":"version:2","remote_key":"DB_PASSWORD"}' \
  | trstctl-cli secrets rotations preview -f -

# Run the reviewed worker-queued connector rotation with an Idempotency-Key.
printf '{"provider":"connector:ci","key":"db/password","old_ref":"version:2","remote_key":"DB_PASSWORD"}' \
  | trstctl-cli --idempotency-key connector-rotation-1 secrets rotations run -f -

# Static-provider and dynamic-lease rotation both fail closed before effects until
# their complete phase chains have one crash-recoverable worker receiver.

# Schedule connector rotation and run due schedules from the served path.
cat > connector-rotation-schedule.json <<'JSON'
{"name":"reporting-hourly","provider":"connector:ci","key":"db/password","old_ref":"version:2","interval_seconds":3600}
JSON
trstctl-cli --idempotency-key connector-rotation-schedule-1 secrets rotation-schedules create -f connector-rotation-schedule.json
trstctl-cli secrets rotation-schedules list
trstctl-cli --idempotency-key connector-rotation-due-1 secrets rotation-schedules run-due

# Review a stored-secret delivery before allowing any write or network effect.
# Preview reads tenant-scoped metadata only: it does not open the secret value,
# append an event, enqueue an outbox row, or contact the target.
cat > secret-sync.json <<'JSON'
{"name":"sync/source","target":"github-actions","remote_key":"DB_PASSWORD"}
JSON
trstctl-cli secrets syncs preview -f secret-sync.json

# Copy request_fingerprint from the preview into preview_fingerprint. Execution
# rejects a stale plan if the caller, secret version, target, or remote key changed.
cat > reviewed-secret-sync.json <<'JSON'
{"name":"sync/source","target":"github-actions","remote_key":"DB_PASSWORD","preview_fingerprint":"sha256:<copy-from-preview>"}
JSON
trstctl-cli --idempotency-key secret-sync-1 secrets syncs run -f reviewed-secret-sync.json

# The execution response is metadata only; the secret value is never echoed back.

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
trstctl-cli secrets scans preview -f secret-scan.json
# Add the returned request_fingerprint as preview_fingerprint in the same body.
# Reuse this idempotency key if the run is interrupted; a completed run replays.
trstctl-cli --idempotency-key secret-scan-1 secrets scans run -f reviewed-secret-scan.json

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
trstctl-cli transit keys versions payments
trstctl-cli transit status

cat > transit-encrypt.json <<'JSON'
{"key":"payments","plaintext":"Y2FyZC10b2tlbi0xMjM=","aad":"dGVuYW50PXBheW1lbnRz"}
JSON
trstctl-cli --idempotency-key transit-payments-encrypt transit encrypt -f transit-encrypt.json
trstctl-cli --idempotency-key transit-payments-rotate transit keys rotate -f transit-key.json

cat > transit-rewrap.json <<'JSON'
{"key":"payments","ciphertext":"trv:1:<ciphertext-from-encrypt>","aad":"dGVuYW50PXBheW1lbnRz"}
JSON
trstctl-cli --idempotency-key transit-payments-rewrap transit rewrap -f transit-rewrap.json

cat > code-sign.json <<'JSON'
{"key_id":"release-key","artifact_type":"oci-image","digest":"4EW4IfBBkDngEwN3v+ChO06PV2er4tF7nEVmFev3x1g="}
JSON
# Review an artifact digest with a configured code-signing key. This is effect-free:
# it does not open the signer, write state, or contact Rekor.
trstctl-cli code-signing preview -f code-sign.json > code-sign-plan.json

# Copy request_fingerprint from the plan into code-sign.json as
# preview_fingerprint, then execute with one retained recovery key. The response
# contains the signature, public key, algorithm, and transparency outbox destination.
trstctl-cli --idempotency-key release-sign-1 code-signing sign -f code-sign.json

# Sign keylessly with a verified Fulcio/Sigstore identity proof. identity_payload is
# base64 JSON bytes; the served attestor verifies it before the signature is issued.
cat > code-sign-keyless.json <<'JSON'
{"artifact_type":"oci-image","digest":"4EW4IfBBkDngEwN3v+ChO06PV2er4tF7nEVmFev3x1g=","identity_method":"github_oidc","identity_payload":"eyJqd3QiOiJleGFtcGxlIn0=","fulcio_san":"repo:acme/payments:ref:refs/heads/main","fulcio_issuer":"https://token.actions.githubusercontent.com"}
JSON
trstctl-cli code-signing keyless-preview -f code-sign-keyless.json > code-sign-keyless-plan.json
trstctl-cli --idempotency-key release-keyless-1 code-signing keyless -f code-sign-keyless.json

# On an enrolled host, report local public certificate files over the agent channel.
trstctl-agent --enroll-url https://localhost:8443 \
  --bootstrap-token-file ./trstctl-bootstrap-token \
  --server localhost:19443 \
  --server-name localhost \
  --name edge-agent-1 \
  --ca-bundle ./trstctl-ca.pem \
  --inventory-cert-roots /etc/ssl,/etc/pki/tls/certs \
  --inventory-os-trust-roots /etc/ssl/certs \
  --inventory-java-trust-stores "$JAVA_HOME/lib/security/cacerts" \
  --inventory-private-key-roots /etc/ssl/private,/etc/ssh
trstctl-cli discovery findings list

# --enroll-url is the control-plane base URL, not /enroll/bootstrap. Plain HTTP
# remains blocked except with --allow-insecure-loopback-enrollment on loopback.

# Correlate one managed issuer to observed trust stores. Authoritative counts use
# exact certificate/SPKI identity; name-only candidates are returned separately.
trstctl-cli graph trust-stores iss:<issuer-id>

# Read the canonical tenant-bound readiness dataset, create an action against
# its current row/owner digest, then download the independently verifiable
# JSON envelope carrying the exact CSV and NDJSON bytes.
trstctl-cli graph crypto-readiness
cat > crypto-readiness-action.json <<'JSON'
{"name":"Payments crypto blocker","owner":"team:payments","deadline":"2026-12-01T00:00:00Z","wave":"wave-1","readiness_criteria":["owner approved","rollback documented"],"finding_ids":["<cbom-finding-id>"]}
JSON
trstctl-cli --idempotency-key payments-crypto-1 graph crypto-readiness actions create -f crypto-readiness-action.json
trstctl-cli graph crypto-readiness export > crypto-readiness-evidence.json

# In a cluster, add --inventory-k8s-secrets to inventory the kubernetes.io/tls
# Secrets in the agent's own namespace (reads tls.crt, never tls.key; needs list
# access to Secrets in that namespace, and sees only that namespace).

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
