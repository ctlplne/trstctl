# Discovery & inventory — find every certificate, key, and secret you already have

## What it is

Before you can manage credentials, you have to *know they exist*. Discovery is how
trstctl finds the credentials already scattered across your infrastructure —
[certificates](../glossary.md), SSH keys, and [secrets](../glossary.md) — and the
**inventory** is the single, tenant-scoped list it keeps them in.

Think of it like a building's master key register. Before you can say "who can open
which door?", someone has to walk every floor, write down every lock and every key,
and keep that register current as locks change. trstctl is that walker and that
register, for machines.

trstctl discovers credentials five ways, and each suits a different corner of your
estate: scanning the network from outside, asking an agent what a host can see from
inside, pulling inventory straight from cloud provider APIs, reading SSH key files
and trust config, and connecting to external secret stores. Everything they find
lands in one inventory.

## Why it exists

Almost every organization has more machine credentials than it can name, and the ones
nobody remembers are the ones that cause outages and breaches: the certificate that
expires on a forgotten load balancer at 3 a.m., the SSH key a contractor left behind,
the API token hard-coded in a script five years ago. You cannot rotate, revoke, or
risk-score a credential you do not know about.

Discovery turns "we think we have a few hundred certs" into a precise, queryable
list — the foundation every other trstctl feature builds on. Risk scoring, drift
detection, the credential graph, and lifecycle automation all read the inventory.

## How it works

### The inventory (F1) — the source of truth that is actually a projection

The inventory is a PostgreSQL table of certificate **metadata** — subject, SANs,
issuer, serial, SHA-256 fingerprint, key algorithm, validity window, where it's
deployed, and lifecycle status. It never stores a private key.

Here's the important part, and it's a core trstctl design rule
([event sourcing](../glossary.md)): nothing writes to that table directly. When a
certificate is discovered or issued, the orchestrator appends a `certificate.recorded`
event to the append-only, tamper-evident log, and a *projector* reads that event and
builds the table row. The table is a **projection** — a derived view you could delete and
rebuild from the log. That's why trstctl can survive a database loss: the truth is the
event log, and the inventory is just a fast index into it.

Ingestion is idempotent: the row key is `(tenant_id, fingerprint)`, so seeing the same
certificate twice refreshes one row instead of creating a duplicate, and the ingest API
requires an [`Idempotency-Key`](../glossary.md) so a retried request can't double-record.
Certificate parsing routes through the single isolated cryptography path, so the inventory
code itself never touches the low-level X.509 libraries directly.

The estate health view is served from the same projection. `GET
/api/v1/certificates/health` returns a tenant-wide expiry dashboard: total active
inventory, expired and 7/30/90-day expiry bands, source breakdown, and the soonest
expiring certificates. It counts trstctl-issued rows, manually imported rows, and
discovery-fed rows together, so a certificate issued by a different CA but found on
a load balancer still appears in the same health posture.

### Network discovery (F2) — scanning from the outside, no agent needed

Network discovery connects to IP/port ranges you define, performs a normal
[TLS](../glossary.md) handshake, captures the certificate each host presents, and
records its metadata. No software is installed on the targets — it sees exactly what
any client on the network would see.

The scanner runs in its own bounded [lane](../glossary.md): a bounded pool of workers
(default 16, queue 256). When the queue fills, it slows the producer instead of dropping
targets or exhausting the pool the API needs — a big scan can never starve the rest of the
system. The handshake and certificate parsing both go through the single isolated
cryptography path. The served scanner also applies the shared SSRF guard and a
reserved-IP denylist before dialing expanded CIDRs, so a scan cannot be turned into a
loopback, RFC1918, link-local, or cloud-metadata probe.

**Status:** served by the running control plane: operators create a `network` source,
queue a run, and inspect findings through REST/CLI/UI. The run executes from the outbox
worker — the external probes are journaled first and delivered at-least-once, so they're
durable and retryable instead of being done inline by the request handler.

### Continuous monitoring repository (CAP-DISC-06)

`GET /api/v1/discovery/monitoring` is the served continuous-monitoring posture view.
It reads the tenant's discovery sources, enabled schedules, last runs, findings, and
certificate inventory projection into one response. Each source row shows whether it
is scheduled, the monitoring interval, the latest run status, finding counts, and the
served repository paths (`/api/v1/certificates` and `/api/v1/discovery/findings`).

This endpoint does not create state. It is a read-side view over event-built
projections: source/schedule/run/finding rows come from `discovery.*` events, and
known certificates come from `certificate.recorded`. The CLI exposes the same view as
`trstctl discovery monitoring`, and the Discovery console renders it above the raw
source, schedule, run, and finding tables so operators can see both the centralized
repository summary and the underlying evidence.

### Agent-based discovery (F3) — what each host can see from the inside

A network scan only sees what a host *presents on a port*. Plenty of credentials never
appear on the wire: a certificate sitting in a file, in a PKCS#11 token, in the
Windows certificate store, or in a Kubernetes Secret. The trstctl **agent** runs on
the host and enumerates those local sources, then reconciles what it finds into the
inventory over its mutually-authenticated ([mTLS](../glossary.md)) channel.

Each source is independent: if one token errors, the agent records the error and keeps
going, so one broken source can't hide the rest. The agent enrolls into the control
plane with a one-time bootstrap token (`POST /enroll/bootstrap`), after which the
control plane lists it at `GET /api/v1/agents`.

The agent's discovery sources are `filesystem`, `pkcs11`, `windows-store`,
`k8s-secret`, `trust-store`, and `private-key`. The local read still runs inside the agent because
only the host can see its files, tokens, Windows store, trust stores, browser
profiles, or in-cluster Secrets. The report path is now served by the control plane:
an enrolled agent sends a metadata-only
`ReportInventory` batch over the same mTLS channel it uses for heartbeat and renewal,
and the server creates a tenant-scoped discovery source, run, findings, audit events,
and credential-graph nodes from that batch. The server rejects inline secret-looking
metadata keys, caps batch size, and runs ingest in the bounded agent lane, so a noisy
fleet cannot starve the API. `GET /api/v1/agents` now advertises the served
`agent.mtls.ReportInventory` path and the endpoint source kinds it accepts, and the
Agents console shows that same capability list for each enrolled endpoint.

For Linux certificate files, the shipped agent can inventory public certificate roots
at startup with `--inventory-cert-roots`. It reports references, fingerprints, and
certificate metadata only — never private keys or secret values.

### Direct CA discovery (CAP-DISC-04) — public and private CA inventory

`GET /api/v1/ca/discovery` is the served direct-CA inventory for CA estates. It
enumerates configured public upstream CAs, configured private upstream CAs, and
imported private CA hierarchy authorities in one tenant-scoped response. Each row
contains source id, source kind, public/private scope, status, and served path
pointers such as `/api/v1/external-cas/{id}/issue` or
`/api/v1/ca/authorities/{id}/issue`. The response intentionally omits certificate
PEM and private-key bytes; operators use it to answer which CAs are connected or
imported, then follow the referenced served route for issuance or import workflow
details.

Trust-store discovery is a separate agent collector because a trusted CA is not the
same thing as a deployed service certificate. The agent can read public trust anchors
from OS trust directories, Java `cacerts`/JKS files, NSS profile exports, browser
profile exports, and Windows trust-store enumerators. Each finding is tagged with
`trust_store_kind` (`os`, `java`, `nss`, `browser`, or `windows`) and
`private_key_present=false`, so the control plane can answer "what does this host
trust?" without ever moving a key.

Private-key-material discovery is the companion collector for "what sensitive key
files exist here?" Operators point the agent at canary directories with
`--inventory-private-key-roots`. The agent reads each regular file locally, classifies
PKCS#8, PKCS#1 RSA, SEC1 EC, OpenSSH, and encrypted private-key containers through the
isolated cryptography boundary, wipes the file buffer after inspection, and reports
only the path, format, algorithm, file-mode metadata, and a fingerprint derived from
the public key when the key is parseable. Encrypted keys are still located and tagged
as encrypted, but no passphrase is requested and no private bytes, PEM blocks, or
secret values are sent to the control plane.

### SSH credential discovery (F42) — keys and standing access

SSH is where forgotten access hides. trstctl inventories SSH credentials two ways: a
network-side SSH handshake captures each host's **host key**, and the on-host agent
reads host keys, user keys, `authorized_keys` grants, `known_hosts` trust anchors, and
the `TrustedUserCAKeys` directive from `sshd_config`. DISC-03 extends the same agent
inventory path to private-key files, so SSH host/user key material and TLS key files
are located and classified as metadata-only `private_key` findings instead of being
copied into the control plane.

Two flags make the result actionable. **StandingAccess** marks an entry that grants
persistent login (an `authorized_keys` line). **Orphaned** marks a standing-access
grant whose comment field is blank — meaning nobody can say whose key it is. An
orphaned standing-access key is exactly the thing a security team wants surfaced. Only
the fingerprint is ever stored, never private key material (held in wipeable memory and
zeroed after use, never written down).

The control plane serves `ssh` discovery source/run/finding records and executes
non-invasive SSH host-key scans from the discovery outbox worker. Source configs accept
explicit `targets` (`host:port`) or CIDRs plus ports, run on a bounded worker lane, and
use reserved-address filtering unless the operator explicitly allows private or loopback
diagnostic targets. Findings are metadata-only `ssh_key` rows with location, key type,
and OpenSSH SHA256 fingerprint evidence. On-host user-key, `authorized_keys`,
`known_hosts`, `TrustedUserCAKeys`, and private-key-material inventory still arrives
through the served agent mTLS report path, not by copying key bytes into the control
plane.

### Agentless cloud discovery (F49) — pull inventory from the cloud's own APIs

Cloud platforms already keep a list of your certificates; you just have to ask.
trstctl's cloud enumerators call the provider control planes read-only — **AWS** ACM,
**Azure** Key Vault, and **GCP** Certificate Manager — page through the results, and
record the metadata. No agent, no network reachability required, just read-only cloud
credentials. Request signing (e.g. AWS SigV4) and all certificate parsing go through the
single isolated cryptography path, and the enumerators run in their own bounded lane with
retry/backoff on rate limits — overload is rejected fast instead of starving other work.

The control plane serves `cloud_certificate` discovery source/run/finding records and
executes AWS ACM, Azure Key Vault, and GCP Certificate Manager enumerators from the
outbox worker. Source configs use credential references such as
`access_key_id_ref`, `secret_access_key_ref`, and `token_ref`; inline cloud
credentials are rejected before a source is stored. LocalStack or emulator fixtures
can opt into a private endpoint, while normal provider endpoints use the public-URL
SSRF guard.

```json
{
  "kind": "cloud_certificate",
  "name": "aws-acm-east",
  "config": {
    "providers": [
      {
        "provider": "aws-acm",
        "region": "us-east-1",
        "access_key_id_ref": "env:AWS_ACCESS_KEY_ID",
        "secret_access_key_ref": "env:AWS_SECRET_ACCESS_KEY"
      }
    ]
  }
}
```

**Status:** source, schedule, run, provider execution, metadata-only findings, and
certificate-inventory projection are served.

### Cross-surface NHI discovery — IdP, cloud, SaaS, on-prem, code, and CI

Some non-human identities are not certificates yet. They are OAuth apps in an
IdP, cloud roles, SaaS integrations, LDAP service accounts, deploy keys found in
code, or workflow identities in CI. trstctl serves those as one
`nhi_cross_surface` discovery source so an operator can ingest metadata from all
six places and see the resulting machine identities in the same finding ledger as
certificates and secrets.

The source config is intentionally only public reference metadata:
`surface`, `system`, `external_id`, `principal`, `owner`, `credential_kind`,
`scopes`, and timestamps. The API rejects inline secret-looking fields before the
source is stored. A valid source must include at least one observation from each
required surface: `idp`, `cloud`, `saas`, `on_prem`, `code`, and `ci`. That keeps
the category denominator honest: a two-source import cannot pretend to be full
cross-surface NHI discovery.

```json
{
  "kind": "nhi_cross_surface",
  "name": "quarterly-nhi-inventory",
  "config": {
    "observations": [
      {
        "surface": "idp",
        "system": "okta",
        "external_id": "app/payments",
        "principal": "payments-api",
        "owner": "platform",
        "credential_kind": "oauth_client"
      },
      {
        "surface": "cloud",
        "system": "aws-iam",
        "external_id": "role/payments-prod",
        "principal": "arn:aws:iam::111111111111:role/payments-prod",
        "owner": "platform",
        "credential_kind": "role"
      },
      {
        "surface": "saas",
        "system": "github",
        "external_id": "app/installations/42",
        "principal": "payments-ci-app",
        "owner": "devex",
        "credential_kind": "github_app"
      },
      {
        "surface": "on_prem",
        "system": "ldap",
        "external_id": "svc-payments",
        "principal": "svc-payments",
        "owner": "identity",
        "credential_kind": "service_account"
      },
      {
        "surface": "code",
        "system": "github-code-search",
        "external_id": "repo/payments/path/deploy.yaml",
        "principal": "payments-deploy-key",
        "owner": "devex",
        "credential_kind": "deploy_key"
      },
      {
        "surface": "ci",
        "system": "github-actions",
        "external_id": "repo/payments/env/prod",
        "principal": "payments-ci-token",
        "owner": "devex",
        "credential_kind": "workflow_identity"
      }
    ]
  }
}
```

Runs execute through the discovery outbox worker, normalize every observation to a
`non_human_identity` finding, preserve provenance as
`nhi_cross_surface:<surface>:<system>:<external_id>`, and append the same
`discovery.*` events as other discovery paths. The finding is metadata only; no
secret value, private key, or token body is stored.

**Status:** source creation, run queueing, outbox execution, metadata-only findings,
REST readback, and UI representation are served for the six-surface NHI
denominator.

### Unified NHI inventory — all credential kinds (CAP-NHI-02)

The served rollup for non-human identities is `GET /api/v1/nhi/inventory`
(`nhi:read`). It is a read-side projection over tenant-scoped tables, not a new
state store: first-party identities, certificate inventory rows, API-token
metadata, enrolled agents, and discovery findings are normalized into one item
shape. The kind denominator is explicit: certificates, SSH keys, secrets, API
keys, OAuth apps, tokens/PATs, service accounts, IAM roles, webhooks, workload
IDs, and agents.

The response preserves provenance (`identity`, `certificate_inventory`,
`access_api_token`, `agent_fleet`, or `discovery_finding`) and public metadata such
as owner, status, fingerprint, risk score, source system, and external reference.
It never returns secret values, private keys, raw API tokens, or inline credential
material; token rows are metadata-only and one-time API-token bodies are not
projected.

The dashboard's non-human-identity inventory summary consumes this served API, so
the first screen counts certificate, SSH, secret, API-key, OAuth, token/PAT,
service-account, IAM-role, webhook, workload-identity, and agent rows instead of
only the managed `identities` table.

Ownership attribution for the same denominator is served by `GET
/api/v1/ownership/attribution`: managed rows resolve `owner_id`, discovery rows
resolve metadata-only owner/team/vendor names to registered owners, and unresolved
records stay marked `orphaned` for CAP-GOV-01 governance reporting.

Managed NHI decommissioning is served by `POST /api/v1/nhi/decommission`.
Departure, vendor-term, and inactivity signals select tenant-local managed
identities from the same ownership/activity metadata and then drive the normal
event-sourced lifecycle revoke/retire transitions for CAP-GOV-04.

**Status:** REST, OpenAPI, generated web client types, dashboard summary, and
served end-to-end acceptance coverage are implemented.

### Service-account discovery — AD and cloud (CAP-NHI-03)

Dedicated service-account inventory uses the `service_account` discovery source kind.
It is narrower than `nhi_cross_surface`: the source must include at least one
AD/on-prem account and at least one cloud service account, so an AD-only or cloud-only
import cannot count as full CAP-NHI-03 coverage. The config carries only public identity
metadata and credential references:

```json
{
  "kind": "service_account",
  "name": "service-account-inventory",
  "config": {
    "accounts": [
      {
        "surface": "active_directory",
        "provider": "ad",
        "directory": "corp.example",
        "account_id": "S-1-5-21-1000",
        "principal": "svc-payments@corp.example",
        "owner": "identity",
        "groups": ["CN=Payments,OU=Service Accounts,DC=corp,DC=example"],
        "credential_refs": ["ad:corp.example:svc-payments"]
      },
      {
        "surface": "cloud",
        "provider": "aws-iam",
        "directory": "111111111111",
        "account_id": "role/payments-prod",
        "principal": "arn:aws:iam::111111111111:role/payments-prod",
        "owner": "platform",
        "privileged": true,
        "roles": ["AdministratorAccess"],
        "credential_refs": ["aws:iam:role/payments-prod"]
      }
    ]
  }
}
```

Runs execute through the discovery outbox worker, emit `service_account` findings tagged
with `CAP-NHI-03`, preserve provenance as
`service_account:<surface>:<provider>:<directory>:<account_id>`, and project the same
tenant-scoped discovery read model as the other source kinds. The API rejects inline
password, token, secret, and private-key shaped fields before storing the source.

**Status:** source creation, run queueing, outbox execution, metadata-only findings,
REST readback, and UI representation are served for the AD/cloud service-account
denominator.

### OAuth app & grant discovery — SaaS-to-SaaS consent and scopes

OAuth grants are the consent edge between one non-human identity and another SaaS
or API resource. trstctl serves `oauth_grant` discovery sources so an operator can
ingest provider exports from Okta, Entra ID, Google Workspace, GitHub, Salesforce,
or similar systems and see third-party apps, granted resources, and scopes in the
same tenant discovery ledger as certificates, secrets, and broader NHI findings.

The source config is metadata only: `provider`, `app_id`, `app_name`, `principal`,
`resource`, `scopes`, `consent_type`, `third_party`, `owner`, publisher, tenant,
timestamps, redirect URIs, and tags. It deliberately has no client-secret or token
field. The API rejects inline secret-looking fields before the source is stored.
Each grant must include at least one scope so the served path proves OAuth app
discovery, grant discovery, and scope discovery together.

```json
{
  "kind": "oauth_grant",
  "name": "quarterly-oauth-consent",
  "config": {
    "grants": [
      {
        "provider": "okta",
        "app_id": "0oa-payments",
        "app_name": "Payments BI Export",
        "principal": "payments-bi-export",
        "resource": "google-workspace",
        "scopes": ["drive.readonly", "admin.directory.user.readonly"],
        "consent_type": "admin",
        "third_party": true,
        "owner": "finance-platform"
      }
    ]
  }
}
```

Runs execute through the discovery outbox worker, normalize every grant to an
`oauth_grant` finding, preserve provenance as
`oauth_grant:<provider>:<app_id>:<resource>`, and append the standard
`discovery.*` events. Risk scoring highlights third-party grants, admin consent,
sensitive scopes such as directory, drive, mail, or write permissions, and missing
owners.

The same source also serves malicious / abused OAuth-grant detection (CAP-ITDR-03)
when the provider export carries concrete abuse metadata. A grant with provider
threat signals, dangerous wildcard or `.default` scope, `offline_access` combined
with high-privilege admin consent, explicitly unverified publisher evidence, missing
owner on a privileged third-party admin grant, or suspicious redirect URIs emits an
additional `oauth_grant_abuse` finding. That finding is tagged with
`capability=CAP-ITDR-03`, `abuse_reasons`, `evidence_refs`, and the source event
reference. Ordinary high-risk but owned grant inventory stays `oauth_grant` only, so
trstctl does not count inventory as ITDR detection.

**Status:** source creation, run queueing, outbox execution, metadata-only
`oauth_grant` findings, CAP-ITDR-03 `oauth_grant_abuse` detections, REST readback,
and UI representation are served.

### NHI behavior baselining and anomaly detection

Behavior analytics turns raw NHI activity into an ITDR signal. trstctl serves
`nhi_behavior` discovery sources so operators can ingest metadata-only activity
events from IdPs, SaaS audit logs, cloud audit trails, API gateways, or service
mesh logs. Baseline events teach normal behavior per principal; observed events
are compared against that baseline and emit `nhi_behavior_anomaly` findings when
they break the learned pattern.

The source config carries only activity metadata: `principal`, `occurred_at`,
`ip`, `geo`, `user_agent`, `action`, `usage_count`, and a `baseline` boolean.
The API rejects inline secret-looking fields before a source is stored. Detection
covers unfamiliar IP, unfamiliar geo, unfamiliar user-agent, usage spike, and
off-hours activity. Business hours default to 08:00-18:00 unless a source
provides `business_hours.start_hour` and `business_hours.end_hour`.

```json
{
  "kind": "nhi_behavior",
  "name": "nhi-behavior-itdr",
  "config": {
    "business_hours": { "start_hour": 8, "end_hour": 18 },
    "events": [
      {
        "principal": "payments-api",
        "occurred_at": "2026-06-01T10:00:00Z",
        "ip": "198.51.100.10",
        "geo": "US",
        "user_agent": "payments-agent/1.0",
        "action": "token_use",
        "usage_count": 10,
        "baseline": true
      },
      {
        "principal": "payments-api",
        "occurred_at": "2026-06-02T02:15:00Z",
        "ip": "203.0.113.9",
        "geo": "DE",
        "user_agent": "curl/8.7",
        "action": "token_use",
        "usage_count": 90
      }
    ]
  }
}
```

Runs execute through the discovery outbox worker, build the per-principal
baseline in memory for the run, normalize anomalous observations to
`nhi_behavior_anomaly` findings, preserve provenance as
`nhi_behavior:<principal>:<occurred_at>`, and append the standard `discovery.*`
events. Findings include the anomaly reasons, business-hours window, baseline
sample count, and average usage, never credential values.

**Status:** source creation, run queueing, outbox execution, metadata-only
`nhi_behavior_anomaly` findings, REST readback, and UI representation are served
for CAP-ITDR-01.

### Compromised-credential and stolen-token detection

Compromised-credential detection turns external ITDR, IdP, SaaS, scanner,
honeytoken, and threat-intel signals into a served Discovery finding. trstctl
serves `credential_compromise` discovery sources for OWASP NHI2 style events:
a token or credential reference was observed in a known leak, replayed after
revocation, used from an unfamiliar network, or triggered a honeytoken. The
source stores only `credential_ref` and evidence references, never the token,
secret, private key, refresh token, or password body.

The source config carries `principal`, `credential_ref`, `credential_kind`,
`provider`, `detector`, `observed_at`, `reason`, `confidence`, optional IP/geo
metadata, and `evidence_refs` or `source_event_ref`. API validation rejects
inline secret-looking fields before the source is stored, and the detector also
performs its own secret-shaped-key check before normalizing findings.

```json
{
  "kind": "credential_compromise",
  "name": "compromised-credentials-itdr",
  "config": {
    "signals": [
      {
        "principal": "payments-api",
        "credential_ref": "api-token:payments-ci",
        "credential_kind": "api_token",
        "provider": "github-actions",
        "detector": "honeytoken",
        "observed_at": "2026-06-03T03:15:00Z",
        "reason": "revoked token replayed from unfamiliar network",
        "confidence": "critical",
        "evidence_refs": ["audit:api-token-use/evt-42"],
        "source_event_ref": "github-audit:evt-42",
        "ip": "203.0.113.44",
        "geo": "DE",
        "user_agent": "curl/8.7"
      }
    ]
  }
}
```

Runs execute through the discovery outbox worker, normalize each signal to a
`compromised_credential` finding, preserve provenance as
`credential_compromise:<provider>:<detector>:<credential_ref>:<observed_at>`,
tag the finding with `owasp_category=NHI2` and `capability=CAP-ITDR-02`, and
append the standard `discovery.*` events. High and critical signals produce
high-risk findings that can drive the incident workflow without pretending that
remediation is the detector.

**Status:** source creation, run queueing, outbox execution, metadata-only
`compromised_credential` findings, REST readback, and UI representation are
served for CAP-ITDR-02.

### Kubernetes Ingress and Gateway API TLS auto-issuance

Kubernetes TLS automation is served through `k8s_ingress_gateway` discovery
sources. Operators can feed metadata exported from an Ingress watch, Gateway API
watch, admission controller, or manifest inventory, and trstctl mints public
certificate inventory rows through the same signer-backed served issuance path
used by lifecycle issuance. The source never carries a TLS private key, Kubernetes
Secret body, kubeconfig, or service-account token.

The source config carries only resource metadata: `kind` (`Ingress` or
`Gateway`), `api_version`, `namespace`, `name`, `tls_secret_name`, `hosts`,
and `auto_issue`. Normal runs require `auto_issue` to be true; use discovery
`dry_run` to plan without minting. Hostnames become the leaf certificate SANs,
and the Kubernetes TLS Secret reference becomes the certificate deployment
location.

```json
{
  "kind": "k8s_ingress_gateway",
  "name": "cluster-edge-tls",
  "config": {
    "resources": [
      {
        "kind": "Ingress",
        "api_version": "networking.k8s.io/v1",
        "namespace": "payments",
        "name": "payments-web",
        "tls_secret_name": "payments-web-tls",
        "hosts": ["payments.example.com"],
        "auto_issue": true
      },
      {
        "kind": "Gateway",
        "api_version": "gateway.networking.k8s.io/v1",
        "namespace": "edge",
        "name": "public",
        "tls_secret_name": "edge-public-tls",
        "hosts": ["edge.example.com", "api.example.com"],
        "auto_issue": true
      }
    ]
  }
}
```

Runs execute through the discovery outbox worker, normalize each resource to a
`k8s_tls_auto_issuance` finding, preserve provenance as
`k8s_ingress_gateway:<kind>:<namespace>/<name>:<tls_secret_name>`, and record the
minted certificate through `certificate.recorded`. The generated private key
lives only inside the crypto boundary during signing and is destroyed before the
inventory row is recorded; the persisted inventory is public certificate metadata.

**Status:** source creation, run queueing, outbox execution, metadata-only
`k8s_tls_auto_issuance` findings, signer-backed certificate minting, certificate
inventory readback, and UI representation are served for CAP-K8S-03.

### Secret-store & API-key discovery (F35, F36; CAP-NHI-04) — names, never values

Secrets and API keys live in many systems, and the dangerous ones are the stale,
never-rotated, high-privilege ones. trstctl serves both `secret_store` and
`api_key` discovery source/run/finding records by **reference only**: path, name,
ARN, stable credential reference, masked fingerprint, scope, expiry, rotation age,
and evidence refs. The source schema has no raw value field, and API validation
rejects secret-looking keys such as `token_value`, `secret`, `password`, or
`private_key` before the source is stored.

The `api_key` source kind is the served CAP-NHI-04 path for estate API keys,
cloud access keys, service-account keys, CI/CD tokens, OAuth refresh tokens, and
personal access tokens. Runs execute through the discovery outbox worker, emit
metadata-only `api_key`, `api_token`, or `personal_access_token` findings, tag
each finding with `capability=CAP-NHI-04`, and feed `/api/v1/nhi/inventory`.

```json
{
  "kind": "api_key",
  "name": "token-estate",
  "config": {
    "observations": [
      {
        "surface": "saas",
        "system": "github",
        "external_id": "user/payments-ci/pat",
        "principal": "payments-ci",
        "credential_kind": "personal_access_token",
        "credential_ref": "github:user/payments-ci/pat",
        "masked_fingerprint": "sha256:github-pat-ref",
        "scopes": ["repo", "workflow"],
        "last_seen_at": "2026-06-21T08:30:00Z",
        "evidence_refs": ["github:audit/pat-1"]
      },
      {
        "surface": "cloud",
        "system": "aws-iam",
        "external_id": "access-key/AKIAEXAMPLE",
        "principal": "arn:aws:iam::111111111111:user/payments-deploy",
        "credential_kind": "access_key",
        "credential_ref": "aws-iam:111111111111:access-key/AKIAEXAMPLE",
        "masked_fingerprint": "sha256:aws-access-key-ref",
        "scopes": ["iam:*"],
        "rotation_age_days": 91,
        "privileged": true,
        "evidence_refs": ["aws-iam:credential-report/2026-06-20"]
      }
    ]
  }
}
```

Each finding becomes a node in the [credential graph](graph-query-ai.md) with its
provenance and risk score. API keys, tokens, and PATs receive higher risk when
they are privileged, long-lived, stale, or broad-scoped. A related bridge ingests
leaked-credential findings from scanners (gitleaks, trufflehog) into the same
graph, again structurally excluding the secret value.

**Status:** source creation, run queueing, outbox execution, metadata-only
API-key/token/PAT findings, REST readback, unified NHI inventory projection, and
UI representation are served for CAP-NHI-04.

Cloud secret-manager import extends that same metadata-only model to AWS Secrets
Manager, GCP Secret Manager, and HashiCorp Vault KV for certificate material stored
as secrets. The providers read only secret metadata plus the current value long
enough to parse certificate fingerprints, then wipe the value and record only
metadata. They run under the discovery bulkhead with the same tenant-scoped
source/run/finding projection.

### Discovery triage

Findings are immutable evidence, but their operator triage state is mutable and
event-sourced. `triage_status` starts as `unmanaged`; the state model also includes
`investigating`, `managed`, and `dismissed`. The served API exposes
`POST /api/v1/discovery/findings/{id}/claim` to mark a finding managed, and
`POST /api/v1/discovery/findings/{id}/dismiss` to dismiss it with a reason. Both are
tenant-scoped, idempotent mutations guarded by `discovery:write`; the investigation
state remains a projected workflow state, not a separate public endpoint.

### In the console

The `/discovery` screen is the discovery front door: a **shadow-inventory** summary of
unmanaged credentials found across your environments, and a **CT-log & drift** panel that
counts certificate-transparency and configuration-drift findings — both projected over the
served sources, schedules, runs, and findings. See [The web console](../web-console.md).

## Use it

The certificate inventory (F1) is live today. Drive it from the CLI:

```sh
# list certificates, newest first, paginated
trstctl-cli certificates list --limit 50

# list only certificates expiring within a window
trstctl-cli certificates list --expiring-before 720h

# show estate-wide expiry/source health, including imported and discovered certs
trstctl-cli certificates health

# ingest a certificate you already have (idempotent)
trstctl-cli certificates ingest -f ./server.pem
```

Those map to the served REST routes `GET /api/v1/certificates`,
`GET /api/v1/certificates/health`, and `POST /api/v1/certificates` (the latter
requires an `Idempotency-Key` header).

Network discovery is live too:

```sh
cat > source.json <<'JSON'
{"kind":"network","name":"edge","config":{"targets":["10.0.0.10:443"]}}
JSON
trstctl-cli discovery sources create -f source.json
trstctl-cli discovery sources list

cat > run.json <<'JSON'
{"source_id":"<source-id>"}
JSON
trstctl-cli discovery runs start -f run.json
trstctl-cli discovery runs list
trstctl-cli discovery findings list --run_id <run-id>
```

Those map to `POST|GET /api/v1/discovery/sources`,
`POST|GET /api/v1/discovery/schedules`, `POST|GET /api/v1/discovery/runs`,
`GET /api/v1/discovery/runs/{id}`, `GET /api/v1/discovery/findings`,
`POST /api/v1/discovery/findings/{id}/claim`, and
`POST /api/v1/discovery/findings/{id}/dismiss`.

To see enrolled agents that perform local discovery:

```sh
trstctl-cli agents list

# On an enrolled host, report public certificate files the agent can see.
trstctl-agent --enroll-url https://localhost:8443 \
  --bootstrap-token-file ./trstctl-bootstrap-token \
  --server localhost:9443 \
  --name edge-agent-1 \
  --ca-bundle ./trstctl-ca.pem \
  --inventory-cert-roots /etc/ssl,/etc/pki/tls/certs \
  --inventory-os-trust-roots /etc/ssl/certs,/etc/pki/ca-trust/source/anchors \
  --inventory-java-trust-stores "$JAVA_HOME/lib/security/cacerts" \
  --inventory-nss-trust-roots "$HOME/.pki/nssdb/exported-roots" \
  --inventory-browser-trust-roots "$HOME/.config/chromium/Default/exported-roots" \
  --inventory-private-key-roots /etc/ssl/private,/etc/ssh

# Then read the projected discovery inventory and graph from the control plane.
trstctl-cli discovery findings list
trstctl-cli graph nodes
```

When you find a credential you didn't expect, follow it into the
[credential graph](graph-query-ai.md) to see what it can reach, or into
[risk scoring](observability-and-risk.md) to see why it matters.

## Pitfalls & limits

Be precise about what runs in the server today versus what ships as tested library
code awaiting control-plane wiring (this matters for an honest evaluation — see also
[Current limitations](../limitations.md)):

| Capability | Status today |
|---|---|
| Certificate inventory (F1) | **Served** — REST + CLI, event-sourced, with `/api/v1/certificates/health` expiry/source dashboard |
| Agent enrollment (for F3) | **Served** — `/enroll/bootstrap`, `/api/v1/agents` |
| Agent-based discovery loop (F3) | **Served report path** — local filesystem, trust-store, private-key-material, token, Windows-store, and Kubernetes enumeration runs inside the agent; mTLS `ReportInventory` records source/run/finding rows and graph nodes |
| Network discovery (F2) | **Served** — source/schedule/run/finding APIs + CLI/UI; TLS scan executes through the outbox with reserved-IP SSRF filtering |
| Agentless cloud discovery (F49) | **Served** — source/schedule/run/finding records; AWS ACM, Azure Key Vault, and GCP Certificate Manager provider execution runs from the outbox with credential references |
| Cross-surface NHI discovery (CAP-NHI-01) | **Served** — `nhi_cross_surface` source/schedule/run/finding records normalize IdP, cloud, SaaS, on-prem, code, and CI observations into metadata-only `non_human_identity` findings |
| Unified NHI inventory (CAP-NHI-02) | **Served** — `/api/v1/nhi/inventory` normalizes identities, certificates, API-token metadata, agents, and discovery findings across certificate, SSH-key, secret, API-key, OAuth-app, token/PAT, service-account, IAM-role, webhook, workload-identity, and agent kinds |
| API-key/token/PAT discovery (CAP-NHI-04) | **Served** — `api_key` source/schedule/run/finding records normalize cloud access keys, SaaS API keys, CI/CD tokens, OAuth refresh tokens, and personal access tokens into metadata-only `api_key`, `api_token`, and `personal_access_token` findings |
| OAuth app/grant/scope discovery (CAP-OAUTH-01) | **Served** — `oauth_grant` source/schedule/run/finding records normalize SaaS-to-SaaS consent metadata into metadata-only `oauth_grant` findings |
| Malicious / abused OAuth-grant detection (CAP-ITDR-03) | **Served** — `oauth_grant` runs emit metadata-only `oauth_grant_abuse` findings tagged `CAP-ITDR-03` when grant exports include provider threat signals, dangerous scopes, unverified-publisher evidence, ownerless privileged admin consent, or suspicious redirect URIs |
| Service-account discovery & inventory (CAP-NHI-03) | **Served** — `service_account` source/schedule/run/finding records normalize AD/on-prem and cloud service-account metadata into `service_account` findings |
| NHI behavior analytics (CAP-ITDR-01) | **Served** — `nhi_behavior` source/schedule/run/finding records baseline activity and emit metadata-only `nhi_behavior_anomaly` findings for IP, geo, user-agent, usage-spike, and off-hours anomalies |
| Compromised-credential / stolen-token detection (CAP-ITDR-02) | **Served** — `credential_compromise` source/schedule/run/finding records normalize ITDR, honeytoken, scanner, IdP, and threat-intel signals into metadata-only `compromised_credential` findings tagged to OWASP NHI2 |
| Kubernetes Ingress/Gateway API TLS auto-issuance (CAP-K8S-03) | **Served** — `k8s_ingress_gateway` source/schedule/run/finding records normalize Ingress and Gateway TLS metadata into `k8s_tls_auto_issuance` findings and mint signer-backed public certificate inventory rows |
| CT-log monitoring (F17) | **Partially served** — source/schedule/run/finding APIs + CLI/UI; CT polling executes through the outbox and raises notification alerts |
| Drift detection (F18) | **Partially served** — source/schedule/run/finding APIs + CLI/UI; watched-path fingerprint/mode checks execute through the outbox and raise notification alerts |
| SSH discovery (F42) | **Served** — source/schedule/run/finding APIs + CLI/UI; SSH host-key scans execute through the outbox worker and on-host SSH/private-key inventory reports through the agent mTLS path |
| Secret-store discovery (F35) | **Served for cloud secret managers** — metadata-only references/fingerprints, never values; includes AWS Secrets Manager, GCP Secret Manager, and HashiCorp Vault KV imports |

Other gotchas: a network scan only sees what a host presents on a port at scan time —
pair it with agent-based discovery for the full picture. Cloud discovery needs
read-only credentials with list/get permission on the relevant service. Secret-store
discovery records *references*, so a finding tells you a secret exists and where, not
what it is.

## Reference

- **CLI groups:** `certificates`, `discovery`, `agents` (full set: `owners`,
  `issuers`, `identities`, `certificates`, `discovery`, `profiles`, `audit`,
  `graph`, `risk`, `agents`).
- **Served routes:** `GET|POST /api/v1/certificates`, `GET /api/v1/certificates/{id}`,
  `GET|POST /api/v1/discovery/sources`, `GET|POST /api/v1/discovery/schedules`,
  `GET|POST /api/v1/discovery/runs`, `GET /api/v1/discovery/runs/{id}`,
  `GET /api/v1/discovery/findings`, `POST /api/v1/discovery/findings/{id}/claim`,
  `POST /api/v1/discovery/findings/{id}/dismiss`, `GET /api/v1/agents`,
  `POST /api/v1/agents/enrollment-tokens`, `GET /api/v1/graph`,
  `POST /enroll/bootstrap`.
- **Agent channel:** `AgentService.ReportInventory` over the mTLS agent gRPC listener
  when `agent_channel.enabled` is true.
- **Config:** `TRSTCTL_LIFECYCLE_RENEW_BEFORE` (default `720h`) sets the
  expiry window the inventory and lifecycle treat as "renew soon".
- **Served discovery source kinds:** `network`, `cloud_certificate`,
  `cloud_secret`, `nhi_cross_surface`, `oauth_grant`, `service_account`,
  `nhi_behavior`, `credential_compromise`, `k8s_ingress_gateway`, `ct_log`, `drift`,
  `manual`, plus metadata-only `ssh`, `secret_store`, `api_key`, and `agent`.
- **Discovery source kinds (agent):** `filesystem`, `pkcs11`, `windows-store`,
  `k8s-secret`, `trust-store`, `private-key`.
- **Agent inventory flags:** `--inventory-cert-roots`, `--inventory-os-trust-roots`,
  `--inventory-java-trust-stores`, `--inventory-java-trust-store-password`,
  `--inventory-nss-trust-roots`, `--inventory-browser-trust-roots`,
  `--inventory-private-key-roots`.
- **Audit events:** `certificate.recorded`, `discovery.source.upserted`,
  `discovery.schedule.upserted`, `discovery.run.queued`, `discovery.run.started`,
  `discovery.finding.recorded`, `discovery.run.completed`, `secretscan.finding`.

## See also

[Observability & risk](observability-and-risk.md) (scoring what you discover) ·
[Graph, query & AI](graph-query-ai.md) (what a credential can reach) ·
[Secrets](secrets.md) · [Current limitations](../limitations.md) ·
glossary: [certificate](../glossary.md), [fingerprint](../glossary.md),
[bulkhead](../glossary.md), [event sourcing](../glossary.md)

**Covers:** F1, F2, F3, F42, F49, F35, F36
