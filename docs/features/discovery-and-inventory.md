# Discovery & inventory — find every certificate, key, and secret you already have

## What it is

Before you can manage credentials, you have to *know they exist*. Discovery is how
trstctl finds the credentials already scattered across your infrastructure —
[certificates](../glossary.md), SSH keys, and [secrets](../glossary.md) — and the
**inventory** is the single, tenant-scoped list it keeps them in.

Think of it like a building's master key register: someone has to walk every floor,
write down every lock and every key, and keep that register current as locks change.
trstctl is that walker and that register, for machines.

In the console, open **Posture & response → Find unmanaged credentials**. The page
starts with the credentials that need a decision. Choose **Run scan** to use an
existing discovery source or add your first one.

trstctl discovers credentials five ways, and each suits a different corner of your
estate: scanning the network from outside, asking an agent what a host can see from
inside, pulling inventory straight from cloud provider APIs, reading SSH key files and
trust config, and connecting to external secret stores. Everything they find lands in
one inventory.

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

Nothing writes to that table directly — a core trstctl design rule
([event sourcing](../glossary.md)). When a certificate is discovered or issued, the
orchestrator appends a `certificate.recorded` event to the append-only, tamper-evident
log, and a *projector* reads that event and builds the table row. The table is a
**projection** — a derived view you could delete and rebuild from the log — which is
why trstctl can survive a database loss: the truth is the event log, and the inventory
is just a fast index into it.

Ingestion is idempotent: the row key is `(tenant_id, fingerprint)`, so seeing the same
certificate twice refreshes one row instead of creating a duplicate, and the ingest API
requires an [`Idempotency-Key`](../glossary.md) so a retried request can't double-record.
Certificate parsing routes through the single isolated cryptography path, so the
inventory code itself never touches the low-level X.509 libraries directly.

`GET /api/v1/certificates/health` serves a tenant-wide expiry dashboard from that same
projection: total active inventory, expired and 7/30/90-day expiry bands, source
breakdown, and the soonest-expiring certificates. It counts trstctl-issued rows,
manually imported rows, and discovery-fed rows together, so a certificate issued by a
different CA but found on a load balancer still shows up in the same health posture.

### Network discovery (F2) — scanning from the outside, no agent needed

Network discovery connects to IP/port ranges you define, performs a normal
[TLS](../glossary.md) handshake, captures the certificate each host presents, and
records its metadata. No software is installed on the targets — it sees exactly what
any client on the network would see.

The scanner runs in its own bounded [lane](../glossary.md): a bounded pool of workers
(default 16, queue 256). When the queue fills, it slows the producer instead of dropping
targets or exhausting the pool the API needs, so a big scan can never starve the rest of
the system. The handshake and certificate parsing both go through the single isolated
cryptography path, and the scanner applies the shared SSRF guard and a reserved-IP
denylist before dialing expanded CIDRs, so a scan cannot be turned into a loopback,
RFC1918, link-local, or cloud-metadata probe.

Operators create a `network` source, queue a run, and inspect findings through
REST/CLI/UI. The run executes from the outbox worker — the external probes are
journaled first and delivered at-least-once, so they're durable and retryable instead
of being done inline by the request handler.

### Continuous monitoring rollup

`GET /api/v1/discovery/monitoring` (CLI: `trstctl discovery monitoring`) is a single
read-side rollup over the tenant's discovery sources, enabled schedules, last runs,
findings, and certificate inventory — it creates no new state, just joins the same
`discovery.*` and `certificate.recorded` projections other endpoints already read. Each
source row shows whether it's scheduled, the monitoring interval, the latest run
status, finding counts, and pointers to `/api/v1/certificates` and
`/api/v1/discovery/findings`. The console keeps this exact rollup under
**Monitoring and exact scan evidence**. The credentials needing a decision appear
first; operators can still expand the underlying CT, drift, coverage, source,
schedule, run, and repository-path proof when they need to verify or troubleshoot it.

### Agent-based discovery (F3) — what each host can see from the inside

A network scan only sees what a host *presents on a port*. Plenty of credentials never
appear on the wire: a certificate sitting in a file, in a PKCS#11 token, in the Windows
certificate store, or in a Kubernetes Secret. The trstctl **agent** runs on the host and
enumerates those local sources, then reconciles what it finds into the inventory over
its mutually-authenticated ([mTLS](../glossary.md)) channel. Each source is
independent: if one token errors, the agent records the error and keeps going, so one
broken source can't hide the rest.

The agent enrolls into the control plane with a one-time bootstrap token
(`POST /enroll/bootstrap`); `GET /api/v1/agents` then lists it, and
`POST /api/v1/agents/{id}/offboard` emits an `agent.offboarded` event, keeps the row
visible as a tombstone with actor/reason evidence, and causes the agent's mTLS
certificate to be rejected on future heartbeat, renewal, and inventory RPCs.

The agent's own discovery sources are `filesystem`, `pkcs11`, `windows-store`,
`k8s-secret`, `trust-store`, and `private-key` — the read has to happen on the host,
since only it can see its own files, tokens, Windows store, trust stores, browser
profiles, or in-cluster Secrets. An enrolled agent sends metadata-only `ReportInventory`
batches over the same mTLS channel it uses for heartbeat and renewal; the server rejects
inline secret-looking metadata keys, caps batch size, and ingests in the bounded agent
lane so a noisy fleet cannot starve the API. `GET /api/v1/agents` advertises the
accepted source kinds for each enrolled endpoint, and the Agents console shows the same
capability list.

For Linux certificate files, the shipped agent can inventory public certificate roots at
startup with `--inventory-cert-roots`, reporting references, fingerprints, and
certificate metadata only — never private keys or secret values.

**Kubernetes TLS Secrets.** A cluster is frequently the largest single population of
certificates an organization holds, and the one nobody has an inventory of. Run the agent
in-cluster with `--inventory-k8s-secrets` and it enumerates the `kubernetes.io/tls`
Secrets in **its own namespace** through the in-cluster service account, reporting each
Secret's certificate metadata over the same mTLS inventory path as every other source.

The exact contract: it reads `tls.crt` — public certificate material — and never
`tls.key`; no key bytes cross the agent channel. It needs list access to Secrets in that
namespace, and it sees **only that namespace**, so a cluster-wide inventory means an
agent per namespace. A Secret whose certificate does not parse is skipped rather than
failing the pass, so one malformed Secret does not cost you the inventory of the rest;
an unreachable API server is an error rather than an empty result, because reporting
"no certificates" for a cluster you could not reach is worse than reporting nothing.

### CA, trust-store & private-key discovery

`GET /api/v1/ca/discovery` rolls up CA estates: configured public upstream CAs,
configured private upstream CAs, and imported private CA hierarchy authorities, all in
one tenant-scoped response with source id, source kind, public/private scope, status,
and pointers such as `/api/v1/external-cas/{id}/issue` or
`/api/v1/ca/authorities/{id}/issue`. It intentionally omits certificate PEM and
private-key bytes — operators use it to see which CAs are connected, then follow the
referenced route for issuance or import.

Trust-store discovery is a separate agent collector, because a trusted CA is not the
same thing as a deployed service certificate. The agent reads public trust anchors from
OS trust directories, Java `cacerts`/JKS files, NSS profile exports, browser profile
exports, and Windows trust-store enumerators, tagging each finding with
`trust_store_kind` (`os`, `java`, `nss`, `browser`, or `windows`) and
`private_key_present=false`. It also reports the certificate SHA-256 fingerprint
and SPKI SHA-256 public-key identity. The graph counts a store as trusting a managed
issuer only when one of those exact identities matches; a subject-name-only match
is a separately visible unverified candidate, not an authoritative edge. This lets
the control plane answer "what does this host trust?" without ever moving a key or
mistaking two same-name roots for the same authority. The control plane stamps the
host from the reporting agent's verified mTLS identity, so several stores or anchor
paths on one machine remain several stores across one host.

Private-key-material discovery answers the companion question: "what sensitive key
files exist here?" Point the agent at canary directories with
`--inventory-private-key-roots`. It reads each regular file locally, classifies PKCS#8,
PKCS#1 RSA, SEC1 EC, OpenSSH, and encrypted private-key containers through the isolated
cryptography boundary, wipes the file buffer after inspection, and reports only the
path, format, algorithm, file-mode metadata, and — when the key is parseable — a
fingerprint derived from the public key. Encrypted keys are located and tagged as
encrypted, but no passphrase is requested and no private bytes ever reach the control
plane.

### SSH credential discovery (F42) — keys and standing access

SSH is where forgotten access hides. trstctl inventories SSH credentials two ways: a
network-side SSH handshake captures each host's **host key**, and the on-host agent
reads host keys, user keys, `authorized_keys` grants, `known_hosts` trust anchors, and
the `TrustedUserCAKeys` directive from `sshd_config`. The same agent path locates and
classifies SSH and TLS private-key files as metadata-only findings instead of copying
key bytes into the control plane.

On-host SSH collection is explicit, not a surprise filesystem crawl. Configure only
the paths the agent may read with `--inventory-ssh-host-key-globs`,
`--inventory-ssh-user-key-globs`, `--inventory-ssh-authorized-keys`,
`--inventory-ssh-known-hosts`, and `--inventory-ssh-sshd-configs`. Every flag is empty
by default. For example:

```sh
trstctl-agent ... \
  --inventory-ssh-host-key-globs '/etc/ssh/ssh_host_*_key.pub' \
  --inventory-ssh-authorized-keys '/home/*/.ssh/authorized_keys' \
  --inventory-ssh-known-hosts '/etc/ssh/ssh_known_hosts,/home/*/.ssh/known_hosts' \
  --inventory-ssh-sshd-configs /etc/ssh/sshd_config
```

The agent reports the result over its existing mTLS inventory RPC. The control plane
derives the tenant from the verified agent certificate, appends discovery events, and
projects the metadata into `GET /api/v1/ssh/fleet`. Operators can read the same view
with `trstctl ssh fleet` or in **Workload & SSH → SSH trust**.

Two flags make the result actionable. **StandingAccess** marks an entry that grants
persistent login (an `authorized_keys` line). **Orphaned** marks a standing-access grant
whose comment field is blank — meaning nobody can say whose key it is. An orphaned
standing-access key is exactly the thing a security team wants surfaced. Only the
fingerprint is ever stored, never private key material (held in wipeable memory and
zeroed after use).

The control plane serves `ssh` discovery source/run/finding records and executes
non-invasive SSH host-key scans from the discovery outbox worker. Source configs accept
explicit `targets` (`host:port`) or CIDRs plus ports, run on a bounded worker lane, and
use reserved-address filtering unless the operator explicitly allows private or loopback
diagnostic targets.

### Discovery source kinds, one shape

Eight more source kinds follow an identical pattern: create a source with a `kind` and
a `config`, queue a run, read back metadata-only findings. Rather than walk through
that shape eight times, here is what each one actually finds:

| Source kind | What it finds | Config essentials |
|---|---|---|
| `cloud_certificate` (F49) | Certificates the cloud provider already knows about: AWS ACM, Azure Key Vault, GCP Certificate Manager | `providers[]` (region/vault/project plus `access_key_id_ref`, `secret_access_key_ref`, or `token_ref`); inline credentials are rejected before storage |
| `nhi_cross_surface` | Non-certificate machine identities across six surfaces: IdP, cloud, SaaS, on-prem, code, and CI | `observations[]`: `surface`, `system`, `external_id`, `principal`, `owner`, `credential_kind`, `scopes`; needs at least one observation per surface |
| `service_account` (CAP-NHI-03) | AD/on-prem and cloud service accounts | `accounts[]`: `surface` (`active_directory` or `cloud`), `provider`, `account_id`, `principal`, `credential_refs`; needs at least one of each surface |
| `oauth_grant` | Third-party OAuth apps, grants, and scopes; a second pass flags abused or malicious grants | `grants[]`: `provider`, `app_id`, `principal`, `resource`, `scopes`, `consent_type`, `third_party`, `owner`; no client-secret or token field exists |
| `nhi_behavior` | Behavior anomalies (unfamiliar IP, geo, or user-agent; usage spikes; off-hours activity) against a learned per-principal baseline | `events[]`: `principal`, `occurred_at`, `ip`, `geo`, `user_agent`, `action`, `usage_count`, `baseline`; optional `business_hours` window |
| `credential_compromise` (CAP-ITDR-02) | Leaked, replayed, or honeytoken-flagged credentials (OWASP NHI2 signals) | `signals[]`: `principal`, `credential_ref`, `credential_kind`, `provider`, `detector`, `observed_at`, `reason`, `confidence`, `evidence_refs` |
| `k8s_ingress_gateway` (CAP-K8S-03) | Kubernetes `Ingress`/`Gateway` API TLS needs; mints signer-backed public certificates through the same issuance path as lifecycle | `resources[]`: `kind` (`Ingress` or `Gateway`), `namespace`, `name`, `tls_secret_name`, `hosts`, `auto_issue` |
| `secret_store` / `api_key` (F35, F36) | Secrets, API keys, tokens, and PATs by reference only — path, name, or ARN plus a masked fingerprint, never a value; also covers cloud secret-manager import from AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, and HashiCorp Vault KV for certificate material stored as secrets | path/name/ARN, `masked_fingerprint`, scope, expiry, `rotation_age_days`; secret-shaped fields (`token_value`, `secret`, `password`, `private_key`) are rejected before a source is stored |

All eight run through the discovery outbox worker, normalize their input into
metadata-only findings carrying a stable provenance string (`<kind>:<key-parts>`), and
append the standard `discovery.*` audit events. Several also stamp a `capability` tag
used for compliance/ITDR mapping (for example `CAP-ITDR-02`, `CAP-ITDR-03`) — see
[Observability & risk](observability-and-risk.md) for how findings feed risk scoring and
posture. Every finding also becomes a node in the [credential graph](graph-query-ai.md)
with its provenance and risk score; a related bridge ingests leaked-credential findings
from scanners (gitleaks, trufflehog) into the same graph, again excluding the secret
value structurally.

One worked example — the shape is identical for the other seven kinds, just swap `kind`
and `config` (the create → run → findings CLI flow is the same one shown for `network`
under **Use it** below):

```json
{
  "kind": "oauth_grant",
  "name": "quarterly-oauth-consent",
  "config": {
    "grants": [
      {
        "provider": "okta",
        "app_id": "0oa-payments",
        "principal": "payments-bi-export",
        "resource": "google-workspace",
        "scopes": ["drive.readonly"],
        "consent_type": "admin",
        "third_party": true,
        "owner": "finance-platform"
      }
    ]
  }
}
```

For `oauth_grant` specifically: a grant with provider threat signals, a dangerous or
`.default` scope, `offline_access` combined with high-privilege admin consent, an
unverified publisher, a missing owner on a privileged grant, or a suspicious redirect
URI additionally emits an `oauth_grant_abuse` finding tagged `capability=CAP-ITDR-03`.
Ordinary high-risk-but-owned grant inventory stays `oauth_grant` only, so trstctl does
not count inventory as detection.

### Unified NHI inventory — every credential kind, one denominator

`GET /api/v1/nhi/inventory` (`nhi:read`) is a read-side projection, not a new state
store, over identities, certificate inventory rows, API-token metadata, enrolled
agents, and discovery findings, normalized into one item shape spanning certificates,
SSH keys, secrets, API keys, OAuth apps, tokens/PATs, service accounts, IAM roles,
webhooks, workload IDs, and agents. Each item preserves its provenance (`identity`,
`certificate_inventory`, `access_api_token`, `agent_fleet`, or `discovery_finding`) plus
public metadata — owner, status, fingerprint, risk score, source system, external
reference — and never returns secret values, private keys, or raw API tokens. The
dashboard's NHI inventory summary consumes this API directly, so the first screen
counts all eleven kinds instead of only the managed `identities` table.

Managed NHI decommissioning rides the same denominator: `POST /api/v1/nhi/decommission`
selects tenant-local managed identities by departure, vendor-term, or inactivity signal
and drives the normal event-sourced revoke/retire lifecycle transitions.

### Ownership attribution — the canonical treatment

Every non-human identity needs an accountable owner, not a discovery note that says
"owner: unknown." `GET /api/v1/ownership/attribution` (`nhi:read`) resolves NHIs to an
owner two ways: managed identities resolve their stored `owner_id` directly, while
discovery-fed rows resolve the metadata-only owner, team, or vendor name captured at
discovery time against registered owners. Anything that doesn't resolve stays marked
`orphaned` rather than silently counted as accountable — that feeds tenant
governance reporting and the orphaned-owner signal risk scoring weighs. Each resolution
carries an evidence ref (such as `discovery.finding:<id>` or `inventory:<id>`) back to
the record that produced it, so an operator can trace an attribution to its source. The
same data is available via `trstctl-cli owners attribution` and the Owners console;
[Policy & governance](policy-and-governance.md) is the main consumer that turns this
into compliance posture.

### Discovery triage

Findings are immutable evidence, but their operator triage state is mutable and
event-sourced. `triage_status` starts as `unmanaged`; the state model also includes
`investigating`, `managed`, and `dismissed`. `POST
/api/v1/discovery/findings/{id}/claim` marks a finding managed, and `POST
/api/v1/discovery/findings/{id}/dismiss` dismisses it with a reason. Both are
tenant-scoped, idempotent mutations guarded by `discovery:write`.

A finding produced without an explicit ID gets one deterministic ID from its exact
tenant, run, kind, reference, and fingerprint. This matters when the outbox retries a
partly completed scan: the retry records the same observation identity instead of a
new UUID that collides only after restart replay. Older histories can contain both
payload IDs for one natural observation. The projection keeps those IDs as aliases,
chooses the earliest immutable observation (then lexical ID for an exact-time tie) as
the canonical row, and resolves later triage events through either alias. A duplicate
whose source, provenance, risk, or metadata differs is not merged: replay fails with
the tenant, natural key, both IDs, and differing fields rather than silently changing
the evidence.

`GET /api/v1/nhi/posture/shadow` is the shadow posture view: it pages
through tenant-scoped discovery findings, excludes anything already claimed as managed
or dismissed, counts unmanaged and unregistered external NHIs by kind and surface, and
returns recommendation/evidence refs only — never credential values.
`trstctl-cli nhi posture shadow` reads the same view.

### In the console

The `/discovery` screen is named **Find unmanaged credentials** because that is the
operator's job, not the database feature underneath it. Its default reading order is:

1. **What needs attention** — unmanaged count, high-risk count, and credential types.
2. **Credentials to review** — one plain-language row action opens the finding.
3. **Claim** — the main next step turns a reviewed finding into managed inventory.

Less-common rotate, revoke, decommission, remediate, and dismiss actions are grouped
under **More actions**. Exact fingerprints, internal finding/source/run IDs,
provenance, evidence references, raw kinds, the shadow-NHI projection, CT monitoring,
and drift details remain available through explicit evidence disclosures. This keeps
the first decision understandable while preserving the technical proof needed for an
audit or investigation. See [The web console](../web-console.md).

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
cat > segment.json <<'JSON'
{"name":"edge","ranges":["10.0.0.0/24"],"staleness_hours":24,"excluded":false}
JSON
trstctl-cli discovery segments create -f segment.json

cat > source.json <<'JSON'
{"kind":"network","name":"edge-tls","config":{"segment":"edge","targets":["10.0.0.10:443"]}}
JSON
trstctl-cli discovery sources create -f source.json
trstctl-cli discovery sources list

cat > run.json <<'JSON'
{"source_id":"<source-id>"}
JSON
trstctl-cli discovery runs start -f run.json
trstctl-cli discovery runs list
trstctl-cli discovery findings list --run_id <run-id>
trstctl-cli nhi posture shadow
```

The segment command maps to `POST /api/v1/discovery/segments`; declare that
bounded estate scope before creating any network or SSH source. The remaining
commands map to `POST|GET /api/v1/discovery/sources`,
`POST|GET /api/v1/discovery/schedules`, `POST|GET /api/v1/discovery/runs`,
`GET /api/v1/discovery/runs/{id}`, `GET /api/v1/discovery/findings`,
`POST /api/v1/discovery/findings/{id}/claim`, and
`POST /api/v1/discovery/findings/{id}/dismiss`. The shadow posture command maps to
`GET /api/v1/nhi/posture/shadow`.

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
| Certificate inventory (F1) | **Served** — REST + CLI, event-sourced, with the `/api/v1/certificates/health` expiry/source dashboard |
| Network discovery (F2) | **Served** — source/schedule/run/finding APIs + CLI/UI; TLS scan executes through the outbox with reserved-IP SSRF filtering |
| Agent-based discovery (F3) | **Served** — enrollment (`/enroll/bootstrap`, `/api/v1/agents`) and the mTLS `ReportInventory` path record source/run/finding rows and graph nodes |
| SSH discovery (F42) | **Served** — source/schedule/run/finding APIs + CLI/UI; host-key scans execute through the outbox, and on-host SSH/private-key inventory reports through the agent mTLS path |
| Agentless cloud discovery (F49) | **Served** — AWS ACM, Azure Key Vault, and GCP Certificate Manager provider execution runs from the outbox with credential references |
| Secret-store & API-key discovery (F35, F36) | **Served for cloud secret managers** — AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, and HashiCorp Vault KV imports; metadata-only references and fingerprints, never values |
| Cross-surface NHI discovery | **Served** — six-surface (IdP/cloud/SaaS/on-prem/code/CI) metadata-only findings |
| Unified NHI inventory | **Served** — `/api/v1/nhi/inventory` normalizes identities, certificates, tokens, agents, and findings across eleven kinds |
| Service-account discovery (CAP-NHI-03) | **Served** — AD/on-prem and cloud service-account findings |
| OAuth grant discovery + abuse detection (CAP-ITDR-03) | **Served** — consent metadata findings, plus `oauth_grant_abuse` detections |
| NHI behavior analytics | **Served** — baseline and anomaly findings for IP, geo, user-agent, usage-spike, and off-hours signals |
| Compromised-credential detection (CAP-ITDR-02) | **Served** — honeytoken/leak/replay signals normalized to findings tagged to OWASP NHI2 |
| Shadow/unmanaged NHI posture | **Served** — `/api/v1/nhi/posture/shadow`, `trstctl-cli nhi posture shadow`, and the Discovery console |
| Kubernetes Ingress/Gateway TLS auto-issuance (CAP-K8S-03) | **Served** — `k8s_ingress_gateway` findings mint signer-backed public certificates for `Ingress`/`Gateway` resources |

NHI policy compliance lives in [Policy & governance](policy-and-governance.md); CT-log
monitoring and drift detection live in [Observability & risk](observability-and-risk.md)
— all three read the same discovery projections, but they aren't this page's features.

Other gotchas: a network scan only sees what a host presents on a port at scan time —
pair it with agent-based discovery for the full picture. Cloud discovery needs
read-only credentials with list/get permission on the relevant service. Secret-store
discovery records *references*, so a finding tells you a secret exists and where, not
what it is.

## Reference

- **CLI groups:** the discovery-relevant commands live under `discovery`
  (`sources`, `schedules`, `runs`, `findings`, `ct-monitoring`, `drift-remediation`,
  `monitoring`), plus `certificates`, `agents`, and `nhi`. trstctl-cli has many more
  command groups outside discovery; `trstctl-cli <group> --help` lists the current
  subcommands for any of them.
- **Served routes:** `GET|POST /api/v1/certificates`, `GET /api/v1/certificates/{id}`,
  `GET|POST /api/v1/discovery/sources`, `GET|POST /api/v1/discovery/schedules`,
  `GET|POST /api/v1/discovery/runs`, `GET /api/v1/discovery/runs/{id}`,
  `GET /api/v1/discovery/findings`, `POST /api/v1/discovery/findings/{id}/claim`,
  `POST /api/v1/discovery/findings/{id}/dismiss`, `GET /api/v1/agents`,
  `GET /api/v1/nhi/posture/shadow`, `GET /api/v1/ownership/attribution`,
  `POST /api/v1/agents/enrollment-tokens`,
  `POST /api/v1/agents/{id}/offboard`,
  `GET /api/v1/graph`,
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
  `--inventory-private-key-roots`, `--inventory-ssh-host-key-globs`,
  `--inventory-ssh-user-key-globs`, `--inventory-ssh-authorized-keys`,
  `--inventory-ssh-known-hosts`, `--inventory-ssh-sshd-configs`.
- **Audit events:** `certificate.recorded`, `discovery.source.upserted`,
  `discovery.schedule.upserted`, `discovery.run.queued`, `discovery.run.started`,
  `discovery.finding.recorded`, `discovery.run.completed`, `secretscan.finding`.

## See also

[Policy & governance](policy-and-governance.md) (ownership attribution's main consumer) ·
[Observability & risk](observability-and-risk.md) (scoring what you discover) ·
[Graph, query & AI](graph-query-ai.md) (what a credential can reach) ·
[Secrets](secrets.md) · [Current limitations](../limitations.md) ·
glossary: [certificate](../glossary.md), [fingerprint](../glossary.md),
[bulkhead](../glossary.md), [event sourcing](../glossary.md)

**Covers:** F1, F2, F3, F42, F49, F35, F36
