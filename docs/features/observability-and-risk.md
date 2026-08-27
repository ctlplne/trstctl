# Observability & risk — see your crypto, score it, catch what changes

## What it is

Discovery tells you *what credentials exist*; this page — the smoke detectors and risk
register to [discovery](discovery-and-inventory.md)'s census — tells you *which ones to
worry about and what's changing*: **Certificate Transparency monitoring** (certificates
issued for your domains you didn't request), **drift detection** (a deployed credential
moved, replaced, or exposed), **credential risk scoring** (rank everything by "fix this
first"), and the **CBOM** — a bill of materials flagging weak and quantum-vulnerable
crypto.

trstctl also exports the control-plane signal you need to operate those workflows:
served HTTP traces and event-sourced audit records can stream to your OpenTelemetry
Collector over OTLP/HTTP protobuf. That lets Splunk, Datadog, or any SIEM pipeline
consume the same immutable audit stream auditors inspect, with event sequence and
tenant attributes for dedupe and gap detection.
In air-gapped installs, that collector must be operator-owned on a private host or
explicitly allowlisted; the no-phone-home guard blocks public collector endpoints.

## Why it exists

A list of credentials only helps if you can act on it. Security teams drown in findings,
so the question is always "what first?" — that's risk scoring. Mis-issuance and shadow
IT show up as certificates in public logs you didn't request — that's CT monitoring.
Quietly broken or loosened deployments cause outages — that's drift. And the looming
quantum transition makes "where is our weak/old crypto?" urgent — that's the CBOM.
Together they turn inventory into action.

## How it works

### Credential risk scoring (F19)

Risk scoring assigns every credential a 0–100 score from six weighted factors: age,
exposure (blast radius from the [graph](graph-query-ai.md)), privilege, rotation
staleness (never-rotated scores highest), owner activity (orphaned scores higher), and
sensitivity (wildcards/large SAN sets) — weighted toward exposure and privilege, what
hurts most in a breach. Scoring pages the whole inventory, tenant-isolated at the
database layer; filter by minimum score, privilege class, or owner.

**Status: served** — `GET /api/v1/risk/credentials`, `GET
/api/v1/risk/contextual-priorities`, and the four NHI-posture routes below, each with a
matching `risk`/`nhi posture` CLI command.

Contextual risk prioritization ranks certificates, NHI, SSH keys, and discovery findings
by blast-radius impact, CBOM crypto context, owner state, staleness, and expiry urgency,
returning priority reasons, evidence refs, severity, and a recommended action — useful
when two credentials score similarly but differ sharply in blast radius.

The web route calls this decision **What to fix first**. Its default layer turns the
contextual ranking into a quiet, human-readable worklist with one review action per
credential. Opening a review shows the recommended next action first. Exact score
inputs, raw reason codes, the versioned model contract, immutable evidence IDs,
generation time, and projection coverage are preserved behind an explicit evidence
disclosure. The certificate-only score table and all supporting posture projections
remain available in a second disclosure, so an operator can audit the complete model
without making proof machinery compete with the first decision.

`GET /api/v1/risk/contextual-priorities` also returns the canonical tenant-scoped
`urgent_summary`. Think of this as counting red lights after combining both served
maps, rather than counting only one map and accidentally showing zero. It names the
included credential-score and contextual-priority projections, reports each
projection's analyzed/critical/high counts, and deduplicates their union by
`credential_id`. Dashboard and Risk consume this same contract. A failed projection
read is an unavailable summary, never a fabricated zero. Recording a critical or high
discovery finding atomically creates one `notification.risk` / `risk.urgent` outbox
intent from the same score band; replaying the immutable event reuses the same
idempotency key rather than creating a second alert.

NHI posture reads the same unified inventory as the dashboard — managed identities,
access tokens, and discovery findings — across four conditions:

| Endpoint | What it answers | Key response fields |
|---|---|---|
| `GET /api/v1/nhi/posture/overprivilege` | Which grants exceed observed usage? | Unused grants, least-privilege recommendation, source row, severity, evidence refs |
| `GET /api/v1/nhi/posture/stale` | Which credentials are stale, dormant, unused, or orphaned? | Thresholds, activity/creation age, owner status, severity, evidence refs, remediation |
| `GET /api/v1/nhi/posture/static-credentials` | Which credentials are long-lived, static, or overdue for rotation? | Credential age, TTL, rotation age, lifetime thresholds, owner status, severity, evidence refs, remediation |
| `GET /api/v1/nhi/posture/exposure` | Which credentials are internet-exposed or insecurely deployed? | Sanitized endpoint/callback URLs, severity, evidence refs, remediation |

Grants with no usage evidence stay unclassified rather than counting as a finding; the
exposure route is read-only and never echoes credential values. For example,
`trstctl-cli nhi posture stale` reports each stale credential's activity age, owner
status, severity, and remediation.

### Certificate Transparency monitoring (F17)

Every certificate a public CA issues is recorded in public, append-only **CT logs**
(RFC 6962). If one appears for *your* domain that you didn't request, that's an early
warning of mis-issuance, shadow IT, or attack. trstctl's monitor polls CT logs
incrementally from a saved checkpoint, matches entries against watched domains (resistant
to the `example.com.evil.net` suffix trick), and alerts on anything not already in your
[inventory](discovery-and-inventory.md). Alerts use reliable, journaled, at-least-once
delivery with an idempotency key (`ct:<log>:<index>`) so a retry never double-alerts.
Polling runs in its own bounded lane, RFC 6962 binary parsing stays inside the single
crypto path, and checkpoints persist so monitoring resumes across restarts, tenant-isolated
at the database layer.

**Status: served.** Use `GET`/`PUT /api/v1/discovery/ct-monitoring`, `discovery
ct-monitoring get|update`, or the console to configure watched domains/logs, inspect
checkpoints, queue a poll, and review `ct_unexpected_issuance` findings. The worker polls,
records tenant-scoped findings, and queues notifications via the outbox.

`PUT` is exact replacement for the named source, not append. The source event and its
tenant-local active watchlist reconcile in one PostgreSQL transaction. Logs and domains
absent from the replacement become retired, cannot be polled by a later run, and remain
separately readable as audit history. Each run records one bounded immutable outcome per
configured log. A failed log therefore stays failed with its diagnostic while a working
peer still advances its checkpoint and keeps its findings; the aggregate run is `partial`
when both happened. The console separates active health from retired history so an old
404 endpoint cannot make the current watchlist look broken. While a run is queued or
running, the CT panel polls its run record to a terminal state and then reloads the
per-log checkpoints in place. The Discovery page's Refresh action reloads this panel as
well. Failed runs show a bounded, credential-redacted diagnostic beside their status;
operators get the repair clue without storing or serving an echoed bearer token or an
unbounded upstream response.

**Where to find it.** CT monitoring is a **discovery** capability — it answers "is
someone issuing certificates for my domains?" — so its home is the **Discovery**
workspace, which carries the whole loop on one surface: the watched-domain and log
watchlist, per-log checkpoint state (so you can see whether a log is actually being
polled, succeeded, failed, or has never been reached), retired log history,
unexpected-issuance findings with the certificate
detail, and a one-click hand-off to the rogue-certificate remediation path. Posture keeps
the readiness view. It previously appeared on Discovery only as a single count shared
with drift detection, which is why operators could not find the capability at all.

**What it does not cover.** CT monitoring sees exactly the domains you list and the logs
you poll — nothing else. A domain you have not added, or a log you do not configure,
produces no finding, so an empty findings list is not an all-clear for an estate. The
Discovery surface states this next to the counts rather than leaving a zero to be
misread. It also only sees certificates a CA chose to log, which in practice means
public issuance: a private CA that logs nothing is invisible here by construction.

### Drift detection (F18)

After the agent installs a credential, drift detection notices if reality diverges from
intent, comparing each watched file's content fingerprint and permissions and classifying
the divergence as `Deleted`, `Replaced` (different content), `Relocated` (same content
elsewhere, so a move isn't misreported as deletion), or `PermissionChanged` (mode/ACL
loosened). Permission checks are platform-aware (POSIX mode bits; Windows DACL for
broad-access ACEs); the agent reports at startup whether the platform can detect
permission loosening. Content hashing goes through the single crypto path;
secret material stays in wipeable memory, zeroed after use.

**Status: served.** Create a Discovery source of kind `drift` with watched paths,
fingerprints, and modes, then start a run; the worker records `credential_drift`
findings and queues notifications. Review findings, see the recommended action, and
record a decision via `GET /api/v1/discovery/drift-remediation`, `POST
/api/v1/discovery/drift-remediation/{id}/decision`, the `discovery drift-remediation`
CLI, or the Posture page. Decisions are event-sourced as
`discovery.finding.triage_changed` audit evidence; the API never stores or returns
credential bytes.

Before a run or recovery, `POST /api/v1/discovery/plans/preview` and `GET
/api/v1/discovery/sources/{id}/preflight` resolve the same drift plan the worker will
execute. This check does not read a watched file, queue a run, create an event, or make
an external call. It returns normalized watched paths, execution and connection origin,
the minimum permission, bounded worker/queue limits, and the non-secret evidence
boundary. It rejects incomplete watches and `auto_remediate`; the served drift worker
does not have declared-content custody or a rollback seam, so pretending otherwise
would be unsafe.

On **Posture → Certificate, AD CS, authority, and drift evidence**, a failed or partial
drift run first exposes **Review exact recovery plan**. **Create recovery run** appears
only after the saved-source preflight is ready and effect-free. The retry endpoint and
`discovery runs retry` CLI create a new idempotent run with `retry_of_run_id`; the
original terminal failure remains unchanged as audit evidence. The console names both
run IDs in its receipt and never renders the stored expected fingerprint.

### The CBOM — cryptographic bill of materials (F52)

You can't plan a crypto migration without knowing what crypto you run. The CBOM scanner
inventories cryptographic usage across TLS endpoints and host config files, then
classifies each observation: algorithm family and strength, whether it's
[quantum-vulnerable](../glossary.md), and whether it meets policy (default floor:
RSA-2048, EC-256, TLS 1.2; bans 3DES/DES/RC4/NULL/EXPORT/MD5/anon). Findings become
`KindCryptoAsset` nodes in the [credential graph](graph-query-ai.md), feeding
blast-radius and [compliance](policy-and-governance.md) reporting and the
[PQC migration](lifecycle-and-pqc.md). Scanning runs in its own bounded lane, is
non-fatal per source, tenant-isolated at the database layer, and keeps TLS/cert parsing
behind the single crypto path.

**Status: served.** `POST /api/v1/cbom/scans` (`discovery:write`, accepts an
`Idempotency-Key`) runs the scanner in the serving binary and records each observation
as an immutable `cbom.asset.observed` event before the read model projects it. `GET
/api/v1/cbom/assets` (`risk:read`) returns the tenant-scoped inventory plus migration
progress. CBOM work has its own bulkhead, so a wide TLS/config sweep rejects fast
instead of starving the regular API or enrollment lanes.

Each returned asset includes the discovered algorithm, source, policy result, PQC
posture, and a migration target:

| Observation | Migration target |
|---|---|
| RSA, ECDSA, Ed25519/EdDSA certificate signatures | `ML-DSA-65` (`FIPS 204`) |
| DSA certificate signatures | `SLH-DSA-SHA2-128s` (`FIPS 205`) |
| TLS protocol/cipher findings such as TLS 1.0 or 3DES | `ML-KEM-768` (`FIPS 203`) |
| Already quantum-safe ML-DSA, ML-KEM, or SLH-DSA observations | marked post-quantum-ready |

`migration_progress` is computed from the stored inventory: total assets, how many are
post-quantum-ready or quantum-vulnerable, and the ready percentage.

Core PQC campaigns turn those observations into owned work without requiring a
licence. From `/posture`, `/api/v1/pqc/campaigns`, or `trstctl-cli pqc campaigns`, an
operator can assign owner/deadline/wave/readiness, record a manual or third-party
remediation for each finding, and close only after every finding has evidence. Closure
produces an offline-verifiable signed artifact. Automated fleet execution remains an
optional Enterprise executor and is stated as unavailable by edition; campaign
tracking itself does not degrade into an upsell-only shell.

The migration surface is one canonical tenant dataset, not separate Risk and CBOM
interpretations. `GET /api/v1/graph/crypto-readiness` returns graph-built ordered rows,
the exact dependent path and attributed owners, bound campaign actions, explicit
coverage limits, and a `dataset_digest`. `/posture` joins those same rows to CBOM;
`/risk` reads the same query key. `POST /api/v1/graph/crypto-readiness/actions` creates
an idempotent event-sourced campaign only when every selected finding has a current
graph row and the requested owner is attributed by it. The immutable start event binds
each finding to its row digest. If topology or ownership changes, the action remains
visible as stale and evidence/readiness/closure mutations return `409` until an
operator creates a new action against current authority.

`GET /api/v1/graph/crypto-readiness/export` returns the exact dataset plus bounded CSV
and NDJSON. Its audit-key JWS binds the dataset and SHA-256 hashes of both byte formats;
the included JWKS supports offline verification. The same dataset is embedded in the
signed compliance manifest. A spreadsheet, log shipper, API client, CBOM view, Risk
view, workflow, and auditor can therefore compare one digest instead of reconciling
look-alike rows.

### In the console

The overview dashboard's **Urgent risk** KPI and `/risk` summary both render the
server's deduplicated `urgent_summary` across credential scores and contextual
priorities. Each projection remains visible, so an operator can see where the urgent
row came from; loading or failure renders unknown/unavailable instead of zero. The
overview's rotate-first list uses the same contextual priorities. Critical/high
discovery findings also surface through the durable `notification.risk` alert intent;
certificate-expiry alerts keep their existing event-backed path. `/notifications`
serves routing-policy authoring and channel-test delivery; scheduled digest delivery
stays outside the served workflow. See [The web console](../web-console.md).

## Use it

Find your riskiest credentials:

```sh
# rotate-this-first: high-privilege, score >= 50
trstctl-cli risk credentials --min_score 50 --privilege high --sort score

# blast-radius priority list with CBOM context + recommended action
trstctl-cli risk contextual-priorities

# NHI posture: overprivilege, stale, static-credential, and exposure findings
trstctl-cli nhi posture overprivilege
trstctl-cli nhi posture stale
trstctl-cli nhi posture static-credentials
trstctl-cli nhi posture exposure
```

Those map to `GET /api/v1/risk/credentials?sort=score&min_score=50&privilege=high`,
`GET /api/v1/risk/contextual-priorities`, and `/api/v1/nhi/posture/*`.
CT monitoring has a dedicated watchlist/checkpoint endpoint:

```sh
# CT-log monitoring: configure watched domains/logs and queue a poll.
trstctl-cli discovery ct-monitoring update --body ct-monitoring.json
trstctl-cli discovery ct-monitoring get
trstctl-cli discovery findings list --run_id "$RUN_ID"
```

`ct-monitoring.json` carries the watchlist:

```json
{
  "name": "public-ct-watch",
  "logs": ["https://ct.example.test/log"],
  "watched_domains": ["example.com"],
  "max_batch": 25,
  "run_now": true
}
```

Drift reuses the source/run/finding path, plus a remediation decision view:

```json
{
  "name": "edge-cert-drift",
  "kind": "drift",
  "config": {
    "watched": [
      {
        "path": "/etc/nginx/tls/edge.crt",
        "class": "certificate",
        "fingerprint": "sha256:...",
        "mode": "0644"
      }
    ]
  }
}
```

```sh
# review the saved source without running it, then create a separate retry
trstctl-cli discovery sources preflight "$SOURCE_ID"
trstctl-cli discovery runs retry "$FAILED_RUN_ID"

# list drift remediation rows and record an operator decision
trstctl-cli discovery drift-remediation
trstctl-cli discovery drift-remediation decide "$FINDING_ID" --body drift-decision.json
```

```json
{
  "decision": "investigate",
  "reason": "rotate certificate on the affected host before accepting the new fingerprint",
  "owner": "platform",
  "tags": ["rotation-ticket"]
}
```

CBOM scan:

```sh
curl -sS \
  -H "Authorization: Bearer $TRSTCTL_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: cbom-demo-001" \
  -X POST https://trstctl.example.com/api/v1/cbom/scans \
  -d '{
    "tls_endpoints": ["payments.internal.example:443"],
    "host_configs": ["/etc/nginx/sites-enabled/payments.conf"]
  }'
```

Then read the migration inventory:

```sh
curl -sS \
  -H "Authorization: Bearer $TRSTCTL_TOKEN" \
  https://trstctl.example.com/api/v1/cbom/assets
```

The response contains `items` and `migration_progress`; a non-empty
`quantum_vulnerable` count means crypto needs a migration target.

## Pitfalls & limits

| Capability | Status today |
|---|---|
| Credential risk scoring (F19) | **Served** — `/api/v1/risk/credentials`, `/api/v1/risk/contextual-priorities`, and the four `/api/v1/nhi/posture/*` routes above, plus `risk`/`nhi posture` CLI |
| CT monitoring (F17) | **Served** — CT watchlist/checkpoint API, CLI, and a headline Discovery surface (watchlist, per-log checkpoints, unexpected-issuance findings, remediation hand-off), plus Discovery `ct_log` execution and outbox-backed alerts |
| Drift detection (F18) | **Served** — shared effect-free plan preview/preflight, Discovery `drift` execution, immutable retry lineage, outbox-backed alerts, remediation API/CLI/Posture dashboard, and event-sourced decisions |
| CBOM (F52) | **Served** — `/api/v1/cbom/scans`, `/api/v1/cbom/assets`, core `/api/v1/pqc/campaigns`, event-backed inventory + signed campaign closure |

Other notes: CT monitoring depends on the logs/domains you list. Drift permission
detection is best-effort where the ACL model can't be fully read — the agent says so
rather than giving false assurance. The CBOM is only as complete as the sources you
point it at (TLS endpoints + config files). See
[Current limitations](../limitations.md) for the served-vs-library picture.

## Reference

- **Served:** `GET /api/v1/risk/credentials` (params `sort`, `min_score`, `privilege`,
  `owner`); `GET /api/v1/risk/contextual-priorities`; CLI `risk credentials`,
  `risk contextual-priorities`.
- **Risk factors:** age, exposure, privilege, rotation staleness, owner activity,
  sensitivity (weighted; defaults favor exposure + privilege).
- **CT:** Discovery source kind `ct_log`; finding kind `ct_unexpected_issuance`;
  idempotency key `ct:<log>:<index>`; RFC 6962.
- **Drift:** Discovery source kind `drift`; finding kind `credential_drift`; drift types
  `Deleted`, `Replaced`, `Relocated`, `PermissionChanged`; remediation routes
  `GET /api/v1/discovery/drift-remediation` and `POST
  /api/v1/discovery/drift-remediation/{id}/decision`; effect-free preview/preflight
  routes `POST /api/v1/discovery/plans/preview` and `GET
  /api/v1/discovery/sources/{id}/preflight`; immutable recovery route `POST
  /api/v1/discovery/runs/{id}/retry`.
- **CBOM API:** `POST /api/v1/cbom/scans` (`discovery:write`, `Idempotency-Key`
  required); `GET /api/v1/cbom/assets` (`risk:read`).
- **CBOM policy floor:** RSA-2048, EC-256, TLS 1.2; bans 3DES/DES/RC4/NULL/EXPORT/MD5.
- **CBOM event/read model:** `cbom.asset.observed` projects into `crypto_assets`;
  rebuilds/snapshots replay the same inventory.

## See also

[Discovery & inventory](discovery-and-inventory.md) (what feeds these) ·
[Graph, query & AI](graph-query-ai.md) (exposure / blast radius) ·
[Lifecycle & PQC](lifecycle-and-pqc.md) (migrating off weak crypto the CBOM finds) ·
[Policy & governance](policy-and-governance.md) (compliance reporting) ·
glossary: [Certificate Transparency](../glossary.md), [drift](../glossary.md),
[CBOM](../glossary.md), [PQC](../glossary.md)

**Covers:** F17, F18, F19, F52
