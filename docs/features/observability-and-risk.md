# Observability & risk — see your crypto, score it, catch what changes

## What it is

Discovery tells you *what credentials exist*; observability and risk tell you *which ones
to worry about and what's changing*. This page covers four capabilities: **Certificate
Transparency monitoring** (catch certificates issued for your domains that you didn't ask
for), **drift detection** (notice when a deployed credential is moved, replaced, or
exposed), **credential risk scoring** (rank everything by "fix this first"), and the
**CBOM** — a cryptographic bill of materials that inventories which algorithms you use and
flags the weak and quantum-vulnerable ones.

The mental model: discovery is the census; this page is the smoke detectors and the risk
register. CT monitoring watches the outside world for someone impersonating you; drift
detection watches your own hosts for unexpected change; risk scoring is the prioritized
to-do list; the CBOM is the materials audit that tells you where the weak crypto is before
an inspector (or an attacker) does.

trstctl also exports the control-plane signal you need to operate those workflows:
served HTTP traces and event-sourced audit records can stream to your OpenTelemetry
Collector over OTLP/HTTP protobuf. That lets Splunk, Datadog, or any SIEM pipeline
consume the same immutable audit stream auditors inspect, with event sequence and
tenant attributes for dedupe and gap detection.
In air-gapped installs, that collector must be operator-owned on a private host or
explicitly allowlisted; the no-phone-home guard blocks public collector endpoints.

## Why it exists

A list of credentials is only useful if you can act on it. Security teams drown in
findings, so the question is always "what first?" — that's risk scoring. Mis-issuance and
shadow IT show up as certificates in public logs you didn't request — that's CT
monitoring. Quietly broken or loosened deployments cause outages and exposure — that's
drift. And the looming quantum transition makes "where is our weak/old crypto?" an urgent
question — that's the CBOM. Together they turn inventory into action.

## How it works

### Credential risk scoring (F19)

Risk scoring assigns every credential a **0–100 score** so you can sort by priority. It
combines six independently-tested factors, each normalized and weighted: **age** (how far
through its validity it is), **exposure** (how many resources it can reach, from the
[graph](graph-query-ai.md)'s blast radius), **privilege**, **rotation staleness**
(never-rotated scores highest), **owner activity** (orphaned credentials score higher),
and **sensitivity** (wildcards/large SAN sets). Default weights favor blast-radius signals
(exposure and privilege) because those are what hurt most in a breach. Scoring pages
through the whole inventory with each tenant's data isolated at the database layer, and
you can filter by minimum score, privilege class, or owner.

**Status: served** — `GET /api/v1/risk/credentials` and the `risk credentials` CLI
command are live.

NHI over-privilege posture (CAP-POST-01) is served by
`GET /api/v1/nhi/posture/overprivilege` and
`trstctl-cli nhi posture overprivilege`. It reads the same unified NHI inventory as
the dashboard, compares granted scopes/permissions/roles with observed usage metadata,
and returns only usage-backed excessive-scope findings. Each finding includes unused
grants, the observed least-privilege recommendation to keep, severity, evidence
references, and the source row (`identity`, `access_api_token`, or
`discovery_finding`). Rows with grants but no usage evidence remain unclassified rather
than being counted as a category meet.

Stale NHI posture (CAP-POST-02) is served by `GET /api/v1/nhi/posture/stale`
and `trstctl-cli nhi posture stale`. It enumerates the same inventory for stale
activity, dormant activity, unused credentials with no observed activity, and
ownerless/orphaned records. The read path reports the thresholds used, the latest
activity and creation ages, owner status, severity, evidence references, and an
explicit remediation recommendation for each finding.

Static credential posture (CAP-POST-03) is served by
`GET /api/v1/nhi/posture/static-credentials` and
`trstctl-cli nhi posture static-credentials`. It detects long-lived credentials,
static lifecycle markers, no-expiry credentials, and overdue rotation age across the
same managed and discovered NHI inventory. Each finding reports lifetime thresholds,
credential age, TTL, rotation age, owner status, evidence references, severity, and
a remediation recommendation.

### Certificate Transparency monitoring (F17)

Every certificate a public CA issues is recorded in public, append-only **CT logs**
(RFC 6962). If a certificate appears there for *your* domain that you didn't request,
that's an early warning of mis-issuance, shadow IT, or attack. trstctl's monitor polls CT
logs incrementally from a saved checkpoint, matches entries against your watched domains
(resistant to the `example.com.evil.net` suffix trick), and for any certificate not
already in your [inventory](discovery-and-inventory.md) raises an alert. Alerts use
reliable, journaled delivery — outbound calls are written down first and delivered
at-least-once — with an idempotency key (`ct:<log>:<index>`) so a retry never
double-alerts; polling runs in its own bounded lane so it can't starve other work; all
RFC 6962 binary parsing stays inside the single crypto path; checkpoints persist so
monitoring resumes across restarts, with each tenant's data isolated at the database
layer.

**Status: partially served.** Create a Discovery source of kind `ct_log`, start a run,
and read the resulting `ct_unexpected_issuance` findings through the served Discovery API
or CLI. The served worker polls configured logs, records tenant-scoped findings, and
queues unexpected-issuance notifications through the outbox. A dedicated CT triage
dashboard and tenant self-service watchlist UI are still future work.

### Drift detection (F18)

After the agent installs a credential, drift detection notices if reality diverges from
intent. For each watched file it compares the content fingerprint and permissions, and
classifies the divergence: **Deleted**, **Replaced** (different content), **Relocated**
(same content found elsewhere — so a move isn't misreported as a deletion), or
**PermissionChanged** (mode/ACL loosened). Permission checks are platform-aware (POSIX
mode bits; Windows DACL for broad-access ACEs), and the agent honestly reports at startup
whether the platform can detect permission loosening at all. Content hashing goes through
the single crypto path; nothing secret is stored, and any secret material is held in
wipeable memory and zeroed after use.

**Status: partially served.** Create a Discovery source of kind `drift` with watched
paths, expected fingerprints, and expected modes, then start a run. The served worker
records `credential_drift` findings and queues drift notifications. Dedicated per-agent
drift dashboards, resolution state, and automated remediation controls are not served
yet.

### The CBOM — cryptographic bill of materials (F52)

You can't plan a crypto migration without knowing what crypto you run. The CBOM scanner
inventories cryptographic usage across TLS endpoints and host config files, then
**classifies** each observation: algorithm family and strength, whether it's
[quantum-vulnerable](../glossary.md), and whether it meets policy (default floor: RSA-2048,
EC-256, TLS 1.2; bans 3DES/DES/RC4/NULL/EXPORT/MD5/anon). Findings persist to a CBOM table
and become `KindCryptoAsset` nodes in the [credential graph](graph-query-ai.md), so crypto
posture flows into blast-radius and [compliance](policy-and-governance.md) reporting — and
into the [PQC migration](lifecycle-and-pqc.md) that consumes it. Scanning runs in its own
bounded lane and is non-fatal per source, keeps each tenant's data isolated at the
database layer, and keeps TLS/cert parsing behind the single crypto path.

**Status: served.** `POST /api/v1/cbom/scans` runs the scanner in the serving binary and
`GET /api/v1/cbom/assets` returns the tenant-scoped inventory plus migration progress.
The scan route requires `discovery:write`, accepts an `Idempotency-Key`, and records each
observation as an immutable `cbom.asset.observed` event before the read model is
projected. The read route requires `risk:read`. CBOM work has its own bulkhead, so a wide
TLS/config sweep rejects fast instead of starving the regular API or enrollment lanes.

Each returned asset includes the discovered algorithm, source, policy result, PQC
posture, and a **migration target**:

| Observation | Migration target |
|---|---|
| RSA, ECDSA, Ed25519/EdDSA certificate signatures | `ML-DSA-65` (`FIPS 204`) |
| DSA certificate signatures | `SLH-DSA-SHA2-128s` (`FIPS 205`) |
| TLS protocol/cipher findings such as TLS 1.0 or 3DES | `ML-KEM-768` (`FIPS 203`) |
| Already quantum-safe ML-DSA, ML-KEM, or SLH-DSA observations | marked post-quantum-ready |

`migration_progress` is computed from the stored inventory: total assets, how many are
already post-quantum-ready, how many are still quantum-vulnerable, and the ready
percentage. ELI5: the CBOM is the list of every lock type you found, and the migration
progress tells you how many locks are already the new quantum-safe kind.

### In the console

The overview dashboard surfaces a severity-ranked **alert center** projected from served
risk and certificate-expiry events, and the `/risk` screen renders a **risk-posture**
summary (counts by band, orphaned credentials, average composite score) above the
scored-credential grid. There is no dedicated alerts endpoint — the center is a projection
of events the backend already serves, and notification *channel* configuration and scheduled
digests are not served. See [The web console](../web-console.md).

## Use it

Risk scoring is live — find your riskiest credentials:

```sh
# the rotate-this-first list: high-privilege, score >= 50
trstctl-cli risk credentials --min_score 50 --privilege high --sort score

# usage-backed NHI over-privilege and least-privilege right-sizing
trstctl-cli nhi posture overprivilege

# stale, unused, orphaned, and dormant NHI posture
trstctl-cli nhi posture stale

# long-lived and static NHI credential posture
trstctl-cli nhi posture static-credentials
```

Those map to `GET /api/v1/risk/credentials?sort=score&min_score=50&privilege=high`
and the NHI posture routes under `/api/v1/nhi/posture/`.
CT monitoring and drift detection are driven through the served Discovery API:

```sh
# CT-log monitoring source: poll the log and alert on unexpected certificates.
trstctl-cli discovery sources create --body ct-log-source.json
trstctl-cli discovery runs start --body ct-log-run.json
trstctl-cli discovery findings list --run_id "$RUN_ID"
```

`ct-log-source.json` carries `kind: "ct_log"` and a config like:

```json
{
  "name": "public-ct-watch",
  "kind": "ct_log",
  "config": {
    "logs": ["https://ct.example.test/log"],
    "watched_domains": ["example.com"]
  }
}
```

Drift uses the same source/run/finding path:

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

The CBOM scanner is served by the API:

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

The response contains `items` and `migration_progress`. A non-empty
`quantum_vulnerable` count means you have crypto that needs a migration target.

## Pitfalls & limits

| Capability | Status today |
|---|---|
| Credential risk scoring (F19) | **Served** — `/api/v1/risk/credentials`, `/api/v1/nhi/posture/overprivilege`, `/api/v1/nhi/posture/stale`, `/api/v1/nhi/posture/static-credentials`, `risk` CLI, NHI posture CLI |
| CT monitoring (F17) | **Partially served** — Discovery `ct_log` source/run/finding execution plus outbox-backed alerts; dedicated CT dashboard/watchlist UI not served |
| Drift detection (F18) | **Partially served** — Discovery `drift` source/run/finding execution plus outbox-backed alerts; dedicated remediation UI not served |
| CBOM (F52) | **Served** — `/api/v1/cbom/scans`, `/api/v1/cbom/assets`, event-backed inventory + FIPS migration progress |

Other notes: CT monitoring depends on you listing the logs and domains to watch. Drift
permission detection is best-effort on platforms whose ACL model it can't fully read —
the agent tells you when that's the case rather than giving false assurance. The CBOM is
only as complete as the sources you point it at (TLS endpoints + config files). See
[Current limitations](../limitations.md) for the served-vs-library picture.

## Reference

- **Served:** `GET /api/v1/risk/credentials` (params `sort`, `min_score`, `privilege`,
  `owner`); CLI `risk credentials`.
- **Risk factors:** age, exposure, privilege, rotation staleness, owner activity,
  sensitivity (weighted; defaults favor exposure + privilege).
- **CT:** Discovery source kind `ct_log`; finding kind `ct_unexpected_issuance`;
  idempotency key `ct:<log>:<index>`; RFC 6962.
- **Drift:** Discovery source kind `drift`; finding kind `credential_drift`; drift types
  `Deleted`, `Replaced`, `Relocated`, `PermissionChanged`.
- **CBOM API:** `POST /api/v1/cbom/scans` (`discovery:write`, `Idempotency-Key`
  required); `GET /api/v1/cbom/assets` (`risk:read`).
- **CBOM policy floor:** RSA-2048, EC-256, TLS 1.2; bans 3DES/DES/RC4/NULL/EXPORT/MD5.
- **CBOM event/read model:** `cbom.asset.observed` projects into `crypto_assets`; rebuilds
  and snapshots replay the same inventory.

## See also

[Discovery & inventory](discovery-and-inventory.md) (what feeds these) ·
[Graph, query & AI](graph-query-ai.md) (exposure / blast radius) ·
[Lifecycle & PQC](lifecycle-and-pqc.md) (migrating off weak crypto the CBOM finds) ·
[Policy & governance](policy-and-governance.md) (compliance reporting) ·
glossary: [Certificate Transparency](../glossary.md), [drift](../glossary.md),
[CBOM](../glossary.md), [PQC](../glossary.md)

**Covers:** F17, F18, F19, F52
