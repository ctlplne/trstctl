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

## Use it

Risk scoring is live — find your riskiest credentials:

```sh
# the rotate-this-first list: high-privilege, score >= 50
trstctl-cli risk credentials --min_score 50 --privilege high --sort score
```

That maps to `GET /api/v1/risk/credentials?sort=score&min_score=50&privilege=high`. The
CT monitor, drift detector, and CBOM scanner are driven through their Go APIs today —
e.g. `monitor.PollAll(ctx, tenant, logs)` to sweep CT logs, or `scanner.Scan(ctx, sources)`
to build a CBOM from your TLS endpoints and config files.

## Pitfalls & limits

| Capability | Status today |
|---|---|
| Credential risk scoring (F19) | **Served** — `/api/v1/risk/credentials`, `risk` CLI |
| CT monitoring (F17) | **Library-complete**, tested (incl. outbox-backed alerts); no scheduler wired |
| Drift detection (F18) | **Library-complete**, tested; agent loop not yet wired |
| CBOM (F52) | **Library-complete**, tested; store + graph wired, no scan trigger yet |

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
- **CT:** `Monitor.Poll` / `PollAll`; idempotency key `ct:<log>:<index>`; RFC 6962.
- **Drift types:** `Deleted`, `Replaced`, `Relocated`, `PermissionChanged`.
- **CBOM policy floor:** RSA-2048, EC-256, TLS 1.2; bans 3DES/DES/RC4/NULL/EXPORT/MD5.

## See also

[Discovery & inventory](discovery-and-inventory.md) (what feeds these) ·
[Graph, query & AI](graph-query-ai.md) (exposure / blast radius) ·
[Lifecycle & PQC](lifecycle-and-pqc.md) (migrating off weak crypto the CBOM finds) ·
[Policy & governance](policy-and-governance.md) (compliance reporting) ·
glossary: [Certificate Transparency](../glossary.md), [drift](../glossary.md),
[CBOM](../glossary.md), [PQC](../glossary.md)

**Covers:** F17, F18, F19, F52
