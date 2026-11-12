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

The tenant audit feed can also deliver native Splunk HEC batches through the
outbox. The [Splunk app](../guides/splunk-app.md) packages two disabled correlation
searches over that stream: repeated renewal failures for one identity and a
certificate-revocation burst for one tenant. Counts deduplicate immutable audit
IDs. Configure the exact index, tenant and Splunk role permissions before enabling
them. The owned scaffold checks these query contracts; Splunk's search engine,
scheduler and RBAC remain unverified until tested in an authorized vendor runtime.

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
| `GET /api/v1/nhi/posture/exposure` | Which credentials are internet-exposed or insecurely deployed? | Sanitized endpoint/callback URLs, severity, evidence refs, remediation, and each record's latest live probe from a relay (`reachability`) |
| `GET /api/v1/nhi/posture/automation` | What will the tenant's `nhi_posture` rules do automatically? | Each rule match's action (revoke, right_size, report_only, not_applicable), the evaluated module digest, the latest automatic playbook run |

Grants with no usage evidence stay unclassified rather than counting as a finding; the
exposure route is read-only and never echoes credential values. For example,
`trstctl-cli nhi posture stale` reports each stale credential's activity age, owner
status, severity, and remediation.

**Usage from trstctl's own activity (M1).** API tokens and machine login methods carry
their recorded usage, so the stale posture needs no operator input for them. Every
authenticated API-token request is recorded with the client network it came from (the
connection's peer address as a /24 or /64; behind a load balancer listed in
`server.trusted_proxies`, the client it forwarded in `X-Forwarded-For`, read from the right;
a forwarded-for header from any other peer is not trusted) and
what it did (`api_call`, `secret_read`, `lease_request`): one `credential.used` event
per token, network, action and hour, plus one each time that hour's count doubles, up
to 1,024. Each machine login counts as a use of its login method by the workload it
attested. `?unused_days=N` (CLI `--unused-days`, 1-3650, default 90) flags a token or
login method with no recorded use for N days as `unused_no_activity`; a source not yet
used on three different days is `new_source` while the credential also has a normal
source, and the flag clears once it has been. Missing telemetry never counts as non-use:
nothing is unused before the first recorded use in the tenant, an expired token is not
idle, and a window in which uses could not be recorded (a full recorder queue or an
unavailable event log, recorded as `credential.usage_gap`) suspends the verdict. The
graph shows each token's `last_used_at` and `last_used_source`. Each stale finding for a
tracked credential carries its `usage`: when tracking began, its last use and where from,
and each source it was used from (newest first, at most 20) with the days seen and whether
it is still new; the console's Risk page shows it in the stale table's Usage column
(M1-L3). Usage is recorded from
the release that adds it; a full read-model rebuild also folds earlier machine logins.
Each token's hourly counts per network and action are kept for 30 days.

**Misuse detection (Enterprise governance, M2).** With the `governance` license feature,
the leader checks the last two hours of that usage every minute and raises two kinds of
finding: an API token requesting a dynamic-secret lease from a client network it has
not used on three different days while it has a network it has (`new_source_lease`),
and an hour in which a token's secret reads reach at least 64 and four times its largest
earlier hour in the last 14 days (`secret_read_burst`). Each finding is recorded as a
`misuse.finding.detected` event — one per token, rule and day, so repeats fold into it —
and raises one alert on the `notification.risk` route with its evidence (the token and
its subject, the network, the counts and the token's normal networks or baseline). A
tenant gets at most 20 such alerts an hour; findings beyond that are still recorded,
marked not alerted. The findings read model rebuilds from the event log, and a rebuild
never alerts again. `GET /api/v1/misuse/findings` (audit:read) lists the tenant's findings,
newest first and a page at a time (`limit` up to 200, `cursor` from the previous page),
optionally one `rule` or one token (`credential_id`), each with its token and subject,
network, hour, counts and whether it alerted; the Risk page's supporting details show
them as Token misuse findings, including those an alert budget held back.

What the exposure posture reads from metadata can be checked live:
`POST /api/v1/nhi/posture/exposure/probe` (`trstctl-cli nhi posture exposure probe`,
discovery:write) asks a network relay to connect to the exposed records' public
endpoints and callback URLs, up to 50 per probe. The relay connects only to public
addresses, refusing a name that resolves to a private or loopback one, and reports
what answered: a served TLS certificate, a listener without TLS, a non-public address or
no answer. The probe is a discovery run; the posture then shows each record's latest
result and the Risk page's exposure panel has a **Probe from a relay** button and a
**Live reachability** column. The control plane never dials the endpoints itself, and a
probe no network relay can claim is refused with `409` rather than left queued.

The cloud's own answer is the second check (A167). `POST
/api/v1/nhi/posture/exposure/attack-paths` (`trstctl-cli nhi posture exposure
attack-paths`, discovery:write) takes a `source_id` naming a
[cloud network paths](discovery-and-inventory.md#cloud-network-paths) source and asks
that AWS account whether its route tables, network ACLs and security groups admit the
internet to each exposed record's public addresses, that Google Cloud project whether
its VPC routes and firewall rules do, or that Azure subscription whether its network
security groups, route tables and public IPs do (A167-L1). The posture then carries an
`attack_path` per record — open through a named security group, firewall rule or
network security group, blocked at a named route table, route, network ACL, security
group, firewall rule, network, network security group or public IP (`blocked_by` says
which stage: `route`, `network_acl`, `network_acl_return`, `security_group`,
`firewall`, `network_security_group` or `public_ip`), not in the account, or unknown
with the reason — and
the exposure panel has a **Validate paths in the cloud** button and a **Cloud path**
column that shows the verdict with the reason beneath it; a schedule on the source
re-validates every exposed endpoint on its own (A167-L4). A probe says something
answered; the attack path says which resource lets it, or which one to change to stop
it. An open verdict is the account's own confirmation, so it also raises the record's
exposure finding (A167-L3): to at least high, to critical when the endpoint also
authenticates weakly, uses insecure transport or admits wildcard reachability, with the
`cloud_path_open` finding type, a risk score to match and a recommendation to close the
rule the Cloud path names. The posture automation's `nhi_posture` rules see the same
raised severity, risk and finding type. A blocked verdict lowers nothing, because paths
the provider adapters do not read yet (load balancers, NAT, gateways) may still reach
the endpoint.

A stale NHI can be handed to a new accountable owner with
`POST /api/v1/nhi/posture/stale/handoff` (`trstctl-cli nhi posture stale handoff`):
the ownership assignment, which the inventory honors for every source, so the row is no
longer orphaned, the previous owner kept in the response, and an `ownership.handoff`
notice to the new owner to reattest what is still in use and retire the rest.

These routes report; they do not act. Acting is opt-in through the tenant's lifecycle
policy module: an `nhi_posture` rule may ask the scheduler to revoke a managed identity
or right-size its usage-backed unused grants (CAP-POST-06, see
[policy and governance](policy-and-governance.md)). The automation route, `trstctl-cli
nhi posture automation` and the Risk page's **Automatic NHI posture actions** panel show
what each rule match will do and the last automatic run.

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

A watched entry can also be an IP address or a CIDR range, such as `203.0.113.0/24`. It
catches a logged certificate whose IP address names fall inside it, because a certificate
issued for an IP address carries no domain to match. An address is kept as itself, and a
range is kept as its network. A range that matches every address (`0.0.0.0/0`, `::/0`) is
refused. The finding's `ref` is the certificate's first DNS name, or its first IP address
when it has none. Its metadata lists `ip_addresses` beside `sans`, and `matched_domain`
names the entry it matched. The console's finding detail shows both.

**Status: served.** Use `GET`/`PUT /api/v1/discovery/ct-monitoring`, `discovery
ct-monitoring get|update`, or the console to configure watched domains/logs, inspect
checkpoints, queue a poll, and review `ct_unexpected_issuance` findings. The worker polls,
records tenant-scoped findings, and queues notifications via the outbox.
An unexpected issuance is a **critical** notification, matching the rogue-certificate
posture, so a severity-based routing rule can page the configured incident channel.

Before the console exposes **Save and run now**, it sends the proposed `ct_log` source to
`POST /api/v1/discovery/plans/preview`. The server uses the same CT validator as execution
and returns the normalized `domain:`, `ip:`, `range:` and `log:` targets, RFC 6962 protocol, child-job count,
concurrency, queue limit, permission, and public-metadata handling boundary. Preview is
effect-free: it does not contact a CT log or create a source, run, event, checkpoint,
finding, or alert. Editing any domain, log, or batch size invalidates the displayed review.

The latest CT run is included in a fresh `GET /api/v1/discovery/ct-monitoring` response, so
a failed or partial result remains visible after reload. Recovery first calls
`GET /api/v1/discovery/sources/{id}/preflight`, which revalidates the saved source without
queueing work. Only then does the console expose a retry. `POST
/api/v1/discovery/runs/{id}/retry` and `discovery runs retry` create a distinct replacement
with `retry_of_run_id`; they never rewrite the original failure. The receipt names both run
IDs, which makes the recovery easy to follow and keeps the original evidence auditable.

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
the read-only evidence view and links back to this one reviewed workflow; it cannot bypass
preview with a second direct-save form. It previously appeared on Discovery only as a single count shared
with drift detection, which is why operators could not find the capability at all.

**What it does not cover.** CT monitoring sees exactly the domains and IP addresses you
list and the logs you poll — nothing else. A domain or address you have not added, or a log
you do not configure,
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
Drift alerts include the detected change type and a non-secret cause. Missing,
replaced, or permission-changed credentials are **critical**; relocated content is
**warning**. Routing policy can send those levels to different incident channels.

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
The recovery card follows the monitoring projection's exact latest run ID for each
drift source. It fetches that run by ID when it is outside the first history page;
if the exact readback is unavailable or disagrees with monitoring, recovery is
withheld until the operator can refresh a trustworthy view.

### The CBOM — cryptographic bill of materials (F52)

You can't plan a crypto migration without knowing what crypto you run. The CBOM scanner
inventories cryptographic usage across TLS endpoints and host config files (nginx,
Apache and sshd directives; HAProxy, Envoy, the OpenSSL configuration file and
`java.security` since X2, each reporting the lowest protocol a statement explicitly
allows, never a product default), then
classifies each observation: algorithm family and strength, whether it's
[quantum-vulnerable](../glossary.md), and whether it meets policy (default floor:
RSA-2048, EC-256, TLS 1.2; bans 3DES/DES/RC4/NULL/EXPORT/MD5/anon). Findings become
`KindCryptoAsset` nodes in the [credential graph](graph-query-ai.md), feeding
blast-radius and [compliance](policy-and-governance.md) reporting and the
[PQC migration](lifecycle-and-pqc.md). Scanning runs in its own bounded lane, is
non-fatal per source, tenant-isolated at the database layer, and keeps TLS/cert parsing
behind the single crypto path.

**Status: served.** `POST /api/v1/cbom/scans/preview` (`discovery:write`) is an
effect-free review of the same plan execution uses. It trims, sorts, and deduplicates
the inputs; turns friendly HTTPS origins and bare hosts into exact `host:port` targets;
and returns the connection, file-read, worker, queue, timeout, and durable-write
ceilings. It makes no connection, file read, event append, projection write, signer
call, or outbox call.

`POST /api/v1/cbom/scans` (`discovery:write`, accepts an `Idempotency-Key`) rebuilds
that plan, then runs it in the serving binary. One request accepts at most 64 TLS
targets and 64 absolute file/glob selectors. TLS discovery performs a default handshake
and, when it negotiates TLS 1.3, a second handshake capped at TLS 1.2. Both share
a ten-second endpoint deadline and send no application data. A successful capped
handshake records the lower protocol separately; a refusal does not invent a finding. Host discovery reads
at most 256 matching files and 1 MiB per file, returns no file contents, and the scan
can append/project no more than 1,024 findings per source. Every successful observation
is first recorded as an immutable `cbom.asset.observed` event. After a complete
scan, a `cbom.source.reconciled` event for each observed file and TLS endpoint
retires older facts no longer present at that exact location. Retired rows remain
in the projection for audit and replay but disappear from current inventory.
Partial input or write failures remain visible in `report.failed`; they retain
prior facts so a failed probe cannot falsely clear a risk. `GET /api/v1/cbom/assets`
(`risk:read`) returns the current tenant-scoped inventory and migration progress.
The four-worker, 64-slot CBOM bulkhead prevents a wide sweep from starving API or
enrollment work.

The same inventory exports as a CycloneDX 1.6 CBOM that scanners and agencies can
ingest: `GET /api/v1/cbom/export/cyclonedx` (`risk:read`), `trstctl-cli cbom
export-cyclonedx`, or **Download CycloneDX CBOM** under the crypto inventory in Posture.
Each inventory asset is one `cryptographic-asset` component whose `bom-ref` is the
asset ID: a certificate key as an algorithm (for example `RSA-2048` with its parameter
set, or `ECDSA-P256` with its curve, the OID, and the classical and NIST quantum
security levels where they are known), a TLS endpoint or declared host protocol as a
protocol with its version, and a declared cipher as a TLS cipher suite. Each carries
where it was observed (`evidence.occurrences`) and the inventory's classification as
`trstctl:` properties. The document states its coverage in its metadata, marks its
composition `incomplete` (it lists what trstctl observed, never the whole estate), and
claims no compliance: choosing an algorithm does not make a deployment compliant.

Beside the inventory's assets the export carries what trstctl knows about them and what
agents report (Q3-L2). Each certificate the certificate inventory holds for an inventory
certificate key is a `certificate` component (subject, issuer, validity, format X.509)
whose `subjectPublicKeyRef` is that key's component. Each key a host agent found in a
keystore or key file is `related-crypto-material` — a `private-key` with its size and
container format (PKCS12, JKS, PEM), or `secret-key` for a store of secret keys only —
and never carries key bytes. Each crypto library a host agent identified is a `library`
component with its version and whether it can negotiate X25519MLKEM768. Each TLS or SSH
handshake an observer saw is a protocol with its version, cipher suite and key exchange
group. Agent and observer classes take the newest finding of each location, at most
10,000 a class; the metadata counts each class and names a class cut at that bound
(`trstctl:coverage:cut_at`).

The response carries the BOM, its SHA-256, a compact JWS over the exact BOM bytes from
the audit evidence key, and the public keys. Verify a saved export offline against the
keys you pinned from `trstctl-cli audit verification-keys`:

```bash
trstctl-cli cbom export-cyclonedx > cbom-export.json
trstctl-cli cbom verify-cyclonedx --export cbom-export.json --audit-jwks audit.jwks.json --bom-out cbom.cdx.json
```

#### Importing CBOMs from vendors, code and images

`POST /api/v1/cbom/imports?source=<source>` (`discovery:write`, `trstctl-cli cbom import
--source <source> -f bom.cdx.json`) takes a CycloneDX 1.4–1.7 CBOM into the same inventory.
The source says who produced it and is part of every location: `vendor:<product>` for a
CBOM a vendor published for its appliance or software, `source:<repository>` for a scan of
code, `image:<reference>` for a scan of a container image, directory or archive. Each
cryptographic asset (algorithm, certificate, key or other crypto material, protocol with
its cipher suites) and each crypto library component (OpenSSL, BoringSSL, Bouncy Castle and
others) becomes one inventory finding located at `<source>:<occurrence>` (the file and line
the BOM gives, or the component's reference), classified like trstctl's own scans: a
1024-bit RSA key is weak, TLS 1.0 is weak, ECDH is quantum-vulnerable. The BOM's
dependency graph is read too (X6-L5): an algorithm, protocol, key or certificate that a
library component `provides` is listed under that library (`openssl 1.1.1w`) instead of
the source, so a weak algorithm points at the library to upgrade; a key or certificate
whose own properties name no algorithm takes it from what it `dependsOn` (an algorithm,
or the algorithm of a key it depends on), and a certificate with no issuer name takes
the subject of a certificate it depends on. A reference into another BOM (`urn:cdx:`
BOM-Link) is not followed. A document that is
not a CycloneDX BOM, or holds no crypto, is refused; one import takes at most 50,000
components and 32 MiB.

Each import is a discovery run keyed by the source and the BOM's serial number and
version (its SHA-256 when it has no serial number). Importing the same BOM again returns
the first import's result with `replayed: true` and writes nothing; a new version of the
BOM is a new import. Every finding is recorded as `cbom.asset.observed` first.

An import also retires what its source no longer lists (X6-L3). Once every finding of the
BOM is recorded, `cbom.import.reconciled` marks the source's rows that earlier imports
recorded and this BOM does not list as inactive: a vendor's newer BOM that drops TLS 1.0
takes TLS 1.0 out of the inventory. The response names those rows as `retired_asset_ids`,
and the Posture page's import says how many; the rows and their events stay for audit, and
a later import that lists one again brings it back. A source is exact: importing
`vendor:acme` never retires `vendor:acme:fw`'s rows, and a row imported before imports named
their source counts as its source's by location. A BOM whose serial number the source
already imported at a later version is refused (409), because taking in the earlier
revision would retire what the later one added; a BOM with another serial number, or none,
is the source's newest. The same BOM again still replays and retires nothing. Certificates
an import put in the certificate inventory stay there under the inventory's own lifecycle.

Discovery coverage counts imports: `vendor-embedded-crypto`, `source-code-crypto` and
`container-image-crypto` are observed while an import of that kind is recent (90 days for
a vendor's CBOM, which describes a release; the ordinary window for code and images).

A certificate component that names its SHA-256 fingerprint — in its `hashes` (CycloneDX
1.6) or in its certificate properties' `fingerprint` (1.7) — also enters the certificate
inventory (`GET /api/v1/certificates`) with the subject, issuer, serial number, key
algorithm and validity the BOM states, source `cbom:<source>`, and no certificate bytes
(X6-L6). The inventory's expiry queries (`trstctl-cli certificates list --expiring-before`,
`certificates health`) and reports then see a vendor's certificates. A fingerprint the
inventory already holds keeps its row as it is: an issued or ingested certificate's owner,
names and location are not replaced by a BOM's statement about it. A certificate the BOM
gives no fingerprint for, such as each entry of an image's CA bundle in an image scanner's
CBOM, stays a CBOM row. The import's response lists the certificate rows as
`certificate_ids`, and the Posture page's import says how many there are.

Two commands produce a CBOM to import on your own machine, offline; neither sends
anything:

```bash
# Code: Go through its syntax tree, Java's JCA calls and Python's cryptography package.
# RSA with its key size, ECDH and ECDSA curves, DSA, 3DES, RC4, MD5 and SHA-1, each with
# its file and line; vendored and generated directories are skipped.
trstctl-cli cbom scan-source ./payments --out payments.cdx.json
trstctl-cli cbom import --source source:payments -f payments.cdx.json

# Images, directories and archives: runs the CBOM scanner you installed (cbomkit-theia),
# passing the arguments after -- unchanged, and keeps its output only when it is a CBOM
# with crypto in it. trstctl never downloads the scanner.
trstctl-cli cbom scan-image --scanner /usr/local/bin/cbomkit-theia --out app.cdx.json -- image registry.example/app:1.4
trstctl-cli cbom import --source image:registry.example/app:1.4 -f app.cdx.json
```

The source scan reads a key size or curve wherever it can be worked out without running
the code (X6-L2). In Go it follows a package's constants and constant expressions
(`const legacyBits = 1024`, `bits * 3`, `1 << 12`), variables assigned once and never
again — in the package or in the function — across the package's files, and a curve held
in a variable (`curve := elliptic.P384()`); and it follows one level of wrapper: a
function of the same package that hands its own parameter to `rsa.GenerateKey` or
`ecdsa.GenerateKey` is reported again at each call in the package that passes a size or
curve it can read (`newRSA(1024)`), with the call's file and line. In Java and Python a
key size given as a name (`initialize(KEY_SIZE)`, `key_size=KEY_BITS`) resolves to the
number the file assigns it once. A name assigned more than once, a struct field, a value
read from configuration or a deeper chain of wrappers is not resolved, and the use is
reported without a size.

To import on every pipeline run, use the CI templates in `deploy/ci` (X6-L7): a reusable
GitHub Actions workflow and a GitLab CI job that install `trstctl-cli` from a published
release (checksums and source commit verified), run `cbom scan-source` and import the
result as `source:<repository>`, with an API token that carries only `discovery:write`.

Imported findings are what the BOM says. trstctl does not re-check a vendor's claims or
the image scanner's results, and the source scan finds calls it recognizes, not every
path by which code reaches cryptography; the location names the source so a reader knows
whose statement each row is.

The scan response includes `observed_asset_ids`: stable IDs for findings that this
run appended and projected. Read those exact IDs back through `GET
/api/v1/cbom/assets` before claiming durable evidence. The console does this check;
older inventory rows cannot make a new scan appear successful. A scan with zero
findings is shown as inconclusive with recovery guidance, even when the tenant has
older assets. Host-config parsing supports NGINX `ssl_protocols` and Apache
`SSLProtocol`, including ordered `+` and `-` modifiers and the `all` macro. An
Apache `all` declaration describes the maximum allowed by the config; the linked
OpenSSL build can support fewer versions, so scan the live TLS endpoint to verify
what clients can actually negotiate. The capped probe detects a TLS 1.2 compatibility
path that a normal TLS 1.3 handshake would hide.

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
license. From `/posture`, `/api/v1/pqc/campaigns`, or `trstctl-cli pqc campaigns`, an
operator can assign owner/deadline/wave/readiness, record a manual or third-party
remediation for each finding, and close only after every finding has evidence. Closure
produces an offline-verifiable signed artifact. The reviewed migration executor is
also in core; it can issue a replacement, while deployment and endpoint readback
remain separate evidence. Campaign tracking does not start the executor implicitly.

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

# probe the exposed records' public endpoints live from a network relay
trstctl-cli nhi posture exposure probe -f nhi-exposure-probe.json --force
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
  "watched_domains": ["example.com", "203.0.113.0/24"],
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
# First review the exact normalized scope and safety ceilings. This POST is read-only:
# do not send an Idempotency-Key.
curl -sS \
  -H "Authorization: Bearer $TRSTCTL_TOKEN" \
  -H "Content-Type: application/json" \
  -X POST https://trstctl.example.com/api/v1/cbom/scans/preview \
  -d '{
    "tls_endpoints": ["https://payments.internal.example"],
    "host_configs": ["/etc/nginx/sites-enabled/payments.conf"]
  }'

# Run the reviewed scope. Execution requires an Idempotency-Key.
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
- **CBOM API:** `POST /api/v1/cbom/scans/preview` (`discovery:write`, effect-free),
  `POST /api/v1/cbom/scans` (`discovery:write`, `Idempotency-Key` required), and
  `GET /api/v1/cbom/assets` (`risk:read`).
- **CBOM policy floor:** RSA-2048, EC-256, TLS 1.2; bans 3DES/DES/RC4/NULL/EXPORT/MD5.
- **CBOM event/read model:** `cbom.asset.observed` and
  `cbom.source.reconciled` project into `crypto_assets`; rebuilds/snapshots
  replay the same active inventory and retained tombstones.

## See also

[Discovery & inventory](discovery-and-inventory.md) (what feeds these) ·
[Graph, query & AI](graph-query-ai.md) (exposure / blast radius) ·
[Lifecycle & PQC](lifecycle-and-pqc.md) (migrating off weak crypto the CBOM finds) ·
[Policy & governance](policy-and-governance.md) (compliance reporting) ·
glossary: [Certificate Transparency](../glossary.md), [drift](../glossary.md),
[CBOM](../glossary.md), [PQC](../glossary.md)

**Covers:** F17, F18, F19, F52

For algorithms unsupported by the Go TLS client, the deployment operator can
configure [native TLS discovery](../configuration.md#native-tls-discovery-for-cryptographic-inventory).
Its preview includes up to two connections per endpoint under the same deadline.
Certificate inspection failures count as partial failures; a completed handshake
alone is insufficient to claim a complete certificate inventory.
