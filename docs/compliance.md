# Audit trail & compliance

trstctl's audit trail is a projection of the event log: every
state-changing operation is recorded as an immutable event, and audit
query/export endpoints derive their views from it. This page describes
what the audit subsystem gives you — and what it does not: trstctl
provides controls and evidence; **certification is yours to obtain with
your auditor**. Nothing here claims that deploying trstctl makes you
compliant.

Plain signed history export and offline verification are available in every
edition. Enterprise audit compliance adds timestamp anchoring, audit retention,
and framework evidence packaging; Provider inherits these capabilities. Removing
a license stops new retention runs and timestamp anchoring, while existing signed
archives, checkpoint recovery, and export of your own history remain available.
Non-audit privacy retention is independent and stays in the core.

## What the audit subsystem provides

- Completeness. Every served mutation is an event, reconstructing the full
  history of owners, issuers, identities, issuance, and revocation; the
  read model projects the same events.
- Attribution. Each event carries the authenticated actor (subject and
  role) from the verified principal (token or OIDC session, R1.2), plus
  event time and tenant — who did what, when, under what authorization.
- Tamper-evidence. Records are hash-linked: altering, dropping, inserting,
  or reordering any one changes its hash and every hash after it;
  chain-verification detects it and names the first broken record.
- Signed, offline-verifiable evidence export. `GET /api/v1/audit/export`
  returns a compact JWS bundle (records + chain head) signed with a
  persistent key, verifiable even after a restart.
- Signed framework evidence packs. `GET
  /api/v1/compliance/evidence-packs/{framework}` turns the audit log and
  tenant graph into a signed report across 15 frameworks (full list in
  [Framework evidence packs](#framework-evidence-packs) below). Each report
  evaluates one explicit 90-day window; it does not treat “some audit data
  exists” as proof of an unrelated control.
- Compliance inventory reporting and signed scheduled reports. `GET
  /api/v1/compliance/inventory-report`, effect-free `POST
  /api/v1/compliance/report-schedules/preview`, and the create/list/pause/resume
  schedule routes expose supported frameworks, report types, evidence references,
  exact-draft review, and idempotent event-sourced recovery. Run receipts and
  exact signed artifacts are available under `/api/v1/compliance/report-runs`.
- Tenant isolation. Every audit query is tenant-scoped.

## The tamper-evidence trust model (read this)

The event log lives in NATS JetStream with append-only file storage.
trstctl also maintains an application-level hash chain over the audit
records and publishes the chain head inside each signed export — the
*anchor*: an export at time T attests to the exact records and head at T,
and any later alteration of the log produces a different head that no
longer matches the signed bundle.

This **does** detect alteration, truncation, insertion, or reordering
relative to a previously signed bundle, and any in-place edit of one (the
signature fails). With Enterprise audit compliance licensed and `protocols.tsa` enabled, the saved JWS envelope and every
record-stream trailer also carry the complete RFC 3161 token over that exact
head. Offline verification takes the separately pinned audit JWK set and TSA root,
recomputes the record chain, checks the timestamp token, and applies the chosen
maximum delay from newest record to authority time.

**Continuous anchoring.** On the same license with the TSA served, the leader
also timestamps each tenant's full audit chain at a known cadence
(`audit.anchor_interval`, hourly by default; `0s` turns it off) whenever the
tenant's log has grown, and appends the timestamp to that tenant's own log as an
`audit.anchored` record, which the next anchor then covers. An export of an
unbroken run of records (no content filter) carries those anchors, and offline
verification with `--tsa-root` re-checks each one: its timestamp against the
pinned root, its chain head against the export's own chain, and the order of
records around it — a record that entered the chain after an anchor it predates
was withheld or back-dated. With `--anchor-cadence 1h` it also requires every
record to be covered by an anchor within an hour of its time. What this cannot
catch is a record withheld for less than one cadence plus the clock tolerance
(`--anchor-skew`, five minutes by default); and an anchor taken before a subject
erasure that changed the records it covers is reported as superseded by that
erasure rather than verified. `GET /api/v1/audit/anchors` (`trstctl-cli audit
anchors`, Audit console) shows the cadence, the state and the tenant's recent
anchors.

**TSA revocation.** The TSA's certificates are entries of the issuing CA's ledger,
so its CRL and OCSP responder answer for them, and an operator rotates the TSA
onto a fresh key (`trstctl-cli protocols tsa certificates rotate`), revoking the
outgoing certificate when it can no longer be trusted. Every export carries the
CA's OCSP answer for each TSA certificate its timestamps rely on, and offline
verification checks it against the pinned root: a certificate revoked for key or
CA compromise refuses every timestamp it signed; one revoked for another reason
refuses only the timestamps at or after its revocation. Bring a current CRL with
`--tsa-crl` to see revocations recorded after the export, and use
`--require-tsa-revocation` to refuse any certificate whose status cannot be
established.

**Anchor log.** The anchors are also kept, per tenant and in order, in an
RFC 6962 Merkle log. Every export carries a head of that log signed with the
audit export key and an inclusion proof for each anchor record it holds; with
`--audit-jwks` the verifier checks them, so an anchor cut from between two that
an export holds is caught. Keep the receipt's `anchor_log.signed_head`: a later
export taken with `anchor_log_from=<its tree_size>` and verified with
`--previous-anchor-log` proves the log only grew in between, so anchors you
already saw cannot have been rewritten. The head is the deployment's own
statement; comparing heads across time (or across auditors) is what detects a
split view. Hardware-notary checkpoints remain a separate roadmap control.

The shipped workflow is `trstctl-cli audit verification-keys` while connected,
followed by `trstctl-cli audit verify --artifact <saved-file> --audit-jwks
<pinned.jwks.json> --tsa-root <pinned-root.pem> --max-anchor-delay <duration>` in
the offline environment. The JWK flag is required for JWS and unnecessary for the
four record-stream shapes; the independently pinned TSA issuer root is required
for every anchored shape. See
[CLI: Verify audit exports offline](cli.md#verify-audit-exports-offline).

## Framework evidence packs

An auditor or operator with `audit:read` can export a framework pack
through the API or CLI:

```sh
trstctl-cli compliance evidence-pack soc2
curl -fsS -H "Authorization: Bearer $TRSTCTL_TOKEN" \
  "$TRSTCTL_SERVER/api/v1/compliance/evidence-packs/soc2"
```

Use `pci-dss`, `hipaa`, `soc2`, `nist-800-53`, `nist-csf-2.0`, `fedramp`,
`cmmc-2.0`, `cnsa-2.0`, `fips-140`, `common-criteria`, `cabf-br`, `webtrust`,
`etsi`, `eidas`, or `nis2` as the framework path value. The JSON response
has seven stable fields:

| Field | Meaning |
| --- | --- |
| `format` | Wire marker: `trstctl.compliance.evidence-pack.v5`; v5 adds canonical crypto-readiness workflow/export evidence while retaining v4 AD CS posture/drift and v3 certificate custody. |
| `framework` | The normalized framework id used to build the report. |
| `signed_export` | A signed envelope whose manifest binds `tenant_id`, `generated_at`, the inclusive `evidence_window`, per-control verdicts/windows, exact evidence references, missing prerequisites, CBOM crypto posture, and operator-attestation gaps. |
| `public_key_der` | PKIX DER public key bytes for offline verification. |
| `custody` | Convenience copy of the tenant certificate-custody summary. The authoritative copy is `signed_export.manifest.custody`; offline verification must verify that manifest before trusting any count or row. |
| `adcs` | Convenience copy of the latest complete per-domain AD CS v2 observations and bounded semantic drift. The authoritative copy is `signed_export.manifest.adcs`; each row carries its immutable audit reference. |
| `crypto_readiness` | Convenience copy of the canonical ordered graph-readiness dataset, bound actions, evidence references, recommendations, coverage wording, and `dataset_digest`. The authoritative copy is `signed_export.manifest.crypto_readiness`. |

The shipped control plane binds a separate `compliance-evidence` key in the
isolated signer's persistent keystore. Its private key does not enter the control
plane, and restarting either process retains the same public verification key.
Back up the signer keystore and KEK together. Pin the public key through an
authenticated, independent channel before accepting an offline pack; the
`public_key_der` supplied alongside a pack identifies its signing key but is
not, by itself, an independent trust anchor. Packs made by older builds with
process-local governance keys keep their original verification key only in
copies saved before that process stopped; the new persistent key cannot
retroactively sign them.

The v4 manifest is derived from tenant-scoped facts, not static product
capability labels. An audit-event reference contains the immutable event ID,
tenant-local sequence, event type, observation time, and audit-chain digest;
current inventory references name the exact tenant graph object and snapshot
time. A control is `evidenced` only when every named prerequisite resolves in
the signed window. Missing, stale, malformed, or wrong-tenant input becomes an
explicit `gap` with `missing` prerequisites. The signature authenticates these
bounded claims; it does not prove that an external auditor agrees with their
sufficiency.

`adcs` includes the exact normalized templates, enrollment services, configured
IIS endpoint observations, CA restriction states, and rule findings that the
Posture console serves. Only v2 observations containing the service-evidence
field qualify; historical template-only v1 events stay audit history rather
than being presented as complete posture. Before signing, findings are
recomputed from the event facts. The latest complete observation per domain and
every source/run/relay-bound v2 drift event in the 90-day window carry event ID,
type, tenant-local sequence, chain digest, and observation time. The convenience
copy is for rendering; offline users verify `signed_export.manifest.adcs`.

`custody` counts every tenant certificate by origin, storage class, and
exportability. `recorded` means all required custody facts are present;
`unrecorded` includes both wholly empty and partially recorded legacy rows. Every
unrecorded row is listed under `unrecorded_certificates` with its certificate ID,
fingerprint, subject, and exact `missing_fields`. A total can therefore never hide
which certificate needs remediation. These bytes are inside the signed manifest:
changing a count, deleting a gap row, or changing a storage locus invalidates the
export signature.

The manifest also includes CBOM-derived post-quantum and quantum-vulnerable
counts. Its `crypto_readiness` member is built from the same graph rows and
event-projected actions served to API, CBOM/Posture, Risk, and CSV/NDJSON export;
matching `dataset_digest` values prove those consumers saw the same ordered facts.
It carries the discovery coverage limitation, so zero observed dependents cannot be
misread as safe. The report separates what trstctl can prove from what your organization must
still attest:

- `soc2` marks CC6 only with a current credential inventory, complete ownership,
  and a completed access-review campaign; CC7 requires policy-decision,
  credential-lifecycle, and monitoring/incident events; CC8 requires an active
  authored policy, an approved change with distinct approver evidence, and a
  credential-lifecycle event. Trust-services scope, management assertion, and
  the CPA examination remain operator/auditor work — not a certification claim.
- `nist-800-53`, `nist-csf-2.0`, `fedramp`, `cmmc-2.0`, `eidas`, and `nis2`
  bind audit evidence, NHI inventory, and posture (least-privilege,
  stale/orphaned, static-credential, CBOM) to framework controls, leaving
  system boundary, authorization packages, CUI scope, and assessor
  decisions as operator/auditor attestations.
- `fips-140` marks a runtime POST only when the active process reports an active
  FIPS module and a passed self-test. The signed build provenance, crypto-boundary
  artifact, NIST CMVP certificate, and approved deployment configuration remain
  gaps unless separately supplied as exact evidence. Tenant custody validation
  and approved-algorithm inventory are evaluated independently.
- `common-criteria` maps attributable active-policy, approved-change, and
  credential-lifecycle facts while keeping the security target, evaluated TOE
  boundary, lab report, certificate, and protection profile as explicit gaps.
- `cabf-br` requires exact profile decision, CA issuance/revocation, tenant
  custody, and authority-ceremony events; it leaves
  CP/CPS publication and independent public-trust audit as
  operator/external-auditor work.
- `webtrust` and `etsi` add broader CA-audit posture, keeping the WebTrust
  opinion and ETSI conformity assessment as external residuals — trstctl
  serves the evidence pack; it does not self-award the certification.

## Compliance inventory report and signed schedules

An auditor or operator with `audit:read` can read the served reporting
coverage:

```sh
trstctl-cli compliance inventory-report
curl -fsS -H "Authorization: Bearer $TRSTCTL_TOKEN" \
  "$TRSTCTL_SERVER/api/v1/compliance/inventory-report"
```

The response is intentionally mechanical: framework ids, report types
(`framework_evidence_pack`, `inventory_snapshot`, `cbom_posture`,
`audit_summary`, `nhi_compliance_mapping`, `crypto_risk`, `customer_assurance`), served routes, evidence
references, inventory counts, and the first page of tenant report schedules.

Before enabling a schedule, set `audit.archive_dir` (or
`TRSTCTL_AUDIT_ARCHIVE_DIR`) to a durable, mounted 0700 directory writable by
the control plane, or set `audit.archive_object_store` (or
`TRSTCTL_AUDIT_ARCHIVE_OBJECT_STORE`) with an [object store](configuration.md#object-store).
The licensed governance signer must be attached. Preview returns `ready=false`
with blockers if either prerequisite is absent; create and resume return 503.
In the directory, the `reports/` subtree holds the tenant-scoped signed
artifacts; in the object store each one is created once under the tenant's
prefix (`tenant/<tenant-id>/reports/<run>/<sha256>.json`), and the run records
that object as its reference, so a download reads exactly the bytes the run
pinned. Artifacts can include inventory and audit metadata. Back up the
directory with the event log and PostgreSQL, or apply the bucket's own
replication and retention; access, retention and erasure of report artifacts
remain operator responsibilities, and an event-log backup alone is not a report
backup.

An operator with `audit:write` first reviews the exact definition and then records it.
Review returns a tenant-bound SHA-256 fingerprint, normalized definition, later writes,
recovery steps, and verification steps. It appends no event, projects no row, generates
no report, resolves no credential, and calls no destination. Creation is a
tenant-scoped, idempotent event. The leader later archives a signed artifact
for each due edge. Unless the schedule names a `dispatch` (see the
[customer assurance report](#customer-assurance-report)), it sends no email,
webhook, or ticket:

```sh
cat > soc2-schedule.json <<'JSON'
{"framework":"soc2","name":"weekly-soc2-pack","report_type":"framework_evidence_pack","interval_seconds":604800,"delivery":"audit_export","recipient_ref":"weekly-soc2"}
JSON
trstctl-cli compliance report-schedules preview -f soc2-schedule.json
trstctl-cli --idempotency-key weekly-soc2 compliance report-schedules create -f soc2-schedule.json
trstctl-cli compliance report-schedules list
trstctl-cli compliance report-schedules runs SCHEDULE_ID
trstctl-cli compliance report-runs get RUN_ID
trstctl-cli compliance report-runs download RUN_ID > signed-report.json
```

`delivery` is `audit_export` only; any other value is rejected, so an
unserved email/webhook delivery can never look like a category met. Cadence is bounded
to one hour through 366 days, preventing a malformed definition from becoming a tight
unbounded loop. The console intentionally accepts whole days from one through 366;
API and CLI automation may use the finer one-hour minimum.
`recipient_ref` is an optional non-secret correlation label in the schedule;
it does not route the report or override `audit.archive_dir`.

The worker checks due schedules every minute, bounds each sweep to 100
attempts and each tenant to five, and locks the exact due edge in PostgreSQL.
Each receipt is `queued`, `retrying`, `failed`, or `completed`; failures retry
with bounded backoff and stop after five attempts. A completed receipt pins
the signed artifact's SHA-256 digest. The download returns the exact signed
bytes. Verify its embedded signature and compare the file's SHA-256 to
`artifact_digest` in the run receipt. Run reads need `audit:read`; a failed
run can be requeued with `audit:write`:

If the receipt says `signer_unavailable`, restore the isolated signer and
confirm the control-plane health endpoint before requeuing. Other failure
codes require checking signer and private archive health for the named code;
requeue only after the dependency is healthy, then verify the signed download.
The run ID and due edge stay the same across requeue, and its retry generation
advances so an operator can distinguish recovery from the original attempts.

```sh
trstctl-cli --idempotency-key retry-soc2-run-1 compliance report-runs requeue RUN_ID
```

Recovery preserves evidence instead of erasing history:

```sh
trstctl-cli --idempotency-key pause-weekly-soc2 \
  compliance report-schedules pause SCHEDULE_ID
trstctl-cli --idempotency-key resume-weekly-soc2 \
  compliance report-schedules resume SCHEDULE_ID
```

Pause writes a new immutable configuration event with `enabled=false`; it does not
delete the definition or prior evidence. Resume writes `enabled=true` and calculates a
fresh full interval. Read the schedule list and inventory report after either action to
verify both the exact row and the aggregate enabled-schedule count.
The console marks an enabled schedule **Overdue** when the server's latest inventory
report was generated after its `next_run_at`. This is a missed deadline signal;
open **Signed runs** for the receipt and artifact. A completed receipt means
the signed artifact is archived locally, not delivered to a third party.

## Customer assurance report

The customer assurance report (`customer_assurance`) is one tenant's account of
its credentials over a period, in plain sentences and in the tenant's
white-label brand, for a Provider (or the tenant's own team) to hand to the
customer. It covers:

- **Inventory and ownership**: active certificates, how many have a named
  owner (coverage is rounded down), cryptographic assets and discovery
  inventory records, and up to ten unowned certificates, soonest expiry first.
- **Expiring, renewed and failed credentials**: certificates that expire within
  30 days (the ten soonest, with owners), expired certificates still active,
  certificates renewed, added and revoked in the period, and the renewal runs
  and connector deliveries that failed in it (the ten newest, with reasons).
- **Verification**: deliveries verified in the period; the latest observation
  of each endpoint from each vantage (serving the expected certificate, a
  different one, or not reached); and, for the credentials whose lifecycle
  changed in the period (at most 50), how many were seen served from outside
  the product's own record, are known only from that record, or were not
  verified, read from their [assurance records](features/discovery-and-inventory.md).
- **Incidents**: credential-compromise and issuer-compromise runs open or
  updated in the period, each with its signed evidence bundle. A bundle over
  64 KiB is named by its SHA-256 digest instead.
- **Changes**: every figure compared with the previous report.
- **Limits**: what the report does not establish.

The report carries a short summary in sentences and a self-contained HTML
rendering: styles inline, the logo embedded, nothing fetched. The rendering
uses the tenant's brand: its product name, its logo when that is a PNG, JPEG,
GIF or WebP data URI of at most 256 KiB (SVG is never embedded), its
`token_overrides.accent` color when that is `#rgb` or `#rrggbb`, and its email
footer. It never names trstctl. A tenant without a white-label brand gets the
built-in one. Machine-readable format identifiers keep their schema names.

On demand, an operator with `audit:read` reads the report for the days ending
now (1 to 366, default 30), compared with the newest completed scheduled one:

```sh
trstctl-cli reports assurance --days 30
```

Scheduled, each run covers the interval before its due edge and is compared
with the schedule's previous completed run, which is read back from the
archive and verified first. Add `dispatch` to announce each completed run on
the tenant's notification channels or in a ServiceNow ticket; the notice names
the run, its SHA-256 and its download route, never the report body:

```sh
cat > assurance-schedule.json <<'JSON'
{"framework":"soc2","name":"monthly-assurance","report_type":"customer_assurance","interval_seconds":2592000,"delivery":"audit_export","dispatch":{"channels":["webhook"]}}
JSON
trstctl-cli --idempotency-key monthly-assurance compliance report-schedules create -f assurance-schedule.json
```

### Verify a saved report offline

Every scheduled run is signed by the governance report key. Pin that key once,
compare its `sha256` with the Provider or operator over a channel of your own,
then verify any saved run on a machine with no access to the server:

```sh
trstctl-cli compliance report-signing-key | jq -r .public_key_pem > report-signing-key.pem
trstctl-cli compliance report-runs download RUN_ID > signed-report.json
trstctl-cli compliance report-runs verify --report signed-report.json \
  --public-key report-signing-key.pem --html assurance-report.html
```

The verifier checks the signature over the run's manifest with the pinned key
(the key inside the file is never trusted) and that the manifest binds a
complete run. It works for every scheduled report type. For a customer
assurance report it also checks the HTML rendering against its digest, and only
then does `--html` write the rendering out.

A Provider schedules a customer's report through a
[tenant template](editions.md#provider-tenant-templates)'s report schedules,
reads the customer's signed runs with the signing key, and downloads a run to
share; see [Provider customer assurance reports](editions.md#provider-customer-assurance-reports).

## What the operator must still do

trstctl enables the controls below; you operate them:

- **Custody and back up the signer key store plus its KEK.** The purpose-bound
  `audit-export` and separate `compliance-evidence` private keys live only there.
  `TRSTCTL_AUDIT_SIGNING_KEY_FILE`
  is a one-time legacy migration path, not live custody. Losing the sealed store
  or KEK means past bundles still verify but you cannot produce new ones under
  the same key; rotating it changes the verification key your auditor pins.
- Distribute the verification (public) key to auditors out of band.
- Connect report schedules to your evidence operations. A schedule's
  `dispatch` announces each completed run on notification channels or in a
  ServiceNow ticket, never with the report body; external WORM storage of the
  artifacts remains operator-run.
- Set a retention policy. By default the served audit view is retained
  indefinitely; setting `TRSTCTL_AUDIT_RETENTION` (e.g. `8760h`) with an
  archive target (`TRSTCTL_AUDIT_ARCHIVE_DIR` or
  `TRSTCTL_AUDIT_ARCHIVE_OBJECT_STORE`) makes a background worker enforce its
  logical query floor while preserving the AN-2 source envelopes: see
  [Audit retention and archive lifecycle](#audit-retention-and-archive-lifecycle)
  below. WORM retention on the archive (a WORM-backed directory, or object lock
  on the bucket) is still your call.
- Schedule periodic signed exports to anchor the log over time (above).
- Handle privacy-erasure residue in old evidence. A served subject erasure
  activates a signed, sequence-preserving replacement history generation with
  matching subject bytes replaced by an erasure placeholder, then securely
  scrubs the superseded generation. Signed archives from before the erasure are
  historical artifacts outside that rewrite — process them under your WORM,
  legal-hold, or cryptographic-shredding policy, then record archive-erasure attestations
  through
  `POST /api/v1/privacy/archive-erasure-attestations`.
  `GET /api/v1/privacy/archive-erasure-attestations` returns the tenant
  evidence ledger for review.
- Run the rest of the program: access reviews, change management, incident
  response, vendor management, and framework-specific evidence your
  auditor requires.

Unlicensed exports report `anchor.kind=""` with detail
`anchoring requires an Enterprise licence`. A licensed export whose configured
TSA fails instead reports that the timestamp authority did not answer. Both keep
the ordinary signed history export available and visibly unanchored.

## Audit retention and archive lifecycle

When Enterprise audit compliance is licensed, `TRSTCTL_AUDIT_RETENTION` is set,
and an archive target is configured (`TRSTCTL_AUDIT_ARCHIVE_DIR`, or
`TRSTCTL_AUDIT_ARCHIVE_OBJECT_STORE` with an object store), a bounded background
worker (per tenant, hourly) enforces the served audit-view policy in four
ordered steps:

1. Sign and verify. Records older than the window are signed as a
   self-contained, offline-verifiable bundle, verifiable with the audit
   verification key like a live export, and the worker verifies it —
   recovers it and checks the hash chain — before writing it anywhere.
2. Archive and read back. The bundle is written to
   `ARCHIVE_DIR/<tenant>/audit-<sequence>.jws` (`0600`), or created once in the
   object store under the tenant's prefix as
   `tenant/<tenant-id>/audit/audit-<sequence>.jws` with its SHA-256. The worker
   reads back what was stored and checks it is the verified segment before
   advancing any served boundary; a failed write or read-back aborts the run
   and the visible view is unchanged. If a crash interrupted an earlier
   attempt after its write, the object store already holds that attempt's
   segment: the worker accepts it only if it verifies and covers exactly the
   same records, and refuses anything else.
3. Record a replayable checkpoint. An `audit.archived` v2 event carries
   the global event boundary, cumulative tenant record count, chain head,
   archive locator, and an explicit retained-source assertion. Replaying
   it reconstructs the tenant-scoped, RLS-protected `audit_checkpoints`
   receiver after PostgreSQL loss.
4. Retire from the served view. The checkpoint becomes the visible
   suffix's chain anchor. Query and export omit the archived prefix, while
   every underlying AN-2 event envelope stays in JetStream for projection
   rebuild, disaster recovery, and authorized privacy rewrite. Each run
   increments
   `trstctl_audit_records_archived_total`,
   `trstctl_audit_source_records_retained_total`, and
   `trstctl_audit_retention_runs_total` on `/metrics`.

The worker splits a large overdue prefix into bounded, contiguous signed
segments below the isolated signer's message limit and drains the backlog in
the same sweep. It does not increase the signing service's transport limit.
Each archived segment chains onto the previous one. The complete event log
remains the AN-2 rebuild source; the signed bundles are independently
verifiable cold evidence, not a substitute event stream. At backup, restore,
and rebuild, trstctl verifies that every logical checkpoint still has its
complete tenant source prefix and fails before mutation if a legacy or
externally damaged source has gaps. Archiving to immutable/WORM storage
remains the operator's responsibility.

Historical administrative audit scopes that predate UUID tenant IDs retain
their original scope in the signed event and checkpoint. A deterministic,
separate UUID partitions their checkpoint rows under PostgreSQL RLS; it does
not merge them with customer or current Provider audit history. Backup and
rebuild use the preserved original scope to verify the retained event source.

## Framework mapping — *enables* vs. operator responsibility

This maps the controls trstctl's audit/identity subsystems help satisfy. It
is not an attestation; an assessor decides whether your overall program
meets each control.

| Framework | Controls trstctl's audit trail helps with | Still the operator's |
| --- | --- | --- |
| SOC 2 | CC6 (NHI logical access), CC7.2/7.3 (security event logging/investigation), CC8.1 (change tracking) — *tenant RBAC, NHI posture, attributable event trail, signed evidence* | Trust-services scope, management assertion, effectiveness sampling, subservice carve-outs, the independent CPA SOC 2 examination |
| ISO 27001 | A.8.15/8.16 (logging, monitoring), A.5.28 (evidence collection) — *event capture + exportable evidence* | Log review cadence, retention schedule, ISMS scope and operation |
| PCI DSS v4 | Req. 10 (log and monitor access) — *who/what/when trail*; 10.5 — *enforced served-view retention: archive → verify → checkpoint, when configured* | 10.5 the chosen window (≥12 months) + WORM archive storage + 3 available copies, daily review, FIM, key custody |
| HIPAA | §164.312(b) audit controls — *recording and examining activity* | §164.308 review procedures, retention (6 years), BAAs |
| FedRAMP / NIST 800-53 | AU-2/3 (event content), AU-9 (audit-info protection, via chain + signed export), AU-11 (served-view retention — *enforced archive + checkpoint when configured*), AU-12 (generation) | AU-6 review, AU-11 retention schedule + WORM storage, AU-9 storage hardening (WORM), FIPS-validated crypto (a build caveat) |
| NIST CSF 2.0 | Govern/Identify/Protect/Detect evidence mappings from NHI inventory, entitlement posture, credential posture, CBOM, and signed audit events | Organizational profile, risk appetite, target profile, and governance acceptance |
| CMMC 2.0 | AC/IA/AU/CM evidence mappings for NHI access, authenticator lifecycle, configuration accountability, and audit trail | CUI boundary, assessment level, assessor package, and organization policy evidence |
| eIDAS | Trust-service security, certificate lifecycle, issuer/subject evidence, and audit evidence mappings | Qualified trust-service status, supervisory notification, and conformity assessment |
| NIS2 | Article 21 risk-management and Article 23 incident-evidence support from NHI posture and audit events | Entity scope, national transposition obligations, management-body accountability, and legal notification process |
| FIPS 140 | FIPS-capable build artifact gate, `--fips` fail-closed POST, `crypto.fips.module_active` posture, single crypto boundary | NIST CMVP certificate for the deployed module, approved FIPS configuration, validation scope |
| Common Criteria | TOE evidence for API, signer, tenant isolation, RBAC, tamper-evident audit, crypto boundary, and release/change evidence | Protection profile, security target approval, external lab evaluation report, certificate, evaluated configuration guide |
| WebTrust for CAs | CA lifecycle event evidence, signer isolation, HSM-capable key-management posture, revocation/profile decision trail | CP/CPS publication, CA/Browser Forum policy program, independent WebTrust practitioner opinion |
| ETSI EN 319 411 | CA operations evidence, key-management posture, audit/profile/revocation trail | External conformity assessment, qualified trust-service status if claimed, subscriber and registration-authority procedures |

**Defensible today:** an attributable, tamper-evident, event-sourced audit
trail with signed, offline-verifiable evidence export, multi-tenant
isolation, and enforced logical retention (archive → verify → replayable
checkpoint → served-view retirement) when a window and an archive directory
are configured, while retaining the complete AN-2 rebuild source.
**Explicitly not claimed:** that trstctl is "compliant" or "certified" with
any framework, that FIPS-validated cryptography is in the *default* build
(it is a FIPS-*capable* opt-in via `make fips-build` / `--fips`; the trstctl product's own NIST CMVP certificate is a separate, external process — see
[FIPS cryptography](#fips-cryptography-a-fips-capable-build-path)),
that trstctl has a Common Criteria certificate or evaluated configuration by
itself,
or that your archive storage is WORM-hardened (that is yours to provide).

## FIPS cryptography: a FIPS-capable build path

trstctl ships a FIPS-capable build path. Building with the Go FIPS 140-3
Cryptographic Module enabled routes Go standard-library cryptography through
that module. CIRCL post-quantum algorithms and external HSM/KMS operations
remain separate validation boundaries:

```sh
make fips-build      # builds bin/<binary>-fips with GOFIPS140=v1.0.0
make fips-image      # builds trstctl:<version>-fips with the same pinned selector
```

For a licensed deployment, pass the vendor **public** license key to the image
build as `LICENSE_KEYS_B64`; keep the private license-signing key outside the
build context. The partner lab accepts `TRSTCTL_LAB_GOFIPS140=v1.0.0` with its
licensed Compose overlay to build the same module into both the control plane
and isolated signer. Set `TRSTCTL_LAB_FIPS_REQUIRED=1` there, or set
`TRSTCTL_FIPS=1` for both processes in another deployment, to make each process
fail closed if its own module is inactive. Both binaries also accept `--fips`.
The Helm chart's `fips.required=true` passes that requirement to both processes
in sidecar and isolated signer topologies when a FIPS-capable image is pinned.
Build the image for
the target architecture and verify its `GET /api/v1/editions` posture in the
running deployment; a local native binary does not establish image posture.

`make fips-build` and `make fips-image` set the pinned regulated selector
`GOFIPS140=v1.0.0` (the toolchain rejects `GOFIPS140=on`; the valid values are
`off|latest|inprocess|certified|vX.Y.Z`). The native target builds every
shipped Go binary and verifies the control plane has the module active —
`bin/trstctl-fips --check-config` reports `crypto.fips.module_active: true`,
and the build fails if it does not. The image build checks the control plane's
active-module posture and the matching Go module build setting in the control
plane, isolated signer, agent, and operator. The `internal/crypto` boundary
keeps Go-backed signature, hash, and AEAD operations on that module; the
algorithm and external-provider fences below still apply. A CI
job (`fips-capable build (GOFIPS140)`) builds and verifies this on every
change. The same module can also be turned on at runtime for a standard
build via `GODEBUG=fips140=on`. `GOFIPS140=latest` remains an explicit
compatibility-test override, not the regulated evidence selector.

The served platform posture is visible on `GET /api/v1/editions` and the
web console's **Platform** page. The response includes the live POST
booleans (`module_active`, `required`, `self_test_passed`) plus the FIPS
path details: `standard: FIPS 140-3`, `module: Go Cryptographic Module`,
`build_target: make fips-build`, `ci_gate: fips-capable build (GOFIPS140)`,
the `internal/crypto` boundary, and the external product-certification
residual.

The same response includes a `regulated_deployment_profile`:

- `go_fips_module_selector: v1.0.0` pins the regulated build selector.
- `approved_algorithms` lists the approved-mode set: ECDSA with SHA-2, RSA
  with PSS/PKCS#1 v1.5 and SHA-2, AES-256-GCM, and SHA-2 digests.
- `non_fips_fences` keeps CIRCL PQC paths (ML-DSA, ML-KEM, SLH-DSA),
  Ed25519, and hybrid TLS/key profiles out of approved-mode FIPS claims
  unless routed through a separately validated module.
- `hsm_kms_validation_certificates` records the certificate references an
  auditor needs per external key-custody boundary: the Go module, AWS
  KMS/CloudHSM, Azure Managed HSM, Google Cloud KMS/Cloud HSM, and PKCS#11
  HSM. These are operator-attached records, not invented by trstctl.
- `operator_required_artifacts` names the remaining evidence: module
  certificate reference, approved configuration, external HSM/KMS
  certificates, signed evidence-pack export, and release manifest.

Enterprise governance packages and signs the same profile from
`GET /api/v1/compliance/evidence-packs/fips-140`: an offline-verifiable
pack proving the trstctl artifact and tenant posture, while still leaving
the product CMVP certificate, deployment-approved configuration, and
external module certificates as operator/lab artifacts.

**Power-on self-test, fail-closed.** A FIPS deployment runs the control plane
and signer with `--fips` (or `TRSTCTL_FIPS=1` on both). At startup, before either
process loads key material or serves
any request, trstctl runs a cryptographic power-on self-test (POST): a
known-answer sign/verify/reject round-trip through the boundary, plus —
under `--fips` — an assertion that the FIPS module is active. If FIPS is
required but the module is not active (a non-FIPS build run with `--fips`),
the binary fails closed and refuses to start, so a regulated deployment can
never silently fall back to an unvalidated module.

**What this is, precisely — and the external residual.** This is
FIPS-*capable*: it uses the Go Cryptographic Module, which carries a CMVP
validation. The trstctl product's own NIST CMVP certificate is a separate, external process (a lab evaluation and certificate issuance) that software
cannot perform; it is the one residual that the build path itself cannot
close. Two further boundaries the build cannot erase:

- The post-quantum schemes (ML-DSA/ML-KEM/SLH-DSA) come from Cloudflare's
  CIRCL, outside the FIPS module's boundary, so a FIPS-required deployment
  should not rely on them for validated operation.
- A key custodied in an external HSM/KMS is validated by that device's
  certificate, not this module.

Alongside the build path, trstctl delivers a BYOK/HSM key lifecycle
(generate-or-import → rotate → revoke → zeroize) for CA/issuing keys and the
secrets KEK — each step recorded as an event and the key material held in
locked, zeroizable memory, with HSM/KMS-resident keys retired through the
provider (disable + scheduled deletion) so the private key never leaves the
device. See [Key custody](limitations.md#ca-key-custody) and
[Configuration → Audit](configuration.md#audit) for the settings referenced
here.
