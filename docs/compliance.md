# Audit trail & compliance

trstctl's audit trail is a projection of the event log: every
state-changing operation is recorded as an immutable event, and audit
query/export endpoints derive their views from it. This page describes
what the audit subsystem gives you — and what it does not: trstctl
provides controls and evidence; **certification is yours to obtain with
your auditor**. Nothing here claims that deploying trstctl makes you
compliant.

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
- Compliance inventory reporting and schedule definitions. `GET
  /api/v1/compliance/inventory-report` and `POST
  /api/v1/compliance/report-schedules` expose supported frameworks, report
  types, evidence references, and idempotent, event-sourced schedule
  definitions.
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
signature fails). With `protocols.tsa` enabled, the saved JWS envelope and every
record-stream trailer also carry the complete RFC 3161 token over that exact
head. Offline verification takes the separately pinned audit JWK set and TSA root,
recomputes the record chain, checks the timestamp token, and applies the chosen
maximum delay from newest record to authority time. It does **not** provide
continuous at-rest notarization without periodic reference points — for that, an
operator schedules exports (e.g. a nightly `trstctl-cli audit export`) and retains
them in write-once / WORM storage. Translog inclusion and hardware-notary
checkpoints remain separate roadmap controls.

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

## Compliance inventory report and schedule definitions

An auditor or operator with `audit:read` can read the served reporting
coverage:

```sh
trstctl-cli compliance inventory-report
curl -fsS -H "Authorization: Bearer $TRSTCTL_TOKEN" \
  "$TRSTCTL_SERVER/api/v1/compliance/inventory-report"
```

The response is intentionally mechanical: framework ids, report types
(`framework_evidence_pack`, `inventory_snapshot`, `cbom_posture`,
`audit_summary`), served routes, evidence references, inventory counts,
and the first page of tenant report schedules.

An operator with `audit:write` can record a schedule definition — a
tenant-scoped, idempotent event that does not claim email, webhook, or
ticket dispatch:

```sh
cat > soc2-schedule.json <<'JSON'
{"framework":"soc2","name":"weekly-soc2-pack","report_type":"framework_evidence_pack","interval_seconds":604800,"delivery":"audit_export","recipient_ref":"audit-archive"}
JSON
trstctl-cli --idempotency-key weekly-soc2 compliance report-schedules create -f soc2-schedule.json
trstctl-cli compliance report-schedules list
```

`delivery` is `audit_export` only; any other value is rejected, so an
unserved email/webhook delivery can never look like a category met.

## What the operator must still do

trstctl enables the controls below; you operate them:

- **Custody and back up the signer key store plus its KEK.** The purpose-bound
  `audit-export` private key lives only there. `TRSTCTL_AUDIT_SIGNING_KEY_FILE`
  is a one-time legacy migration path, not live custody. Losing the sealed store
  or KEK means past bundles still verify but you cannot produce new ones under
  the same key; rotating it changes the verification key your auditor pins.
- Distribute the verification (public) key to auditors out of band.
- Connect report schedules to your evidence operations — external WORM
  storage, ticketing, email, and webhook dispatch remain operator-run
  until a served runner exists.
- Set a retention policy. By default the served audit view is retained
  indefinitely; setting both `TRSTCTL_AUDIT_RETENTION` (e.g. `8760h`) and
  `TRSTCTL_AUDIT_ARCHIVE_DIR` makes a background worker enforce its logical
  query floor while preserving the AN-2 source envelopes: see
  [Audit retention and archive lifecycle](#audit-retention-and-archive-lifecycle)
  below. Pointing the archive dir at WORM-backed storage is still your
  call.
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

## Audit retention and archive lifecycle

When `TRSTCTL_AUDIT_RETENTION` and `TRSTCTL_AUDIT_ARCHIVE_DIR` are both
set, a bounded background worker (per tenant, hourly) enforces the served
audit-view policy in four ordered steps:

1. Archive. Records older than the window are signed as a self-contained,
   offline-verifiable bundle and written to
   `ARCHIVE_DIR/<tenant>/audit-<sequence>.jws` (`0600`), verifiable with
   the audit verification key like a live export.
2. Verify. The worker re-verifies the bundle it wrote — recovers it
   and checks the hash chain — before advancing any served boundary; a
   failed verification aborts the run and the visible view is unchanged.
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

Each archived segment chains onto the previous one. The complete event log
remains the AN-2 rebuild source; the signed bundles are independently
verifiable cold evidence, not a substitute event stream. At backup, restore,
and rebuild, trstctl verifies that every logical checkpoint still has its
complete tenant source prefix and fails before mutation if a legacy or
externally damaged source has gaps. Archiving to immutable/WORM storage
remains the operator's responsibility.

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
Cryptographic Module enabled routes all of trstctl's cryptography through
that module:

```sh
make fips-build      # builds bin/<binary>-fips with GOFIPS140=v1.0.0
```

`make fips-build` sets the pinned regulated selector `GOFIPS140=v1.0.0`
(the toolchain rejects `GOFIPS140=on`; the valid values are
`off|latest|inprocess|certified|vX.Y.Z`), builds all three binaries, and
verifies the produced binary actually has the module active —
`bin/trstctl-fips --check-config` reports `crypto.fips.module_active: true`,
and the build fails if it does not. Because everything routes through one
crypto boundary, when the module is active every signature, hash, and AEAD
trstctl performs runs inside the validated Go Cryptographic Module. A CI
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

**Power-on self-test, fail-closed.** A FIPS deployment runs trstctl with
`--fips` (or `TRSTCTL_FIPS=1`). At startup, before the control plane serves
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
