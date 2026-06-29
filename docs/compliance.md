# Audit trail & compliance

trstctl's audit trail is a **projection of the event log**: every
state-changing operation is recorded as an immutable event, and the audit
query/export endpoints derive their views from that log. This page describes what
the audit subsystem **gives you** and — just as importantly — what it **does
not** do for you. trstctl provides controls and evidence; **certification is yours
to obtain with your auditor**. Nothing here is a claim that deploying trstctl
makes you compliant.

## What the audit subsystem provides

- **Completeness.** Every served mutation is recorded as an event, so the
  trail reconstructs the full history of owners, issuers, identities, issuance,
  and revocation. The relational read model is a projection of the same events.
- **Attribution — who did what, when, under what authorization.** Each event
  carries the authenticated **actor** (subject and the role names it acted under),
  set from the verified principal (token or OIDC session, R1.2), plus the event
  time and tenant. A reconstructed trail answers "who revoked this credential, at
  what time, under which role."
- **Tamper-evidence.** Audit records are **hash-linked**: each record's hash folds
  in its predecessor's, so altering, dropping, inserting, or reordering any record
  changes that record's hash and every hash after it. The chain-verification
  routine detects it and names the first broken record.
- **Signed, offline-verifiable evidence export.** `GET /api/v1/audit/export`
  returns a compact JWS bundle (records + the chain head) signed with a
  **persistent** key, so a bundle exported today still verifies after a restart.
  An auditor verifies the signature and recomputes the chain offline.
- **Signed framework evidence packs.** `GET /api/v1/compliance/evidence-packs/{framework}`
  turns the tenant audit log and CBOM graph into a signed report for `pci-dss`,
  `hipaa`, `soc2`, `fedramp`, `cnsa-2.0`, `fips-140`, `common-criteria`,
  `cabf-br`, `webtrust`, or `etsi`. The response includes
  `signed_export` plus `public_key_der`, so an auditor can verify the report
  manifest offline without trusting the API response body after the fact.
- **Compliance inventory reporting and schedule definitions.** `GET
  /api/v1/compliance/inventory-report` returns the CAP-OBS-02 reporting view:
  supported frameworks, supported report types, backing API routes, evidence
  references, report-schedule rows, and counts from certificates, CBOM assets,
  discovery schedules, and compliance report schedules. `POST
  /api/v1/compliance/report-schedules` records an idempotent, event-sourced
  audit-export schedule definition, and `GET
  /api/v1/compliance/report-schedules` lists those definitions.
- **Tenant isolation.** Every audit query is tenant-scoped.

## The tamper-evidence trust model (read this)

The event log lives in NATS JetStream with **append-only file storage**. On top of
that, trstctl maintains an application-level **hash chain** over the audit records
and publishes the chain head inside each **signed** export. The signed export is
the *anchor*: an export captured at time T attests to the exact records and head
at T, and any later alteration of the underlying log produces a different head
that no longer matches the trusted, signed bundle.

What this **does** detect: alteration, truncation, insertion, or reordering of
records relative to a previously signed bundle, and any in-place edit of a signed
bundle (the signature fails).

What it does **not** do by itself: provide continuous at-rest notarization without
a reference point. For that, an **operator** schedules periodic signed exports
(for example a nightly `trstctl-cli audit export`) and retains them in
write-once / WORM storage; each export anchors the log up to its point in time. A
future hardware-anchored or external-notary checkpoint is a roadmap item.

## Framework evidence packs

An auditor or operator with `audit:read` can export a framework pack through the
API or CLI:

```sh
trstctl-cli compliance evidence-pack soc2
curl -fsS -H "Authorization: Bearer $TRSTCTL_TOKEN" \
  "$TRSTCTL_SERVER/api/v1/compliance/evidence-packs/soc2"
```

Use `pci-dss`, `hipaa`, `soc2`, `fedramp`, `cnsa-2.0`, `fips-140`,
`common-criteria`, `cabf-br`, `webtrust`, or `etsi` as the framework path
value. The JSON response has four stable fields:

| Field | Meaning |
| --- | --- |
| `format` | Wire marker: `trstctl.compliance.evidence-pack.v1`. |
| `framework` | The normalized framework id used to build the report. |
| `signed_export` | A signed envelope whose manifest contains controls, CBOM crypto posture, product evidence, and operator-attestation gaps. |
| `public_key_der` | PKIX DER public key bytes for offline verification. |

The manifest is intentionally honest. It marks each control as `evidenced` or
`gap`, includes CBOM-derived post-quantum and quantum-vulnerable counts, and
separates what trstctl can prove from what your organization must still attest.
For example, the SOC 2 pack can show tamper-evident audit evidence and FIPS
203/204/205 migration posture from the CBOM, but it does not claim trstctl or
your deployment is SOC 2 certified.

The `fips-140` pack shows the FIPS-capable build artifact gate, `--fips`
fail-closed power-on self-test, crypto boundary, signer isolation, and CI
verification evidence. It still marks the deployed module's NIST CMVP certificate
number, approved FIPS configuration, and validation scope as operator or vendor
artifacts. The `common-criteria` pack maps served TOE evidence for API, signer,
tenant isolation, RBAC, tamper-evident audit, and crypto-boundary controls; it
keeps the lab evaluation report, certificate, protection profile, security target,
and evaluated configuration guide as external residuals.

For CA audit programs, the `cabf-br` pack adds CA/Browser Forum Baseline
Requirements posture controls for profile lint/zlint evidence, certificate
issuance and revocation events, certificate profile decisions, signer isolation,
and HSM-capable key management. It still marks CP/CPS publication,
domain-validation/CAA procedures, CA/Browser Forum policy-program operation, and
independent public-trust audit as operator or external-auditor responsibilities.
The `webtrust` and `etsi` packs add broader CA-audit posture controls and keep
WebTrust practitioner opinion, ETSI conformity assessment, qualified trust-service
status, and subscriber/registration-authority procedures as external residuals. In
other words: trstctl serves the evidence pack; it does not self-award WebTrust,
ETSI, or CA/Browser Forum compliance certification.

## Compliance inventory report and schedule definitions

An auditor or operator with `audit:read` can read the served reporting coverage:

```sh
trstctl-cli compliance inventory-report
curl -fsS -H "Authorization: Bearer $TRSTCTL_TOKEN" \
  "$TRSTCTL_SERVER/api/v1/compliance/inventory-report"
```

The response is intentionally mechanical. It names the capability
(`CAP-OBS-02`), the supported framework ids, the supported report types
(`framework_evidence_pack`, `inventory_snapshot`, `cbom_posture`, and
`audit_summary`), the served routes, evidence references, inventory counts, and
the first page of tenant report schedules.

An operator with `audit:write` can record a schedule definition. This is a
tenant-scoped, idempotent event plus read-model projection; it does not claim
email, webhook, or ticket dispatch.

```sh
cat > soc2-schedule.json <<'JSON'
{"framework":"soc2","name":"weekly-soc2-pack","report_type":"framework_evidence_pack","interval_seconds":604800,"delivery":"audit_export","recipient_ref":"audit-archive"}
JSON
trstctl-cli --idempotency-key weekly-soc2 compliance report-schedules create -f soc2-schedule.json
trstctl-cli compliance report-schedules list
```

`delivery` is `audit_export` only. Any other delivery value is rejected, because
the product should never make an unserved email/webhook delivery look like a
category meet.

## What the operator must still do

trstctl enables the controls below; **you** operate them:

- **Custody and back up the export signing key** (`TRSTCTL_AUDIT_SIGNING_KEY_FILE`,
  written `0600`). Losing it means past bundles still verify (you keep the public
  half) but you cannot produce new bundles under the same key; rotating it changes
  the verification key your auditor pins.
- **Distribute the verification (public) key** to auditors out of band.
- **Connect report-schedule definitions to your evidence operations.** The served
  schedule API records the reporting plan and exposes it in the CAP-OBS-02
  inventory report; external WORM storage, ticketing, email, and webhook dispatch
  remain operator-run until a served runner exists.
- **Set a retention policy — trstctl can now enforce it.** By default the event log
  is **retained indefinitely** (no pruning). When you set **both**
  `TRSTCTL_AUDIT_RETENTION` (a window, e.g. `8760h`) **and**
  `TRSTCTL_AUDIT_ARCHIVE_DIR`, a background worker enforces it: see
  [Audit retention and archive lifecycle](#audit-retention-and-archive-lifecycle) below.
  Pointing `TRSTCTL_AUDIT_ARCHIVE_DIR` at WORM-backed storage is still your call.
- **Schedule periodic signed exports** to anchor the log over time (above).
- **Handle privacy erasure residue in old evidence artifacts.** A served subject
  erasure secure-deletes and republishes the hot JetStream log with matching raw
  subject bytes replaced by the tenant-bound erasure placeholder, so new hot-log
  replay and later backups do not carry that raw subject. Signed archives and
  backups created before the erasure are historical artifacts outside the hot-log
  rewrite; process them under your WORM, legal-hold, and backup-deletion policy.
- **Run the rest of the program**: access reviews, change management, incident
  response, vendor management, and the framework-specific evidence your auditor
  requires.

## Audit retention and archive lifecycle

When `TRSTCTL_AUDIT_RETENTION` and `TRSTCTL_AUDIT_ARCHIVE_DIR` are both set, a
bounded background worker (per tenant, tenant-isolated; hourly cadence) enforces the
policy in four ordered steps, so the configuration does real work rather than merely
documenting intent:

1. **Archive.** Records older than the window are signed as a self-contained,
   offline-verifiable bundle (a compact JWS) and written to
   `ARCHIVE_DIR/<tenant>/audit-<sequence>.jws` (`0600`). Verify any archive with the
   audit verification key, exactly like a live export.
2. **Verify.** The worker re-verifies the bundle it just wrote — it recovers and its
   hash chain checks out — **before** anything is deleted. A bundle that fails
   verification aborts the run; nothing is pruned.
3. **Seal a checkpoint.** A signed checkpoint records the boundary (sequence + the
   audit chain head at that point) in `audit_checkpoints` (tenant-scoped, RLS). The
   checkpoint is the surviving records' new chain anchor.
4. **Prune.** Only now are the archived records deleted from the hot event log. The
   surviving records hash-link onto the checkpoint, so **`VerifyChain` still holds
   across the prune** and a previously exported bundle still verifies. Each run also
   emits an `audit.archived` event (itself auditable) and increments
   `trstctl_audit_records_archived_total`, `trstctl_audit_records_pruned_total`, and
   `trstctl_audit_retention_runs_total` on `/metrics`.

Each archived segment chains onto the previous one (its `prev_hash` is the prior
segment's head), so the **archive bundles plus the live log are the authoritative
history**: a full disaster-recovery rebuild restores from the archive **and** the
live log together. Archiving to immutable/WORM storage (and protecting it) remains
the operator's responsibility. This is the one place trstctl deletes from the event
log, and it does so only after archive → verify → seal.

## Framework mapping — *enables* vs. operator responsibility

This maps the controls trstctl's audit/identity subsystems **help satisfy**. It is
not an attestation; an assessor decides whether your overall program meets each
control.

| Framework | Controls trstctl's audit trail helps with | Still the operator's |
| --- | --- | --- |
| SOC 2 | CC7.2/7.3 (security event logging), CC8.1 (change tracking) — *attributable, tamper-evident event trail + signed evidence* | Monitoring/alerting program, change-management process, retention enforcement, the audit engagement |
| ISO 27001 | A.8.15/8.16 (logging, monitoring), A.5.28 (evidence collection) — *event capture + exportable evidence* | Log review cadence, retention schedule, ISMS scope and operation |
| PCI DSS v4 | Req. 10 (log and monitor access) — *who/what/when trail*; 10.5 — *enforced retention: archive to signed bundles → checkpoint → prune, when configured* | 10.5 the chosen window (≥12 months) + WORM archive storage + 3-readily-available copies, daily review, FIM, key custody |
| HIPAA | §164.312(b) audit controls — *recording and examining activity* | §164.308 review procedures, retention (6 years), BAAs |
| FedRAMP / NIST 800-53 | AU-2/3 (event content), AU-9 (protection of audit info, via the chain + signed export), AU-11 (retention — *enforced archive + prune when configured*), AU-12 (generation) | AU-6 review, AU-11 retention schedule + WORM storage, AU-9 storage hardening (WORM), FIPS-validated crypto (a build caveat) |
| FIPS 140 | FIPS-capable build artifact gate, `--fips` fail-closed POST, `crypto.fips.module_active` posture, single crypto boundary | NIST CMVP certificate for the deployed module, approved FIPS configuration, validation scope |
| Common Criteria | TOE evidence for API, signer, tenant isolation, RBAC, tamper-evident audit, crypto boundary, and release/change evidence | Protection profile, security target approval, external lab evaluation report, certificate, evaluated configuration guide |
| WebTrust for CAs | CA lifecycle event evidence, signer isolation, HSM-capable key-management posture, revocation/profile decision trail | CP/CPS publication, CA/Browser Forum policy program, independent WebTrust practitioner opinion |
| ETSI EN 319 411 | CA operations evidence, key-management posture, audit/profile/revocation trail | External conformity assessment, qualified trust-service status if claimed, subscriber and registration-authority procedures |

**Defensible today:** an attributable, tamper-evident, event-sourced audit trail
with signed, offline-verifiable evidence export, multi-tenant isolation, and
**enforced retention** (archive → checkpoint → prune, chain-verifiable across the
prune) when a window and an archive directory are configured.
**Explicitly not claimed:** that trstctl is "compliant" or "certified" with any
framework, that FIPS-validated cryptography is in the *default* build (it is a
FIPS-*capable* opt-in via `make fips-build` / `--fips`; the trstctl product's own
NIST CMVP certificate is a separate, external process — see
[FIPS cryptography](#fips-cryptography--a-fips-capable-build-path)),
that trstctl has a Common Criteria certificate or evaluated configuration by
itself,
or that your archive storage is WORM-hardened (that is yours to provide).

## FIPS cryptography — a FIPS-capable build path

trstctl ships a **FIPS-capable build path**. Building with the Go FIPS 140-3
Cryptographic Module enabled routes all of trstctl's cryptography through that
module:

```sh
make fips-build      # builds bin/<binary>-fips with GOFIPS140=v1.0.0
```

`make fips-build` sets the pinned regulated selector `GOFIPS140=v1.0.0` (the
toolchain rejects `GOFIPS140=on`; the valid values are
`off|latest|inprocess|certified|vX.Y.Z`), builds all three binaries, and
**verifies the produced binary actually has the module active** —
`bin/trstctl-fips --check-config` reports `crypto.fips.module_active: true`, and
the build fails if it does not. Because trstctl's entire cryptographic surface
enters through one single crypto boundary, when the module is active every
signature, hash, and AEAD trstctl performs runs inside the validated Go
Cryptographic Module. A CI job (`fips-capable build (GOFIPS140)`) builds and
verifies this on every change. The same module can also be turned on at runtime
for a standard build via `GODEBUG=fips140=on`. `GOFIPS140=latest` remains an
explicit compatibility-test override; it is not the regulated evidence selector.

The served platform posture is visible on `GET /api/v1/editions` and the web
console's **Platform** page. The response includes the live POST booleans
(`module_active`, `required`, `self_test_passed`) plus the CAP-KEY-03 path details:
`standard: FIPS 140-3`, `module: Go Cryptographic Module`, `build_target: make
fips-build`, `ci_gate: fips-capable build (GOFIPS140)`, the `internal/crypto`
boundary, and the external product-certification residual.

The same response includes a `regulated_deployment_profile`:

- `go_fips_module_selector: v1.0.0` pins the regulated build selector.
- `approved_algorithms` enumerates the approved-mode algorithm/mode set trstctl
  uses through the Go module: ECDSA with SHA-2, RSA with PSS/PKCS#1 v1.5 and
  SHA-2, AES-256-GCM, and SHA-2 digests.
- `non_fips_fences` explicitly keeps CIRCL PQC paths (ML-DSA, ML-KEM, SLH-DSA),
  Ed25519, and hybrid TLS/key profiles out of approved-mode FIPS claims unless a
  deployment routes those operations through a separately validated module.
- `hsm_kms_validation_certificates` records the certificate references an auditor
  needs for each external key-custody boundary: the Go module, AWS KMS/CloudHSM,
  Azure Managed HSM, Google Cloud KMS/Cloud HSM, and PKCS#11 HSM deployments.
  These are operator-attached certificate records, not invented by trstctl.
- `operator_required_artifacts` names the remaining lab/operator evidence:
  module certificate reference, approved configuration, external HSM/KMS
  certificates, signed evidence-pack export, and release manifest.

Enterprise governance packages and signs the same profile from
`GET /api/v1/compliance/evidence-packs/fips-140`. The signed export is an
offline-verifiable evidence pack: it proves the trstctl artifact and tenant
posture it describes, while still leaving the product CMVP certificate,
deployment-approved configuration, and external module certificates as explicit
operator/lab artifacts.

**Power-on self-test, fail-closed.** A FIPS deployment runs trstctl with `--fips`
(or `TRSTCTL_FIPS=1`). At startup, before the control plane serves any request,
trstctl runs a cryptographic power-on self-test (POST): a known-answer
sign/verify/reject round-trip through the boundary, plus — under `--fips` — an
assertion that the FIPS module is active. If FIPS is required but the module is
**not** active (a non-FIPS build run with `--fips`), the binary **fails closed and
refuses to start**, so a regulated deployment can never silently fall back to an
unvalidated module.

**What this is, precisely — and the external residual.** This is FIPS-*capable*:
it uses the Go Cryptographic Module, which carries a CMVP validation. The
**trstctl product's own NIST CMVP certificate is a separate, external process** (a
lab evaluation and certificate issuance) that software cannot perform; it is the
one residual that the build path itself cannot close. Two further boundaries the
build cannot erase:

- The post-quantum schemes (ML-DSA/ML-KEM/SLH-DSA) come from Cloudflare's CIRCL,
  which is **not** in the FIPS module's boundary, so a FIPS-required deployment
  should not rely on the PQC algorithms for validated operation.
- A key custodied in an external HSM/KMS is validated by **that device's**
  certificate, not by this module.

Alongside the build path, trstctl delivers a **BYOK/HSM key lifecycle**
(generate-or-import → rotate → revoke → zeroize) for CA/issuing keys and the
secrets KEK — each step recorded as an event and the key material held in locked,
zeroizable memory, with HSM/KMS-resident keys retired through the provider
(disable + scheduled deletion) so the private key never leaves the device. See
[Key custody](limitations.md#ca-key-custody) and
[Configuration → Audit](configuration.md#audit) for the settings referenced here.
