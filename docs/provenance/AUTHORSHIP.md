# Authorship and development method

<!-- Target path in repo: docs/provenance/AUTHORSHIP.md
     DRAFT — assembled from repository evidence by an external review pass.
     [FILL] markers are facts only the author holds. Counsel must review before
     this is relied upon in any transaction or registration. -->

> **Status: draft for counsel review.** This document records *how* trstctl was built,
> so that questions about authorship and ownership can be answered from evidence rather
> than recollection. It is a factual record, not a legal conclusion. Nothing here should
> be read as an assertion about what is or is not protectable; that determination
> belongs to counsel.

---

## 1. Summary

trstctl was designed and specified by a single human author, **[FILL: legal name]**, and
implemented substantially with the assistance of AI coding agents operating under
written architectural constraints authored by that person, with human review and
acceptance at every merge.

There have been **no other human contributors**. No code was written under an employment
agreement or contract that assigns intellectual property to a third party. No code was
carried in from a prior project encumbered by third-party rights. **[FILL: confirm each
of these three statements is accurate as written, and amend if not.]**

Development period: **[FILL: start date]** to present.

---

## 2. Why this record exists

United States copyright protects works of human authorship. Current guidance from the
U.S. Copyright Office (Part 2 of its *Copyright and Artificial Intelligence* report,
January 2025) is that a work is protectable **to the extent a human exercised creative
control over its expressive elements**, assessed case by case, and that prompting alone
is generally not sufficient to establish that control. The human-authorship requirement
was affirmed by the D.C. Circuit in March 2025; the Supreme Court declined review in
2026. Registrants are expected to identify and disclaim purely AI-generated portions.

Because this codebase was built with substantial AI assistance, the sensible posture is
to describe the actual method precisely — including where human creative control was
exercised and where it was not — rather than to make a blanket ownership claim that
cannot be substantiated. This document is that description. The artifacts it cites are
preserved in the repository and its history.

---

## 3. What the human author created

The following were authored by the human, independently of any AI system, and constitute
the architecture and specification of the work:

**3.1 The architectural contract.** `README.md` defines nine binding invariants
(AN-1 … AN-9) that govern every line of the system: PostgreSQL row-level security as the
tenancy fence; event-sourced state with projections as the only read path; a single
cryptographic boundary at `internal/crypto`; an isolated signing process; idempotency on
every mutation; an outbox for every external effect; bounded worker pools; byte-backed,
locked, zeroed key material; and a core-versus-`ee/` editions fence. These are original
design decisions, not derived from any implementation, and they determine the structure
of the entire codebase.

**3.2 The product design.** The open-core split line — what remains MPL-2.0 and free
(multi-tenancy, the crypto boundary, audit and export rights, the offline license
verifier) versus what is commercial — is a human product judgment recorded in
`docs/editions.md`, including the "zero removal" principle stating that
no capability may be taken away from the free tier to create an upsell.

**3.3 The specifications.** Work was decomposed into sprint cards
(**[FILL: path — e.g. `trstctl-backlog.md`]**), each stating scope, explicit exclusions,
dependencies, and acceptance criteria before implementation began. Implementation was
constrained to the card; scope expansion was prohibited by the written process
(the written sprint-card process).

**3.4 The enforcement design.** The custom `go/analysis` architecture linter
(`tools/trstctllint`, eight analyzers), the catalog-derived invariant tests, the
served-proof harness design, the definition-of-done census, and the thirteen
gate self-tests are human-designed mechanisms for making the invariants
mechanically enforceable. Their existence and design are original; their code was
written with agent assistance.

**3.5 Selection, review, and acceptance.** Every change was reviewed and accepted or
rejected by the human author against the invariants and the card's acceptance criteria.
Output that violated an invariant was rejected regardless of whether it functioned.
Additionally, an author-designed adversarial audit program was run continuously across
eight review lanes, with the author adjudicating findings; roughly sixty defects were
identified and closed through that process. The commits produced by that program remain
in git history and are the surviving evidence of it; see §5 on the working directory's
retention status.

---

## 4. What AI systems produced

AI coding agents produced substantial portions of the implementation source, tests, and
documentation prose, in each case: (a) under the constraints in §3.1–3.3, (b) reviewed
against §3.4's mechanical gates, and (c) accepted or rejected by the human author per
§3.5.

The honest characterization is **human-specified, agent-implemented, human-verified**.
Expressive choices at the level of individual functions and statements were frequently
made by the model. Architectural, structural, interface, and invariant choices were made
by the human and imposed on the model.

**[FILL: name the tools and approximate period of use — e.g. "Claude (Anthropic) via
Claude Code, [dates]". If usage terms of those tools assign output rights to the user,
note that here; it is the first thing counsel will check.]**

---

## 5. Evidence preserved

These artifacts substantiate §3 and should be retained as part of the record. They are
IP evidence, not process exhaust, and should not be garbage-collected.

| Evidence | Location | What it shows |
|---|---|---|
| Architectural contract | `README.md` (AN-1 … AN-9) | Human-authored invariants predating implementation |
| Invariant documentation | `docs/design/architecture-invariants.md` | The design in reader form |
| Threat models | `docs/security/threat-model.md`, `docs/design/signing-service.md` | Human security analysis |
| Sprint specifications | **[FILL: path]** | Per-change human specification with acceptance criteria |
| Change history | `CHANGELOG.md` (698 entries), git history | Sequence, authorship, and review record |
| Adversarial audit program | **[FILL: path]** — the `audit-harness/` working directory (backlog, playbook, matrices) was deleted after the pass completed and was never tracked in git. Locate a backup or Trash copy, or record that it is unrecoverable | Human-designed review and adjudication |
| Enforcement mechanisms | `tools/trstctllint`, catalog-derived tests, gate self-tests | Human-designed verification |
| Maintainer transfer record | `MAINTAINERS.md` | Human operational knowledge, written for a successor |

**Retention action: [FILL] — URGENT.** The `audit-harness/` working directory was deleted
after its pass completed and was never tracked in git, so it is not recoverable from the
repository. Recover it from Trash or a backup if possible; if it is genuinely gone, say so
here plainly rather than leaving the citation dangling. Then confirm the sprint backlog
and any successor loop directory are archived alongside the repository and included in any
transfer. A record that cites evidence which no longer exists is worse than one that
admits the gap.

---

## 6. Protection posture

Recorded for counsel's assessment, not asserted as conclusion:

- **Trade secret** — the `ee/` tree has never been published and is distributed only
  under commercial agreement with a license fence enforced in code (AN-9). It is
  maintained as confidential material.
- **Patents** — provisional application(s) have been filed covering
  **[FILL: subject matter]**. Claim-to-code traceability is generated from source at
  `ee/docs/claim-traceability.md`. **[FILL: filing dates and the 12-month conversion
  deadline for each.]**
- **Copyright** — registration strategy to be determined with counsel, including which
  portions carry sufficient human creative control to be claimed and how AI-generated
  portions are disclaimed, consistent with Copyright Office guidance.
- **Trademark** — **[FILL: status of "trstctl" and any product marks.]**
- **Contribution policy** — `NOTICE` currently records that the project has a single
  author and that CLA/DCO workflows are out of scope. If outside contributions are ever
  accepted, a DCO or CLA must be in place *before* the first one is merged; retroactive
  collection is impractical.

---

## 7. Third-party code

Dependencies are audited mechanically. `scripts/ci/license-audit.py` resolves every Go
module actually linked into each shipped binary, classifies its license by title
priority (correctly distinguishing MPL's Exhibit B secondary-license reference from
genuine GPL), and fails the build on strong copyleft reaching a distributed artifact or
on any module shipping no license text. An npm equivalent covers the console. Both run
in CI and emit receipts to `dist/release-evidence/`.

Every source file carries an SPDX identifier (**[FILL: confirm 2,391/2,391 after adding
the missing header to `internal/aimodel/zz_pii_before_test.go`]**), and a guard test
should enforce this going forward.

Regarding inadvertent reproduction of third-party code through model output: the license
audit governs *linked* dependencies, which is a different risk from verbatim
reproduction inside first-party files. Mitigations in place: SPDX discipline, the
copyleft gate, and human review of every change. **[FILL: state whether a periodic code
similarity scan is run; if not, consider adding one — it is inexpensive insurance and
a question diligence may ask.]**

---

## 8. Open questions for counsel

1. Given the method in §3–§4, what portions are appropriately claimed for copyright
   registration, and how should AI-assisted portions be characterized or disclaimed?
2. Does the AI tooling's terms of service affect ownership or licensing of output?
3. Should the protection center of gravity be trade secret plus patents rather than
   copyright, given §2?
4. What is the conversion deadline for each provisional, and what post-provisional
   subject matter needs its own filing?
5. Does publication of the MPL core disclose claim matter, and must the non-provisional
   be filed first?
6. Is an entity formation and IP assignment advisable before any transaction?

---

## 9. Maintenance

This document is verified by `docs/provenance/authorship_test.go`, which asserts that
every artifact path cited in §5 exists. If a cited artifact is moved or deleted, the
test fails and this record must be updated in the same change — the same discipline the
repository applies to its architectural invariants.

Last reviewed: **[FILL: date]** · Next review: on any change to contribution policy,
tooling, or patent status.
