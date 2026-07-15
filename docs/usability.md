# Usability Outcome SLOs

This page defines the usability outcomes that are allowed to appear in release
copy. The rule is simple: if the product says an operator can finish a human
journey in a time budget, or that operators are satisfied, the claim must point at
a fresh receipt.

## USABILITY-SLO-001: first-run time to first certificate

**Target:** the assisted first-run wizard path stays inside a 15 minute
time-to-first-certificate budget.

**Measured path:** the automated receipt walks the same first-run UI contract that
fresh tenants see: confirm the signer-backed internal CA, issue the first
certificate, mint an agent enrollment token, detect the first agent, and complete
setup.

**Receipt:** `scripts/usability/first-run-receipt.json`

**Regenerate:**

```sh
node scripts/usability/measure-first-run.mjs
```

**CI form:**

```sh
node scripts/usability/measure-first-run.mjs --out "$RUNNER_TEMP/first-run-receipt.json"
python3 scripts/usability/verify-release-evidence.py --first-run "$RUNNER_TEMP/first-run-receipt.json"
```

The receipt is intentionally scoped. It measures the assisted browser journey and
served API-client contract in CI; it does not include human reading time, package
download time, real network latency, or the physical agent installation step.

## USABILITY-SLO-002: operator satisfaction / NPS

**Target before a numeric claim is allowed:** at least five external operators run
the release-candidate getting-started first-certificate path, and the study records completion,
blockers, CSAT, NPS, and anonymized notes. A measured receipt must be fresh within
180 days and carry `status: "measured"`.

**Current receipt:** `scripts/usability/operator-study-receipt.json`

The current receipt has `status: "no_numeric_claim"`. That is not a satisfaction
score. It is a release guard: release notes may not publish NPS, CSAT, or
operator-satisfaction numbers until a real operator-study receipt replaces it.

## Release gate

Release tooling calls:

```sh
python3 scripts/usability/verify-release-evidence.py --release-notes-text "trstctl <tag>"
```

The verifier fails closed when the first-run receipt is missing, stale, over
budget, or not generated from the wizard test. It also fails when release notes
contain an NPS/operator-satisfaction claim but the operator-study receipt is still
`no_numeric_claim`.
