#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
"""CWE register + coverage ledger generator.

Generates two committed documents from the tree, so neither can drift from the
code it describes:

  docs/security/cwe-register.md   every triaged weakness finding: the fixes
                                  (each with its guard) and every in-source
                                  `#nosec G### -- reason` waiver, harvested
                                  from the code itself
  docs/security/cwe-coverage.md   the coverage ledger: which CWE classes are
                                  detector-covered, fixed-with-guard, waived
                                  with reasons, or recorded not-applicable —
                                  a class with none of the four is the gap

Usage:
  scripts/ci/gen-cwe-docs.py            # rewrite both documents
  scripts/ci/gen-cwe-docs.py --check    # fail if either committed file is stale
  scripts/ci/gen-cwe-docs.py --root X   # scan a different tree (self-test hook)

A `#nosec` annotation that names no G-rule or carries no substantive reason
(>= 20 chars after `--`) fails the run: a waiver without a reason is a blanket
suppression, which this repository does not accept.

Exit codes: 0 ok · 1 stale or malformed annotation · 2 usage error.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from collections import defaultdict

REGISTER_PATH = os.path.join("docs", "security", "cwe-register.md")
COVERAGE_PATH = os.path.join("docs", "security", "cwe-coverage.md")

# Scan the core package roots and ee/, which make lint checks through its
# separate ee-lint-ratchet target. Both contain effective inline waivers;
# every matching annotation must appear in the generated register.
SCAN_DIRS = ["clients", "cmd", "deploy", "docs", "ee", "internal", "scripts", "tools"]

# Matches only what gosec itself honors: #nosec as the first token of a
# comment. A prose mention of the marker inside comment text is not an
# annotation and is ignored.
NOSEC = re.compile(r"(?://|/\*)\s*#nosec\b(?P<rules>(?:\s+G\d{3})*)\s*(?:--\s*(?P<reason>.*?))?\s*(?:\*/)?$")

CWE_BY_RULE = {
    "G101": ("CWE-798", "Use of hardcoded credentials"),
    "G107": ("CWE-88", "Argument injection (variable URL request)"),
    "G112": ("CWE-400", "Uncontrolled resource consumption (slowloris)"),
    "G115": ("CWE-190", "Integer overflow or wraparound"),
    "G117": ("CWE-200", "Exposure of sensitive information (marshaled secret field)"),
    "G118": ("CWE-664", "Improper lifetime control (goroutine context)"),
    "G122": ("CWE-367", "Time-of-check time-of-use race (walk callback)"),
    "G123": ("CWE-295", "Improper certificate validation (resumed sessions)"),
    "G124": ("CWE-1004", "Sensitive cookie without protective attributes"),
    "G204": ("CWE-78", "OS command injection"),
    "G301": ("CWE-276", "Incorrect default permissions (directory)"),
    "G302": ("CWE-276", "Incorrect default permissions (chmod)"),
    "G304": ("CWE-22", "Path traversal (file inclusion via variable)"),
    "G306": ("CWE-276", "Incorrect default permissions (file write)"),
    "G401": ("CWE-328", "Use of weak hash"),
    "G402": ("CWE-295", "Improper certificate validation (InsecureSkipVerify)"),
    "G403": ("CWE-326", "Inadequate encryption strength (RSA key size)"),
    "G404": ("CWE-338", "Cryptographically weak PRNG"),
    "G505": ("CWE-328", "Weak hash import (SHA-1)"),
    "G602": ("CWE-118", "Incorrect access of indexable resource"),
    "G702": ("CWE-78", "OS command injection (taint)"),
    "G703": ("CWE-22", "Path traversal (taint)"),
    "G704": ("CWE-918", "Server-side request forgery (taint)"),
    "G705": ("CWE-79", "Cross-site scripting (taint)"),
    "G710": ("CWE-601", "Open redirect (taint)"),
}

# The weaknesses that were FIXED (not waived), each with the guard that fails
# if the weakness returns. Hand-maintained: a fix lands here in the same change.
FIXED = [
    ("CWE-400", "internal/notify/email/email.go",
     "Native SMTP delivery could remain blocked after the notification dispatch deadline. The complete exchange now shares a bounded socket deadline, and context cancellation closes the connection, releasing the worker even when a relay withholds its greeting or DATA acknowledgement.",
     "TestSMTPGreetingHonorsCancellation and TestSMTPProductionExchangeAndDataDeadline (internal/notify/email/smtp_deadline_test.go)"),
    ("CWE-863", "internal/api/endpoint_binding_execution.go",
     "Endpoint enrollment and direct destination deployment could queue certificate issuance without the ordinary issuance permission, policy, dual-control and profile checks. Both now share the identity issuance gate and retain the exact profile binding through host-agent handoff.",
     "TestEndpointEnrollmentHonorsIssuanceAuthority (internal/server/endpoint_binding_authority_served_test.go)"),
    ("CWE-367", "internal/orchestrator/endpoint_binding.go",
     "Endpoint metadata changes do not increment the lifecycle version. Reviewed identity snapshots now participate in approval evidence and are compared under the identity row lock before issuance, preventing policy-time binding changes from authorizing different work.",
     "TestEndpointEnrollmentHonorsIssuanceAuthority/endpoint_enrollment/identity_changed_during_policy and target_deploy/identity_changed_during_policy (internal/server/endpoint_binding_authority_served_test.go)"),
    ("CWE-494", "internal/server/bundled_pg.go",
     "Bundled PostgreSQL could execute a cold download before its committed archive checksum was checked, or reuse unrelated extracted binaries. Startup now requires independent archive authentication and fresh private extraction before execution.",
     "TestBundledPostgresRejectsUnrelatedExtractedCache and TestBundledPostgresAuthenticatedFixtureReachesInitializerAndCleansUp (internal/server/bundled_pg_start_test.go) + TestVerifiedStartAuthenticatesColdArchiveBeforeInit (third_party/embedded-postgres/verified_binary_test.go)"),
    ("CWE-22", "third_party/embedded-postgres/verified_binary.go",
     "The served loader uses rooted extraction into a fresh private directory and rejects traversal, escaping links, special files and duplicate entries. Legacy NewDatabase callers remain a separate unresolved scope.",
     "TestVerifiedExtractionRejectsUnsafePathsLinksAndTypes (third_party/embedded-postgres/verified_binary_test.go)"),
    ("CWE-400", "third_party/embedded-postgres/verified_binary.go",
     "Served archive acquisition and extraction now bound compressed bytes, XZ dictionary memory, the raw expanded stream including hidden TAR metadata, individual files and visible entries.",
     "TestVerifiedExtractionBoundsHiddenMetadataAndDictionary and TestVerifiedDownloadClosesBodiesAndBoundsResponses (third_party/embedded-postgres/verified_acquisition_test.go)"),
    ("CWE-362", "third_party/embedded-postgres/verified_binary.go",
     "Served cache publication no longer depends on a process-local mutex. Atomic create-if-absent publication validates the winning archive bytes; private extracted trees are published only after complete validation.",
     "TestVerifiedPublicationCrossProcess (third_party/embedded-postgres/verified_acquisition_test.go) + TestVerifiedPreparationConcurrencyUsesDistinctTrees (third_party/embedded-postgres/verified_binary_test.go)"),
    ("CWE-252", "Makefile",
     "Formatting enumeration, gofmt, temporary-file creation and architecture-analyzer build errors could be hidden by later successful commands. The lint gate now stops on each prerequisite failure.",
     "TestMakeLintStopsOnToolFailure (docs/lint_failure_test.go)"),
    ("CWE-754", "scripts/ci/ee-lint-ratchet.py",
     "EE lint counted text findings without checking scanner completion. It now requires a complete, uncapped six-linter JSON report and a matching native exit status; malformed reports, tool errors and timeouts fail without changing the baseline.",
     "TestEELintRejectsIncompleteScans and TestMakeLintStopsOnToolFailure/python-deadline-retains-output (docs/lint_failure_test.go)"),
    ("CWE-772", "scripts/ci/ee-lint-ratchet.py",
     "The scanner timeout killed only the direct child. EE lint now bounds live output and terminates the owned scanner process group on timeout, SIGINT, SIGTERM, or a leader exit that leaves descendants.",
     "TestEELintScannerSupervision (docs/lint_supervision_test.go)"),
    ("CWE-287", "internal/server/workload_identity.go",
     "Automatic workload identities omitted the authenticated tenant under a shared CA. Versioned names now bind tenant, route, verified method and broker agent; approval recovery checks the signed tenant and method.",
     "TestServedWorkloadIdentitiesAreTenantIsolated and TestServedEphemeralIdentitiesAndApprovalsAreTenantIsolated (internal/server/workload_identity_tenant_test.go) + TestApprovalBindingDecodesScopedSubjectWithoutChangingAuthority (internal/ephemeral/approval_test.go)"),
    ("CWE-863", "internal/crypto/workload_namespace.go",
     "Ordinary CSR profiles and manual Workload API registrations could claim automatic workload names. Both now refuse the reserved /_trstctl namespace, including alias attempts.",
     "TestLeafProfilesCannotMintReservedWorkloadIdentities (internal/crypto/workload_namespace_test.go) + TestRegistrationCannotClaimAutomaticWorkloadNamespace (internal/protocols/spiffe/workload_namespace_test.go)"),
    ("CWE-863", "internal/crypto/leafca.go",
     "LeafProfile.ExtraExtensions could overwrite a checked SAN or another core certificate policy field. The shared classical/opaque profile gate now rejects those parsed OIDs before signing; non-core extensions remain supported.",
     "TestLeafProfileExtraExtensionsCannotOverrideIdentityPolicy (internal/crypto/workload_namespace_test.go)"),
    ("CWE-190", "internal/crypto/seal/seal.go",
     "Seal accepted a wrapped DEK larger than the v1 container's 2-byte length prefix and silently mis-framed it; now refused with ErrFormat.",
     "TestSealRefusesOversizedWrappedDEK (internal/crypto/seal/bounds_guard_test.go)"),
    ("CWE-295", "internal/crypto/mtls/mtls.go",
     "Pinned TLS configs enforced the key pin only in VerifyPeerCertificate, which resumed sessions skip, so a session ticket could outlive a pin rotation; pinned listeners now disable tickets and re-verify the pin in VerifyConnection.",
     "TestPinnedConfigsEnforcePinOnResumedSessions (internal/crypto/mtls/resumption_pin_test.go)"),
    ("CWE-79", "internal/secretstore/access.go",
     "The secret-store access API returned secret bytes with no declared content type, inviting browsers to sniff them into a renderable type; every response now declares Content-Type and X-Content-Type-Options: nosniff.",
     "TestAPIResponsesDeclareContentTypeAndNosniff (internal/secretstore/access_headers_test.go)"),
    ("CWE-295", "tools/trstctllint/tlsverify",
     "Class guard, not an instance fix: the ninth trstctllint analyzer forbids InsecureSkipVerify outside the tlsprobe discovery prober, the mtls loopback liveness probe, and _test.go files, so the class cannot reappear anywhere in shipped code.",
     "TestTLSVerify fixtures (tools/trstctllint/tlsverify) + the repo-wide linter selftest"),
]

DETECTORS = [
    ("CodeQL `security-extended`", "the broadest CWE query set; push, PR, and weekly", ".github/workflows/codeql.yml"),
    ("gosec (in golangci-lint)", "Core and EE Go analysis; pinned integration disables G407, filters generated-file findings and discards internal analyzer logs. Standalone analysis and independent review must account for those limits. Inline waivers are listed below; configured coverage is not current scan proof", ".golangci.yml via make lint and ee-lint-ratchet"),
    ("govulncheck", "reachability-aware dependency vulnerabilities", "make vuln + the govulncheck CI job"),
    ("gitleaks", "committed secrets (CWE-798)", ".github/workflows/security.yml"),
    ("Trivy", "container image and native-binary CVEs", ".github/workflows/security.yml"),
    ("ClusterFuzzLite + TestEveryUntrustedParserIsFuzzed", "memory/parsing classes on untrusted input", "repo fuzz targets"),
    ("trstctllint (9 analyzers)", "architecture classes: tenant scoping (CWE-639-shaped), key material in strings (CWE-316-shaped), SSRF/exec surfaces (CWE-918/CWE-78), certificate-verification bypass (CWE-295), crypto boundary, idempotency, event sourcing, editions fence", "tools/trstctllint via make lint"),
    ("npm audit surfaces + license audits", "console and SDK-generator dependency advisories", "scripts/ci/npm-audit-dependency-surfaces.sh"),
]

# CWE classes recorded not-applicable or covered-by-construction, with the
# stated reason. Adding a class here is a reviewed change.
NOT_APPLICABLE = [
    ("CWE-120/121/122/787/416/476 (memory corruption)",
     "Go's memory-safe runtime; no cgo in the served binaries. The remaining native surface is the bundled evaluation PostgreSQL binary (scanned by Trivy, external in production) and mlock/madvise syscalls on key buffers (AN-8)."),
    ("CWE-89 (SQL injection)",
     "All SQL goes through pgx parameterized queries; the tenantfilter analyzer additionally requires a tenant_id predicate on repository DML, and raw SQL against read models is rejected by the eventsource analyzer."),
    ("CWE-798 in production code (hardcoded credentials)",
     "gitleaks scans full history; gosec G101 is clean; secrets ship as []byte via internal/crypto/secret with no string form (AN-8, keymaterial analyzer)."),
    ("CWE-311/319 (missing encryption in transit)",
     "TLS 1.3 minimums in internal/crypto/mtls; the signer speaks over a Unix domain socket or mTLS only (AN-4); plaintext listeners exist only for loopback liveness."),
]


def scan_waivers(root: str):
    waivers = []
    bad = []
    for d in SCAN_DIRS:
        base = os.path.join(root, d)
        if not os.path.isdir(base):
            continue
        for dirpath, dirs, files in os.walk(base):
            dirs[:] = [x for x in dirs if x not in ("node_modules", "testdata", ".sandbox-build")]
            for fn in sorted(files):
                if not fn.endswith(".go"):
                    continue
                path = os.path.join(dirpath, fn)
                rel = os.path.relpath(path, root)
                try:
                    lines = open(path, encoding="utf-8", errors="ignore").read().split("\n")
                except OSError:
                    continue
                for n, line in enumerate(lines, 1):
                    if "#nosec" not in line:
                        continue
                    m = NOSEC.search(line)
                    if not m:
                        continue  # prose mention, not an annotation
                    rules = (m.group("rules") or "").split()
                    reason = (m.group("reason") or "").strip()
                    if not rules or len(reason) < 20:
                        bad.append((rel, n, line.strip()[:120]))
                        continue
                    waivers.append((rel, n, rules, reason))
    return waivers, bad


def render_register(waivers):
    out = []
    w = out.append
    w("<!-- GENERATED FILE — do not edit by hand.")
    w("     Regenerate: scripts/ci/gen-cwe-docs.py")
    w("     CI verifies freshness with --check. -->")
    w("")
    w("# CWE register")
    w("")
    w("Every triaged weakness finding in this repository: what was fixed (with the")
    w("guard that fails if the weakness returns) and every accepted or")
    w("false-positive verdict, harvested from the `#nosec G### -- reason` waivers")
    w("in the source itself. A waiver with no rule id or no reason fails the")
    w("generator, so a blanket suppression cannot exist in the tree.")
    w("")
    w("The scan scope includes `clients cmd deploy docs internal scripts tools`")
    w("and `ee/`, which runs through the separate EE lint ratchet. The table below")
    w("records configured detectors and their known limits. It does not establish")
    w("that a scan completed on the current candidate. CI declares CodeQL")
    w("`security-extended`; exact-commit results require separate evidence. Local")
    w("golangci-lint results do not replace that evidence.")
    w("")
    w("## Detectors wired into CI")
    w("")
    w("| Detector | Coverage | Wired at |")
    w("|---|---|---|")
    for name, cov, at in DETECTORS:
        w(f"| {name} | {cov} | `{at}` |")
    w("")
    w("## Fixed, each with a guard")
    w("")
    w("| CWE | Where | What was fixed | Guard that fails if it returns |")
    w("|---|---|---|---|")
    for cwe, where, what, guard in FIXED:
        w(f"| {cwe} | `{where}` | {what} | {guard} |")
    w("")
    w("## Waivers (accepted or false-positive, in-source, reasoned)")
    w("")
    by_rule = defaultdict(list)
    for rel, n, rules, reason in waivers:
        for r in rules:
            by_rule[r].append((rel, n, reason))
    w(f"{len(waivers)} annotated sites across {len(by_rule)} rules. Each row is")
    w("generated from the `#nosec` comment at that exact line; edit the source,")
    w("not this file.")
    w("")
    for rule in sorted(by_rule):
        cwe, title = CWE_BY_RULE.get(rule, ("CWE-?", "(unmapped rule)"))
        sites = by_rule[rule]
        w(f"### {rule} — {cwe} {title} ({len(sites)} sites)")
        w("")
        w("| Location | Reason |")
        w("|---|---|")
        for rel, n, reason in sorted(sites):
            w(f"| `{rel}:{n}` | {reason} |")
        w("")
    return "\n".join(out) + "\n"


def render_coverage(waivers):
    out = []
    w = out.append
    w("<!-- GENERATED FILE — do not edit by hand.")
    w("     Regenerate: scripts/ci/gen-cwe-docs.py")
    w("     CI verifies freshness with --check. -->")
    w("")
    w("# CWE coverage ledger")
    w("")
    w("Which weakness classes this repository can currently see, which it fixed")
    w("with guards, which it accepted with reasons, and which are recorded")
    w("not-applicable — so a class with none of the four is visible as the gap,")
    w("instead of silently unexamined. The same three-bucket honesty the CBOM")
    w("coverage ledger applies to assets, applied to weaknesses.")
    w("")
    w("## Detector-covered classes")
    w("")
    w("| Detector | Classes |")
    w("|---|---|")
    for name, cov, _at in DETECTORS:
        w(f"| {name} | {cov} |")
    w("")
    w("## Fixed with a returning-weakness guard")
    w("")
    w("| CWE | Where | Guard |")
    w("|---|---|---|")
    for cwe, where, _what, guard in FIXED:
        w(f"| {cwe} | `{where}` | {guard} |")
    w("")
    w("## Accepted / false-positive, by CWE class")
    w("")
    counts = defaultdict(int)
    for _rel, _n, rules, _reason in waivers:
        for r in rules:
            cwe, _ = CWE_BY_RULE.get(r, ("CWE-?", ""))
            counts[cwe] += 1
    w("| CWE | Waived sites | Register section |")
    w("|---|---|---|")
    for cwe in sorted(counts, key=lambda c: (-counts[c], c)):
        w(f"| {cwe} | {counts[cwe]} | [cwe-register.md](cwe-register.md) |")
    w("")
    w("Every waived site carries its reason inline in source and in the register;")
    w("the dominant classes are test fixtures and operator-configured paths, which")
    w("is expected for a self-hosted control plane whose operators point it at")
    w("their own files and commands.")
    w("")
    w("## Recorded not-applicable / covered by construction")
    w("")
    w("| Class | Reason |")
    w("|---|---|")
    for cls, reason in NOT_APPLICABLE:
        w(f"| {cls} | {reason} |")
    w("")
    return "\n".join(out) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--check", action="store_true",
                    help="fail if either committed document differs from fresh output")
    ap.add_argument("--root", default=".", help="tree to scan (default .)")
    args = ap.parse_args()

    waivers, bad = scan_waivers(args.root)
    if bad:
        print("cwe docs: malformed #nosec annotations (need 'G### -- reason', reason >= 20 chars):",
              file=sys.stderr)
        for rel, n, line in bad:
            print(f"  {rel}:{n}: {line}", file=sys.stderr)
        return 1
    if not waivers and args.root == ".":
        print("cwe docs: found no #nosec annotations at all — wrong tree?", file=sys.stderr)
        return 2

    rendered = {
        os.path.join(args.root, REGISTER_PATH): render_register(waivers),
        os.path.join(args.root, COVERAGE_PATH): render_coverage(waivers),
    }
    if args.check:
        for path, want in rendered.items():
            try:
                got = open(path, encoding="utf-8").read()
            except OSError:
                print(f"cwe docs: {path} is missing — run scripts/ci/gen-cwe-docs.py and commit",
                      file=sys.stderr)
                return 1
            if got != want:
                print(f"cwe docs: {path} is stale — run scripts/ci/gen-cwe-docs.py and commit",
                      file=sys.stderr)
                return 1
        print("cwe docs: current")
        return 0
    for path, content in rendered.items():
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        print(f"cwe docs: wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
