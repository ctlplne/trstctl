<!-- GENERATED FILE — do not edit by hand.
     Regenerate: scripts/ci/gen-cwe-docs.py
     CI verifies freshness with --check. -->

# CWE coverage ledger

Which weakness classes this repository can currently see, which it fixed
with guards, which it accepted with reasons, and which are recorded
not-applicable — so a class with none of the four is visible as the gap,
instead of silently unexamined. The same three-bucket honesty the CBOM
coverage ledger applies to assets, applied to weaknesses.

## Detector-covered classes

| Detector | Classes |
|---|---|
| CodeQL `security-extended` | the broadest CWE query set; push, PR, and weekly |
| gosec (in golangci-lint) | Go-specific CWE-mapped rules G1xx-G7xx over the full lint scope; zero open findings — every site is fixed or carries a reasoned in-source waiver listed below |
| govulncheck | reachability-aware dependency vulnerabilities |
| gitleaks | committed secrets (CWE-798) |
| Trivy | container image and native-binary CVEs |
| ClusterFuzzLite + TestEveryUntrustedParserIsFuzzed | memory/parsing classes on untrusted input |
| trstctllint (9 analyzers) | architecture classes: tenant scoping (CWE-639-shaped), key material in strings (CWE-316-shaped), SSRF/exec surfaces (CWE-918/CWE-78), certificate-verification bypass (CWE-295), crypto boundary, idempotency, event sourcing, editions fence |
| npm audit surfaces + license audits | console and SDK-generator dependency advisories |

## Fixed with a returning-weakness guard

| CWE | Where | Guard |
|---|---|---|
| CWE-190 | `internal/crypto/seal/seal.go` | TestSealRefusesOversizedWrappedDEK (internal/crypto/seal/bounds_guard_test.go) |
| CWE-295 | `internal/crypto/mtls/mtls.go` | TestPinnedConfigsEnforcePinOnResumedSessions (internal/crypto/mtls/resumption_pin_test.go) |
| CWE-79 | `internal/secretstore/access.go` | TestAPIResponsesDeclareContentTypeAndNosniff (internal/secretstore/access_headers_test.go) |
| CWE-295 | `tools/trstctllint/tlsverify` | TestTLSVerify fixtures (tools/trstctllint/tlsverify) + the repo-wide linter selftest |

## Accepted / false-positive, by CWE class

| CWE | Waived sites | Register section |
|---|---|---|
| CWE-22 | 323 | [cwe-register.md](cwe-register.md) |
| CWE-798 | 219 | [cwe-register.md](cwe-register.md) |
| CWE-276 | 146 | [cwe-register.md](cwe-register.md) |
| CWE-78 | 137 | [cwe-register.md](cwe-register.md) |
| CWE-190 | 127 | [cwe-register.md](cwe-register.md) |
| CWE-1004 | 31 | [cwe-register.md](cwe-register.md) |
| CWE-367 | 22 | [cwe-register.md](cwe-register.md) |
| CWE-338 | 15 | [cwe-register.md](cwe-register.md) |
| CWE-79 | 11 | [cwe-register.md](cwe-register.md) |
| CWE-328 | 8 | [cwe-register.md](cwe-register.md) |
| CWE-400 | 8 | [cwe-register.md](cwe-register.md) |
| CWE-118 | 5 | [cwe-register.md](cwe-register.md) |
| CWE-295 | 4 | [cwe-register.md](cwe-register.md) |
| CWE-918 | 4 | [cwe-register.md](cwe-register.md) |
| CWE-664 | 2 | [cwe-register.md](cwe-register.md) |
| CWE-200 | 1 | [cwe-register.md](cwe-register.md) |
| CWE-326 | 1 | [cwe-register.md](cwe-register.md) |
| CWE-601 | 1 | [cwe-register.md](cwe-register.md) |
| CWE-88 | 1 | [cwe-register.md](cwe-register.md) |

Every waived site carries its reason inline in source and in the register;
the dominant classes are test fixtures and operator-configured paths, which
is expected for a self-hosted control plane whose operators point it at
their own files and commands.

## Recorded not-applicable / covered by construction

| Class | Reason |
|---|---|
| CWE-120/121/122/787/416/476 (memory corruption) | Go's memory-safe runtime; no cgo in the served binaries. The remaining native surface is the bundled evaluation PostgreSQL binary (scanned by Trivy, external in production) and mlock/madvise syscalls on key buffers (AN-8). |
| CWE-89 (SQL injection) | All SQL goes through pgx parameterized queries; the tenantfilter analyzer additionally requires a tenant_id predicate on repository DML, and raw SQL against read models is rejected by the eventsource analyzer. |
| CWE-798 in production code (hardcoded credentials) | gitleaks scans full history; gosec G101 is clean; secrets ship as []byte via internal/crypto/secret with no string form (AN-8, keymaterial analyzer). |
| CWE-311/319 (missing encryption in transit) | TLS 1.3 minimums in internal/crypto/mtls; the signer speaks over a Unix domain socket or mTLS only (AN-4); plaintext listeners exist only for loopback liveness. |

