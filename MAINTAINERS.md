# Maintaining trstctl

This file is the transfer document: what a new maintainer needs in their head
to own this repository, written for someone who did not build it. `README.md`
states the contract; this states the *operational* knowledge — why the gates
exist, what breaks when you touch which tree, and how to debug a red pipeline
without archaeology.

If you are here because you inherited this codebase: read `README.md` first,
then this, then `docs/design/architecture-invariants.md`. That is roughly two
hours and covers everything load-bearing.

## The mental model in one paragraph

trstctl is an event-sourced control plane for non-human credentials. A request
mutates state by appending an **event**; projections build the relational read
model from that log; anything that touches the outside world (a CA, a
connector, a webhook) writes its intent to an **outbox** row in the same
transaction and a worker performs it later. Tenant isolation is PostgreSQL
row-level security, not application `if` statements. All cryptography enters
through one package (`internal/crypto`) and private keys live in a **separate
signing process** the control plane can call but never inspect. Commercial code
lives under `ee/` behind an offline license check applied at exactly two
tagged attach seams. Every one of those sentences is enforced by a test or a
linter, which is why the invariants have survived.

## The architecture linter is the load-bearing tool

`tools/trstctllint` is a custom `go/analysis` multichecker. It exists because
the invariants are the kind that decay silently: one `crypto/rand` import in a
handler, one query missing `tenant_id`, and the property is gone with no
symptom until an incident. The analyzers:

| Analyzer | Invariant | What it fails on |
| --- | --- | --- |
| `cryptoboundary` | AN-3 | a `crypto/*` import outside `internal/crypto` |
| `tenantfilter` | AN-1 | a repository query with no `tenant_id` filter |
| `keymaterial` | AN-8 | `string`-typed key material in a key-handling package |
| `idempotency` | AN-5 | a mutating handler that does not thread an idempotency key |
| `eventsource` | AN-2 | a served mutation writing the read model directly |
| `cryptoagility` | PQC-00 | a runtime plugin/provider registry growing inside crypto |
| `netexec` | SEC-005 | a new HTTP/exec surface bypassing the SSRF-safe client |
| `licenseboundary` | AN-9 / PACKAGING-007 | SPDX drift or a core→`ee/` import |

Run it standalone (`go run ./tools/trstctllint ./...`) or as a vettool, which
is what `make lint` does. **There is deliberately no per-line suppression** —
no `//nolint`, no ignore file. A false positive is fixed in the rule with a
test fixture under the analyzer's `testdata/`, which keeps the rule honest and
the exceptions reviewable. `repo_selftest_test.go` runs the analyzers over the
real tree, so a rule that stops matching anything is itself a failure.

Extending it: copy the shape of an existing analyzer package, add it to the
multichecker list in `main.go`, add a `testdata/src/...` fixture for both the
positive and the negative case, and document the rule in `doc.go` and
`README.md` (a docs test asserts they stay in sync).

Three invariants have **no analyzer** and lean on tests instead — AN-4 (signer
isolation), AN-6 (same-transaction outbox), and AN-7 (bounded pools). This
asymmetry is deliberate: "the enqueue happened in the same transaction as the
state change" is not reasonably lintable. It also means changes in those areas
carry more risk than the linter's silence suggests. Touching signer wiring
means running `cmd/trstctl-signer/core_boundary_test.go` (a dependency-closure
test: the signer must not link SQL, HTTP, or heavy dependencies) and the
integration tests around the outbox dispatcher.

## Where the danger is

**`internal/crypto`** — the only package that may import `crypto/*`. Parsers
here take untrusted bytes and are fuzzed with committed corpora. Never add a
second path; add a backend. Ask before changing key custody (HSM/KMS
placement).

**`cmd/trstctl-signer` and `internal/signing`** — if this process is
compromised, the company is over. It has no HTTP server, no SQL driver, and a
minimal audited transport. In single-binary mode it still runs as a separate
child process. Anything that would give it a new dependency deserves a
conversation before a PR.

**`internal/store`** — RLS policies live here. A cross-tenant query is
sometimes legitimate (a scheduler enumerating tenants), and those are marked
with a `//trstctl:system-query` comment explaining why; the linter honors the
marker, so the marker is where the review attention belongs.

**The two attach seams** — `cmd/trstctl/ee_attach.go` and
`cmd/trstctl-signer/ee_attach.go`. These are the *only* files where core may
reference `ee/`, each with a `//go:build !trstctl_core` tag and a `*_core.go`
twin. License checks belong here, one block per feature — never scattered
`lic.Has()` calls in handlers. The core families (PCAS, AGID, XREC, VDEC, PQC)
are not licensed: they attach in every build through the untagged
`cmd/*/attach_families.go` files and `cmd/trstctl-agent/cosign_attach.go`,
which import nothing from `ee/`. The core-only build must link zero `ee/`
packages; that is a test, not a hope.

## The gate map

`make lint test` is the local gate. CI runs ~40 jobs; these are the ones whose
failures mean something specific:

- **`build / test / lint`** — the main suite plus coverage floors. Coverage is
  a signal, not a target, but the floors are enforced.
- **`definition of done / wiring census`** — proves each claimed capability is
  actually reachable in the shipped binary. If you add a feature and this goes
  red, the feature is library-only and the census is telling the truth.
- **Protocol conformance jobs** (`acme`, `est`, `cmp`, `scep`, `tsa`, `spiffe`)
  — differential tests against real reference clients (Pebble, certbot, libest,
  OpenSSL, sscep, go-spiffe). A red one usually means a wire-format change, not
  a flake.
- **`pqc e2e (dodproof)`** — the post-quantum proofs against the shipped
  artifact. Requires a runner with OpenSSL ≥ 3.5 for ML-DSA; it fails loudly
  rather than skipping if the runner lacks it.
- **`kubernetes / kind e2e`** and **`spire container e2e`** — real cert-manager
  and real SPIRE containers. Slow, occasionally infrastructure-flaky; read the
  diagnostics step before assuming a product bug.
- **`reproducible build`** — byte-identical rebuild. Breaks when a build stamps
  something non-deterministic (a timestamp, a path) into the binary.
- **`govulncheck`** and the license audit beside it — dependency CVEs and
  copyleft contamination of the shipped binaries.

`.github/branch-protection.json` is the in-repo source of truth for which
checks are required, kept in sync with the workflow by a docs test, so a
renamed job cannot silently drop out of the required set.

## Release

Tags drive `.github/workflows/release.yml`: the container image, the Windows
agent (Authenticode-signed via a remote HSM signer), the Helm chart (cosign
keyless), the SPIRE upstream-authority plugin, the Terraform provider in
Registry layout, and the Python SDK — each with SLSA provenance and each gated
on the test and required-checks jobs. Publishing steps that need credentials
(Terraform GPG key, PyPI token) live in protected GitHub environments and
**fail loudly when unset** rather than skipping, so a release cannot quietly
ship less than it claims.

## Docs are tested

`docs/*_test.go` greps exact phrases in the reader-facing pages: served-state
claims, required-check names, feature IDs. Grep before rewording, and never
split a guarded phrase across a line wrap. `docs/limitations.md` is the
canonical served-vs-library statement and the first place to update when
capability status changes — it is also the artifact that makes diligence go
well, so keep it honest even when a claim would look better rounded up.

## Bus factor

This file, `README.md`, `docs/design/architecture-invariants.md`, and the nine
runbooks under `docs/runbooks/` are the transfer set. The runbooks cover the
operations a maintainer will actually be paged for: signer recovery, key
ceremony, disaster-recovery drill, outbox dead letters, fleet rollout and
rollback, upgrade rollback, incident response, and PCAS operations. If you
learn something operationally load-bearing that is not written down here, that
is the bug — write it down in the same change.
