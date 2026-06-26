package docs

// PROTECT track (completeness slice): regression guards that LOCK confirmed
// strengths whose anchors were not yet pinned by docs/protect_guards_test.go.
// These add NO product behavior — each fails `go test ./docs/...` (the claim-drift
// gate) if the concrete source/CI/config/docs/web anchor a strength relies on stops
// being true. Every guard binds its finding ID(s) in the test name and a comment,
// asserts a meaningful anchor (not a trivially-true string), and runs fast WITHOUT
// embedded Postgres / NATS / network.
//
// Helpers `read` and `anyTestDeclaresUnder` are defined in the existing docs test
// package (docs/docs_test.go, docs/protect_guards_test.go) and are reused here.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/config"
)

// requireAllContained fails t for any wanted substring missing from body,
// attributing the failure to the given finding label and artifact. (Named distinctly
// from the existing docs_test.go containsAll(string,[]string)bool helper.)
func requireAllContained(t *testing.T, finding, artifact, body string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("%s: %s no longer contains %q; the confirmed strength's anchor regressed", finding, artifact, want)
		}
	}
}

// ---- SUPPLY-101: vulnerability scans are clean AND required ---------------------

// TestSupply101VulnScansStayRequired locks SUPPLY-101: the vulnerability/SCA scan
// surface must stay first-class. The Makefile must keep a `vuln` target (pinned
// govulncheck) and an `sca` target spanning Go + npm + the embedded-PostgreSQL
// runtime binary, and CI must keep running govulncheck, `npm audit`, and the
// embedded-postgres verify+Trivy receipt step. ELI5: "we scan for known-vulnerable
// code/deps" only means something if the scan commands cannot quietly fall out of
// the build.
func TestSupply101VulnScansStayRequired(t *testing.T) {
	mk := read(t, "../Makefile")
	requireAllContained(t, "SUPPLY-101", "Makefile", mk,
		".PHONY: vuln",
		"vuln: ## Reachability-aware vulnerability scan",
		"golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)",
		"$(GOVULNCHECK) ./...",
		".PHONY: sca",
		"npm audit --omit=dev --audit-level=high",
		"scripts/supply-chain/verify-embedded-postgres.sh",
	)

	ci := read(t, "../.github/workflows/ci.yml")
	requireAllContained(t, "SUPPLY-101", "ci.yml", ci,
		"govulncheck:",
		"go install golang.org/x/vuln/cmd/govulncheck@v1.1.4",
		"run: govulncheck ./...",
		"npm audit --omit=dev --audit-level=high",
		"Verify & scan the embedded-postgres binary",
		"run: bash scripts/supply-chain/verify-embedded-postgres.sh",
		"embedded-postgres-trivy-receipt",
	)
}

// ---- SUPPLY-102: WASM plugin provenance fails closed BEFORE instantiation -------

// TestSupply102PluginProvenanceVerifiesBeforeLoad locks SUPPLY-102: the served
// plugin admission path must verify provenance (signature + optional content pin)
// BEFORE the module is ever instantiated. The guard reads provenance.go and asserts
// (1) LoadVerified calls tp.Verify before h.Load (textual ordering), (2) Verify
// fails closed with no trusted key / no signature, and (3) the pin check precedes
// the signature check. ELI5: code the core team did not write must prove who signed
// it before it is allowed to run at all.
func TestSupply102PluginProvenanceVerifiesBeforeLoad(t *testing.T) {
	src := read(t, "../internal/pluginhost/provenance.go")

	requireAllContained(t, "SUPPLY-102", "internal/pluginhost/provenance.go", src,
		"func (h *Host) LoadVerified(",
		"func (tp *TrustPolicy) Verify(",
		"refusing to load unverified module (fail closed)",
		"module has no provenance signature; refusing to load",
		"is not in the pinned allowlist",
		"does not verify under any trusted key; refusing to load",
	)

	// Verify-before-Load ordering: in LoadVerified, the tp.Verify(...) call and its
	// fail-closed early return must appear before h.Load(...). If a refactor reorders
	// them (instantiate, then verify), this anchor breaks.
	lv := src[strings.Index(src, "func (h *Host) LoadVerified("):]
	verifyAt := strings.Index(lv, "tp.Verify(wasm, signature)")
	earlyReturn := strings.Index(lv, "return nil, err")
	loadAt := strings.Index(lv, "h.Load(ctx, wasm, grant)")
	if verifyAt < 0 || earlyReturn < 0 || loadAt < 0 {
		t.Fatal("SUPPLY-102: LoadVerified no longer verifies-then-loads; provenance gate may have moved")
	}
	if verifyAt >= earlyReturn || earlyReturn >= loadAt {
		t.Error("SUPPLY-102: LoadVerified must Verify (and fail closed) BEFORE h.Load; instantiation-before-verification would be a supply-chain bypass")
	}

	// Inside Verify, the content-pin rejection must come before the signature loop, so
	// a tampered/unknown artifact is rejected even if it were somehow signed.
	verifyBody := src[strings.Index(src, "func (tp *TrustPolicy) Verify("):]
	pinAt := strings.Index(verifyBody, "is not in the pinned allowlist")
	sigLoopAt := strings.Index(verifyBody, "crypto.VerifyEd25519(der, wasm, signature)")
	if pinAt < 0 || sigLoopAt < 0 || pinAt > sigLoopAt {
		t.Error("SUPPLY-102: Verify must apply the content pin before accepting any signature; pin-after-signature weakens the gate")
	}
}

// ---- SUPPLY-103: cosign signing + documented verification -----------------------

// TestSupply103CosignSigningAndVerifyDocsStayRequired locks SUPPLY-103: the release
// workflow must sign the image, attest the SBOM, and sign the packaged Helm chart
// (all keyless cosign), and the verify path must stay documented and scripted so an
// operator can check provenance before running. ELI5: signatures only help if the
// signing steps stay in the release pipeline and the "how to verify" instructions
// stay accurate.
func TestSupply103CosignSigningAndVerifyDocsStayRequired(t *testing.T) {
	rel := read(t, "../.github/workflows/release.yml")
	requireAllContained(t, "SUPPLY-103", "release.yml", rel,
		"sigstore/cosign-installer@",
		`cosign sign "${GHCR_IMAGE}@${digest}"`,
		`cosign attest --yes --predicate sbom.cyclonedx.json --type cyclonedx`,
		"anchore/sbom-action@",
		"format: cyclonedx-json",
		"id-token: write",                 // keyless OIDC signing
		`cosign sign "${repo}@${digest}"`, // helm chart OCI signature
	)

	script := read(t, "../scripts/verify-image.sh")
	requireAllContained(t, "SUPPLY-103", "scripts/verify-image.sh", script, "cosign verify")

	install := read(t, "../docs/install.md")
	requireAllContained(t, "SUPPLY-103", "docs/install.md", install,
		"scripts/verify-image.sh",
		"cosign verify",
		"keyless cosign signature",
		"SBOM attestation",
	)
}

// ---- SUPPLY-104: third-party Actions SHA-pinned + self-tested -------------------

// TestSupply104ThirdPartyActionsAreShaPinned locks SUPPLY-104: every external
// GitHub Action a workflow `uses:` must be pinned to a full 40-hex commit SHA (never
// a mutable tag), and the pin-check script + its self-test must stay wired into the
// lint gate. The guard re-derives the check directly over the committed workflows so
// it fails RED the moment any external action regresses to a floating tag. ELI5: a
// `@v4` tag can be silently repointed by a compromised upstream; an immutable SHA
// cannot, and our release jobs hold OIDC + packages:write.
func TestSupply104ThirdPartyActionsAreShaPinned(t *testing.T) {
	// The pin-check machinery must stay present and wired into `make lint`.
	requireAllContained(t, "SUPPLY-104", "scripts/ci/check-actions-pinned.sh",
		read(t, "../scripts/ci/check-actions-pinned.sh"),
		"offending_uses()", `sha_re='[0-9a-f]{40}'`, "SUPPLY-002")
	if _, err := os.Stat(filepath.FromSlash("../scripts/ci/check-actions-pinned_selftest.sh")); err != nil {
		t.Error("SUPPLY-104: check-actions-pinned_selftest.sh is missing; the pin checker is no longer self-tested")
	}
	mk := read(t, "../Makefile")
	requireAllContained(t, "SUPPLY-104", "Makefile lint gate", mk,
		"bash scripts/ci/check-actions-pinned_selftest.sh",
		"bash scripts/ci/check-actions-pinned.sh .",
	)

	// Independently re-derive the invariant: scan every workflow file and assert each
	// external `uses:` (owner/repo[/path]@ref; not ./local, not docker://) is pinned
	// to a 40-hex SHA. The only allowed tag is slsa-github-generator's official
	// generic reusable workflow, because upstream requires an exact vX.Y.Z tag and
	// rejects SHA refs. This is the load-bearing behavior, not just the script's text.
	sha := regexp.MustCompile(`^[0-9a-f]{40}$`)
	slsaGeneric := regexp.MustCompile(`^slsa-framework/slsa-github-generator/\.github/workflows/generator_generic_slsa3\.yml@v[0-9]+\.[0-9]+\.[0-9]+$`)
	usesLine := regexp.MustCompile(`(?m)^\s*-?\s*uses:\s*(.+)$`)
	wfDir := filepath.FromSlash("../.github/workflows")
	entries, err := os.ReadDir(wfDir)
	if err != nil {
		t.Fatalf("SUPPLY-104: cannot read workflows dir: %v", err)
	}
	external := 0
	for _, e := range entries {
		if e.IsDir() || (!strings.HasSuffix(e.Name(), ".yml") && !strings.HasSuffix(e.Name(), ".yaml")) {
			continue
		}
		body := read(t, filepath.Join("../.github/workflows", e.Name()))
		for _, m := range usesLine.FindAllStringSubmatch(body, -1) {
			val := strings.TrimSpace(m[1])
			if i := strings.Index(val, "#"); i >= 0 { // strip trailing version comment
				val = strings.TrimSpace(val[:i])
			}
			val = strings.Trim(val, `"'`)
			if strings.HasPrefix(val, "./") || strings.HasPrefix(val, "docker://") {
				continue // local / container action: out of scope
			}
			at := strings.LastIndex(val, "@")
			if at < 0 || !strings.Contains(val[:at], "/") {
				continue // not an owner/repo@ref third-party action
			}
			external++
			if slsaGeneric.MatchString(val) {
				continue
			}
			if ref := val[at+1:]; !sha.MatchString(ref) {
				t.Errorf("SUPPLY-104: %s pins third-party action %q by a mutable ref %q, not a 40-hex commit SHA", e.Name(), val[:at], ref)
			}
		}
	}
	if external == 0 {
		t.Error("SUPPLY-104: found no external `uses:` actions across workflows; the scan likely stopped matching and the guard is no longer meaningful")
	}
}

// ---- FUZZ-006: fuzz entry points + smoke gate + OSS-Fuzz build stay real --------

// TestFuzz006SmokeAndOSSFuzzStayReal locks FUZZ-006: real fuzz entry points exist
// under internal/, the Makefile keeps a `fuzz-smoke` target that discovers and runs
// every FuzzXxx, CI keeps running fuzz-smoke + the parser-coverage guard, and the
// ClusterFuzzLite (OSS-Fuzz) build is present. ELI5: fuzzing is only protection if
// the targets exist, the smoke run cannot be deleted from the build, and the
// continuous-fuzzing harness can actually compile the targets.
func TestFuzz006SmokeAndOSSFuzzStayReal(t *testing.T) {
	// Count real fuzz entry points (the audit denominator was 31; require a healthy
	// floor so deletions are caught while allowing additions).
	fuzzRE := regexp.MustCompile(`(?m)^func Fuzz[A-Za-z0-9_]+\(`)
	count := 0
	_ = filepath.WalkDir(filepath.FromSlash("../internal"), func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		count += len(fuzzRE.FindAll(b, -1))
		return nil
	})
	if count < 30 {
		t.Errorf("FUZZ-006: discovered only %d FuzzXxx entry points under internal/; expected at least the audited ~31", count)
	}

	mk := read(t, "../Makefile")
	requireAllContained(t, "FUZZ-006", "Makefile", mk,
		".PHONY: fuzz-smoke",
		"fuzz-smoke: ## Run every Go fuzz target",
		`grep -rEl '^func Fuzz[A-Za-z0-9_]+\(' --include='*_test.go' internal`,
		`-fuzz="^$$fn$$"`,
	)

	ci := read(t, "../.github/workflows/ci.yml")
	requireAllContained(t, "FUZZ-006", "ci.yml", ci,
		"make fuzz-smoke",
		"go test ./internal/crypto/ -run TestEveryUntrustedParserIsFuzzed -count=1",
	)

	// The continuous-fuzzing (ClusterFuzzLite / OSS-Fuzz) build must exist and compile
	// the discovered targets via compile_go_fuzzer.
	if _, err := os.Stat(filepath.FromSlash("../.clusterfuzzlite/project.yaml")); err != nil {
		t.Error("FUZZ-006: .clusterfuzzlite/project.yaml is missing; OSS-Fuzz build is no longer present")
	}
	requireAllContained(t, "FUZZ-006", ".clusterfuzzlite/build.sh", read(t, "../.clusterfuzzlite/build.sh"),
		"compile_go_fuzzer",
		`grep -rE '^func Fuzz[A-Za-z0-9_]+\(' --include='*_test.go' ./internal`,
	)
}

// ---- OPS-005: runtime config validation fails closed ----------------------------

// TestOps005ConfigValidationFailsClosed locks OPS-005: the unified config validator
// (config.Config.Validate) runs every sub-validator and is invoked on the load path
// before the process serves. The guard reads config.go to assert the validator
// aggregates the sub-validators and is called from Load, then EXECUTES the validator
// on deliberately-unsafe configs (no services, fully pure) to prove it actually
// rejects them. ELI5: a misconfigured deployment must fail to start, not boot into an
// unsafe state.
func TestOps005ConfigValidationFailsClosed(t *testing.T) {
	src := read(t, "../internal/config/config.go")
	requireAllContained(t, "OPS-005", "internal/config/config.go", src,
		"func (c *Config) Validate() error",
		"validateServerConfig",
		"validateDatastores",
		"validateSignerConfig",
		"validateServedSurfaces",
		"errors.Join(errs...)",
		"if err := cfg.Validate(); err != nil", // called on the load path before serving
	)

	// Behavioral proof #1: an invalid TLS mode must be rejected.
	bad := config.Default()
	bad.Server.TLS.Mode = "totally-invalid-mode"
	if err := bad.Validate(); err == nil {
		t.Error("OPS-005: Config.Validate accepted an invalid server.tls.mode; fail-closed validation regressed")
	}

	// Behavioral proof #2: an over-limit JetStream replication factor must be rejected.
	bad2 := config.Default()
	bad2.NATS.Mode = config.NATSExternal
	bad2.NATS.URL = "nats://example:4222"
	bad2.NATS.Replicas = 6 // JetStream max is 5
	if err := bad2.Validate(); err == nil {
		t.Error("OPS-005: Config.Validate accepted nats.replicas=6 (> JetStream max 5); fail-closed validation regressed")
	}

	// Behavioral proof #3: the shipped Default() config must itself be valid, so the
	// fail-closed validator is not vacuously rejecting everything.
	if err := config.Default().Validate(); err != nil {
		t.Errorf("OPS-005: Config.Default() no longer validates clean: %v", err)
	}
}

// ---- TEST-008: fuzz smoke + policy/query property slices ------------------------

// TestTest008PropertyAndFuzzSmokeSlicesStayRequired locks TEST-008: the policy
// engine keeps its property/invariant tests, the store keeps its tenant-scope query
// markers tested, and the `make fuzz-smoke` target stays present. ELI5: the parts of
// the system where a subtle logic bug is most dangerous (policy decisions, tenant
// query scoping, untrusted parsers) keep their generative/property coverage.
func TestTest008PropertyAndFuzzSmokeSlicesStayRequired(t *testing.T) {
	// Policy property/invariant slice.
	for _, name := range []string{
		"TestPolicyInvariantsBaseModule",
		"TestPolicyNeverPanicsOnArbitraryInput",
		"TestPolicyProfileMonotonicity",
	} {
		if !anyTestDeclaresUnder(t, "../internal/policy", name) {
			t.Errorf("TEST-008: internal/policy no longer declares %s; the policy property slice regressed", name)
		}
	}
	if _, err := os.Stat(filepath.FromSlash("../internal/policy/property_test.go")); err != nil {
		t.Error("TEST-008: internal/policy/property_test.go is missing; the policy property slice file was removed")
	}

	// Store tenant-scope query slice: system-query markers stay explained/tested.
	for _, name := range []string{
		"TestSystemQueryMarkersExplainTenantExposure",
		"TestBootstrapTokenRedeemIsMarkedSystemQueryAndSingleUse",
	} {
		if !anyTestDeclaresUnder(t, "../internal/store", name) {
			t.Errorf("TEST-008: internal/store no longer declares %s; the tenant-scope query slice regressed", name)
		}
	}

	// Fuzz-smoke target must stay present (shared with FUZZ-006, asserted here for the
	// TEST-008 binding so this finding fails independently).
	requireAllContained(t, "TEST-008", "Makefile", read(t, "../Makefile"),
		".PHONY: fuzz-smoke", "fuzz-smoke: ## Run every Go fuzz target")
}

// ---- TEST-009: CI spans a broad quality surface ---------------------------------

// TestTest009CISpansBroadQualitySurface locks TEST-009: the CI workflow keeps its
// broad set of quality jobs — Go build/test/lint, fuzz smoke, chaos, frontend
// audit/typecheck/test/build, docs, actionlint, action-pin, and govulncheck. ELI5: a
// security product's CI must keep testing many dimensions; this guard fails if a
// whole class of checks is quietly dropped.
func TestTest009CISpansBroadQualitySurface(t *testing.T) {
	ci := read(t, "../.github/workflows/ci.yml")
	requireAllContained(t, "TEST-009", "ci.yml jobs/steps", ci,
		"build-test-lint:",        // Go build + test + lint job
		"fuzz:",                   // fuzz smoke job
		"make fuzz-smoke",         // ... actually runs the smoke
		"chaos:",                  // fault-injection job
		"make chaos",              // ... actually runs chaos
		"web:",                    // frontend job
		"npm audit",               // frontend SCA
		"npm run typecheck",       // frontend typecheck
		"npm run test",            // frontend tests
		"npm run build",           // frontend build
		"docs:",                   // docs job
		"actionlint:",             // workflow lint job
		"check-actions-pinned.sh", // action-pin check
		"govulncheck:",            // vulnerability scan job
	)
}

// ---- CODE-103: embedded C EST client safety tests -------------------------------

// TestCode103EmbeddedESTClientSafetyStaysGuarded locks CODE-103: the reference C EST
// client validates path/host args against a conservative allow-list before shelling
// out via system(), and caps the response size (failing closed on overflow rather
// than decoding a truncated chain). The guard asserts both anchors in the .c source
// and that the Go test exercises the oversize-response and shell-injection rejections.
// ELI5: a constrained device's enroll client must not let a crafted workdir/host
// inject shell commands, and must not silently accept a truncated certificate chain.
func TestCode103EmbeddedESTClientSafetyStaysGuarded(t *testing.T) {
	csrc := read(t, "../clients/embedded/csrc/est_client.c")
	requireAllContained(t, "CODE-103", "clients/embedded/csrc/est_client.c", csrc,
		"static int safe_path_arg(const char *s)",
		"c == '-' || c == '.' || c == '_' || c == '/' || c == ':' || c == '@'", // allow-list charset
		"refusing unsafe workdir",
		"refusing unsafe host",
		"if (!safe_path_arg(wd))",   // workdir validated before interpolation
		"if (!safe_path_arg(host))", // parsed host validated before use
		"const size_t RESP_CAP",     // response size cap
		"response too large",        // fail-closed on overflow
		"refusing to decode a truncated certificate chain",
	)

	test := read(t, "../clients/embedded/est_client_test.go")
	requireAllContained(t, "CODE-103", "clients/embedded/est_client_test.go", test,
		"func TestEmbeddedESTClientRejectsOversizedResponse(",
		"func TestEmbeddedESTClientRejectsShellInjectionWorkdir(",
		"unsafe workdir",
	)
}

// ---- CODE-104: build target covers all binaries + vuln gate ---------------------

// TestCode104BuildAndVulnTargetsStayDefined locks CODE-104: the Makefile `build`
// target builds all five product binaries, and the `vuln` gate exists. The guard
// asserts the binary list and build loop, plus the vuln target — without running a
// full build. ELI5: "it builds and passes the vuln scan" is only durable if the
// build target keeps enumerating every binary and the scan target stays defined.
func TestCode104BuildAndVulnTargetsStayDefined(t *testing.T) {
	mk := read(t, "../Makefile")
	requireAllContained(t, "CODE-104", "Makefile", mk,
		"CMDS    := trstctl trstctl-signer trstctl-agent trstctl-operator trstctl-cli",
		".PHONY: build",
		"build: ## Build all binaries",
		"for cmd in $(CMDS); do",
		"$(GO_BUILD) -o $(BIN_DIR)/$$cmd ./cmd/$$cmd",
		".PHONY: vuln",
		"$(GOVULNCHECK) ./...",
	)
	// Each named binary must have a real cmd/ entrypoint, so the build list is not stale.
	for _, bin := range []string{"trstctl", "trstctl-signer", "trstctl-agent", "trstctl-operator", "trstctl-cli"} {
		if _, err := os.Stat(filepath.FromSlash("../cmd/" + bin)); err != nil {
			t.Errorf("CODE-104: cmd/%s is missing but the Makefile build list still names it", bin)
		}
	}
}

// ---- COVER-011 / TRACE-012: REST/CLI/OpenAPI parity spine -----------------------

// TestCover011Trace012RestCliOpenAPIParitySpineStaysRequired locks COVER-011 and
// TRACE-012: the platform keeps a central API route registry (internal/api.Routes +
// the `route` struct) and a CLI command registry (internal/cli.commandTable, one
// command per core API op), and the parity/golden tests that bind REST<->CLI<->
// OpenAPI stay present. The guard asserts the registries and the test names exist;
// it does NOT run the heavy tests. ELI5: the API, CLI, and published contract are
// generated from one source of truth and proven to stay in lockstep.
func TestCover011Trace012RestCliOpenAPIParitySpineStaysRequired(t *testing.T) {
	api := read(t, "../internal/api/api.go")
	requireAllContained(t, "COVER-011/TRACE-012", "internal/api/api.go", api,
		"func (a *API) Routes() []Route",
		"type route struct",
		"mux             *http.ServeMux",
	)

	cmd := read(t, "../internal/cli/command.go")
	requireAllContained(t, "COVER-011/TRACE-012", "internal/cli/command.go", cmd,
		"var commandTable = []Command{",
		"is one command per core API operation",
		`Path: "/api/v1/owners"`,
		`Path: "/api/v1/identities/{id}/transitions"`,
	)

	// Parity / golden tests must still exist (anchor on names, do not execute them).
	mustDeclare := []struct{ root, name string }{
		{"../internal/cli", "TestEveryAPIOperationHasACLICommand"},
		{"../internal/api", "TestOpenAPIGolden"},
		{"../internal/api", "TestNoManualAPIV1MuxRoutesBypassOpenAPI"},
		{"../internal/api", "TestOpenAPISpecCoversRoutes"},
	}
	for _, m := range mustDeclare {
		if !anyTestDeclaresUnder(t, m.root, m.name) {
			t.Errorf("COVER-011/TRACE-012: %s no longer declares %s; REST/CLI/OpenAPI parity proof regressed", m.root, m.name)
		}
	}
}

// ---- COVER-012 / TRACE-014: limitations doc separates served vs library ----------

// TestCover012Trace014LimitationsSeparatesServedVsLibrary locks COVER-012 and the
// docs half of TRACE-014: docs/limitations.md must keep separating what the running
// binary serves today from what is built-and-tested library code but not yet served,
// using that explicit vocabulary, and must keep the tenant-offboarding boundary
// section. ELI5: the docs must not blur "you can use this in the product" with "this
// exists as a Go package"; buyers rely on that honest line.
func TestCover012Trace014LimitationsSeparatesServedVsLibrary(t *testing.T) {
	lim := read(t, "../docs/limitations.md")
	requireAllContained(t, "COVER-012/TRACE-014", "docs/limitations.md", lim,
		"## Served by the running binary today",
		"## Built and tested, but not yet served by the binary",
		"library code",
		"not yet wired into the served API",
		"Tenant offboarding boundary",
	)
	low := strings.ToLower(lim)
	for _, vocab := range []string{"library-only", "phase 2"} {
		if !strings.Contains(low, vocab) {
			t.Errorf("COVER-012/TRACE-014: docs/limitations.md no longer uses the %q tier vocabulary", vocab)
		}
	}
}

// ---- COVER-013: arch-linter fixtures pass ---------------------------------------

// TestCover013ArchLinterFixturesStayPresent locks COVER-013: the architecture linter
// keeps planted-violation fixtures and an analysistest harness for each of its five
// rules (crypto-import boundary, idempotency, key-material, tenant-filter, event
// sourcing). The guard asserts each analyzer dir has a _test.go and a testdata tree,
// and that main.go wires all five analyzers. ELI5: the linter that enforces our
// architecture is itself tested against deliberately-bad code, so it cannot silently
// stop catching violations.
func TestCover013ArchLinterFixturesStayPresent(t *testing.T) {
	for _, analyzer := range []string{"cryptoboundary", "idempotency", "keymaterial", "tenantfilter", "eventsource"} {
		dir := filepath.FromSlash("../tools/trstctllint/" + analyzer)
		if _, err := os.Stat(filepath.Join(dir, "testdata")); err != nil {
			t.Errorf("COVER-013: tools/trstctllint/%s/testdata is missing; planted-fixture coverage regressed", analyzer)
		}
		if _, err := os.Stat(filepath.Join(dir, analyzer+"_test.go")); err != nil {
			t.Errorf("COVER-013: tools/trstctllint/%s/%s_test.go is missing; the analyzer is no longer fixture-tested", analyzer, analyzer)
		}
	}

	main := read(t, "../tools/trstctllint/main.go")
	requireAllContained(t, "COVER-013", "tools/trstctllint/main.go", main,
		"cryptoboundary.Analyzer",
		"idempotency.Analyzer",
		"keymaterial.Analyzer",
		"tenantfilter.Analyzer",
		"eventsource.Analyzer",
	)
}

// ---- JOURNEY-005: core issue/revoke surfaces are real + route parity tested ------

// TestJourney005IssueFlowAndRouteParityStayWired locks JOURNEY-005: the web client
// keeps the chained owner->identity->issue convenience (issueCertificate creates an
// owner, creates the identity, and transitions it to "issued"), and the route-parity
// proof (web availability copy backed by OpenAPI + CLI) stays present. ELI5: the UI's
// "issue a certificate" button really walks the full backend lifecycle, and a test
// proves the UI's claims about what's available match the served contract.
func TestJourney005IssueFlowAndRouteParityStayWired(t *testing.T) {
	apiTS := read(t, "../web/src/lib/api.ts")
	requireAllContained(t, "JOURNEY-005", "web/src/lib/api.ts", apiTS,
		"issueCertificate",
		"api.createOwner(",
		"api.createIdentity(",
		`api.transitionIdentity(identity.id, "issued"`,
		`mutate<Identity>("POST", `+"`/api/v1/identities/${encodeURIComponent(id)}/transitions`",
	)

	// Route-parity proof must still exist (the docs-side parity test that binds web
	// availability copy to the served OpenAPI + CLI).
	if !anyTestDeclaresUnder(t, ".", "TestWebAvailabilityCopyIsBackedByOpenAPIAndCLI") {
		t.Error("JOURNEY-005: docs no longer declare TestWebAvailabilityCopyIsBackedByOpenAPIAndCLI; web<->served route parity proof regressed")
	}
	if !anyTestDeclaresUnder(t, "../internal/cli", "TestEveryAPIOperationHasACLICommand") {
		t.Error("JOURNEY-005: internal/cli no longer declares TestEveryAPIOperationHasACLICommand; API<->CLI parity proof regressed")
	}
}

// ---- JOURNEY-006 / TRACE-014: console discloses library-only gaps honestly -------

// TestJourney006Trace014ConsoleDisclosesLibraryGaps locks JOURNEY-006 and the UI half
// of TRACE-014: the console keeps explicit "unavailable / not served yet" disclosures
// instead of pretending a not-yet-served feature is live, while shipped platform
// features name the operating model instead of stale roadmap language. The guard
// asserts the shared UnavailableState primitive exists, the Platform page renders
// shipped passive federation language plus other not-served platform reads, the
// Discovery page renders a Discovery-unavailable state, and the Connectors page
// discloses it is read evidence (not a deploy button). ELI5: when the binary can't
// do something yet, the UI says so plainly; when the binary can do it, the UI names
// exactly how it works.
func TestJourney006Trace014ConsoleDisclosesLibraryGaps(t *testing.T) {
	// Shared disclosure primitive.
	requireAllContained(t, "JOURNEY-006/TRACE-014", "web/src/components/StatePrimitives.tsx",
		read(t, "../web/src/components/StatePrimitives.tsx"),
		"UnavailableState")

	platform := read(t, "../web/src/pages/Platform.tsx")
	requireAllContained(t, "JOURNEY-006/TRACE-014", "web/src/pages/Platform.tsx", platform,
		"UnavailableState",
		"not served yet",
		"Passive-read-state model",
		"served worker",
		"one writable region per tenant",
	)

	discovery := read(t, "../web/src/pages/Discovery.tsx")
	requireAllContained(t, "JOURNEY-006/TRACE-014", "web/src/pages/Discovery.tsx", discovery,
		"Discovery unavailable")

	connectors := read(t, "../web/src/pages/Connectors.tsx")
	requireAllContained(t, "JOURNEY-006/TRACE-014", "web/src/pages/Connectors.tsx", connectors,
		"read evidence, not a deploy button")
}

// ---- VERIFY-004: strict appendices + no fabricated citations (in-repo anchor) ----

// TestVerify004CorpusCitationIntegrityAnchorStaysRequired pins the in-repo evidence
// VERIFY-004 relies on. VERIFY-004 itself is a property of the audit kit
// (trstctl-audit), which this repo must NOT modify; the in-repo control that makes it
// checkable is the corpus verifier (scripts/audit/verify-corpus.mjs, wired as `make
// audit-verify`), which checks that every sampled citation opens its cited file and
// that strict machine-readable appendices cover all tracked files. The pre-existing
// TestVerifyAuditCorpusGuardStayRequired locks the verifier's score/severity anchors;
// this guard locks the COMPLEMENTARY citation-integrity + tracked-file-coverage
// anchors under the VERIFY-004 name so the coordinator has an explicit VERIFY-004
// lock. ELI5: "no made-up citations and the appendices cover every file" stays a real
// runnable check, not a claim.
func TestVerify004CorpusCitationIntegrityAnchorStaysRequired(t *testing.T) {
	mk := read(t, "../Makefile")
	requireAllContained(t, "VERIFY-004", "Makefile audit-verify target", mk,
		".PHONY: audit-verify",
		"node scripts/audit/verify-corpus.mjs",
	)

	verifier := read(t, "../scripts/audit/verify-corpus.mjs")
	requireAllContained(t, "VERIFY-004", "scripts/audit/verify-corpus.mjs", verifier,
		"verifyCitations(allFindings)",     // every sampled citation is opened/checked
		"fabricated_or_drifted_citations=", // the fabrication counter is reported
		"0 DRIFTED, 0 FABRICATED",          // clean-state assertion the verifier enforces
	)
}

// ---- TRACE-013: protocol-server traceability -----------------------------------

// TestTrace013ProtocolMountsStayTraceable locks TRACE-013: the server mounts every
// served protocol (ACME, EST, SCEP, CMP, SSH, TSA on the HTTP mux; SPIFFE on its UDS),
// the central mount-pattern function keeps the concrete path patterns, and the served
// protocol end-to-end tests stay present. ELI5: each issuance protocol the product
// claims to serve is wired to a real route and proven by an end-to-end test.
func TestTrace013ProtocolMountsStayTraceable(t *testing.T) {
	mounts := read(t, "../internal/server/protocol_mounts.go")
	requireAllContained(t, "TRACE-013", "internal/server/protocol_mounts.go", mounts,
		`protocolHTTPMountPatterns("acme")`,
		`protocolHTTPMountPatterns("est")`,
		`protocolHTTPMountPatterns("scep")`,
		`protocolHTTPMountPatterns("cmp")`,
		`protocolHTTPMountPatterns("tsa")`,
		`protocolHTTPMountPatterns("ssh")`,
		"sp.spiffe", // SPIFFE protocol assembled (run on UDS, not the HTTP mux)
	)

	patterns := read(t, "../internal/server/protocol_authz.go")
	requireAllContained(t, "TRACE-013", "internal/server/protocol_authz.go (mount patterns)", patterns,
		`return []string{"/directory", "/acme/"}`,
		`return []string{"/.well-known/est/"}`,
		`return []string{"/scep", "/scep/"}`,
		`return []string{"/cmp"}`,
		`return []string{"/ssh/"}`,
		`return []string{"/tsa"}`,
	)

	// Served protocol end-to-end tests must still exist.
	for _, name := range []string{
		"TestServedACMEEndToEnd",
		"TestServedESTEndToEnd",
		"TestServedSCEPEndToEnd",
		"TestServedCMPEndToEnd",
		"TestServedSPIFFEWorkloadAPIEndToEnd",
		"TestServedSSHEndToEnd",
		"TestServedTSAOpenSSLTimestampOverHTTP",
	} {
		if !anyTestDeclaresUnder(t, "../internal/server", name) {
			t.Errorf("TRACE-013: internal/server no longer declares %s; served-protocol traceability proof regressed", name)
		}
	}
}

// ---- PRODUCT-008: UI accessibility foundations ----------------------------------

// TestProduct008AppShellA11yFoundationsStayPresent locks PRODUCT-008: the
// authenticated app shell keeps its accessibility foundations — a labeled primary
// navigation landmark, a skip link targeting the main region, a focusable main
// landmark, and visible focus styling. ELI5: keyboard and screen-reader users keep a
// way to skip the nav and land on content, and the nav announces what it is.
func TestProduct008AppShellA11yFoundationsStayPresent(t *testing.T) {
	shell := read(t, "../web/src/components/AppShell.tsx")
	requireAllContained(t, "PRODUCT-008", "web/src/components/AppShell.tsx", shell,
		"<nav aria-label=",             // labeled navigation landmark
		`href="#main"`,                 // skip link target
		"sr-only focus:not-sr-only",    // visually-hidden-until-focused skip link
		`{t("app.skipToMain")}`,        // skip-link label
		`<main id="main"`,              // main landmark with matching id
		"tabIndex={-1}",                // main is programmatically focusable
		"focus:ring-2 focus:ring-ring", // visible focus styling
	)
}

// ---- PRODUCT-009: platform/API doc claims are backed by the served surface -------

// TestProduct009PlatformApiDocClaimsAreBacked locks PRODUCT-009: the platform-and-API
// feature doc keeps describing the single-source ServeMux + OpenAPI 3.1 + CLI table,
// problem+json errors, Idempotency-Key on mutations, and cursor pagination — AND those
// claims stay backed by the served code (the CLI command table carries cursor query
// params; the API exposes the OpenAPI spec route). ELI5: the doc's promises about how
// the platform behaves are kept honest by pointing at the code that implements them.
func TestProduct009PlatformApiDocClaimsAreBacked(t *testing.T) {
	doc := read(t, "../docs/features/platform-and-api.md")
	low := strings.ToLower(doc)
	for _, claim := range []string{
		"servemux",
		"openapi 3.1",
		"application/problem+json",
		"idempotency-key",
		"cursor",
	} {
		if !strings.Contains(low, claim) {
			t.Errorf("PRODUCT-009: docs/features/platform-and-api.md no longer documents %q", claim)
		}
	}

	// Backed by code: the CLI command table uses cursor pagination on list ops, and the
	// API serves the OpenAPI document.
	cmd := read(t, "../internal/cli/command.go")
	if !strings.Contains(cmd, `Query: []string{"limit", "cursor"}`) {
		t.Error("PRODUCT-009: internal/cli command table no longer uses cursor pagination; the doc claim is unbacked")
	}
	api := read(t, "../internal/api/api.go")
	if !strings.Contains(api, "openapi") && !strings.Contains(strings.ToLower(api), "openapi") {
		t.Error("PRODUCT-009: internal/api no longer references the OpenAPI document; the doc claim is unbacked")
	}
}

// ---- PRIVACY-007: tenant offboarding erases tenant-scoped rows ------------------

// TestPrivacy007TenantOffboardingErasesTenantRows locks PRIVACY-007: the store keeps
// the authoritative TenantScopedTables list and the OffboardTenant primitive, which
// deletes every tenant-scoped row under the tenant's RLS context, then re-counts and
// FAILS CLOSED if any row survives. The guard reads offboard.go and asserts the table
// list is non-trivial, the delete loop and the fail-closed verify pass exist, and an
// empty tenant id is rejected. ELI5: "we can erase a tenant's data" is durable only if
// the erase enumerates every table and refuses to report success on a partial wipe.
func TestPrivacy007TenantOffboardingErasesTenantRows(t *testing.T) {
	src := read(t, "../internal/store/offboard.go")
	requireAllContained(t, "PRIVACY-007", "internal/store/offboard.go", src,
		"var TenantScopedTables = []string{",
		"func (s *Store) OffboardTenant(",
		`"DELETE FROM "+table+" WHERE tenant_id = $1"`,          // per-table tenant-scoped delete
		`"SELECT count(*) FROM "+table+" WHERE tenant_id = $1"`, // re-count verify pass
		"offboard incomplete",                                   // fail-closed message
		"OffboardTenant requires a tenant id",                   // empty-tenant rejection (no fail-open)
		"att.Complete = true",
	)

	// The TenantScopedTables list must be a meaningful set including the high-value
	// tenant-scoped stores (certs, sealed secrets, SSH keys, CA state) and end with the
	// tenant's own row. A trivially-short list would be a regression.
	for _, table := range []string{
		`"certificates"`, `"secret_store"`, `"ssh_keys"`, `"ca_authorities"`,
		`"identities"`, `"owners"`, `"outbox"`, `"idempotency_keys"`, `"tenants"`,
	} {
		if !strings.Contains(src, table) {
			t.Errorf("PRIVACY-007: TenantScopedTables no longer includes %s; tenant erasure would leave that table's rows behind", table)
		}
	}
}
