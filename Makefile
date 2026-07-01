# trstctl --- build, test, lint, run.
#
# Reproducible builds: -trimpath strips local filesystem paths, CGO is disabled
# for the shipped binaries, and version metadata is derived from git (with safe
# fallbacks) and injected via -ldflags so that rebuilding the same commit yields
# identical binaries. The architecture linter (tools/trstctllint) is part of
# `make lint` so architecture drift fails locally and in CI.

SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

MODULE  := trstctl.com/trstctl
BIN_DIR := bin
CMDS    := trstctl trstctl-signer trstctl-agent trstctl-operator trstctl-cli terraform-provider-trstctl trstctl-license

GO          ?= go
CGO_ENABLED ?= 0

# Version metadata, git-derived with fallbacks so builds work outside a checkout.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo none)
# Commit timestamp in strict ISO-8601; sourced from the commit (not wall-clock)
# so the build is reproducible regardless of when or where it runs.
DATE    ?= $(shell git show -s --format=%cI HEAD 2>/dev/null || echo unknown)

BUILDINFO := $(MODULE)/internal/buildinfo
LICENSEINFO := $(MODULE)/internal/license
LICENSE_KEYS_B64 ?=
LDFLAGS   := -s -w \
	-X $(BUILDINFO).version=$(VERSION) \
	-X $(BUILDINFO).commit=$(COMMIT) \
	-X $(BUILDINFO).date=$(DATE) \
	-X $(LICENSEINFO).builtinPubKeysB64=$(LICENSE_KEYS_B64)
GO_BUILD  := CGO_ENABLED=$(CGO_ENABLED) $(GO) build -trimpath -ldflags '$(LDFLAGS)'
# npm installs may include Go helper packages inside web/node_modules. web/ is
# gated by npm scripts; Go gates enumerate first-party Go roots by construction.
GO_PACKAGES ?= ./clients/... ./cmd/... ./deploy/... ./docs/... ./internal/... ./scripts/... ./tools/...
GO_COVER_PACKAGES ?= ./clients/...,./cmd/...,./deploy/...,./docs/...,./internal/...,./scripts/...,./tools/...
GO_PACKAGE_DIRS ?= $(GO_PACKAGES)

GOLANGCI_LINT_VERSION ?= v2.12.2
ACTIONLINT_VERSION ?= v1.7.7
# Supply-chain tooling, pinned so the vulnerability gate and SBOM are deterministic.
GOVULNCHECK_VERSION ?= v1.1.4
CYCLONEDX_GOMOD_VERSION ?= v1.7.0
GO_ENV_GOBIN := $(shell $(GO) env GOBIN)
GO_ENV_GOPATH := $(shell $(GO) env GOPATH)
GO_TOOL_BIN ?= $(if $(GO_ENV_GOBIN),$(GO_ENV_GOBIN),$(GO_ENV_GOPATH)/bin)
GOVULNCHECK := $(GO_TOOL_BIN)/govulncheck
CYCLONEDX_GOMOD := $(GO_TOOL_BIN)/cyclonedx-gomod
WEB_NPM ?= npm --prefix web

# Minimum total test coverage (percent), enforced by `make test`. Generated code
# (*.pb.go) is excluded from the measurement.
COVERAGE_MIN ?= 70
COVERPROFILE := cover.out
AUDIT_OUTPUTS ?= ../trustctl-audit/outputs

# Minimum coverage (percent) for the assembled control plane's core lifecycle
# functions (server.Build / IssueLeaf / Drain / Shutdown). These are exercised by
# the cross-package projections e2e, so the in-package figure badly understates
# them (Build/Drain/Shutdown read 0% measured in-package); the merged -coverpkg
# profile shows their real ~80-100%. This floor surfaces and guards that real
# number so CI reports the assembled server honestly, not the misleading 15%
# in-package figure (R4.3).
SERVER_FUNC_COVERAGE_MIN ?= 70
SERVER_LIFECYCLE_FUNCS := Build|IssueLeaf|Drain|Shutdown

# Minimum coverage (percent) that EACH security-critical package must independently
# meet — a stronger bar than the single aggregate COVERAGE_MIN above, which a
# critical package can hide behind when the average passes. Computed from the same
# merged -coverpkg profile, so it counts coverage delivered by cross-package
# integration tests. Enforced by `make test` and the CI coverage gate (SF.1).
CRITICAL_COVERAGE_MIN ?= 70

.PHONY: help
help: ## Show this help
	@awk 'BEGIN{FS=":.*##"; printf "Usage: make <target>\n\nTargets:\n"} /^[a-zA-Z0-9_.-]+:.*?##/{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build
build: ## Build all binaries into ./bin
	@mkdir -p $(BIN_DIR)
	@set -e; for cmd in $(CMDS); do \
		echo ">> build $$cmd"; \
		$(GO_BUILD) -o $(BIN_DIR)/$$cmd ./cmd/$$cmd; \
	done

.PHONY: airgap-bundle
airgap-bundle: ## Build an offline install bundle (requires VERSION=vX.Y.Z; docker unless TRSTCTL_AIRGAP_SKIP_IMAGES=1)
	@scripts/airgap-bundle.sh

# GOFIPS140 value for the regulated FIPS-capable build. The default pins the
# audited Go FIPS module selector used in the product evidence profile; operators
# can override it only when their evidence pack names the replacement selector.
# The Go toolchain rejects GOFIPS140=on — valid values are off|latest|inprocess|
# certified|vX.Y.Z — so approved deployments use a concrete vX.Y.Z selector.
GOFIPS140 ?= v1.0.0
# CGO must stay disabled for the FIPS build too; the Go FIPS module is pure-Go and
# needs no C toolchain (unlike the old GOEXPERIMENT=boringcrypto path).
GO_BUILD_FIPS := GOFIPS140=$(GOFIPS140) CGO_ENABLED=$(CGO_ENABLED) $(GO) build -trimpath -ldflags '$(LDFLAGS)'

.PHONY: fips-build
fips-build: ## Build all binaries with the Go FIPS 140-3 Cryptographic Module enabled (PKIGOV-007); fails closed at runtime under --fips if inactive
	@mkdir -p $(BIN_DIR)
	@echo ">> FIPS-capable build (GOFIPS140=$(GOFIPS140)) — routes crypto/* through the Go FIPS 140-3 Cryptographic Module"
	@echo ">> NOTE: this is FIPS-*capable* (validated Go module). The trstctl product NIST CMVP certificate is a separate, external process."
	@set -e; for cmd in $(CMDS); do \
		echo ">> fips-build $$cmd"; \
		$(GO_BUILD_FIPS) -o $(BIN_DIR)/$$cmd-fips ./cmd/$$cmd; \
	done
	@# Prove the produced binary actually has the FIPS module ACTIVE — not merely
	@# that it compiled. The control plane reports its module posture via the AN-3
	@# boundary in --check-config; assert it says module_active:true, and that the
	@# --fips power-on self-test (POST) boots cleanly rather than failing closed.
	@echo ">> verify the FIPS module is active in the built binary"
	@$(BIN_DIR)/trstctl-fips --check-config 2>/dev/null | grep -qx 'crypto.fips.module_active: true' \
		|| { echo "FAIL: fips-build produced a binary whose FIPS module is NOT active" >&2; exit 1; }
	@echo ">> FIPS build verified: crypto.fips.module_active: true"

.PHONY: test
test: ## Run all tests (race + coverage) and enforce the coverage minimum
	@echo ">> go test (race + merged first-party coverage)"
	@$(GO) test -race -count=1 -covermode=atomic -coverpkg=$(GO_COVER_PACKAGES) -coverprofile=$(COVERPROFILE) $(GO_PACKAGES)
	@grep -v -E '\.pb\.go:' $(COVERPROFILE) > $(COVERPROFILE).nogen
	@total=$$($(GO) tool cover -func=$(COVERPROFILE).nogen | awk '/^total:/ {print $$3}' | tr -d '%'); \
	echo ">> coverage: $$total% (minimum $(COVERAGE_MIN)%, generated *.pb.go excluded)"; \
	awk -v t="$$total" -v m=$(COVERAGE_MIN) 'BEGIN { if (t+0 < m+0) exit 1 }' || \
		{ echo "FAIL: coverage $$total% is below the required $(COVERAGE_MIN)%"; exit 1; }
	@echo ">> internal/server assembled-lifecycle coverage (merged via -coverpkg; exercised by the cross-package e2e, not in-package):"
	@# The lifecycle floor is a self-tested script (TEST-007), not inline awk, so the
	@# gate-of-the-gate is itself covered (scripts/ci/coverage-server-lifecycle_selftest.sh).
	@$(GO) tool cover -func=$(COVERPROFILE).nogen | \
		SERVER_LIFECYCLE_FUNCS='$(SERVER_LIFECYCLE_FUNCS)' SERVER_FUNC_COVERAGE_MIN=$(SERVER_FUNC_COVERAGE_MIN) \
		bash scripts/ci/coverage-server-lifecycle.sh
	@CRITICAL_COVERAGE_MIN=$(CRITICAL_COVERAGE_MIN) bash scripts/ci/coverage-critical.sh $(COVERPROFILE).nogen

.PHONY: coverage-critical
coverage-critical: ## Enforce the per-package coverage floor on security-critical packages (consumes cover.out.nogen from `make test`)
	@CRITICAL_COVERAGE_MIN=$(CRITICAL_COVERAGE_MIN) bash scripts/ci/coverage-critical.sh $(COVERPROFILE).nogen

.PHONY: cover
cover: test ## Alias for `make test`; writes cover.out and prints per-function coverage
	@$(GO) tool cover -func=$(COVERPROFILE).nogen | tail -1

# Per-target fuzz budget for the smoke run (FUZZ-003). Short enough for a per-PR
# CI gate; the nightly job overrides it (e.g. FUZZ_SMOKE_TIME=120s) for depth.
FUZZ_SMOKE_TIME ?= 10s

.PHONY: fuzz-smoke
fuzz-smoke: ## Run every Go fuzz target for a short budget against its committed seed corpus (FUZZ-003)
	@echo ">> fuzz-smoke (each FuzzXxx for $(FUZZ_SMOKE_TIME); committed seeds replayed first)"
	@set -euo pipefail; \
	fail=0; \
	while read -r pkg fn; do \
		echo ">> $$pkg $$fn"; \
		$(GO) test "$$pkg" -run='^$$' -fuzz="^$$fn$$" -fuzztime=$(FUZZ_SMOKE_TIME) || fail=1; \
	done < <( \
		grep -rEl '^func Fuzz[A-Za-z0-9_]+\(' --include='*_test.go' internal ee | while read -r f; do \
			pkg="./$$(dirname "$$f")"; \
			grep -oE '^func (Fuzz[A-Za-z0-9_]+)\(' "$$f" | sed -E 's/^func //; s/\(//' | while read -r fn; do \
				echo "$$pkg $$fn"; \
			done; \
		done | sort -u \
	); \
	if [ "$$fail" -ne 0 ]; then echo "FAIL: a fuzz target crashed (see above)"; exit 1; fi; \
	echo ">> fuzz-smoke: all targets clean"

.PHONY: chaos
chaos: ## Run the fault-injection / chaos suite over the embedded spine (RESIL-005)
	@echo ">> chaos: fault injection over embedded PostgreSQL + in-process NATS (build tag: chaos)"
	$(GO) test -tags=chaos -race -count=1 -run '^TestChaos' ./internal/orchestrator/... ./internal/signing/...
	@echo ">> chaos: all fault-injection scenarios held the safe failure direction"

.PHONY: perf-smoke
perf-smoke: ## Run the committed hot-path performance SLO smoke gate (PERF-001/002/003)
	@out="$${PERF_OUT:-$${TMPDIR:-/tmp}/trstctl-perf-smoke.json}"; \
	echo ">> perf-smoke ($$out)"; \
	scripts/perf/run-local.sh --profile smoke --out "$$out"

.PHONY: perf-live
perf-live: ## Run the served hot-path live load gate with realistic and peak phases (PERF-001)
	@out="$${PERF_LIVE_OUT:-$${TMPDIR:-/tmp}/trstctl-perf-live.json}"; \
	echo ">> perf-live ($$out)"; \
	scripts/perf/run-local.sh --profile live --out "$$out"

.PHONY: perf-capacity
perf-capacity: ## Recompute the measured capacity and cost calibration artifact (PERF-004)
	@out="$${PERF_CAPACITY_OUT:-scripts/perf/artifacts/capacity-measurement-baseline.json}"; \
	echo ">> perf-capacity ($$out)"; \
	scripts/perf/run-capacity-calibration.sh --out "$$out"

.PHONY: usability-first-run
usability-first-run: ## Regenerate and verify the first-run usability receipt (TRACE-010)
	@echo ">> usability-first-run"
	node scripts/usability/measure-first-run.mjs
	python3 scripts/usability/verify-release-evidence.py

.PHONY: usability-release-check
usability-release-check: ## Fail release notes that claim NPS/operator satisfaction without measured evidence
	@notes="$${TRSTCTL_RELEASE_NOTES_FILE:-}"; \
	if [ -n "$$notes" ]; then \
		python3 scripts/usability/verify-release-evidence.py --release-notes "$$notes"; \
	else \
		python3 scripts/usability/verify-release-evidence.py --release-notes-text "$${TRSTCTL_RELEASE_NOTES_TEXT:-trstctl local release}"; \
	fi

.PHONY: soak
soak: ## Run the endurance/soak gate self-test: fail on an induced leak, pass on a healthy series (PERF-004)
	@out="$${SOAK_OUT:-$${TMPDIR:-/tmp}/trstctl-soak.json}"; \
	echo ">> soak: self-test (induced leak must fail, healthy series must pass) -> $$out"; \
	if scripts/perf/soak.sh --selftest-fail --out "$$out.fail" >/dev/null 2>&1; then \
		echo "FAIL: soak gate passed an induced leak series" >&2; exit 1; \
	else \
		echo ">> soak: induced leak correctly failed the gate"; \
	fi; \
	scripts/perf/soak.sh --selftest-ok --out "$$out"; \
	echo ">> soak: healthy series passed; trend report at $$out"

.PHONY: soak-capture
soak-capture: ## Capture and analyze a real local eval-stack sustained-load soak series (PERF-003)
	@series="$${SOAK_SERIES_OUT:-$${TMPDIR:-/tmp}/trstctl-soak-series.json}"; \
	report="$${SOAK_REPORT_OUT:-$${TMPDIR:-/tmp}/trstctl-soak-trend.json}"; \
	echo ">> soak-capture: series=$$series report=$$report"; \
	scripts/perf/capture-soak-series.sh --out "$$series"; \
	scripts/perf/soak.sh --in "$$series" --out "$$report" --profile captured-soak; \
	echo ">> soak-capture: trend report at $$report"

.PHONY: spine-burst
spine-burst: ## Capture and analyze the CAP-SMALL event-spine burst artifact (SPINE-002)
	@series="$${SPINE_BURST_OUT:-scripts/perf/artifacts/spine-burst-cap-small.json}"; \
	report="$${SPINE_BURST_REPORT_OUT:-$${TMPDIR:-/tmp}/trstctl-spine-burst-trend.json}"; \
	echo ">> spine-burst: series=$$series report=$$report"; \
	scripts/perf/run-spine-burst.sh --profile cap-small --out "$$series"; \
	scripts/perf/soak.sh --in "$$series" --out "$$report" --profile spine-burst-cap-small; \
	echo ">> spine-burst: trend report at $$report"

.PHONY: lint lint-partial
lint-partial: ## Run gofmt, go vet, architecture lint, and action-pin checks; warn if optional lint tools are absent
	@$(MAKE) -f $(firstword $(MAKEFILE_LIST)) lint LINT_ALLOW_PARTIAL=1

lint: ## Run the full lint gate: gofmt, go vet, architecture lint, golangci-lint, actionlint, and action-pin checks
	@echo ">> gofmt"
	@unformatted=$$(gofmt -l -s $$(find . -name '*.go' -not -path '*/testdata/*' -not -path './.git/*')); \
	if [ -n "$$unformatted" ]; then \
		echo "These files are not gofmt-clean (run: gofmt -w -s .):"; \
		echo "$$unformatted"; \
		exit 1; \
	fi
	@echo ">> go vet"
	$(GO) vet $(GO_PACKAGES)
	@echo ">> trstctllint (architecture rules: AN-1, AN-3, AN-5, AN-8, crypto-agility)"
	@vettool=$$(mktemp "$${TMPDIR:-/tmp}/trstctllint.XXXXXX"); \
	trap 'rm -f "$$vettool"' EXIT; \
	$(GO) build -o "$$vettool" ./tools/trstctllint; \
	$(GO) vet -vettool="$$vettool" $(GO_PACKAGES)
	@# golangci-lint carries errcheck/staticcheck/unused — a real part of the gate.
	@# When it is missing we must NOT pass silently (CODE-005): make lint is the
	@# full gate and fails closed by default. Developers who explicitly want only
	@# the cheap local subset must run the intentionally named make lint-partial.
	@if command -v golangci-lint >/dev/null 2>&1; then \
		echo ">> golangci-lint"; golangci-lint run $(GO_PACKAGE_DIRS); \
	elif [ "$${LINT_ALLOW_PARTIAL:-0}" = "1" ]; then \
		echo "!! ============================================================"; \
		echo "!! WARNING: golangci-lint NOT installed — SKIPPING it (CODE-005)."; \
		echo "!! errcheck / staticcheck / unused did NOT run; this is a PARTIAL"; \
		echo "!! lint. Run 'make tools' and then 'make lint' for the full gate."; \
		echo "!! ============================================================"; \
	else \
		echo "FAIL: golangci-lint is not installed, so make lint would skip errcheck/staticcheck/unused. Run 'make tools' or use 'make lint-partial' deliberately." >&2; \
		exit 1; \
	fi
	@if command -v actionlint >/dev/null 2>&1; then \
		echo ">> actionlint (GitHub Actions workflows)"; actionlint; \
	elif [ "$${LINT_ALLOW_PARTIAL:-0}" = "1" ]; then \
		echo "!! WARNING: actionlint NOT installed — SKIPPING workflow lint (install with: make tools)"; \
	else \
		echo "FAIL: actionlint is not installed, so make lint would skip workflow lint. Run 'make tools' or use 'make lint-partial' deliberately." >&2; \
		exit 1; \
	fi
	@echo ">> third-party GitHub Actions are SHA-pinned (SUPPLY-002)"
	@bash scripts/ci/check-actions-pinned_selftest.sh >/dev/null
	@bash scripts/ci/check-actions-pinned.sh .

.PHONY: editions-gate
editions-gate: ## Prove the open-core one-way valve and core-only build
	@echo ">> editions import guard self-test"
	@SELFTEST=1 ./scripts/check_editions_imports.sh
	@echo ">> trstctl_core build"
	@$(GO) build -tags trstctl_core ./cmd/trstctl
	@echo ">> trstctl_core dependency graph links zero ee/"
	@if $(GO) list -tags trstctl_core -deps ./cmd/trstctl | grep -E '^$(MODULE)/ee(/|$$)' >/dev/null; then \
		echo "FAIL: trstctl_core build links ee/ packages" >&2; \
		$(GO) list -tags trstctl_core -deps ./cmd/trstctl | grep -E '^$(MODULE)/ee(/|$$)' >&2; \
		exit 1; \
	fi
	@echo ">> trstctl_core dependency graph links zero remediation internals"
	@if $(GO) list -tags trstctl_core -deps ./cmd/trstctl | grep -E '^$(MODULE)/internal/(incident|fleet|pqcmigration)(/|$$)' >/dev/null; then \
		echo "FAIL: trstctl_core build links moved remediation internals" >&2; \
		$(GO) list -tags trstctl_core -deps ./cmd/trstctl | grep -E '^$(MODULE)/internal/(incident|fleet|pqcmigration)(/|$$)' >&2; \
		exit 1; \
	fi
	@echo ">> trstctl_core tests over non-ee packages"
	@pkgs="$$( $(GO) list $(GO_PACKAGES) | grep -v -E '^$(MODULE)/ee(/|$$)' )"; \
	$(GO) test -tags trstctl_core $$pkgs

.PHONY: web-lint web-format-check web-check
web-lint: ## Run frontend ESLint from the repository root (CODE-002)
	@echo ">> web lint"
	@$(WEB_NPM) run lint

web-format-check: ## Check frontend formatting from the repository root (CODE-002)
	@echo ">> web format:check"
	@$(WEB_NPM) run format:check

web-check: web-lint web-format-check ## Run the frontend lint and formatter gates from the repository root (CODE-002)

.PHONY: run
run: ## Build and run the control plane (pass args via ARGS, e.g. ARGS=--version)
	$(GO) run ./cmd/trstctl $(ARGS)

DIST_DIR ?= dist
WIN_ARCH ?= amd64

.PHONY: windows-build
windows-build: ## Cross-compile every package for windows/amd64 (compile check)
	GOOS=windows GOARCH=$(WIN_ARCH) $(GO) build ./...
	GOOS=windows GOARCH=$(WIN_ARCH) $(GO) vet ./...

.PHONY: dist-windows
dist-windows: ## Build the Windows agent + MSI, remote-sign when WINDOWS_CODESIGN_URL is set, and publish SHA-256 sums
	@mkdir -p $(DIST_DIR)
	@echo ">> cross-build trstctl-agent.exe (windows/$(WIN_ARCH))"
	GOOS=windows GOARCH=$(WIN_ARCH) $(GO_BUILD) -o $(DIST_DIR)/trstctl-agent.exe ./cmd/trstctl-agent
	@cp deploy/windows/trstctl-agent.wxs $(DIST_DIR)/trstctl-agent.wxs
	@# Authenticode-sign the binary through the CI remote signer when configured.
	@# The release workflow grants GitHub OIDC to this job; the signing service
	@# holds the HSM/cloud code-signing authority. No PKCS#12 secret is materialized
	@# on the runner.
	@if [ -n "$$WINDOWS_CODESIGN_URL" ]; then \
		echo ">> remote Authenticode-sign trstctl-agent.exe"; \
		scripts/ci/sign-windows-artifact-oidc.sh $(DIST_DIR)/trstctl-agent.exe && \
		echo ">> verify trstctl-agent.exe signature" && \
		osslsigncode verify -in $(DIST_DIR)/trstctl-agent.exe; \
	else \
		echo ">> WINDOWS_CODESIGN_URL not set; leaving trstctl-agent.exe unsigned"; \
	fi
	@# Build the MSI when a WiX toolchain (msitools' wixl) is present, then sign
	@# it the same way as the binary so the installer itself is trusted.
	@if command -v wixl >/dev/null 2>&1; then \
		echo ">> build MSI (wixl)"; \
		( cd $(DIST_DIR) && wixl -o trstctl-agent.msi trstctl-agent.wxs ); \
		if [ -n "$$WINDOWS_CODESIGN_URL" ]; then \
			echo ">> remote Authenticode-sign trstctl-agent.msi"; \
			scripts/ci/sign-windows-artifact-oidc.sh $(DIST_DIR)/trstctl-agent.msi && \
			echo ">> verify trstctl-agent.msi signature" && \
			osslsigncode verify -in $(DIST_DIR)/trstctl-agent.msi; \
		else \
			echo ">> WINDOWS_CODESIGN_URL not set; leaving trstctl-agent.msi unsigned"; \
		fi; \
	else \
		echo ">> wixl not found; skipping MSI build (install msitools, or use WiX on Windows)"; \
	fi
	@echo ">> publish SHA-256 sums"
	@( cd $(DIST_DIR) && sha256sum $$(ls trstctl-agent.exe trstctl-agent.msi 2>/dev/null) > SHA256SUMS && cat SHA256SUMS )

.PHONY: tools
tools: ## Install developer tooling (golangci-lint v2, govulncheck, actionlint)
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	$(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	$(GO) install github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)

.PHONY: vuln
vuln: ## Reachability-aware vulnerability scan (pinned govulncheck) over shipped packages
	$(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	$(GOVULNCHECK) ./...

.PHONY: audit-verify
audit-verify: ## Verify audit corpus citation, score, and cross-reference integrity (VERIFY-101..103)
	node scripts/audit/verify-corpus.mjs --audit-dir "$(AUDIT_OUTPUTS)" --repo "$(CURDIR)"

.PHONY: sbom
sbom: ## Generate a CycloneDX SBOM of the Go module graph (sbom.module.cyclonedx.json)
	$(GO) install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@$(CYCLONEDX_GOMOD_VERSION)
	$(CYCLONEDX_GOMOD) mod -json -licenses -output sbom.module.cyclonedx.json
	@test -s sbom.module.cyclonedx.json && echo ">> wrote sbom.module.cyclonedx.json"

.PHONY: dependency-freshness
dependency-freshness: ## Validate dependency freshness SLO report and owner queue (CODE-005)
	@echo ">> dependency freshness SLO"
	@node scripts/ci/check-dependency-freshness.mjs

.PHONY: sca
sca: ## Software-composition analysis across all dependency surfaces (Go + npm + embedded-postgres)
	@echo ">> Go module SCA (pinned govulncheck)"; $(MAKE) --no-print-directory vuln
	@echo ">> npm dependency tree SCA"; ( cd web && npm audit --omit=dev --audit-level=high )
	@echo ">> embedded-postgres runtime-binary provenance + scan"; scripts/supply-chain/verify-embedded-postgres.sh

.PHONY: supply-chain
supply-chain: sbom sca dependency-freshness ## Full supply-chain pass: module SBOM, SCA, and dependency freshness SLO

.PHONY: generate
generate: ## Regenerate code from .proto (needs protoc + protoc-gen-go + protoc-gen-go-grpc)
	protoc -I . \
		--go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		internal/signing/proto/signer.proto

.PHONY: tidy
tidy: ## Tidy and verify the module graph
	$(GO) mod tidy
	$(GO) mod verify

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(BIN_DIR)

.PHONY: web
web: ## Install deps, build the web console into internal/webui/dist (embedded by the binary), and verify the embed is a REAL Vite build
	cd web && npm ci && npm run build
	@# SURFACE-001/006: prove the bundle we just embedded is a real build, not the
	@# "not built" placeholder. `npm run build` already runs the FE↔BE contract check
	@# (gen:api --check); this asserts the embedded artifact end-to-end on the Go side.
	@echo ">> verify embedded console is a real build (TRSTCTL_REQUIRE_BUILT_UI=1)"
	TRSTCTL_REQUIRE_BUILT_UI=1 $(GO) test ./internal/webui/...

.PHONY: web-contract
web-contract: ## Regenerate the FE API types from the served OpenAPI contract (SURFACE-005); commit the diff
	cd web && npm run gen:api

.PHONY: sdk
sdk: ## Regenerate the published client SDKs (Go + TypeScript + Python + Java) from the served OpenAPI contract (PRODUCT-007); commit the diff
	./scripts/gen-sdk.sh

.PHONY: sdk-check
sdk-check: ## Verify the published client SDKs are in sync with the served OpenAPI contract; fail on drift (PRODUCT-007)
	./scripts/gen-sdk.sh --check

.PHONY: sdk-test
sdk-test: ## Build and test the Go, TypeScript, Python, and Java client SDKs
	cd clients/sdk/go && $(GO) build ./... && $(GO) vet ./... && $(GO) test ./... -count=1
	npm --prefix clients/sdk/typescript ci
	npm --prefix clients/sdk/typescript run typecheck
	npm --prefix clients/sdk/typescript test
	PYTHONPYCACHEPREFIX=$${TMPDIR:-/tmp}/trstctl-sdk-pycache PYTHONPATH=clients/sdk/python/src python3 -m compileall -q clients/sdk/python/src clients/sdk/python/tests
	PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=clients/sdk/python/src python3 -m unittest discover -s clients/sdk/python/tests -v
	clients/sdk/java/scripts/run_tests.sh

.PHONY: image
image: ## Build the control-plane container image (deploy/docker/Dockerfile)
	docker build -f deploy/docker/Dockerfile \
		--build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg DATE=$(DATE) \
		-t trstctl:$(VERSION) .

.PHONY: compose-up
compose-up: ## Bring up the evaluation stack (Postgres + NATS + trstctl)
	docker compose -f deploy/docker/docker-compose.yml up --build

.PHONY: reproducible-check
reproducible-check: ## Build shipped binaries and image layers twice; verify byte/layer-identical output
	@set -euo pipefail; \
	tmp=$$(mktemp -d); \
	trap 'rm -rf "$$tmp"' EXIT; \
	reproducible_cmds="trstctl trstctl-signer trstctl-agent trstctl-operator trstctl-cli terraform-provider-trstctl trstctl-license"; \
	for cmd in $$reproducible_cmds; do \
		a="$$tmp/$$cmd.a"; b="$$tmp/$$cmd.b"; \
		echo ">> reproducible binary $$cmd"; \
		$(GO_BUILD) -buildvcs=false -o "$$a" ./cmd/$$cmd; \
		$(GO_BUILD) -buildvcs=false -o "$$b" ./cmd/$$cmd; \
		if cmp -s "$$a" "$$b"; then \
			echo "reproducible: identical binary $$cmd"; \
		else \
			echo "NOT reproducible: $$cmd differs" >&2; \
			exit 1; \
		fi; \
	done; \
	echo "reproducible: identical binaries ($$reproducible_cmds)"; \
	command -v docker >/dev/null 2>&1 || { echo "docker is required for the reproducible image-layer check" >&2; exit 1; }; \
	docker buildx version >/dev/null 2>&1 || { echo "docker buildx is required for the reproducible image-layer check" >&2; exit 1; }; \
	tag_a="trstctl:reproducible-a"; tag_b="trstctl:reproducible-b"; \
	build_image() { \
		local tag="$$1"; \
		echo ">> reproducible image layers $$tag"; \
		DOCKER_BUILDKIT=1 SOURCE_DATE_EPOCH=$$(git show -s --format=%ct HEAD 2>/dev/null || echo 0) \
		docker buildx build \
			--provenance=false \
			--sbom=false \
			--output type=docker,rewrite-timestamp=true \
			-f deploy/docker/Dockerfile \
			--build-arg VERSION=$(VERSION) \
			--build-arg COMMIT=$(COMMIT) \
			--build-arg DATE=$(DATE) \
			-t "$$tag" . >/dev/null; \
	}; \
	build_image "$$tag_a"; \
	build_image "$$tag_b"; \
	layers_a=$$(docker image inspect "$$tag_a" --format '{{json .RootFS.Layers}}'); \
	layers_b=$$(docker image inspect "$$tag_b" --format '{{json .RootFS.Layers}}'); \
	if [ "$$layers_a" = "$$layers_b" ]; then \
		echo "reproducible: identical image layers"; \
	else \
		echo "NOT reproducible: image layer digests differ" >&2; \
		echo "first:  $$layers_a" >&2; \
		echo "second: $$layers_b" >&2; \
		exit 1; \
	fi; \
	docker image rm -f "$$tag_a" "$$tag_b" >/dev/null 2>&1 || true

.PHONY: helm-lint
helm-lint: ## Lint + render the control-plane Helm chart (requires helm)
	helm lint deploy/helm/trstctl \
		--set postgres.dsn='postgres://u:p@pg:5432/trstctl?sslmode=require' \
		--set nats.url='nats://nats:4222' --set kek.generate=true
	helm template trstctl deploy/helm/trstctl --namespace trstctl \
		--set postgres.dsn='postgres://u:p@pg:5432/trstctl?sslmode=require' \
		--set nats.url='nats://nats:4222' --set kek.generate=true >/dev/null
	@echo ">> helm chart lints and renders"
