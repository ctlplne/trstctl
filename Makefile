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
CMDS    := trstctl trstctl-signer trstctl-agent trstctl-operator trstctl-cli terraform-provider-trstctl trstctl-license trstctl-spire-upstream-authority

GO          ?= go
CGO_ENABLED ?= 0
# Fast/intermediate gates may use Go's test cache. Exact-tip and dod_proof runs
# set TRSTCTL_EXACT_TIP=1 so every otherwise-cacheable Go test gets -count=1.
GO_TEST_EXACT_FLAG := $(if $(filter 1 true,$(TRSTCTL_EXACT_TIP)),-count=1,)

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
# These packages boot real embedded PostgreSQL/JetStream spines. Run them in a
# serial lane so the all-package race/coverage gate does not make independent
# database bootstraps contend for the same host resources. No test is skipped.
LIVE_PERF_PACKAGES := ./internal/perf ./scripts/perf/cmd/capacitycalibrate ./scripts/perf/cmd/perfgate ./scripts/perf/cmd/soakcapture ./scripts/perf/cmd/spineburst
LIVE_PERF_IMPORT_RE := $(MODULE)/(internal/perf|scripts/perf/cmd/(capacitycalibrate|perfgate|soakcapture|spineburst))
PCAS_E2E_RUN ?= TestINT20_FullStackPCASUserJourneys|TestINT20_PCASWASMParity_NoSkip|TestINT21_PCASOpsSLOBackpressureAndCrash

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
COVERPROFILE_MAIN := $(COVERPROFILE).main
COVERPROFILE_LIVE_PERF := $(COVERPROFILE).liveperf
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
EE_COVERAGE_MIN ?= 40

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

.PHONY: build-trstctl
build-trstctl: ## Build the default static control-plane artifact used by the DoD profile
	@mkdir -p $(BIN_DIR)
	@$(GO_BUILD) -o $(BIN_DIR)/trstctl ./cmd/trstctl

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
	@set -euo pipefail; parallelism="$$(scripts/ci/go-package-parallelism.sh)"; \
	pkgs="$$( $(GO) list $(GO_PACKAGES) | grep -v -E '^$(LIVE_PERF_IMPORT_RE)$$' )"; \
	$(GO) test -race -count=1 -p=$$parallelism -covermode=atomic -coverpkg=$(GO_COVER_PACKAGES) -coverprofile=$(COVERPROFILE_MAIN) $$pkgs
	@echo ">> go test live perf packages (serial)"
	@$(GO) test -race -count=1 -p=1 -covermode=atomic -coverpkg=$(GO_COVER_PACKAGES) -coverprofile=$(COVERPROFILE_LIVE_PERF) $(LIVE_PERF_PACKAGES)
	@{ head -n 1 $(COVERPROFILE_MAIN); tail -n +2 $(COVERPROFILE_MAIN); tail -n +2 $(COVERPROFILE_LIVE_PERF); } > $(COVERPROFILE)
	@set -euo pipefail; grep -v -E '\.pb\.go:' $(COVERPROFILE) | scripts/ci/coverage-normalize.sh - $(COVERPROFILE).nogen
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

.PHONY: perf-live-wall
perf-live-wall: ## Run the serialized live-performance SLO wall for iteration tips, batch tips, and release candidates
	@echo ">> live performance SLO wall (serial, uninstrumented, uncached)"
	@$(GO) test -count=1 -p=1 ./scripts/perf/cmd/perfgate -run '^TestPerfGateRunsLiveProfile$$'

.PHONY: coverage-critical
coverage-critical: ## Enforce the per-package coverage floor on security-critical packages (consumes cover.out.nogen from `make test`)
	@CRITICAL_COVERAGE_MIN=$(CRITICAL_COVERAGE_MIN) bash scripts/ci/coverage-critical.sh $(COVERPROFILE).nogen

.PHONY: cover
cover: test ## Alias for `make test`; writes cover.out and prints per-function coverage
	@$(GO) tool cover -func=$(COVERPROFILE).nogen | tail -1

DOD_CENSUS_OUT ?= wiring-census.json
DOD_CARD ?=
DOD_CAPABILITY ?=
# Keep compilation artifacts across reboots by default. Operators can still
# isolate or relocate the cache with TRSTCTL_DOD_GOCACHE.
DOD_GOCACHE_DEFAULT := $(if $(XDG_CACHE_HOME),$(XDG_CACHE_HOME),$(HOME)/.cache)/trstctl/dodcensus-gocache
DOD_SELECTION :=
ifneq ($(strip $(DOD_CARD)),)
DOD_SELECTION += --card $(DOD_CARD)
endif
ifneq ($(strip $(DOD_CAPABILITY)),)
DOD_SELECTION += --capability $(DOD_CAPABILITY)
endif

.PHONY: dod-gate
dod-gate: ## Prove every required capability is compiled, production-assembled, and non-sentinel served
	@echo ">> definition-of-done wiring census (manifest-pinned shipped profiles)"
	@if [ -n "$(strip $(DOD_CARD))" ] && [ -n "$(strip $(DOD_CAPABILITY))" ]; then \
		echo "dod-gate: choose only one of DOD_CARD or DOD_CAPABILITY" >&2; exit 2; \
	fi
	@set -eu; cache="$${TRSTCTL_DOD_GOCACHE:-$(DOD_GOCACHE_DEFAULT)}"; \
		if [ ! -e "$$cache" ]; then (umask 077; mkdir -p "$$cache"); fi
	@TRSTCTL_DOD_GOCACHE="$${TRSTCTL_DOD_GOCACHE:-$(DOD_GOCACHE_DEFAULT)}" GOCACHE="$${TRSTCTL_DOD_GOCACHE:-$(DOD_GOCACHE_DEFAULT)}" $(GO) test ./tools/dodcensus/... -count=1
	@TRSTCTL_DOD_GOCACHE="$${TRSTCTL_DOD_GOCACHE:-$(DOD_GOCACHE_DEFAULT)}" GOCACHE="$${TRSTCTL_DOD_GOCACHE:-$(DOD_GOCACHE_DEFAULT)}" $(GO) test ./internal/server -run '^TestDODGateProductionAssemblyCanary$$' -count=1
	@TRSTCTL_DOD_GOCACHE="$${TRSTCTL_DOD_GOCACHE:-$(DOD_GOCACHE_DEFAULT)}" GOCACHE="$${TRSTCTL_DOD_GOCACHE:-$(DOD_GOCACHE_DEFAULT)}" $(GO) run ./tools/dodcensus \
		--repo . --manifest tools/dodcensus/manifest.json --out "$(DOD_CENSUS_OUT)" $(DOD_SELECTION)

PQC_OPERATOR_LAB_MODE = $(if $(filter core-only,$(MAKECMDGOALS)),core,licensed)
PQC_OPERATOR_LAB_OUT ?= dist/pqc-operator-lab-$(PQC_OPERATOR_LAB_MODE).tar.gz

.PHONY: pqc-operator-lab core-only
pqc-operator-lab: ## Run the offline shipped-binary PQC rehearsal and archive non-secret receipts
	@TRSTCTL_DOD_GOCACHE="$${TRSTCTL_DOD_GOCACHE:-$(DOD_GOCACHE_DEFAULT)}" GOCACHE="$${TRSTCTL_DOD_GOCACHE:-$(DOD_GOCACHE_DEFAULT)}" \
		$(GO) run ./tools/pqclab --repo . --mode "$(PQC_OPERATOR_LAB_MODE)" --out "$(PQC_OPERATOR_LAB_OUT)"

core-only:
	@if [ -z "$(filter pqc-operator-lab,$(MAKECMDGOALS))" ]; then \
		echo "core-only is a selector; run: make core-only pqc-operator-lab" >&2; exit 2; \
	fi

.PHONY: journey-census journey-census-check
journey-census: ## Regenerate journey served badges and console data from wiring-census.json
	@python3 scripts/docs/render-journey-served.py

journey-census-check: ## Fail when journey served claims drift from a fresh wiring census
	@python3 scripts/docs/render-journey-served.py --check

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
	@set -e; \
	series="$${SOAK_SERIES_OUT:-$${TMPDIR:-/tmp}/trstctl-soak-series.json}"; \
	report="$${SOAK_REPORT_OUT:-$${TMPDIR:-/tmp}/trstctl-soak-trend.json}"; \
	echo ">> soak-capture: series=$$series report=$$report"; \
	scripts/perf/capture-soak-series.sh --out "$$series"; \
	scripts/perf/soak.sh --in "$$series" --out "$$report" --profile captured-soak; \
	echo ">> soak-capture: trend report at $$report"

.PHONY: spine-burst
spine-burst: ## Capture and analyze an event-spine burst artifact (SPINE-002; default CAP-SMALL)
	@set -e; \
	profile="$${SPINE_BURST_PROFILE:-cap-small}"; \
	default_series="scripts/perf/artifacts/spine-burst-$${profile}.json"; \
	series="$${SPINE_BURST_OUT:-$$default_series}"; \
	report="$${SPINE_BURST_REPORT_OUT:-$${TMPDIR:-/tmp}/trstctl-spine-burst-trend.json}"; \
	echo ">> spine-burst: profile=$$profile series=$$series report=$$report"; \
	scripts/perf/run-spine-burst.sh --profile "$$profile" --out "$$series"; \
	scripts/perf/soak.sh --in "$$series" --out "$$report" --profile "spine-burst-$$profile"; \
	echo ">> spine-burst: trend report at $$report"

.PHONY: lint lint-partial
lint-partial: ## Run gofmt, go vet, architecture lint, and action-pin checks; warn if optional lint tools are absent
	@$(MAKE) -f $(firstword $(MAKEFILE_LIST)) lint LINT_ALLOW_PARTIAL=1

lint: ## Run the full lint gate: gofmt, go vet, architecture lint, golangci-lint, actionlint, and action-pin checks
	@echo ">> gofmt"
	@unformatted=$$(git ls-files -z --cached --others --exclude-standard -- '*.go' ':!:**/testdata/**' | xargs -0 sh -c 'for file do [ ! -f "$$file" ] || gofmt -l -s "$$file"; done' sh); \
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
	@golangci_lint=""; \
	if command -v golangci-lint >/dev/null 2>&1; then golangci_lint="golangci-lint"; \
	elif [ -x "$(GO_TOOL_BIN)/golangci-lint" ]; then golangci_lint="$(GO_TOOL_BIN)/golangci-lint"; fi; \
	if [ -n "$$golangci_lint" ]; then \
		echo ">> golangci-lint"; \
		if [ "$$golangci_lint" = "golangci-lint" ]; then golangci-lint run $(GO_PACKAGE_DIRS); else "$$golangci_lint" run $(GO_PACKAGE_DIRS); fi; \
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
	@actionlint_bin=$$(command -v actionlint 2>/dev/null || true); \
	if [ -z "$$actionlint_bin" ] && [ -x "$(GO_TOOL_BIN)/actionlint" ]; then actionlint_bin="$(GO_TOOL_BIN)/actionlint"; fi; \
	if [ -n "$$actionlint_bin" ]; then \
		echo ">> actionlint (GitHub Actions workflows)"; "$$actionlint_bin"; \
	elif [ "$${LINT_ALLOW_PARTIAL:-0}" = "1" ]; then \
		echo "!! WARNING: actionlint NOT installed — SKIPPING workflow lint (install with: make tools)"; \
	else \
		echo "FAIL: actionlint is not installed, so make lint would skip workflow lint. Run 'make tools' or use 'make lint-partial' deliberately." >&2; \
		exit 1; \
	fi
	@echo ">> third-party GitHub Actions are SHA-pinned (SUPPLY-002)"
	@bash scripts/ci/check-actions-pinned_selftest.sh >/dev/null
	@bash scripts/ci/check-actions-pinned.sh .
	@# AGID-INT-CALL production-caller FLOOR: every ee/agentid mechanism has a non-test
	@# caller (the DEFERRED ee/agentid/verify RP SDK excepted). This is the lexical,
	@# always-runnable tier; the whole-program RTA strong check is CI-only (-tags agidrta).
	@# ee/... is outside GO_PACKAGES (the core Go gates skip ee/), so the floor is invoked
	@# explicitly here. PCAS gets the same always-runnable caller/no-skip floors; its
	@# heavyweight real-infra e2e runs through pcas-release-gate in CI/release.
	@if [ "$${LINT_ALLOW_PARTIAL:-0}" = "1" ]; then \
		echo "!! WARNING: PCAS caller/no-skip gates NOT run by lint-partial; run 'make pcas-release-gate' for the full PCAS release gate."; \
	else \
		$(MAKE) -f $(firstword $(MAKEFILE_LIST)) pcas-caller-gate pcas-no-skip-gate; \
	fi
	@$(MAKE) -f $(firstword $(MAKEFILE_LIST)) agid-caller-gate xrec-caller-gate vdec-caller-gate

.PHONY: editions-gate
.PHONY: vault-compat-gate
vault-compat-gate: ## Run the Vault/OpenBao shim acceptance against a real CLI (TEST-VAULT-001)
	@echo ">> vault-compat-gate (real vault/openbao CLI, non-skipped)"
	@if [ -z "$${TRSTCTL_VAULT_BIN:-}" ] && ! command -v vault >/dev/null 2>&1; then 		echo "FAIL: TEST-VAULT-001 requires a real vault/openbao CLI; set TRSTCTL_VAULT_BIN or install 'vault'" >&2; 		exit 1; 	fi
	@$(GO) test ./internal/server -run 'VaultCLICompatibility' -count=1

.PHONY: ee-test
ee-test: ## Run the ee/ unit tests with a coverage floor (TEST-EE-CI-001)
	@echo ">> ee/ unit tests (race + coverage floor $(EE_COVERAGE_MIN)%)"
	@set -euo pipefail; \
	$(GO) test -race -count=1 -covermode=atomic -coverpkg=./ee/... -coverprofile=$(COVERPROFILE).ee ./ee/...; \
	total=$$($(GO) tool cover -func=$(COVERPROFILE).ee | awk '/^total:/ {print $$3}' | tr -d '%'); \
	echo ">> ee/ coverage: $$total% (minimum $(EE_COVERAGE_MIN)%)"; \
	awk -v t="$$total" -v m=$(EE_COVERAGE_MIN) 'BEGIN { if (t+0 < m+0) exit 1 }' || \
		{ echo "FAIL: ee/ coverage $$total% is below the required $(EE_COVERAGE_MIN)%"; exit 1; }

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
	@set -euo pipefail; parallelism="$$(scripts/ci/go-package-parallelism.sh)"; \
	pkgs="$$( $(GO) list $(GO_PACKAGES) | grep -v -E '^$(MODULE)/ee(/|$$)' | grep -v -E '^$(LIVE_PERF_IMPORT_RE)$$' )"; \
	$(GO) test -tags trstctl_core $(GO_TEST_EXACT_FLAG) -p=$$parallelism $$pkgs
	@echo ">> trstctl_core live perf packages (serial)"
	@$(GO) test -tags trstctl_core $(GO_TEST_EXACT_FLAG) -p=1 $(LIVE_PERF_PACKAGES)

.PHONY: pcas-caller-gate
pcas-caller-gate: ## PCAS production-caller gate (INT-23): every delivered mechanism has a non-test caller
	@./scripts/pcas_prod_caller_gate.sh

.PHONY: pcas-no-skip-gate no-skip-gate
pcas-no-skip-gate: ## PCAS no-skip gate (INT-20): release-gate tests must not call t.Skip
	@./scripts/pcas_no_skip_gate.sh

no-skip-gate: pcas-no-skip-gate

.PHONY: pcas-e2e-gate pcas-release-gate
pcas-e2e-gate: ## PCAS full-stack e2e gate (INT-20): real PG + JetStream + signer subprocess + WASM parity
	@$(GO) test ./ee/succession/conformance -run '$(PCAS_E2E_RUN)' -count=1 -timeout=10m

pcas-release-gate: pcas-caller-gate pcas-no-skip-gate pcas-e2e-gate ## PCAS release gate (INT-23)

.PHONY: agid-caller-gate agid-caller-gate-strong
agid-caller-gate: ## AGID-INT-CALL production-caller FLOOR: every ee/agentid mechanism has a non-test caller; the ee/agentid/verify RP SDK is the DEFERRED exception
	@echo ">> agid-caller-gate (AGID-INT-CALL floor + seam: every ee/agentid constructor has a non-test caller rooted at the ee_attach seam)"
	@$(GO) test ./ee/agentid/intgate/... -count=1
agid-caller-gate-strong: ## AGID-INT-CALL STRONG check (CI): RTA call graph from cmd/* main.main (no -tags trstctl_core) proves every ee/agentid constructor is reachable
	@echo ">> agid-caller-gate-strong (AGID-INT-CALL RTA reachability; whole-program load, CI-only)"
	@$(GO) test -tags agidrta ./ee/agentid/intgate/... -count=1

.PHONY: xrec-caller-gate xrec-caller-gate-strong xrec-wire-gate xrec-release-gate
xrec-caller-gate: ## XREC-INT-CALL production-caller FLOOR: every ee/reconcile constructor has a seam-rooted non-test caller
	@echo ">> xrec-caller-gate (XREC-INT-CALL floor + seam: every ee/reconcile constructor has a non-test caller rooted at the ee_attach seam)"
	@$(GO) test ./ee/reconcile/intgate/... -count=1
xrec-caller-gate-strong: ## XREC-INT-CALL STRONG check (CI): RTA call graph from cmd/trstctl and cmd/trstctl-signer proves every XREC constructor is reachable
	@echo ">> xrec-caller-gate-strong (XREC-INT-CALL RTA reachability; whole-program load, CI-only)"
	@$(GO) test -tags xrecrta ./ee/reconcile/intgate/... -count=1

.PHONY: vdec-caller-gate vdec-caller-gate-strong vdec-wire-gate vdec-release-gate
vdec-caller-gate: ## VDEC-INT-CALL production-caller FLOOR: every ee/decommission constructor has a seam-rooted non-test caller
	@echo ">> vdec-caller-gate (VDEC-INT-CALL floor + seam: every ee/decommission constructor has a non-test caller rooted at the ee_attach seam)"
	@$(GO) test ./ee/decommission/intgate/... -count=1
vdec-caller-gate-strong: ## VDEC-INT-CALL STRONG check (CI): RTA call graph from cmd/trstctl and cmd/trstctl-signer proves every VDEC constructor is reachable
	@echo ">> vdec-caller-gate-strong (VDEC-INT-CALL RTA reachability; whole-program load, CI-only)"
	@$(GO) test -tags vdecrta ./ee/decommission/intgate/... -count=1
vdec-wire-gate: ## VDEC-INT-WIRE real-infra gate: PostgreSQL/RLS + embedded NATS + real signer + restart replay
	@echo ">> vdec-wire-gate (VDEC-INT-WIRE real PG/RLS + embedded NATS + cmd/trstctl-signer)"
	@$(GO) test -tags integration ./ee/decommission/intwire/... -count=1 -timeout=10m
vdec-release-gate: vdec-caller-gate vdec-wire-gate ## VDEC-11 release gate: conformance, vectors, fuzz seeds, traceability, edition/zero-removal, and e2e
	@echo ">> vdec-release-gate (VDEC-11 conformance, vectors, fuzz seeds, traceability, edition/zero-removal, and real-substrate e2e)"
	@$(GO) test ./ee/decommission/conformance/... -count=1
	@$(GO) test -tags integration ./ee/decommission/conformance/... -count=1 -timeout=12m
xrec-wire-gate: ## XREC-INT-WIRE real-infra gate: PostgreSQL/RLS + embedded NATS + real signer + restart replay
	@echo ">> xrec-wire-gate (XREC-INT-WIRE real PG/RLS + embedded NATS + cmd/trstctl-signer)"
	@$(GO) test -tags integration ./ee/reconcile/intwire/... -count=1 -timeout=10m
xrec-release-gate: ## XREC-13 release gate: conformance vectors + differential + fuzz decode smoke + edition/zero-removal + e2e
	@echo ">> xrec-release-gate (XREC-13 conformance, differential, fuzz decode smoke, edition/zero-removal, and real-substrate e2e)"
	@$(GO) test -tags integration ./ee/reconcile/conformance/... -count=1 -timeout=10m

.PHONY: security-review
security-review: editions-gate xrec-caller-gate xrec-caller-gate-strong xrec-wire-gate xrec-release-gate vdec-caller-gate vdec-caller-gate-strong vdec-wire-gate vdec-release-gate ## Security-focused local review for signer, remediation, connectors, XREC, and VDEC delivery paths
	@echo ">> security-review (privileged signer/server/orchestrator/connectors/XREC/VDEC package tests)"
	@$(GO) test ./internal/signing ./internal/server ./internal/orchestrator ./internal/connector/... ./ee/reconcile/... ./ee/decommission/... -count=1

.PHONY: web-typecheck web-lint web-format-check web-check
web-typecheck: ## Run the frontend TypeScript no-emit check from the repository root (CODE-002)
	@echo ">> web typecheck"
	@$(WEB_NPM) run typecheck

web-lint: ## Run frontend ESLint from the repository root (CODE-002)
	@echo ">> web lint"
	@$(WEB_NPM) run lint

web-format-check: ## Check frontend formatting from the repository root (CODE-002)
	@echo ">> web format:check"
	@$(WEB_NPM) run format:check

web-check: web-typecheck web-lint web-format-check ## Run the frontend TypeScript, lint, and formatter gates from the repository root (CODE-002)

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

.PHONY: license-audit
license-audit: ## Fail if a copyleft, source-available, or unlicensed dependency ships (D9)
	@echo ">> dependency license audit (shipped binaries)"
	@mkdir -p dist/release-evidence
	@python3 scripts/ci/license-audit.py --json dist/release-evidence/license-audit.json
	@# The Go audit cannot see the console's dependency tree, so until this ran
	@# a web dependency could carry any license at all and no gate would notice.
	@echo ">> dependency license audit (console tree)"
	@python3 scripts/ci/npm-license-audit.py --json dist/release-evidence/npm-license-audit.json

.PHONY: dependency-freshness
dependency-freshness: ## Validate dependency freshness SLO report and owner queue (CODE-005)
	@echo ">> dependency freshness SLO"
	@node scripts/ci/check-dependency-freshness.mjs

.PHONY: sca
sca: ## Software-composition analysis across all dependency surfaces (Go + npm + embedded-postgres)
	@echo ">> Go module SCA (pinned govulncheck)"; $(MAKE) --no-print-directory vuln
	@echo ">> npm dependency tree SCA (web + TypeScript SDK generator)"; bash scripts/ci/npm-audit-dependency-surfaces.sh
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
	@# Local repeats reuse only a tree stamped for the exact lock digest. CI and
	@# exact-tip proofs force npm ci with CI=true or TRSTCTL_WEB_CLEAN_INSTALL=1.
	scripts/ci/install-web-deps.sh web
	$(WEB_NPM) run build
	@# SURFACE-001/006: prove the bundle we just embedded is a real build, not the
	@# "not built" placeholder. `npm run build` already runs the FE↔BE contract check
	@# (gen:api --check); this asserts the embedded artifact end-to-end on the Go side.
	@echo ">> verify embedded console is a real build (TRSTCTL_REQUIRE_BUILT_UI=1)"
	TRSTCTL_REQUIRE_BUILT_UI=1 $(GO) test $(GO_TEST_EXACT_FLAG) ./internal/webui/...

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

.PHONY: docker-context-check
docker-context-check: ## Prove ignored caches/secrets cannot enter any Docker build stage
	./scripts/ci/docker-context-audit.sh

.PHONY: image
image: docker-context-check ## Build the control-plane container image (deploy/docker/Dockerfile)
	docker build -f deploy/docker/Dockerfile \
		--build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg DATE=$(DATE) \
		-t trstctl:$(VERSION) .

.PHONY: compose-up
compose-up: docker-context-check ## Bring up the evaluation stack (Postgres + NATS + trstctl)
	docker compose -f deploy/docker/docker-compose.yml up --build

.PHONY: reproducible-check
reproducible-check: ## Build shipped binaries and image layers twice; verify byte/layer-identical output
	@set -euo pipefail; \
	tmp=$$(mktemp -d); \
	trap 'rm -rf "$$tmp"' EXIT; \
	reproducible_cmds="trstctl trstctl-signer trstctl-agent trstctl-operator trstctl-cli terraform-provider-trstctl trstctl-license trstctl-spire-upstream-authority"; \
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
	command -v python3 >/dev/null 2>&1 || { echo "python3 is required for the reproducible image metadata check" >&2; exit 1; }; \
	tag_a="trstctl:reproducible-a"; tag_b="trstctl:reproducible-b"; \
	oci_a="$$tmp/reproducible-a.oci"; oci_b="$$tmp/reproducible-b.oci"; \
	meta_a="$$tmp/reproducible-a.json"; meta_b="$$tmp/reproducible-b.json"; \
	image_digest() { \
		python3 -c 'import json, sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["containerimage.digest"])' "$$1"; \
	}; \
	layer_digests() { \
		python3 -c 'import json, sys, tarfile; tf = tarfile.open(sys.argv[1]); idx = json.load(tf.extractfile("index.json")); manifest_digest = idx["manifests"][0]["digest"].split(":", 1)[1]; manifest = json.load(tf.extractfile("blobs/sha256/" + manifest_digest)); print("\n".join(layer["digest"] for layer in manifest["layers"]))' "$$1"; \
	}; \
	build_image() { \
		local tag="$$1"; local oci="$$2"; local meta="$$3"; \
		echo ">> reproducible image layers $$tag"; \
		DOCKER_BUILDKIT=1 SOURCE_DATE_EPOCH=$$(git show -s --format=%ct HEAD 2>/dev/null || echo 0) \
		docker buildx build \
			--provenance=false \
			--sbom=false \
			--output "type=oci,dest=$$oci,rewrite-timestamp=true" \
			--metadata-file "$$meta" \
			-f deploy/docker/Dockerfile \
			--build-arg VERSION=$(VERSION) \
			--build-arg COMMIT=$(COMMIT) \
			--build-arg DATE=$(DATE) \
			-t "$$tag" . >/dev/null; \
	}; \
	build_image "$$tag_a" "$$oci_a" "$$meta_a"; \
	build_image "$$tag_b" "$$oci_b" "$$meta_b"; \
	image_digest_a=$$(image_digest "$$meta_a"); \
	image_digest_b=$$(image_digest "$$meta_b"); \
	if [ "$$image_digest_a" = "$$image_digest_b" ]; then \
		echo "reproducible: identical release image digest $$image_digest_a"; \
	else \
		echo "NOT reproducible: release image digest differs" >&2; \
		echo "first:  $$image_digest_a" >&2; \
		echo "second: $$image_digest_b" >&2; \
		exit 1; \
	fi; \
	layers_a=$$(layer_digests "$$oci_a"); \
	layers_b=$$(layer_digests "$$oci_b"); \
	if [ "$$layers_a" = "$$layers_b" ]; then \
		echo "reproducible: identical image layers"; \
	else \
		echo "NOT reproducible: image layer digests differ" >&2; \
		echo "first:  $$layers_a" >&2; \
		echo "second: $$layers_b" >&2; \
		exit 1; \
	fi

.PHONY: helm-lint
helm-lint: ## Lint + render the control-plane Helm chart (requires helm)
	helm lint deploy/helm/trstctl \
		--set postgres.dsn='postgres://u:p@pg:5432/trstctl?sslmode=require' \
		--set nats.url='nats://nats:4222' --set kek.generate=true \
		--set signer.auth.tokenCommand=/usr/local/bin/trstctl-sign-approve
	helm template trstctl deploy/helm/trstctl --namespace trstctl \
		--set postgres.dsn='postgres://u:p@pg:5432/trstctl?sslmode=require' \
		--set nats.url='nats://nats:4222' --set kek.generate=true \
		--set signer.auth.tokenCommand=/usr/local/bin/trstctl-sign-approve >/dev/null
	@echo ">> helm chart lints and renders"
