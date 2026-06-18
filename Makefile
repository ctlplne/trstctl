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
CMDS    := trstctl trstctl-signer trstctl-agent trstctl-operator trstctl-cli

GO          ?= go
CGO_ENABLED ?= 0

# Version metadata, git-derived with fallbacks so builds work outside a checkout.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo none)
# Commit timestamp in strict ISO-8601; sourced from the commit (not wall-clock)
# so the build is reproducible regardless of when or where it runs.
DATE    ?= $(shell git show -s --format=%cI HEAD 2>/dev/null || echo unknown)

BUILDINFO := $(MODULE)/internal/buildinfo
LDFLAGS   := -s -w \
	-X $(BUILDINFO).version=$(VERSION) \
	-X $(BUILDINFO).commit=$(COMMIT) \
	-X $(BUILDINFO).date=$(DATE)
GO_BUILD  := CGO_ENABLED=$(CGO_ENABLED) $(GO) build -trimpath -ldflags '$(LDFLAGS)'

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

# GOFIPS140 value for the FIPS-capable build. `latest` selects the newest FIPS
# 140-3 Go Cryptographic Module bundled with the toolchain; an operator pinning a
# specific validated module version overrides it (e.g. GOFIPS140=v1.0.0). Note the
# Go toolchain rejects GOFIPS140=on — the valid values are off|latest|inprocess|
# certified|vX.Y.Z — so the FIPS-*capable* build uses `latest` here.
GOFIPS140 ?= latest
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
	$(GO) test -race -count=1 -covermode=atomic -coverpkg=./... -coverprofile=$(COVERPROFILE) ./...
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
		grep -rEl '^func Fuzz[A-Za-z0-9_]+\(' --include='*_test.go' internal | while read -r f; do \
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
	$(GO) vet ./...
	@echo ">> trstctllint (architecture rules: AN-1, AN-3, AN-5, AN-8)"
	@vettool=$$(mktemp "$${TMPDIR:-/tmp}/trstctllint.XXXXXX"); \
	trap 'rm -f "$$vettool"' EXIT; \
	$(GO) build -o "$$vettool" ./tools/trstctllint; \
	$(GO) vet -vettool="$$vettool" ./...
	@# golangci-lint carries errcheck/staticcheck/unused — a real part of the gate.
	@# When it is missing we must NOT pass silently (CODE-005): make lint is the
	@# full gate and fails closed by default. Developers who explicitly want only
	@# the cheap local subset must run the intentionally named make lint-partial.
	@if command -v golangci-lint >/dev/null 2>&1; then \
		echo ">> golangci-lint"; golangci-lint run ./...; \
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
dist-windows: ## Build the (optionally signed) Windows agent + MSI and publish SHA-256 sums
	@mkdir -p $(DIST_DIR)
	@echo ">> cross-build trstctl-agent.exe (windows/$(WIN_ARCH))"
	GOOS=windows GOARCH=$(WIN_ARCH) $(GO_BUILD) -o $(DIST_DIR)/trstctl-agent.exe ./cmd/trstctl-agent
	@cp deploy/windows/trstctl-agent.wxs $(DIST_DIR)/trstctl-agent.wxs
	@# Authenticode-sign the binary when a signing identity is provided (osslsigncode on
	@# Linux/macOS, or signtool on Windows). Unsigned otherwise.
	@if [ -n "$$SIGN_PFX" ]; then \
		echo ">> Authenticode-sign trstctl-agent.exe"; \
		osslsigncode sign -pkcs12 "$$SIGN_PFX" -pass "$$SIGN_PASS" -n "trstctl agent" \
			-t http://timestamp.digicert.com \
			-in $(DIST_DIR)/trstctl-agent.exe -out $(DIST_DIR)/trstctl-agent.signed.exe && \
		mv $(DIST_DIR)/trstctl-agent.signed.exe $(DIST_DIR)/trstctl-agent.exe && \
		echo ">> verify trstctl-agent.exe signature" && \
		osslsigncode verify -in $(DIST_DIR)/trstctl-agent.exe; \
	else \
		echo ">> SIGN_PFX not set; skipping signing (set SIGN_PFX/SIGN_PASS to sign)"; \
	fi
	@# Build the MSI when a WiX toolchain (msitools' wixl) is present, then sign
	@# it the same way as the binary so the installer itself is trusted.
	@if command -v wixl >/dev/null 2>&1; then \
		echo ">> build MSI (wixl)"; \
		( cd $(DIST_DIR) && wixl -o trstctl-agent.msi trstctl-agent.wxs ); \
		if [ -n "$$SIGN_PFX" ]; then \
			echo ">> Authenticode-sign trstctl-agent.msi"; \
			osslsigncode sign -pkcs12 "$$SIGN_PFX" -pass "$$SIGN_PASS" -n "trstctl agent" \
				-t http://timestamp.digicert.com \
				-in $(DIST_DIR)/trstctl-agent.msi -out $(DIST_DIR)/trstctl-agent.signed.msi && \
			mv $(DIST_DIR)/trstctl-agent.signed.msi $(DIST_DIR)/trstctl-agent.msi && \
			echo ">> verify trstctl-agent.msi signature" && \
			osslsigncode verify -in $(DIST_DIR)/trstctl-agent.msi; \
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

.PHONY: sca
sca: ## Software-composition analysis across all dependency surfaces (Go + npm + embedded-postgres)
	@echo ">> Go module SCA (pinned govulncheck)"; $(MAKE) --no-print-directory vuln
	@echo ">> npm dependency tree SCA"; ( cd web && npm audit --omit=dev --audit-level=high )
	@echo ">> embedded-postgres runtime-binary provenance + scan"; scripts/supply-chain/verify-embedded-postgres.sh

.PHONY: supply-chain
supply-chain: sbom sca ## Full supply-chain pass: module SBOM + SCA over every dependency surface

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

.PHONY: image
image: ## Build the control-plane container image (deploy/docker/Dockerfile)
	docker build -f deploy/docker/Dockerfile \
		--build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg DATE=$(DATE) \
		-t trstctl:$(VERSION) .

.PHONY: compose-up
compose-up: ## Bring up the evaluation stack (Postgres + NATS + trstctl)
	docker compose -f deploy/docker/docker-compose.yml up --build

.PHONY: reproducible-check
reproducible-check: ## Build the control plane twice and verify byte-identical output
	@set -euo pipefail; \
	a=$$(mktemp); b=$$(mktemp); \
	$(GO_BUILD) -buildvcs=false -o $$a ./cmd/trstctl; \
	$(GO_BUILD) -buildvcs=false -o $$b ./cmd/trstctl; \
	if cmp -s $$a $$b; then echo "reproducible: identical binaries"; else echo "NOT reproducible" >&2; exit 1; fi; \
	rm -f $$a $$b

.PHONY: helm-lint
helm-lint: ## Lint + render the control-plane Helm chart (requires helm)
	helm lint deploy/helm/trstctl \
		--set postgres.dsn='postgres://u:p@pg:5432/trstctl?sslmode=require' \
		--set nats.url='nats://nats:4222' --set kek.generate=true
	helm template trstctl deploy/helm/trstctl --namespace trstctl \
		--set postgres.dsn='postgres://u:p@pg:5432/trstctl?sslmode=require' \
		--set nats.url='nats://nats:4222' --set kek.generate=true >/dev/null
	@echo ">> helm chart lints and renders"
