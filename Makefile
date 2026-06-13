# trustctl --- build, test, lint, run.
#
# Reproducible builds: -trimpath strips local filesystem paths, CGO is disabled
# for the shipped binaries, and version metadata is derived from git (with safe
# fallbacks) and injected via -ldflags so that rebuilding the same commit yields
# identical binaries. The architecture linter (tools/trustctllint) is the scope
# of sprint S0.2 and will be wired into the `lint` target when it lands.

SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

MODULE  := trustctl.io/trustctl
BIN_DIR := bin
CMDS    := trustctl trustctl-signer trustctl-agent

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

# Minimum total test coverage (percent), enforced by `make test`. Generated code
# (*.pb.go) is excluded from the measurement.
COVERAGE_MIN ?= 70
COVERPROFILE := cover.out

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

.PHONY: test
test: ## Run all tests (race + coverage) and enforce the coverage minimum
	$(GO) test -race -count=1 -covermode=atomic -coverpkg=./... -coverprofile=$(COVERPROFILE) ./...
	@grep -v -E '\.pb\.go:' $(COVERPROFILE) > $(COVERPROFILE).nogen
	@total=$$($(GO) tool cover -func=$(COVERPROFILE).nogen | awk '/^total:/ {print $$3}' | tr -d '%'); \
	echo ">> coverage: $$total% (minimum $(COVERAGE_MIN)%, generated *.pb.go excluded)"; \
	awk -v t="$$total" -v m=$(COVERAGE_MIN) 'BEGIN { if (t+0 < m+0) exit 1 }' || \
		{ echo "FAIL: coverage $$total% is below the required $(COVERAGE_MIN)%"; exit 1; }
	@echo ">> internal/server assembled-lifecycle coverage (merged via -coverpkg; exercised by the cross-package e2e, not in-package):"
	@$(GO) tool cover -func=$(COVERPROFILE).nogen | awk '$$1 ~ /\/internal\/server\/server\.go:/ && $$2 ~ /^($(SERVER_LIFECYCLE_FUNCS))$$/ { printf "   %-10s %s\n", $$2, $$3 }'
	@$(GO) tool cover -func=$(COVERPROFILE).nogen | awk -v m=$(SERVER_FUNC_COVERAGE_MIN) '$$1 ~ /\/internal\/server\/server\.go:/ && $$2 ~ /^($(SERVER_LIFECYCLE_FUNCS))$$/ { seen++; cov=$$3; sub(/%$$/,"",cov); if (cov+0 < m+0) { bad++; printf "FAIL: internal/server %s coverage %s is below the required %d%% (assembled fail-closed/drain branches regressed, or were measured in-package only)\n", $$2, $$3, m } } END { if (seen+0 < 4) { printf "FAIL: expected 4 assembled-lifecycle functions in the merged profile, saw %d (did the cross-package e2e run under -coverpkg=./...?)\n", seen+0; exit 1 } if (bad) exit 1 }'
	@CRITICAL_COVERAGE_MIN=$(CRITICAL_COVERAGE_MIN) bash scripts/ci/coverage-critical.sh $(COVERPROFILE).nogen

.PHONY: coverage-critical
coverage-critical: ## Enforce the per-package coverage floor on security-critical packages (consumes cover.out.nogen from `make test`)
	@CRITICAL_COVERAGE_MIN=$(CRITICAL_COVERAGE_MIN) bash scripts/ci/coverage-critical.sh $(COVERPROFILE).nogen

.PHONY: cover
cover: test ## Alias for `make test`; writes cover.out and prints per-function coverage
	@$(GO) tool cover -func=$(COVERPROFILE).nogen | tail -1

.PHONY: lint
lint: ## Run gofmt, go vet, and the architecture linter (plus golangci-lint if installed)
	@echo ">> gofmt"
	@unformatted=$$(gofmt -l -s $$(find . -name '*.go' -not -path '*/testdata/*' -not -path './.git/*')); \
	if [ -n "$$unformatted" ]; then \
		echo "These files are not gofmt-clean (run: gofmt -w -s .):"; \
		echo "$$unformatted"; \
		exit 1; \
	fi
	@echo ">> go vet"
	$(GO) vet ./...
	@echo ">> trustctllint (architecture rules: AN-1, AN-3, AN-5, AN-8)"
	$(GO) run ./tools/trustctllint ./...
	@if command -v golangci-lint >/dev/null 2>&1; then \
		echo ">> golangci-lint"; golangci-lint run ./...; \
	else \
		echo ">> golangci-lint not installed; skipping (install with: make tools)"; \
	fi
	@if command -v actionlint >/dev/null 2>&1; then \
		echo ">> actionlint (GitHub Actions workflows)"; actionlint; \
	else \
		echo ">> actionlint not installed; skipping (install with: make tools)"; \
	fi

.PHONY: run
run: ## Build and run the control plane (pass args via ARGS, e.g. ARGS=--version)
	$(GO) run ./cmd/trustctl $(ARGS)

DIST_DIR ?= dist
WIN_ARCH ?= amd64

.PHONY: windows-build
windows-build: ## Cross-compile every package for windows/amd64 (compile check)
	GOOS=windows GOARCH=$(WIN_ARCH) $(GO) build ./...
	GOOS=windows GOARCH=$(WIN_ARCH) $(GO) vet ./...

.PHONY: dist-windows
dist-windows: ## Build the (optionally signed) Windows agent + MSI and publish SHA-256 sums
	@mkdir -p $(DIST_DIR)
	@echo ">> cross-build trustctl-agent.exe (windows/$(WIN_ARCH))"
	GOOS=windows GOARCH=$(WIN_ARCH) $(GO_BUILD) -o $(DIST_DIR)/trustctl-agent.exe ./cmd/trustctl-agent
	@cp deploy/windows/trustctl-agent.wxs $(DIST_DIR)/trustctl-agent.wxs
	@# Authenticode-sign the binary when a signing identity is provided (osslsigncode on
	@# Linux/macOS, or signtool on Windows). Unsigned otherwise.
	@if [ -n "$$SIGN_PFX" ]; then \
		echo ">> Authenticode-sign trustctl-agent.exe"; \
		osslsigncode sign -pkcs12 "$$SIGN_PFX" -pass "$$SIGN_PASS" -n "trustctl agent" \
			-t http://timestamp.digicert.com \
			-in $(DIST_DIR)/trustctl-agent.exe -out $(DIST_DIR)/trustctl-agent.signed.exe && \
		mv $(DIST_DIR)/trustctl-agent.signed.exe $(DIST_DIR)/trustctl-agent.exe; \
	else \
		echo ">> SIGN_PFX not set; skipping signing (set SIGN_PFX/SIGN_PASS to sign)"; \
	fi
	@# Build the MSI when a WiX toolchain (msitools' wixl) is present, then sign
	@# it the same way as the binary so the installer itself is trusted.
	@if command -v wixl >/dev/null 2>&1; then \
		echo ">> build MSI (wixl)"; \
		( cd $(DIST_DIR) && wixl -o trustctl-agent.msi trustctl-agent.wxs ); \
		if [ -n "$$SIGN_PFX" ]; then \
			echo ">> Authenticode-sign trustctl-agent.msi"; \
			osslsigncode sign -pkcs12 "$$SIGN_PFX" -pass "$$SIGN_PASS" -n "trustctl agent" \
				-t http://timestamp.digicert.com \
				-in $(DIST_DIR)/trustctl-agent.msi -out $(DIST_DIR)/trustctl-agent.signed.msi && \
			mv $(DIST_DIR)/trustctl-agent.signed.msi $(DIST_DIR)/trustctl-agent.msi; \
		fi; \
	else \
		echo ">> wixl not found; skipping MSI build (install msitools, or use WiX on Windows)"; \
	fi
	@echo ">> publish SHA-256 sums"
	@( cd $(DIST_DIR) && sha256sum $$(ls trustctl-agent.exe trustctl-agent.msi 2>/dev/null) > SHA256SUMS && cat SHA256SUMS )

.PHONY: tools
tools: ## Install developer tooling (golangci-lint v2, govulncheck, actionlint)
	$(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	$(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	$(GO) install github.com/rhysd/actionlint/cmd/actionlint@$(ACTIONLINT_VERSION)

.PHONY: vuln
vuln: ## Reachability-aware vulnerability scan (pinned govulncheck) over shipped packages
	$(GO) install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	govulncheck ./...

.PHONY: sbom
sbom: ## Generate a CycloneDX SBOM of the Go module graph (sbom.module.cyclonedx.json)
	$(GO) install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@$(CYCLONEDX_GOMOD_VERSION)
	cyclonedx-gomod mod -json -licenses -output sbom.module.cyclonedx.json
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
web: ## Install deps and build the web UI into internal/webui/dist (embedded by the binary)
	cd web && npm ci && npm run build

.PHONY: image
image: ## Build the control-plane container image (deploy/docker/Dockerfile)
	docker build -f deploy/docker/Dockerfile \
		--build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) --build-arg DATE=$(DATE) \
		-t trustctl:$(VERSION) .

.PHONY: compose-up
compose-up: ## Bring up the evaluation stack (Postgres + NATS + trustctl)
	docker compose -f deploy/docker/docker-compose.yml up --build

.PHONY: reproducible-check
reproducible-check: ## Build the control plane twice and verify byte-identical output
	@set -euo pipefail; \
	a=$$(mktemp); b=$$(mktemp); \
	$(GO_BUILD) -buildvcs=false -o $$a ./cmd/trustctl; \
	$(GO_BUILD) -buildvcs=false -o $$b ./cmd/trustctl; \
	if cmp -s $$a $$b; then echo "reproducible: identical binaries"; else echo "NOT reproducible" >&2; exit 1; fi; \
	rm -f $$a $$b

.PHONY: helm-lint
helm-lint: ## Lint + render the control-plane Helm chart (requires helm)
	helm lint deploy/helm/trustctl \
		--set postgres.dsn='postgres://u:p@pg:5432/trustctl?sslmode=require' \
		--set nats.url='nats://nats:4222' --set kek.generate=true
	helm template trustctl deploy/helm/trustctl --namespace trustctl \
		--set postgres.dsn='postgres://u:p@pg:5432/trustctl?sslmode=require' \
		--set nats.url='nats://nats:4222' --set kek.generate=true >/dev/null
	@echo ">> helm chart lints and renders"
