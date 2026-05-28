# certctl --- build, test, lint, run.
#
# Reproducible builds: -trimpath strips local filesystem paths, CGO is disabled
# for the shipped binaries, and version metadata is derived from git (with safe
# fallbacks) and injected via -ldflags so that rebuilding the same commit yields
# identical binaries. The architecture linter (tools/certctllint) is the scope
# of sprint S0.2 and will be wired into the `lint` target when it lands.

SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

MODULE  := certctl.io/certctl
BIN_DIR := bin
CMDS    := certctl certctl-signer certctl-agent

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

GOLANGCI_LINT_VERSION ?= v1.59.1

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
test: ## Run all tests with the race detector and coverage
	$(GO) test -race -count=1 -covermode=atomic ./...

.PHONY: lint
lint: ## Run gofmt and go vet (plus golangci-lint if installed)
	@echo ">> gofmt"
	@unformatted=$$(gofmt -l -s .); \
	if [ -n "$$unformatted" ]; then \
		echo "These files are not gofmt-clean (run: gofmt -w -s .):"; \
		echo "$$unformatted"; \
		exit 1; \
	fi
	@echo ">> go vet"
	$(GO) vet ./...
	@if command -v golangci-lint >/dev/null 2>&1; then \
		echo ">> golangci-lint"; golangci-lint run ./...; \
	else \
		echo ">> golangci-lint not installed; skipping (install with: make tools)"; \
	fi

.PHONY: run
run: ## Build and run the control plane (pass args via ARGS, e.g. ARGS=--version)
	$(GO) run ./cmd/certctl $(ARGS)

.PHONY: tools
tools: ## Install developer tooling (golangci-lint)
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

.PHONY: tidy
tidy: ## Tidy and verify the module graph
	$(GO) mod tidy
	$(GO) mod verify

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(BIN_DIR)
