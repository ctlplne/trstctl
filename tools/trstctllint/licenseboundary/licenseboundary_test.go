// SPDX-License-Identifier: BUSL-1.1

package licenseboundary

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPQCPlacementAllowsOnlyNonShippedEvidenceTooling(t *testing.T) {
	for _, path := range []string{
		"/workspace/trstctl/tools/dodcensus/runtime_runner.go",
		"/workspace/trstctl/tools/dodcensus/runtime_runner_test.go",
		"/workspace/trstctl/tools/pqclab/main.go",
		"/workspace/trstctl/tools/pqclab/main_test.go",
	} {
		if !isPQCAllowedCorePath(path) {
			t.Fatalf("DoD evidence tooling path %q was not allowed", path)
		}
	}
	for _, path := range []string{
		"/workspace/trstctl/internal/server/pqc_runtime.go",
		"/workspace/trstctl/internal/crypto/mldsa.go",
		"/workspace/trstctl/cmd/trstctl-agent/pqc.go",
	} {
		if isPQCAllowedCorePath(path) {
			t.Fatalf("shipped core product path %q bypassed PACKAGING-007", path)
		}
	}
}

func TestRepoSourcePathIgnoresCheckoutParentNames(t *testing.T) {
	filename := "/Users/example/Desktop/ctlplne-trstctl/qa-worktrees/dev/docs/aud65_test.go"
	if got, want := repoSourcePath(filename, modulePath+"/docs"), "docs/aud65_test.go"; got != want {
		t.Fatalf("repoSourcePath() = %q, want %q", got, want)
	}
	if got, want := repoSourcePath(filename, modulePath+"/docs_test"), "docs/aud65_test.go"; got != want {
		t.Fatalf("repoSourcePath() for external test package = %q, want %q", got, want)
	}
	attach := "/workspace/qa-worktrees/dev/cmd/trstctl/ee_attach.go"
	if got, want := repoSourcePath(attach, modulePath+"/cmd/trstctl.test"), "cmd/trstctl/ee_attach.go"; got != want {
		t.Fatalf("repoSourcePath() for synthetic test package = %q, want %q", got, want)
	}

	eeFilename := "/tmp/a-path-containing-pqc-and-core/ee/pqc/service.go"
	if got, want := repoSourcePath(eeFilename, modulePath+"/ee/pqc"), "ee/pqc/service.go"; got != want {
		t.Fatalf("repoSourcePath() for EE = %q, want %q", got, want)
	}
}

func TestClientTreeIsClassifiedByRepositoryRelativePath(t *testing.T) {
	for _, path := range []string{"clients/embedded/embedded.go", "clients/sdk/go/trstctl/client.go"} {
		if !isClientPath(path) {
			t.Fatalf("client tree path %q was not classified as clients/", path)
		}
	}
	for _, path := range []string{
		"internal/server/clients.go",
		"cmd/trstctl/clients_cmd.go",
		"ee/provider/clients.go",
		"/workspace/clients/embedded/embedded.go",
	} {
		if isClientPath(path) {
			t.Fatalf("non-client path %q was classified as clients/", path)
		}
	}
}

func TestTaggedAttachSeamsAcceptRepositoryRelativePaths(t *testing.T) {
	for _, filename := range []string{
		"cmd/trstctl/ee_attach.go",
		"cmd/trstctl-signer/ee_attach.go",
		"cmd/trstctl-agent/cosign_attach.go",
	} {
		if !isTaggedAttachSeam(filename) {
			t.Fatalf("repository-relative attach seam %q was rejected", filename)
		}
	}
	if isTaggedAttachSeam("internal/api/ee_attach.go") {
		t.Fatal("unapproved repository-relative attach seam was accepted")
	}
}

func TestVendoredEmbeddedPostgresLicenseBoundaryIsExact(t *testing.T) {
	for _, path := range []string{
		"third_party/embedded-postgres/embedded_postgres.go",
		"third_party/embedded-postgres/remote_fetch_test.go",
	} {
		if !isEmbeddedPostgresSource(path) {
			t.Fatalf("fixture escaped exact vendored source prefix: %s", path)
		}
	}
	for _, path := range []string{
		"third_party/other/library.go",
		"internal/embedded-postgres/library.go",
	} {
		if isEmbeddedPostgresSource(path) {
			t.Fatalf("unrelated source acquired the MIT boundary: %s", path)
		}
	}
}

func TestPQCOperatorLabExemptionContainsNoAlgorithmOrEEImplementation(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "pqclab", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, forbidden := range []string{
		`"trstctl.com/trstctl/ee/`,
		`"github.com/cloudflare/circl/`,
		`"crypto/x509"`,
		`"crypto/rsa"`,
		`"crypto/ecdsa"`,
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("operator-lab evidence exemption contains implementation import %q", forbidden)
		}
	}
	for _, required := range []string{
		`"./tools/dodcensus"`,
		`"/v1/editions"`,
		`"/api/v1/cbom/assets"`,
		`"trstctl_core"`,
	} {
		if !strings.Contains(body, required) {
			t.Fatalf("operator-lab evidence exemption lost bounded proof marker %q", required)
		}
	}
}

func TestPQCPlacementAllowsCoreCampaignRecordsButNotAlgorithmsOrFleetExecution(t *testing.T) {
	for _, body := range []string{
		`type PQCMigrationCampaign struct{ Owner string }`,
		`const event = "pqc.migration_campaign.closed"`,
		`const route = "/api/v1/pqc/campaigns/{id}/evidence"`,
		`const summary = "Record a PQC finding disposition in the core campaign"`,
	} {
		if term := forbiddenCorePQCTerm(body); term != "" {
			t.Fatalf("core campaign bookkeeping was rejected by %q: %s", term, body)
		}
	}
	for _, body := range []string{
		`const Algorithm = "ML-DSA-65" // even inside a PQC campaign`,
		`const Route = "/api/v1/pqc/migrations"`,
		`type PQCMigrationRun struct{ Executor any }`,
		`const Scope = "post-quantum fleet execution"`,
		`type PQCCampaignExecutor struct{ Worker any }`,
		`const Route = "/api/v1/pqc/campaigns/{id}/execute"`,
	} {
		if term := forbiddenCorePQCTerm(body); term == "" {
			t.Fatalf("licensed PQC implementation/execution escaped PACKAGING-007: %s", body)
		}
	}
}
