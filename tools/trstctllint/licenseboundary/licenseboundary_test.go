// SPDX-License-Identifier: MPL-2.0

package licenseboundary

import "testing"

func TestPQCPlacementAllowsOnlyNonShippedEvidenceTooling(t *testing.T) {
	for _, path := range []string{
		"/workspace/trstctl/tools/dodcensus/runtime_runner.go",
		"/workspace/trstctl/tools/dodcensus/runtime_runner_test.go",
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
