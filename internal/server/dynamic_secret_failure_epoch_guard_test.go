// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/projections"
)

func TestDynamicSecretIssuanceFailureProducersCarryLiveTenantEpochAUD108(t *testing.T) {
	for _, item := range []struct {
		file      string
		producers int
	}{
		{file: "dynamic_secret_lifecycle.go", producers: 2},
		{file: "secret_integrations_outbox.go", producers: 2},
	} {
		raw, err := os.ReadFile(item.file) // #nosec G304 -- closed sibling-source fixture list.
		if err != nil {
			t.Fatalf("read %s: %v", item.file, err)
		}
		source := string(raw)
		if got := strings.Count(source, "projections.DynamicSecretLeaseIssuanceFailure{"); got != item.producers {
			t.Errorf("%s issuance-failure producers = %d, want %d current-schema payloads", item.file, got, item.producers)
		}
		epochBoundFailure := regexp.MustCompile(`(?s)projections\.DynamicSecretLeaseIssuanceFailure\{[^}]*TenantEpoch\s*:`)
		if got := len(epochBoundFailure.FindAllStringIndex(source, -1)); got != item.producers {
			t.Errorf("%s epoch-bound issuance-failure producers = %d, want %d", item.file, got, item.producers)
		}
		normalized := strings.Join(strings.Fields(source), " ")
		if strings.Contains(normalized,
			"projections.EventDynamicSecretLeaseIssuanceFailed, projections.DynamicSecretLeaseFailure{") {
			t.Errorf("%s still emits a schema-v1 issuance failure without immutable tenant epoch", item.file)
		}
		if !strings.Contains(source, "SchemaVersion: dynamicSecretEventSchemaVersion(eventType)") {
			t.Errorf("%s append helper bypasses the dynamic-secret schema selector", item.file)
		}
	}

	if got := dynamicSecretEventSchemaVersion(projections.EventDynamicSecretLeaseIssuanceFailed); got != projections.DynamicSecretIssuanceFailureEventSchemaVersion {
		t.Fatalf("issuance-failure schema = %d, want %d", got, projections.DynamicSecretIssuanceFailureEventSchemaVersion)
	}
	for _, eventType := range []string{
		projections.EventDynamicSecretLeasePending,
		projections.EventDynamicSecretLeasePrepared,
		projections.EventDynamicSecretLeaseIssued,
		projections.EventDynamicSecretLeaseRenewed,
		projections.EventDynamicSecretLeaseRevocationRequested,
		projections.EventDynamicSecretLeaseRevocationCompleted,
		projections.EventDynamicSecretLeaseRevocationFailed,
		projections.EventDynamicSecretOperationRequested,
		projections.EventDynamicSecretOperationCompleted,
	} {
		if got := dynamicSecretEventSchemaVersion(eventType); got != projections.DynamicSecretEventSchemaVersion {
			t.Fatalf("%s schema = %d, want epoch-bound v%d", eventType, got, projections.DynamicSecretEventSchemaVersion)
		}
	}
}
