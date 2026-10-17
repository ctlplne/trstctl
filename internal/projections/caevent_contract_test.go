// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/caevent"
	"trstctl.com/trstctl/internal/eventspec"
)

func TestProjectorAndSignerAgreeOnCADependencySchemaVersions(t *testing.T) {
	for _, eventType := range []string{
		EventCAIssuedCertificate, EventCAEndEntityIssued, EventCAAuthorityImported,
		EventCAIntermediateCreated, EventCAAuthorityRekeyed,
		EventCAIntermediateCSRIssued, EventCACrossSigned,
	} {
		for version := 0; version <= 4; version++ {
			event := eventspec.Event{Type: eventType, SchemaVersion: version}
			pureErr := caevent.ValidateSchemaVersion(event)
			projectionErr := ValidateSchemaVersion(event)
			if (pureErr == nil) != (projectionErr == nil) {
				t.Errorf("%s v%d: signer=%v projector=%v", eventType, version, pureErr, projectionErr)
			}
			if pureErr != nil && !errors.Is(projectionErr, ErrUnknownSchemaVersion) {
				t.Errorf("%s v%d: projector lost unknown-schema identity: %v", eventType, version, projectionErr)
			}
		}
	}
}

func TestProjectorAndSignerAgreeOnHistoricalCAInventoryIDs(t *testing.T) {
	event := eventspec.Event{TenantID: "11111111-1111-4111-8111-111111111111", ID: "mint-17"}
	if got, want := LegacyManagedCAInventoryID(event), caevent.LegacyManagedCAInventoryID(event); got != want {
		t.Fatalf("managed legacy inventory ID: projector=%s signer=%s", got, want)
	}
	if got, want := SecretPKIInventoryID(event), caevent.SecretPKIInventoryID(event); got != want {
		t.Fatalf("secret PKI inventory ID: projector=%s signer=%s", got, want)
	}
}
