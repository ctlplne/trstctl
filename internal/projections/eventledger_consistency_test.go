package projections_test

import (
	"testing"

	"trstctl.com/trstctl/internal/eventledger"
	"trstctl.com/trstctl/internal/projections"
)

// projectionEventConstants is the set of event-type strings the projector decodes.
// It mirrors the Event* constants in projections.go. The ledger (internal/eventledger)
// duplicates these strings as literals because it is a leaf package that internal/audit
// can import without an import cycle; this test pins the duplication to the projector's
// constants so the two can never silently drift (COVER-008).
var projectionEventConstants = map[string]string{
	projections.EventCertificateRecorded:                 "EventCertificateRecorded",
	projections.EventCertificateRevoked:                  "EventCertificateRevoked",
	projections.EventCertificateSuperseded:               "EventCertificateSuperseded",
	projections.EventCACeremonyStarted:                   "EventCACeremonyStarted",
	projections.EventCACeremonyApproved:                  "EventCACeremonyApproved",
	projections.EventCARootCreated:                       "EventCARootCreated",
	projections.EventCAAuthorityImported:                 "EventCAAuthorityImported",
	projections.EventCAAuthorityRotated:                  "EventCAAuthorityRotated",
	projections.EventCAAuthorityRekeyed:                  "EventCAAuthorityRekeyed",
	projections.EventCAIntermediateCreated:               "EventCAIntermediateCreated",
	projections.EventCAIntermediateCSRIssued:             "EventCAIntermediateCSRIssued",
	projections.EventCAEndEntityIssued:                   "EventCAEndEntityIssued",
	projections.EventOCSPResponderRotated:                "EventOCSPResponderRotated",
	projections.EventDiscoverySourceUpserted:             "EventDiscoverySourceUpserted",
	projections.EventDiscoveryScheduleUpserted:           "EventDiscoveryScheduleUpserted",
	projections.EventDiscoveryRunQueued:                  "EventDiscoveryRunQueued",
	projections.EventDiscoveryFindingTriageChanged:       "EventDiscoveryFindingTriageChanged",
	projections.EventACMEDNS01ProviderConfigUpserted:     "EventACMEDNS01ProviderConfigUpserted",
	projections.EventACMEDNS01ProviderConfigDeleted:      "EventACMEDNS01ProviderConfigDeleted",
	projections.EventACMEDNS01Preflighted:                "EventACMEDNS01Preflighted",
	projections.EventMDMSCEPPolicyUpserted:               "EventMDMSCEPPolicyUpserted",
	projections.EventMDMSCEPPolicyDeleted:                "EventMDMSCEPPolicyDeleted",
	projections.EventMDMSCEPChallengeRotated:             "EventMDMSCEPChallengeRotated",
	projections.EventWorkloadAttesterTrustSourceUpserted: "EventWorkloadAttesterTrustSourceUpserted",
	projections.EventWorkloadAttesterTrustSourceRotated:  "EventWorkloadAttesterTrustSourceRotated",
	projections.EventWorkloadAttesterTrustSourceRevoked:  "EventWorkloadAttesterTrustSourceRevoked",
	projections.EventWorkloadAttesterTrustSourceDeleted:  "EventWorkloadAttesterTrustSourceDeleted",
	projections.EventComplianceReportScheduleUpserted:    "EventComplianceReportScheduleUpserted",
	projections.EventSecretRotationScheduleUpserted:      "EventSecretRotationScheduleUpserted",
	projections.EventSecretRotationScheduleRan:           "EventSecretRotationScheduleRan",
	projections.EventCBOMAssetObserved:                   "EventCBOMAssetObserved",
	projections.EventPQCMigrationStarted:                 "EventPQCMigrationStarted",
	projections.EventPQCMigrationAssetCompleted:          "EventPQCMigrationAssetCompleted",
	projections.EventPQCMigrationRollbackCompleted:       "EventPQCMigrationRollbackCompleted",
	projections.EventIdentityCreated:                     "EventIdentityCreated",
	projections.EventIdentityIssued:                      "EventIdentityIssued",
	projections.EventIdentityDeployed:                    "EventIdentityDeployed",
	projections.EventIdentityRenewing:                    "EventIdentityRenewing",
	projections.EventIdentityRenewed:                     "EventIdentityRenewed",
	projections.EventIdentityRevoked:                     "EventIdentityRevoked",
	projections.EventIdentityRetired:                     "EventIdentityRetired",
	projections.EventIssuerCreated:                       "EventIssuerCreated",
	projections.EventDeploymentTargetUpserted:            "EventDeploymentTargetUpserted",
	projections.EventDeploymentTargetDeleted:             "EventDeploymentTargetDeleted",
	projections.EventIdentityConnectorTargetBound:        "EventIdentityConnectorTargetBound",
	projections.EventConnectorDeliveryRecorded:           "EventConnectorDeliveryRecorded",
	projections.EventLifecycleRotationRecorded:           "EventLifecycleRotationRecorded",
	projections.EventIncidentExecutionRecorded:           "EventIncidentExecutionRecorded",
	projections.EventIncidentFleetReissuanceRecorded:     "EventIncidentFleetReissuanceRecorded",
	projections.EventRemediationPlaybookRunRecorded:      "EventRemediationPlaybookRunRecorded",
	projections.EventResponseIntegrationDispatched:       "EventResponseIntegrationDispatched",
	projections.EventOwnerCreated:                        "EventOwnerCreated",
	projections.EventOwnerUpdated:                        "EventOwnerUpdated",
	projections.EventOwnerDeleted:                        "EventOwnerDeleted",
	projections.EventTenantMemberUpserted:                "EventTenantMemberUpserted",
	projections.EventTenantMemberOffboarded:              "EventTenantMemberOffboarded",
	projections.EventAPITokenCreated:                     "EventAPITokenCreated",
	projections.EventAPITokenRevoked:                     "EventAPITokenRevoked",
	projections.EventPAMSessionStarted:                   "EventPAMSessionStarted",
	projections.EventPAMSessionExpired:                   "EventPAMSessionExpired",
	projections.EventProfileCreated:                      "EventProfileCreated",
	projections.EventProfileUpdated:                      "EventProfileUpdated",
	projections.EventPrivacySubjectErased:                "EventPrivacySubjectErased",
	projections.EventPrivacyRetentionEnforced:            "EventPrivacyRetentionEnforced",
	projections.EventNHIAccessReviewCampaignStarted:      "EventNHIAccessReviewCampaignStarted",
	projections.EventNHIAccessReviewItemDecided:          "EventNHIAccessReviewItemDecided",
	projections.EventAccessChangeRequestCreated:          "EventAccessChangeRequestCreated",
	projections.EventAccessChangeRequestDecided:          "EventAccessChangeRequestDecided",
}

// TestEventLedgerConstantsMatchProjector asserts every event type the ledger
// catalogues is a real projector event constant — so the leaf-package literals
// cannot drift from the shapes the projector actually decodes. A typo in the ledger
// (an event type the projector never emits) fails here.
func TestEventLedgerConstantsMatchProjector(t *testing.T) {
	for _, typ := range eventledger.EventTypes() {
		if _, ok := projectionEventConstants[typ]; !ok {
			t.Errorf("ledger catalogues event %q that is not a projector event constant; the catalog has drifted from internal/projections", typ)
		}
	}
}

// TestEventLedgerEntriesNonEmpty asserts every ledger row names a feature id, an
// action, and at least one non-empty event type. This is the "no catalogued action
// points at an empty event name" half of the COVER-008 completeness contract.
func TestEventLedgerEntriesNonEmpty(t *testing.T) {
	for _, fe := range projections.EventLedger() {
		if fe.FeatureID == "" || fe.Action == "" {
			t.Errorf("ledger row %+v missing feature id or action", fe)
		}
		if len(fe.EventTypes) == 0 {
			t.Errorf("ledger row %s/%s has no event type", fe.FeatureID, fe.Action)
		}
		for _, typ := range fe.EventTypes {
			if typ == "" {
				t.Errorf("ledger row %s/%s has an empty event type", fe.FeatureID, fe.Action)
			}
		}
	}
}

// TestEventTypesForFeatureActionResolves checks the audit-filter resolver: a
// feature+action returns its event types, a feature alone widens to all its actions'
// types, an empty selector signals "no filter", and an unknown selector signals
// "filter set but matched nothing" (so the audit query returns zero records rather
// than the unfiltered log).
func TestEventTypesForFeatureActionResolves(t *testing.T) {
	if types, ok := projections.EventTypesForFeatureAction("F6", "revoke"); !ok || len(types) != 1 || types[0] != projections.EventIdentityRevoked {
		t.Fatalf("F6/revoke = %v ok=%v, want [%s]", types, ok, projections.EventIdentityRevoked)
	}
	// A renewal action emits two phases.
	if types, ok := projections.EventTypesForFeatureAction("F6", "renew"); !ok || len(types) != 2 {
		t.Fatalf("F6/renew = %v ok=%v, want two event types", types, ok)
	}
	// Feature alone widens to all that feature's event types (more than one action).
	if types, ok := projections.EventTypesForFeatureAction("F8", ""); !ok || len(types) < 2 {
		t.Fatalf("F8 (feature only) = %v ok=%v, want several event types", types, ok)
	}
	// Empty selector: no filter.
	if types, ok := projections.EventTypesForFeatureAction("", ""); ok || types != nil {
		t.Fatalf("empty selector = %v ok=%v, want (nil,false)", types, ok)
	}
	// Unknown selector: filter set, nothing matched.
	if types, ok := projections.EventTypesForFeatureAction("F999", "nope"); !ok || len(types) != 0 {
		t.Fatalf("unknown selector = %v ok=%v, want ([],true)", types, ok)
	}
}
