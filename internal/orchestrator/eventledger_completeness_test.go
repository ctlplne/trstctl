package orchestrator_test

import (
	"testing"

	"trstctl.com/trstctl/internal/eventledger"
	"trstctl.com/trstctl/internal/orchestrator"
)

// TestEventLedgerCoversLifecycleTransitions is the COVER-008 conformance check on
// the served lifecycle path: every event type the lifecycle state machine emits
// (derived from the transition registry, the source of truth) must map back to a
// catalogued entry in the event-name ledger. The audit finding was that some
// mutating GA paths emitted events with no defined feature/action, so an auditor
// could not filter the trail by feature_id/action. This test makes that
// impossible to regress for the lifecycle path: add a transition that emits a new
// event type without cataloguing it in internal/eventledger and this fails.
//
// It needs no database — it compares two in-memory tables — but lives in the
// orchestrator package so the assertion sits next to the state machine it guards
// (and is covered by the COVER-008 gate, which names ./internal/orchestrator).
func TestEventLedgerCoversLifecycleTransitions(t *testing.T) {
	for typ := range orchestrator.LifecycleEventTypes() {
		if !eventledger.HasEventType(typ) {
			t.Errorf("lifecycle emits event %q that the event ledger does not catalogue; "+
				"add a row to internal/eventledger so audit can filter it by feature_id/action (COVER-008)", typ)
		}
	}
}

// orchestratorCommandEventTypes is the set of event types the orchestrator's served
// domain commands emit (internal/orchestrator/commands.go), beyond the lifecycle
// transitions. Each is a mutating GA path that must be filterable in the audit trail.
// Adding a served command that emits a new event type means adding it here and to the
// ledger; this list and the ledger are cross-asserted below.
var orchestratorCommandEventTypes = []string{
	eventledger.EventCertificateRecorded,
	eventledger.EventCertificateRevoked,
	eventledger.EventCertificateSuperseded,
	eventledger.EventIdentityCreated,
	eventledger.EventIssuerCreated,
	eventledger.EventOwnerCreated,
	eventledger.EventOwnerUpdated,
	eventledger.EventOwnerDeleted,
	eventledger.EventProfileCreated,
	eventledger.EventProfileUpdated,
	eventledger.EventTenantMemberUpserted,
	eventledger.EventTenantMemberOffboarded,
	eventledger.EventAPITokenCreated,
	eventledger.EventAPITokenRevoked,
	eventledger.EventDeploymentTargetUpserted,
	eventledger.EventDeploymentTargetDeleted,
	eventledger.EventIdentityConnectorTargetBound,
	eventledger.EventConnectorDeliveryRecorded,
	eventledger.EventLifecycleRotationRecorded,
	eventledger.EventIncidentExecutionRecorded,
	eventledger.EventDiscoverySourceUpserted,
	eventledger.EventDiscoveryScheduleUpserted,
	eventledger.EventDiscoveryRunQueued,
	eventledger.EventPrivacySubjectErased,
	eventledger.EventPrivacyRetentionEnforced,
	eventledger.EventNHIAccessReviewCampaignStarted,
	eventledger.EventNHIAccessReviewItemDecided,
}

// TestEventLedgerCoversCommandEvents asserts every served orchestrator command event
// is catalogued, and conversely every ledger entry names a non-empty event type — the
// two-direction completeness contract from COVER-008.
func TestEventLedgerCoversCommandEvents(t *testing.T) {
	for _, typ := range orchestratorCommandEventTypes {
		if !eventledger.HasEventType(typ) {
			t.Errorf("served command emits event %q absent from the event ledger (COVER-008)", typ)
		}
	}
	for _, fe := range eventledger.Ledger() {
		if len(fe.EventTypes) == 0 {
			t.Errorf("ledger row %s/%s has no event type", fe.FeatureID, fe.Action)
		}
		for _, typ := range fe.EventTypes {
			if typ == "" {
				t.Errorf("ledger row %s/%s names an empty event type", fe.FeatureID, fe.Action)
			}
		}
	}
}
