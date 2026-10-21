// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"fmt"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/succession"
)

// The PCAS succession vocabulary (internal/succession) is shared with the agent
// binary, which must not link the control plane's event log, so its closed
// privacy policies register here on the control-plane append side: the served
// control plane refuses any append whose exact (type, schema version) has no
// policy, and the full-stack conformance journeys run under that same
// requirement. Every payload type below is rejecting (no subject data may be
// rewritten in a signed record); the finding keeps its free-text reason
// clearable. The genesis and KEM events live in the core events catalog with
// explicit shapes.
func init() {
	rejecting := func(shape events.PrivacyPayloadShape, rules ...events.PrivacyFieldRule) events.PrivacyEventPolicy {
		return events.PrivacyEventPolicy{Rules: rules, PayloadShape: shape, RejectSubjectData: true}
	}
	policies := []struct {
		eventType string
		version   int
		policy    events.PrivacyEventPolicy
	}{
		{succession.TypeFinding, succession.FindingSchemaV1, events.PrivacyEventPolicy{
			Rules:        []events.PrivacyFieldRule{{Path: "/reason", Mode: events.PrivacyFieldFreeTextClear}},
			PayloadShape: events.PrivacyPayloadShapeOf[succession.FindingV1](),
		}},
		{succession.TypeSuccession, succession.SuccessionSchemaV1, rejecting(events.PrivacyPayloadShapeOf[succession.SuccessionV1]())},
		{succession.TypeRetirement, succession.RetirementSchemaV1, rejecting(events.PrivacyPayloadShapeOf[succession.RetirementV1]())},
		{succession.TypeRPAck, succession.RPAckSchemaV1, rejecting(events.PrivacyPayloadShapeOf[succession.RPAckV1]())},
		{succession.TypeRefusal, succession.RefusalSchemaV1, rejecting(events.PrivacyPayloadShapeOf[succession.RefusalV1]())},
		{succession.TypeRewrapStage, succession.RewrapStageSchemaV1, rejecting(events.PrivacyPayloadShapeOf[succession.RewrapStageV1]())},
		{succession.TypeRewrapCompleted, succession.RewrapCompletedSchemaV1, rejecting(events.PrivacyPayloadShapeOf[succession.RewrapCompletedV1]())},
		{succession.TypeMisissuance, succession.MisissuanceSchemaV1, rejecting(events.PrivacyPayloadShapeOf[succession.MisissuanceV1]())},
	}
	for _, p := range policies {
		if err := events.RegisterPrivacyEventPolicy(p.eventType, p.version, p.policy); err != nil {
			panic(fmt.Sprintf("pcas orchestrator: register privacy policy for %s v%d: %v", p.eventType, p.version, err))
		}
	}
}
