// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"fmt"

	"trstctl.com/trstctl/internal/events"
)

func registerProjectorPrivacyPolicies() {
	exact := exactProjectorPrivacyPolicies()
	exactShapes := exactProjectorPrivacyPayloadShapes()
	shapes := projectorPrivacyPayloadShapes()
	rejectRules := projectorRejectPrivacyRules()
	for eventType, versions := range knownSchemaVersions {
		for version := range versions {
			if events.HasPrivacyEventPolicy(eventType, version) {
				continue
			}
			policy, ok := exact[privacyEventPolicyKey{EventType: eventType, Version: version}]
			if ok {
				shape, found := exactShapes[privacyEventPolicyKey{EventType: eventType, Version: version}]
				if !found {
					panic(fmt.Sprintf("no concrete exact privacy payload shape for projector event %s v%d", eventType, version))
				}
				policy.PayloadShape = shape
			} else {
				shape, found := shapes[privacyEventPolicyKey{EventType: eventType, Version: version}]
				if !found {
					panic(fmt.Sprintf("no closed privacy payload shape for projector event %s v%d", eventType, version))
				}
				policy = events.PrivacyEventPolicy{
					Rules:             append([]events.PrivacyFieldRule(nil), rejectRules[eventType]...),
					PayloadShape:      shape,
					RejectSubjectData: true,
				}
			}
			if err := events.RegisterPrivacyEventPolicy(eventType, version, policy); err != nil {
				panic(fmt.Sprintf("register exact privacy policy for %s v%d: %v", eventType, version, err))
			}
		}
	}
}
