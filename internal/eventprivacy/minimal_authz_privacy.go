// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import "trstctl.com/trstctl/internal/events"

// AuthorizationPrivacyPolicies returns fresh, version-specific typed policies
// shared by source registration and the projector's closed-shape registry.
func AuthorizationPrivacyPolicies() map[int]events.PrivacyEventPolicy {
	return map[int]events.PrivacyEventPolicy{
		events.DefaultSchemaVersion: detailedAuthzPrivacyPolicy(),
		MinimalAuthzSchemaVersion: {
			Rules: []events.PrivacyFieldRule{
				{Path: "/permission", Mode: events.PrivacyFieldOpaqueExact},
				{Path: "/decision", Mode: events.PrivacyFieldOpaqueExact},
				{Path: "/details_omitted", Mode: events.PrivacyFieldOpaqueExact},
			},
			PayloadShape: events.PrivacyPayloadShapeOf[MinimalAuthzDecision](),
		},
	}
}

func init() {
	for version, policy := range AuthorizationPrivacyPolicies() {
		if err := events.RegisterPrivacyEventPolicy(EventAuthorizationDecision, version, policy); err != nil {
			panic(err)
		}
	}
}
