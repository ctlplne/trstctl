// SPDX-License-Identifier: MPL-2.0

package orchestrator

import "trstctl.com/trstctl/internal/events"

// authz.decision is emitted by the command layer rather than a projector, so it
// cannot rely on the projector catalog to register its production append shape.
// Keep the payload closed here: the actor and governed target are exact identity
// fields, while policy vocabulary and role names are non-personal authority data.
func init() {
	err := events.RegisterPrivacyEventPolicy(EventAuthzDecision, events.DefaultSchemaVersion, events.PrivacyEventPolicy{
		Rules: []events.PrivacyFieldRule{
			{Path: "/actor", Mode: events.PrivacyFieldIdentityExact},
			{Path: "/permission", Mode: events.PrivacyFieldOpaqueExact},
			{Path: "/resource", Mode: events.PrivacyFieldOpaqueExact},
			{Path: "/target", Mode: events.PrivacyFieldIdentityExact},
			{Path: "/decision", Mode: events.PrivacyFieldOpaqueExact},
			{Path: "/reason", Mode: events.PrivacyFieldFreeTextClear},
			{Path: "/roles/*", Mode: events.PrivacyFieldSubjectToken},
		},
		PayloadShape: events.PrivacyPayloadShapeOf[AuthzDecision](),
	})
	if err != nil {
		panic(err)
	}
}
