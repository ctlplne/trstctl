// SPDX-License-Identifier: BUSL-1.1

package eventprivacy

import "trstctl.com/trstctl/internal/events"

// Register both audit schemas before projection initialization. The detailed
// schema is shared with the command layer through a type alias, so its fields
// and privacy classes cannot drift between append and replay.
type AuthzDecision struct {
	Actor      string   `json:"actor"`
	Permission string   `json:"permission"`
	Resource   string   `json:"resource"`
	Target     string   `json:"target"`
	Decision   string   `json:"decision"`
	Reason     string   `json:"reason,omitempty"`
	Roles      []string `json:"roles,omitempty"`
}

func detailedAuthzPrivacyPolicy() events.PrivacyEventPolicy {
	return events.PrivacyEventPolicy{
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
	}
}
