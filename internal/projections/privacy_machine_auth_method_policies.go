// SPDX-License-Identifier: BUSL-1.1

package projections

import "trstctl.com/trstctl/internal/events"

// The method name is an authority key and must remain byte-identical through
// erasure. The operator attribution is personal data and can be pseudonymized.
func machineAuthMethodPrivacyPolicies() map[privacyEventPolicyKey]events.PrivacyEventPolicy {
	policy := privacyRules(
		privacyRule("/name", events.PrivacyFieldOpaqueExact),
		privacyRule("/updated_by", events.PrivacyFieldIdentityExact),
	)
	return map[privacyEventPolicyKey]events.PrivacyEventPolicy{
		{EventMachineAuthMethodDisabled, 1}: policy,
		{EventMachineAuthMethodEnabled, 1}:  policy,
	}
}
