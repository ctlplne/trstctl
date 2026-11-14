// SPDX-License-Identifier: BUSL-1.1

package projections

import "trstctl.com/trstctl/internal/events"

// credentialUsedPrivacyPolicy is the exact payload-field policy for
// credential.used (M1). It lives beside the usage projection so the central
// schema registry stays within its served-source size guard. The principal is
// the token's subject; the client network and the rest are opaque.
// tokenExchangedPrivacyPolicy is the exact policy for token.exchanged (M4): the
// principal and the workload's SPIFFE ID name the workload; the rest is opaque.
func tokenExchangedPrivacyPolicy() events.PrivacyEventPolicy {
	const (
		exact  = events.PrivacyFieldIdentityExact
		opaque = events.PrivacyFieldOpaqueExact
	)
	return privacyRules(
		privacyRule("/method", opaque), privacyRule("/principal", exact),
		privacyRule("/spiffe_id", exact), privacyRule("/audience/*", opaque),
		privacyRule("/scopes/*", opaque), privacyRule("/jti", opaque),
		privacyRule("/expires_at", opaque), privacyRule("/subject_token_digest", opaque),
		privacyRule("/issued_token_type", opaque), privacyRule("/opaque", opaque),
	)
}

func credentialUsedPrivacyPolicy() events.PrivacyEventPolicy {
	const (
		exact  = events.PrivacyFieldIdentityExact
		opaque = events.PrivacyFieldOpaqueExact
	)
	return privacyRules(
		privacyRule("/kind", opaque), privacyRule("/credential_id", opaque),
		privacyRule("/principal", exact), privacyRule("/source_kind", opaque),
		privacyRule("/source", opaque), privacyRule("/action", opaque),
		privacyRule("/window_start", opaque), privacyRule("/used_at", opaque),
		privacyRule("/count", opaque),
	)
}

// addCredentialActivityPrivacyPolicies registers the exact policies of the
// credential-activity events — usage (M1), token exchange (M4) and leaked
// secrets moved into the store (P6) — so the central registry stays within its
// served-source size guard.
func addCredentialActivityPrivacyPolicies(policies map[privacyEventPolicyKey]events.PrivacyEventPolicy) {
	policies[privacyEventPolicyKey{EventCredentialUsed, 1}] = credentialUsedPrivacyPolicy()
	policies[privacyEventPolicyKey{EventTokenExchanged, 1}] = tokenExchangedPrivacyPolicy()
	policies[privacyEventPolicyKey{EventDiscoveryFindingSecretMoved, 1}] = discoverySecretMovedPrivacyPolicy()
	policies[privacyEventPolicyKey{EventDiscoveryFindingSecretConsumerRead, 1}] = discoverySecretConsumerReadPrivacyPolicy()
}

// addCredentialActivityPrivacyShapes registers the same events' payload shapes.
func addCredentialActivityPrivacyShapes(shapes map[privacyEventPolicyKey]events.PrivacyPayloadShape) {
	shapes[privacyEventPolicyKey{EventCredentialUsed, 1}] = privacyPayloadShape[CredentialUsed]()
	shapes[privacyEventPolicyKey{EventTokenExchanged, 1}] = privacyPayloadShape[TokenExchanged]()
	shapes[privacyEventPolicyKey{EventDiscoveryFindingSecretMoved, 1}] = privacyPayloadShape[DiscoveryFindingSecretMoved]()
	shapes[privacyEventPolicyKey{EventDiscoveryFindingSecretConsumerRead, 1}] = privacyPayloadShape[DiscoveryFindingSecretConsumerRead]()
}
