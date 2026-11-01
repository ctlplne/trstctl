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
