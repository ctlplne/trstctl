// SPDX-License-Identifier: BUSL-1.1

package projections

import "trstctl.com/trstctl/internal/events"

// These are exact payload-field policies for the revocation worker receipts.
// Keeping them beside the workflow also keeps the central schema registry
// below its served-source size guard.
func keyCompromiseCAEffectPrivacyPolicy() events.PrivacyEventPolicy {
	const opaque = events.PrivacyFieldOpaqueExact
	return privacyRules(
		privacyRule("/source_event_id", opaque), privacyRule("/outbox_id", opaque),
		privacyRule("/destination", opaque), privacyRule("/status", opaque),
		privacyRule("/attempts", opaque),
	)
}

func revocationBatchPrivacyPolicy() events.PrivacyEventPolicy {
	const opaque = events.PrivacyFieldOpaqueExact
	return privacyRules(
		privacyRule("/request_binding", opaque), privacyRule("/reason", opaque),
		privacyRule("/items/*/id", opaque), privacyRule("/items/*/matched", opaque),
		privacyRule("/items/*/status", opaque), privacyRule("/items/*/error", opaque),
		privacyRule("/items/*/fingerprint", opaque), privacyRule("/items/*/serial", opaque),
		privacyRule("/items/*/ca_id", opaque),
		privacyRule("/items/*/external_ca_id", opaque),
	)
}
