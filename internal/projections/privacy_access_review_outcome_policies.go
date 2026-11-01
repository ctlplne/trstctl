// SPDX-License-Identifier: BUSL-1.1

package projections

import "trstctl.com/trstctl/internal/events"

// The exact payload-field policies for access review outcomes (Q1). The detail
// and evidence are trstctl's own wording about the reviewed credential; they
// can quote a provider's refusal, so they are free text.

func nhiReviewRevocationRecordedPrivacyPolicy() events.PrivacyEventPolicy {
	const (
		clear  = events.PrivacyFieldFreeTextClear
		opaque = events.PrivacyFieldOpaqueExact
	)
	return privacyRules(
		privacyRule("/campaign_id", opaque), privacyRule("/item_id", opaque),
		privacyRule("/status", opaque), privacyRule("/detail", clear),
	)
}

func nhiReviewItemClosedPrivacyPolicy() events.PrivacyEventPolicy {
	const (
		clear  = events.PrivacyFieldFreeTextClear
		opaque = events.PrivacyFieldOpaqueExact
	)
	return privacyRules(
		privacyRule("/campaign_id", opaque), privacyRule("/item_id", opaque), privacyRule("/evidence", clear),
	)
}
