// SPDX-License-Identifier: BUSL-1.1

package projections

import "trstctl.com/trstctl/internal/events"

// addTransparencyPrivacyShapes closes what CT logs answered for submissions
// (A213): log URLs, log ids and keys, SCT times, digests and inclusion facts,
// no personal data; and the public certificate bytes recovered for an
// inventory row (A215).
func addTransparencyPrivacyShapes(shapes map[privacyEventPolicyKey]events.PrivacyPayloadShape) {
	shapes[privacyEventPolicyKey{EventType: EventCertificateSCTRecorded, Version: 1}] = privacyPayloadShape[CertificateSCTRecorded]()
	shapes[privacyEventPolicyKey{EventType: EventCertificateSCTInclusion, Version: 1}] = privacyPayloadShape[CertificateSCTInclusion]()
	// A215: recovered certificate bytes and where they came from.
	shapes[privacyEventPolicyKey{EventType: EventCertificateDERRecovered, Version: 1}] = privacyPayloadShape[CertificateDERRecovered]()
}
