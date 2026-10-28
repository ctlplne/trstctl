// SPDX-License-Identifier: BUSL-1.1

package projections

import "trstctl.com/trstctl/internal/events"

// addTransparencyPrivacyShapes closes what CT logs answered for submissions
// (A213): log URLs, log ids and keys, SCT times, digests and inclusion facts,
// no personal data.
func addTransparencyPrivacyShapes(shapes map[privacyEventPolicyKey]events.PrivacyPayloadShape) {
	shapes[privacyEventPolicyKey{EventType: EventCertificateSCTRecorded, Version: 1}] = privacyPayloadShape[CertificateSCTRecorded]()
	shapes[privacyEventPolicyKey{EventType: EventCertificateSCTInclusion, Version: 1}] = privacyPayloadShape[CertificateSCTInclusion]()
}
