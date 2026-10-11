// SPDX-License-Identifier: BUSL-1.1

package projections

import "trstctl.com/trstctl/internal/events"

// CA cross-signing has one event contract for signer-backed issuers and
// imported offline roots. The offline marker is the only optional field;
// both public certificates and their exact ceremony binding are required.
type privacyCACrossSignedV1 struct {
	CAID                 string `json:"ca_id"`
	CeremonyID           string `json:"ceremony_id"`
	OfflineRoot          bool   `json:"offline_root,omitempty"`
	TargetCertificateDER []byte `json:"target_certificate_der"`
	CrossCertificateDER  []byte `json:"cross_certificate_der"`
	TargetSHA256         string `json:"target_sha256"`
}

// Earlier in-process hierarchy events recorded completion but omitted the
// certificate. They remain replayable; no public receipt can be inferred.
type privacyCACrossSignedLegacyV1 struct {
	CAID       string `json:"ca_id"`
	CeremonyID string `json:"ceremony_id"`
}

func caCrossSignedPrivacyShape() events.PrivacyPayloadShape {
	return events.PrivacyPayloadShapeOneOf(
		privacyPayloadShape[privacyCACrossSignedV1](),
		privacyPayloadShape[privacyCACrossSignedLegacyV1](),
	)
}
