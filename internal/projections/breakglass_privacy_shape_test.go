// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/events"
)

// These are the four payloads emitted by the configured signer runtime and the
// offline reconciler. A shape-only ceremony_id policy rejected all four after
// the two-person approval, before the append could commit.
func TestBreakglassPrivacyShapesAcceptProducedEvidenceAndRejectUnknownFields(t *testing.T) {
	for _, tc := range []struct {
		name, eventType, payload string
	}{
		{"offline_issue", EventBreakglassIssued, `{"request_id":"r","subject":"qa-person","reason":"recovery","issued_at":"2026-10-12T12:00:00Z","approvals":2}`},
		{"online_issue", EventBreakglassIssued, `{"request_id":"r","subject":"qa-person","reason":"recovery","issued_at":"2026-10-12T12:00:00Z","approvals":2,"bundle":{"request_id":"r","subject":"qa-person","cert_der":"AQ==","reason":"recovery","approvals":["custodian-a","custodian-b"],"issued_at":"2026-10-12T12:00:00Z","signature":"AQ=="},"ceremony_id":"ceremony-r","request_digest":"digest-r"}`},
		{"rotation", EventBreakglassCARotated, `{"previous_signer_handle":"old","active_signer_handle":"new","previous_certificate_der":"AQ==","active_certificate_der":"AQ==","new_signed_by_previous_der":"AQ==","previous_signed_by_new_der":"AQ==","ceremony_id":"ceremony-r","request_digest":"digest-r","reason":"qa-person","ttl_seconds":900,"approvers":["custodian-a","custodian-b"]}`},
		{"cross_sign", EventBreakglassCACrossSigned, `{"issuer_signer_handle":"issuer","issuer_certificate_der":"AQ==","target_certificate_der":"AQ==","cross_certificate_der":"AQ==","ceremony_id":"ceremony-r","request_digest":"digest-r","approvers":["qa-person","custodian-b"]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := events.PseudonymizeEventDataForSubject([]byte(tc.payload), "tenant-a", "qa-person", tc.eventType, 1)
			if err == nil || !strings.Contains(err.Error(), "rejects subject-bearing payload data") {
				t.Fatalf("expected the closed signed-evidence privacy boundary, got %v", err)
			}
			bad := strings.TrimSuffix(tc.payload, "}") + `,"undeclared":"qa-person"}`
			_, _, err = events.PseudonymizeEventDataForSubject([]byte(bad), "tenant-a", "qa-person", tc.eventType, 1)
			if err == nil || !strings.Contains(err.Error(), "undeclared object field /undeclared") {
				t.Fatalf("unknown break-glass field passed closed shape: %v", err)
			}
		})
	}
}
