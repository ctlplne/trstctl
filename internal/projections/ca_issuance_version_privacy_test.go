// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

func TestCAIssuancePublicEvidenceRequiresVersionedPrivacyPayload(t *testing.T) {
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, events.WithRequiredPrivacyEventPolicies())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	for _, tc := range []struct {
		name, kind, payload string
	}{
		{"responder", EventCAIssuedCertificate, `{"ca_id":"issuer","serial":"12","issued_at":"2026-09-27T00:00:00Z","source":"pkisecret","certificate_der":"AQID","fingerprint":"public-fingerprint"}`},
		{"hierarchy", EventCAEndEntityIssued, `{"ca_id":"issuer","serial":"12","subject":"CN=leaf","certificate_der":"AQID","fingerprint":"public-fingerprint"}`},
		{"exact-migration", EventCAEndEntityIssued, `{"ca_id":"issuer","serial":"12","subject":"CN=leaf","certificate_der":"AQID","fingerprint":"public-fingerprint","migration_exact_authority":true}`},
		{"rotation-route", EventCAEndEntityIssued, `{"ca_id":"successor","serial":"12","subject":"CN=leaf","certificate_der":"AQID","fingerprint":"public-fingerprint","requested_ca_id":"issuer","rotation_routed":true}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			event := events.Event{ID: "public-proof-v1-" + tc.name, TenantID: "11111111-1111-4111-8111-111111111111", Type: tc.kind, SchemaVersion: 1, Data: []byte(tc.payload)}
			if _, err := log.Append(t.Context(), event); err == nil {
				t.Error("new public-certificate fields silently widened the historical v1 contract")
			}
			event.ID, event.SchemaVersion = "public-proof-v2-"+tc.name, 2
			if _, err := log.Append(t.Context(), event); err != nil {
				t.Errorf("declared v2 public-certificate payload rejected: %v", err)
			}
			event.ID, event.Data = "undeclared-proof-v2-"+tc.name, []byte(tc.payload[:len(tc.payload)-1]+`,"private_key":"undeclared"}`)
			if _, err := log.Append(t.Context(), event); err == nil {
				t.Error("v2 accepted an undeclared field")
			}
			event.ID, event.Data = "missing-proof-v2-"+tc.name, []byte(`{"ca_id":"issuer","serial":"12"}`)
			if _, err := log.Append(t.Context(), event); err == nil {
				t.Error("v2 accepted a serial without public certificate evidence")
			}
		})
	}
}
