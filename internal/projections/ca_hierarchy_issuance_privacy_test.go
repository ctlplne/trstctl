// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"bytes"
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
)

func TestCAHierarchyIssuancePrivacyRetainsProducerVariants(t *testing.T) {
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, events.WithRequiredPrivacyEventPolicies())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	for name, payload := range map[string]string{
		"legacy-serial":   `{"ca_id":"issuer","serial":"12"}`,
		"direct":          `{"ca_id":"issuer","serial":"12","subject":"CN=privacy-subject"}`,
		"exact-migration": `{"ca_id":"issuer","serial":"12","subject":"CN=privacy-subject","migration_exact_authority":true}`,
		"rotation-route":  `{"ca_id":"successor","serial":"12","subject":"CN=privacy-subject","requested_ca_id":"issuer","rotation_routed":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			event := events.Event{ID: "hierarchy-" + name, TenantID: "11111111-1111-4111-8111-111111111111", Type: EventCAEndEntityIssued, SchemaVersion: 1, Data: []byte(payload)}
			if _, err := log.Append(t.Context(), event); err != nil {
				t.Fatalf("production producer payload rejected: %v", err)
			}
			retained, found, err := log.EventByID(t.Context(), event.ID)
			if err != nil || !found || !bytes.Equal(retained.Data, event.Data) {
				t.Fatalf("issuance authority evidence changed: found=%v err=%v", found, err)
			}
			if name != "legacy-serial" {
				if _, _, err := events.PseudonymizeEventDataForSubject(retained.Data, event.TenantID, "privacy-subject", event.Type, event.SchemaVersion); err == nil {
					t.Fatal("subject-bearing certificate evidence silently passed the existing reject policy")
				}
			}
		})
	}
	for name, payload := range map[string]string{
		"undeclared":                  `{"ca_id":"issuer","serial":"12","subject":"CN=leaf","private_key":"unexpected"}`,
		"subject-type":                `{"ca_id":"issuer","serial":"12","subject":42}`,
		"missing-subject":             `{"ca_id":"issuer","serial":"12","migration_exact_authority":true}`,
		"missing-requested-authority": `{"ca_id":"issuer","serial":"12","subject":"CN=leaf","rotation_routed":true}`,
		"mixed-routing":               `{"ca_id":"issuer","serial":"12","subject":"CN=leaf","migration_exact_authority":true,"requested_ca_id":"old","rotation_routed":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			event := events.Event{ID: "rejected-hierarchy-" + name, TenantID: "11111111-1111-4111-8111-111111111111", Type: EventCAEndEntityIssued, SchemaVersion: 1, Data: json.RawMessage(payload)}
			if _, err := log.Append(t.Context(), event); err == nil {
				t.Fatal("closed producer variants accepted malformed or undeclared authority")
			}
			if _, found, err := log.EventByID(t.Context(), event.ID); err != nil || found {
				t.Fatalf("rejected event retained: found=%v err=%v", found, err)
			}
		})
	}
}
