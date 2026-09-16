// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"bytes"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/projections"
)

func TestEndpointVerificationAlertKeepsIncidentIdentityStable(t *testing.T) {
	v := projections.EndpointVerificationObservedWithAlert{
		EndpointVerificationObserved: projections.EndpointVerificationObserved{
			EndpointID: "qa-db", Address: "db.example.test:5432", Vantage: "relay",
			ExpectedFingerprint: "expected", Detail: "first dial error", ObservedAt: time.Now().UTC(),
		}, AlertRequired: true,
	}
	first, err := endpointVerificationAlertEntry("tenant-a", v)
	if err != nil || first.Destination == "" {
		t.Fatalf("first incident: %+v %v", first, err)
	}
	otherTenant, err := endpointVerificationAlertEntry("tenant-b", v)
	if err != nil || otherTenant.IdempotencyKey == first.IdempotencyKey {
		t.Fatalf("tenants shared an external notification identity: %+v %v", otherTenant, err)
	}
	v.Detail = "different dial error on the same unreachable listener"
	v.ObservedAt = v.ObservedAt.Add(time.Minute)
	v.EvidenceDigest = "next-signed-probe"
	next, err := endpointVerificationAlertEntry("tenant-a", v)
	if err != nil || next.IdempotencyKey != first.IdempotencyKey || !bytes.Equal(next.Payload, first.Payload) {
		t.Fatalf("a repeated outage changed its immutable outbox command: %+v %v", next, err)
	}
	for name, change := range map[string]func(*projections.EndpointVerificationObservedWithAlert){
		"recovered then failed": func(v *projections.EndpointVerificationObservedWithAlert) { v.AlertLastGoodAt = time.Now().UTC() },
		"different listener":    func(v *projections.EndpointVerificationObservedWithAlert) { v.Address = "db.example.test:5433" },
		"different vantage":     func(v *projections.EndpointVerificationObservedWithAlert) { v.Vantage = "local" },
		"new expected identity": func(v *projections.EndpointVerificationObservedWithAlert) { v.ExpectedFingerprint = "replacement" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := v
			change(&changed)
			entry, err := endpointVerificationAlertEntry("tenant-a", changed)
			if err != nil || entry.IdempotencyKey == first.IdempotencyKey {
				t.Fatalf("new incident was suppressed: %+v %v", entry, err)
			}
		})
	}
	v.Reached, v.AlertRequired = true, false
	if entry, err := endpointVerificationAlertEntry("tenant-a", v); err != nil || entry.Destination != "" {
		t.Fatalf("healthy observation emitted an alert: %+v %v", entry, err)
	}
	v.AlertRequired = true
	if _, err := endpointVerificationAlertEntry("tenant-a", v); err == nil {
		t.Fatal("contradictory alert authority was accepted")
	}
}
