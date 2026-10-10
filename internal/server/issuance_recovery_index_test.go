// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"testing"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

func TestRetainedCertificateRecoverySelectsExactKeyAfterColdRestart(t *testing.T) {
	const tenant = "a1000000-0000-4000-8000-000000000001"
	const otherTenant = "b2000000-0000-4000-8000-000000000002"
	cfg := config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}
	log, err := events.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	appendEvent := func(id, eventType, tenantID, key string) {
		t.Helper()
		if _, err := log.Append(t.Context(), events.Event{ID: id, Type: eventType, TenantID: tenantID,
			Data: []byte(`{"issuance_idempotency_key":"` + key + `"}`)}); err != nil {
			t.Fatal(err)
		}
	}
	appendEvent("wrong-type", "test.unrelated", tenant, "issue:wanted")
	for range 80 {
		appendEvent("", "test.unrelated", otherTenant, "")
	}
	appendEvent("wrong-tenant", projections.EventCertificateRecorded, otherTenant, "issue:wanted")
	appendEvent("wrong-key", projections.EventCertificateRecorded, tenant, "issue:other")
	appendEvent("wanted-certificate", projections.EventCertificateRecorded, tenant, "issue:wanted")
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	log, err = events.Open(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	got, err := retainedCertificatesByIssuanceKey(t.Context(), log, tenant, "issue:wanted")
	if err != nil || len(got) != 1 || got[0].ID != "wanted-certificate" {
		t.Fatalf("cold recovery events = %+v, err=%v; want exact tenant/key certificate", got, err)
	}
	missing, err := retainedCertificatesByIssuanceKey(t.Context(), log, tenant, "issue:missing")
	if err != nil || len(missing) != 0 {
		t.Fatalf("missing issuance key returned %d retained events: %v", len(missing), err)
	}
}
