// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
)

// Certificate recording scans a shared event stream to recover unfinished
// metadata writes. An old Provider audit partition may appear between two
// tenant commands, but it must never enter the tenant UUID receipt batch.
func TestCertificateRecordingRecoverySkipsLegacyProviderAuditPartition(t *testing.T) {
	s, log, _ := recordingSpine(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	if _, err := log.Append(ctx, events.Event{
		ID:   "legacy-provider-audit-between-certificate-writes",
		Type: "provider.isolation.drill", TenantID: events.LegacyProviderGlobalAuditScope,
		Data: []byte(`{"result":"recorded"}`),
	}); err != nil {
		t.Fatal(err)
	}
	in, _ := recordingCertificates(t)
	if _, err := orchestrator.NewOrchestrator(log, s, nil).RecordCertificate(ctx, tenantA, in); err != nil {
		t.Fatalf("certificate recording crossed historical Provider audit: %v", err)
	}
}
