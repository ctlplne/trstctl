// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A recovery scan must admit the retained schema before classifying its fields.
// Unknown future fields cannot make pending metadata look irrelevant and permit
// an irreversible append after the projector has already refused that event.
func TestCertificateRecordingRejectsFutureSchemaBeforeRecoveryAppend(t *testing.T) {
	for _, tc := range []struct{ name, kind, payload string }{
		{"malformed_ownership", projections.EventOwnershipAssigned, `"future ownership shape"`},
		{"future_ownership_fields", projections.EventOwnershipAssigned, `{"future_inventory_ids":["certificate/future"]}`},
		{"future_certificate_fields", projections.EventCertificateRecorded, `{"future_fingerprint":"future-public-fingerprint"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, log, p := recordingSpine(t)
			ctx := t.Context()
			e, err := log.Append(ctx, events.Event{Type: tc.kind, TenantID: tenantA, SchemaVersion: 99, Data: []byte(tc.payload)})
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Apply(ctx, e); !errors.Is(err, projections.ErrUnknownSchemaVersion) {
				t.Fatalf("projection did not reject future schema: %v", err)
			}
			before, err := log.LastSequence(ctx)
			if err != nil {
				t.Fatal(err)
			}
			in, _ := recordingCertificates(t)
			o := orchestrator.NewOrchestrator(log, s, nil)
			for attempt := 0; attempt < 2; attempt++ {
				certificate, commandErr := o.RecordCertificate(ctx, tenantA, in)
				if !errors.Is(commandErr, projections.ErrUnknownSchemaVersion) || certificate.ID != "" {
					t.Fatalf("recovery attempt %d did not refuse with schema error: certificate=%q err=%v", attempt, certificate.ID, commandErr)
				}
				after, err := log.LastSequence(ctx)
				if err != nil || after != before {
					t.Fatalf("recovery appended after future schema: before=%d after=%d err=%v", before, after, err)
				}
				rows, err := s.ListCertificatesPage(ctx, tenantA, store.ZeroUUID, nil, 10, nil)
				if err != nil || len(rows) != 0 {
					t.Fatalf("recovery changed certificate inventory: rows=%d err=%v", len(rows), err)
				}
			}
		})
	}
}
