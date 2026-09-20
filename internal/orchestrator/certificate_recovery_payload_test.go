// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"encoding/json"
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// An exact completion receipt is the only authority to skip repeated domain
// decoding. A retained, unapplied malformed payload must still block any new
// append, just as it blocks the ordinary projector.
func TestCertificateRecoveryUnappliedMalformedPayloadRefusesBeforeAppend(t *testing.T) {
	for _, payload := range []string{`{"fingerprint":42}`, `{"certificate_der":{}}`, `{"subject":["wrong shape"]}`} {
		t.Run(payload, func(t *testing.T) {
			s, log, p := recordingSpine(t)
			ctx := t.Context()
			bad, err := log.Append(ctx, events.Event{Type: projections.EventCertificateRecorded, TenantID: tenantA, Data: []byte(payload)})
			if err != nil {
				t.Fatal(err)
			}
			var shape *json.UnmarshalTypeError
			if err := p.Apply(ctx, bad); !errors.As(err, &shape) {
				t.Fatalf("ordinary projector did not reject malformed material: %v", err)
			}
			in, _ := recordingCertificates(t)
			o := orchestrator.NewOrchestrator(log, s, nil)
			for range 2 {
				got, err := o.RecordCertificate(ctx, tenantA, in)
				if !errors.As(err, &shape) || got.ID != "" {
					t.Fatalf("recovery did not preserve payload refusal: certificate=%q err=%v", got.ID, err)
				}
				if head, err := log.LastSequence(ctx); err != nil || head != bad.Sequence {
					t.Fatalf("malformed recovery appended an event: head=%d err=%v", head, err)
				}
				rows, err := s.ListCertificatesPage(ctx, tenantA, store.ZeroUUID, nil, 10, nil)
				if err != nil || len(rows) != 0 {
					t.Fatalf("malformed recovery changed inventory: rows=%d err=%v", len(rows), err)
				}
			}
		})
	}
}
