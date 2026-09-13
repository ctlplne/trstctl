// SPDX-License-Identifier: MPL-2.0

package orchestrator_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// Direct external-CA issuance can be the first event after SQL bootstrap.
// An empty source log is valid only while its SQL metadata has no later or
// unknown certificate writes. Never invent a sequence to pass the fence.
func TestFirstCertificateRecordingAllowsCleanBootstrapAndPreservesMetadataFence(t *testing.T) {
	for _, scenario := range []string{"clean bootstrap", "unknown zero-row writer", "lost source history"} {
		t.Run(scenario, func(t *testing.T) {
			s := newStore(t)
			p := projections.New(s)
			ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
			defer cancel()
			// The installed bootstrap can create its tenant before any events.
			if err := p.Apply(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegisteredJSON("first-external-certificate")}); err != nil {
				t.Fatal(err)
			}
			if scenario == "lost source history" {
				priorLog := openLog(t)
				registered, err := priorLog.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegisteredJSON("first-external-certificate")})
				if err != nil {
					t.Fatal(err)
				}
				if err := p.Apply(ctx, registered); err != nil {
					t.Fatal(err)
				}
				prior, _ := recordingCertificates(t)
				if _, err := orchestrator.NewOrchestrator(priorLog, s, nil).RecordCertificate(ctx, tenantA, prior); err != nil {
					t.Fatal(err)
				}
			}
			log := openLog(t)
			if head, err := log.LastSequence(ctx); err != nil || head != 0 {
				t.Fatalf("fixture source is not empty: %d %v", head, err)
			}
			if scenario == "unknown zero-row writer" {
				if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
					_, err := tx.Exec(ctx, `UPDATE certificates SET source='legacy-unknown' WHERE tenant_id=$1`, tenantA)
					return err
				}); err != nil {
					t.Fatal(err)
				}
			}
			in, _ := recordingCertificates(t)
			in.IssuanceIdempotencyKey = "first-empty-log-certificate"
			o := orchestrator.NewOrchestrator(log, s, nil)
			got, err := o.RecordCertificate(ctx, tenantA, in)
			if scenario != "clean bootstrap" {
				if !errors.Is(err, store.ErrCertificateRecordingRebuildRequired) {
					t.Fatalf("unsafe metadata was not rejected by its fence: %v", err)
				}
				if head, err := log.LastSequence(ctx); err != nil || head != 0 {
					t.Fatalf("unsafe recording appended: %d %v", head, err)
				}
				if _, err := s.GetCertificateByFingerprint(ctx, tenantA, in.Fingerprint); !store.IsNotFound(err) {
					t.Fatalf("unsafe recording wrote a certificate: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("first certificate after clean bootstrap: %v", err)
			}
			if got.Fingerprint != in.Fingerprint || !bytes.Equal(got.CertificateDER, in.CertificateDER) {
				t.Fatal("first certificate material differs")
			}
			replayed, err := o.RecordCertificate(ctx, tenantA, in)
			if err != nil || replayed.ID != got.ID {
				t.Fatalf("first certificate retry differs: %v", err)
			}
			if head, err := log.LastSequence(ctx); err != nil || head != 1 {
				t.Fatalf("first certificate and retry must retain one source event: %d %v", head, err)
			}
			if err := p.ProjectCatchUp(ctx, log); err != nil {
				t.Fatalf("ordered catch-up: %v", err)
			}
		})
	}
}
