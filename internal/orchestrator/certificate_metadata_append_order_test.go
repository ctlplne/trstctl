// SPDX-License-Identifier: MPL-2.0

package orchestrator_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// A real demo failed when revocation appended while another recording owned
// the metadata fence. The recording committed a later sequence first, making
// the unapplied revocation unsafe forever. Admission must precede the append.
func TestCertificateMetadataCommandsFenceBeforeAppend(t *testing.T) {
	for _, command := range []string{"revoke", "durable-revoke", "supersede"} {
		t.Run(command, func(t *testing.T) {
			s, log, projector := recordingSpine(t)
			ctx, cancel := context.WithTimeout(t.Context(), 35*time.Second)
			defer cancel()
			in, _ := recordingCertificates(t)
			in.Source, in.IssuanceIdempotencyKey = "import", ""
			in.CertificateDER, in.CertificatePEM = nil, nil
			if _, err := orchestrator.NewOrchestrator(log, s, nil).RecordCertificate(ctx, tenantA, in); err != nil {
				t.Fatal(err)
			}
			var recording events.Event
			if err := log.Replay(ctx, 2, func(e events.Event) error { recording = e; return nil }); err != nil {
				t.Fatal(err)
			}
			before := recording.Sequence
			peer, err := store.Open(ctx, testDSN+"?application_name=metadata_append_peer")
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			o := orchestrator.NewOrchestrator(log, peer, nil)
			result := make(chan error, 1)
			var expected string
			err = s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
				if err := s.LockCertificateMetadataOrderTx(ctx, tx, tenantA); err != nil {
					return err
				}
				go func() {
					switch command {
					case "revoke":
						result <- o.RevokeCertificate(ctx, tenantA, in.Fingerprint, in.Serial, "keyCompromise", time.Now().UTC())
					case "durable-revoke":
						result <- o.RevokeCertificateForCAWithEventID(ctx, tenantA, "owned-append-order-revoke", in.Fingerprint, in.Serial, "", "keyCompromise", 1)
					case "supersede":
						result <- o.SupersedeCertificate(ctx, tenantA, in.Fingerprint, in.Serial, "replacement", time.Now().UTC())
					}
				}()
				// Observe the actual independent PostgreSQL session waiting. A
				// sleep alone could pass without the competing command starting.
				waiting := false
				until := time.Now().Add(5 * time.Second)
				for time.Now().Before(until) {
					//trstctl:system-query — inspect only the owned fixture session's lock state; no tenant data is selected (AN-1 exemption).
					if err := s.SystemPool().QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name='metadata_append_peer' AND wait_event_type='Lock' AND wait_event='advisory')`).Scan(&waiting); err != nil {
						return err
					}
					if waiting {
						break
					}
					time.Sleep(10 * time.Millisecond)
				}
				if !waiting {
					return fmt.Errorf("metadata command never reached the owned PostgreSQL fence")
				}
				if head, err := log.LastSequence(ctx); err != nil || head != before {
					return fmt.Errorf("metadata command appended before admission: before=%d after=%d err=%v", before, head, err)
				}
				// Finish the recording that already owns admission, through the
				// real log and projector. The waiting command must append later.
				recording.ID, recording.Sequence, recording.Time = "", 0, time.Time{}
				recorded, err := log.Append(ctx, recording)
				if err != nil {
					return err
				}
				return projector.ApplyTx(ctx, tx, recorded)
			})
			// The transaction releases admission even on a failed assertion;
			// collect the owned worker before closing its pool or fixture.
			select {
			case commandErr := <-result:
				if err != nil {
					t.Fatal(err)
				}
				if commandErr != nil {
					t.Fatal(commandErr)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if command == "supersede" {
				expected = "superseded"
			} else {
				expected = "revoked"
			}
			check := func() {
				t.Helper()
				certificate, err := s.GetCertificateByFingerprint(ctx, tenantA, in.Fingerprint)
				if err != nil || certificate.Status != expected {
					t.Fatalf("metadata state=%s want=%s err=%v", certificate.Status, expected, err)
				}
				if head, err := log.LastSequence(ctx); err != nil || head != before+2 {
					t.Fatalf("unexpected source history: %d %v", head, err)
				}
			}
			check()
			if err := projector.ProjectCatchUp(ctx, log); err != nil {
				t.Fatal(err)
			}
			check()
			if err := projector.Rebuild(ctx, log); err != nil {
				t.Fatal(err)
			}
			check()
		})
	}
}
