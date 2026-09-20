// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

func TestCertificateMetadataLockRejectsInvalidTenantScope(t *testing.T) {
	s, _, _ := recordingSpine(t)
	ctx := t.Context()
	for _, tc := range []struct {
		name       string
		argument   any
		emptyScope bool
		code       string
	}{
		{"different tenant", "22222222-2222-2222-2222-222222222222", false, "P0001"},
		{"null tenant", nil, false, "P0001"},
		{"empty tenant", "", false, "22P02"},
		{"empty transaction scope", tenantA, true, "22P02"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
				if tc.emptyScope {
					if _, err := tx.Exec(ctx, `SELECT set_config('trstctl.tenant_id','',true)`); err != nil {
						return err
					}
				}
				_, err := tx.Exec(ctx, `SELECT lock_certificate_metadata_order($1::uuid)`, tc.argument)
				return err
			})
			var postgresError *pgconn.PgError
			if !errors.As(err, &postgresError) || postgresError.Code != tc.code {
				t.Fatalf("tenant guard returned %v, want SQLSTATE %s", err, tc.code)
			}
		})
	}
	if err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		return s.LockCertificateMetadataOrderTx(ctx, tx, tenantA)
	}); err != nil {
		t.Fatalf("matching tenant scope rejected: %v", err)
	}
}

func TestCertificateMetadataLockDoesNotBlockUnrelatedOwnerCreation(t *testing.T) {
	s, log, _ := recordingSpine(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	// Holding the real certificate fence must not stall an independent owner
	// creation. This exercises the command, append and projector, not a lock mock.
	err := s.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		if err := s.LockCertificateMetadataOrderTx(ctx, tx, tenantA); err != nil {
			return err
		}
		commandCtx, commandCancel := context.WithTimeout(ctx, 2*time.Second)
		defer commandCancel()
		_, err := orchestrator.NewOrchestrator(log, s, nil).CreateOwnerRecord(commandCtx, store.Owner{
			TenantID: tenantA, Kind: store.OwnerTeam, Name: "independent owner creation",
		})
		return err
	})
	if err != nil {
		t.Fatalf("unrelated owner command blocked behind certificate metadata: %v", err)
	}
}

func TestCertificateRecordingAndRevocationAcquireMetadataBeforeRows(t *testing.T) {
	s, log, _ := recordingSpine(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	o := orchestrator.NewOrchestrator(log, s, nil)
	issued, _ := recordingCertificates(t)
	certificate, err := o.RecordCertificate(ctx, tenantA, issued)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := store.Open(ctx, testDSN+"?application_name=recording_revocation_order_peer")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	rowLocked, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	revoked := make(chan error, 1)
	go func() {
		result, err := o.BulkRevokeCertificates(ctx, tenantA, "recording-revocation-lock", strings.Repeat("c", 64), []string{certificate.ID}, "keyCompromise", orchestrator.CertificateRevocationChecks{
			Authorize: func(ctx context.Context, _ store.Certificate) error {
				// This real public method invokes Authorize only after it has
				// acquired CertificateForRevocationTx's actual row lock.
				close(rowLocked)
				select {
				case <-release:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			},
			// The real unsupported-authority branch still records/projects a
			// failed item. No CA ledger, revocation receipt or signer is faked.
			Authority: func(context.Context, store.Certificate) (string, error) {
				return "", orchestrator.ErrCertificateRevocationUnsupported
			},
		})
		if err == nil && (result.TotalMatched != 1 || result.TotalFailed != 1 || result.TotalRevoked != 0) {
			err = fmt.Errorf("unexpected unsupported-authority outcome: %+v", result)
		}
		revoked <- err
	}()
	select {
	case <-rowLocked:
	case err := <-revoked:
		t.Fatalf("revocation never acquired certificate row: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	observation := issued
	observation.Source = "import"
	observation.IssuanceIdempotencyKey = ""
	observation.CertificateDER, observation.CertificatePEM = nil, nil
	recorded := make(chan error, 1)
	go func() {
		_, err := orchestrator.NewOrchestrator(log, peer, nil).RecordCertificate(ctx, tenantA, observation)
		recorded <- err
	}()
	wait := ""
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		//trstctl:system-query — exact owned test connection wait kind only, not tenant data or statement text (AN-1 exemption).
		if err := s.SystemPool().QueryRow(ctx, `SELECT coalesce(max(wait_event),'') FROM pg_stat_activity WHERE application_name='recording_revocation_order_peer' AND wait_event_type='Lock'`).Scan(&wait); err != nil {
			t.Fatal(err)
		}
		if wait != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Before the repair, recording owns metadata and waits on revocation's row
	// (transactionid). Releasing revocation then makes ApplyTx wait on metadata:
	// PostgreSQL detects the real cycle and one public command fails.
	if wait != "advisory" {
		t.Errorf("recording wait=%q, want metadata advisory before certificate rows", wait)
	}
	close(release)
	for name, done := range map[string]<-chan error{"revocation": revoked, "recording": recorded} {
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("%s failed under concurrent public commands: %v", name, err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}
