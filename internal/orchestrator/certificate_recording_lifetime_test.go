// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/orchestrator"
)

func TestCertificateRecordingRecoveryCannotCrossCustomerLifetimes(t *testing.T) {
	for _, retryOld := range []bool{false, true} {
		name := "new-certificate"
		if retryOld {
			name = "old-command-retry"
		}
		t.Run(name, func(t *testing.T) {
			st, log, projector := recordingSpine(t)
			ctx := t.Context()
			orch := orchestrator.NewOrchestrator(log, st, nil)
			old, _ := recordingCertificates(t)
			oldRow, err := orch.RecordCertificateWithEventID(ctx, tenantA, "old-lifetime-recording", old)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := orchestrator.ResolveLiveTenantRegistrationAuthority(ctx, log, st, tenantA)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := orch.OffboardTenant(ctx, orchestrator.TenantOffboardCommand{
				TenantID: tenantA, RegistrationIdentity: proof.EventID,
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := orchestrator.ExecuteTenantRegistration(ctx, log, st, projector,
				orchestrator.NewIdempotency(st), registrationCommand(tenantA, "replacement-customer", "replacement-registration")); err != nil {
				t.Fatal(err)
			}
			if _, err := st.GetCertificate(ctx, tenantA, oldRow.ID); !errors.Is(err, pgx.ErrNoRows) {
				t.Fatalf("offboard did not erase original certificate: %v", err)
			}
			if retryOld {
				if _, err := orch.RecordCertificateWithEventID(ctx, tenantA, "old-lifetime-recording", old); err == nil {
					t.Error("old customer command was accepted in replacement customer")
				}
			} else {
				next, _ := recordingCertificates(t)
				next.IssuanceIdempotencyKey += "-replacement"
				if _, err := orch.RecordCertificateWithEventID(ctx, tenantA, "replacement-recording", next); err != nil {
					t.Fatal(err)
				}
			}
			if got, err := st.GetCertificate(ctx, tenantA, oldRow.ID); !errors.Is(err, pgx.ErrNoRows) {
				t.Errorf("certificate recovery resurrected prior customer's certificate %s: error=%v", got.ID, err)
			}
		})
	}
}
