// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing_test

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/ee/billing"
	"trstctl.com/trstctl/internal/usage"
)

func TestResponderHistoryUnknownCannotBecomeConfirmedZero(t *testing.T) {
	pg, cs := newBillingStoreOn(t, "billing_responder_upgrade")
	_, _, orch := billingHistory(t, cs)
	hour := time.Now().UTC().Truncate(time.Hour)
	billingRecordAt(t, orch, quotaTenant, hour.Add(time.Minute))
	if err := pg.AddCounters(t.Context(), []billing.CounterDelta{{TenantID: quotaTenant, Meter: usage.MeterCertificatesIssued, Period: hour, Delta: 7}}); err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"false", "NULL"} {
		t.Run(flag, func(t *testing.T) {
			// false is a migrated pre-upgrade CA ledger; NULL is an older snapshot
			// without the column. Neither proves complete issuance history.
			if err := cs.WithTenant(t.Context(), quotaTenant, func(tx pgx.Tx) error {
				_, err := tx.Exec(t.Context(), `UPDATE tenants SET responder_issuance_history_known=`+flag+` WHERE tenant_id=$1`, quotaTenant)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			_, known, err := pg.IssuedInPeriod(t.Context(), quotaTenant, hour, hour.Add(time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			if known {
				t.Error("incomplete responder history was reported as a verified recount")
			}
			if err := pg.RefreshIssuedCounters(t.Context()); !errors.Is(err, billing.ErrIssuanceHistoryUnknown) {
				t.Errorf("refresh error=%v, want unverified-history refusal", err)
			}
			rows, err := pg.Query(t.Context(), hour, hour.Add(time.Hour), quotaTenant)
			if err != nil {
				t.Fatal(err)
			}
			var got int64
			for _, row := range rows {
				if row.Meter == usage.MeterCertificatesIssued {
					got += row.Value
				}
			}
			if got != 7 {
				t.Errorf("incomplete recovery replaced measured count with %d, want original 7", got)
			}
		})
	}
}
