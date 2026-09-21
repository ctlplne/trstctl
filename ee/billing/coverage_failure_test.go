// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/billing"
)

func TestCoverageDistinguishesNeverObservedFromDatabaseUnavailable(t *testing.T) {
	store, connection := newBillingStoreOn(t, "billing_coverage_read_failure")
	ctx := t.Context()
	coverage, err := store.CoverageFor(ctx, quotaTenant)
	if err != nil {
		t.Fatalf("an unobserved tenant is a valid empty result: %v", err)
	}
	period := billing.EvidencePeriod{
		CustomerID: quotaTenant,
		Start:      time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC),
		End:        time.Date(2026, 9, 16, 13, 0, 0, 0, time.UTC),
	}
	if decision := billing.MaySign(period, coverage, period.End.Add(time.Hour)); decision.Signable {
		t.Fatal("unobserved customer was reported as covered")
	}
	connection.Close()
	if _, err := store.CoverageFor(ctx, quotaTenant); err == nil {
		t.Fatal("closed database connection was silently reported as an unobserved customer; operator cannot distinguish unavailable evidence from empty history")
	}
	response := serveEvidenceRequest(t, store, quotaTenant, periodQuery(quotaTenant))
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "could not read metering coverage") {
		t.Fatalf("unavailable coverage response = %d/%s", response.Code, response.Body.String())
	}
}
