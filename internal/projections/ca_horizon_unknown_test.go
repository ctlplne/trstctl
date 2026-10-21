// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"testing"
	"time"
)

// A22/A23: the unknown-expiry decision carries no dates and only its reserved
// band; the beyond-band planning entry carries dates like any band.
func TestValidateCAAuthorityHorizonAlertedUnknownAndBeyondBands(t *testing.T) {
	t.Parallel()
	const id = "6b8b1f9a-2f0c-4f1a-9d3e-7c3f6a2b1d10"
	unknown := CAAuthorityHorizonAlerted{
		CAAuthorityID: id, CommonName: "acme root", Kind: "root", HorizonMonths: 1200, ExpiryUnknown: true,
		AlertKind: "ca.horizon", AlertDetail: "no recorded expiry", Severity: "warning",
	}
	if err := ValidateCAAuthorityHorizonAlerted(unknown); err != nil {
		t.Fatalf("unknown-expiry decision refused: %v", err)
	}
	withDate := unknown
	withDate.NotAfter = time.Now()
	if err := ValidateCAAuthorityHorizonAlerted(withDate); err == nil {
		t.Fatal("an unknown-expiry decision with a date must be refused")
	}
	reserved := unknown
	reserved.ExpiryUnknown = false
	reserved.NotAfter, reserved.RenewBy = time.Now().Add(48*time.Hour), time.Now().Add(24*time.Hour)
	if err := ValidateCAAuthorityHorizonAlerted(reserved); err == nil {
		t.Fatal("band 1200 without the unknown-expiry mark must be refused")
	}
	beyond := CAAuthorityHorizonAlerted{
		CAAuthorityID: id, CommonName: "acme root", Kind: "root", HorizonMonths: 37, MonthsRemaining: 120,
		NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour), RenewBy: time.Now().Add(9 * 365 * 24 * time.Hour),
		AlertKind: "ca.horizon", AlertDetail: "on the calendar", Severity: "low", DependentCertificates: 2,
	}
	if err := ValidateCAAuthorityHorizonAlerted(beyond); err != nil {
		t.Fatalf("beyond-band planning decision refused: %v", err)
	}
}
