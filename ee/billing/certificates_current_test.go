// SPDX-License-Identifier: LicenseRef-trstctl-EE

package billing_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/ee/billing"
	"trstctl.com/trstctl/internal/usage"

	corestore "trstctl.com/trstctl/internal/store"
)

// MTR-D1: the certificate quota and the evidence's certificate line count the
// tenant's current certificates. A renewal leaves its predecessor superseded,
// so one certificate issued and renewed three times is one current
// certificate (certificates_stored, kept as telemetry, reads 4); an expired,
// unrenewed certificate drops out; a tenant whose renewals fill the old stored
// count is still admitted a new certificate under its cap and refused one only
// at it; and the period's evidence says why the current line has no
// independent recount.
func TestCurrentCertificatesMeterCountsOnlyLiveCertificatesMTRD1(t *testing.T) {
	pgStore, st := newBillingStoreOn(t, "billing_mtr_d1")
	ctx := context.Background()
	const tenant = "4d7a0000-0000-4000-8000-0000000000d1"
	seedBillingRegistration(t, st, tenant)
	now := time.Now().UTC().Truncate(time.Second)
	record := func(n int, replaces string, notAfter time.Time) string {
		t.Helper()
		id := fmt.Sprintf("4d7a0000-0000-4000-8000-%012d", n)
		notBefore := notAfter.Add(-47 * 24 * time.Hour)
		c := corestore.Certificate{ID: id, TenantID: tenant, Subject: "CN=mtr-d1.example.test", Issuer: "CN=MTR-D1 CA",
			Serial: fmt.Sprintf("%x", 0xd100+n), Fingerprint: fmt.Sprintf("%064x", 0xd100+n), KeyAlgorithm: "ECDSA-P256",
			NotBefore: &notBefore, NotAfter: &notAfter, Source: "issued", Status: "active", CreatedAt: now.Add(time.Duration(n) * time.Minute)}
		if replaces != "" {
			c.ReplacesID = &replaces
		}
		if err := st.WithTenant(ctx, tenant, func(tx pgx.Tx) error { return st.ApplyCertificateRecordedTx(ctx, tx, c) }); err != nil {
			t.Fatalf("record certificate %d: %v", n, err)
		}
		return id
	}
	counts := func() billing.TenantCounts {
		t.Helper()
		got, err := billing.StoreTenantCounter(st)(ctx, tenant)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	// Issued once, renewed three times: each renewal records its successor
	// naming the predecessor, which the projection marks superseded.
	previous := record(1, "", now.Add(47*24*time.Hour))
	for n := 2; n <= 4; n++ {
		previous = record(n, previous, now.Add(time.Duration(47+n)*24*time.Hour))
	}
	if got := counts(); got[usage.MeterCertificatesCurrent] != 1 || got[usage.MeterCertificatesStored] != 4 {
		t.Fatalf("after one issue and three renewals: current %d, stored %d; want 1 and 4", got[usage.MeterCertificatesCurrent], got[usage.MeterCertificatesStored])
	}
	// An expired certificate nobody renewed is not current.
	record(5, "", now.Add(-time.Hour))
	if got := counts(); got[usage.MeterCertificatesCurrent] != 1 || got[usage.MeterCertificatesStored] != 5 {
		t.Fatalf("with an expired certificate: current %d, stored %d; want 1 and 5", got[usage.MeterCertificatesCurrent], got[usage.MeterCertificatesStored])
	}

	// The cap reads the current stock: at a cap of 2 a new certificate is
	// admitted although five are stored, and refused once two are current.
	limit := 2
	seedQuota(t, st, billing.Quota{TenantID: tenant, MaxCertificatesStored: &limit})
	checker := billing.NewQuotaChecker(pgStore, billing.StoreTenantAdmissionCounter(st), time.Millisecond)
	if err := checker.AllowCreate(ctx, tenant, usage.MeterCertificatesCurrent); err != nil {
		t.Fatalf("one current certificate under a cap of two was refused: %v", err)
	}
	record(6, "", now.Add(90*24*time.Hour))
	err := checker.AllowCreate(ctx, tenant, usage.MeterCertificatesCurrent)
	if !errors.Is(err, usage.ErrQuotaExhausted) || !strings.Contains(err.Error(), "2 of 2") {
		t.Fatalf("two current certificates at a cap of two = %v, want refused naming 2 of 2", err)
	}

	// The evidence's current line has no independent recount, and says why.
	recount, err := pgStore.GaugeAt(ctx, tenant, usage.MeterCertificatesCurrent, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if recount.Checked || !strings.Contains(recount.Note, "neither a renewal's supersession nor a revocation") {
		t.Fatalf("the current line's reconciliation = %+v, want unchecked with its reason", recount)
	}
	if kind := billing.MeterKind(usage.MeterCertificatesCurrent); kind != billing.KindGauge {
		t.Fatalf("certificates_current is a %s, want a gauge", kind)
	}
}
