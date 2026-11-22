// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"slices"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

type cr069NotDueStore struct{ *multiCRLStore }

func (*cr069NotDueStore) CRLDueForRegeneration(context.Context, string, string, time.Time, time.Duration) (bool, error) {
	return false, nil
}

// An upgrade must not keep serving an old, still-fresh unscoped CRL under a
// tenant's route. The trusted maintenance path regenerates it with the CDP's
// signed scope even when the ordinary freshness timer says it is not due.
func TestLegacyUnscopedFullCRLRegeneratesForTenantScopeCR069(t *testing.T) {
	ctx := context.Background()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	issuer, err := crypto.SelfSignedCACert(key, "CR-069 upgrade CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	st := &cr069NotDueStore{multiCRLStore: &multiCRLStore{issued: []store.IssuedCert{{
		TenantID: publicCRLTestTenant, CAID: IssuingCAID(), Serial: "10", IssuedAt: now.Add(-time.Hour),
	}}}}
	svc := &revocationService{store: st, caID: IssuingCAID(), caSigner: key, caCertDER: issuer, now: func() time.Time { return now }}
	if _, err := svc.generateCRL(ctx, publicCRLTestTenant); err != nil {
		t.Fatal(err)
	}
	const scopeOrigin = "https://cp.example.test/crl/"
	want := []string{scopeOrigin + publicCRLTestTenant}
	svc.fullCRLURLs = func(string) []string { return want }
	if _, err := svc.servedCRL(ctx, publicCRLTestTenant); err == nil {
		t.Fatal("public route served a legacy unscoped full CRL after tenant scope was required")
	}
	if err := svc.ensureCRL(ctx, publicCRLTestTenant); err != nil {
		t.Fatal(err)
	}
	der, err := svc.servedCRL(ctx, publicCRLTestTenant)
	if err != nil {
		t.Fatal(err)
	}
	info, err := crypto.ParseCRL(der, issuer)
	if err != nil || !slices.Equal(info.IssuingDistributionPointURLs, want) {
		t.Fatalf("regenerated full CRL IDP = %v, want %v: %v", info.IssuingDistributionPointURLs, want, err)
	}
}
