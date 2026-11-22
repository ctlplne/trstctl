// SPDX-License-Identifier: BUSL-1.1

package server

// R1 review reproduction (S1b) against the real served code.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/agent/revcache"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

// S1b-L1: no CA-signed CRL the served CA publishes may verify as a complete CRL
// that is newer than the full CRL while omitting a serial the full CRL revokes;
// the product's own CRL cache must not accept such a list in place of the full one.
func TestServedPartitionCRLsAreNotUsableAsCompleteCRLsR1S1b(t *testing.T) {
	ctx := context.Background()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	caDER, err := crypto.SelfSignedCACert(key, "R1 S1b partitioned CRL CA", 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	st := &multiCRLStore{issued: []store.IssuedCert{
		{TenantID: publicCRLTestTenant, CAID: IssuingCAID(), Serial: "10", IssuedAt: now.Add(-time.Hour)},
		{TenantID: publicCRLTestTenant, CAID: IssuingCAID(), Serial: "20", IssuedAt: now.Add(-time.Hour)},
	}}
	svc := &revocationService{store: st, caID: IssuingCAID(), caSigner: key, caCertDER: caDER,
		now: func() time.Time { return now.Add(-10 * time.Minute) }}
	fullURL := "https://cp.example.test/crl/" + publicCRLTestTenant
	svc.fullCRLURLs = func(string) []string { return []string{fullURL} }
	if _, err := svc.generateCRL(ctx, publicCRLTestTenant); err != nil {
		t.Fatal(err)
	}
	st.revoke("10", now.Add(-5*time.Minute), 1) // one keyCompromise revocation
	svc.now = func() time.Time { return now }
	fullDER, err := svc.generateCRL(ctx, publicCRLTestTenant)
	if err != nil {
		t.Fatal(err)
	}
	full, err := crypto.ParseCRL(fullDER, caDER)
	if err != nil || !slices.Contains(full.RevokedSerials, "10") || !slices.Equal(full.IssuingDistributionPointURLs, []string{fullURL}) {
		t.Fatalf("full CRL = %+v err=%v", full, err)
	}
	var manifest struct {
		Shards []struct {
			Index int    `json:"index"`
			URL   string `json:"url"`
		} `json:"shards"`
	}
	getRevocationJSON(t, svc, "/crl/"+publicCRLTestTenant+"/manifest.json", &manifest)
	var substitute []byte
	for _, shard := range manifest.Shards {
		der := getRevocationBytes(t, svc, shard.URL, "application/pkix-crl")
		info, err := crypto.ParseCRL(der, caDER)
		if err != nil {
			continue
		}
		if info.IssuingDistributionPointURL == "" || info.IssuingDistributionPointURL == full.IssuingDistributionPointURL {
			t.Errorf("published shard %d has no distinct critical issuing distribution point: %q", shard.Index, info.IssuingDistributionPointURL)
		}
		if info.Number > full.Number && !slices.Contains(info.RevokedSerials, "10") && !info.HasDeltaCRLIndicator &&
			!info.NextUpdate.Before(full.NextUpdate) && info.IssuingDistributionPointURL == full.IssuingDistributionPointURL {
			t.Errorf("published shard %d (%s) is a CA-signed CRL number %d > full %d, valid until %s, that does not "+
				"list revoked serial 10 and carries nothing that scopes it: any relying party handed it instead of the full "+
				"CRL accepts serial 10 as not revoked", shard.Index, shard.URL, info.Number, full.Number, info.NextUpdate.Format(time.RFC3339))
			if substitute == nil {
				substitute = der
			}
		}
	}
	if substitute == nil {
		return
	}
	// The product's own CRL cache (agent revcache) takes the shard in place of
	// the full CRL: the rollback check only compares CRL numbers.
	serve := fullDER
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(serve) }))
	t.Cleanup(up.Close)
	cache, err := revcache.New(up.URL, caDER, revcache.Options{Client: up.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	serve = substitute
	if err := cache.Refresh(ctx); err == nil {
		served, _ := cache.Serve()
		info, _ := crypto.ParseCRL(served, caDER)
		t.Errorf("revcache replaced full CRL %d with partition CRL %d and now serves revoked=%v (serial 10 un-revoked)",
			full.Number, info.Number, info.RevokedSerials)
	}
}
