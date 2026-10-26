// SPDX-License-Identifier: BUSL-1.1

package query_test

import (
	"context"
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/query"
	"trstctl.com/trstctl/internal/store"
)

// seedFilterInventory adds certificates with distinct issuers, algorithms,
// owners, statuses and expiries to tenant A, beside seed's two-tenant fixture.
func seedFilterInventory(t *testing.T, st *store.Store) map[string]string {
	t.Helper()
	ctx := context.Background()
	owner, err := st.CreateOwner(ctx, store.Owner{TenantID: tenantA, Kind: store.OwnerKind("workload"), Name: "Payments-Team"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	at := func(d time.Duration) *time.Time { v := now.Add(d); return &v }
	ids := map[string]string{}
	for _, c := range []struct {
		serial, issuer, alg string
		owned               bool
		notAfter            *time.Time
		sans                []string
	}{
		{"f-rsa-soon", "CN=Acme Issuing CA", "RSA", true, at(10 * 24 * time.Hour), []string{"pay.example.test"}},
		{"f-ec-soon", "CN=Other CA", "ECDSA-P256", false, at(20 * 24 * time.Hour), nil},
		{"f-rsa-late", "CN=Acme Issuing CA", "RSA", false, at(90 * 24 * time.Hour), nil},
		{"f-expired", "CN=Acme Issuing CA", "ML-DSA-65", true, at(-24 * time.Hour), nil},
		{"f-revoked", "CN=Acme Issuing CA", "RSA", false, at(5 * 24 * time.Hour), nil},
	} {
		cert := store.Certificate{TenantID: tenantA, Subject: "CN=" + c.serial, SANs: c.sans, Issuer: c.issuer, Serial: c.serial,
			Fingerprint: "fp-" + c.serial, KeyAlgorithm: c.alg, NotAfter: c.notAfter, Source: "issued"}
		if c.owned {
			cert.OwnerID = &owner.ID
		}
		saved, err := st.UpsertCertificate(ctx, cert)
		if err != nil {
			t.Fatalf("seed %s: %v", c.serial, err)
		}
		ids[c.serial] = saved.ID
	}
	if err := st.WithTenant(ctx, tenantA, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE certificates SET status = 'revoked' WHERE tenant_id = $1 AND serial = 'f-revoked'`, tenantA)
		return err
	}); err != nil {
		t.Fatalf("revoke fixture: %v", err)
	}
	return ids
}

func serialsOf(rows []query.Row) []string {
	var out []string
	for _, r := range rows {
		if r.Surface == query.SurfaceCertificates {
			out = append(out, r.Columns["serial"])
		}
	}
	sort.Strings(out)
	return out
}

// A152: each typed certificate filter selects exactly what it says, inside the
// tenant's RLS boundary; counts are exact; truncation is declared.
func TestTypedCertificateFiltersAnswerExactly(t *testing.T) {
	e, st := seed(t)
	seedFilterInventory(t, st)
	ctx := context.Background()
	now := time.Now().UTC()
	in30 := now.Add(30 * 24 * time.Hour)
	certs := []query.Surface{query.SurfaceCertificates}
	for name, tc := range map[string]struct {
		selectS []query.Surface
		filter  query.CertificateFilter
		want    []string
	}{
		"issuer":           {certs, query.CertificateFilter{IssuerContains: "acme issuing"}, []string{"f-expired", "f-revoked", "f-rsa-late", "f-rsa-soon"}},
		"algorithm family": {certs, query.CertificateFilter{KeyAlgorithm: "ECDSA"}, []string{"f-ec-soon", "serial-alpha-01"}},
		"pqc family":       {certs, query.CertificateFilter{KeyAlgorithm: "ml-dsa"}, []string{"f-expired"}},
		"active window":    {certs, query.CertificateFilter{Status: "active", ExpiresAfter: &now, ExpiresBefore: &in30}, []string{"f-ec-soon", "f-rsa-soon", "serial-alpha-01"}},
		"expired":          {certs, query.CertificateFilter{Status: "active", ExpiresBefore: &now}, []string{"f-expired"}},
		"revoked":          {certs, query.CertificateFilter{Status: "revoked"}, []string{"f-revoked"}},
		"name or SAN":      {certs, query.CertificateFilter{NameContains: "PAY.example"}, []string{"f-rsa-soon"}},
		"unowned":          {certs, query.CertificateFilter{Unowned: true, IssuerContains: "Acme"}, []string{"f-revoked", "f-rsa-late"}},
		"owner name":       {[]query.Surface{query.SurfaceCertificates, query.SurfaceOwners}, query.CertificateFilter{OwnerName: "payments-team"}, []string{"f-expired", "f-rsa-soon"}},
		"serial":           {certs, query.CertificateFilter{Serial: "F-RSA-LATE"}, []string{"f-rsa-late"}},
	} {
		f := tc.filter
		res, err := e.Query(ctx, admin(tenantA), query.Spec{Select: tc.selectS, Certificates: &f, Count: true})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got := serialsOf(res.Rows)
		if len(got) != len(tc.want) || !res.Counted || res.Count != len(tc.want) || res.Truncated {
			t.Errorf("%s = %v (count %d counted %t truncated %t), want %v", name, got, res.Count, res.Counted, res.Truncated, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s = %v, want %v", name, got, tc.want)
				break
			}
		}
		for _, r := range res.Rows {
			if r.Surface != query.SurfaceCertificates {
				t.Errorf("%s: a filtered query returned a %s row", name, r.Surface)
			}
		}
	}

	f := query.CertificateFilter{IssuerContains: "Acme"}
	res, err := e.Query(ctx, admin(tenantA), query.Spec{Select: certs, Certificates: &f, Count: true, Limit: 2})
	if err != nil || len(res.Rows) != 2 || !res.Truncated || res.Count != 4 {
		t.Fatalf("limited filter = %d rows truncated %t count %d, %v", len(res.Rows), res.Truncated, res.Count, err)
	}
}

// A filter naming the other tenant's data returns nothing, and every filter's
// rows stay the caller's — the same property the unfiltered queries hold.
func TestTypedFiltersCannotReachAnotherTenant(t *testing.T) {
	e, st := seed(t)
	seedFilterInventory(t, st)
	ctx := context.Background()
	for _, f := range []query.CertificateFilter{
		{Serial: "serial-beta-01"}, {Fingerprint: "fp-beta-01"}, {NameContains: "b.svc"},
		{KeyAlgorithm: "ECDSA", NameContains: "b.svc"},
	} {
		f := f
		res, err := e.Query(ctx, admin(tenantA), query.Spec{Select: []query.Surface{query.SurfaceCertificates}, Certificates: &f, Count: true})
		if err != nil || len(res.Rows) != 0 || res.Count != 0 {
			t.Fatalf("tenant A filter %+v reached tenant B: %d rows count %d, %v", f, len(res.Rows), res.Count, err)
		}
	}
	owner := query.CertificateFilter{OwnerName: "beta-owner"}
	res, err := e.Query(ctx, admin(tenantA), query.Spec{Select: []query.Surface{query.SurfaceCertificates, query.SurfaceOwners}, Certificates: &owner, Count: true})
	if err != nil || len(res.Rows) != 0 || res.Count != 0 {
		t.Fatalf("tenant A owner filter reached tenant B's owner: %d rows, %v", len(res.Rows), err)
	}

	rng := rand.New(rand.NewSource(7)) // #nosec G404 -- test shuffle, not a security decision (CWE-338)
	values := []string{"", "a", "b", "svc", "Acme", "serial", "fp", "alpha", "beta", "CN="}
	pick := func() string { return values[rng.Intn(len(values))] }
	for i := 0; i < 200; i++ {
		tenant := tenantA
		if rng.Intn(2) == 0 {
			tenant = tenantB
		}
		f := query.CertificateFilter{IssuerContains: pick(), NameContains: pick(), Serial: pick(), Unowned: rng.Intn(3) == 0}
		if f.Serial != "" && rng.Intn(2) == 0 {
			f.Serial = ""
		}
		res, err := e.Query(ctx, admin(tenant), query.Spec{Select: []query.Surface{query.SurfaceCertificates}, Certificates: &f, Count: rng.Intn(2) == 0})
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		assertNoForeignRows(t, tenant, res.Rows)
	}
	crypto := query.CryptoAssetFilter{Algorithm: "ecdsa"}
	cres, err := e.Query(ctx, admin(tenantA), query.Spec{Select: []query.Surface{query.SurfaceCBOM}, CryptoAssets: &crypto, Count: true})
	if err != nil || len(cres.Rows) != 0 || cres.Count != 0 {
		t.Fatalf("tenant A crypto filter reached tenant B's ECDSA asset: %d rows, %v", len(cres.Rows), err)
	}
	rsa := query.CryptoAssetFilter{Algorithm: "rsa"}
	cres, err = e.Query(ctx, admin(tenantA), query.Spec{Select: []query.Surface{query.SurfaceCBOM}, CryptoAssets: &rsa, Count: true})
	if err != nil || len(cres.Rows) != 1 || cres.Count != 1 {
		t.Fatalf("tenant A crypto filter = %d rows count %d, %v", len(cres.Rows), cres.Count, err)
	}
	assertNoForeignRows(t, tenantA, cres.Rows)
}

// The typed filters are allow-listed like every other part of a spec: malformed
// or inconsistent filters fail closed before any read.
func TestTypedFiltersFailClosed(t *testing.T) {
	e := newValidationEngine()
	ctx := context.Background()
	now := time.Now()
	long := string(make([]byte, 201))
	certs := []query.Surface{query.SurfaceCertificates}
	for name, spec := range map[string]query.Spec{
		"filter without its surface": {Select: []query.Surface{query.SurfaceOwners}, Certificates: &query.CertificateFilter{}},
		"unknown status":             {Select: certs, Certificates: &query.CertificateFilter{Status: "pending"}},
		"inverted bounds":            {Select: certs, Certificates: &query.CertificateFilter{ExpiresAfter: &now, ExpiresBefore: &now}},
		"owner without owners":       {Select: certs, Certificates: &query.CertificateFilter{OwnerName: "x"}},
		"owner and unowned":          {Select: []query.Surface{query.SurfaceCertificates, query.SurfaceOwners}, Certificates: &query.CertificateFilter{OwnerName: "x", Unowned: true}},
		"oversized value":            {Select: certs, Certificates: &query.CertificateFilter{IssuerContains: long}},
		"filter beside window":       {Select: certs, Certificates: &query.CertificateFilter{}, CertificateExpiryWindow: &query.CertificateExpiryWindow{After: now, Before: now.Add(time.Hour)}},
		"two filtered surfaces":      {Select: []query.Surface{query.SurfaceCertificates, query.SurfaceCBOM}, Certificates: &query.CertificateFilter{}, CryptoAssets: &query.CryptoAssetFilter{}},
		"count without a filter":     {Select: certs, Count: true},
		"crypto without cbom":        {Select: certs, CryptoAssets: &query.CryptoAssetFilter{}},
		"negative key bits":          {Select: []query.Surface{query.SurfaceCBOM}, CryptoAssets: &query.CryptoAssetFilter{KeyBitsBelow: -1}},
		"focus not selected":         {Select: certs, Focus: []query.Surface{query.SurfaceOwners}},
	} {
		if _, err := e.Query(ctx, admin(tenantA), spec); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
