package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/store"
)

const publicCRLTestTenant = "11111111-1111-1111-1111-111111111111"

func TestPublicCRLDoesNotCreateForeignTenantState(t *testing.T) {
	for _, tc := range []struct {
		name      string
		tenant    string
		hasIssued bool
	}{
		{name: "random tenant with no issued surface", tenant: "22222222-2222-2222-2222-222222222222"},
		{name: "tenant with issued surface but no published CRL", tenant: publicCRLTestTenant, hasIssued: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := &fakeRevocationStore{hasIssued: tc.hasIssued}
			svc := &revocationService{store: st, caID: IssuingCAID(), now: time.Now}
			rr := servePublicCRL(t, svc, tc.tenant)
			if rr.Code != http.StatusNotFound {
				t.Fatalf("GET /crl/%s = %d, want 404 (body %q)", tc.tenant, rr.Code, rr.Body.String())
			}
			if st.mutations != 0 {
				t.Fatalf("public CRL GET performed %d mutation-oriented calls, want 0", st.mutations)
			}
			if st.latestCalls != boolToInt(tc.hasIssued) {
				t.Fatalf("LatestCRL calls = %d, want %d", st.latestCalls, boolToInt(tc.hasIssued))
			}
		})
	}
}

func TestPublicCRLServesPublishedCRLReadOnly(t *testing.T) {
	st := &fakeRevocationStore{
		hasIssued:   true,
		latestFound: true,
		latest:      store.CRL{TenantID: publicCRLTestTenant, CAID: IssuingCAID(), Number: 7, DER: []byte{0x30, 0x03, 0x02, 0x01, 0x07}},
	}
	svc := &revocationService{store: st, caID: IssuingCAID(), now: time.Now}
	rr := servePublicCRL(t, svc, publicCRLTestTenant)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /crl/%s = %d, want 200 (body %q)", publicCRLTestTenant, rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Type"); got != "application/pkix-crl" {
		t.Fatalf("Content-Type = %q, want application/pkix-crl", got)
	}
	body, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != string(st.latest.DER) {
		t.Fatalf("served CRL DER = %v, want %v", body, st.latest.DER)
	}
	if st.mutations != 0 {
		t.Fatalf("public CRL GET performed %d mutation-oriented calls, want 0", st.mutations)
	}
}

func servePublicCRL(t *testing.T, svc *revocationService, tenant string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	svc.routes(mux)
	req := httptest.NewRequest(http.MethodGet, "/crl/"+tenant, nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

type fakeRevocationStore struct {
	hasIssued   bool
	latestFound bool
	latest      store.CRL
	latestCalls int
	mutations   int
}

func (f *fakeRevocationStore) LookupIssuedCert(context.Context, string, string, string) (store.IssuedCert, bool, error) {
	return store.IssuedCert{}, false, errors.New("unexpected LookupIssuedCert")
}

func (f *fakeRevocationStore) HasIssuedCerts(context.Context, string, string) (bool, error) {
	return f.hasIssued, nil
}

func (f *fakeRevocationStore) ListRevokedCerts(context.Context, string, string) ([]store.IssuedCert, error) {
	f.mutations++
	return nil, errors.New("public CRL GET must not list revoked certs for generation")
}

func (f *fakeRevocationStore) NextCRLNumber(context.Context, string, string) (int64, error) {
	f.mutations++
	return 0, errors.New("public CRL GET must not allocate a CRL number")
}

func (f *fakeRevocationStore) InsertCRL(context.Context, store.CRL) error {
	f.mutations++
	return errors.New("public CRL GET must not insert CRLs")
}

func (f *fakeRevocationStore) TenantsWithIssuedCerts(context.Context, string) ([]string, error) {
	return nil, errors.New("unexpected TenantsWithIssuedCerts")
}

func (f *fakeRevocationStore) CRLDueForRegeneration(context.Context, string, string, time.Time, time.Duration) (bool, error) {
	return false, errors.New("unexpected CRLDueForRegeneration")
}

func (f *fakeRevocationStore) LatestCRL(context.Context, string, string) (store.CRL, bool, error) {
	f.latestCalls++
	return f.latest, f.latestFound, nil
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
