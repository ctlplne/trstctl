package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
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

func TestPublicCRLUsesETagAndConditionalCaching(t *testing.T) {
	firstDER := []byte{0x30, 0x03, 0x02, 0x01, 0x08}
	st := &fakeRevocationStore{
		hasIssued:   true,
		latestFound: true,
		latest:      store.CRL{TenantID: publicCRLTestTenant, CAID: IssuingCAID(), Number: 8, DER: firstDER},
	}
	svc := &revocationService{store: st, caID: IssuingCAID(), now: time.Now}

	first := servePublicCRL(t, svc, publicCRLTestTenant)
	if first.Code != http.StatusOK {
		t.Fatalf("first GET /crl/%s = %d, want 200 (body %q)", publicCRLTestTenant, first.Code, first.Body.String())
	}
	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Fatal("first GET did not return ETag")
	}
	if !strings.HasPrefix(etag, "W/\"") || !strings.HasSuffix(etag, "\"") {
		t.Fatalf("ETag = %q, want weak validator", etag)
	}
	if got := first.Header().Get("Cache-Control"); got != "public, max-age=3600, must-revalidate" {
		t.Fatalf("Cache-Control = %q, want public, max-age=3600, must-revalidate", got)
	}
	if got := first.Body.Bytes(); string(got) != string(firstDER) {
		t.Fatalf("first body = %v, want %v", got, firstDER)
	}

	notModified := servePublicCRLWithHeaders(t, svc, publicCRLTestTenant, map[string]string{
		"If-None-Match": etag,
	})
	if notModified.Code != http.StatusNotModified {
		t.Fatalf("conditional GET /crl/%s = %d, want 304 (body %q)", publicCRLTestTenant, notModified.Code, notModified.Body.String())
	}
	if notModified.Body.Len() != 0 {
		t.Fatalf("304 body length = %d, want 0", notModified.Body.Len())
	}

	st.latest = store.CRL{
		TenantID: publicCRLTestTenant,
		CAID:     IssuingCAID(),
		Number:   9,
		DER:      []byte{0x30, 0x03, 0x02, 0x01, 0x09},
	}
	refreshed := servePublicCRLWithHeaders(t, svc, publicCRLTestTenant, map[string]string{
		"If-None-Match": etag,
	})
	if refreshed.Code != http.StatusOK {
		t.Fatalf("refreshed GET /crl/%s = %d, want 200 (body %q)", publicCRLTestTenant, refreshed.Code, refreshed.Body.String())
	}
	if refreshed.Header().Get("ETag") == etag {
		t.Fatalf("regenerated CRL reused ETag %q", etag)
	}
	if got := refreshed.Body.Bytes(); string(got) != string(st.latest.DER) {
		t.Fatalf("refreshed body = %v, want %v", got, st.latest.DER)
	}
}

func TestTrustedCRLPublishAfterRevocationReplacesStaleCRL(t *testing.T) {
	ctx := context.Background()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	t.Cleanup(key.Destroy)
	caDER, err := crypto.SelfSignedCACert(key, "CRL Freshness Test CA", 24*time.Hour)
	if err != nil {
		t.Fatalf("self-signed CA: %v", err)
	}

	serial := "42"
	now := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	st := &freshCRLStore{
		issued: store.IssuedCert{
			TenantID: publicCRLTestTenant,
			CAID:     IssuingCAID(),
			Serial:   serial,
			IssuedAt: now.Add(-time.Hour),
		},
	}
	svc := &revocationService{
		store:     st,
		caID:      IssuingCAID(),
		caSigner:  key,
		caCertDER: caDER,
		now:       func() time.Time { return now },
	}

	staleDER, err := svc.generateCRL(ctx, publicCRLTestTenant)
	if err != nil {
		t.Fatalf("generate stale baseline CRL: %v", err)
	}
	stale, err := crypto.ParseCRL(staleDER, caDER)
	if err != nil {
		t.Fatalf("parse stale baseline CRL: %v", err)
	}
	if stale.Number != 1 {
		t.Fatalf("stale CRL number = %d, want 1", stale.Number)
	}
	if containsSerial(stale.RevokedSerials, serial) {
		t.Fatalf("baseline CRL already lists serial %s: %v", serial, stale.RevokedSerials)
	}

	revokedAt := now.Add(time.Minute)
	st.issued.RevokedAt = &revokedAt
	st.issued.ReasonCode = 1
	svc.now = func() time.Time { return revokedAt }
	freshDER, err := svc.generateCRL(ctx, publicCRLTestTenant)
	if err != nil {
		t.Fatalf("generate post-revocation CRL: %v", err)
	}
	fresh, err := crypto.ParseCRL(freshDER, caDER)
	if err != nil {
		t.Fatalf("parse post-revocation CRL: %v", err)
	}
	if fresh.Number != 2 {
		t.Fatalf("fresh CRL number = %d, want 2 (a new CRL after revocation)", fresh.Number)
	}
	if !containsSerial(fresh.RevokedSerials, serial) {
		t.Fatalf("fresh CRL serials = %v, want revoked serial %s", fresh.RevokedSerials, serial)
	}

	rr := servePublicCRL(t, svc, publicCRLTestTenant)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /crl/%s = %d, want 200 (body %q)", publicCRLTestTenant, rr.Code, rr.Body.String())
	}
	servedDER, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Fatal(err)
	}
	served, err := crypto.ParseCRL(servedDER, caDER)
	if err != nil {
		t.Fatalf("parse served post-revocation CRL: %v", err)
	}
	if served.Number != 2 || !containsSerial(served.RevokedSerials, serial) {
		t.Fatalf("served CRL number=%d serials=%v, want number 2 containing %s", served.Number, served.RevokedSerials, serial)
	}
}

func servePublicCRL(t *testing.T, svc *revocationService, tenant string) *httptest.ResponseRecorder {
	t.Helper()
	return servePublicCRLWithHeaders(t, svc, tenant, nil)
}

func servePublicCRLWithHeaders(t *testing.T, svc *revocationService, tenant string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	svc.routes(mux)
	req := httptest.NewRequest(http.MethodGet, "/crl/"+tenant, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
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

func (f *fakeRevocationStore) ActiveOCSPResponder(context.Context, string, string) (store.OCSPResponder, bool, error) {
	return store.OCSPResponder{}, false, errors.New("unexpected ActiveOCSPResponder")
}

func (f *fakeRevocationStore) UpsertOCSPResponder(context.Context, store.OCSPResponder) error {
	f.mutations++
	return errors.New("public CRL GET must not rotate OCSP responders")
}

type freshCRLStore struct {
	issued store.IssuedCert
	crls   []store.CRL
}

func (f *freshCRLStore) LookupIssuedCert(_ context.Context, tenantID, caID, serial string) (store.IssuedCert, bool, error) {
	if f.issued.TenantID == tenantID && f.issued.CAID == caID && f.issued.Serial == serial {
		return f.issued, true, nil
	}
	return store.IssuedCert{}, false, nil
}

func (f *freshCRLStore) HasIssuedCerts(_ context.Context, tenantID, caID string) (bool, error) {
	return f.issued.TenantID == tenantID && f.issued.CAID == caID && f.issued.Serial != "", nil
}

func (f *freshCRLStore) ListRevokedCerts(_ context.Context, tenantID, caID string) ([]store.IssuedCert, error) {
	if f.issued.TenantID != tenantID || f.issued.CAID != caID || f.issued.RevokedAt == nil {
		return nil, nil
	}
	return []store.IssuedCert{f.issued}, nil
}

func (f *freshCRLStore) NextCRLNumber(context.Context, string, string) (int64, error) {
	return int64(len(f.crls) + 1), nil
}

func (f *freshCRLStore) InsertCRL(_ context.Context, crl store.CRL) error {
	f.crls = append(f.crls, crl)
	return nil
}

func (f *freshCRLStore) TenantsWithIssuedCerts(context.Context, string) ([]string, error) {
	return []string{publicCRLTestTenant}, nil
}

func (f *freshCRLStore) CRLDueForRegeneration(context.Context, string, string, time.Time, time.Duration) (bool, error) {
	return true, nil
}

func (f *freshCRLStore) LatestCRL(context.Context, string, string) (store.CRL, bool, error) {
	if len(f.crls) == 0 {
		return store.CRL{}, false, nil
	}
	return f.crls[len(f.crls)-1], true, nil
}

func (f *freshCRLStore) ActiveOCSPResponder(context.Context, string, string) (store.OCSPResponder, bool, error) {
	return store.OCSPResponder{}, false, errors.New("unexpected ActiveOCSPResponder")
}

func (f *freshCRLStore) UpsertOCSPResponder(context.Context, store.OCSPResponder) error {
	return errors.New("unexpected UpsertOCSPResponder")
}

func containsSerial(serials []string, want string) bool {
	for _, got := range serials {
		if got == want {
			return true
		}
	}
	return false
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
