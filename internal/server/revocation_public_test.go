package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
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

func TestServedPartitionedAndDeltaCRLsCAPREV02(t *testing.T) {
	ctx := context.Background()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	t.Cleanup(key.Destroy)
	caDER, err := crypto.SelfSignedCACert(key, "Partitioned CRL Test CA", 24*time.Hour)
	if err != nil {
		t.Fatalf("self-signed CA: %v", err)
	}

	now := time.Date(2026, 6, 29, 9, 0, 0, 0, time.UTC)
	st := &multiCRLStore{issued: []store.IssuedCert{
		{TenantID: publicCRLTestTenant, CAID: IssuingCAID(), Serial: "10", IssuedAt: now.Add(-time.Hour)},
		{TenantID: publicCRLTestTenant, CAID: IssuingCAID(), Serial: "20", IssuedAt: now.Add(-time.Hour)},
		{TenantID: publicCRLTestTenant, CAID: IssuingCAID(), Serial: "30", IssuedAt: now.Add(-time.Hour)},
	}}
	svc := &revocationService{
		store:     st,
		caID:      IssuingCAID(),
		caSigner:  key,
		caCertDER: caDER,
		now:       func() time.Time { return now },
	}

	baselineDER, err := svc.generateCRL(ctx, publicCRLTestTenant)
	if err != nil {
		t.Fatalf("generate baseline CRL: %v", err)
	}
	baseline, err := crypto.ParseCRL(baselineDER, caDER)
	if err != nil {
		t.Fatalf("parse baseline CRL: %v", err)
	}
	if len(baseline.RevokedSerials) != 0 {
		t.Fatalf("baseline CRL serials = %v, want none before revocation", baseline.RevokedSerials)
	}

	revokedAt := now.Add(10 * time.Minute)
	st.revoke("10", revokedAt, 1)
	st.revoke("20", revokedAt.Add(time.Minute), 1)
	svc.now = func() time.Time { return revokedAt.Add(2 * time.Minute) }
	fullDER, err := svc.generateCRL(ctx, publicCRLTestTenant)
	if err != nil {
		t.Fatalf("generate partitioned CRL collection: %v", err)
	}
	full, err := crypto.ParseCRL(fullDER, caDER)
	if err != nil {
		t.Fatalf("parse partitioned full CRL: %v", err)
	}
	if got := sortedSerials(full.RevokedSerials); strings.Join(got, ",") != "10,20" {
		t.Fatalf("full CRL serials = %v, want [10 20]", got)
	}

	var manifest struct {
		FullURL         string `json:"full_url"`
		DeltaURL        string `json:"delta_url"`
		DeltaBaseNumber int64  `json:"delta_base_number"`
		ShardCount      int    `json:"shard_count"`
		Shards          []struct {
			Index        int    `json:"index"`
			URL          string `json:"url"`
			RevokedCount int    `json:"revoked_count"`
		} `json:"shards"`
	}
	getRevocationJSON(t, svc, "/crl/"+publicCRLTestTenant+"/manifest.json", &manifest)
	if manifest.FullURL != "/crl/"+publicCRLTestTenant {
		t.Fatalf("manifest full_url = %q", manifest.FullURL)
	}
	if manifest.ShardCount < 4 || len(manifest.Shards) != manifest.ShardCount {
		t.Fatalf("manifest shard count = %d len=%d, want at least 4 complete shard urls", manifest.ShardCount, len(manifest.Shards))
	}
	if manifest.DeltaBaseNumber != baseline.Number || manifest.DeltaURL == "" {
		t.Fatalf("manifest delta base/url = %d %q, want base %d and a delta URL", manifest.DeltaBaseNumber, manifest.DeltaURL, baseline.Number)
	}

	shardUnion := map[string]bool{}
	for _, shard := range manifest.Shards {
		der := getRevocationBytes(t, svc, shard.URL, "application/pkix-crl")
		info, err := crypto.ParseCRL(der, caDER)
		if err != nil {
			t.Fatalf("parse shard %d: %v", shard.Index, err)
		}
		if len(info.RevokedSerials) != shard.RevokedCount {
			t.Fatalf("shard %d revoked_count = %d, CRL serials = %d", shard.Index, shard.RevokedCount, len(info.RevokedSerials))
		}
		for _, serial := range info.RevokedSerials {
			shardUnion[serial] = true
		}
	}
	if got := sortedSerialsFromSet(shardUnion); strings.Join(got, ",") != "10,20" {
		t.Fatalf("partitioned shard union = %v, want [10 20]", got)
	}

	deltaDER := getRevocationBytes(t, svc, manifest.DeltaURL, "application/pkix-crl")
	delta, err := crypto.ParseCRL(deltaDER, caDER)
	if err != nil {
		t.Fatalf("parse delta CRL: %v", err)
	}
	if !delta.HasDeltaCRLIndicator || delta.DeltaBaseNumber != baseline.Number {
		t.Fatalf("delta CRL indicator/base = %t/%d, want true/%d", delta.HasDeltaCRLIndicator, delta.DeltaBaseNumber, baseline.Number)
	}
	if got := sortedSerials(delta.RevokedSerials); strings.Join(got, ",") != "10,20" {
		t.Fatalf("delta CRL serials = %v, want revocations since baseline [10 20]", got)
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

func getRevocationBytes(t *testing.T, svc *revocationService, path, wantContentType string) []byte {
	t.Helper()
	rr := serveRevocationPath(t, svc, path, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200 (body %q)", path, rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Type"); got != wantContentType {
		t.Fatalf("GET %s Content-Type = %q, want %q", path, got, wantContentType)
	}
	body, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func getRevocationJSON(t *testing.T, svc *revocationService, path string, dst any) {
	t.Helper()
	body := getRevocationBytes(t, svc, path, "application/json")
	if err := json.Unmarshal(body, dst); err != nil {
		t.Fatalf("decode %s: %v (%s)", path, err, body)
	}
}

func serveRevocationPath(t *testing.T, svc *revocationService, path string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	svc.routes(mux)
	req := httptest.NewRequest(http.MethodGet, path, nil)
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

func (f *fakeRevocationStore) LatestCRLShard(context.Context, string, string, int) (store.CRL, bool, error) {
	return store.CRL{}, false, errors.New("unexpected LatestCRLShard")
}

func (f *fakeRevocationStore) LatestDeltaCRL(context.Context, string, string, int64) (store.CRL, bool, error) {
	return store.CRL{}, false, errors.New("unexpected LatestDeltaCRL")
}

func (f *fakeRevocationStore) ListLatestCRLArtifacts(context.Context, string, string) ([]store.CRL, error) {
	return nil, errors.New("unexpected ListLatestCRLArtifacts")
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
	return latestFullCRL(f.crls)
}

func (f *freshCRLStore) LatestCRLShard(_ context.Context, _ string, _ string, shardIndex int) (store.CRL, bool, error) {
	return latestShardCRL(f.crls, shardIndex)
}

func (f *freshCRLStore) LatestDeltaCRL(_ context.Context, _ string, _ string, baseNumber int64) (store.CRL, bool, error) {
	return latestDeltaCRL(f.crls, baseNumber)
}

func (f *freshCRLStore) ListLatestCRLArtifacts(context.Context, string, string) ([]store.CRL, error) {
	return latestCRLArtifacts(f.crls), nil
}

func (f *freshCRLStore) ActiveOCSPResponder(context.Context, string, string) (store.OCSPResponder, bool, error) {
	return store.OCSPResponder{}, false, errors.New("unexpected ActiveOCSPResponder")
}

func (f *freshCRLStore) UpsertOCSPResponder(context.Context, store.OCSPResponder) error {
	return errors.New("unexpected UpsertOCSPResponder")
}

type multiCRLStore struct {
	issued []store.IssuedCert
	crls   []store.CRL
}

func (f *multiCRLStore) revoke(serial string, at time.Time, reason int) {
	for i := range f.issued {
		if f.issued[i].Serial == serial {
			f.issued[i].RevokedAt = &at
			f.issued[i].ReasonCode = reason
		}
	}
}

func (f *multiCRLStore) LookupIssuedCert(_ context.Context, tenantID, caID, serial string) (store.IssuedCert, bool, error) {
	for _, cert := range f.issued {
		if cert.TenantID == tenantID && cert.CAID == caID && cert.Serial == serial {
			return cert, true, nil
		}
	}
	return store.IssuedCert{}, false, nil
}

func (f *multiCRLStore) HasIssuedCerts(_ context.Context, tenantID, caID string) (bool, error) {
	for _, cert := range f.issued {
		if cert.TenantID == tenantID && cert.CAID == caID {
			return true, nil
		}
	}
	return false, nil
}

func (f *multiCRLStore) ListRevokedCerts(_ context.Context, tenantID, caID string) ([]store.IssuedCert, error) {
	var out []store.IssuedCert
	for _, cert := range f.issued {
		if cert.TenantID == tenantID && cert.CAID == caID && cert.RevokedAt != nil {
			out = append(out, cert)
		}
	}
	return out, nil
}

func (f *multiCRLStore) NextCRLNumber(context.Context, string, string) (int64, error) {
	return int64(len(f.crls) + 1), nil
}

func (f *multiCRLStore) InsertCRL(_ context.Context, crl store.CRL) error {
	f.crls = append(f.crls, crl)
	return nil
}

func (f *multiCRLStore) TenantsWithIssuedCerts(context.Context, string) ([]string, error) {
	return []string{publicCRLTestTenant}, nil
}

func (f *multiCRLStore) CRLDueForRegeneration(context.Context, string, string, time.Time, time.Duration) (bool, error) {
	return true, nil
}

func (f *multiCRLStore) LatestCRL(context.Context, string, string) (store.CRL, bool, error) {
	return latestFullCRL(f.crls)
}

func (f *multiCRLStore) LatestCRLShard(_ context.Context, _ string, _ string, shardIndex int) (store.CRL, bool, error) {
	return latestShardCRL(f.crls, shardIndex)
}

func (f *multiCRLStore) LatestDeltaCRL(_ context.Context, _ string, _ string, baseNumber int64) (store.CRL, bool, error) {
	return latestDeltaCRL(f.crls, baseNumber)
}

func (f *multiCRLStore) ListLatestCRLArtifacts(context.Context, string, string) ([]store.CRL, error) {
	return latestCRLArtifacts(f.crls), nil
}

func (f *multiCRLStore) ActiveOCSPResponder(context.Context, string, string) (store.OCSPResponder, bool, error) {
	return store.OCSPResponder{}, false, errors.New("unexpected ActiveOCSPResponder")
}

func (f *multiCRLStore) UpsertOCSPResponder(context.Context, store.OCSPResponder) error {
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

func sortedSerials(serials []string) []string {
	out := append([]string(nil), serials...)
	sort.Strings(out)
	return out
}

func sortedSerialsFromSet(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for serial := range set {
		out = append(out, serial)
	}
	sort.Strings(out)
	return out
}

func latestFullCRL(crls []store.CRL) (store.CRL, bool, error) {
	for i := len(crls) - 1; i >= 0; i-- {
		if crls[i].Kind == "" || crls[i].Kind == store.CRLKindFull {
			return crls[i], true, nil
		}
	}
	return store.CRL{}, false, nil
}

func latestShardCRL(crls []store.CRL, shardIndex int) (store.CRL, bool, error) {
	for i := len(crls) - 1; i >= 0; i-- {
		if crls[i].Kind == store.CRLKindShard && crls[i].ShardIndex == shardIndex {
			return crls[i], true, nil
		}
	}
	return store.CRL{}, false, nil
}

func latestDeltaCRL(crls []store.CRL, baseNumber int64) (store.CRL, bool, error) {
	for i := len(crls) - 1; i >= 0; i-- {
		if crls[i].Kind == store.CRLKindDelta && crls[i].DeltaBaseNumber != nil && *crls[i].DeltaBaseNumber == baseNumber {
			return crls[i], true, nil
		}
	}
	return store.CRL{}, false, nil
}

func latestCRLArtifacts(crls []store.CRL) []store.CRL {
	full, found, _ := latestFullCRL(crls)
	if !found {
		return nil
	}
	out := []store.CRL{full}
	for _, crl := range crls {
		if crl.ParentNumber != nil && *crl.ParentNumber == full.Number {
			out = append(out, crl)
		}
	}
	return out
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
