package server

import (
	"bytes"
	"context"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/store"
)

func TestServedOCSPUsesDelegatedResponderAndRotates(t *testing.T) {
	ctx := context.Background()
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "Delegated OCSP Test CA", 24*time.Hour)
	if err != nil {
		t.Fatalf("self-signed CA: %v", err)
	}
	responderKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate responder key: %v", err)
	}
	t.Cleanup(responderKey.Destroy)

	const serial = "abc123"
	now := time.Date(2026, 6, 27, 12, 0, 0, 0, time.UTC)
	st := &ocspResponderRotationStore{
		issued: store.IssuedCert{
			TenantID: publicCRLTestTenant,
			CAID:     IssuingCAID(),
			Serial:   serial,
			IssuedAt: now.Add(-time.Hour),
		},
	}
	svc := &revocationService{
		store:      st,
		caID:       IssuingCAID(),
		caSigner:   caKey,
		caCertDER:  caDER,
		ocspSigner: responderKey,
		now:        func() time.Time { return now },
	}
	reqDER, err := crypto.BuildOCSPRequestForSerial(caDER, serial)
	if err != nil {
		t.Fatalf("BuildOCSPRequestForSerial: %v", err)
	}

	firstDER, err := svc.respondOCSP(ctx, publicCRLTestTenant, reqDER)
	if err != nil {
		t.Fatalf("respondOCSP first: %v", err)
	}
	first, err := crypto.ParseOCSPResponse(firstDER, caDER)
	if err != nil {
		t.Fatalf("ParseOCSPResponse first: %v", err)
	}
	if first.ResponderIsIssuer {
		t.Fatal("first OCSP response was signed by the CA directly")
	}
	if !first.ResponderHasOCSPSigningEKU || !first.ResponderHasOCSPNoCheck {
		t.Fatalf("first responder metadata EKU=%v noCheck=%v, want delegated OCSP responder", first.ResponderHasOCSPSigningEKU, first.ResponderHasOCSPNoCheck)
	}
	if st.rotations != 1 {
		t.Fatalf("rotations after first response = %d, want 1 bootstrap rotation", st.rotations)
	}

	secondDER, err := svc.respondOCSP(ctx, publicCRLTestTenant, reqDER)
	if err != nil {
		t.Fatalf("respondOCSP second: %v", err)
	}
	second, err := crypto.ParseOCSPResponse(secondDER, caDER)
	if err != nil {
		t.Fatalf("ParseOCSPResponse second: %v", err)
	}
	if second.ResponderSerial != first.ResponderSerial {
		t.Fatalf("second response responder serial = %q, want reused active responder %q", second.ResponderSerial, first.ResponderSerial)
	}
	if st.rotations != 1 {
		t.Fatalf("rotations after reusable response = %d, want still 1", st.rotations)
	}

	st.responder.NotAfter = now.Add(10 * time.Minute)
	rotatedDER, err := svc.respondOCSP(ctx, publicCRLTestTenant, reqDER)
	if err != nil {
		t.Fatalf("respondOCSP rotated: %v", err)
	}
	rotated, err := crypto.ParseOCSPResponse(rotatedDER, caDER)
	if err != nil {
		t.Fatalf("ParseOCSPResponse rotated: %v", err)
	}
	if rotated.ResponderSerial == first.ResponderSerial {
		t.Fatalf("rotated response reused responder serial %q; want a new delegated responder cert", rotated.ResponderSerial)
	}
	if st.rotations != 2 {
		t.Fatalf("rotations after stale responder = %d, want 2", st.rotations)
	}
	if st.responder.RotatedFromSerial != first.ResponderSerial {
		t.Fatalf("rotated_from_serial = %q, want previous responder %q", st.responder.RotatedFromSerial, first.ResponderSerial)
	}
}

func TestServedOCSPCachesIdenticalFreshResponses(t *testing.T) {
	ctx := context.Background()
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	t.Cleanup(caKey.Destroy)
	caDER, err := crypto.SelfSignedCACert(caKey, "Cached OCSP Test CA", 24*time.Hour)
	if err != nil {
		t.Fatalf("self-signed CA: %v", err)
	}
	responderKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("generate responder key: %v", err)
	}
	t.Cleanup(responderKey.Destroy)
	countedResponder := &countingDigestSigner{inner: responderKey}

	const serial = "c0ffee"
	now := time.Date(2026, 6, 27, 14, 0, 0, 0, time.UTC)
	st := &ocspResponderRotationStore{
		issued: store.IssuedCert{
			TenantID: publicCRLTestTenant,
			CAID:     IssuingCAID(),
			Serial:   serial,
			IssuedAt: now.Add(-time.Hour),
		},
	}
	svc := &revocationService{
		store:      st,
		caID:       IssuingCAID(),
		caSigner:   caKey,
		caCertDER:  caDER,
		ocspSigner: countedResponder,
		ocspCache:  newOCSPResponseCache(),
		now:        func() time.Time { return now },
	}
	reqDER, err := crypto.BuildOCSPRequestForSerial(caDER, serial)
	if err != nil {
		t.Fatalf("BuildOCSPRequestForSerial: %v", err)
	}

	firstDER, err := svc.respondOCSP(ctx, publicCRLTestTenant, reqDER)
	if err != nil {
		t.Fatalf("respondOCSP first: %v", err)
	}
	secondDER, err := svc.respondOCSP(ctx, publicCRLTestTenant, reqDER)
	if err != nil {
		t.Fatalf("respondOCSP second: %v", err)
	}
	if !bytes.Equal(firstDER, secondDER) {
		t.Fatal("second identical OCSP response was not served from the cache")
	}
	if countedResponder.signs != 1 {
		t.Fatalf("responder SignDigest calls = %d, want 1 because the second query hits cache", countedResponder.signs)
	}
}

type countingDigestSigner struct {
	inner crypto.DigestSigner
	signs int
}

func (c *countingDigestSigner) Public() crypto.PublicKey { return c.inner.Public() }

func (c *countingDigestSigner) Algorithm() crypto.Algorithm { return c.inner.Algorithm() }

func (c *countingDigestSigner) SignDigest(digest []byte, opts crypto.SignOptions) ([]byte, error) {
	c.signs++
	return c.inner.SignDigest(digest, opts)
}

type ocspResponderRotationStore struct {
	issued    store.IssuedCert
	responder store.OCSPResponder
	found     bool
	rotations int
}

func (f *ocspResponderRotationStore) LookupIssuedCert(_ context.Context, tenantID, caID, serial string) (store.IssuedCert, bool, error) {
	if f.issued.TenantID == tenantID && f.issued.CAID == caID && f.issued.Serial == serial {
		return f.issued, true, nil
	}
	return store.IssuedCert{}, false, nil
}

func (f *ocspResponderRotationStore) ActiveOCSPResponder(_ context.Context, tenantID, caID string) (store.OCSPResponder, bool, error) {
	if f.found && f.responder.TenantID == tenantID && f.responder.CAID == caID {
		return f.responder, true, nil
	}
	return store.OCSPResponder{}, false, nil
}

func (f *ocspResponderRotationStore) UpsertOCSPResponder(_ context.Context, responder store.OCSPResponder) error {
	f.responder = responder
	f.found = true
	f.rotations++
	return nil
}

func (f *ocspResponderRotationStore) HasIssuedCerts(context.Context, string, string) (bool, error) {
	return true, nil
}

func (f *ocspResponderRotationStore) ListRevokedCerts(context.Context, string, string) ([]store.IssuedCert, error) {
	return nil, nil
}

func (f *ocspResponderRotationStore) NextCRLNumber(context.Context, string, string) (int64, error) {
	return 1, nil
}

func (f *ocspResponderRotationStore) InsertCRL(context.Context, store.CRL) error {
	return nil
}

func (f *ocspResponderRotationStore) TenantsWithIssuedCerts(context.Context, string) ([]string, error) {
	return []string{publicCRLTestTenant}, nil
}

func (f *ocspResponderRotationStore) CRLDueForRegeneration(context.Context, string, string, time.Time, time.Duration) (bool, error) {
	return false, nil
}

func (f *ocspResponderRotationStore) LatestCRL(context.Context, string, string) (store.CRL, bool, error) {
	return store.CRL{}, false, nil
}
