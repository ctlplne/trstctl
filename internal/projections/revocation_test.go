package projections_test

import (
	"context"
	"encoding/pem"
	"errors"
	"sync"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/bulkhead"
	"trstctl.com/trstctl/internal/ca/revocation"
	"trstctl.com/trstctl/internal/crypto"
	cryptoca "trstctl.com/trstctl/internal/crypto/ca"
	"trstctl.com/trstctl/internal/store"
)

const revokeCAID = "11111111-aaaa-bbbb-cccc-222222222222"

// internalCA builds an internal root CA and an issued leaf, returning the CA, the
// leaf DER, the issuer DER, and the leaf serial.
func internalCA(t *testing.T, cn string) (*cryptoca.CA, []byte, []byte, string) {
	t.Helper()
	caObj, err := cryptoca.NewRoot(cryptoca.CASpec{CommonName: "trstctl Internal Root", TTL: 10 * 365 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: cn, DNSNames: []string{cn}}, key)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := caObj.IssueLeaf(csr, 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(issued.CertificatePEM)
	if block == nil {
		t.Fatal("no leaf PEM block")
	}
	return caObj, block.Bytes, caObj.CertificateDER(), issued.Serial
}

func revocationService(t *testing.T, s *store.Store, caObj *cryptoca.CA, opts ...revocation.Option) *revocation.Service {
	t.Helper()
	lookup := func(_, _ string) (*cryptoca.CA, error) { return caObj, nil }
	svc := revocation.New(s, openLog(t), lookup, opts...)
	t.Cleanup(svc.Close)
	return svc
}

// TestRevocationReflectsInOCSPAndCRL is the acceptance: revoking an
// internally-issued cert reflects in both OCSP and the next CRL.
func TestRevocationReflectsInOCSPAndCRL(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	caObj, leafDER, issuerDER, serial := internalCA(t, "svc.corp.internal")
	svc := revocationService(t, s, caObj)

	if err := svc.RecordIssued(ctx, tenantA, revokeCAID, serial); err != nil {
		t.Fatal(err)
	}
	reqDER, err := cryptoca.BuildOCSPRequest(leafDER, issuerDER)
	if err != nil {
		t.Fatal(err)
	}

	// Before revocation: good.
	respDER, err := svc.OCSP(ctx, tenantA, revokeCAID, reqDER)
	if err != nil {
		t.Fatalf("OCSP: %v", err)
	}
	if st, err := cryptoca.ParseOCSPResponse(respDER, issuerDER); err != nil || st.Status != cryptoca.OCSPGood {
		t.Fatalf("pre-revocation OCSP status = %q err=%v, want good", st.Status, err)
	}

	// Revoke.
	if err := svc.Revoke(ctx, tenantA, revokeCAID, serial, 1); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// OCSP now reports revoked.
	respDER, err = svc.OCSP(ctx, tenantA, revokeCAID, reqDER)
	if err != nil {
		t.Fatal(err)
	}
	st, err := cryptoca.ParseOCSPResponse(respDER, issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != cryptoca.OCSPRevoked {
		t.Errorf("post-revocation OCSP status = %q, want revoked", st.Status)
	}

	// The next CRL lists the revoked serial.
	crlDER, err := svc.GenerateCRL(ctx, tenantA, revokeCAID)
	if err != nil {
		t.Fatalf("GenerateCRL: %v", err)
	}
	info, err := cryptoca.ParseCRL(crlDER)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, sn := range info.RevokedSerials {
		if sn == serial {
			found = true
		}
	}
	if !found {
		t.Errorf("CRL serials = %v, want to contain revoked %s", info.RevokedSerials, serial)
	}

	// The CRL is published and retrievable.
	if latest, err := svc.LatestCRL(ctx, tenantA, revokeCAID); err != nil || len(latest) == 0 {
		t.Errorf("LatestCRL err=%v len=%d, want a published CRL", err, len(latest))
	}
}

// TestOCSPGoodResponseCacheable: a good response carries a future NextUpdate.
func TestOCSPGoodResponseCacheable(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	caObj, leafDER, issuerDER, serial := internalCA(t, "live.corp.internal")
	svc := revocationService(t, s, caObj, revocation.WithCacheTTL(15*time.Minute))
	if err := svc.RecordIssued(ctx, tenantA, revokeCAID, serial); err != nil {
		t.Fatal(err)
	}
	reqDER, _ := cryptoca.BuildOCSPRequest(leafDER, issuerDER)
	respDER, err := svc.OCSP(ctx, tenantA, revokeCAID, reqDER)
	if err != nil {
		t.Fatal(err)
	}
	st, err := cryptoca.ParseOCSPResponse(respDER, issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != cryptoca.OCSPGood {
		t.Fatalf("status = %q, want good", st.Status)
	}
	if !st.NextUpdate.After(time.Now().Add(10 * time.Minute)) {
		t.Errorf("NextUpdate = %v, want ~15m ahead (cacheable)", st.NextUpdate)
	}
}

// TestOCSPUnknownSerialRejected: a serial the responder never issued is reported
// unknown (per RFC 6960), not vouched for.
func TestOCSPUnknownSerialRejected(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	caObj, _, issuerDER, _ := internalCA(t, "known.corp.internal")
	svc := revocationService(t, s, caObj)

	// A second leaf that is NOT recorded as issued.
	_, strayDER, _, _ := internalCA(t, "stray.corp.internal")
	reqDER, err := cryptoca.BuildOCSPRequest(strayDER, issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	respDER, err := svc.OCSP(ctx, tenantA, revokeCAID, reqDER)
	if err != nil {
		t.Fatal(err)
	}
	st, err := cryptoca.ParseOCSPResponse(respDER, issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != cryptoca.OCSPUnknown {
		t.Errorf("unknown-serial status = %q, want unknown", st.Status)
	}
}

// TestOCSPLoadIsBounded: the responder runs on a bounded bulkhead pool, so when
// it is saturated new queries are rejected fast rather than starving the API.
func TestOCSPLoadIsBounded(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	caObj, leafDER, issuerDER, serial := internalCA(t, "load.corp.internal")

	pool := bulkhead.New(bulkhead.Config{Name: "ocsp", Workers: 1, Queue: 0})
	svc := revocationService(t, s, caObj, revocation.WithPool(pool))
	if err := svc.RecordIssued(ctx, tenantA, revokeCAID, serial); err != nil {
		t.Fatal(err)
	}
	reqDER, _ := cryptoca.BuildOCSPRequest(leafDER, issuerDER)

	// Occupy the only worker with a task that blocks until released.
	release := make(chan struct{})
	var occupied sync.WaitGroup
	occupied.Add(1)
	if err := pool.Submit(func() { occupied.Done(); <-release }); err != nil {
		t.Fatalf("could not occupy pool: %v", err)
	}
	occupied.Wait()

	// With the worker busy and no queue, an OCSP query is rejected (bounded).
	if _, err := svc.OCSP(ctx, tenantA, revokeCAID, reqDER); !errors.Is(err, bulkhead.ErrRejected) {
		t.Errorf("saturated OCSP err = %v, want bulkhead rejection", err)
	}
	close(release)

	// Once capacity frees up, queries succeed again.
	time.Sleep(20 * time.Millisecond)
	if _, err := svc.OCSP(ctx, tenantA, revokeCAID, reqDER); err != nil {
		t.Errorf("OCSP after capacity freed: %v", err)
	}
}
