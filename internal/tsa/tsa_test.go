package tsa

import (
	"context"
	"testing"
	"time"

	"trustctl.io/trustctl/internal/auditsink"
	"trustctl.io/trustctl/internal/crypto"
)

func newTSA(t *testing.T, clock func() time.Time) (*Authority, []byte) {
	t.Helper()
	root, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(root.Destroy)
	rootDER, _ := crypto.SelfSignedCACert(root, "TSA Root", time.Hour)
	tsaKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tsaKey.Destroy)
	csr, _ := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "TSA"}, tsaKey)
	tsaCert, err := crypto.SignLeafFromCSR(rootDER, root, csr, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	a, err := New(Config{TenantID: "t1", TSACertDER: tsaCert, TSASigner: tsaKey, Audit: &auditsink.Recorder{}, Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	return a, rootDER
}

func TestTimestampIssuesAndVerifies(t *testing.T) {
	a, rootDER := newTSA(t, nil)
	hash := crypto.SHA256Sum([]byte("the signed data"))
	tok, err := a.Timestamp(context.Background(), hash)
	if err != nil {
		t.Fatalf("Timestamp: %v", err)
	}
	if err := Verify(tok, hash, rootDER); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// Wrong imprint must fail.
	if err := Verify(tok, crypto.SHA256Sum([]byte("other")), rootDER); err == nil {
		t.Error("timestamp verified against the wrong imprint")
	}
}

func TestLongTermValidityAcrossExpiry(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	// Token is generated at t0+30m, while the signing cert (valid t0..t0+1h) is live.
	a, rootDER := newTSA(t, func() time.Time { return t0.Add(30 * time.Minute) })
	hash := crypto.SHA256Sum([]byte("data signed at t0+30m"))
	tok, err := a.Timestamp(context.Background(), hash)
	if err != nil {
		t.Fatal(err)
	}
	signingNotBefore, signingNotAfter := t0, t0.Add(time.Hour)
	// Even though the signing cert is now long expired, the timestamp proves it was
	// signed in-window, so it still validates.
	if err := VerifyLongTermValidity(tok, hash, rootDER, signingNotBefore, signingNotAfter); err != nil {
		t.Fatalf("LTV should hold for an in-window timestamp: %v", err)
	}
	// A timestamp outside the signing-cert window must NOT validate.
	if err := VerifyLongTermValidity(tok, hash, rootDER, t0.Add(time.Hour), t0.Add(2*time.Hour)); err == nil {
		t.Error("LTV accepted a timestamp outside the signing certificate window")
	}
}
