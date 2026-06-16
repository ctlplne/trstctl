package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
)

// slowSigner wraps a real signer but stalls before each signature — the fault we
// inject to exercise the issuance timeout branch.
type slowSigner struct {
	inner crypto.DigestSigner
	delay time.Duration
}

func (s slowSigner) Public() crypto.PublicKey    { return s.inner.Public() }
func (s slowSigner) Algorithm() crypto.Algorithm { return s.inner.Algorithm() }
func (s slowSigner) SignDigest(digest []byte, opts crypto.SignOptions) ([]byte, error) {
	time.Sleep(s.delay)
	return s.inner.SignDigest(digest, opts)
}

// TestIssueLeafSlowSignerFailsClosedWithinTimeout is the R2.3 catastrophe-grade
// signer property that previously had no ran-it evidence: when the signer is slow,
// issuance fails closed within the configured timeout rather than hanging or — far
// worse — falling back to an in-process signature.
func TestIssueLeafSlowSignerFailsClosedWithinTimeout(t *testing.T) {
	caKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer caKey.Destroy()
	caDER, err := crypto.SelfSignedCACert(caKey, "Test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	defer leafKey.Destroy()
	csrDER, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "payments.svc"}, leafKey)
	if err != nil {
		t.Fatal(err)
	}

	// A signer that takes far longer than the per-issuance deadline.
	s := &Server{
		caSigner:  slowSigner{inner: caKey, delay: 5 * time.Second},
		caCertDER: caDER,
		signTO:    50 * time.Millisecond,
	}
	start := time.Now()
	_, err = s.IssueLeaf(context.Background(), csrDER, time.Hour)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a slow signer must fail closed — IssueLeaf returned a certificate")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("error = %v, want a fail-closed timeout", err)
	}
	if elapsed > time.Second {
		t.Errorf("IssueLeaf took %v; it must fail closed within ~the 50ms timeout, not wait on the slow signer", elapsed)
	}
}

// TestIssueLeafNoSignerFailsClosed confirms the unavailable-signer branch fails
// closed (the unreachable/stopped-signer branch is covered by the assembled
// TestAssembledFailsClosedWhenSignerStops).
func TestIssueLeafNoSignerFailsClosed(t *testing.T) {
	s := &Server{signTO: time.Second} // no caSigner / caCertDER provisioned
	if _, err := s.IssueLeaf(context.Background(), []byte("ignored-csr"), time.Hour); err == nil {
		t.Fatal("issuance with no out-of-process signer must fail closed, never sign in-process")
	}
}
