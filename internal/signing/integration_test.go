package signing_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"certctl.io/certctl/internal/crypto"
	"certctl.io/certctl/internal/signing"
)

// TestSignCSROverUDS is the S1.4 acceptance test: the control plane launches the
// signer as its own process, then signs a CSR through it over a Unix domain
// socket, and the resulting CSR verifies.
func TestSignCSROverUDS(t *testing.T) {
	bin := buildSigner(t)

	// Keep the socket path short (UDS sun_path is limited to ~108 bytes).
	dir, err := os.MkdirTemp("", "cs")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	socket := filepath.Join(dir, "s.sock")

	ctx := context.Background()
	client, stop, err := signing.StartChild(ctx, bin, socket)
	if err != nil {
		t.Fatalf("StartChild: %v", err)
	}
	defer stop()

	signer, err := client.GenerateKey(ctx, crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// The private key lives in the signer; CreateCertificateRequest signs the
	// CSR's TBS digest by calling the signer's Sign RPC over the UDS.
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{
		CommonName: "test.certctl.io",
		DNSNames:   []string{"test.certctl.io"},
	}, signer)
	if err != nil {
		t.Fatalf("CreateCertificateRequest over UDS: %v", err)
	}
	if err := crypto.VerifyCertificateRequest(csr); err != nil {
		t.Errorf("CSR signed over UDS is invalid: %v", err)
	}

	if err := signer.Destroy(ctx); err != nil {
		t.Errorf("Destroy: %v", err)
	}
}
