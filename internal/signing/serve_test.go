package signing_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"certctl.io/certctl/internal/crypto"
	"certctl.io/certctl/internal/signing"
)

// TestServeInProcess runs Serve in-process (covering the UDS listener, peer
// authentication, and graceful-shutdown paths that otherwise run only in the
// child during TestSignCSROverUDS) and signs a CSR through it.
func TestServeInProcess(t *testing.T) {
	dir, err := os.MkdirTemp("", "cs")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	socket := filepath.Join(dir, "s.sock")

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- signing.Serve(ctx, socket) }()

	client := waitReady(t, socket)
	defer func() { _ = client.Close() }()

	signer, err := client.GenerateKey(ctx, crypto.ECDSAP256)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	csr, err := crypto.CreateCertificateRequest(crypto.CertificateRequestTemplate{CommonName: "in-process"}, signer)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	if err := crypto.VerifyCertificateRequest(csr); err != nil {
		t.Errorf("CSR invalid: %v", err)
	}
	if err := signer.Destroy(ctx); err != nil {
		t.Errorf("Destroy: %v", err)
	}

	cancel() // trigger graceful shutdown + zeroize
	select {
	case err := <-served:
		if err != nil {
			t.Errorf("Serve returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after context cancellation")
	}
}

// TestHarden exercises the process-hardening entry point (a no-op off Linux).
func TestHarden(t *testing.T) {
	if err := signing.Harden(); err != nil {
		t.Fatalf("Harden: %v", err)
	}
}

func waitReady(t *testing.T, socket string) *signing.Client {
	t.Helper()
	client, err := signing.Dial(socket)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		hctx, cancel := context.WithTimeout(context.Background(), time.Second)
		ok := client.Healthy(hctx)
		cancel()
		if ok {
			return client
		}
		if time.Now().After(deadline) {
			_ = client.Close()
			t.Fatal("server not ready within 5s")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
