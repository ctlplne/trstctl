package server

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
	"time"

	"certctl.io/certctl/internal/crypto/kek"
	"certctl.io/certctl/internal/crypto/seal"
	"certctl.io/certctl/internal/signing"
)

// TestProvisionCAStableAcrossSignerRestart is the R3.2 disconfirming test for the
// silent-CA-rotation finding: across a real signer restart (a fresh persistent
// signer over the same sealed key store + the persisted CA cert), the issuing CA
// certificate is byte-for-byte stable. Before R3.2 the signer regenerated the CA
// key on every restart, silently rotating the CA.
func TestProvisionCAStableAcrossSignerRestart(t *testing.T) {
	dir := t.TempDir()
	kekW, err := kek.LoadOrCreate(filepath.Join(dir, "kek.bin"))
	if err != nil {
		t.Fatalf("LoadOrCreate KEK: %v", err)
	}
	defer kekW.Destroy()
	keysDir := filepath.Join(dir, "keys")
	socket := filepath.Join(dir, "signer.sock")
	caCertFile := filepath.Join(dir, "issuing-ca.crt")

	// Boot 1: a persistent signer; the control plane provisions a fresh CA (key
	// generated in the signer + cert persisted).
	cert1 := provisionOnce(t, keysDir, kekW, socket, caCertFile)
	if len(cert1) == 0 {
		t.Fatal("boot 1 produced no CA certificate")
	}

	// Boot 2: a NEW persistent signer over the SAME sealed key store and socket
	// (the restart) — and the same persisted CA cert. The control plane must reuse
	// both, yielding an identical CA certificate.
	cert2 := provisionOnce(t, keysDir, kekW, socket, caCertFile)

	if !bytes.Equal(cert1, cert2) {
		t.Fatal("issuing CA certificate changed across a signer restart — the CA silently rotated")
	}
}

// provisionOnce starts a persistent signer over the given sealed key store +
// socket, has a control-plane Server provision the issuing CA against it, and
// returns the CA certificate PEM. The signer is stopped before returning, so the
// next call is a genuine restart over the same persisted keys.
func provisionOnce(t *testing.T, keysDir string, kekW *seal.LocalKEK, socket, caCertFile string) []byte {
	t.Helper()
	ks := signing.NewKeyStore(keysDir, kekW)
	srv, err := signing.NewPersistentServer(ks)
	if err != nil {
		t.Fatalf("NewPersistentServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = signing.ServeServer(ctx, socket, srv) }()
	defer func() { cancel(); <-done }()

	client, err := signing.DialReady(context.Background(), socket, 10*time.Second)
	if err != nil {
		t.Fatalf("dial signer: %v", err)
	}
	defer func() { _ = client.Close() }()

	s := &Server{}
	if err := s.provisionCA(ctx, client, "", caCertFile); err != nil {
		t.Fatalf("provisionCA: %v", err)
	}
	return s.CACertPEM()
}
