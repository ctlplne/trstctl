package server

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/signing"
)

func testSignAuthorizer(t *testing.T) *crypto.SignAuthorizer {
	t.Helper()
	authz, err := crypto.NewSignAuthorizer(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatalf("NewSignAuthorizer: %v", err)
	}
	t.Cleanup(authz.Destroy)
	return authz
}

func serveSignerWithAuthorizer(t *testing.T, authz *crypto.SignAuthorizer) *signing.Client {
	t.Helper()
	dir, err := os.MkdirTemp("", "srvsign")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "s.sock")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() {
		done <- signing.ServeServer(ctx, socket, signing.NewServer(signing.WithAuthorizer(authz)))
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("signer server did not stop")
		}
	})
	client, err := signing.DialReady(ctx, socket, 10*time.Second)
	if err != nil {
		t.Fatalf("DialReady signer: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestProvisionCAUsesDualControlSignerHandle(t *testing.T) {
	authz := testSignAuthorizer(t)
	client := serveSignerWithAuthorizer(t, authz)
	s := &Server{signAuthz: authz}
	ctx := context.Background()
	if err := s.provisionCA(ctx, client, "trstctl Test Issuing CA", ""); err != nil {
		t.Fatalf("provisionCA: %v", err)
	}
	if s.caSigner == nil || len(s.caCertDER) == 0 {
		t.Fatal("provisionCA did not install an issuing CA signer and certificate")
	}
	digest, err := crypto.Digest(crypto.SHA256, []byte("attested certificate body"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.caSigner.SignDigest(digest, crypto.SignOptions{Hash: crypto.SHA256}); err != nil {
		t.Fatalf("attested CA sign through provisioned signer failed: %v", err)
	}

	forgeDigest, err := crypto.Digest(crypto.SHA256, []byte("forged certificate body"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := client.SignerForHandleWithPurpose(ctx, issuingCAHandle, signing.PurposeCASign)
	if err != nil {
		t.Fatalf("bind raw signer for issuing CA: %v", err)
	}
	_, err = raw.SignDigest(forgeDigest, crypto.SignOptions{Hash: crypto.SHA256})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("raw CA_SIGN against provisioned CA without token = %v, want PermissionDenied", status.Code(err))
	}
}
